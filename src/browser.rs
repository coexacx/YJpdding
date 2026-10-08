use crate::{
    config::{BrowserMode, CaptureArgs, Protocol, UaMode},
    process::{Process, find_program},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    fs, io,
    net::TcpStream,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tungstenite::{Message, WebSocket};

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct BrowserRequest {
    pub request_id: String,
    pub url: String,
    pub method: String,
    pub resource_type: String,
    pub frame_id: String,
    pub status: Option<u16>,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub protocol: Option<String>,
    pub tls_version: Option<String>,
    pub cached: bool,
    pub error: Option<String>,
    pub finished: bool,
    pub encoded_bytes: u64,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct BrowserEvidence {
    pub browser_version: String,
    pub user_agent: String,
    #[serde(default)]
    pub native_user_agent: String,
    pub user_agent_metadata: Value,
    pub main_frame: String,
    pub requests: Vec<BrowserRequest>,
    pub navigation_errors: Vec<String>,
    pub navigations: usize,
    pub dropped_events: usize,
    pub sandbox_disabled: bool,
    pub virtual_display: bool,
    pub native_ua_note: String,
    #[serde(default)]
    pub clicks: Vec<crate::browse::Click>,
    #[serde(default)]
    pub browsing_errors: Vec<String>,
    #[serde(default)]
    pub dismissed_overlays: Vec<String>,
    #[serde(skip)]
    pub(crate) indices: HashMap<String, usize>,
}
impl BrowserEvidence {
    pub fn event(&mut self, event: Value) {
        let p = &event["params"];
        let id = p["requestId"].as_str().unwrap_or("").to_owned();
        match event["method"].as_str().unwrap_or("") {
            "Network.requestWillBeSent" => {
                if let Some(&index) = self.indices.get(&id) {
                    if p.get("redirectResponse").is_some() {
                        apply_response(&mut self.requests[index], &p["redirectResponse"]);
                        self.requests[index].finished = true;
                    }
                }
                if self.requests.len() >= 50_000 {
                    self.dropped_events += 1;
                    return;
                }
                let url = p["request"]["url"].as_str().unwrap_or("");
                if !(url.starts_with("https://") || url.starts_with("http://")) {
                    return;
                }
                self.indices.insert(id.clone(), self.requests.len());
                self.requests.push(BrowserRequest {
                    request_id: id,
                    url: url.to_owned(),
                    method: p["request"]["method"].as_str().unwrap_or("").to_owned(),
                    resource_type: p["type"].as_str().unwrap_or("").to_owned(),
                    frame_id: p["frameId"].as_str().unwrap_or("").to_owned(),
                    ..Default::default()
                });
            }
            "Network.responseReceived" => {
                if let Some(&i) = self.indices.get(&id) {
                    apply_response(&mut self.requests[i], &p["response"]);
                }
            }
            "Network.loadingFailed" => {
                if let Some(&i) = self.indices.get(&id) {
                    self.requests[i].finished = true;
                    self.requests[i].error = Some(
                        p["errorText"]
                            .as_str()
                            .unwrap_or("request failed")
                            .to_owned(),
                    );
                }
            }
            "Network.loadingFinished" => {
                if let Some(&i) = self.indices.get(&id) {
                    self.requests[i].finished = true;
                    self.requests[i].encoded_bytes =
                        p["encodedDataLength"].as_f64().unwrap_or(0.0).max(0.0) as u64;
                }
            }
            _ => {}
        }
    }
    pub fn successful_documents(&self) -> usize {
        self.requests
            .iter()
            .filter(|r| {
                r.resource_type == "Document"
                    && r.frame_id == self.main_frame
                    && r.finished
                    && r.error.is_none()
                    && r.status.is_some_and(|s| (200..300).contains(&s))
            })
            .count()
    }
    pub fn latest_document(&self) -> Option<&BrowserRequest> {
        self.requests
            .iter()
            .rev()
            .find(|r| r.resource_type == "Document" && r.frame_id == self.main_frame)
    }
    pub fn page_failure(&self) -> Option<String> {
        if self.successful_documents() > 0 {
            return None;
        }
        let documents: Vec<_> = self
            .requests
            .iter()
            .filter(|r| r.resource_type == "Document" && r.frame_id == self.main_frame)
            .collect();
        // Chrome may append ERR_ABORTED retries after the useful original error.
        let request = documents
            .iter()
            .rev()
            .find(|r| r.error.as_deref().is_some_and(|e| e != "net::ERR_ABORTED"))
            .copied()
            .or_else(|| documents.last().copied());
        let reason = if let Some(r) = request {
            if let Some(e) = &r.error {
                format!("主页面访问失败：{e}（{}）", r.url)
            } else if let Some(status) = r.status.filter(|s| !(200..300).contains(s)) {
                format!("主页面返回 HTTP {status}（{}）", r.url)
            } else {
                "采集时限内主页面未完成加载；可增加 --duration".into()
            }
        } else {
            format!(
                "未取得主页面请求：{}",
                self.navigation_errors
                    .last()
                    .map(String::as_str)
                    .unwrap_or("Chrome 未开始或未完成导航")
            )
        };
        let hint = if self.user_agent.contains("HeadlessChrome/") {
            "；当前 UA 含 HeadlessChrome，可使用 --ua desktop 或 --browser headed 重试"
        } else {
            ""
        };
        Some(format!("{reason}{hint}"))
    }
}
fn apply_response(request: &mut BrowserRequest, r: &Value) {
    request.status = r["status"].as_f64().map(|s| s as u16);
    request.remote_ip = r["remoteIPAddress"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    request.remote_port = r["remotePort"]
        .as_u64()
        .filter(|v| *v <= 65535)
        .map(|v| v as u16);
    request.protocol = r["protocol"].as_str().map(str::to_owned);
    request.tls_version = r["securityDetails"]["protocol"].as_str().map(str::to_owned);
    request.cached = r["fromDiskCache"].as_bool().unwrap_or(false)
        || r["fromServiceWorker"].as_bool().unwrap_or(false);
}

pub struct Cdp {
    socket: WebSocket<TcpStream>,
    next_id: u64,
    pub events: VecDeque<Value>,
    cancel: Arc<AtomicBool>,
}
impl Cdp {
    fn connect(port: u16, route: &str, cancel: Arc<AtomicBool>) -> Result<Self> {
        let stream = TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse()?,
            Duration::from_secs(3),
        )?;
        stream.set_read_timeout(Some(Duration::from_millis(150)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let (socket, _) = tungstenite::client(format!("ws://127.0.0.1:{port}{route}"), stream)
            .context("连接 Chrome DevTools 失败")?;
        Ok(Self {
            socket,
            next_id: 0,
            events: VecDeque::new(),
            cancel,
        })
    }
    pub fn send(&mut self, method: &str, params: Value, session: Option<&str>) -> Result<u64> {
        self.next_id += 1;
        let mut request = json!({"id": self.next_id, "method": method, "params": params});
        if let Some(s) = session {
            request["sessionId"] = json!(s);
        }
        self.socket
            .send(Message::Text(request.to_string().into()))?;
        Ok(self.next_id)
    }
    fn read(&mut self) -> Result<Option<Value>> {
        match self.socket.read() {
            Ok(Message::Text(s)) => Ok(Some(serde_json::from_str(&s)?)),
            Ok(Message::Close(_)) => bail!("Chrome DevTools 连接关闭"),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }
    pub fn call(&mut self, method: &str, params: Value, session: Option<&str>) -> Result<Value> {
        let id = self.send(method, params, session)?;
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            ensure!(!self.cancel.load(Ordering::Relaxed), "用户中断");
            if let Some(v) = self.read()? {
                if v["id"].as_u64() == Some(id) {
                    if let Some(e) = v.get("error") {
                        bail!("CDP {method}: {e}");
                    }
                    return Ok(v["result"].clone());
                }
                if v.get("method").is_some() {
                    ensure!(self.events.len() < 100_000, "CDP 事件队列达到上限");
                    self.events.push_back(v);
                }
            }
        }
        bail!("CDP {method} 超时")
    }
    pub fn poll(&mut self) -> Result<Option<Value>> {
        if let Some(event) = self.events.pop_front() {
            return Ok(Some(event));
        }
        self.read()
    }
}

pub struct Browser {
    pub cdp: Cdp,
    pub session: String,
    pub evidence: BrowserEvidence,
    pub debug_port: u16,
    profile: TempDir,
    process: Process,
    display: Option<Process>,
    pub netlog: PathBuf,
    pub keylog: PathBuf,
    navigation_pending: Option<u64>,
    page_loading: bool,
}
impl Browser {
    pub fn launch(args: &CaptureArgs, output: &Path, cancel: Arc<AtomicBool>) -> Result<Self> {
        let chrome = args
            .chrome
            .clone()
            .or_else(|| {
                find_program(&[
                    "google-chrome",
                    "google-chrome-stable",
                    "chromium",
                    "chromium-browser",
                ])
            })
            .context("未找到 Chrome/Chromium，请先运行安装菜单")?;
        let profile = tempfile::Builder::new()
            .prefix("capture-chrome-")
            .tempdir_in("/tmp")?;
        let mut display = None;
        let mut display_name = None;
        if args.browser == BrowserMode::Headed
            && std::env::var_os("DISPLAY").is_none()
            && std::env::var_os("WAYLAND_DISPLAY").is_none()
        {
            let xvfb = find_program(&["Xvfb"])
                .context("有界面模式需要 DISPLAY 或 Xvfb，请运行安装菜单")?;
            // Xvfb chooses a free display via -displayfd, with no TCP listener.
            use std::os::fd::AsRawFd;
            let (reader, writer) = std::os::unix::net::UnixStream::pair()?;
            reader.set_read_timeout(Some(Duration::from_secs(8)))?;
            let fd = writer.as_raw_fd();
            let mut cmd = Command::new(xvfb);
            cmd.args([
                "-displayfd",
                &fd.to_string(),
                "-screen",
                "0",
                "1440x1000x24",
                "-nolisten",
                "tcp",
                "-ac",
            ]);
            unsafe {
                cmd.pre_exec(move || {
                    if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let proc = Process::spawn(&mut cmd, &output.join("display.log"))?;
            drop(writer);
            use std::io::BufRead;
            let mut line = String::new();
            io::BufReader::new(reader).read_line(&mut line)?;
            let number: u16 = line.trim().parse().context("Xvfb 未能创建显示器")?;
            display_name = Some(format!(":{number}"));
            display = Some(proc);
        }
        let netlog = profile.path().join("netlog.json");
        let keylog = profile.path().join("tls.keys");
        let mut cmd = Command::new(chrome);
        cmd.current_dir(profile.path());
        cmd.args([
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-dev-shm-usage",
            "--disable-breakpad",
            "--password-store=basic",
            "--no-proxy-server",
            "--window-size=1440,1000",
        ]);
        cmd.arg(format!("--user-data-dir={}", profile.path().display()));
        cmd.env("XDG_CONFIG_HOME", profile.path().join("config"));
        cmd.env("XDG_CACHE_HOME", profile.path().join("cache"));
        cmd.arg(format!("--log-net-log={}", netlog.display()));
        // Default NetLog mode omits cookie credentials and socket payloads.
        cmd.arg("--net-log-capture-mode=Default");
        if args.browser == BrowserMode::Headless {
            cmd.arg("--headless=new");
        }
        if args.protocol == Protocol::Tcp {
            cmd.arg("--disable-quic");
        }
        if args.keylog {
            cmd.arg(format!("--ssl-key-log-file={}", keylog.display()));
        }
        if args.no_sandbox {
            cmd.arg("--no-sandbox");
        }
        if let Some(name) = &display_name {
            cmd.env("DISPLAY", name);
        }
        // Do not inherit a proxy or existing user profile from the caller.
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "SSLKEYLOGFILE",
        ] {
            cmd.env_remove(name);
        }
        if unsafe { libc::geteuid() } == 0 && !args.no_sandbox {
            let cpath = std::ffi::CString::new(profile.path().as_os_str().as_encoded_bytes())?;
            ensure!(
                unsafe { libc::chown(cpath.as_ptr(), 65534, 65534) } == 0,
                "设置浏览器临时目录权限失败"
            );
            unsafe {
                cmd.pre_exec(|| {
                    if libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setgid(65534) != 0
                        || libc::setuid(65534) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        cmd.arg("about:blank");
        let mut process = Process::spawn(&mut cmd, &output.join("chrome.log"))?;
        let end = Instant::now() + Duration::from_secs(20);
        let (port, route) = loop {
            ensure!(!cancel.load(Ordering::Relaxed), "用户中断");
            process
                .check()
                .context("Chrome 启动失败，详情见 chrome.log")?;
            if let Ok(s) = fs::read_to_string(profile.path().join("DevToolsActivePort")) {
                let mut lines = s.lines();
                if let (Some(p), Some(route)) = (lines.next(), lines.next()) {
                    if let Ok(port) = p.parse::<u16>() {
                        break (port, route.to_owned());
                    }
                }
            }
            ensure!(Instant::now() < end, "Chrome 启动超时，详情见 chrome.log");
            thread::sleep(Duration::from_millis(80));
        };
        let mut cdp = Cdp::connect(port, &route, cancel)?;
        let version = cdp.call("Browser.getVersion", json!({}), None)?;
        let target = cdp.call("Target.createTarget", json!({"url":"about:blank"}), None)?;
        let attached = cdp.call(
            "Target.attachToTarget",
            json!({"targetId":target["targetId"], "flatten":true}),
            None,
        )?;
        let session = attached["sessionId"]
            .as_str()
            .context("缺少 CDP session")?
            .to_owned();
        cdp.call("Page.enable", json!({}), Some(&session))?;
        cdp.call("Network.enable", json!({"maxTotalBufferSize":1_048_576,"maxResourceBufferSize":262_144,"maxPostDataSize":0}), Some(&session))?;
        cdp.call(
            "Network.setCacheDisabled",
            json!({"cacheDisabled":!args.cache}),
            Some(&session),
        )?;
        cdp.call(
            "Network.setBypassServiceWorker",
            json!({"bypass":!args.cache}),
            Some(&session),
        )?;
        if args.insecure {
            cdp.call(
                "Security.setIgnoreCertificateErrors",
                json!({"ignore":true}),
                None,
            )?;
        }
        let full_version = version["product"]
            .as_str()
            .unwrap_or("Chrome/0.0.0.0")
            .split('/')
            .nth(1)
            .unwrap_or("0.0.0.0");
        let native = version["userAgent"].as_str().unwrap_or("");
        let (ua, metadata, platform) = if args.ua == UaMode::Desktop {
            desktop_identity(&mut cdp)?
        } else {
            make_ua(args.ua, native, full_version, args.user_agent.as_deref())
        };
        if args.ua != UaMode::Native {
            cdp.call(
                "Emulation.setUserAgentOverride",
                json!({"userAgent":ua,"platform":platform,"userAgentMetadata":metadata}),
                Some(&session),
            )?;
        }
        let tree = cdp.call("Page.getFrameTree", json!({}), Some(&session))?;
        let evidence = BrowserEvidence {
            browser_version: version["product"].as_str().unwrap_or("").to_owned(),
            user_agent: ua,
            native_user_agent: native.to_owned(),
            user_agent_metadata: metadata,
            main_frame: tree["frameTree"]["frame"]["id"]
                .as_str()
                .unwrap_or("")
                .to_owned(),
            sandbox_disabled: args.no_sandbox,
            virtual_display: display.is_some(),
            native_ua_note: match args.ua {
                UaMode::Desktop => "使用本机桌面 UA（HeadlessChrome → Chrome），Client Hints 读取自本机浏览器，不随机更换平台".into(),
                UaMode::Native => "保留本机 Chrome 原生 UA 和 Client Hints；无头模式可能含 HeadlessChrome".into(),
                _ => "UA 覆盖仅影响 UA/Client Hints，不改变 Chrome 引擎、TLS 栈或操作系统".into(),
            },
            ..Default::default()
        };
        Ok(Self {
            cdp,
            session,
            evidence,
            debug_port: port,
            profile,
            process,
            display,
            netlog,
            keylog,
            navigation_pending: None,
            page_loading: false,
        })
    }
    pub fn navigate(&mut self, url: &str) -> Result<()> {
        // Async navigation: a hung DNS/TLS request cannot extend the capture deadline.
        self.navigation_pending = Some(self.cdp.send(
            "Page.navigate",
            json!({"url":url}),
            Some(&self.session),
        )?);
        self.page_loading = true;
        self.evidence.navigations += 1;
        Ok(())
    }
    pub fn poll(&mut self) -> Result<()> {
        if let Some(event) = self.cdp.poll()? {
            if event["id"].as_u64().is_some() && event["id"].as_u64() == self.navigation_pending {
                self.navigation_pending = None;
            }
            if let Some(e) = event["result"]["errorText"].as_str() {
                self.evidence.navigation_errors.push(e.to_owned());
            }
            if event.get("error").is_some() {
                self.evidence
                    .navigation_errors
                    .push(event["error"].to_string());
            }
            if event["sessionId"].as_str() == Some(self.session.as_str()) {
                if event["params"]["frameId"].as_str() == Some(self.evidence.main_frame.as_str()) {
                    match event["method"].as_str() {
                        Some("Page.frameStartedLoading") => self.page_loading = true,
                        Some("Page.frameStoppedLoading") => self.page_loading = false,
                        _ => {}
                    }
                }
                self.evidence.event(event);
            }
        }
        Ok(())
    }
    pub fn can_reload(&self) -> bool {
        self.navigation_pending.is_none()
            && !self.page_loading
            && self.evidence.latest_document().is_some_and(|r| r.finished)
    }
    pub fn close(&mut self) {
        let _ = self.cdp.send("Browser.close", json!({}), None);
        self.process.shutdown(Duration::from_secs(4));
        // Keep profile/NetLog alive until final connection attribution completes.
    }
    pub fn save_keylog(&self, output: &Path) -> Result<bool> {
        if self.keylog.is_file() {
            let target = output.join("tls.keys");
            fs::copy(&self.keylog, &target)?;
            fs::set_permissions(target, fs::Permissions::from_mode(0o600))?;
            return Ok(true);
        }
        Ok(false)
    }
}

fn desktop_identity(cdp: &mut Cdp) -> Result<(String, Value, String)> {
    // about:blank is not a secure context and hides navigator.userAgentData.
    // Read the real values from an isolated, internal Chrome page. No target or
    // external website is contacted before the packet capture becomes ready.
    let target = cdp.call(
        "Target.createTarget",
        json!({"url":"chrome://version/"}),
        None,
    )?;
    let result = (|| -> Result<_> {
        let attached = cdp.call(
            "Target.attachToTarget",
            json!({"targetId":target["targetId"],"flatten":true}),
            None,
        )?;
        let session = attached["sessionId"].as_str().context("缺少 UA 探测会话")?;
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            let reply = cdp.call("Runtime.evaluate", json!({
                "expression":"(async()=>({ua:navigator.userAgent,platform:navigator.platform,hints:await navigator.userAgentData?.getHighEntropyValues(['architecture','bitness','model','platformVersion','fullVersionList','wow64'])}))()",
                "awaitPromise":true,"returnByValue":true
            }), Some(session))?;
            let v = &reply["result"]["value"];
            if v["hints"].is_object()
                && v["ua"].as_str().is_some()
                && v["platform"].as_str().is_some()
            {
                return Ok((
                    v["ua"]
                        .as_str()
                        .unwrap()
                        .replace("HeadlessChrome/", "Chrome/"),
                    v["hints"].clone(),
                    v["platform"].as_str().unwrap().to_owned(),
                ));
            }
            ensure!(
                Instant::now() < end,
                "无法读取本机 UA Client Hints，可使用 --ua native 或 --ua random"
            );
            thread::sleep(Duration::from_millis(50));
        }
    })();
    let _ = cdp.call(
        "Target.closeTarget",
        json!({"targetId":target["targetId"]}),
        None,
    );
    result.context("读取本机桌面 UA 失败")
}
impl Drop for Browser {
    fn drop(&mut self) {
        self.process.shutdown(Duration::ZERO);
        if let Some(display) = &mut self.display {
            display.shutdown(Duration::ZERO);
        }
        let _ = self.profile.path();
    }
}

fn make_ua(
    mode: UaMode,
    native: &str,
    full: &str,
    custom: Option<&str>,
) -> (String, Value, String) {
    if mode == UaMode::Native {
        return (native.to_owned(), Value::Null, String::new());
    }
    let major = full.split('.').next().unwrap_or("0");
    let profiles = [
        ("X11; Linux x86_64", "Linux", "Linux x86_64", "6.1.0"),
        ("Windows NT 10.0; Win64; x64", "Windows", "Win32", "15.0.0"),
        (
            "Macintosh; Intel Mac OS X 10_15_7",
            "macOS",
            "MacIntel",
            "14.0.0",
        ),
    ];
    let p = profiles[rand::random_range(0..profiles.len())];
    let ua = custom.map(str::to_owned).unwrap_or_else(|| format!("Mozilla/5.0 ({}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36", p.0));
    if mode == UaMode::Custom {
        // Arbitrary strings do not provide reliable Client Hint metadata. Suppress brands
        // rather than sending contradictory fake browser versions.
        return (
            ua,
            json!({"brands":[],"fullVersionList":[],"platform":"","platformVersion":"","architecture":"","model":"","mobile":false}),
            String::new(),
        );
    }
    let meta = json!({"brands":[{"brand":"Chromium","version":major},{"brand":"Google Chrome","version":major}],
        "fullVersionList":[{"brand":"Chromium","version":full},{"brand":"Google Chrome","version":full}],
        "platform":p.1,"platformVersion":p.3,"architecture":"x86","bitness":"64","model":"","mobile":false});
    (ua, meta, p.2.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redirect_retains_both_endpoints() {
        let mut e = BrowserEvidence::default();
        e.event(json!({"method":"Network.requestWillBeSent","params":{"requestId":"1","request":{"url":"http://a/","method":"GET"},"type":"Document"}}));
        e.event(json!({"method":"Network.requestWillBeSent","params":{"requestId":"1","request":{"url":"https://b/","method":"GET"},"redirectResponse":{"status":302,"remoteIPAddress":"127.0.0.1","remotePort":80}}}));
        assert_eq!(e.requests.len(), 2);
        assert_eq!(e.requests[0].status, Some(302));
        assert_eq!(e.requests[0].remote_port, Some(80));
    }
    #[test]
    fn random_ua_uses_actual_engine_version() {
        let (ua, meta, _) = make_ua(UaMode::Random, "native", "154.1.2.3", None);
        assert!(ua.contains("Chrome/154.0.0.0"));
        assert_eq!(meta["fullVersionList"][0]["version"], "154.1.2.3");
    }
    #[test]
    fn failure_diagnosis_keeps_protocol_error_before_aborted_retry() {
        let mut e = BrowserEvidence {
            main_frame: "main".into(),
            user_agent: "HeadlessChrome/154.0.0.0".into(),
            ..Default::default()
        };
        for (id, error) in [
            ("1", "net::ERR_HTTP2_PROTOCOL_ERROR"),
            ("2", "net::ERR_ABORTED"),
        ] {
            e.event(json!({"method":"Network.requestWillBeSent","params":{"requestId":id,"request":{"url":"https://example.com/","method":"GET"},"type":"Document","frameId":"main"}}));
            e.event(json!({"method":"Network.loadingFailed","params":{"requestId":id,"errorText":error}}));
        }
        assert!(e.latest_document().unwrap().finished);
        assert_eq!(e.successful_documents(), 0);
        let message = e.page_failure().unwrap();
        assert!(message.contains("ERR_HTTP2_PROTOCOL_ERROR"));
        assert!(message.contains("--ua desktop"));
        e.requests.push(BrowserRequest {
            resource_type: "Document".into(),
            frame_id: "main".into(),
            finished: true,
            status: Some(200),
            ..Default::default()
        });
        assert!(e.page_failure().is_none());
    }
    #[test]
    fn subframe_success_does_not_hide_main_page_http_denial() {
        let mut e = BrowserEvidence {
            main_frame: "main".into(),
            ..Default::default()
        };
        for (frame, status) in [("main", 403), ("child", 200)] {
            e.requests.push(BrowserRequest {
                resource_type: "Document".into(),
                frame_id: frame.into(),
                finished: true,
                status: Some(status),
                ..Default::default()
            });
        }
        assert_eq!(e.successful_documents(), 0);
        assert!(e.page_failure().unwrap().contains("HTTP 403"));
    }
}
