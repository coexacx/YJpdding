mod analysis;
mod browse;
mod browser;
mod capture;
mod config;
mod packet;
mod padding;
mod process;
mod report;
mod retention;
mod session;
mod stream;
mod tuning;
mod ui;
mod validation;
use anyhow::{Context, Result};
use clap::Parser;
use config::{Action, AnalyzeArgs, CaptureArgs, Cli};
use console::style;
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn output_dir(parent: &Path, label: &str) -> Result<PathBuf> {
    fs::create_dir_all(parent)?;
    let parent = parent.canonicalize()?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let temp = tempfile::Builder::new()
        .prefix(&format!("{label}-{timestamp}-"))
        .tempdir_in(parent)?;
    let path = temp.keep();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}
struct CaptureOutcome {
    code: i32,
    output: PathBuf,
    sample: Option<tuning::RoundSample>,
}
fn run_single_capture(
    args: CaptureArgs,
    cancel: Arc<AtomicBool>,
    prepare_timer: bool,
    verify: bool,
) -> Result<CaptureOutcome> {
    let url = config::validate_capture(&args)?;
    fs::create_dir_all(&args.output)?;
    let removed = retention::cleanup_root(&args.output, retention::now()?)?;
    if removed > 0 {
        println!("已清理 {removed} 个超过三天的历史抓包目录");
    }
    let site = retention::site_name(&url);
    let output = output_dir(&args.output, &site)?;
    let _lease = retention::Lease::create(&output, url.as_str())?;
    let pcap_path = output.join(format!("{site}.pcap"));
    println!("{} {}", style("输出目录").cyan(), output.display());
    let mut sample = None;
    let operation = (|| -> Result<i32> {
        if prepare_timer {
            validation::configure_cleanup(&output, &cancel)?;
        }
        println!("{}", style("[1/4] 启动独立 Chrome 会话 …").cyan());
        let mut browser = browser::Browser::launch(&args, &output, cancel.clone())?;
        println!(
            "      {} · {}",
            browser.evidence.browser_version, browser.evidence.user_agent
        );
        println!("{}", style("[2/4] 抓包器已就绪后开始访问 …").cyan());
        // The staging capture is temporary; only browser-associated packets are published.
        let staging = tempfile::Builder::new()
            .prefix(".staging-")
            .suffix(".pcap")
            .tempfile_in(&output)?;
        let mut task = capture::CaptureTask::start(
            &args.interface,
            staging.path(),
            args.max_mib * 1024 * 1024,
            browser.debug_port,
        )?;
        let started = Instant::now();
        let deadline = started + Duration::from_secs(args.duration);
        let mut error = None;
        if let Err(e) = browser.navigate(url.as_str()) {
            error = Some(e.to_string());
        }
        let mut last_nav = Instant::now();
        let mut last_progress = Instant::now();
        let mut last_scroll = Instant::now();
        let mut last_browse = Instant::now();
        let mut walker = browse::Walker::new(&url);
        while error.is_none()
            && Instant::now() < deadline
            && !cancel.load(Ordering::Relaxed)
            && !task.ended()
        {
            if let Err(e) = browser.poll() {
                error = Some(e.to_string());
                break;
            }
            let mut clicked = false;
            if args.browse_interval > 0
                && last_browse.elapsed() >= Duration::from_secs(args.browse_interval)
                && browser.evidence.successful_documents() > 0
                && browser.can_reload()
                && Instant::now() + Duration::from_secs(3) < deadline
            {
                match walker.step(&mut browser) {
                    Ok(browse::Step::Navigated) => {
                        clicked = true;
                        last_nav = Instant::now();
                        println!(
                            "      站内点击 → {}",
                            browser.evidence.clicks.last().unwrap().target
                        );
                    }
                    Ok(browse::Step::OverlayDismissed) => {
                        clicked = true;
                        last_nav = Instant::now();
                        println!("      已关闭识别到的隐私弹窗，继续站内浏览");
                    }
                    Ok(browse::Step::Idle) => {}
                    Err(e) => {
                        if browser.evidence.browsing_errors.len() < 100 {
                            browser.evidence.browsing_errors.push(e.to_string());
                        }
                    }
                }
                last_browse = Instant::now();
            }
            if !clicked
                && args.reload_interval > 0
                && last_nav.elapsed() >= Duration::from_secs(args.reload_interval)
                && browser.can_reload()
            {
                if let Err(e) = browser.navigate(url.as_str()) {
                    error = Some(e.to_string());
                    break;
                }
                last_nav = Instant::now();
            }
            if clicked {
                last_scroll = Instant::now();
            }
            if !clicked && last_scroll.elapsed() >= Duration::from_secs(3) {
                if let Err(e) = browser.cdp.send(
                    "Runtime.evaluate",
                    json!({"expression":"window.scrollBy(0, Math.max(300, innerHeight * 0.7))"}),
                    Some(&browser.session),
                ) {
                    error = Some(e.to_string());
                    break;
                }
                last_scroll = Instant::now();
            }
            if last_progress.elapsed() >= Duration::from_secs(5) {
                println!(
                    "      {:>3}/{} 秒 · {} 请求 · {} 次主页面成功",
                    started.elapsed().as_secs(),
                    args.duration,
                    browser.evidence.requests.len(),
                    browser.evidence.successful_documents()
                );
                last_progress = Instant::now();
            }
        }
        let interrupted = cancel.load(Ordering::Relaxed);
        // Drain already-queued events before stopping; no unbounded network-idle wait.
        let end = Instant::now() + Duration::from_millis(250);
        while Instant::now() < end {
            if browser.poll().is_err() {
                break;
            }
        }
        browser.close();
        thread::sleep(Duration::from_millis(100));
        let captured = task.finish()?;
        println!("{}", style("[3/4] 关联浏览器连接并重组 TLS …").cyan());
        fs::copy(&browser.netlog, output.join("netlog.json"))
            .context("保存 Chrome 连接日志失败")?;
        let connections = session::connections_from_netlog(&browser.netlog, &browser.evidence)?;
        let keylog_saved = if args.keylog {
            browser.save_keylog(&output)?
        } else {
            false
        };
        let mut session = session::Session {
            schema_version: 1,
            target: url.to_string(),
            settings: serde_json::to_value(&args)?,
            browser: browser.evidence.clone(),
            connections,
            capture: captured,
            interrupted,
            runtime_error: error,
            elapsed_seconds: started.elapsed().as_secs_f64(),
            keylog_saved,
            analysis_quality_errors: 0,
        };
        report::save_json(&output.join("session.json"), &session)?;
        let a = analysis::analyze(staging.path(), &session.connections, &[], Some(&pcap_path))?;
        session.analysis_quality_errors =
            a.truncated_packets + a.fragmented_packets + a.malformed_packets;
        report::save_json(&output.join("session.json"), &session)?;
        let mut issues = session.quality_issues();
        if a.packets_matched == 0 || a.up.ip_lengths.is_empty() || a.down.ip_lengths.is_empty() {
            issues.push("未匹配到浏览器的完整双向流量，请检查网卡及连接日志".into());
        }
        let good = issues.is_empty();
        let mut recommendation = padding::recommend(&a, good);
        sample = Some(tuning::RoundSample::extract(&a, good, &output));
        if verify {
            validation::verify_recommendation(&mut recommendation, &output, &cancel);
        }
        println!("{}", style("[4/4] 写入报告与采样依据 …").cyan());
        report::write_report(&output, &a, Some(&session), &recommendation)?;
        println!(
            "\n{} {} 个关联包 · {} 条连接 · {} 个请求",
            style("采集结果").bold(),
            a.packets_matched,
            a.flows.len(),
            session.browser.requests.len()
        );
        println!("Padding：{}", recommendation.reason);
        for issue in &issues {
            eprintln!("诊断：{issue}");
        }
        println!(
            "报告：{}\n数据：{}",
            output.join("report.txt").display(),
            pcap_path.display()
        );
        if interrupted || cancel.load(Ordering::Relaxed) {
            return Ok(130);
        }
        if !good || recommendation.status == "validation_failed" {
            if recommendation.status == "validation_failed" {
                issues.push(recommendation.reason.clone());
            }
            report::save_json(
                &output.join("failure.json"),
                &json!({"status":"partial_or_failed","reason":issues.join("；"),"issues":issues}),
            )?;
            eprintln!("采集未满足完整成功条件，已保留诊断报告。");
            return Ok(2);
        }
        Ok(0)
    })();
    if let Err(e) = &operation {
        let _ = report::save_json(
            &output.join("failure.json"),
            &json!({"status":"failed","error":format!("{e:#}")}),
        );
        eprintln!("诊断目录：{}", output.display());
    }
    operation.map(|code| CaptureOutcome {
        code,
        output,
        sample,
    })
}
fn run_capture(args: CaptureArgs, cancel: Arc<AtomicBool>, prepare_timer: bool) -> Result<i32> {
    config::validate_capture(&args)?;
    if args.rounds == 1 {
        return Ok(run_single_capture(args, cancel, prepare_timer, true)?.code);
    }
    let url = config::target_url(&args.target)?;
    fs::create_dir_all(&args.output)?;
    retention::cleanup_root(&args.output, retention::now()?)?;
    let output = output_dir(&args.output, &retention::site_name(&url))?;
    let _lease = retention::Lease::create(&output, url.as_str())?;
    println!("多轮优化目录：{}", output.display());
    let operation = (|| -> Result<i32> {
        if prepare_timer {
            validation::configure_cleanup(&output, &cancel)?;
        }
        let mut samples = Vec::new();
        for round in 0..args.rounds {
            if cancel.load(Ordering::Relaxed) {
                return Ok(130);
            }
            let mut current = args.clone();
            current.rounds = 1;
            current.duration = args.duration / u64::from(args.rounds)
                + u64::from(u64::from(round) < args.duration % u64::from(args.rounds));
            current.output = output.join(format!("round-{:02}", round + 1));
            println!(
                "\n采样轮 {}/{} · {} 秒 · {}",
                round + 1,
                args.rounds,
                current.duration,
                if round + 1 == args.rounds {
                    "独立复核"
                } else {
                    "训练"
                }
            );
            let result = run_single_capture(current, cancel.clone(), false, false)?;
            if let Some(mut sample) = result.sample {
                sample.directory = result
                    .output
                    .strip_prefix(&output)?
                    .to_string_lossy()
                    .into_owned();
                samples.push(sample);
            }
            report::save_json(&output.join("sampling.json"), &samples)?;
            if result.code != 0 {
                report::save_json(
                    &output.join("failure.json"),
                    &json!({"status":"sampling_failed", "round":round+1,"code":result.code,"directory":result.output}),
                )?;
                return Ok(result.code);
            }
        }
        tuning::optimize(&samples, &url, &output, &cancel)
    })();
    if let Err(e) = &operation {
        let _ = report::save_json(
            &output.join("failure.json"),
            &json!({"status":"failed","error":format!("{e:#}")}),
        );
        eprintln!("多轮优化诊断目录：{}", output.display());
    }
    if cancel.load(Ordering::Relaxed) {
        return Ok(130);
    }
    operation
}
fn run_analyze(args: AnalyzeArgs, cancel: Arc<AtomicBool>) -> Result<i32> {
    let session = args
        .session
        .as_ref()
        .map(|p| session::read_session(p))
        .transpose()?;
    let servers = args
        .server
        .iter()
        .map(|s| config::parse_server(s))
        .collect::<Result<Vec<_>>>()?;
    let connections = session
        .as_ref()
        .map(|s| s.connections.as_slice())
        .unwrap_or(&[]);
    let output = output_dir(&args.output, "analysis")?;
    let a = analysis::analyze(&args.pcap, connections, &servers, None)?;
    let quality = session
        .as_ref()
        .is_some_and(|s| s.quality_issues().is_empty());
    let mut r = padding::recommend(&a, quality);
    validation::verify_recommendation(&mut r, &output, &cancel);
    report::write_report(&output, &a, session.as_ref(), &r)?;
    println!("报告已保存：{}", output.join("report.txt").display());
    if cancel.load(Ordering::Relaxed) {
        return Ok(130);
    }
    if a.packets_matched == 0 {
        eprintln!("没有符合条件的有效数据包");
        return Ok(2);
    }
    if r.status == "validation_failed" {
        eprintln!("{}", r.reason);
        return Ok(2);
    }
    Ok(0)
}

fn run_self_test(parent: &Path, cancel: Arc<AtomicBool>) -> Result<i32> {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };
    let output = output_dir(parent, "self-test")?;
    let _lease = retention::Lease::create(&output, "loopback-self-test")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let cli = Cli::try_parse_from([
        "capture-rs",
        "capture",
        &format!("http://{address}/"),
        "--duration",
        "3",
        "--rounds",
        "1",
        "--reload-interval",
        "0",
        "--browse-interval",
        "0",
        "--output",
        output.to_str().context("输出路径需要 UTF-8")?,
    ])?;
    let Some(Action::Capture(args)) = cli.command else {
        unreachable!()
    };
    let stop = Arc::new(AtomicBool::new(false));
    let javascript = Arc::new(AtomicBool::new(false));
    let (done, seen) = (stop.clone(), javascript.clone());
    let worker = thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    let _ = socket.set_read_timeout(Some(Duration::from_millis(100)));
                    let _ = socket.set_write_timeout(Some(Duration::from_millis(500)));
                    let mut bytes = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while bytes.len() < 8192 && !bytes.ends_with(b"\r\n\r\n") {
                        match socket.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(length) => bytes.extend_from_slice(&chunk[..length]),
                        }
                    }
                    if !bytes.ends_with(b"\r\n\r\n") {
                        continue;
                    }
                    let request = String::from_utf8_lossy(&bytes);
                    if request.starts_with("GET /probe ") {
                        seen.store(true, Ordering::Relaxed);
                    }
                    let body = "<html><body>YJpdding preflight<script>fetch('/probe')</script></body></html>";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
    });
    println!("部署前自检：仅使用回环测试端口 {address}");
    let captured = run_capture(args, cancel.clone(), false);
    stop.store(true, Ordering::Relaxed);
    let _ = worker.join();
    let browser_ok = matches!(&captured, Ok(0)) && javascript.load(Ordering::Relaxed);
    let scheme =
        "stop=8\n0=30-30\n1=100-400\n2=64-512\n3=64-512\n4=64-512\n5=64-512\n6=64-512\n7=64-512\n";
    let padding = if browser_ok {
        validation::verify_scheme(scheme, &output, &cancel)
    } else {
        json!({"status":"skipped","reason":"Chrome 抓包或 JavaScript 执行检查未通过"})
    };
    let passed = browser_ok
        && padding["status"] == "passed"
        && padding["cleanup_ok"] == true
        && !cancel.load(Ordering::Relaxed);
    report::save_json(
        &output.join("preflight.json"),
        &json!({"status":if passed {"passed"} else {"failed"},"chrome_capture":browser_ok,"javascript_executed":javascript.load(Ordering::Relaxed),"capture_error":captured.err().map(|e|format!("{e:#}")),"anytls":padding}),
    )?;
    println!(
        "部署前自检{}：{}",
        if passed { "通过" } else { "失败" },
        output.join("preflight.json").display()
    );
    Ok(if cancel.load(Ordering::Relaxed) {
        130
    } else if passed {
        0
    } else {
        2
    })
}
fn run() -> Result<i32> {
    // Restrict artifacts; prevent orphaned Chrome descendants from becoming zombies.
    unsafe {
        libc::umask(0o077);
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))
        .context("安装中断处理器失败")?;
    let cli = Cli::parse();
    let action = match cli.command {
        Some(a) => Some(a),
        None => ui::menu()?,
    };
    match action {
        Some(Action::Capture(args)) => run_capture(args, cancel, true),
        Some(Action::Analyze(args)) => run_analyze(args, cancel),
        Some(Action::Doctor) => {
            ui::doctor()?;
            Ok(0)
        }
        Some(Action::Validate { file }) => {
            padding::validate_file(&file)?;
            Ok(0)
        }
        Some(Action::Cleanup { state_dir }) => {
            let state = state_dir.map(Ok).unwrap_or_else(retention::state_dir)?;
            println!(
                "已清理 {} 个超过三天的抓包目录",
                retention::cleanup(&state)?
            );
            Ok(0)
        }
        Some(Action::SelfTest { output }) => run_self_test(&output, cancel),
        Some(Action::VerifyPadding { file, output }) => {
            padding::validate_file(&file)?;
            let output = output_dir(&output, "padding-validation")?;
            let result = validation::verify_scheme(&fs::read_to_string(file)?, &output, &cancel);
            println!(
                "验证报告：{}",
                output.join("padding-validation.json").display()
            );
            if cancel.load(Ordering::Relaxed) {
                return Ok(130);
            }
            Ok(
                if result["status"] == "passed" && result["cleanup_ok"] == true {
                    0
                } else {
                    2
                },
            )
        }
        None => Ok(0),
    }
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{} {e:#}", style("错误：").red().bold());
            std::process::exit(1);
        }
    }
}
