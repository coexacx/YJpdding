use anyhow::{Result, bail, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
use url::Url;

#[derive(Parser)]
#[command(version, about = "Chrome 真实流量采集 · Rust / libpcap", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Action>,
}

#[derive(Subcommand)]
pub enum Action {
    /// 采集真实 Chrome 流量并生成报告
    Capture(CaptureArgs),
    /// 重分析已有 pcap / pcapng
    Analyze(AnalyzeArgs),
    /// 检查运行环境（不访问目标网站）
    Doctor,
    /// 检查 AnyTLS padding 文件的语法及边界
    Validate { file: PathBuf },
    /// 清理登记目录中超过三天且未在运行的抓包任务
    Cleanup {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// 本机部署前检查：真实 Chrome 抓包及临时 AnyTLS 节点互通
    SelfTest {
        #[arg(long, default_value = "./capture-results")]
        output: PathBuf,
    },
    /// 使用本机临时 AnyTLS 客户端和服务端验证候选配置
    VerifyPadding {
        file: PathBuf,
        #[arg(long, default_value = "./capture-results")]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserMode {
    Headless,
    Headed,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UaMode {
    Desktop,
    Native,
    Random,
    Custom,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Tcp,
    Natural,
}

#[derive(Args, Clone, Debug, Serialize)]
pub struct CaptureArgs {
    /// 域名或 http(s) URL（支持 IPv6 和非标准端口）
    pub target: String,
    /// 浏览器采集总时长（均分到各轮）；本机候选比对另有 90 秒上限
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(2..=3600))]
    pub duration: u64,
    /// 3–5 轮启用分层采样和实测筛选；1 轮保留快速采集
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=5))]
    pub rounds: u8,
    /// any 同时覆盖路由变化、IPv4/IPv6 和回环
    #[arg(long, default_value = "any")]
    pub interface: String,
    #[arg(long, value_enum, default_value = "headless")]
    pub browser: BrowserMode,
    /// desktop 使用本机桌面 UA；native 保留 HeadlessChrome 等原始标识
    #[arg(long, value_enum, default_value = "desktop")]
    pub ua: UaMode,
    /// 仅在 --ua custom 时使用
    #[arg(long)]
    pub user_agent: Option<String>,
    /// tcp 禁用 QUIC；natural 保留 Chrome 自然协商
    #[arg(long, value_enum, default_value = "tcp")]
    pub protocol: Protocol,
    /// 定时重新访问目标的最小间隔，等待当前页面结束；0 关闭定时重访
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(0..=3600))]
    pub reload_interval: u64,
    /// 成功加载后随机点击站内页面链接的最小间隔；0 关闭；最多尝试 30 个链接
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(0..=3600))]
    pub browse_interval: u64,
    /// 保留本次会话的浏览器缓存（默认关闭）
    #[arg(long)]
    pub cache: bool,
    /// 显式允许自签名/无效证书
    #[arg(long)]
    pub insecure: bool,
    /// 可选 Chrome 可执行文件
    #[arg(long)]
    pub chrome: Option<PathBuf>,
    /// 输出父目录；每次自动创建独立子目录
    #[arg(long, default_value = "./capture-results")]
    pub output: PathBuf,
    /// 每轮暂存抓包上限（MiB）；总上限为轮数 × 此值，另加 64 MiB 比对抓包
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u64).range(1..=2048))]
    pub max_mib: u64,
    /// 可选保存本次浏览器 TLS 密钥，供离线解密分析
    #[arg(long)]
    pub keylog: bool,
    /// 特殊环境下显式关闭 Chrome 沙箱
    #[arg(long)]
    pub no_sandbox: bool,
}

#[derive(Args)]
pub struct AnalyzeArgs {
    pub pcap: PathBuf,
    /// 在线采集生成的 session.json，优先使用精确连接关联
    #[arg(long, conflicts_with = "server")]
    pub session: Option<PathBuf>,
    /// 无 session 时显式指定服务器 IP 或 IP:端口；可重复
    #[arg(long, required_unless_present = "session")]
    pub server: Vec<String>,
    #[arg(long, default_value = "./capture-results")]
    pub output: PathBuf,
}

pub fn target_url(input: &str) -> Result<Url> {
    let input = input.trim();
    ensure!(
        !input.is_empty() && input.len() <= 8192,
        "目标不能为空或过长"
    );
    ensure!(
        !input.chars().any(|c| c.is_control() || c.is_whitespace()),
        "目标不能包含空白或控制字符"
    );
    let normalized = if input.contains("://") {
        input.to_owned()
    } else if let Ok(ip) = input.parse::<IpAddr>() {
        match ip {
            IpAddr::V6(_) => format!("https://[{ip}]/"),
            _ => format!("https://{ip}/"),
        }
    } else {
        format!("https://{input}")
    };
    let mut url = Url::parse(&normalized)?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "只支持 HTTP/HTTPS"
    );
    ensure!(url.host_str().is_some(), "缺少目标主机");
    if let Some(url::Host::Domain(domain)) = url.host() {
        ensure!(
            domain.len() <= 253
                && domain
                    .trim_end_matches('.')
                    .split('.')
                    .all(|label| !label.is_empty()
                        && label.len() <= 63
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')),
            "目标主机名格式不合法"
        );
    }
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "URL 不支持嵌入用户名或密码"
    );
    ensure!(url.port_or_known_default() != Some(0), "端口必须大于 0");
    url.set_fragment(None);
    Ok(url)
}

pub fn validate_capture(args: &CaptureArgs) -> Result<Url> {
    ensure!((2..=3600).contains(&args.duration), "时长必须为 2–3600 秒");
    ensure!(
        args.rounds == 1 || (3..=5).contains(&args.rounds),
        "轮数须为 1 或 3–5"
    );
    ensure!(
        args.duration >= u64::from(args.rounds) * 2,
        "总时长须至少为每轮 2 秒"
    );
    ensure!(
        (1..=2048).contains(&args.max_mib),
        "抓包大小必须为 1–2048 MiB"
    );
    ensure!(args.reload_interval <= 3600, "重新访问间隔最大 3600 秒");
    ensure!(args.browse_interval <= 3600, "站内浏览间隔最大 3600 秒");
    match (args.ua, &args.user_agent) {
        (UaMode::Custom, Some(s))
            if !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control) => {}
        (UaMode::Custom, _) => bail!("自定义 UA 需要 --user-agent，长度 1–512 且不能包含控制字符"),
        (_, Some(_)) => bail!("--user-agent 需要同时指定 --ua custom"),
        _ => {}
    }
    target_url(&args.target)
}

#[derive(Clone, Debug)]
pub struct Server {
    pub ip: IpAddr,
    pub port: Option<u16>,
}
pub fn parse_server(s: &str) -> Result<Server> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(Server { ip, port: None });
    }
    let socket: SocketAddr = s.parse()?;
    ensure!(socket.port() > 0, "服务器端口不能为 0");
    Ok(Server {
        ip: socket.ip(),
        port: Some(socket.port()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_validation() {
        assert_eq!(target_url("::1").unwrap().as_str(), "https://[::1]/");
        assert_eq!(
            target_url("localhost:8443/a?b=2").unwrap().port(),
            Some(8443)
        );
        for s in [
            "",
            "ftp://host/a",
            "https://user:pw@host",
            "host\nxxx",
            "http://host:0",
        ] {
            assert!(target_url(s).is_err(), "{s}");
        }
        assert!(target_url("example.com');print('x").is_err());
    }
}
