use crate::{config::*, process::find_program};
use anyhow::Result;
use console::{Term, style};
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use std::{path::PathBuf, process::Command};

pub fn banner() {
    let width = 54;
    println!("\n{}", style(format!("  ╭{}╮", "─".repeat(width))).cyan());
    for text in [
        concat!(
            "YJ PADDING           CHROME × RUST · v",
            env!("CARGO_PKG_VERSION")
        ),
        "真实浏览器采集 · 连接重组 · 可追溯分析",
    ] {
        let padding = " ".repeat(width - console::measure_text_width(text) - 4);
        println!(
            "{}  {}{}  {}",
            style("  │").cyan(),
            style(text).bold(),
            padding,
            style("│").cyan()
        );
    }
    println!("{}\n", style(format!("  ╰{}╯", "─".repeat(width))).cyan());
}
pub fn menu() -> Result<Option<Action>> {
    anyhow::ensure!(
        Term::stdout().is_term(),
        "非交互环境请使用 capture / analyze / doctor / validate 子命令，或 --help"
    );
    banner();
    let choice = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("选择操作")
        .items([
            "◉  开始采集       多轮 Chrome 采样与 padding 实测筛选",
            "↻  离线分析       重分析 pcap / pcapng",
            "✓  环境检查       系统、资源、权限与浏览器",
            "↓  一键安装       安装运行依赖与预编译内核",
            "◇  校验配置       检查 AnyTLS padding 文件",
            "◆  节点验证       创建本机临时 AnyTLS 节点测试配置",
            "✓  部署前自检     Chrome 抓包与 AnyTLS 互通检查",
            "退出",
        ])
        .default(0)
        .interact()?;
    match choice {
        0 => Ok(Some(Action::Capture(wizard()?))),
        1 => {
            let pcap: String = Input::new()
                .with_prompt("pcap / pcapng 路径")
                .interact_text()?;
            let session: String = Input::new()
                .with_prompt("session.json 路径（没有则留空）")
                .allow_empty(true)
                .interact_text()?;
            let server = if session.is_empty() {
                vec![
                    Input::<String>::new()
                        .with_prompt("服务器 IP 或 IP:端口")
                        .interact_text()?,
                ]
            } else {
                vec![]
            };
            Ok(Some(Action::Analyze(AnalyzeArgs {
                pcap: pcap.into(),
                session: if session.is_empty() {
                    None
                } else {
                    Some(session.into())
                },
                server,
                output: PathBuf::from("./capture-results"),
            })))
        }
        2 => Ok(Some(Action::Doctor)),
        3 => {
            let directory = std::env::var_os("CAPTURE_PROJECT_DIR")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::current_exe()
                        .ok()?
                        .parent()?
                        .parent()
                        .map(PathBuf::from)
                })
                .ok_or_else(|| anyhow::anyhow!("无法定位安装目录，请通过 capture.sh 启动"))?;
            let status = Command::new("bash")
                .arg(directory.join("install.sh"))
                .status()?;
            anyhow::ensure!(status.success(), "安装未完成，请查看上述错误");
            Ok(None)
        }
        4 => Ok(Some(Action::Validate {
            file: Input::<String>::new()
                .with_prompt("padding 配置文件")
                .interact_text()?
                .into(),
        })),
        5 => Ok(Some(Action::VerifyPadding {
            file: Input::<String>::new()
                .with_prompt("padding 配置文件")
                .interact_text()?
                .into(),
            output: "./capture-results".into(),
        })),
        6 => Ok(Some(Action::SelfTest {
            output: "./capture-results".into(),
        })),
        _ => Ok(None),
    }
}
fn wizard() -> Result<CaptureArgs> {
    let theme = ColorfulTheme::default();
    let target: String = Input::with_theme(&theme)
        .with_prompt("目标域名或 URL")
        .validate_with(|s: &String| target_url(s).map(|_| ()).map_err(|e| e.to_string()))
        .interact_text()?;
    let duration: u64 = Input::with_theme(&theme)
        .with_prompt("浏览器采集总时长（秒，至少每轮 2 秒）")
        .default(60)
        .validate_with(|v: &u64| {
            if (2..=3600).contains(v) {
                Ok(())
            } else {
                Err("请输入 2–3600")
            }
        })
        .interact_text()?;
    let rounds = if Select::with_theme(&theme)
        .with_prompt("采样策略")
        .items([
            "三轮优化 · 两轮训练 + 一轮独立复核 + 本机抓包比对",
            "单轮快速采集 · 不进行多轮筛选",
        ])
        .default(0)
        .interact()?
        == 0
    {
        3
    } else {
        1
    };
    let browser = if Select::with_theme(&theme)
        .with_prompt("Chrome 运行方式")
        .items([
            "无头模式 · 适合服务器",
            "有界面模式 · 无桌面时自动使用 Xvfb",
        ])
        .default(0)
        .interact()?
        == 0
    {
        BrowserMode::Headless
    } else {
        BrowserMode::Headed
    };
    let ua = match Select::with_theme(&theme)
        .with_prompt("User-Agent 策略")
        .items([
            "本机桌面 UA · 推荐，无头模式也使用普通 Chrome 标识",
            "本机原生 UA · 保留实际浏览器标识",
            "随机 Chrome UA · 实际版本 + 随机桌面平台",
            "自定义 UA",
        ])
        .default(0)
        .interact()?
    {
        0 => UaMode::Desktop,
        1 => UaMode::Native,
        2 => UaMode::Random,
        _ => UaMode::Custom,
    };
    let user_agent = if ua == UaMode::Custom {
        Some(
            Input::<String>::with_theme(&theme)
                .with_prompt("User-Agent")
                .interact_text()?,
        )
    } else {
        None
    };
    let protocol = if Select::with_theme(&theme)
        .with_prompt("采样协议")
        .items([
            "TCP/TLS 分析 · 禁用 QUIC，适合 AnyTLS 候选分析",
            "自然浏览 · 保留 QUIC / HTTP/3，分别统计",
        ])
        .default(0)
        .interact()?
        == 0
    {
        Protocol::Tcp
    } else {
        Protocol::Natural
    };
    println!("采集 {rounds} 轮 · 每轮抓包上限 256 MiB · 比对抓包另限 64 MiB");
    let mut args = CaptureArgs {
        target,
        duration,
        rounds,
        interface: "any".into(),
        browser,
        ua,
        user_agent,
        protocol,
        reload_interval: 10,
        browse_interval: 5,
        cache: false,
        insecure: false,
        chrome: None,
        output: "./capture-results".into(),
        max_mib: 256,
        keylog: false,
        no_sandbox: false,
    };
    if Confirm::with_theme(&theme)
        .with_prompt("调整网卡、缓存、证书等高级设置？")
        .default(false)
        .interact()?
    {
        args.interface = Input::with_theme(&theme)
            .with_prompt("网卡（any 覆盖全部接口）")
            .default("any".into())
            .interact_text()?;
        args.reload_interval = Input::with_theme(&theme)
            .with_prompt("重新访问最小间隔（等待页面完成，0 关闭定时重访）")
            .default(10)
            .interact_text()?;
        args.browse_interval = Input::with_theme(&theme)
            .with_prompt("站内随机点击间隔（秒，0 关闭）")
            .default(5)
            .interact_text()?;
        args.cache = Confirm::with_theme(&theme)
            .with_prompt("保留本次会话缓存？")
            .default(false)
            .interact()?;
        args.insecure = Confirm::with_theme(&theme)
            .with_prompt("跳过证书验证？")
            .default(false)
            .interact()?;
        args.keylog = Confirm::with_theme(&theme)
            .with_prompt("保存本次 TLS 密钥供离线解密？")
            .default(false)
            .interact()?;
        args.output = Input::<String>::with_theme(&theme)
            .with_prompt("输出目录")
            .default("./capture-results".into())
            .interact_text()?
            .into();
    }
    validate_capture(&args)?;
    Ok(args)
}
pub fn doctor() -> Result<()> {
    banner();
    if let Ok(s) = std::fs::read_to_string("/etc/os-release") {
        for l in s.lines().filter(|l| l.starts_with("PRETTY_NAME=")) {
            println!(
                "系统       {}",
                l.trim_start_matches("PRETTY_NAME=").trim_matches('"')
            );
        }
    }
    println!(
        "架构       {}\n采集权限   {}",
        std::env::consts::ARCH,
        if unsafe { libc::geteuid() } == 0 {
            "root"
        } else {
            "需 CAP_NET_RAW 或 sudo"
        }
    );
    println!("libpcap    已链接（由预编译发行包提供）");
    for (label, names) in [
        (
            "Chrome",
            vec![
                "google-chrome",
                "google-chrome-stable",
                "chromium",
                "chromium-browser",
            ],
        ),
        ("Xvfb", vec!["Xvfb"]),
    ] {
        println!(
            "{label:<10} {}",
            find_program(&names)
                .map(|p| p.display().to_string())
                .unwrap_or("未安装".into())
        );
    }
    println!("Rust       部署运行不需要；本机使用预编译内核");
    println!(
        "网卡       {}",
        pcap::Device::list()?
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
        for l in s.lines().filter(|l| l.starts_with("MemAvailable:")) {
            println!(
                "可用内存   {}",
                l.trim_start_matches("MemAvailable:").trim()
            );
        }
    }
    let out = Command::new("df").args(["-h", "."]).output()?;
    print!("{}", String::from_utf8_lossy(&out.stdout));
    Ok(())
}
