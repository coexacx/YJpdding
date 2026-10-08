mod analysis;
mod browser;
mod capture;
mod config;
mod packet;
mod padding;
mod process;
mod report;
mod session;
mod stream;
mod ui;
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
fn run_capture(args: CaptureArgs, cancel: Arc<AtomicBool>) -> Result<i32> {
    let url = config::validate_capture(&args)?;
    let output = output_dir(&args.output, "capture")?;
    println!("{} {}", style("输出目录").cyan(), output.display());
    let operation = (|| -> Result<i32> {
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
        while error.is_none()
            && Instant::now() < deadline
            && !cancel.load(Ordering::Relaxed)
            && !task.ended()
        {
            if let Err(e) = browser.poll() {
                error = Some(e.to_string());
                break;
            }
            if args.reload_interval > 0
                && last_nav.elapsed() >= Duration::from_secs(args.reload_interval)
            {
                if let Err(e) = browser.navigate(url.as_str()) {
                    error = Some(e.to_string());
                    break;
                }
                last_nav = Instant::now();
            }
            if last_scroll.elapsed() >= Duration::from_secs(3) {
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
        let a = analysis::analyze(
            staging.path(),
            &session.connections,
            &[],
            Some(&output.join("capture.pcap")),
        )?;
        session.analysis_quality_errors =
            a.truncated_packets + a.fragmented_packets + a.malformed_packets;
        report::save_json(&output.join("session.json"), &session)?;
        let good = !interrupted
            && session.runtime_error.is_none()
            && !session.capture.size_limit_reached
            && session.capture.kernel_dropped == 0
            && session.capture.interface_dropped == 0
            && session.browser.dropped_events == 0
            && session.analysis_quality_errors == 0
            && session.browser.successful_documents() > 0;
        let recommendation = padding::recommend(&a, good);
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
        println!(
            "报告：{}\n数据：{}",
            output.join("report.txt").display(),
            output.join("capture.pcap").display()
        );
        if interrupted {
            return Ok(130);
        }
        if !good
            || a.packets_matched == 0
            || a.up.ip_lengths.is_empty()
            || a.down.ip_lengths.is_empty()
        {
            report::save_json(
                &output.join("failure.json"),
                &json!({"status":"partial_or_failed","reason":"页面未成功、流量不完整或运行错误；详情见 session.json / report.txt"}),
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
    operation
}
fn run_analyze(args: AnalyzeArgs) -> Result<i32> {
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
    let quality = session.as_ref().is_some_and(|s| {
        !s.interrupted
            && s.runtime_error.is_none()
            && s.capture.kernel_dropped == 0
            && s.capture.interface_dropped == 0
            && !s.capture.size_limit_reached
            && s.analysis_quality_errors == 0
            && s.browser.dropped_events == 0
            && s.browser.successful_documents() > 0
    });
    let r = padding::recommend(&a, quality);
    report::write_report(&output, &a, session.as_ref(), &r)?;
    println!("报告已保存：{}", output.join("report.txt").display());
    if a.packets_matched == 0 {
        eprintln!("没有符合条件的有效数据包");
        return Ok(2);
    }
    Ok(0)
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
        Some(Action::Capture(args)) => run_capture(args, cancel),
        Some(Action::Analyze(args)) => run_analyze(args),
        Some(Action::Doctor) => {
            ui::doctor()?;
            Ok(0)
        }
        Some(Action::Validate { file }) => {
            padding::validate_file(&file)?;
            Ok(0)
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
