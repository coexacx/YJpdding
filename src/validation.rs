use crate::{padding, process::Process, report, retention};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub fn helper(name: &str) -> Result<PathBuf> {
    let mut roots = Vec::new();
    if let Some(root) = std::env::var_os("CAPTURE_PROJECT_DIR") {
        roots.push(PathBuf::from(root));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(root) = exe.parent().and_then(Path::parent) {
            roots.push(root.to_owned());
        }
    }
    roots.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    roots
        .into_iter()
        .map(|r| r.join("tools").join(name))
        .find(|p| p.is_file())
        .context("缺少验证工具，请安装完整 Release 包")
}

pub fn configure_cleanup(output: &Path, cancel: &Arc<AtomicBool>) -> Result<()> {
    if std::env::var_os("YJPADDING_SKIP_TIMER").as_deref() == Some(std::ffi::OsStr::new("1")) {
        return Ok(());
    }
    let binary = std::env::var_os("CAPTURE_PROJECT_DIR")
        .map(|p| PathBuf::from(p).join("bin/capture-rs"))
        .filter(|p| p.is_file())
        .unwrap_or(std::env::current_exe()?);
    let mut cmd = Command::new("python3");
    cmd.arg(helper("setup-cleanup.py")?)
        .arg("--binary")
        .arg(binary)
        .arg("--state-dir")
        .arg(retention::state_dir()?);
    run_helper(
        &mut cmd,
        &output.join("cleanup-setup.log"),
        Duration::from_secs(45),
        cancel,
    )
}

fn run_helper(
    cmd: &mut Command,
    log: &Path,
    limit: Duration,
    cancel: &Arc<AtomicBool>,
) -> Result<()> {
    let mut child = Process::spawn(cmd, log)?;
    let end = Instant::now() + limit;
    loop {
        ensure!(!cancel.load(Ordering::Relaxed), "验证被中断");
        if let Some(status) = child.try_wait()? {
            ensure!(
                status.success(),
                "验证工具退出：{status}，详情见 {}",
                log.display()
            );
            return Ok(());
        }
        ensure!(Instant::now() < end, "验证超时，已终止本次测试进程");
        thread::sleep(Duration::from_millis(30));
    }
}

pub fn verify_scheme(scheme: &str, output: &Path, cancel: &Arc<AtomicBool>) -> Value {
    let operation = (|| -> Result<Value> {
        padding::validate(scheme)?;
        let scratch = tempfile::Builder::new()
            .prefix(".padding-test-")
            .tempdir_in(output)?;
        let file = scratch.path().join("padding.txt");
        report::atomic_write(&file, scheme.as_bytes())?;
        let result = output.join("padding-validation.json");
        let mut cmd = Command::new("python3");
        cmd.arg(helper("runtime.py")?)
            .arg("verify")
            .arg("--scheme")
            .arg(file)
            .arg("--result")
            .arg(&result)
            .arg("--state-dir")
            .arg(retention::state_dir()?);
        let status = run_helper(
            &mut cmd,
            &output.join("padding-validation.log"),
            Duration::from_secs(50),
            cancel,
        );
        if result.is_file() {
            return Ok(serde_json::from_slice(&fs::read(result)?)?);
        }
        status?;
        anyhow::bail!("验证工具未输出结果")
    })();
    match operation {
        Ok(value) => value,
        Err(e) => {
            let value =
                json!({"status":"failed","error":format!("{e:#}"),"scope":"本机临时 AnyTLS 节点"});
            let _ = report::save_json(&output.join("padding-validation.json"), &value);
            value
        }
    }
}

pub fn verify_recommendation(
    recommendation: &mut padding::Recommendation,
    output: &Path,
    cancel: &Arc<AtomicBool>,
) {
    if let Some(scheme) = &recommendation.scheme {
        println!("      自动验证 AnyTLS 候选配置（仅本机临时节点） …");
        let result = verify_scheme(scheme, output, cancel);
        if result["status"] == "passed" && result["cleanup_ok"] == true {
            recommendation.status = "locally_verified_candidate".into();
            recommendation.reason =
                "已通过本机 AnyTLS 配置同步、连接复用及双向数据传输测试；临时节点已清理".into();
        } else {
            recommendation.status = "validation_failed".into();
            recommendation.reason = format!(
                "AnyTLS 自动验证未通过：{}",
                result["error"]
                    .as_str()
                    .unwrap_or("详见 padding-validation.json")
            );
        }
        recommendation.validation = Some(result);
    }
}
