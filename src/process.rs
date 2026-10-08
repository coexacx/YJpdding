use anyhow::{Context, Result, bail};
use std::{
    fs::File,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Each owned process gets its own process group. Never touch an existing browser.
pub struct Process {
    child: Child,
    pgid: i32,
    stopped: bool,
}
impl Process {
    pub fn spawn(command: &mut Command, log: &Path) -> Result<Self> {
        let file = File::create(log)?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(file.try_clone()?))
            .stderr(Stdio::from(file));
        command.process_group(0);
        let child = command.spawn().context("启动子进程失败")?;
        let pgid = child.id() as i32;
        Ok(Self {
            child,
            pgid,
            stopped: false,
        })
    }
    pub fn check(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            bail!("子进程提前退出: {status}");
        }
        Ok(())
    }
    pub fn shutdown(&mut self, graceful: Duration) {
        if self.stopped {
            return;
        }
        let end = Instant::now() + graceful;
        while Instant::now() < end {
            if self.child.try_wait().ok().flatten().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(40));
        }
        // A process may exit before its descendants, so signal the owned group too.
        unsafe {
            libc::kill(-self.pgid, libc::SIGTERM);
        }
        let end = Instant::now() + Duration::from_millis(600);
        while Instant::now() < end {
            if unsafe { libc::kill(-self.pgid, 0) } != 0 {
                break;
            }
            thread::sleep(Duration::from_millis(30));
        }
        unsafe {
            libc::kill(-self.pgid, libc::SIGKILL);
        }
        let _ = self.child.wait();
        // Main enables subreaping: collect orphaned descendants of this group only.
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            let result = unsafe { libc::waitpid(-self.pgid, std::ptr::null_mut(), libc::WNOHANG) };
            if result < 0 || Instant::now() >= end {
                break;
            }
            if result == 0 {
                thread::sleep(Duration::from_millis(20));
            }
        }
        self.stopped = true;
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.shutdown(Duration::ZERO);
    }
}

pub fn find_program(names: &[&str]) -> Option<std::path::PathBuf> {
    for name in names {
        for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
            let path = directory.join(name);
            if let Ok(meta) = path.metadata() {
                use std::os::unix::fs::PermissionsExt;
                if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                    return Some(path);
                }
            }
        }
    }
    None
}
