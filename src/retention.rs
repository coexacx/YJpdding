use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MARKER: &str = ".yjpdding-capture.json";
pub const KEEP_SECONDS: u64 = 3 * 24 * 60 * 60;

#[derive(Serialize, Deserialize)]
struct Marker {
    owner: String,
    created_at: u64,
    target: String,
}

pub fn state_dir() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("YJPADDING_STATE_DIR") {
        return Ok(p.into());
    }
    let parent = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/state")))
        .context("缺少 HOME / XDG_STATE_HOME，无法保存清理任务")?;
    Ok(parent.join("YJpdding"))
}
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn lock_file(path: &Path, create: bool, nonblocking: bool) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mode = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), mode) } == 0,
        "目录正在使用，跳过清理"
    );
    Ok(f)
}

pub fn register(root: &Path) -> Result<()> {
    let state = state_dir()?;
    fs::create_dir_all(&state)?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    let _lock = lock_file(&state.join("registry.lock"), true, false)?;
    let registry = state.join("capture-roots.json");
    let mut roots: Vec<PathBuf> = if registry.exists() {
        serde_json::from_slice(&fs::read(&registry)?)?
    } else {
        Vec::new()
    };
    let root = root.canonicalize()?;
    let previous_len = roots.len();
    roots.retain(|p| p.is_dir());
    let mut changed = previous_len != roots.len();
    if !roots.contains(&root) {
        ensure!(roots.len() < 4096, "清理目录登记已达上限");
        roots.push(root);
        changed = true;
    }
    if changed {
        crate::report::save_json(&registry, &roots)?;
    }
    Ok(())
}

pub struct Lease {
    _lock: File,
}
impl Lease {
    pub fn create(directory: &Path, target: &str) -> Result<Self> {
        let lock = lock_file(&directory.join(".active.lock"), true, false)?;
        crate::report::save_json(
            &directory.join(MARKER),
            &Marker {
                owner: "YJpdding".into(),
                created_at: now()?,
                target: target.into(),
            },
        )?;
        register(directory.parent().context("缺少输出父目录")?)?;
        Ok(Self { _lock: lock })
    }
}

pub fn cleanup_root(root: &Path, time: u64) -> Result<usize> {
    let mut removed = 0;
    if !root.exists() {
        return Ok(0);
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        } // Never follow directory symlinks.
        let path = entry.path();
        if fs::symlink_metadata(&path)?.uid() != unsafe { libc::geteuid() } {
            continue;
        }
        let Ok(_lock) = lock_file(&path.join(".active.lock"), false, true) else {
            continue;
        };
        let marker = path.join(MARKER);
        let Ok(meta) = fs::symlink_metadata(&marker) else {
            continue;
        };
        if !meta.is_file() || meta.len() > 16_384 {
            continue;
        }
        let Ok(bytes) = fs::read(&marker) else {
            continue;
        };
        let Ok(marker) = serde_json::from_slice::<Marker>(&bytes) else {
            continue;
        };
        if marker.owner == "YJpdding"
            && marker.created_at > 0
            && time.saturating_sub(marker.created_at) >= KEEP_SECONDS
        {
            fs::remove_dir_all(&path).with_context(|| format!("清理 {} 失败", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn cleanup(state: &Path) -> Result<usize> {
    let registry = state.join("capture-roots.json");
    if !registry.exists() {
        return Ok(0);
    }
    ensure!(
        fs::metadata(&registry)?.len() <= 4 * 1024 * 1024,
        "清理登记文件过大"
    );
    let roots: Vec<PathBuf> = serde_json::from_slice(&fs::read(registry)?)?;
    let mut count = 0;
    for root in roots {
        count += cleanup_root(&root, now()?)?;
    }
    Ok(count)
}

pub fn site_name(url: &url::Url) -> String {
    let mut name: String = url
        .host_str()
        .unwrap_or("site")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if let Some(port) = url.port() {
        name.push_str(&format!("_{port}"));
    }
    // Leave room for timestamp/random suffix within NAME_MAX.
    name.truncate(180);
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_only_expired_owned_inactive_directories() {
        let temp = tempfile::tempdir().unwrap();
        let time = 1_000_000;
        let mut active_lock = None;
        for (name, age) in [
            ("expired", KEEP_SECONDS + 1),
            ("recent", 30),
            ("active", KEEP_SECONDS + 1),
        ] {
            let path = temp.path().join(name);
            fs::create_dir(&path).unwrap();
            let lock = lock_file(&path.join(".active.lock"), true, false).unwrap();
            crate::report::save_json(
                &path.join(MARKER),
                &Marker {
                    owner: "YJpdding".into(),
                    created_at: time - age,
                    target: "https://example.com".into(),
                },
            )
            .unwrap();
            if name == "active" {
                active_lock = Some(lock);
            }
        }
        fs::create_dir(temp.path().join("unrelated")).unwrap();
        std::os::unix::fs::symlink(temp.path().join("recent"), temp.path().join("symlink"))
            .unwrap();
        assert_eq!(cleanup_root(temp.path(), time).unwrap(), 1);
        assert!(!temp.path().join("expired").exists());
        for name in ["active", "recent", "unrelated", "symlink"] {
            assert!(temp.path().join(name).exists());
        }
        drop(active_lock);
        assert_eq!(cleanup_root(temp.path(), time).unwrap(), 1);
    }
}
