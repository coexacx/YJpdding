use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct CaptureStats {
    pub packets_written: u64,
    pub bytes_written: u64,
    pub kernel_received: u32,
    pub kernel_dropped: u32,
    pub interface_dropped: u32,
    pub size_limit_reached: bool,
}

pub struct CaptureTask {
    stop: Arc<AtomicBool>,
    done: mpsc::Receiver<()>,
    handle: Option<JoinHandle<Result<CaptureStats>>>,
}
impl CaptureTask {
    pub fn start(interface: &str, path: &Path, max_bytes: u64, exclude_port: u16) -> Result<Self> {
        // Open synchronously: readiness means libpcap is activated and the filter installed.
        let mut cap = pcap::Capture::from_device(interface)?
            .promisc(false)
            .snaplen(262144)
            .buffer_size(64 * 1024 * 1024)
            .timeout(20)
            .immediate_mode(false)
            .open()
            .context("无法打开抓包设备；检查网卡、root 或 CAP_NET_RAW 权限")?
            .setnonblock()?;
        cap.filter(
            &format!(
                "(tcp or udp) and not (tcp port {exclude_port} and (host 127.0.0.1 or host ::1))"
            ),
            true,
        )?;
        let mut output = cap.savefile(path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let (tx, done) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = (|| {
                let mut stats = CaptureStats::default();
                while !flag.load(Ordering::Relaxed) {
                    match cap.next_packet() {
                        Ok(packet) => {
                            stats.bytes_written += packet.data.len() as u64 + 16;
                            if stats.bytes_written > max_bytes {
                                stats.size_limit_reached = true;
                                break;
                            }
                            output.write(&packet);
                            stats.packets_written += 1;
                        }
                        Err(pcap::Error::TimeoutExpired) => thread::sleep(Duration::from_millis(5)),
                        Err(e) => return Err(e.into()),
                    }
                }
                output.flush()?;
                let kernel = cap.stats()?;
                stats.kernel_received = kernel.received;
                stats.kernel_dropped = kernel.dropped;
                stats.interface_dropped = kernel.if_dropped;
                Ok(stats)
            })();
            let _ = tx.send(());
            result
        });
        Ok(Self {
            stop,
            done,
            handle: Some(handle),
        })
    }
    pub fn ended(&self) -> bool {
        !matches!(self.done.try_recv(), Err(mpsc::TryRecvError::Empty))
    }
    pub fn finish(&mut self) -> Result<CaptureStats> {
        self.stop.store(true, Ordering::Relaxed);
        match self.handle.take() {
            Some(handle) => handle.join().map_err(|_| anyhow::anyhow!("抓包线程异常"))?,
            None => bail!("抓包已经结束"),
        }
    }
}
impl Drop for CaptureTask {
    fn drop(&mut self) {
        if self.handle.is_some() {
            let _ = self.finish();
        }
    }
}
