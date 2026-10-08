use crate::{
    config::Server,
    packet::{self, DecodeError, Packet},
    session::Connection,
    stream::Stream,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{collections::HashMap, net::SocketAddr, path::Path};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    pub count: usize,
    pub min: usize,
    pub max: usize,
    pub mean: f64,
    pub std_dev: f64,
    pub p10: usize,
    pub p25: usize,
    pub p50: usize,
    pub p75: usize,
    pub p90: usize,
    pub p95: usize,
    pub p99: usize,
}
pub fn stats(data: &[usize]) -> Stats {
    if data.is_empty() {
        return Stats::default();
    }
    let mut s = data.to_vec();
    s.sort_unstable();
    let n = s.len();
    let mean = s.iter().map(|&v| v as f64).sum::<f64>() / n as f64;
    let std_dev = (s.iter().map(|&v| (v as f64 - mean).powi(2)).sum::<f64>() / n as f64).sqrt();
    let q = |p: usize| s[(n * p).div_ceil(100).saturating_sub(1).min(n - 1)];
    Stats {
        count: n,
        min: s[0],
        max: s[n - 1],
        mean,
        std_dev,
        p10: q(10),
        p25: q(25),
        p50: q(50),
        p75: q(75),
        p90: q(90),
        p95: q(95),
        p99: q(99),
    }
}

#[derive(Default, Debug, Serialize)]
pub struct Direction {
    pub ip_lengths: Vec<usize>,
    pub tcp_payload_lengths: Vec<usize>,
    pub udp_payload_lengths: Vec<usize>,
}
#[derive(Debug, Serialize)]
pub struct Flow {
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub transport: String,
    pub packet_count: usize,
    pub up: Stream,
    pub down: Stream,
}
#[derive(Debug, Default, Serialize)]
pub struct Analysis {
    pub packets_scanned: usize,
    pub packets_matched: usize,
    pub truncated_packets: usize,
    pub fragmented_packets: usize,
    pub malformed_packets: usize,
    pub oversized_ip_packets: usize,
    pub up: Direction,
    pub down: Direction,
    pub flows: Vec<Flow>,
    pub link_type: i32,
    pub attribution: String,
}
type FlowKey = (u8, SocketAddr, SocketAddr);

pub fn analyze(
    path: &Path,
    connections: &[Connection],
    servers: &[Server],
    filtered: Option<&Path>,
) -> Result<Analysis> {
    ensure!(
        std::fs::metadata(path)?.len() <= 2 * 1024 * 1024 * 1024,
        "抓包文件超过 2 GiB 分析上限"
    );
    let mut cap = pcap::Capture::from_file(path).context("打开 pcap/pcapng 失败")?;
    let link = cap.get_datalink().0;
    ensure!(
        [0, 1, 12, 101, 108, 113, 228, 229, 276].contains(&link),
        "暂不支持链路类型 {link}"
    );
    let mut writer = filtered.map(|p| cap.savefile(p)).transpose()?;
    let mut result = Analysis {
        link_type: link,
        attribution: if servers.is_empty() {
            "chrome_netlog_socket"
        } else {
            "explicit_server_filter_unverified"
        }
        .into(),
        ..Default::default()
    };
    let exact: HashMap<FlowKey, ()> = connections
        .iter()
        .filter(|c| !c.local.ip().is_unspecified())
        .map(|c| {
            (
                (if c.transport == "tcp" { 6 } else { 17 }, c.local, c.remote),
                (),
            )
        })
        .collect();
    let wildcard: Vec<_> = connections
        .iter()
        .filter(|c| c.local.ip().is_unspecified())
        .collect();
    let mut indexes: HashMap<FlowKey, usize> = HashMap::new();
    let mut pending_bytes = 0usize;
    let mut tls_samples = 0usize;
    loop {
        let raw = match cap.next_packet() {
            Ok(p) => p,
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(e).context("抓包文件损坏或读取失败"),
        };
        result.packets_scanned += 1;
        let truncated = raw.header.caplen < raw.header.len;
        if truncated {
            result.truncated_packets += 1;
        }
        let p = match packet::decode(link, raw.data) {
            Ok(p) => p,
            Err(DecodeError::Truncated) => {
                if !truncated {
                    result.truncated_packets += 1;
                }
                continue;
            }
            Err(DecodeError::Fragmented) => {
                result.fragmented_packets += 1;
                continue;
            }
            Err(DecodeError::Malformed) => {
                result.malformed_packets += 1;
                continue;
            }
            Err(DecodeError::Unsupported) => continue,
        };
        let Some(up) = classify(&p, &exact, &wildcard, servers) else {
            continue;
        };
        ensure!(
            result.packets_matched < 2_000_000,
            "有效样本超过 200 万，请缩短采集时长或分批分析"
        );
        result.packets_matched += 1;
        if let Some(w) = writer.as_mut() {
            w.write(&raw);
        }
        if p.ip_length > 1500 {
            result.oversized_ip_packets += 1;
        }
        let direction = if up { &mut result.up } else { &mut result.down };
        direction.ip_lengths.push(p.ip_length);
        if !p.payload.is_empty() {
            if p.protocol == 6 {
                direction.tcp_payload_lengths.push(p.payload.len());
            } else {
                direction.udp_payload_lengths.push(p.payload.len());
            }
        }
        let (client, server) = if up {
            (p.source, p.destination)
        } else {
            (p.destination, p.source)
        };
        let key = (p.protocol, client, server);
        let reused = p.syn
            && !p.ack
            && indexes.get(&key).is_some_and(|&i| {
                result.flows[i]
                    .up
                    .syn_sequence()
                    .is_some_and(|s| s != p.sequence)
            });
        if reused {
            indexes.remove(&key);
        }
        let index = match indexes.get(&key) {
            Some(&i) => i,
            None => {
                ensure!(result.flows.len() < 10_000, "连接数超出 10000 上限");
                let i = result.flows.len();
                result.flows.push(Flow {
                    client,
                    server,
                    transport: if p.protocol == 6 { "tcp" } else { "udp" }.into(),
                    packet_count: 0,
                    up: Stream::default(),
                    down: Stream::default(),
                });
                indexes.insert(key, i);
                i
            }
        };
        let flow = &mut result.flows[index];
        flow.packet_count += 1;
        if p.protocol == 6 {
            let stream = if up { &mut flow.up } else { &mut flow.down };
            pending_bytes = pending_bytes.saturating_sub(stream.buffered_bytes());
            tls_samples = tls_samples.saturating_sub(stream.tls.record_lengths.len());
            stream.feed(p.sequence, p.syn, p.payload);
            pending_bytes += stream.buffered_bytes();
            tls_samples += stream.tls.record_lengths.len();
            ensure!(
                tls_samples <= 1_000_000,
                "TLS record 样本超过 100 万，请分批分析"
            );
            ensure!(
                pending_bytes <= 64 * 1024 * 1024,
                "TCP 乱序缓冲超过 64 MiB，请缩短采集或检查丢包"
            );
        }
    }
    if let Some(w) = writer.as_mut() {
        w.flush()?;
    }
    Ok(result)
}
fn classify(
    p: &Packet<'_>,
    exact: &HashMap<FlowKey, ()>,
    wildcard: &[&Connection],
    servers: &[Server],
) -> Option<bool> {
    if exact.contains_key(&(p.protocol, p.source, p.destination)) {
        return Some(true);
    }
    if exact.contains_key(&(p.protocol, p.destination, p.source)) {
        return Some(false);
    }
    for c in wildcard {
        if (p.protocol == 6) != (c.transport == "tcp") {
            continue;
        }
        if p.source.port() == c.local.port() && p.destination == c.remote {
            return Some(true);
        }
        if p.destination.port() == c.local.port() && p.source == c.remote {
            return Some(false);
        }
    }
    let is_server = |addr: SocketAddr| {
        servers
            .iter()
            .any(|s| s.ip == addr.ip() && s.port.is_none_or(|port| port == addr.port()))
    };
    match (is_server(p.source), is_server(p.destination)) {
        (true, false) => Some(false),
        (false, true) => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quantiles() {
        let s = stats(&[1, 2, 3, 4]);
        assert_eq!(s.p50, 2);
        assert_eq!(s.p99, 4);
        assert_eq!(s.mean, 2.5);
        assert_eq!(stats(&[]).count, 0);
    }
}
