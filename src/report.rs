use crate::{
    analysis::{Analysis, Stats, stats},
    padding::Recommendation,
    session::Session,
};
use anyhow::Result;
use serde_json::json;
use std::{fmt::Write as _, fs, io::Write, path::Path};

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap_or(Path::new(".")))?;
    file.write_all(data)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}
pub fn save_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(value)?)
}

pub fn write_report(
    directory: &Path,
    analysis: &Analysis,
    session: Option<&Session>,
    recommendation: &Recommendation,
) -> Result<()> {
    let up_tls: Vec<_> = analysis
        .flows
        .iter()
        .flat_map(|f| f.up.tls.record_lengths.iter().copied())
        .collect();
    let down_tls: Vec<_> = analysis
        .flows
        .iter()
        .flat_map(|f| f.down.tls.record_lengths.iter().copied())
        .collect();
    let summary = json!({
        "schema_version":1,"generator":concat!("capture-rs ",env!("CARGO_PKG_VERSION")),
        "session":session,
        "summary":{"packets_scanned":analysis.packets_scanned,"packets_matched":analysis.packets_matched,"connections":analysis.flows.len(),
            "attribution":analysis.attribution,"truncated_packets":analysis.truncated_packets,"fragmented_packets":analysis.fragmented_packets,
            "malformed_packets":analysis.malformed_packets,"oversized_ip_packets":analysis.oversized_ip_packets,
            "up_ip":stats(&analysis.up.ip_lengths),"down_ip":stats(&analysis.down.ip_lengths),
            "up_tcp_payload":stats(&analysis.up.tcp_payload_lengths),"down_tcp_payload":stats(&analysis.down.tcp_payload_lengths),
            "up_udp_payload":stats(&analysis.up.udp_payload_lengths),"down_udp_payload":stats(&analysis.down.udp_payload_lengths),
            "up_tls_record":stats(&up_tls),"down_tls_record":stats(&down_tls)},
        "flows":analysis.flows,"padding":recommendation
    });
    save_json(&directory.join("report.json"), &summary)?;
    let mut text = String::new();
    writeln!(
        text,
        "╔══════════════════════════════════════════════════════════════╗\n║            YJ PADDING · Chrome 流量分析报告                   ║\n╚══════════════════════════════════════════════════════════════╝\n"
    )?;
    if let Some(s) = session {
        writeln!(
            text,
            "目标：{}\n浏览器：{}\nUA：{}\n模式：{} / {}\n",
            s.target,
            s.browser.browser_version,
            s.browser.user_agent,
            s.settings["browser"],
            s.settings["protocol"]
        )?;
        writeln!(
            text,
            "网页请求：{}  主页面成功：{}  导航次数：{}  用时：{:.1}s",
            s.browser.requests.len(),
            s.browser.successful_documents(),
            s.browser.navigations,
            s.elapsed_seconds
        )?;
        writeln!(
            text,
            "抓包内核丢包：{}  网卡丢包：{}  大小上限：{}  中断：{}",
            s.capture.kernel_dropped,
            s.capture.interface_dropped,
            s.capture.size_limit_reached,
            s.interrupted
        )?;
        if let Some(e) = &s.runtime_error {
            writeln!(text, "运行问题：{e}")?;
        }
    }
    writeln!(
        text,
        "匹配包：{}  连接：{}  关联方式：{}",
        analysis.packets_matched,
        analysis.flows.len(),
        analysis.attribution
    )?;
    writeln!(
        text,
        "截断：{}  IP 分片跳过：{}  非法包：{}",
        analysis.truncated_packets, analysis.fragmented_packets, analysis.malformed_packets
    )?;
    writeln!(
        text,
        "\n长度统计（字节）\n类别                       样本      p25      p50      p95      最大       均值"
    )?;
    for (name, s) in [
        ("上行 IP 总长", stats(&analysis.up.ip_lengths)),
        ("下行 IP 总长", stats(&analysis.down.ip_lengths)),
        ("上行 TCP payload", stats(&analysis.up.tcp_payload_lengths)),
        (
            "下行 TCP payload",
            stats(&analysis.down.tcp_payload_lengths),
        ),
        ("上行 UDP payload", stats(&analysis.up.udp_payload_lengths)),
        (
            "下行 UDP payload",
            stats(&analysis.down.udp_payload_lengths),
        ),
        ("上行 TLS record", stats(&up_tls)),
        ("下行 TLS record", stats(&down_tls)),
    ] {
        write_stats(&mut text, name, &s)?;
    }
    writeln!(
        text,
        "\n口径：IP 总长包含 IP/传输头；TCP/UDP payload 排除头部，TCP 包级统计包含重传。\nTLS record 为重组去重后的 record body 长度，排除 5 字节头，包含加密开销。\nUDP 单独统计，不按 TLS-over-TCP 解读；HTTP/3 以 Chrome 记录为准。"
    )?;
    histogram(&mut text, "上行 TLS record 分布", &up_tls)?;
    histogram(&mut text, "下行 TLS record 分布", &down_tls)?;
    if analysis.oversized_ip_packets > 0 {
        writeln!(
            text,
            "观察到 {} 个超过 1500 字节的 IP 包；本机分段/聚合卸载或链路 MTU 会影响包长，不能据此推断线上 MTU。",
            analysis.oversized_ip_packets
        )?;
    }
    writeln!(
        text,
        "\n连接明细（上/下行重组唯一字节、重传字节、TLS record 数）"
    )?;
    for f in analysis.flows.iter().take(100) {
        writeln!(
            text,
            "{} {} → {} | bytes {}/{} | duplicate {}/{} | TLS {}/{} | 完整重组 {}/{}",
            f.transport,
            f.client,
            f.server,
            f.up.unique_bytes,
            f.down.unique_bytes,
            f.up.duplicate_bytes,
            f.down.duplicate_bytes,
            f.up.tls.record_lengths.len(),
            f.down.tls.record_lengths.len(),
            f.up.complete(),
            f.down.complete()
        )?;
    }
    if analysis.flows.len() > 100 {
        writeln!(text, "其余连接见 report.json")?;
    }
    writeln!(
        text,
        "\nAnyTLS 候选配置：{}\n{}\n有效连接：{}  样本：{}",
        recommendation.status,
        recommendation.reason,
        recommendation.qualified_connections,
        recommendation.samples
    )?;
    if let Some(scheme) = &recommendation.scheme {
        writeln!(text, "\n{scheme}")?;
        writeln!(
            text,
            "模型估算平均附加字节：{:.1}；附加比例：{:.1}%",
            recommendation.estimated_mean_added_bytes.unwrap_or(0.0),
            recommendation.estimated_added_ratio.unwrap_or(0.0) * 100.0
        )?;
        atomic_write(&directory.join("padding-candidate.txt"), scheme.as_bytes())?;
    }
    for line in &recommendation.assumptions {
        writeln!(text, "• {line}")?;
    }
    writeln!(text, "协议参考：{}", recommendation.protocol_reference)?;
    if let Some(s) = session {
        writeln!(
            text,
            "\n请求明细（最多展示 100 条，完整记录见 session.json）"
        )?;
        for r in s.browser.requests.iter().take(100) {
            writeln!(
                text,
                "{} {} {} {} {}",
                r.method,
                r.status.map(|s| s.to_string()).unwrap_or("—".into()),
                r.protocol.as_deref().unwrap_or("—"),
                r.url,
                r.error.as_deref().unwrap_or("")
            )?;
        }
    }
    atomic_write(&directory.join("report.txt"), text.as_bytes())?;
    ensure_report_exists(directory)?;
    Ok(())
}
fn write_stats(text: &mut String, name: &str, s: &Stats) -> std::fmt::Result {
    if s.count == 0 {
        return writeln!(text, "{name:<24} 无样本");
    }
    writeln!(
        text,
        "{name:<24} {:>7} {:>8} {:>8} {:>8} {:>8} {:>10.1}",
        s.count, s.p25, s.p50, s.p95, s.max, s.mean
    )
}
fn ensure_report_exists(directory: &Path) -> Result<()> {
    anyhow::ensure!(
        fs::metadata(directory.join("report.txt"))?.len() > 0,
        "报告未写入"
    );
    Ok(())
}

fn histogram(text: &mut String, title: &str, values: &[usize]) -> std::fmt::Result {
    if values.is_empty() {
        return Ok(());
    }
    let min = *values.iter().min().unwrap();
    let max = *values.iter().max().unwrap();
    let width = (max - min + 1).div_ceil(12).max(1);
    let mut counts = [0usize; 12];
    for &v in values {
        counts[((v - min) / width).min(11)] += 1;
    }
    let largest = *counts.iter().max().unwrap();
    writeln!(text, "\n{title}")?;
    for (i, &count) in counts.iter().enumerate() {
        let lo = min + i * width;
        if lo > max {
            break;
        }
        writeln!(
            text,
            "{:>5}–{:<5} {:<24} {:>6} ({:>5.1}%)",
            lo,
            (lo + width - 1).min(max),
            "█".repeat(count * 24 / largest),
            count,
            count as f64 / values.len() as f64 * 100.0
        )?;
    }
    Ok(())
}
