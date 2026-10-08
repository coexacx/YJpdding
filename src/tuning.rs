//! Bounded, connection-balanced sampling and empirical loopback TLS comparison.
//! Browser record positions are reference observations, NOT inferred AnyTLS Write boundaries.
use crate::{
    analysis::{self, Analysis, stats},
    capture::CaptureTask,
    padding, report, retention,
    session::Connection,
    validation,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use url::Url;

const POSITIONS: usize = 8;
const MAX_FLOWS: usize = 128;
const MIN_FLOWS: usize = 6;
const DEFAULT: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000\n";
const SCOPE: &str = "网站 TLS record 长度序列驱动的本机 AnyTLS 负载；实际 pcap 重组后比较上行 TLS record，不是公网 TCP 包长或完整浏览器流量指纹验证。记录位置不等于网站应用 Write 边界；未解密，可能包含加密握手。";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowSample {
    pub up: Vec<usize>,
    pub down: Vec<usize>,
    pub up_later: Vec<usize>,
    pub down_later: Vec<usize>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundSample {
    pub directory: String,
    pub quality_ok: bool,
    pub qualified_connections: usize,
    pub packets: u64,
    pub flows: Vec<FlowSample>,
}
fn evenly<T: Clone>(items: &[T], count: usize) -> Vec<T> {
    if items.len() <= count {
        return items.to_vec();
    }
    (0..count)
        .map(|i| items[i * (items.len() - 1) / (count - 1)].clone())
        .collect()
}
impl RoundSample {
    pub fn extract(a: &Analysis, good: bool, directory: &Path) -> Self {
        let qualified: Vec<_> = a
            .flows
            .iter()
            .filter(|f| {
                f.transport == "tcp"
                    && f.up.complete()
                    && f.down.complete()
                    && f.up.tls.client_hellos > 0
                    && f.down.tls.tls13
                    && f.up.tls.encrypted_lengths.len() >= 3
                    && !f.down.tls.encrypted_lengths.is_empty()
                    && f.up
                        .tls
                        .encrypted_lengths
                        .iter()
                        .chain(&f.down.tls.encrypted_lengths)
                        .all(|v| (17..=16640).contains(v))
            })
            .collect();
        let flows = evenly(&qualified, MAX_FLOWS)
            .iter()
            .map(|f| {
                fn direction(v: &[usize]) -> (Vec<usize>, Vec<usize>) {
                    let v: Vec<_> = v
                        .iter()
                        .copied()
                        .filter(|v| (17..=16640).contains(v))
                        .collect();
                    (
                        v.iter().take(POSITIONS).copied().collect(),
                        evenly(v.get(POSITIONS..).unwrap_or(&[]), POSITIONS),
                    )
                }
                let (up, up_later) = direction(&f.up.tls.encrypted_lengths);
                let (down, down_later) = direction(&f.down.tls.encrypted_lengths);
                FlowSample {
                    up,
                    down,
                    up_later,
                    down_later,
                }
            })
            .collect();
        Self {
            directory: directory.display().to_string(),
            quality_ok: good && a.attribution == "chrome_netlog_socket",
            qualified_connections: qualified.len(),
            packets: a.packets_matched as u64,
            flows,
        }
    }
}
#[derive(Clone, Serialize)]
struct Candidate {
    id: String,
    scheme: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Trace {
    id: String,
    partition: String,
    round: usize,
    target: Vec<usize>,
    payload: Vec<usize>,
}

// A round has total weight 1, and each connection contributes at most once per position.
fn quantile(rounds: &[RoundSample], position: usize, q: f64) -> Option<usize> {
    let mut values = Vec::new();
    for round in rounds {
        let lengths: Vec<_> = round
            .flows
            .iter()
            .filter_map(|f| f.up.get(position).copied())
            .collect();
        if lengths.len() < 2 {
            return None;
        }
        let weight = 1.0 / lengths.len() as f64 / rounds.len() as f64;
        values.extend(lengths.into_iter().map(|v| (v, weight)));
    }
    if values.len() < MIN_FLOWS {
        return None;
    }
    values.sort_unstable_by_key(|v| v.0);
    let mut sum = 0.0;
    for (v, w) in values.iter() {
        sum += w;
        if sum + 1e-12 >= q {
            return Some(*v);
        }
    }
    values.last().map(|v| v.0)
}
fn candidates(training: &[RoundSample]) -> Result<Vec<Candidate>> {
    let mut result = vec![Candidate {
        id: "default".into(),
        scheme: DEFAULT.into(),
    }];
    for (id, low, high) in [("position-iqr", 0.25, 0.75), ("position-wide", 0.10, 0.90)] {
        let mut rules = Vec::new();
        for position in 0..POSITIONS {
            let Some((lo, hi)) =
                quantile(training, position, low).zip(quantile(training, position, high))
            else {
                break;
            };
            // These are candidate plaintext target sizes only; the empirical test includes
            // the real frame headers, waste records and TLS expansion of this implementation.
            let lo = lo.saturating_sub(17).clamp(8, 16384);
            let hi = hi.saturating_sub(17).clamp(lo, 16384);
            rules.push(format!("{}={lo}-{hi}\n", position + 2));
        }
        ensure!(
            rules.len() >= 3,
            "每个训练轮需至少 6 条合格连接，且前 3 个发送位置具有足够样本"
        );
        let scheme = format!(
            "stop={}\n0=30-30\n1=100-400\n{}",
            rules.len() + 2,
            rules.concat()
        );
        padding::validate(&scheme)?;
        if !result.iter().any(|c| c.scheme == scheme) {
            result.push(Candidate {
                id: id.into(),
                scheme,
            });
        }
    }
    Ok(result)
}
fn traces(rounds: &[RoundSample]) -> Vec<Trace> {
    let mut result = Vec::new();
    for (round, sample) in rounds.iter().enumerate() {
        // Six quantile representatives (two per size third), equal weight per round.
        let mut flows: Vec<_> = sample.flows.iter().filter(|f| f.up.len() >= 3).collect();
        flows.sort_by_key(|f| f.up.iter().sum::<usize>() / f.up.len());
        for (stratum, percent) in [8, 25, 41, 58, 75, 91].iter().enumerate() {
            let index = (flows.len() * percent / 100).min(flows.len() - 1);
            let target = flows[index].up.clone();
            let payload = target
                .iter()
                .map(|v| v.saturating_sub(17).clamp(1, 16384))
                .collect();
            result.push(Trace {
                id: format!("r{}-s{}", round + 1, stratum + 1),
                partition: if round + 1 == rounds.len() {
                    "holdout"
                } else {
                    "train"
                }
                .into(),
                round: round + 1,
                target,
                payload,
            });
        }
    }
    result
}
fn strata(rounds: &[RoundSample]) -> Value {
    let mut summaries = Vec::new();
    for (r, round) in rounds.iter().enumerate() {
        let mut directions = Vec::new();
        for up in [true, false] {
            let positions: Vec<_> = (0..POSITIONS)
                .map(|p| {
                    let v: Vec<_> = round
                        .flows
                        .iter()
                        .filter_map(|f| if up { f.up.get(p) } else { f.down.get(p) })
                        .copied()
                        .collect();
                    json!({"ordinal":p+1,"stats":stats(&v)})
                })
                .collect();
            let later: Vec<_> = round
                .flows
                .iter()
                .flat_map(|f| if up { &f.up_later } else { &f.down_later })
                .copied()
                .collect();
            directions.push(json!({"direction":if up{"up"}else{"down"},"early_positions":positions,"later_balanced_sample":stats(&later)}));
        }
        summaries.push(json!({"round":r+1,"role":if r+1==rounds.len(){"holdout"}else{"train"},"connections":round.qualified_connections,"retained_connections":round.flows.len(),"directions":directions}));
    }
    json!({"record_unit":"TLS encrypted record body, including encryption overhead, excluding 5-byte header","max_connections_per_round":MAX_FLOWS,"max_early_records_per_connection":POSITIONS,"rounds":summaries,"scope":SCOPE})
}
#[derive(Deserialize)]
struct Benchmark {
    status: String,
    cleanup_ok: bool,
    #[serde(default)]
    runs: Vec<Run>,
    error: Option<String>,
}
#[derive(Deserialize)]
struct Run {
    candidate: String,
    trace: String,
    repetition: usize,
    local: std::net::SocketAddr,
    remote: std::net::SocketAddr,
    up_records: Vec<usize>,
    windows: Vec<Window>,
    payload_bytes: usize,
    data_ok: bool,
    scheme_confirmed: bool,
}
#[derive(Deserialize)]
struct Window {
    begin: usize,
    end: usize,
    seconds: f64,
}
#[derive(Clone, Debug, Default, Serialize)]
struct Metric {
    streams: usize,
    score: f64,
    ks: f64,
    log_distance: f64,
    position_error: f64,
    record_count_error: f64,
    small_share: f64,
    large_share: f64,
    target_small_share: f64,
    target_large_share: f64,
    payload_bytes: usize,
    measured_tls_bytes: usize,
    wire_to_payload: f64,
    p95_write_rtt_ms: f64,
}
fn cdf_distance(a: &[usize], b: &[usize]) -> f64 {
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort_unstable();
    b.sort_unstable();
    let (mut i, mut j, mut distance) = (0, 0, 0.0f64);
    while i < a.len() || j < b.len() {
        let v = a
            .get(i)
            .copied()
            .unwrap_or(usize::MAX)
            .min(b.get(j).copied().unwrap_or(usize::MAX));
        while i < a.len() && a[i] <= v {
            i += 1;
        }
        while j < b.len() && b[j] <= v {
            j += 1;
        }
        distance = distance.max((i as f64 / a.len() as f64 - j as f64 / b.len() as f64).abs());
    }
    distance
}
fn metric(
    runs: &[&Run],
    traces: &HashMap<&str, &Trace>,
    small: usize,
    large: usize,
) -> Result<Metric> {
    ensure!(!runs.is_empty(), "缺少测试流");
    let (mut actual, mut target, mut positions, mut latency) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut payload, mut wire) = (0, 0);
    for run in runs {
        let trace = traces[run.trace.as_str()];
        ensure!(run.windows.len() == trace.target.len(), "测试写入位置缺失");
        for (window, wanted) in run.windows.iter().zip(&trace.target) {
            ensure!(
                window.seconds.is_finite() && window.seconds >= 0.0,
                "实测耗时无效"
            );
            ensure!(
                window.end > window.begin && window.end <= run.up_records.len(),
                "实测 TLS 记录窗口缺失"
            );
            let observed = &run.up_records[window.begin..window.end];
            actual.extend_from_slice(observed);
            target.push(*wanted);
            wire += observed.iter().map(|v| v + 5).sum::<usize>();
            positions.push(
                ((observed.iter().sum::<usize>() as f64 + 1.0) / (*wanted as f64 + 1.0))
                    .ln()
                    .abs()
                    / 16385f64.ln(),
            );
            latency.push(window.seconds);
        }
        payload += run.payload_bytes;
    }
    actual.sort_unstable();
    target.sort_unstable();
    latency.sort_by(f64::total_cmp);
    let ks = cdf_distance(&actual, &target);
    let log_distance = (0..101)
        .map(|i| {
            let a = actual[i * (actual.len() - 1) / 100] as f64 + 1.0;
            let b = target[i * (target.len() - 1) / 100] as f64 + 1.0;
            (a.ln() - b.ln()).abs() / 16385f64.ln()
        })
        .sum::<f64>()
        / 101.0;
    let position_error = positions.iter().sum::<f64>() / positions.len() as f64;
    let record_count_error = (actual.len() as f64 / target.len() as f64 - 1.0)
        .abs()
        .min(1.0);
    let share = |v: &[usize], low: bool| {
        v.iter()
            .filter(|&&v| if low { v <= small } else { v >= large })
            .count() as f64
            / v.len() as f64
    };
    Ok(Metric {
        streams: runs.len(),
        score: 0.4 * ks + 0.3 * log_distance + 0.2 * position_error + 0.1 * record_count_error,
        ks,
        log_distance,
        position_error,
        record_count_error,
        small_share: share(&actual, true),
        large_share: share(&actual, false),
        target_small_share: share(&target, true),
        target_large_share: share(&target, false),
        payload_bytes: payload,
        measured_tls_bytes: wire,
        wire_to_payload: wire as f64 / payload as f64,
        p95_write_rtt_ms: latency[(latency.len() * 95).div_ceil(100).saturating_sub(1)] * 1000.0,
    })
}
#[derive(Serialize)]
struct Evaluation {
    id: String,
    train: Metric,
    holdout: Metric,
    holdout_repetitions: Vec<Metric>,
}
fn better(candidate: &Metric, baseline: &Metric) -> bool {
    candidate.score + 0.01 <= baseline.score
        && candidate.score <= baseline.score * 0.95
        && candidate.measured_tls_bytes as f64 <= baseline.measured_tls_bytes as f64 * 1.10
        && candidate.p95_write_rtt_ms <= (baseline.p95_write_rtt_ms * 3.0).max(50.0)
}
fn choose(evaluations: &[Evaluation]) -> (&str, &'static str) {
    let base = &evaluations[0];
    let best = evaluations
        .iter()
        .skip(1)
        .filter(|e| better(&e.train, &base.train))
        .min_by(|a, b| a.train.score.total_cmp(&b.train.score));
    if let Some(best) = best {
        // Select using training results ONLY. Holdout may accept/reject that single winner.
        if better(&best.holdout, &base.holdout)
            && best
                .holdout_repetitions
                .iter()
                .zip(&base.holdout_repetitions)
                .all(|(c, b)| better(c, b))
        {
            return (
                &best.id,
                "训练最优候选在独立复核轮及两次重复实测中均改善，开销和延迟满足限制",
            );
        }
        return (
            "default",
            "训练最优候选未通过独立复核或开销限制，保留默认配置",
        );
    }
    ("default", "候选在训练实测中未达到改善门槛，保留默认配置")
}

pub fn optimize(
    rounds: &[RoundSample],
    url: &Url,
    output: &Path,
    cancel: &Arc<AtomicBool>,
) -> Result<i32> {
    ensure!(rounds.len() >= 3, "至少需要 3 个独立采样轮");
    report::save_json(&output.join("strata.json"), &strata(rounds))?;
    ensure!(
        rounds
            .iter()
            .all(|r| r.quality_ok && r.flows.len() >= MIN_FLOWS),
        "多轮优化需要每轮至少 6 条完整且质量合格的 TLS 1.3 连接；请增加 --duration，原始抓包已保留"
    );
    let candidates = candidates(&rounds[..rounds.len() - 1])?;
    let traces = traces(rounds);
    let reference: Vec<_> = traces
        .iter()
        .filter(|t| t.partition == "train")
        .flat_map(|t| t.target.iter().copied())
        .collect();
    let distribution = stats(&reference);
    let (small, large) = (distribution.p25, distribution.p75.max(distribution.p25 + 1));
    let manifest = json!({"schema_version":1,"candidates":candidates,"traces":traces,"repetitions":2,
        "scope":SCOPE,"thresholds":{"small_at_most":small,"large_at_least":large},"selection_policy":{"minimum_absolute_improvement":0.01,"minimum_relative_improvement":0.05,"max_bytes_vs_default":1.10}});
    let file = output.join("calibration-input.json");
    report::save_json(&file, &manifest)?;
    println!(
        "\n实测筛选：{} 组配置 × 2 次重复 · 仅本机临时 AnyTLS 节点",
        candidates.len()
    );
    let staging = tempfile::Builder::new()
        .prefix(".calibration-")
        .suffix(".pcap")
        .tempfile_in(output)?;
    let mut capture = CaptureTask::start("lo", staging.path(), 64 * 1024 * 1024, 0)?;
    let result = output.join("calibration-runtime.json");
    let mut command = Command::new("python3");
    command
        .arg(validation::helper("calibrate.py")?)
        .arg("--input")
        .arg(&file)
        .arg("--result")
        .arg(&result)
        .arg("--state-dir")
        .arg(retention::state_dir()?);
    let execution = validation::run_helper(
        &mut command,
        &output.join("calibration.log"),
        Duration::from_secs(95),
        cancel,
    );
    thread::sleep(Duration::from_millis(150));
    let captured = capture.finish()?;
    report::save_json(&output.join("calibration-capture.json"), &captured)?;
    execution?;
    let benchmark: Benchmark = serde_json::from_slice(&fs::read(&result)?)?;
    ensure!(
        benchmark.status == "passed" && benchmark.cleanup_ok,
        "实测节点失败或清理未完成：{:?}",
        benchmark.error
    );
    ensure!(
        !captured.size_limit_reached
            && captured.kernel_dropped == 0
            && captured.interface_dropped == 0,
        "本机比对抓包不完整，拒绝推荐"
    );
    ensure!(
        benchmark.runs.len() == candidates.len() * traces.len() * 2,
        "实测数量不完整"
    );
    let connections: Vec<_> = benchmark
        .runs
        .iter()
        .enumerate()
        .map(|(i, r)| Connection {
            local: r.local,
            remote: r.remote,
            transport: "tcp".into(),
            source_id: i as u64,
            attribution: "owned_loopback_anytls".into(),
        })
        .collect();
    let pcap = output.join(format!(
        "{}-anytls-comparison.pcap",
        retention::site_name(url)
    ));
    let analysis = analysis::analyze(staging.path(), &connections, &[], Some(&pcap))?;
    ensure!(
        analysis.truncated_packets + analysis.malformed_packets + analysis.fragmented_packets == 0,
        "实测报文存在解析错误"
    );
    let lookup: HashMap<_, _> = analysis
        .flows
        .iter()
        .map(|f| ((f.client, f.server), f))
        .collect();
    let trace_lookup: HashMap<_, _> = traces.iter().map(|t| (t.id.as_str(), t)).collect();
    let mut unique = std::collections::HashSet::new();
    for run in &benchmark.runs {
        ensure!(
            run.repetition < 2 && candidates.iter().any(|c| c.id == run.candidate),
            "未知配置或重复轮数"
        );
        ensure!(
            run.local.ip().is_loopback() && run.remote.ip().is_loopback(),
            "测试连接不在回环接口"
        );
        ensure!(
            run.data_ok && run.scheme_confirmed,
            "配置同步或双向传输未验证"
        );
        ensure!(
            unique.insert((&run.candidate, &run.trace, run.repetition)),
            "重复实测标识"
        );
        let trace = trace_lookup
            .get(run.trace.as_str())
            .context("未知负载标识")?;
        ensure!(
            run.payload_bytes == trace.payload.iter().sum::<usize>(),
            "实测负载长度不符"
        );
        let flow = lookup
            .get(&(run.local, run.remote))
            .context("未在 pcap 找到测试连接")?;
        ensure!(
            flow.up.complete() && flow.down.complete() && flow.down.tls.tls13,
            "测试连接未完整重组为 TLS 1.3"
        );
        // Tap labels windows, but only an exact match of the independently captured
        // record sequence is accepted as evidence for scoring.
        ensure!(
            flow.up.tls.encrypted_lengths == run.up_records,
            "pcap 与测试记录不一致，拒绝评分"
        );
    }
    let mut evaluations = Vec::new();
    for candidate in &candidates {
        let subset = |partition: &str, repetition: Option<usize>| {
            benchmark
                .runs
                .iter()
                .filter(|r| {
                    r.candidate == candidate.id
                        && trace_lookup[r.trace.as_str()].partition == partition
                        && repetition.is_none_or(|v| v == r.repetition)
                })
                .collect::<Vec<_>>()
        };
        let train = metric(&subset("train", None), &trace_lookup, small, large)?;
        let holdout = metric(&subset("holdout", None), &trace_lookup, small, large)?;
        let repeats = (0..2)
            .map(|r| metric(&subset("holdout", Some(r)), &trace_lookup, small, large))
            .collect::<Result<Vec<_>>>()?;
        evaluations.push(Evaluation {
            id: candidate.id.clone(),
            train,
            holdout,
            holdout_repetitions: repeats,
        });
    }
    let (selected, reason) = choose(&evaluations);
    let scheme = &candidates.iter().find(|c| c.id == selected).unwrap().scheme;
    let validation = validation::verify_scheme(scheme, output, cancel);
    let verified = validation["status"] == "passed" && validation["cleanup_ok"] == true;
    let status = if !verified {
        "validation_failed"
    } else if selected == "default" {
        "baseline_retained"
    } else {
        "measured_candidate_selected"
    };
    let selected_report = json!({"schema_version":1,"generator":concat!("capture-rs ",env!("CARGO_PKG_VERSION")),"target":url,
        "status":status,"selected":selected,"reason":reason,"scope":SCOPE,"evaluations":evaluations,
        "validation":validation,"pcap":pcap.file_name().unwrap().to_string_lossy(),"strata":"strata.json",
        "scoring":{"lower_is_better":true,"formula":"0.4*KS + 0.3*log_quantile_distance + 0.2*position_error + 0.1*record_count_error",
        "position_basis":"observed encrypted record ordinal -> test payload write ordinal; not recovered website Write boundaries",
        "selection":"training picks one winner; independent holdout and both repeats must accept, otherwise default",
        "traffic_overhead":"measured uplink TLS record headers+bodies during payload windows; excludes initial authentication/handshake, TCP/IP and ACKs"}});
    report::save_json(&output.join("selection.json"), &selected_report)?;
    report::save_json(&output.join("report.json"), &selected_report)?;
    let mut text = format!(
        "YJ PADDING · 多轮采样与实测筛选\n目标：{url}\n轮数：{}（最后一轮为独立复核）\n状态：{status}\n选择：{selected}\n依据：{reason}\n\n配置                       训练分数    复核分数    TLS/负载比\n",
        rounds.len()
    );
    for evaluation in &evaluations {
        use std::fmt::Write;
        writeln!(
            text,
            "{:<26} {:.4}      {:.4}      {:.3}",
            evaluation.id,
            evaluation.train.score,
            evaluation.holdout.score,
            evaluation.holdout.wire_to_payload
        )?;
    }
    text.push_str(&format!("\n分数越低，长度分布越接近参考样本；只比较相同测试负载，不是公网相似性保证。\n{SCOPE}\n\n节点互通：{}\n临时节点清理：{}\n\n{scheme}",validation["status"],validation["cleanup_ok"]));
    report::atomic_write(&output.join("report.txt"), text.as_bytes())?;
    report::atomic_write(&output.join("padding-candidate.txt"), scheme.as_bytes())?;
    if verified {
        report::atomic_write(&output.join("padding-verified.txt"), scheme.as_bytes())?;
    }
    println!(
        "选择：{selected} · {reason}\n报告：{}",
        output.join("report.txt").display()
    );
    Ok(if cancel.load(Ordering::Relaxed) {
        130
    } else if verified {
        0
    } else {
        2
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn round(up: Vec<Vec<usize>>) -> RoundSample {
        RoundSample {
            directory: String::new(),
            quality_ok: true,
            qualified_connections: up.len(),
            packets: 100,
            flows: up
                .into_iter()
                .map(|up| FlowSample {
                    up,
                    down: vec![55, 1000],
                    up_later: vec![],
                    down_later: vec![],
                })
                .collect(),
        }
    }
    #[test]
    fn round_weights_and_positions() {
        let rounds = vec![
            round(vec![vec![100, 1000, 5000]; 6]),
            round(vec![vec![200, 2000, 10000]; 100]),
        ];
        assert_eq!(quantile(&rounds, 0, 0.25), Some(100));
        assert_eq!(quantile(&rounds, 1, 0.75), Some(2000));
        let candidates = candidates(&rounds).unwrap();
        assert!(
            candidates[1]
                .scheme
                .contains("2=83-183\n3=983-1983\n4=4983-9983")
        );
        assert!(
            candidates
                .iter()
                .all(|c| padding::validate(&c.scheme).is_ok())
        );
    }
    #[test]
    fn holdout_never_fits_rules() {
        let mut rounds = vec![round(vec![vec![80, 500, 1000]; 6]); 3];
        let before = candidates(&rounds[..2]).unwrap()[1].scheme.clone();
        rounds[2] = round(vec![vec![16000; 8]; 6]);
        assert_eq!(before, candidates(&rounds[..2]).unwrap()[1].scheme);
        assert!(
            traces(&rounds)
                .iter()
                .filter(|t| t.partition == "holdout")
                .all(|t| t.target == vec![16000; 8])
        );
    }
    #[test]
    fn cdf_handles_ties() {
        assert_eq!(cdf_distance(&[1, 1, 2], &[1, 1, 2]), 0.0);
        assert_eq!(cdf_distance(&[1, 1], &[2, 2]), 1.0);
    }
    #[test]
    fn scoring_penalizes_extra_records() {
        let t = Trace {
            id: "t".into(),
            partition: "train".into(),
            round: 1,
            target: vec![100, 1000],
            payload: vec![83, 983],
        };
        let traces = HashMap::from([("t", &t)]);
        let mut run = Run {
            candidate: "default".into(),
            trace: "t".into(),
            repetition: 0,
            local: "127.0.0.1:1".parse().unwrap(),
            remote: "127.0.0.1:2".parse().unwrap(),
            up_records: vec![100, 1000],
            windows: vec![
                Window {
                    begin: 0,
                    end: 1,
                    seconds: 0.001,
                },
                Window {
                    begin: 1,
                    end: 2,
                    seconds: 0.001,
                },
            ],
            payload_bytes: 1066,
            data_ok: true,
            scheme_confirmed: true,
        };
        assert_eq!(metric(&[&run], &traces, 100, 1000).unwrap().score, 0.0);
        run.up_records.push(500);
        run.windows[1].end = 3;
        assert!(metric(&[&run], &traces, 100, 1000).unwrap().score > 0.1);
    }
    fn evaluation(id: &str, train: f64, holdout: f64) -> Evaluation {
        let metric = |score| Metric {
            score,
            measured_tls_bytes: 1000,
            p95_write_rtt_ms: 1.0,
            ..Metric::default()
        };
        Evaluation {
            id: id.into(),
            train: metric(train),
            holdout: metric(holdout),
            holdout_repetitions: vec![metric(holdout); 2],
        }
    }
    #[test]
    fn selection_requires_independent_improvement() {
        let mut e = vec![
            evaluation("default", 0.4, 0.4),
            evaluation("candidate", 0.2, 0.2),
        ];
        assert_eq!(choose(&e).0, "candidate");
        e[1].holdout_repetitions[1].score = 0.39;
        assert_eq!(choose(&e).0, "default");
        e[1].holdout_repetitions[1].score = 0.2;
        e[1].holdout.measured_tls_bytes = 1200;
        assert_eq!(choose(&e).0, "default");
    }
    #[test]
    fn never_pick_runner_up_using_holdout() {
        let e = vec![
            evaluation("default", 0.4, 0.4),
            evaluation("train-winner", 0.1, 0.5),
            evaluation("runner-up", 0.2, 0.1),
        ];
        assert_eq!(choose(&e).0, "default");
    }
    #[test]
    fn insufficient_position_support_rejected() {
        assert!(candidates(&vec![round(vec![vec![80, 90, 100]; 2]); 2]).is_err());
    }
    #[test]
    fn balanced_later_samples() {
        assert_eq!(evenly(&[1, 2, 3, 4, 5, 6, 7, 8, 9], 3), vec![1, 5, 9]);
        assert!(evenly::<usize>(&[], 8).is_empty());
    }
}
