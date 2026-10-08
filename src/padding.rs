use crate::analysis::{Analysis, stats};
use anyhow::{Result, bail, ensure};
use serde::Serialize;
use std::collections::BTreeMap;

pub const REFERENCE: &str = "https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/docs/protocol.md";
#[derive(Debug, Serialize)]
pub struct Recommendation {
    pub status: String,
    pub reason: String,
    pub qualified_connections: usize,
    pub samples: usize,
    pub scheme: Option<String>,
    pub estimated_mean_added_bytes: Option<f64>,
    pub estimated_added_ratio: Option<f64>,
    pub assumptions: Vec<String>,
    pub protocol_reference: &'static str,
    pub validation: Option<serde_json::Value>,
}

#[derive(Debug, PartialEq)]
pub enum Token {
    Range(u16, u16),
    Check,
}
pub fn validate(text: &str) -> Result<BTreeMap<usize, Vec<Token>>> {
    ensure!(text.len() <= 64 * 1024, "配置太大");
    let mut fields = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|s| !s.is_empty()) {
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("缺少 =: {line}"))?;
        ensure!(!fields.contains_key(k), "重复字段 {k}");
        fields.insert(k, v);
    }
    let stop: usize = fields
        .remove("stop")
        .ok_or_else(|| anyhow::anyhow!("缺少 stop"))?
        .parse()?;
    ensure!((1..=64).contains(&stop), "stop 必须在 1–64");
    let mut result = BTreeMap::new();
    for (key, value) in fields {
        let i: usize = key.parse()?;
        ensure!(i < stop, "规则 {i} 超出 stop 范围");
        let mut tokens = Vec::new();
        for part in value.split(',') {
            if part == "c" {
                ensure!(
                    i != 0 && !tokens.is_empty() && !matches!(tokens.last(), Some(Token::Check)),
                    "c 位置不合法"
                );
                tokens.push(Token::Check);
            } else {
                let (lo, hi) = part
                    .split_once('-')
                    .ok_or_else(|| anyhow::anyhow!("无效区间 {part}"))?;
                let lo: u16 = lo.parse()?;
                let hi: u16 = hi.parse()?;
                ensure!(
                    lo > 0 && lo <= hi && hi <= 16384,
                    "区间需满足 1 ≤ 下界 ≤ 上界 ≤ 16384"
                );
                tokens.push(Token::Range(lo, hi));
            }
        }
        ensure!(
            !tokens.is_empty() && !matches!(tokens.last(), Some(Token::Check)),
            "规则不能以 c 结尾"
        );
        ensure!(tokens.len() <= 31, "单条规则过长");
        ensure!(
            i != 0 || tokens.len() == 1,
            "padding0 为认证填充，不支持分包"
        );
        ensure!(result.insert(i, tokens).is_none(), "重复规则序号 {i}");
    }
    ensure!(result.contains_key(&0), "缺少认证填充规则 0");
    Ok(result)
}

pub fn recommend(a: &Analysis, quality_ok: bool) -> Recommendation {
    let mut samples = Vec::new();
    let mut n = 0;
    for f in &a.flows {
        // TLS 1.3 overhead estimate is meaningful only after an observed ServerHello.
        if f.transport == "tcp"
            && f.up.complete()
            && f.down.complete()
            && f.up.tls.client_hellos > 0
            && f.down.tls.tls13
            && !f.up.tls.encrypted_lengths.is_empty()
            && !f.down.tls.encrypted_lengths.is_empty()
        {
            n += 1;
            samples.extend(
                f.up.tls
                    .encrypted_lengths
                    .iter()
                    .filter(|&&v| v >= 17)
                    .map(|&v| v - 17),
            );
        }
    }
    let mut r=Recommendation {status:"insufficient_evidence".into(),reason:String::new(),qualified_connections:n,samples:samples.len(),scheme:None,
        estimated_mean_added_bytes:None,estimated_added_ratio:None,protocol_reference:REFERENCE,validation:None,
        assumptions:vec![
            "候选配置是启发式；浏览器 TLS record 与 AnyTLS Write 调用并非一一对应，不能由 pcap 恢复 Write 边界。".into(),
            "仅采用完整重组且观察到 TLS 1.3 ServerHello 的上行连接；record 长度减去 16 字节 AEAD tag 和 1 字节内部类型，假设无额外 TLS padding。".into(),
            "加密 record 可能包含握手消息，未解密时不会将其标注为 HTTP 请求或 Finished。".into(),
            "padding0 固定采用协议默认认证填充 30；padding1 使用默认控制帧区间，二者不从网站包长反推。".into(),
            "开销仅模拟样本作为单次写入、单段填充的平均增量，不包含认证、TLS/TCP 头、额外记录及实际复用影响。".into(),
            "自动互通测试的范围以 validation 字段为准；本机参考实现通过不代表其他实现、生产节点或流量相似性已经验证。".into(),
        ]};
    if !quality_ok || a.truncated_packets > 0 || a.fragmented_packets > 0 || a.malformed_packets > 0
    {
        r.reason =
            "采集不完整、被中断、存在丢包/解析问题或页面访问失败，保留统计但不生成候选".into();
        return r;
    }
    if a.attribution != "chrome_netlog_socket" {
        r.reason = "离线仅按服务器过滤，缺少 Chrome 会话关联，暂不生成候选".into();
        return r;
    }
    if n < 3 || samples.len() < 20 {
        r.reason = format!(
            "需要至少 3 条完整 TLS 1.3 连接和 20 个上行加密 record；当前 {n} 条 / {} 个",
            samples.len()
        );
        return r;
    }
    let s = stats(&samples);
    // Bounded single-fragment rules avoid invented MTU/phase mappings.
    let lo = s.p25.clamp(64, 4096);
    let hi = s.p75.clamp(lo, 8192);
    let scheme = format!(
        "stop=8\n0=30-30\n1=100-400\n2={lo}-{hi}\n3={lo}-{hi}\n4={lo}-{hi}\n5={lo}-{hi}\n6={lo}-{hi}\n7={lo}-{hi}\n"
    );
    if let Err(error) = validate(&scheme) {
        r.status = "internal_validation_failure".into();
        r.reason = error.to_string();
        return r;
    }
    // The upstream generator uses a half-open random interval [lo,hi), unless equal.
    let mut added = 0f64;
    for &length in &samples {
        let start = lo.max(length + 1);
        if lo == hi {
            added += lo.saturating_sub(length) as f64;
        } else if start < hi {
            let count = (hi - start) as f64;
            added += count * ((start - length) + (hi - 1 - length)) as f64 / 2.0 / (hi - lo) as f64;
        }
    }
    let total = samples.iter().sum::<usize>() as f64;
    r.status = "experimental_candidate".into();
    r.reason =
        "满足最低采样门槛，已通过本地严格语法检查；须使用目标 AnyTLS 实现进行部署前验证".into();
    r.estimated_mean_added_bytes = Some(added / samples.len() as f64);
    r.estimated_added_ratio = Some(if total > 0.0 { added / total } else { 0.0 });
    r.scheme = Some(scheme);
    r
}

pub fn validate_file(path: &std::path::Path) -> Result<()> {
    if std::fs::metadata(path)?.len() > 65536 {
        bail!("配置文件超过 64 KiB");
    }
    let text = std::fs::read_to_string(path)?;
    let rules = validate(&text)?;
    println!(
        "✓ 语法及边界检查通过，共 {} 条规则。部署效果需另行验证。",
        rules.len()
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn valid_reference() {
        assert!(validate("stop=3\n0=30-30\n1=100-400\n2=400-500,c,500-1000").is_ok());
    }
    #[test]
    fn reject_invalid() {
        for text in [
            "stop=8\n0=1-2,c,3-4",
            "stop=8\n0=0-1",
            "stop=8\n0=1-2\n8=2-3",
            "stop=8\n0=1-2\n0=1-3",
            "stop=-1\n0=1-2",
            "stop=1\n0=2-1",
        ] {
            assert!(validate(text).is_err(), "{text}");
        }
    }
}
