use crate::{browser::BrowserEvidence, capture::CaptureStats};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Connection {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub transport: String,
    pub source_id: u64,
    pub attribution: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub schema_version: u32,
    pub target: String,
    pub settings: Value,
    pub browser: BrowserEvidence,
    pub connections: Vec<Connection>,
    pub capture: CaptureStats,
    pub interrupted: bool,
    pub runtime_error: Option<String>,
    pub elapsed_seconds: f64,
    pub keylog_saved: bool,
    #[serde(default)]
    pub analysis_quality_errors: usize,
}

#[derive(Default)]
struct SocketEvidence {
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    transport: String,
}

fn endpoint(s: &Value) -> Option<SocketAddr> {
    s.as_str()?.parse().ok()
}

pub fn connections_from_netlog(path: &Path, evidence: &BrowserEvidence) -> Result<Vec<Connection>> {
    let len = fs::metadata(path)
        .context("Chrome 未生成 NetLog，无法进行精确连接关联")?
        .len();
    ensure!(len <= 256 * 1024 * 1024, "NetLog 超出 256 MiB 解析上限");
    let log: Value = serde_json::from_slice(&fs::read(path)?)
        .context("Chrome NetLog 不完整，无法进行可靠连接关联")?;
    let types: HashMap<u64, String> = log["constants"]["logEventTypes"]
        .as_object()
        .context("NetLog 缺少事件类型映射")?
        .iter()
        .filter_map(|(k, v)| v.as_u64().map(|v| (v, k.clone())))
        .collect();
    let urls: HashSet<&str> = evidence.requests.iter().map(|r| r.url.as_str()).collect();
    let remotes: HashSet<SocketAddr> = evidence
        .requests
        .iter()
        .filter_map(|r| {
            let ip: IpAddr = r
                .remote_ip
                .as_ref()?
                .trim_matches(['[', ']'])
                .parse()
                .ok()?;
            Some(SocketAddr::new(ip, r.remote_port?))
        })
        .collect();
    let events = log["events"].as_array().context("NetLog 缺少 events")?;
    let mut sockets: HashMap<u64, SocketEvidence> = HashMap::new();
    let mut edges: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut seeds = HashSet::new();
    for event in events {
        let Some(id) = event["source"]["id"].as_u64() else {
            continue;
        };
        let p = &event["params"];
        if p["url"].as_str().is_some_and(|u| urls.contains(u)) {
            seeds.insert(id);
        }
        if let Some(other) = p["source_dependency"]["id"].as_u64() {
            edges.entry(id).or_default().push(other);
            edges.entry(other).or_default().push(id);
        }
        let name = event["type"]
            .as_u64()
            .and_then(|id| types.get(&id))
            .map(String::as_str)
            .unwrap_or("");
        match name {
            "TCP_CONNECT_ATTEMPT" => {
                let socket = sockets.entry(id).or_default();
                socket.transport = "tcp".into();
                if let Some(remote) =
                    endpoint(&p["remote_address"]).or_else(|| endpoint(&p["address"]))
                {
                    socket.remote = Some(remote);
                }
                if let Some(local) = endpoint(&p["local_address"]) {
                    socket.local = Some(local);
                }
            }
            "TCP_CONNECT" => {
                if let Some(local) =
                    endpoint(&p["local_address"]).or_else(|| endpoint(&p["source_address"]))
                {
                    let socket = sockets.entry(id).or_default();
                    socket.local = Some(local);
                    socket.transport = "tcp".into();
                }
                if let Some(remote) = endpoint(&p["remote_address"]) {
                    sockets.entry(id).or_default().remote = Some(remote);
                }
            }
            "UDP_CONNECT" => {
                let s = sockets.entry(id).or_default();
                s.transport = "udp".into();
                if let Some(r) = endpoint(&p["address"]) {
                    s.remote = Some(r);
                }
            }
            "UDP_LOCAL_ADDRESS" => {
                let s = sockets.entry(id).or_default();
                s.transport = "udp".into();
                s.local = endpoint(&p["address"]);
            }
            _ => {}
        }
    }
    let mut related = seeds.clone();
    let mut stack: Vec<u64> = seeds.into_iter().collect();
    while let Some(id) = stack.pop() {
        if let Some(neighbors) = edges.get(&id) {
            for next in neighbors {
                if related.insert(*next) {
                    stack.push(*next);
                }
            }
        }
    }
    let requested_ports: HashSet<u16> = evidence
        .requests
        .iter()
        .filter_map(|r| url::Url::parse(&r.url).ok()?.port_or_known_default())
        .collect();
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for (id, socket) in sockets {
        if let (Some(local), Some(remote)) = (socket.local, socket.remote) {
            let observed = remotes.contains(&remote);
            let associated = related.contains(&id) && requested_ports.contains(&remote.port());
            if (observed || associated)
                && local.port() > 0
                && !remote.ip().is_unspecified()
                && seen.insert((local, remote, socket.transport.clone()))
            {
                result.push(Connection {
                    local,
                    remote,
                    transport: socket.transport,
                    source_id: id,
                    attribution: if observed {
                        "netlog_socket+cdp_remote_endpoint"
                    } else {
                        "netlog_request_dependency"
                    }
                    .into(),
                });
            }
        }
    }
    result.sort_by_key(|c| (c.transport.clone(), c.local, c.remote));
    Ok(result)
}

pub fn read_session(path: &Path) -> Result<Session> {
    ensure!(
        fs::metadata(path)?.len() <= 64 * 1024 * 1024,
        "session.json 过大"
    );
    let s: Session = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(s.schema_version == 1, "不支持此 session 版本");
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::BrowserRequest;
    use serde_json::json;
    #[test]
    fn excludes_other_sockets_and_supports_ipv6() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(),json!({"constants":{"logEventTypes":{"TCP_CONNECT_ATTEMPT":1}},"events":[
            {"type":1,"source":{"id":1},"params":{"local_address":"[::1]:1234","remote_address":"[::1]:443"}},
            {"type":1,"source":{"id":2},"params":{"local_address":"127.0.0.1:1235","remote_address":"127.0.0.1:80"}}
        ]}).to_string()).unwrap();
        let e = BrowserEvidence {
            requests: vec![BrowserRequest {
                remote_ip: Some("::1".into()),
                remote_port: Some(443),
                ..Default::default()
            }],
            ..Default::default()
        };
        let c = connections_from_netlog(file.path(), &e).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].local.port(), 1234);
    }
    #[test]
    fn chrome154_connect_end_addresses() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(),json!({"constants":{"logEventTypes":{"TCP_CONNECT":51}},"events":[
            {"type":51,"source":{"id":3},"params":{"local_address":"127.0.0.1:3456","remote_address":"127.0.0.1:443"}}
        ]}).to_string()).unwrap();
        let mut e = BrowserEvidence::default();
        e.requests.push(BrowserRequest {
            remote_ip: Some("127.0.0.1".into()),
            remote_port: Some(443),
            ..Default::default()
        });
        let connections = connections_from_netlog(file.path(), &e).unwrap();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].local.port(), 3456);
    }
}
