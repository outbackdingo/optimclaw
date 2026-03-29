//! Cluster configuration from environment variables.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// Configuration for the mesh cluster.
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// Whether clustering is enabled.
    pub enabled: bool,
    /// Human-readable node name (defaults to hostname).
    pub node_name: String,
    /// UDP broadcast port for beacon discovery.
    pub beacon_port: u16,
    /// WebSocket port for the encrypted overlay mesh.
    pub mesh_port: u16,
    /// How often to broadcast presence beacon.
    pub beacon_interval: Duration,
    /// How often to send heartbeat pings to peers.
    pub heartbeat_interval: Duration,
    /// How long before a silent peer is marked suspect.
    pub suspect_timeout: Duration,
    /// How long before a suspect peer is marked dead.
    pub dead_timeout: Duration,
    /// How often to run gossip exchange rounds.
    pub gossip_interval: Duration,
    /// Maximum number of direct peer connections.
    pub max_peers: usize,
    /// Address to bind UDP and WS listeners.
    pub bind_addr: IpAddr,
    /// UDP broadcast destination address.
    pub broadcast_addr: Ipv4Addr,
    /// Path to persist mesh keypair.
    pub keys_path: String,
    /// Static remote peers to connect to (host:port, may include hostnames).
    /// Resolved and retried periodically. LAN discovery via UDP broadcast is unaffected.
    /// Set via CLUSTER_STATIC_PEERS (comma-separated).
    pub static_peers: Vec<String>,
    /// Externally-reachable address advertised to static/remote peers (host:port).
    /// Needed when this node is behind NAT with a port forward or public IP.
    /// Set via CLUSTER_ADVERTISE_ADDR.
    pub advertise_addr: Option<String>,
    /// Enable VLESS proxy inbound on the mesh QUIC port (ALPN "oproxy/1").
    /// Set via CLUSTER_PROXY_ENABLED=1.
    pub proxy_enabled: bool,
    /// UUIDs allowed to authenticate as VLESS proxy clients.
    /// Set via CLUSTER_PROXY_UUIDS (comma-separated standard UUID strings).
    pub proxy_uuids: Vec<String>,
}

impl ClusterConfig {
    /// Load from environment variables with sane defaults.
    pub fn from_env() -> Self {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into());

        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());

        Self {
            enabled: std::env::var("CLUSTER_ENABLED")
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false),
            node_name: std::env::var("CLUSTER_NODE_NAME").unwrap_or(hostname),
            beacon_port: parse_env("CLUSTER_BEACON_PORT", 9900),
            mesh_port: parse_env("CLUSTER_MESH_PORT", 9901),
            beacon_interval: Duration::from_secs(parse_env("CLUSTER_BEACON_INTERVAL_SECS", 5)),
            heartbeat_interval: Duration::from_secs(parse_env("CLUSTER_HEARTBEAT_INTERVAL_SECS", 3)),
            suspect_timeout: Duration::from_secs(parse_env("CLUSTER_SUSPECT_TIMEOUT_SECS", 10)),
            dead_timeout: Duration::from_secs(parse_env("CLUSTER_DEAD_TIMEOUT_SECS", 15)),
            gossip_interval: Duration::from_secs(parse_env("CLUSTER_GOSSIP_INTERVAL_SECS", 2)),
            max_peers: parse_env("CLUSTER_MAX_PEERS", 5),
            bind_addr: std::env::var("CLUSTER_BIND_ADDR")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            broadcast_addr: std::env::var("CLUSTER_BROADCAST_ADDR")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(Ipv4Addr::BROADCAST),
            keys_path: std::env::var("CLUSTER_KEYS_PATH")
                .unwrap_or_else(|_| format!("{}/.optimclaw/mesh_keys.json", home)),
            static_peers: std::env::var("CLUSTER_STATIC_PEERS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            advertise_addr: std::env::var("CLUSTER_ADVERTISE_ADDR").ok(),
            proxy_enabled: std::env::var("CLUSTER_PROXY_ENABLED")
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false),
            proxy_uuids: std::env::var("CLUSTER_PROXY_UUIDS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
        }
    }
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
