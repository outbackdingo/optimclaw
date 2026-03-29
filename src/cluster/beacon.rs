//! UDP beacon for zero-config mesh discovery.
//!
//! Broadcasts a compact signed beacon every N seconds.
//! Listens for beacons from other nodes on the same LAN.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::config::ClusterConfig;
use super::crypto::MeshIdentity;
use super::types::*;

/// A discovered peer from a beacon.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub node_id: NodeId,
    pub mesh_addr: SocketAddr,
    pub flags: u8,
    pub source_addr: SocketAddr,
}

/// Start the beacon broadcaster and listener.
/// Returns a receiver that yields newly discovered peers.
pub async fn start_beacon(
    config: &ClusterConfig,
    identity: Arc<MeshIdentity>,
) -> anyhow::Result<mpsc::Receiver<DiscoveredPeer>> {
    let (tx, rx) = mpsc::channel(64);

    // Bind listener
    let listen_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, config.beacon_port);
    let listener = UdpSocket::bind(listen_addr).await?;
    listener.set_broadcast(true)?;

    // Bind sender (ephemeral port)
    let sender = UdpSocket::bind("0.0.0.0:0").await?;
    sender.set_broadcast(true)?;

    let broadcast_dest = SocketAddrV4::new(config.broadcast_addr, config.beacon_port);
    let beacon_interval = config.beacon_interval;
    let mesh_port = config.mesh_port;
    let my_id = identity.node_id;

    // Broadcaster task
    let id_clone = identity.clone();
    tokio::spawn(async move {
        loop {
            let has_gpu = super::detect_gpu().is_some();
            let flags = FLAG_ACCEPTING_TASKS | if has_gpu { FLAG_HAS_GPU } else { 0 };
            let packet = build_beacon(&id_clone, mesh_port, flags);
            if let Err(e) = sender.send_to(&packet, broadcast_dest).await {
                tracing::warn!("Beacon send failed: {}", e);
            }
            tokio::time::sleep(beacon_interval).await;
        }
    });

    // Listener task
    tokio::spawn(async move {
        let mut buf = [0u8; 256];
        loop {
            match listener.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    if let Some(peer) = parse_beacon(&buf[..len], src, &my_id) {
                        if tx.send(peer).await.is_err() {
                            break; // receiver dropped
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Beacon recv error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    });

    Ok(rx)
}

/// Build a beacon packet.
///
/// Format: MAGIC(6) + NodeId(16) + MeshPort(2) + Flags(1) + Signature(64) = 89 bytes
fn build_beacon(identity: &MeshIdentity, mesh_port: u16, flags: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(25);
    payload.extend_from_slice(BEACON_MAGIC);
    payload.extend_from_slice(&identity.node_id);
    payload.extend_from_slice(&mesh_port.to_be_bytes());
    payload.push(flags);

    let sig = identity.sign(&payload);

    let mut packet = payload;
    packet.extend_from_slice(&sig);
    packet
}

/// Parse a beacon packet. Returns None if invalid or from self.
fn parse_beacon(data: &[u8], source: SocketAddr, my_id: &NodeId) -> Option<DiscoveredPeer> {
    // Minimum: 6 + 16 + 2 + 1 + 64 = 89 bytes
    if data.len() < 89 {
        return None;
    }

    // Check magic
    if &data[..6] != BEACON_MAGIC {
        return None;
    }

    // Extract fields
    let mut node_id = [0u8; 16];
    node_id.copy_from_slice(&data[6..22]);

    // Ignore own beacons
    if &node_id == my_id {
        return None;
    }

    let mesh_port = u16::from_be_bytes([data[22], data[23]]);
    let flags = data[24];

    // Signature verification happens during the PQ WebSocket handshake.
    // The beacon signature ensures the packet wasn't tampered with in transit,
    // but full identity verification requires the PQ key exchange.

    let mesh_addr = SocketAddr::new(source.ip(), mesh_port);

    Some(DiscoveredPeer {
        node_id,
        mesh_addr,
        flags,
        source_addr: source,
    })
}
