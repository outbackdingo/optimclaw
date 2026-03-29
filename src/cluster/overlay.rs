//! QUIC overlay mesh with post-quantum encrypted channels.
//!
//! Transport: QUIC over UDP (NAT hole-punching capable, like Nebula).
//! Security:  ML-KEM-768 key encapsulation + AES-256-GCM per-session, over the
//!            first QUIC bidirectional stream. The QUIC TLS layer uses an ephemeral
//!            self-signed cert for transport only — all authentication is PQ.
//!
//! Dedup rule: lower NodeId is always the connector (initiator). The higher-ID
//! side is the responder. Static peers (unknown remote ID) skip this check and
//! let the post-handshake is_connected guard prevent duplicate channels.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use aes_gcm::Aes256Gcm;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};

use super::config::ClusterConfig;
use super::crypto::{self, MeshIdentity};
use super::gossip::GossipState;
use super::transport::{self, ALPN_MESH, ALPN_PROXY};
use super::types::*;

// ── Peer connection ───────────────────────────────────────────────────────────

/// A connected peer with its outbound message channel.
pub struct PeerConnection {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub send_tx: mpsc::Sender<Vec<u8>>,
}

impl std::fmt::Debug for PeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConnection")
            .field("node_id", &node_id_hex(&self.node_id))
            .field("addr", &self.addr)
            .finish()
    }
}

// ── Handshake messages ────────────────────────────────────────────────────────

/// Sent by the initiator: our KEM public key + signing key + node ID.
#[derive(Serialize, Deserialize)]
struct HandshakeInit {
    node_id: NodeId,
    kem_pk: Vec<u8>,
    verify_pk: Vec<u8>,
}

/// Sent by the responder: KEM ciphertext + signing key + Ed25519 signature.
#[derive(Serialize, Deserialize)]
struct HandshakeReply {
    node_id: NodeId,
    ciphertext: Vec<u8>,
    verify_pk: Vec<u8>,
    signature: Vec<u8>,
}

// ── OverlayMesh ───────────────────────────────────────────────────────────────

/// Manages the QUIC overlay mesh connections.
pub struct OverlayMesh {
    pub identity: Arc<MeshIdentity>,
    pub peers: RwLock<HashMap<NodeId, PeerConnection>>,
    pub gossip: Arc<GossipState>,
    pub config: ClusterConfig,
    pub incoming_tx: mpsc::Sender<(NodeId, MeshMessage)>,
    /// Shared QUIC endpoint — used for both listening and outbound dials.
    endpoint: quinn::Endpoint,
    /// Client config used when dialing peers (skips cert verification).
    client_cfg: quinn::ClientConfig,
}

impl OverlayMesh {
    pub fn new(
        identity: Arc<MeshIdentity>,
        gossip: Arc<GossipState>,
        config: ClusterConfig,
        incoming_tx: mpsc::Sender<(NodeId, MeshMessage)>,
    ) -> anyhow::Result<Self> {
        let bind_addr = SocketAddr::new(config.bind_addr, config.mesh_port);
        let endpoint = transport::make_server_endpoint(bind_addr)?;
        let client_cfg = transport::make_client_config()?;

        Ok(Self {
            identity,
            peers: RwLock::new(HashMap::new()),
            gossip,
            config,
            incoming_tx,
            endpoint,
            client_cfg,
        })
    }

    // ── Listener ──────────────────────────────────────────────────────────────

    /// Accept incoming QUIC connections and dispatch by ALPN.
    ///
    /// `"omesh/1"` → PQ mesh handshake.
    /// `"oproxy/1"` → VLESS proxy (handled by proxy::handle_proxy_connection).
    pub async fn start_listener(
        self: &Arc<Self>,
        proxy_uuids: Arc<Vec<[u8; 16]>>,
    ) -> anyhow::Result<()> {
        let listen_addr = SocketAddr::new(self.config.bind_addr, self.config.mesh_port);
        tracing::info!("Mesh overlay listening on UDP {}", listen_addr);

        let mesh = self.clone();
        tokio::spawn(async move {
            while let Some(incoming) = mesh.endpoint.accept().await {
                let mesh = mesh.clone();
                let proxy_uuids = proxy_uuids.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!("QUIC accept error: {}", e);
                            return;
                        }
                    };

                    let alpn = conn
                        .handshake_data()
                        .and_then(|d| {
                            d.downcast::<quinn::crypto::rustls::HandshakeData>()
                                .ok()
                        })
                        .and_then(|d| d.protocol.clone());

                    match alpn.as_deref() {
                        Some(p) if p == ALPN_MESH => {
                            if let Err(e) = mesh.handle_incoming(conn).await {
                                tracing::debug!("Mesh handshake failed: {}", e);
                            }
                        }
                        Some(p) if p == ALPN_PROXY => {
                            if let Err(e) =
                                super::proxy::handle_proxy_connection(conn, proxy_uuids).await
                            {
                                tracing::debug!("Proxy connection failed: {}", e);
                            }
                        }
                        _ => tracing::debug!("Incoming QUIC conn with unknown ALPN, dropping"),
                    }
                });
            }
        });

        Ok(())
    }

    // ── Incoming PQ handshake (responder) ─────────────────────────────────────

    async fn handle_incoming(self: &Arc<Self>, conn: quinn::Connection) -> anyhow::Result<()> {
        let peer_addr = conn.remote_address();
        let (mut send, mut recv) = conn.accept_bi().await?;

        // Receive initiator's HandshakeInit
        let init_bytes = transport::recv_frame(&mut recv).await?;
        let init: HandshakeInit = serde_json::from_slice(&init_bytes)?;

        // Dedup: if the initiator has a higher ID than us, they should be the
        // connector, not us — drop this and let the ordering play out.
        if init.node_id > self.identity.node_id {
            return Ok(());
        }

        // Encapsulate shared secret with initiator's KEM public key
        let (shared_secret, ciphertext) = crypto::encapsulate(&init.kem_pk)?;

        // Sign ciphertext || our node_id so the initiator can verify us
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&ciphertext);
        sign_data.extend_from_slice(&self.identity.node_id);
        let signature = self.identity.sign(&sign_data);

        let reply = HandshakeReply {
            node_id: self.identity.node_id,
            ciphertext,
            verify_pk: self.identity.verify_key_bytes(),
            signature,
        };
        transport::send_frame(&mut send, &serde_json::to_vec(&reply)?).await?;

        // Derive symmetric keys and start the encrypted peer loop
        let (send_cipher, recv_cipher) =
            crypto::derive_keys(&shared_secret, &init.node_id, &self.identity.node_id);

        self.run_peer_loop(init.node_id, peer_addr, send, recv, send_cipher, recv_cipher)
            .await;

        Ok(())
    }

    // ── Outbound dial — known peer ID (LAN beacon discovery) ─────────────────

    /// Connect to a peer discovered via UDP beacon (node ID known).
    ///
    /// Lower-ID rule: only the node with the lower ID initiates. Higher-ID
    /// nodes wait for the remote to connect to them.
    pub async fn connect_to_peer(
        self: &Arc<Self>,
        peer_addr: SocketAddr,
        peer_node_id: &NodeId,
    ) -> anyhow::Result<()> {
        if self.identity.node_id >= *peer_node_id {
            return Ok(());
        }
        if self.is_connected(peer_node_id).await {
            return Ok(());
        }
        self.dial(peer_addr, Some(*peer_node_id)).await
    }

    // ── Outbound dial — unknown peer ID (static peers / hole-punch) ──────────

    /// Connect to a static peer whose NodeId is not known until the PQ handshake.
    ///
    /// Both sides of a static peer pair attempt this simultaneously. Sending the
    /// QUIC Initial packet from each side opens a NAT pinhole (UDP hole punching),
    /// so at least one direction succeeds. The post-handshake `is_connected` guard
    /// prevents duplicate channels if both sides finish the handshake concurrently.
    pub async fn connect_to_addr(self: &Arc<Self>, peer_addr: SocketAddr) -> anyhow::Result<()> {
        if self.is_connected_by_addr(&peer_addr).await {
            return Ok(());
        }
        self.dial(peer_addr, None).await
    }

    // ── Core dial logic ───────────────────────────────────────────────────────

    async fn dial(
        self: &Arc<Self>,
        peer_addr: SocketAddr,
        known_peer_id: Option<NodeId>,
    ) -> anyhow::Result<()> {
        let conn = self
            .endpoint
            .connect_with(self.client_cfg.clone(), peer_addr, "omesh")?
            .await?;

        let (mut send, mut recv) = conn.open_bi().await?;

        // Send our HandshakeInit
        let init = HandshakeInit {
            node_id: self.identity.node_id,
            kem_pk: self.identity.kem_pk_bytes(),
            verify_pk: self.identity.verify_key_bytes(),
        };
        transport::send_frame(&mut send, &serde_json::to_vec(&init)?).await?;

        // Receive HandshakeReply
        let reply_bytes = transport::recv_frame(&mut recv).await?;
        let reply: HandshakeReply = serde_json::from_slice(&reply_bytes)?;

        // Verify Ed25519 signature over (ciphertext || responder node_id)
        let peer_verify_key = ed25519_dalek::VerifyingKey::from_bytes(
            reply
                .verify_pk
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid verify key length"))?,
        )?;
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&reply.ciphertext);
        sign_data.extend_from_slice(&reply.node_id);
        if !MeshIdentity::verify(&peer_verify_key, &sign_data, &reply.signature) {
            anyhow::bail!("Invalid handshake signature from {}", peer_addr);
        }

        // If known peer ID was supplied, verify it matches
        if let Some(expected) = known_peer_id {
            if reply.node_id != expected {
                anyhow::bail!(
                    "Peer ID mismatch: expected {} got {}",
                    node_id_hex(&expected),
                    node_id_hex(&reply.node_id)
                );
            }
        }

        // Guard against races (both sides completed simultaneously)
        if self.is_connected(&reply.node_id).await {
            return Ok(());
        }

        let shared_secret = self.identity.decapsulate(&reply.ciphertext)?;
        let (send_cipher, recv_cipher) =
            crypto::derive_keys(&shared_secret, &self.identity.node_id, &reply.node_id);

        tracing::info!(
            "PQ handshake complete with {} at {} (ML-KEM-768 + AES-256-GCM)",
            node_id_hex(&reply.node_id),
            peer_addr,
        );

        let mesh = self.clone();
        let peer_id = reply.node_id;
        tokio::spawn(async move {
            mesh.run_peer_loop(peer_id, peer_addr, send, recv, send_cipher, recv_cipher)
                .await;
        });

        Ok(())
    }

    // ── Encrypted peer loop ───────────────────────────────────────────────────

    /// Run the AES-256-GCM encrypted send/receive loop for a connected peer.
    ///
    /// Frames are length-prefixed over the QUIC bidirectional stream. The QUIC
    /// layer provides reliability and ordering; we provide confidentiality and
    /// integrity via our PQ-derived symmetric keys.
    async fn run_peer_loop(
        &self,
        peer_id: NodeId,
        addr: SocketAddr,
        mut quic_tx: quinn::SendStream,
        mut quic_rx: quinn::RecvStream,
        send_cipher: Aes256Gcm,
        recv_cipher: Aes256Gcm,
    ) {
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
        self.add_peer(peer_id, addr, out_tx).await;

        let incoming_tx = self.incoming_tx.clone();
        let send_cipher = Arc::new(send_cipher);
        let recv_cipher = Arc::new(recv_cipher);

        // Sender: encrypt plaintext → length-prefixed frame → QUIC stream
        let send_c = send_cipher.clone();
        let sender = tokio::spawn(async move {
            let mut nonce: u64 = 0;
            while let Some(plaintext) = out_rx.recv().await {
                nonce += 1;
                let frame = crypto::encrypt(&send_c, nonce, &plaintext);
                if transport::send_frame(&mut quic_tx, &frame).await.is_err() {
                    break;
                }
            }
        });

        // Receiver: QUIC stream → decrypt frame → dispatch MeshMessage
        let recv_c = recv_cipher.clone();
        let receiver = tokio::spawn(async move {
            loop {
                let frame = match transport::recv_frame(&mut quic_rx).await {
                    Ok(f) => f,
                    Err(_) => break,
                };
                match crypto::decrypt(&recv_c, &frame) {
                    Ok(plaintext) => match serde_json::from_slice::<MeshMessage>(&plaintext) {
                        Ok(msg) => {
                            if incoming_tx.send((peer_id, msg)).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Invalid mesh message from {}: {}",
                                node_id_hex(&peer_id),
                                e
                            );
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Decrypt failed from {}: {}", node_id_hex(&peer_id), e);
                        break;
                    }
                }
            }
        });

        tokio::select! {
            _ = sender => {}
            _ = receiver => {}
        }

        self.remove_peer(&peer_id).await;
    }

    // ── Peer registry ─────────────────────────────────────────────────────────

    /// Check if we're connected to a peer by node ID.
    pub async fn is_connected(&self, node_id: &NodeId) -> bool {
        self.peers.read().await.contains_key(node_id)
    }

    /// Check if we already have an outbound connection to a given socket address.
    pub async fn is_connected_by_addr(&self, addr: &SocketAddr) -> bool {
        self.peers.read().await.values().any(|p| p.addr == *addr)
    }

    /// Number of active peer connections.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Send a message to a specific peer.
    pub async fn send_to(&self, node_id: &NodeId, msg: &MeshMessage) -> anyhow::Result<()> {
        let peers = self.peers.read().await;
        let peer = peers
            .get(node_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not connected: {}", node_id_hex(node_id)))?;
        let json = serde_json::to_vec(msg)?;
        peer.send_tx
            .send(json)
            .await
            .map_err(|_| anyhow::anyhow!("Peer channel closed: {}", node_id_hex(node_id)))
    }

    /// Broadcast a message to all connected peers.
    pub async fn broadcast(&self, msg: &MeshMessage) {
        let json = match serde_json::to_vec(msg) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("Failed to serialize mesh message: {}", e);
                return;
            }
        };
        let peers = self.peers.read().await;
        for (id, peer) in peers.iter() {
            if peer.send_tx.send(json.clone()).await.is_err() {
                tracing::warn!("Failed to send to peer {}", node_id_hex(id));
            }
        }
    }

    /// Register a new peer connection.
    pub async fn add_peer(
        &self,
        node_id: NodeId,
        addr: SocketAddr,
        send_tx: mpsc::Sender<Vec<u8>>,
    ) {
        let mut peers = self.peers.write().await;
        if peers.len() >= self.config.max_peers && !peers.contains_key(&node_id) {
            tracing::debug!(
                "Max peers ({}) reached, rejecting {}",
                self.config.max_peers,
                node_id_hex(&node_id)
            );
            return;
        }
        tracing::info!("Peer connected: {} ({})", node_id_hex(&node_id), addr);
        peers.insert(node_id, PeerConnection { node_id, addr, send_tx });
    }

    /// Remove a peer connection.
    pub async fn remove_peer(&self, node_id: &NodeId) {
        if self.peers.write().await.remove(node_id).is_some() {
            tracing::info!("Peer disconnected: {}", node_id_hex(node_id));
        }
    }

    /// Get list of connected peer IDs.
    pub async fn connected_peer_ids(&self) -> Vec<NodeId> {
        self.peers.read().await.keys().cloned().collect()
    }
}
