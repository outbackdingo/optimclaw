//! WebSocket overlay mesh with post-quantum encrypted channels.
//!
//! Each peer connection is a WebSocket tunnel encrypted with AES-256-GCM
//! after an ML-KEM-768 key exchange handshake.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{accept_async, connect_async};
use futures::{SinkExt, StreamExt};
use aes_gcm::Aes256Gcm;
use serde::{Deserialize, Serialize};

use super::config::ClusterConfig;
use super::crypto::{self, MeshIdentity};
use super::gossip::GossipState;
use super::types::*;

/// A connected peer with its encrypted channel.
pub struct PeerConnection {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub send_tx: mpsc::Sender<Vec<u8>>,
    pub send_nonce: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for PeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConnection")
            .field("node_id", &node_id_hex(&self.node_id))
            .field("addr", &self.addr)
            .finish()
    }
}

/// Handshake message sent during PQ key exchange.
#[derive(Serialize, Deserialize)]
struct HandshakeInit {
    node_id: NodeId,
    kem_pk: Vec<u8>,
    verify_pk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct HandshakeReply {
    node_id: NodeId,
    ciphertext: Vec<u8>,
    verify_pk: Vec<u8>,
    signature: Vec<u8>,
}

/// Manages the overlay mesh connections.
pub struct OverlayMesh {
    pub identity: Arc<MeshIdentity>,
    pub peers: RwLock<HashMap<NodeId, PeerConnection>>,
    pub gossip: Arc<GossipState>,
    pub config: ClusterConfig,
    pub incoming_tx: mpsc::Sender<(NodeId, MeshMessage)>,
}

impl OverlayMesh {
    pub fn new(
        identity: Arc<MeshIdentity>,
        gossip: Arc<GossipState>,
        config: ClusterConfig,
        incoming_tx: mpsc::Sender<(NodeId, MeshMessage)>,
    ) -> Self {
        Self {
            identity,
            peers: RwLock::new(HashMap::new()),
            gossip,
            config,
            incoming_tx,
        }
    }

    /// Start the WebSocket listener for incoming peer connections.
    pub async fn start_listener(self: &Arc<Self>) -> anyhow::Result<()> {
        let listen_addr = format!("{}:{}", self.config.bind_addr, self.config.mesh_port);
        let listener = TcpListener::bind(&listen_addr).await?;
        tracing::info!("Mesh overlay listening on {}", listen_addr);

        let mesh = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let mesh = mesh.clone();
                        tokio::spawn(async move {
                            if let Err(e) = mesh.handle_incoming(stream, addr).await {
                                tracing::debug!("Incoming peer {} handshake failed: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Mesh accept error: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle an incoming WebSocket connection (responder side of PQ handshake).
    async fn handle_incoming(&self, stream: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
        let ws = accept_async(stream).await?;
        let (mut ws_tx, mut ws_rx) = ws.split();

        // Step 1: Receive initiator's handshake (kem_pk + verify_pk + node_id)
        let init_msg = ws_rx
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("No handshake received"))??;

        let init: HandshakeInit = serde_json::from_slice(&init_msg.into_data())?;

        // Dedup: if lower ID should be connector, reject
        if init.node_id > self.identity.node_id {
            // We have the lower ID -- we should be the connector, not the responder
            // Drop this connection; we'll connect outbound instead
            return Ok(());
        }

        // Step 2: Encapsulate shared secret with initiator's KEM public key
        let (shared_secret, ciphertext) = crypto::encapsulate(&init.kem_pk)?;

        // Step 3: Sign the ciphertext + our node_id
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

        ws_tx
            .send(WsMessage::Binary(serde_json::to_vec(&reply)?.into()))
            .await?;

        // Step 4: Derive symmetric keys
        let (send_cipher, recv_cipher) =
            crypto::derive_keys(&shared_secret, &self.identity.node_id, &init.node_id);

        // Connection established -- run the encrypted message loop
        self.run_peer_loop(init.node_id, addr, ws_tx, ws_rx, send_cipher, recv_cipher)
            .await;

        Ok(())
    }

    /// Initiate an outbound connection to a discovered peer (initiator side).
    pub async fn connect_to_peer(self: &Arc<Self>, peer_addr: SocketAddr, peer_node_id: &NodeId) -> anyhow::Result<()> {
        // Dedup: lower NodeId is always the connector
        if self.identity.node_id >= *peer_node_id {
            // We have the higher ID -- wait for the other side to connect to us
            return Ok(());
        }

        if self.is_connected(peer_node_id).await {
            return Ok(());
        }

        let url = format!("ws://{}", peer_addr);
        let (ws, _) = connect_async(&url).await?;
        let (mut ws_tx, mut ws_rx) = ws.split();

        // Step 1: Send our handshake (kem_pk + verify_pk + node_id)
        let init = HandshakeInit {
            node_id: self.identity.node_id,
            kem_pk: self.identity.kem_pk_bytes(),
            verify_pk: self.identity.verify_key_bytes(),
        };

        ws_tx
            .send(WsMessage::Binary(serde_json::to_vec(&init)?.into()))
            .await?;

        // Step 2: Receive responder's reply (ciphertext + verify_pk + signature)
        let reply_msg = ws_rx
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("No handshake reply"))??;

        let reply: HandshakeReply = serde_json::from_slice(&reply_msg.into_data())?;

        // Step 3: Verify signature
        let peer_verify_key = ed25519_dalek::VerifyingKey::from_bytes(
            reply.verify_pk.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid verify key length"))?,
        )?;

        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&reply.ciphertext);
        sign_data.extend_from_slice(&reply.node_id);

        if !MeshIdentity::verify(&peer_verify_key, &sign_data, &reply.signature) {
            anyhow::bail!("Invalid handshake signature from peer");
        }

        // Step 4: Decapsulate shared secret
        let shared_secret = self.identity.decapsulate(&reply.ciphertext)?;

        // Step 5: Derive symmetric keys (we are the initiator)
        let (send_cipher, recv_cipher) =
            crypto::derive_keys(&shared_secret, &self.identity.node_id, &reply.node_id);

        tracing::info!(
            "PQ handshake complete with {} (ML-KEM-768 + AES-256-GCM)",
            node_id_hex(&reply.node_id)
        );

        // Run encrypted message loop
        let mesh = self.clone();
        let peer_id = reply.node_id;
        tokio::spawn(async move {
            mesh.run_peer_loop(peer_id, peer_addr, ws_tx, ws_rx, send_cipher, recv_cipher)
                .await;
        });

        Ok(())
    }

    /// Run the encrypted message loop for a connected peer.
    async fn run_peer_loop<S, R>(
        &self,
        peer_id: NodeId,
        addr: SocketAddr,
        mut ws_tx: S,
        mut ws_rx: R,
        send_cipher: Aes256Gcm,
        recv_cipher: Aes256Gcm,
    ) where
        S: futures::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin + Send + 'static,
        R: futures::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>> + Unpin + Send + 'static,
    {
        // Channel for outgoing messages (plaintext bytes, encrypted before sending)
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);

        // Register peer
        self.add_peer(peer_id, addr, out_tx).await;

        let incoming_tx = self.incoming_tx.clone();
        let send_cipher = Arc::new(send_cipher);
        let recv_cipher = Arc::new(recv_cipher);

        // Sender task: encrypt and send
        let send_c = send_cipher.clone();
        let sender = tokio::spawn(async move {
            let mut nonce: u64 = 0;
            while let Some(plaintext) = out_rx.recv().await {
                nonce += 1;
                let frame = crypto::encrypt(&send_c, nonce, &plaintext);
                if ws_tx.send(WsMessage::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
        });

        // Receiver task: decrypt and dispatch
        let recv_c = recv_cipher.clone();
        let receiver = tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_rx.next().await {
                let data = match msg {
                    WsMessage::Binary(b) => b.to_vec(),
                    WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
                    WsMessage::Close(_) => break,
                    _ => continue,
                };

                match crypto::decrypt(&recv_c, &data) {
                    Ok(plaintext) => {
                        match serde_json::from_slice::<MeshMessage>(&plaintext) {
                            Ok(mesh_msg) => {
                                if incoming_tx.send((peer_id, mesh_msg)).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Invalid mesh message from {}: {}", node_id_hex(&peer_id), e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Decrypt failed from {}: {}", node_id_hex(&peer_id), e);
                        break; // Crypto failure = drop connection
                    }
                }
            }
        });

        // Wait for either task to finish, then clean up
        tokio::select! {
            _ = sender => {},
            _ = receiver => {},
        }

        self.remove_peer(&peer_id).await;
    }

    /// Check if we're connected to a peer.
    pub async fn is_connected(&self, node_id: &NodeId) -> bool {
        self.peers.read().await.contains_key(node_id)
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
            .ok_or_else(|| anyhow::anyhow!("Peer not connected"))?;

        let json = serde_json::to_vec(msg)?;
        peer.send_tx
            .send(json)
            .await
            .map_err(|_| anyhow::anyhow!("Peer channel closed"))
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
    pub async fn add_peer(&self, node_id: NodeId, addr: SocketAddr, send_tx: mpsc::Sender<Vec<u8>>) {
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

        peers.insert(
            node_id,
            PeerConnection {
                node_id,
                addr,
                send_tx,
                send_nonce: std::sync::atomic::AtomicU64::new(0),
            },
        );
    }

    /// Remove a peer connection.
    pub async fn remove_peer(&self, node_id: &NodeId) {
        let mut peers = self.peers.write().await;
        if peers.remove(node_id).is_some() {
            tracing::info!("Peer disconnected: {}", node_id_hex(node_id));
        }
    }

    /// Get list of connected peer IDs.
    pub async fn connected_peer_ids(&self) -> Vec<NodeId> {
        self.peers.read().await.keys().cloned().collect()
    }
}
