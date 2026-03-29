//! Autonomous AI mesh network for OptimClaw.
//!
//! Nodes self-discover via UDP beacons, form a peer-to-peer overlay mesh
//! with post-quantum encrypted WebSocket channels, and route tasks
//! intelligently based on GPU capability, model availability, and load.

pub mod api;
pub mod beacon;
pub mod config;
pub mod crypto;
pub mod gossip;
pub mod overlay;
pub mod router;
pub mod types;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use config::ClusterConfig;
use crypto::MeshIdentity;
use gossip::GossipState;
use overlay::OverlayMesh;
use types::*;

/// A node in the OptimClaw mesh network.
pub struct MeshNode {
    pub config: ClusterConfig,
    pub identity: Arc<MeshIdentity>,
    pub gossip: Arc<GossipState>,
    pub overlay: Arc<OverlayMesh>,
    pub event_tx: tokio::sync::broadcast::Sender<ClusterEvent>,
    capabilities: NodeCapabilities,
    pending_tasks: PendingTasks,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl MeshNode {
    /// Start a new mesh node. Begins discovery, gossip, and overlay management.
    pub async fn start(config: ClusterConfig) -> anyhow::Result<Arc<Self>> {
        // Load or generate identity
        let identity = Arc::new(MeshIdentity::load_or_generate(&config.keys_path)?);
        tracing::info!(
            "Mesh node starting: id={} name={}",
            node_id_hex(&identity.node_id),
            config.node_name
        );

        // Detect local capabilities
        let capabilities = detect_capabilities();

        // Initialize gossip state
        let gossip = Arc::new(GossipState::new(identity.node_id));

        // Message channel for incoming mesh messages
        let (incoming_tx, mut incoming_rx) = mpsc::channel::<(NodeId, MeshMessage)>(256);

        // Initialize overlay mesh
        let overlay = Arc::new(OverlayMesh::new(
            identity.clone(),
            gossip.clone(),
            config.clone(),
            incoming_tx,
        ));

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let (event_tx, _) = tokio::sync::broadcast::channel(128);
        let pending_tasks: PendingTasks = Arc::new(RwLock::new(HashMap::new()));

        let node = Arc::new(Self {
            config: config.clone(),
            identity: identity.clone(),
            gossip: gossip.clone(),
            overlay: overlay.clone(),
            event_tx: event_tx.clone(),
            capabilities,
            pending_tasks: pending_tasks.clone(),
            shutdown_tx: shutdown_tx.clone(),
        });

        // Start beacon discovery
        let mut beacon_rx = beacon::start_beacon(&config, identity.clone()).await?;
        tracing::info!("Beacon broadcasting on port {}", config.beacon_port);

        // Start the overlay WebSocket listener
        overlay.start_listener().await?;

        // Task: process discovered peers -- connect via PQ-encrypted WebSocket
        let overlay_disc = overlay.clone();
        let gossip_disc = gossip.clone();
        tokio::spawn(async move {
            while let Some(peer) = beacon_rx.recv().await {
                if overlay_disc.is_connected(&peer.node_id).await {
                    continue;
                }
                tracing::info!(
                    "Discovered peer {} at {}",
                    node_id_hex(&peer.node_id),
                    peer.mesh_addr
                );

                // Record in gossip
                let info = NodeInfo {
                    id: peer.node_id,
                    hostname: format!("{}", peer.source_addr.ip()),
                    mesh_addr: peer.mesh_addr,
                    gateway_addr: None,
                    capabilities: NodeCapabilities {
                        gpu: None,
                        loaded_model: None,
                        available_tools: vec![],
                        free_memory_mb: 0,
                        total_memory_mb: 0,
                    },
                    load: 0.0,
                    version: String::new(),
                    started_at: 0,
                    last_heartbeat: chrono::Utc::now().timestamp(),
                };
                gossip_disc
                    .merge_node(info, 0, MemberStatus::Alive)
                    .await;

                // Initiate PQ-encrypted WebSocket connection
                let overlay_conn = overlay_disc.clone();
                let peer_id = peer.node_id;
                let peer_addr = peer.mesh_addr;
                tokio::spawn(async move {
                    if let Err(e) = overlay_conn.connect_to_peer(peer_addr, &peer_id).await {
                        tracing::debug!(
                            "Failed to connect to {}: {}",
                            node_id_hex(&peer_id),
                            e
                        );
                    }
                });
            }
        });

        // Task: process incoming mesh messages
        let gossip_msg = gossip.clone();
        let overlay_msg = overlay.clone();
        let pending_msg = pending_tasks.clone();
        let event_tx_msg = Some(event_tx.clone());
        tokio::spawn(async move {
            while let Some((from, msg)) = incoming_rx.recv().await {
                handle_mesh_message(&gossip_msg, &overlay_msg, from, msg, &pending_msg, &event_tx_msg).await;
            }
        });

        // Task: periodic gossip / failure detection
        let gossip_tick = gossip.clone();
        let overlay_tick = overlay.clone();
        let suspect_timeout = config.suspect_timeout;
        let dead_timeout = config.dead_timeout;
        let gossip_interval = config.gossip_interval;
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(gossip_interval) => {
                        // Check timeouts
                        let (suspects, dead) = gossip_tick
                            .check_timeouts(suspect_timeout, dead_timeout)
                            .await;
                        for id in suspects {
                            gossip_tick.mark_suspect(&id).await;
                        }
                        for id in dead {
                            gossip_tick.mark_dead(&id).await;
                            overlay_tick.remove_peer(&id).await;
                        }

                        // Prune long-dead nodes
                        gossip_tick.prune_dead(std::time::Duration::from_secs(120)).await;

                        // Gossip exchange with a random peer
                        if let Some(peer) = gossip_tick.random_alive_peer().await {
                            let updates = gossip_tick.membership_updates().await;
                            let msg = MeshMessage::Ping {
                                from: identity.node_id,
                                seq: rand::random(),
                                piggyback: updates,
                            };
                            let _ = overlay_tick.send_to(&peer.id, &msg).await;
                        }
                    }
                    _ = shutdown_rx.recv() => break,
                }
            }
        });

        tracing::info!(
            "Mesh node ready: {} peers=0 beacon=:{} mesh=:{}",
            node_id_hex(&node.identity.node_id),
            config.beacon_port,
            config.mesh_port
        );

        Ok(node)
    }

    /// Get local node capabilities.
    pub fn local_capabilities(&self) -> &NodeCapabilities {
        &self.capabilities
    }

    /// Build a NodeInfo for the local node.
    pub fn local_info(&self) -> NodeInfo {
        NodeInfo {
            id: self.identity.node_id,
            hostname: self.config.node_name.clone(),
            mesh_addr: std::net::SocketAddr::new(
                self.config.bind_addr,
                self.config.mesh_port,
            ),
            gateway_addr: None,
            capabilities: self.capabilities.clone(),
            load: compute_load(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            started_at: chrono::Utc::now().timestamp(),
            last_heartbeat: chrono::Utc::now().timestamp(),
        }
    }

    /// Submit a task to the mesh for intelligent routing.
    /// Returns the result from whichever node handles it.
    pub async fn submit_task(&self, content: String, timeout_secs: u64) -> anyhow::Result<TaskResult> {
        let task_id = uuid::Uuid::new_v4().to_string();
        let envelope = TaskEnvelope {
            task_id: task_id.clone(),
            content: content.clone(),
            origin_node: self.identity.node_id,
            required_model: None,
            required_tools: vec![],
            min_vram_mb: None,
            priority: 0,
            hop_count: 0,
        };

        let best = router::route_task(&self.gossip, &self.local_info(), &envelope).await;

        let target = match best {
            Some(node) => node,
            None => anyhow::bail!("No suitable node found for task"),
        };

        // If best node is self, execute locally
        if target.id == self.identity.node_id {
            tracing::info!("Executing task {} locally", task_id);
            return Ok(TaskResult {
                success: true,
                response: format!("Local execution: {}", content),
                node_id: self.identity.node_id,
                duration_ms: 0,
            });
        }

        // Send to remote peer and wait for result
        tracing::info!(
            "Routing task {} to {} ({})",
            task_id,
            node_id_hex(&target.id),
            target.hostname
        );

        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        self.pending_tasks.write().await.insert(task_id.clone(), result_tx);

        let msg = MeshMessage::TaskRequest {
            task_id: task_id.clone(),
            envelope,
        };
        self.overlay.send_to(&target.id, &msg).await?;

        // Wait for result with timeout
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            result_rx,
        ).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => {
                self.pending_tasks.write().await.remove(&task_id);
                anyhow::bail!("Task result channel closed")
            }
            Err(_) => {
                self.pending_tasks.write().await.remove(&task_id);
                anyhow::bail!("Task timed out after {}s", timeout_secs)
            }
        }
    }

    /// Subscribe to cluster events for the UI.
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<ClusterEvent> {
        self.event_tx.subscribe()
    }

    /// Graceful shutdown.
    pub async fn shutdown(&self) {
        // Broadcast leave
        let msg = MeshMessage::Leaving {
            id: self.identity.node_id,
        };
        self.overlay.broadcast(&msg).await;
        let _ = self.shutdown_tx.send(());
        tracing::info!("Mesh node shutting down");
    }
}

/// Pending tasks waiting for results from remote nodes.
pub type PendingTasks =
    Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<TaskResult>>>>;

/// Handle an incoming mesh message from a peer.
async fn handle_mesh_message(
    gossip: &GossipState,
    overlay: &OverlayMesh,
    from: NodeId,
    msg: MeshMessage,
    pending_tasks: &PendingTasks,
    event_tx: &Option<tokio::sync::broadcast::Sender<ClusterEvent>>,
) {
    match msg {
        MeshMessage::Ping { piggyback, seq, .. } => {
            gossip.heartbeat(&from).await;
            for update in piggyback {
                let info = NodeInfo {
                    id: update.node_id,
                    hostname: String::new(),
                    mesh_addr: "0.0.0.0:0".parse().unwrap(),
                    gateway_addr: None,
                    capabilities: NodeCapabilities {
                        gpu: None,
                        loaded_model: None,
                        available_tools: vec![],
                        free_memory_mb: 0,
                        total_memory_mb: 0,
                    },
                    load: 0.0,
                    version: String::new(),
                    started_at: 0,
                    last_heartbeat: chrono::Utc::now().timestamp(),
                };
                gossip.merge_node(info, update.incarnation, update.status).await;
            }
            // Send ack
            let updates = gossip.membership_updates().await;
            let ack = MeshMessage::Ack {
                from: overlay.identity.node_id,
                seq,
                piggyback: updates,
            };
            let _ = overlay.send_to(&from, &ack).await;
        }
        MeshMessage::Ack { piggyback, .. } => {
            gossip.heartbeat(&from).await;
            for update in piggyback {
                let info = NodeInfo {
                    id: update.node_id,
                    hostname: String::new(),
                    mesh_addr: "0.0.0.0:0".parse().unwrap(),
                    gateway_addr: None,
                    capabilities: NodeCapabilities {
                        gpu: None, loaded_model: None, available_tools: vec![],
                        free_memory_mb: 0, total_memory_mb: 0,
                    },
                    load: 0.0, version: String::new(), started_at: 0,
                    last_heartbeat: chrono::Utc::now().timestamp(),
                };
                gossip.merge_node(info, update.incarnation, update.status).await;
            }
        }
        MeshMessage::PeerExchange { nodes } => {
            for info in nodes {
                gossip.merge_node(info, 0, MemberStatus::Alive).await;
            }
        }
        MeshMessage::Leaving { id } => {
            gossip.handle_leave(&id).await;
            if let Some(tx) = event_tx {
                let _ = tx.send(ClusterEvent::NodeLeft {
                    node_id: node_id_hex(&id),
                });
            }
        }
        MeshMessage::TaskRequest { task_id, envelope } => {
            tracing::info!("Received task {} from {}", task_id, node_id_hex(&from));
            // Check if we can handle this task
            let local_info = NodeInfo {
                id: overlay.identity.node_id,
                hostname: String::new(),
                mesh_addr: "0.0.0.0:0".parse().unwrap(),
                gateway_addr: None,
                capabilities: detect_capabilities(),
                load: compute_load(),
                version: String::new(),
                started_at: 0,
                last_heartbeat: 0,
            };
            if router::score_node(&local_info, &envelope).is_none() {
                let reject = MeshMessage::TaskReject {
                    task_id,
                    node_id: overlay.identity.node_id,
                    reason: "Capability mismatch".into(),
                };
                let _ = overlay.send_to(&from, &reject).await;
                return;
            }

            let accept = MeshMessage::TaskAccept {
                task_id: task_id.clone(),
                node_id: overlay.identity.node_id,
            };
            let _ = overlay.send_to(&from, &accept).await;

            if let Some(tx) = event_tx {
                let _ = tx.send(ClusterEvent::TaskReceived {
                    task_id: task_id.clone(),
                    from: node_id_hex(&from),
                    content: envelope.content.chars().take(100).collect(),
                });
            }

            // Execute the task via optimclaw single-message mode
            let overlay_exec = overlay.identity.node_id;
            let from_id = from;
            let overlay_ref = overlay.incoming_tx.clone();
            let task_id_exec = task_id.clone();
            let content = envelope.content.clone();

            // Run in a blocking thread since it spawns a subprocess
            let result = tokio::task::spawn_blocking(move || {
                let start = std::time::Instant::now();
                let output = std::process::Command::new("optimclaw")
                    .args(["run", "--cli-only", "--no-onboard", "-m", &content])
                    .env("OPTIMCLAW_LAZY_TOOLS", "1")
                    .output();

                match output {
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        let response = stderr.lines()
                            .skip_while(|l| !l.contains("────"))
                            .skip(1)
                            .collect::<Vec<&str>>()
                            .join("\n");
                        let response = if response.trim().is_empty() {
                            String::from_utf8_lossy(&out.stdout).trim().to_string()
                        } else {
                            response.trim().to_string()
                        };
                        TaskResult {
                            success: out.status.success(),
                            response,
                            node_id: overlay_exec,
                            duration_ms: start.elapsed().as_millis() as u64,
                        }
                    }
                    Err(e) => TaskResult {
                        success: false,
                        response: format!("Execution failed: {}", e),
                        node_id: overlay_exec,
                        duration_ms: start.elapsed().as_millis() as u64,
                    },
                }
            }).await.unwrap_or_else(|e| TaskResult {
                success: false,
                response: format!("Task spawn error: {}", e),
                node_id: overlay.identity.node_id,
                duration_ms: 0,
            });

            // Send result back to origin
            let complete = MeshMessage::TaskComplete {
                task_id: task_id_exec,
                result,
            };
            let _ = overlay.send_to(&from_id, &complete).await;
        }
        MeshMessage::TaskAccept { task_id, node_id } => {
            tracing::info!(
                "Task {} accepted by {}",
                task_id,
                node_id_hex(&node_id)
            );
            if let Some(tx) = event_tx {
                let _ = tx.send(ClusterEvent::TaskAccepted {
                    task_id,
                    node_id: node_id_hex(&node_id),
                });
            }
        }
        MeshMessage::TaskStream { task_id, chunk } => {
            if let Some(tx) = event_tx {
                let _ = tx.send(ClusterEvent::TaskStream {
                    task_id,
                    chunk,
                });
            }
        }
        MeshMessage::TaskComplete { task_id, result } => {
            tracing::info!(
                "Task {} completed by {} (success={})",
                task_id,
                node_id_hex(&result.node_id),
                result.success
            );
            // Resolve pending task future
            let mut pending = pending_tasks.write().await;
            if let Some(tx) = pending.remove(&task_id) {
                let _ = tx.send(result.clone());
            }
            if let Some(etx) = event_tx {
                let _ = etx.send(ClusterEvent::TaskCompleted {
                    task_id,
                    node_id: node_id_hex(&result.node_id),
                    success: result.success,
                    response: result.response,
                });
            }
        }
        _ => {
            tracing::debug!("Unhandled mesh message from {}", node_id_hex(&from));
        }
    }
}

/// Events emitted by the cluster for the UI/SSE layer.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type")]
pub enum ClusterEvent {
    NodeJoined { node_id: String, hostname: String },
    NodeLeft { node_id: String },
    TaskReceived { task_id: String, from: String, content: String },
    TaskAccepted { task_id: String, node_id: String },
    TaskStream { task_id: String, chunk: TaskStreamChunk },
    TaskCompleted { task_id: String, node_id: String, success: bool, response: String },
    MeshStatus { node_count: usize, peer_count: usize },
}

/// Detect local system capabilities.
fn detect_capabilities() -> NodeCapabilities {
    let gpu = detect_gpu();

    let (free_mem, total_mem) = {
        let info = sys_info::mem_info().ok();
        (
            info.as_ref().map(|i| i.avail / 1024).unwrap_or(0),
            info.as_ref().map(|i| i.total / 1024).unwrap_or(0),
        )
    };

    NodeCapabilities {
        gpu,
        loaded_model: None, // Set by the agent after model loads
        available_tools: vec![], // Set by the tool registry
        free_memory_mb: free_mem,
        total_memory_mb: total_mem,
    }
}

/// Compute current system load as 0.0-1.0.
fn compute_load() -> f32 {
    if let Ok(info) = sys_info::loadavg() {
        let cpus = sys_info::cpu_num().unwrap_or(1) as f64;
        (info.one / cpus).min(1.0) as f32
    } else {
        0.0
    }
}

/// Detect NVIDIA GPU via nvidia-smi.
fn detect_gpu() -> Option<GpuInfo> {
    let output = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,memory.total,memory.free",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let line = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = line.trim().split(", ").collect();
    if parts.len() < 3 {
        return None;
    }

    Some(GpuInfo {
        name: parts[0].to_string(),
        vram_total_mb: parts[1].parse().unwrap_or(0),
        vram_free_mb: parts[2].parse().unwrap_or(0),
        compute_capability: None,
    })
}
