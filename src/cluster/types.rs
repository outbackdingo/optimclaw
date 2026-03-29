//! Core types for the OptimClaw mesh network.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// 16-byte node identifier, derived from blake3 hash of the node's public key.
pub type NodeId = [u8; 16];

/// Hex-encode a NodeId for display.
pub fn node_id_hex(id: &NodeId) -> String {
    hex::encode(id)
}

/// Parse a hex string back to NodeId.
pub fn node_id_from_hex(s: &str) -> Option<NodeId> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    Some(id)
}

/// Information about a node in the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: NodeId,
    pub hostname: String,
    pub mesh_addr: SocketAddr,
    pub gateway_addr: Option<SocketAddr>,
    pub capabilities: NodeCapabilities,
    pub load: f32,
    pub version: String,
    pub started_at: i64,
    pub last_heartbeat: i64,
}

/// What a node can do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub gpu: Option<GpuInfo>,
    pub loaded_model: Option<String>,
    pub available_tools: Vec<String>,
    pub free_memory_mb: u64,
    pub total_memory_mb: u64,
}

/// GPU information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub name: String,
    pub vram_total_mb: u64,
    pub vram_free_mb: u64,
    pub compute_capability: Option<String>,
}

/// Messages exchanged between mesh nodes (over encrypted WebSocket).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MeshMessage {
    // -- Gossip / Membership --
    Ping {
        from: NodeId,
        seq: u64,
        piggyback: Vec<MembershipUpdate>,
    },
    Ack {
        from: NodeId,
        seq: u64,
        piggyback: Vec<MembershipUpdate>,
    },
    IndirectPing {
        origin: NodeId,
        target: NodeId,
        seq: u64,
    },
    IndirectAck {
        origin: NodeId,
        target: NodeId,
        seq: u64,
        alive: bool,
    },

    // -- Peer exchange --
    PeerExchange {
        nodes: Vec<NodeInfo>,
    },

    // -- Task routing --
    TaskRequest {
        task_id: String,
        envelope: TaskEnvelope,
    },
    TaskAccept {
        task_id: String,
        node_id: NodeId,
    },
    TaskReject {
        task_id: String,
        node_id: NodeId,
        reason: String,
    },
    TaskStream {
        task_id: String,
        chunk: TaskStreamChunk,
    },
    TaskComplete {
        task_id: String,
        result: TaskResult,
    },

    // -- Lifecycle --
    Leaving {
        id: NodeId,
    },
}

/// Piggybacked membership state change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipUpdate {
    pub node_id: NodeId,
    pub incarnation: u64,
    pub status: MemberStatus,
}

/// Node status in the membership table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberStatus {
    Alive,
    Suspect,
    Dead,
    Left,
}

/// A task to be routed across the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskEnvelope {
    pub task_id: String,
    pub content: String,
    pub origin_node: NodeId,
    pub required_model: Option<String>,
    pub required_tools: Vec<String>,
    pub min_vram_mb: Option<u64>,
    pub priority: u8,
    pub hop_count: u8,
}

/// Streaming chunk from a task execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum TaskStreamChunk {
    Text { content: String },
    ToolStarted { name: String, summary: String },
    ToolCompleted { name: String, success: bool, output: String },
    Thinking,
}

/// Final result of a task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub success: bool,
    pub response: String,
    pub node_id: NodeId,
    pub duration_ms: u64,
}

/// UDP beacon packet (compact binary format).
pub const BEACON_MAGIC: &[u8; 6] = b"OMESH1";
pub const BEACON_PORT: u16 = 9900;
pub const MESH_PORT: u16 = 9901;

/// Beacon flags.
pub const FLAG_HAS_GPU: u8 = 0x01;
pub const FLAG_ACCEPTING_TASKS: u8 = 0x02;
