//! REST API endpoints for mesh cluster status and task submission.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Arc;

use super::types::*;
use super::MeshNode;

/// Build the cluster API routes.
pub fn cluster_routes() -> Router<Option<Arc<MeshNode>>> {
    Router::new()
        .route("/api/mesh/status", get(mesh_status))
        .route("/api/mesh/nodes", get(mesh_nodes))
}

#[derive(Serialize)]
struct MeshStatus {
    enabled: bool,
    node_id: String,
    hostname: String,
    peer_count: usize,
    total_nodes: usize,
    mesh_port: u16,
}

#[derive(Serialize)]
struct MeshNodeInfo {
    node_id: String,
    hostname: String,
    status: String,
    load: f32,
    gpu: Option<String>,
    loaded_model: Option<String>,
    tool_count: usize,
    free_memory_mb: u64,
}

async fn mesh_status(
    State(mesh): State<Option<Arc<MeshNode>>>,
) -> Json<MeshStatus> {
    match mesh {
        Some(node) => {
            let peer_count = node.overlay.peer_count().await;
            let total = node.gossip.node_count().await + 1; // +1 for self
            Json(MeshStatus {
                enabled: true,
                node_id: node_id_hex(&node.identity.node_id),
                hostname: node.config.node_name.clone(),
                peer_count,
                total_nodes: total,
                mesh_port: node.config.mesh_port,
            })
        }
        None => Json(MeshStatus {
            enabled: false,
            node_id: String::new(),
            hostname: String::new(),
            peer_count: 0,
            total_nodes: 0,
            mesh_port: 0,
        }),
    }
}

async fn mesh_nodes(
    State(mesh): State<Option<Arc<MeshNode>>>,
) -> Json<Vec<MeshNodeInfo>> {
    let Some(node) = mesh else {
        return Json(vec![]);
    };

    let mut nodes = Vec::new();

    // Add self
    nodes.push(MeshNodeInfo {
        node_id: node_id_hex(&node.identity.node_id),
        hostname: node.config.node_name.clone(),
        status: "self".into(),
        load: super::compute_load(),
        gpu: node.local_capabilities().gpu.as_ref().map(|g| g.name.clone()),
        loaded_model: node.local_capabilities().loaded_model.clone(),
        tool_count: node.local_capabilities().available_tools.len(),
        free_memory_mb: node.local_capabilities().free_memory_mb,
    });

    // Add peers
    for (info, status) in node.gossip.all_peers().await {
        nodes.push(MeshNodeInfo {
            node_id: node_id_hex(&info.id),
            hostname: info.hostname,
            status: format!("{:?}", status),
            load: info.load,
            gpu: info.capabilities.gpu.as_ref().map(|g| g.name.clone()),
            loaded_model: info.capabilities.loaded_model.clone(),
            tool_count: info.capabilities.available_tools.len(),
            free_memory_mb: info.capabilities.free_memory_mb,
        });
    }

    Json(nodes)
}
