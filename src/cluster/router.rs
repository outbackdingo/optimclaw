//! Intelligent task routing across the mesh.
//!
//! Scores nodes based on capability match, load, VRAM, and hop distance.

use super::gossip::GossipState;
use super::types::*;
use std::sync::Arc;

/// Score a node for a given task. Returns None if hard requirements aren't met.
pub fn score_node(node: &NodeInfo, task: &TaskEnvelope) -> Option<f64> {
    // Hard filters
    if let Some(ref model) = task.required_model {
        if node.capabilities.loaded_model.as_ref() != Some(model) {
            return None;
        }
    }

    for tool in &task.required_tools {
        if !node.capabilities.available_tools.contains(tool) {
            return None;
        }
    }

    if let Some(min_vram) = task.min_vram_mb {
        let free = node
            .capabilities
            .gpu
            .as_ref()
            .map(|g| g.vram_free_mb)
            .unwrap_or(0);
        if free < min_vram {
            return None;
        }
    }

    // Soft scoring (higher is better)
    let load_score = 1.0 - node.load.clamp(0.0, 1.0) as f64;

    let vram_score = node
        .capabilities
        .gpu
        .as_ref()
        .map(|g| {
            if g.vram_total_mb > 0 {
                g.vram_free_mb as f64 / g.vram_total_mb as f64
            } else {
                0.0
            }
        })
        .unwrap_or(0.0);

    let memory_score = if node.capabilities.total_memory_mb > 0 {
        node.capabilities.free_memory_mb as f64 / node.capabilities.total_memory_mb as f64
    } else {
        0.0
    };

    let hop_score = if task.hop_count == 0 {
        1.0
    } else {
        1.0 / (task.hop_count as f64 + 1.0)
    };

    let model_bonus = if task.required_model.is_some()
        && node.capabilities.loaded_model == task.required_model
    {
        1.0
    } else {
        0.0
    };

    Some(
        load_score * 0.35
            + vram_score * 0.25
            + memory_score * 0.15
            + hop_score * 0.15
            + model_bonus * 0.10,
    )
}

/// Select the best node for a task from the gossip membership.
pub async fn route_task(
    gossip: &GossipState,
    local_info: &NodeInfo,
    task: &TaskEnvelope,
) -> Option<NodeInfo> {
    let mut candidates: Vec<(NodeInfo, f64)> = Vec::new();

    // Score local node
    if let Some(score) = score_node(local_info, task) {
        candidates.push((local_info.clone(), score));
    }

    // Score peers
    for peer in gossip.alive_peers().await {
        if let Some(score) = score_node(&peer, task) {
            candidates.push((peer, score));
        }
    }

    // Sort by score descending
    candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    candidates.into_iter().next().map(|(node, _)| node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn make_node(load: f32, vram_free: u64, vram_total: u64, model: Option<&str>) -> NodeInfo {
        NodeInfo {
            id: [0; 16],
            hostname: "test".into(),
            mesh_addr: "127.0.0.1:9901".parse().unwrap(),
            gateway_addr: None,
            capabilities: NodeCapabilities {
                gpu: Some(GpuInfo {
                    name: "RTX 3060".into(),
                    vram_total_mb: vram_total,
                    vram_free_mb: vram_free,
                    compute_capability: None,
                }),
                loaded_model: model.map(|s| s.to_string()),
                available_tools: vec!["shell".into(), "read_file".into()],
                free_memory_mb: 8000,
                total_memory_mb: 16000,
            },
            load,
            version: "0.22.0".into(),
            started_at: 0,
            last_heartbeat: 0,
        }
    }

    fn make_task() -> TaskEnvelope {
        TaskEnvelope {
            task_id: "test".into(),
            content: "test task".into(),
            origin_node: [0; 16],
            required_model: None,
            required_tools: vec![],
            min_vram_mb: None,
            priority: 0,
            hop_count: 0,
        }
    }

    #[test]
    fn test_idle_node_preferred() {
        let task = make_task();
        let idle = make_node(0.1, 4000, 6000, None);
        let busy = make_node(0.9, 4000, 6000, None);
        assert!(score_node(&idle, &task).unwrap() > score_node(&busy, &task).unwrap());
    }

    #[test]
    fn test_model_hard_filter() {
        let mut task = make_task();
        task.required_model = Some("llama3".into());
        let node = make_node(0.0, 4000, 6000, Some("qwen2.5"));
        assert!(score_node(&node, &task).is_none());
    }

    #[test]
    fn test_vram_hard_filter() {
        let mut task = make_task();
        task.min_vram_mb = Some(8000);
        let node = make_node(0.0, 4000, 6000, None);
        assert!(score_node(&node, &task).is_none());
    }
}
