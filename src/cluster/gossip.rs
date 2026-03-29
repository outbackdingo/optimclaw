//! SWIM-lite gossip protocol for membership and failure detection.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use super::types::*;

/// State of a member in the gossip membership table.
#[derive(Debug, Clone)]
pub struct MemberState {
    pub info: NodeInfo,
    pub status: MemberStatus,
    pub incarnation: u64,
    pub last_seen: Instant,
    pub suspect_since: Option<Instant>,
}

/// The gossip membership table.
pub struct GossipState {
    members: RwLock<HashMap<NodeId, MemberState>>,
    local_id: NodeId,
    local_incarnation: RwLock<u64>,
}

impl GossipState {
    pub fn new(local_id: NodeId) -> Self {
        Self {
            members: RwLock::new(HashMap::new()),
            local_id,
            local_incarnation: RwLock::new(0),
        }
    }

    /// Add or update a node in the membership table.
    pub async fn merge_node(&self, info: NodeInfo, incarnation: u64, status: MemberStatus) {
        if info.id == self.local_id {
            return; // never merge self
        }

        let mut members = self.members.write().await;
        let entry = members.entry(info.id).or_insert_with(|| MemberState {
            info: info.clone(),
            status: MemberStatus::Alive,
            incarnation: 0,
            last_seen: Instant::now(),
            suspect_since: None,
        });

        // Only accept updates with higher incarnation
        if incarnation > entry.incarnation
            || (incarnation == entry.incarnation && status_priority(status) > status_priority(entry.status))
        {
            entry.info = info;
            entry.incarnation = incarnation;
            entry.status = status;
            entry.last_seen = Instant::now();

            if status == MemberStatus::Suspect {
                entry.suspect_since = Some(Instant::now());
            } else {
                entry.suspect_since = None;
            }
        }
    }

    /// Record a heartbeat from a node.
    pub async fn heartbeat(&self, node_id: &NodeId) {
        let mut members = self.members.write().await;
        if let Some(entry) = members.get_mut(node_id) {
            entry.last_seen = Instant::now();
            if entry.status == MemberStatus::Suspect {
                entry.status = MemberStatus::Alive;
                entry.suspect_since = None;
            }
        }
    }

    /// Mark a node as suspect.
    pub async fn mark_suspect(&self, node_id: &NodeId) {
        let mut members = self.members.write().await;
        if let Some(entry) = members.get_mut(node_id) {
            if entry.status == MemberStatus::Alive {
                entry.status = MemberStatus::Suspect;
                entry.suspect_since = Some(Instant::now());
                tracing::info!("Node {} marked suspect", node_id_hex(node_id));
            }
        }
    }

    /// Mark a node as dead and remove it.
    pub async fn mark_dead(&self, node_id: &NodeId) {
        let mut members = self.members.write().await;
        if let Some(entry) = members.get_mut(node_id) {
            entry.status = MemberStatus::Dead;
            tracing::info!("Node {} marked dead", node_id_hex(node_id));
        }
    }

    /// Remove dead nodes that have been dead for more than the given duration.
    pub async fn prune_dead(&self, max_age: std::time::Duration) {
        let mut members = self.members.write().await;
        members.retain(|id, entry| {
            if entry.status == MemberStatus::Dead || entry.status == MemberStatus::Left {
                if entry.last_seen.elapsed() > max_age {
                    tracing::debug!("Pruning dead node {}", node_id_hex(id));
                    return false;
                }
            }
            true
        });
    }

    /// Get all alive peers.
    pub async fn alive_peers(&self) -> Vec<NodeInfo> {
        self.members
            .read()
            .await
            .values()
            .filter(|m| m.status == MemberStatus::Alive)
            .map(|m| m.info.clone())
            .collect()
    }

    /// Get all known peers (any status).
    pub async fn all_peers(&self) -> Vec<(NodeInfo, MemberStatus)> {
        self.members
            .read()
            .await
            .values()
            .map(|m| (m.info.clone(), m.status))
            .collect()
    }

    /// Get nodes that should be checked for suspect/dead transitions.
    pub async fn check_timeouts(
        &self,
        suspect_timeout: std::time::Duration,
        dead_timeout: std::time::Duration,
    ) -> (Vec<NodeId>, Vec<NodeId>) {
        let members = self.members.read().await;
        let mut new_suspects = Vec::new();
        let mut new_dead = Vec::new();

        for (id, entry) in members.iter() {
            match entry.status {
                MemberStatus::Alive => {
                    if entry.last_seen.elapsed() > suspect_timeout {
                        new_suspects.push(*id);
                    }
                }
                MemberStatus::Suspect => {
                    if let Some(since) = entry.suspect_since {
                        if since.elapsed() > dead_timeout {
                            new_dead.push(*id);
                        }
                    }
                }
                _ => {}
            }
        }

        (new_suspects, new_dead)
    }

    /// Get a random alive peer for ping selection.
    pub async fn random_alive_peer(&self) -> Option<NodeInfo> {
        let members = self.members.read().await;
        let alive: Vec<_> = members
            .values()
            .filter(|m| m.status == MemberStatus::Alive)
            .collect();

        if alive.is_empty() {
            return None;
        }

        let idx = rand::random::<usize>() % alive.len();
        Some(alive[idx].info.clone())
    }

    /// Build piggybacked membership updates for gossip dissemination.
    pub async fn membership_updates(&self) -> Vec<MembershipUpdate> {
        self.members
            .read()
            .await
            .values()
            .map(|m| MembershipUpdate {
                node_id: m.info.id,
                incarnation: m.incarnation,
                status: m.status,
            })
            .collect()
    }

    /// Node count.
    pub async fn node_count(&self) -> usize {
        self.members.read().await.len()
    }

    /// Handle a node gracefully leaving.
    pub async fn handle_leave(&self, node_id: &NodeId) {
        let mut members = self.members.write().await;
        if let Some(entry) = members.get_mut(node_id) {
            entry.status = MemberStatus::Left;
            tracing::info!("Node {} left the mesh", node_id_hex(node_id));
        }
    }
}

fn status_priority(status: MemberStatus) -> u8 {
    match status {
        MemberStatus::Alive => 0,
        MemberStatus::Suspect => 1,
        MemberStatus::Dead => 2,
        MemberStatus::Left => 3,
    }
}
