# OptimClaw Mesh Cluster

## Overview

The OptimClaw Mesh Cluster enables multiple OptimClaw instances to form an autonomous AI mesh network. Each node in the cluster operates independently while collaborating on tasks, sharing workload, and providing fault tolerance. Nodes discover each other automatically via UDP beacons, authenticate using post-quantum cryptography, and coordinate through a gossip-based membership protocol.

Key capabilities:

- **Automatic discovery** -- zero-configuration node joining via UDP broadcast beacons
- **Post-quantum security** -- ML-KEM-768 key encapsulation with AES-256-GCM authenticated encryption
- **Gossip membership** -- SWIM protocol for reliable failure detection and cluster state convergence
- **Intelligent task routing** -- scoring algorithm that considers load, latency, capability, and affinity
- **Graceful degradation** -- nodes operate independently if connectivity is lost

## Architecture

```
                         ┌─────────────────────────────────────────────┐
                         │              Mesh Cluster                   │
                         │                                             │
  ┌──────────────┐       │   ┌──────────┐    Gossip     ┌──────────┐  │
  │   Client     │──────►│   │  Node A  │◄────────────►│  Node B  │  │
  │  (any chan.) │       │   │          │   (SWIM)      │          │  │
  └──────────────┘       │   │ ┌──────┐ │               │ ┌──────┐ │  │
                         │   │ │Agent │ │               │ │Agent │ │  │
                         │   │ │ Loop │ │               │ │ Loop │ │  │
                         │   │ └──────┘ │               │ └──────┘ │  │
                         │   │ ┌──────┐ │               │ ┌──────┐ │  │
                         │   │ │Tools │ │               │ │Tools │ │  │
                         │   │ └──────┘ │               │ └──────┘ │  │
                         │   └─────┬────┘               └────┬─────┘  │
                         │         │                         │        │
                         │         │    UDP Beacons          │        │
                         │         │◄───────────────────────►│        │
                         │         │                         │        │
                         │         │    Task Routing          │        │
                         │         │◄───────────────────────►│        │
                         │         │   (ML-KEM-768 +         │        │
                         │         │    AES-256-GCM)         │        │
                         │   ┌─────┴────┐               ┌────┴─────┐  │
                         │   │  Node C  │◄────────────►│  Node D  │  │
                         │   └──────────┘   Gossip      └──────────┘  │
                         │                                             │
                         └─────────────────────────────────────────────┘

Data flow:
  1. UDP beacon broadcast → node discovery
  2. ML-KEM-768 handshake → shared secret
  3. AES-256-GCM encrypted channel established
  4. SWIM gossip protocol → membership state
  5. Task routing → best node selected via scoring
  6. Encrypted task dispatch + result collection
```

## Configuration

All cluster settings are controlled via environment variables prefixed with `CLUSTER_`. They can be set in `~/.optimclaw/.env` or passed directly.

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CLUSTER_ENABLED` | bool | `false` | Enable mesh cluster mode |
| `CLUSTER_NODE_ID` | string | auto (hostname) | Unique identifier for this node |
| `CLUSTER_BIND_ADDR` | string | `0.0.0.0` | Address to bind the cluster transport |
| `CLUSTER_BIND_PORT` | u16 | `9400` | Port for the encrypted cluster transport |
| `CLUSTER_BEACON_PORT` | u16 | `9401` | UDP port for discovery beacons |
| `CLUSTER_BEACON_INTERVAL_MS` | u64 | `5000` | Milliseconds between beacon broadcasts |
| `CLUSTER_BEACON_SUBNET` | string | `255.255.255.255` | Broadcast address for beacons |
| `CLUSTER_SECRET` | string | *required* | Pre-shared key for cluster authentication (min 32 chars) |
| `CLUSTER_SEEDS` | string | `""` | Comma-separated seed node addresses (`host:port`) for non-broadcast environments |
| `CLUSTER_GOSSIP_INTERVAL_MS` | u64 | `1000` | Milliseconds between gossip protocol rounds |
| `CLUSTER_GOSSIP_FANOUT` | u8 | `3` | Number of peers to gossip with per round |
| `CLUSTER_SUSPICION_MULT` | u8 | `4` | Multiplier for suspicion timeout (suspicion_mult * gossip_interval) |
| `CLUSTER_PROBE_INTERVAL_MS` | u64 | `2000` | Milliseconds between SWIM probe pings |
| `CLUSTER_PROBE_TIMEOUT_MS` | u64 | `500` | Timeout for a direct probe response |
| `CLUSTER_INDIRECT_PROBES` | u8 | `3` | Number of indirect probes before suspicion |
| `CLUSTER_TASK_TIMEOUT_SECS` | u64 | `300` | Timeout for a routed task to complete |
| `CLUSTER_MAX_NODES` | u16 | `64` | Maximum cluster size |
| `CLUSTER_TLS_CERT` | path | `""` | Optional TLS certificate for cross-datacenter transport |
| `CLUSTER_TLS_KEY` | path | `""` | Optional TLS private key |
| `CLUSTER_ADVERTISE_ADDR` | string | auto | Address advertised to other nodes (for NAT traversal) |
| `CLUSTER_ADVERTISE_PORT` | u16 | same as bind | Port advertised to other nodes |
| `CLUSTER_REGION` | string | `""` | Logical region tag for locality-aware routing |
| `CLUSTER_CAPABILITIES` | string | `""` | Comma-separated capability tags (e.g., `gpu,high-memory,docker`) |

### Minimal Configuration

```env
CLUSTER_ENABLED=true
CLUSTER_SECRET=my-very-long-pre-shared-key-at-least-32-chars
```

### Cross-Datacenter Configuration

```env
CLUSTER_ENABLED=true
CLUSTER_SECRET=my-very-long-pre-shared-key-at-least-32-chars
CLUSTER_SEEDS=dc1-node1.example.com:9400,dc2-node1.example.com:9400
CLUSTER_ADVERTISE_ADDR=203.0.113.10
CLUSTER_REGION=us-east-1
CLUSTER_TLS_CERT=/etc/optimclaw/cluster.crt
CLUSTER_TLS_KEY=/etc/optimclaw/cluster.key
```

## Discovery Protocol

Nodes discover each other using a UDP beacon protocol. When a node starts with `CLUSTER_ENABLED=true`, it begins broadcasting beacon packets on the configured broadcast address and port.

### Beacon Packet Format

```
Offset  Size    Field
0       4       Magic bytes: 0x4F 0x43 0x4D 0x53 ("OCMS")
4       1       Protocol version (currently 0x01)
5       2       Beacon port (big-endian u16)
7       2       Transport port (big-endian u16)
9       32      Node ID (UTF-8, zero-padded)
41      32      HMAC-SHA256 of bytes 0..41 using CLUSTER_SECRET
```

Total beacon size: 73 bytes.

### Discovery Sequence

1. On startup, the node broadcasts a beacon every `CLUSTER_BEACON_INTERVAL_MS` milliseconds to `CLUSTER_BEACON_SUBNET:CLUSTER_BEACON_PORT`.
2. All listening nodes receive the beacon, verify the HMAC against their own `CLUSTER_SECRET`, and extract the sender's transport address.
3. If the beacon is from an unknown node, the receiving node initiates a post-quantum key exchange (see below) over TCP to the sender's transport address.
4. Once the encrypted channel is established, the new node is added to the membership list and the gossip protocol takes over.
5. In non-broadcast environments (cloud, cross-datacenter), set `CLUSTER_SEEDS` to bootstrap. The node will contact seed addresses directly instead of relying on broadcast.

Beacons continue to be sent after joining to help new nodes discover the cluster.

## Post-Quantum Cryptography

All inter-node communication is encrypted using a hybrid post-quantum scheme to protect against both classical and quantum adversaries.

### Key Exchange: ML-KEM-768

ML-KEM-768 (formerly CRYSTALS-Kyber) is a lattice-based key encapsulation mechanism standardized in FIPS 203. It provides IND-CCA2 security at NIST security level 3 (roughly equivalent to AES-192).

The handshake proceeds as follows:

1. **Initiator** generates an ML-KEM-768 keypair (ephemeral) and sends the public key (1184 bytes) along with its node ID and a challenge derived from `CLUSTER_SECRET`.
2. **Responder** verifies the challenge, encapsulates a shared secret using the received public key, and sends back the ciphertext (1088 bytes) along with its own challenge response.
3. Both sides derive the same 256-bit shared secret from the ML-KEM decapsulation.
4. The shared secret is combined with `CLUSTER_SECRET` via HKDF-SHA256 to produce the final session key, binding the session to the cluster identity.

### Authenticated Encryption: AES-256-GCM

All messages after the handshake are encrypted with AES-256-GCM using the derived session key:

- **Nonce**: 96-bit, incremented per message (with sender-direction bit to avoid reuse)
- **AAD (Additional Authenticated Data)**: message type + sequence number + sender node ID
- **Tag**: 128-bit authentication tag appended to ciphertext

### Key Rotation

Session keys are rotated every 1 hour or after 2^32 messages, whichever comes first. Rotation uses a new ML-KEM-768 encapsulation within the existing encrypted channel.

### Why Post-Quantum?

Mesh clusters may carry sensitive task data (credentials, personal information, tool outputs). Harvest-now-decrypt-later attacks make it prudent to deploy post-quantum cryptography today, even before large-scale quantum computers exist.

## Gossip Protocol (SWIM Membership)

The cluster uses the SWIM (Scalable Weakly-consistent Infection-style process group Membership) protocol for membership management and failure detection.

### Membership States

Each node maintains a membership list where every entry is in one of three states:

| State | Meaning |
|-------|---------|
| **Alive** | Node is healthy and responsive |
| **Suspect** | Node failed to respond to probes; may be down |
| **Dead** | Node confirmed unreachable; removed from routing |

### Protocol Rounds

Every `CLUSTER_GOSSIP_INTERVAL_MS`, each node performs:

1. **Probe** -- Select a random alive member and send a direct ping. If no ack within `CLUSTER_PROBE_TIMEOUT_MS`, send indirect pings through `CLUSTER_INDIRECT_PROBES` random members. If still no ack, mark the target as Suspect.
2. **Gossip** -- Piggyback membership updates (state changes, join/leave events) on probe messages. Each update includes a Lamport timestamp for crdt-style conflict resolution.
3. **Suspicion** -- Suspect nodes have `CLUSTER_SUSPICION_MULT * CLUSTER_GOSSIP_INTERVAL_MS` to refute by sending an Alive message with a higher incarnation number. If not refuted, the node transitions to Dead.

### Consistency

SWIM provides eventual consistency. After a state change, all nodes converge within O(log N) gossip rounds, where N is the cluster size. With default settings (1s gossip interval, fanout 3), a 64-node cluster converges in under 7 seconds.

### Join and Leave

- **Join**: Triggered by beacon discovery or seed contact. The joining node sends a Join message; existing members propagate the new membership via gossip.
- **Graceful leave**: A node sends a Leave message before shutting down. Other nodes immediately mark it Dead without suspicion.
- **Crash**: Detected by the probe/suspicion mechanism described above.

## Task Routing Algorithm

When a task arrives at any node, the router decides whether to execute it locally or forward it to a better-suited node. The decision is based on a scoring formula applied to each alive node.

### Scoring Formula

```
score(node) = w_load * (1 - load_ratio)
            + w_latency * (1 - latency_ratio)
            + w_capability * capability_match
            + w_affinity * affinity_bonus
            + w_locality * locality_bonus
```

Where:

| Factor | Weight (default) | Description |
|--------|-------------------|-------------|
| `load_ratio` | `w_load = 0.35` | Current jobs / max parallel jobs (lower is better) |
| `latency_ratio` | `w_latency = 0.25` | P95 RTT to this node / max observed RTT (lower is better) |
| `capability_match` | `w_capability = 0.25` | 1.0 if node has all required capabilities, 0.0 otherwise |
| `affinity_bonus` | `w_affinity = 0.10` | 1.0 if the task has session affinity to this node, 0.0 otherwise |
| `locality_bonus` | `w_locality = 0.05` | 1.0 if same `CLUSTER_REGION`, 0.5 if no region set, 0.0 otherwise |

### Routing Decision

1. Compute `score(node)` for all alive nodes including self.
2. If the local node's score is within 10% of the best score, execute locally (avoids unnecessary forwarding overhead).
3. Otherwise, forward the task to the highest-scoring node over the encrypted channel.
4. If the target node fails to accept within 5 seconds, fall back to local execution.
5. Results are returned to the originating node and delivered to the original client.

### Session Affinity

Tasks that reference an ongoing conversation or job context are preferentially routed to the node that holds that context. This avoids expensive context transfer between nodes.

## API Endpoints

The mesh cluster exposes monitoring endpoints on the standard web gateway.

### GET /api/mesh/status

Returns the cluster status for the local node.

**Response:**

```json
{
  "cluster_enabled": true,
  "node_id": "node-alpha",
  "state": "alive",
  "region": "us-east-1",
  "capabilities": ["gpu", "docker"],
  "uptime_secs": 86423,
  "transport": {
    "bind_addr": "0.0.0.0:9400",
    "advertise_addr": "203.0.113.10:9400",
    "encryption": "ML-KEM-768 + AES-256-GCM",
    "protocol_version": 1
  },
  "membership": {
    "alive": 4,
    "suspect": 0,
    "dead": 1,
    "total_seen": 5
  },
  "routing": {
    "local_load": 0.35,
    "tasks_routed_out": 142,
    "tasks_routed_in": 87,
    "tasks_failed_over": 3
  }
}
```

### GET /api/mesh/nodes

Returns the membership list with per-node details.

**Response:**

```json
{
  "nodes": [
    {
      "node_id": "node-alpha",
      "state": "alive",
      "addr": "203.0.113.10:9400",
      "region": "us-east-1",
      "capabilities": ["gpu", "docker"],
      "load_ratio": 0.35,
      "latency_ms": 0,
      "last_seen": "2026-03-29T12:34:56Z",
      "incarnation": 7,
      "is_self": true
    },
    {
      "node_id": "node-beta",
      "state": "alive",
      "addr": "203.0.113.11:9400",
      "region": "us-east-1",
      "capabilities": ["high-memory"],
      "load_ratio": 0.12,
      "latency_ms": 2,
      "last_seen": "2026-03-29T12:34:55Z",
      "incarnation": 3,
      "is_self": false
    }
  ]
}
```

### POST /api/mesh/nodes/{node_id}/drain

Puts a node into drain mode (stops accepting new routed tasks, finishes existing ones). Useful before maintenance.

**Response:**

```json
{
  "node_id": "node-beta",
  "drained": true,
  "remaining_tasks": 2
}
```

## Quick Start

### Running Two Nodes on the Same Machine

**Terminal 1 (Node A):**

```bash
export CLUSTER_ENABLED=true
export CLUSTER_SECRET="change-me-to-a-strong-shared-secret-at-least-32-characters"
export CLUSTER_NODE_ID=node-a
export CLUSTER_BIND_PORT=9400
export CLUSTER_BEACON_PORT=9401
export DATABASE_URL=postgres://localhost/optimclaw_a

optimclaw onboard   # if not already configured
cargo run
```

**Terminal 2 (Node B):**

```bash
export CLUSTER_ENABLED=true
export CLUSTER_SECRET="change-me-to-a-strong-shared-secret-at-least-32-characters"
export CLUSTER_NODE_ID=node-b
export CLUSTER_BIND_PORT=9410
export CLUSTER_BEACON_PORT=9401   # same beacon port so they discover each other
export DATABASE_URL=postgres://localhost/optimclaw_b

optimclaw onboard
cargo run
```

Within 5 seconds, both nodes should discover each other via UDP beacons. Verify by hitting the status endpoint:

```bash
curl http://localhost:3000/api/mesh/status | jq .membership
# {"alive": 2, "suspect": 0, "dead": 0, "total_seen": 2}
```

### Running Across Machines

On each machine, set the same `CLUSTER_SECRET` and either:

- Ensure UDP broadcast works on the local network (same subnet), or
- Set `CLUSTER_SEEDS` to the address of at least one other node:

```bash
export CLUSTER_SEEDS=192.168.1.100:9400
```

## Security Model

### Threat Model

The mesh cluster is designed to be secure against:

1. **Passive eavesdropping** -- All traffic is encrypted with AES-256-GCM.
2. **Active MITM** -- The ML-KEM-768 handshake is bound to `CLUSTER_SECRET`, preventing interception by parties without the pre-shared key.
3. **Quantum adversaries** -- ML-KEM-768 provides post-quantum security for key exchange.
4. **Rogue node injection** -- Beacons are authenticated with HMAC-SHA256; the handshake requires `CLUSTER_SECRET`.
5. **Replay attacks** -- Nonces are strictly monotonic; replayed messages are rejected.
6. **Partition exploitation** -- Nodes degrade to independent operation; no split-brain data corruption.

### Trust Boundaries

- All nodes sharing the same `CLUSTER_SECRET` are in the same trust domain.
- A compromised `CLUSTER_SECRET` means any attacker can join the cluster. Rotate the secret and restart all nodes if a compromise is suspected.
- Task data (including tool outputs) is encrypted in transit but available in plaintext to any node in the cluster. Do not add untrusted machines to a cluster that handles sensitive data.

### Network Recommendations

| Deployment | Recommendation |
|------------|----------------|
| Same LAN | UDP beacons work out of the box. Use a firewall to restrict beacon and transport ports to trusted hosts. |
| Cross-datacenter | Use `CLUSTER_SEEDS`, disable beacons by setting `CLUSTER_BEACON_INTERVAL_MS=0`, enable TLS (`CLUSTER_TLS_CERT` / `CLUSTER_TLS_KEY`), and restrict access via network ACLs. |
| Cloud (AWS/GCP/Azure) | Use private VPC networking. Set `CLUSTER_ADVERTISE_ADDR` to the private IP. Use security groups to restrict ports 9400-9401. |

## Troubleshooting

### Nodes not discovering each other

1. **Check `CLUSTER_SECRET`** -- Must be identical on all nodes. Even trailing whitespace matters.
2. **Check beacon port** -- All nodes must use the same `CLUSTER_BEACON_PORT`.
3. **Check UDP broadcast** -- Some cloud providers and corporate networks block UDP broadcast. Use `CLUSTER_SEEDS` instead.
4. **Check firewall** -- Ports `CLUSTER_BEACON_PORT` (UDP) and `CLUSTER_BIND_PORT` (TCP) must be open.
5. **Check logs** -- Run with `RUST_LOG=optimclaw::cluster=debug` to see beacon send/receive events.

### Node stuck in Suspect state

- This typically means the node is slow to respond to probes.
- Increase `CLUSTER_PROBE_TIMEOUT_MS` on busy nodes.
- Increase `CLUSTER_SUSPICION_MULT` to give more time before declaring a node dead.
- Check if the node is CPU-starved or under heavy I/O load.

### High task routing latency

- Check `curl localhost:3000/api/mesh/nodes | jq '.nodes[].latency_ms'` to identify slow links.
- Tasks are only routed away from the local node if a remote node scores >10% better. If most tasks should stay local, this is expected behavior.
- For cross-datacenter deployments, set `CLUSTER_REGION` on each node so the locality bonus keeps tasks close.

### Session key negotiation failures

- Both nodes must support the same protocol version. Ensure all nodes are running the same OptimClaw release.
- If using TLS (`CLUSTER_TLS_CERT`), verify the certificate is valid and trusted by the other node.
- Check for clock skew greater than 5 minutes between nodes.

### Node rejoining after network partition

- After a partition heals, the previously-dead node sends beacons again and is rediscovered.
- The rejoining node increments its incarnation number to override the Dead state in other nodes' membership lists.
- Any tasks that were in-flight to the partitioned node will have timed out and been retried locally.

### Diagnostic Commands

```bash
# Check cluster status
curl -s http://localhost:3000/api/mesh/status | jq .

# List all known nodes
curl -s http://localhost:3000/api/mesh/nodes | jq .

# Drain a node before maintenance
curl -s -X POST http://localhost:3000/api/mesh/nodes/node-beta/drain | jq .

# Watch cluster events in real time
RUST_LOG=optimclaw::cluster=debug cargo run 2>&1 | grep cluster
```
