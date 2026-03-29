//! VLESS proxy inbound over QUIC.
//!
//! Accepts QUIC connections with ALPN `"oproxy/1"` and speaks the VLESS v0
//! protocol, making the relay node usable as an Xray-compatible proxy.
//!
//! ## PQ note
//! The QUIC TLS layer uses a classical ephemeral cert (transport confidentiality
//! only). For 100% post-quantum on the proxy path, clients need a PQ-capable
//! QUIC stack (e.g. a PQ-enabled Xray build with ML-KEM support). The mesh
//! node-to-node path is always 100% PQ regardless.
//!
//! ## VLESS v0 header format
//! ```
//! [version:     1 byte  = 0x00]
//! [UUID:        16 bytes       ]
//! [addon_len:   1 byte         ]
//! [addons:      addon_len bytes]
//! [command:     1 byte  (1=TCP, 2=UDP)]
//! [port:        2 bytes BE     ]
//! [addr_type:   1 byte  (1=IPv4, 2=domain, 3=IPv6)]
//! [addr:        4 / N+1 / 16 bytes]
//! ```
//! Response: `[0x00][addon_len=0x00]` then raw data.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const VLESS_VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;
const ATYPE_IPV4: u8 = 0x01;
const ATYPE_DOMAIN: u8 = 0x02;
const ATYPE_IPV6: u8 = 0x03;

/// Handle a QUIC connection that arrived with ALPN `"oproxy/1"`.
///
/// Validates the VLESS UUID against `allowed_uuids`, connects to the
/// requested target, and splices the QUIC stream bidirectionally with TCP.
pub async fn handle_proxy_connection(
    conn: quinn::Connection,
    allowed_uuids: Arc<Vec<[u8; 16]>>,
) -> Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await?;

    // Parse the VLESS request header
    let (target_addr, target_port) = parse_vless_header(&mut recv, &allowed_uuids).await?;

    // Send VLESS response header: version(0x00) + addon_len(0x00)
    send.write_all(&[VLESS_VERSION, 0x00]).await?;

    // Connect to the target
    let target_addr_str = format!("{}:{}", target_addr, target_port);
    tracing::debug!("VLESS proxy → {}", target_addr_str);
    let tcp = TcpStream::connect(&target_addr_str).await?;
    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();

    // Splice: QUIC recv → TCP, TCP → QUIC send
    let quic_to_tcp = tokio::io::copy(&mut recv, &mut tcp_tx);
    let tcp_to_quic = tokio::io::copy(&mut tcp_rx, &mut send);

    tokio::select! {
        r = quic_to_tcp => { r.ok(); }
        r = tcp_to_quic => { r.ok(); }
    }

    Ok(())
}

/// Parse the VLESS v0 request header from a QUIC receive stream.
///
/// Returns `(target_host_string, port)` on success, or an error if the
/// UUID is not in `allowed_uuids` or the header is malformed.
async fn parse_vless_header(
    recv: &mut quinn::RecvStream,
    allowed_uuids: &[[u8; 16]],
) -> Result<(String, u16)> {
    // Version
    let version = recv.read_u8().await?;
    if version != VLESS_VERSION {
        bail!("Unsupported VLESS version: {}", version);
    }

    // UUID (16 bytes)
    let mut uuid = [0u8; 16];
    recv.read_exact(&mut uuid).await?;
    if !allowed_uuids.iter().any(|u| u == &uuid) {
        bail!("VLESS UUID not authorized");
    }

    // Additional info (skip)
    let addon_len = recv.read_u8().await? as usize;
    if addon_len > 0 {
        let mut skip = vec![0u8; addon_len];
        recv.read_exact(&mut skip).await?;
    }

    // Command
    let cmd = recv.read_u8().await?;
    if cmd != CMD_TCP && cmd != CMD_UDP {
        bail!("Unsupported VLESS command: {}", cmd);
    }

    // Port (2 bytes BE)
    let port = recv.read_u16().await?;

    // Address
    let addr_type = recv.read_u8().await?;
    let host = match addr_type {
        ATYPE_IPV4 => {
            let mut octets = [0u8; 4];
            recv.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets)).to_string()
        }
        ATYPE_IPV6 => {
            let mut octets = [0u8; 16];
            recv.read_exact(&mut octets).await?;
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
        ATYPE_DOMAIN => {
            let domain_len = recv.read_u8().await? as usize;
            if domain_len == 0 || domain_len > 253 {
                bail!("Invalid VLESS domain length: {}", domain_len);
            }
            let mut domain_bytes = vec![0u8; domain_len];
            recv.read_exact(&mut domain_bytes).await?;
            String::from_utf8(domain_bytes)
                .map_err(|_| anyhow::anyhow!("VLESS domain is not valid UTF-8"))?
        }
        _ => bail!("Unknown VLESS address type: {}", addr_type),
    };

    Ok((host, port))
}

/// Parse a UUID string (e.g. `"550e8400-e29b-41d4-a716-446655440000"`) into 16 bytes.
pub fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        bail!("Invalid UUID: {}", s);
    }
    let bytes = (0..16)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()
        .map_err(|_| anyhow::anyhow!("UUID parse failed: {}", s))?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}
