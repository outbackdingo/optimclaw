//! QUIC transport layer for the mesh overlay.
//!
//! Provides UDP-based connectivity (NAT hole-punching capable, like Nebula) via
//! the quinn QUIC implementation. An ephemeral self-signed TLS certificate is used
//! for the QUIC handshake — it provides transport confidentiality only. All real
//! authentication and post-quantum security comes from the ML-KEM-768 application
//! handshake in overlay.rs.
//!
//! Two ALPN values share the single UDP port:
//!   "omesh/1"  — mesh overlay protocol (PQ handshake + MeshMessage frames)
//!   "oproxy/1" — VLESS proxy inbound (for Xray-compatible clients)

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, PrivateKeyDer};

/// ALPN token for mesh overlay traffic.
pub const ALPN_MESH: &[u8] = b"omesh/1";
/// ALPN token for VLESS proxy traffic.
pub const ALPN_PROXY: &[u8] = b"oproxy/1";

// ── Endpoint construction ─────────────────────────────────────────────────────

/// Build a QUIC endpoint that listens for incoming connections (server role)
/// and can also initiate outbound connections (client role).
///
/// Accepts connections with ALPN `"omesh/1"` (mesh) and `"oproxy/1"` (proxy).
/// Uses an ephemeral self-signed certificate — authentication is done by the PQ
/// application handshake, not by TLS certificate verification.
pub fn make_server_endpoint(bind_addr: SocketAddr) -> Result<Endpoint> {
    let (cert_chain, priv_key) = generate_ephemeral_cert()?;

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)?;
    tls.alpn_protocols = vec![ALPN_MESH.to_vec(), ALPN_PROXY.to_vec()];

    let server_cfg = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| anyhow::anyhow!("QUIC server crypto: {}", e))?,
    ));

    let endpoint = Endpoint::server(server_cfg, bind_addr)?;
    Ok(endpoint)
}

/// Build a QUIC client config that skips TLS certificate verification.
///
/// Security does NOT depend on certificate validity — our ML-KEM-768 handshake
/// running on the first QUIC stream provides authentication and PQ confidentiality.
pub fn make_client_config() -> Result<ClientConfig> {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN_MESH.to_vec()];

    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| anyhow::anyhow!("QUIC client crypto: {}", e))?,
    )))
}

// ── Length-prefix framing over QUIC streams ───────────────────────────────────
//
// QUIC streams are byte streams, not message streams. We use 4-byte big-endian
// length prefixes so both handshake JSON and encrypted MeshMessage frames can
// be exchanged as discrete messages.

/// Write a length-prefixed frame to a QUIC send stream.
pub async fn send_frame(stream: &mut quinn::SendStream, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| anyhow::anyhow!("Frame too large: {} bytes", data.len()))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    Ok(())
}

/// Read a length-prefixed frame from a QUIC receive stream.
pub async fn recv_frame(stream: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        anyhow::bail!("Frame too large: {} bytes", len);
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

// ── Ephemeral certificate ─────────────────────────────────────────────────────

fn generate_ephemeral_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["omesh".to_string()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    Ok((vec![cert_der], key_der))
}

// ── TLS certificate verifier that accepts any cert ───────────────────────────

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
