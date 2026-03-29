//! Post-quantum cryptography for mesh communication.
//!
//! Uses ML-KEM-768 (Kyber) for key encapsulation and AES-256-GCM for
//! symmetric encryption. Ed25519 for signing beacons and handshakes.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

use super::types::NodeId;

/// Persistent mesh identity (keypairs).
#[derive(Serialize, Deserialize)]
struct StoredKeys {
    kem_pk: Vec<u8>,
    kem_sk: Vec<u8>,
    sign_seed: [u8; 32],
}

/// A node's cryptographic identity.
pub struct MeshIdentity {
    pub node_id: NodeId,
    pub kem_pk: kyber768::PublicKey,
    kem_sk: kyber768::SecretKey,
    pub sign_key: SigningKey,
    pub verify_key: VerifyingKey,
}

impl MeshIdentity {
    /// Generate a new identity or load from disk.
    pub fn load_or_generate(path: &str) -> anyhow::Result<Self> {
        if Path::new(path).exists() {
            Self::load(path)
        } else {
            let identity = Self::generate();
            identity.save(path)?;
            Ok(identity)
        }
    }

    /// Generate fresh keypairs.
    pub fn generate() -> Self {
        let (kem_pk, kem_sk) = kyber768::keypair();
        let mut seed = [0u8; 32];
        rand::Fill::try_fill(&mut seed, &mut OsRng).expect("RNG fill");
        let sign_key = SigningKey::from_bytes(&seed);
        let verify_key = sign_key.verifying_key();

        // NodeId = first 16 bytes of blake3(kem_pk || sign_pk)
        let mut hasher = blake3::Hasher::new();
        hasher.update(kem_pk.as_bytes());
        hasher.update(verify_key.as_bytes());
        let hash = hasher.finalize();
        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&hash.as_bytes()[..16]);

        Self {
            node_id,
            kem_pk,
            kem_sk,
            sign_key,
            verify_key,
        }
    }

    fn save(&self, path: &str) -> anyhow::Result<()> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let stored = StoredKeys {
            kem_pk: self.kem_pk.as_bytes().to_vec(),
            kem_sk: self.kem_sk.as_bytes().to_vec(),
            sign_seed: self.sign_key.to_bytes(),
        };
        let json = serde_json::to_string_pretty(&stored)?;
        std::fs::write(path, json)?;
        // Restrict permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn load(path: &str) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let stored: StoredKeys = serde_json::from_str(&json)?;

        let kem_pk = kyber768::PublicKey::from_bytes(&stored.kem_pk)
            .map_err(|_| anyhow::anyhow!("Invalid KEM public key"))?;
        let kem_sk = kyber768::SecretKey::from_bytes(&stored.kem_sk)
            .map_err(|_| anyhow::anyhow!("Invalid KEM secret key"))?;
        let sign_key = SigningKey::from_bytes(&stored.sign_seed);
        let verify_key = sign_key.verifying_key();

        let mut hasher = blake3::Hasher::new();
        hasher.update(kem_pk.as_bytes());
        hasher.update(verify_key.as_bytes());
        let hash = hasher.finalize();
        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&hash.as_bytes()[..16]);

        Ok(Self {
            node_id,
            kem_pk,
            kem_sk,
            sign_key,
            verify_key,
        })
    }

    /// Sign a message with ed25519.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sign_key.sign(msg).to_bytes().to_vec()
    }

    /// Verify a signature against a public key.
    pub fn verify(pubkey: &VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != 64 {
            return false;
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(sig);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        pubkey.verify(msg, &signature).is_ok()
    }

    /// Decapsulate a shared secret from a ciphertext (responder side).
    pub fn decapsulate(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let ct = kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| anyhow::anyhow!("Invalid KEM ciphertext"))?;
        let ss = kyber768::decapsulate(&ct, &self.kem_sk);
        Ok(ss.as_bytes().to_vec())
    }

    /// Public KEM key bytes for sharing.
    pub fn kem_pk_bytes(&self) -> Vec<u8> {
        self.kem_pk.as_bytes().to_vec()
    }

    /// Public verify key bytes for sharing.
    pub fn verify_key_bytes(&self) -> Vec<u8> {
        self.verify_key.to_bytes().to_vec()
    }
}

/// Encapsulate a shared secret using a peer's public KEM key (initiator side).
pub fn encapsulate(peer_kem_pk: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let pk = kyber768::PublicKey::from_bytes(peer_kem_pk)
        .map_err(|_| anyhow::anyhow!("Invalid peer KEM public key"))?;
    let (ss, ct) = kyber768::encapsulate(&pk);
    Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
}

/// Derive symmetric encryption keys from a shared secret.
pub fn derive_keys(shared_secret: &[u8], initiator_id: &NodeId, responder_id: &NodeId) -> (Aes256Gcm, Aes256Gcm) {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);

    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];

    // Deterministic key derivation: initiator always gets "init" key
    let mut info_send = Vec::new();
    info_send.extend_from_slice(b"omesh-send-");
    info_send.extend_from_slice(initiator_id);
    info_send.extend_from_slice(responder_id);
    hk.expand(&info_send, &mut send_key).expect("HKDF expand");

    let mut info_recv = Vec::new();
    info_recv.extend_from_slice(b"omesh-recv-");
    info_recv.extend_from_slice(responder_id);
    info_recv.extend_from_slice(initiator_id);
    hk.expand(&info_recv, &mut recv_key).expect("HKDF expand");

    let send_cipher = Aes256Gcm::new_from_slice(&send_key).expect("AES key");
    let recv_cipher = Aes256Gcm::new_from_slice(&recv_key).expect("AES key");

    (send_cipher, recv_cipher)
}

/// Encrypt a message with AES-256-GCM.
pub fn encrypt(cipher: &Aes256Gcm, nonce_counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&nonce_counter.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext).expect("AES-GCM encrypt");

    // Frame: nonce_counter(8 bytes) || ciphertext
    let mut frame = Vec::with_capacity(8 + ciphertext.len());
    frame.extend_from_slice(&nonce_counter.to_be_bytes());
    frame.extend_from_slice(&ciphertext);
    frame
}

/// Decrypt a message with AES-256-GCM.
pub fn decrypt(cipher: &Aes256Gcm, frame: &[u8]) -> anyhow::Result<Vec<u8>> {
    if frame.len() < 8 {
        anyhow::bail!("Frame too short");
    }
    let mut nonce_counter_bytes = [0u8; 8];
    nonce_counter_bytes.copy_from_slice(&frame[..8]);
    let nonce_counter = u64::from_be_bytes(nonce_counter_bytes);

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&nonce_counter.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, &frame[8..])
        .map_err(|_| anyhow::anyhow!("AES-GCM decrypt failed"))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generate() {
        let id = MeshIdentity::generate();
        assert_ne!(id.node_id, [0u8; 16]);
    }

    #[test]
    fn test_sign_verify() {
        let id = MeshIdentity::generate();
        let msg = b"hello mesh";
        let sig = id.sign(msg);
        assert!(MeshIdentity::verify(&id.verify_key, msg, &sig));
        assert!(!MeshIdentity::verify(&id.verify_key, b"wrong", &sig));
    }

    #[test]
    fn test_kem_roundtrip() {
        let node_a = MeshIdentity::generate();
        let node_b = MeshIdentity::generate();

        // A encapsulates for B
        let (ss_a, ct) = encapsulate(&node_b.kem_pk_bytes()).unwrap();
        // B decapsulates
        let ss_b = node_b.decapsulate(&ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let node_a = MeshIdentity::generate();
        let node_b = MeshIdentity::generate();

        let (ss, _ct) = encapsulate(&node_b.kem_pk_bytes()).unwrap();
        let (send_cipher, recv_cipher) = derive_keys(&ss, &node_a.node_id, &node_b.node_id);

        let plaintext = b"secret mesh message";
        let frame = encrypt(&send_cipher, 1, plaintext);
        let decrypted = decrypt(&recv_cipher, &frame).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
