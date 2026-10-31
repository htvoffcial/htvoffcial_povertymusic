//! Cryptographic building blocks: server identity, key exchange,
//! session keys and the media stream cipher.
//!
//! PVTP's threat model (spec §6) is *fake-server protection*: the
//! client must be sure it is talking to the genuine server. The server
//! therefore owns a long-term Ed25519 identity key whose public half is
//! pinned inside the app — a dedicated app talking to a dedicated
//! server needs no CA or certificate chain.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{PvtpError, Result};
use crate::PACKET_PAYLOAD_BYTES;

/// The server's long-term Ed25519 identity.
pub struct ServerIdentity {
    signing: SigningKey,
}

impl ServerIdentity {
    /// Generate a fresh identity (server provisioning).
    pub fn generate() -> Self {
        ServerIdentity {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Load an identity from its 32-byte secret seed.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        ServerIdentity {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    /// The 32-byte secret seed, for server-side storage. Treat like a
    /// password: never ship this to clients.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// The 32-byte public key that gets pinned in the app.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign a message with the identity key.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}

/// Verify an identity signature (client side, against the pinned key).
pub fn verify_server_signature(
    public: &[u8; 32],
    msg: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| PvtpError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    key.verify(msg, &sig).map_err(|_| PvtpError::BadSignature)
}

/// An ephemeral X25519 key pair for one handshake.
pub struct EphemeralKeypair {
    secret: StaticSecret,
    /// The public half, sent on the wire.
    pub public: [u8; 32],
}

impl EphemeralKeypair {
    /// Generate a fresh ephemeral key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        EphemeralKeypair { secret, public }
    }

    /// Run Diffie–Hellman against the peer's ephemeral public key.
    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer = PublicKey::from(*peer_public);
        self.secret.diffie_hellman(&peer).to_bytes()
    }
}

/// Keys derived from one handshake's shared secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// ChaCha20 key for media payloads.
    pub media_key: [u8; 32],
    /// BLAKE3 key for group MACs.
    pub mac_key: [u8; 32],
    /// ChaCha20 key for bulk blocks.
    pub bulk_key: [u8; 32],
    /// First 4 bytes of every per-packet nonce.
    pub nonce_prefix: [u8; 4],
}

/// Derive session keys from the X25519 shared secret, bound to the
/// client's handshake random so keys differ across sessions.
pub fn derive_session_keys(shared_secret: &[u8; 32], client_random: &[u8; 16]) -> SessionKeys {
    let hk = Hkdf::<Sha256>::new(Some(client_random), shared_secret);
    let mut media_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    let mut bulk_key = [0u8; 32];
    let mut nonce_prefix = [0u8; 4];
    hk.expand(b"pvtp v1 media key", &mut media_key)
        .expect("32-byte HKDF output is always in range");
    hk.expand(b"pvtp v1 mac key", &mut mac_key)
        .expect("32-byte HKDF output is always in range");
    hk.expand(b"pvtp v1 bulk key", &mut bulk_key)
        .expect("32-byte HKDF output is always in range");
    hk.expand(b"pvtp v1 nonce prefix", &mut nonce_prefix)
        .expect("4-byte HKDF output is always in range");
    SessionKeys {
        media_key,
        mac_key,
        bulk_key,
        nonce_prefix,
    }
}

/// The payload cipher for one direction of one session.
///
/// Each packet uses a fresh nonce — `nonce_prefix ‖ packet index` — so
/// the keystream is never reused within a session; encryption and
/// decryption are the same operation.
pub struct MediaCipher {
    key: [u8; 32],
    nonce_prefix: [u8; 4],
}

impl MediaCipher {
    /// Build from derived session keys.
    pub fn from_session_keys(keys: &SessionKeys) -> Self {
        MediaCipher {
            key: keys.media_key,
            nonce_prefix: keys.nonce_prefix,
        }
    }

    /// Encrypt or decrypt one packet payload in place.
    pub fn apply(&self, packet_index: u64, payload: &mut [u8; PACKET_PAYLOAD_BYTES]) {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..].copy_from_slice(&packet_index.to_be_bytes());
        let mut cipher = ChaCha20::new(&self.key.into(), &nonce.into());
        cipher.apply_keystream(payload);
    }
}

/// The block cipher for bulk transfers: same construction as
/// [`MediaCipher`], with the block index as the nonce suffix.
pub struct BulkCipher {
    key: [u8; 32],
    nonce_prefix: [u8; 4],
}

impl BulkCipher {
    /// Build from derived session keys.
    pub fn from_session_keys(keys: &SessionKeys) -> Self {
        BulkCipher {
            key: keys.bulk_key,
            nonce_prefix: keys.nonce_prefix,
        }
    }

    /// Encrypt or decrypt one bulk block in place (any length).
    pub fn apply(&self, block_index: u32, data: &mut [u8]) {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..8].copy_from_slice(&block_index.to_be_bytes());
        let mut cipher = ChaCha20::new(&self.key.into(), &nonce.into());
        cipher.apply_keystream(data);
    }
}

/// The byte string the server signs in its ServerHello (spec §3.1):
/// binds the server's ephemeral key to the client's random, the
/// client's ephemeral key and the requested content.
pub fn server_hello_signing_payload(
    client_random: &[u8; 16],
    client_ephemeral: &[u8; 32],
    server_ephemeral: &[u8; 32],
    content_id: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + 16 + 32 + 32 + 8);
    out.extend_from_slice(b"PVTP-SERVERHELLO-V1");
    out.extend_from_slice(client_random);
    out.extend_from_slice(client_ephemeral);
    out.extend_from_slice(server_ephemeral);
    out.extend_from_slice(&content_id.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_sign_verify() {
        let id = ServerIdentity::generate();
        let sig = id.sign(b"hello");
        assert!(verify_server_signature(&id.public_bytes(), b"hello", &sig).is_ok());
        assert!(verify_server_signature(&id.public_bytes(), b"hellp", &sig).is_err());
        // A different identity's key must not verify.
        let other = ServerIdentity::generate();
        assert!(verify_server_signature(&other.public_bytes(), b"hello", &sig).is_err());
    }

    #[test]
    fn identity_secret_roundtrip() {
        let id = ServerIdentity::generate();
        let loaded = ServerIdentity::from_secret_bytes(&id.secret_bytes());
        assert_eq!(loaded.public_bytes(), id.public_bytes());
    }

    #[test]
    fn dh_and_key_derivation_agree() {
        let client = EphemeralKeypair::generate();
        let server = EphemeralKeypair::generate();
        let random = [5u8; 16];
        let a = derive_session_keys(&client.diffie_hellman(&server.public), &random);
        let b = derive_session_keys(&server.diffie_hellman(&client.public), &random);
        assert_eq!(a, b);
        // A different client random derives different keys.
        let c = derive_session_keys(&client.diffie_hellman(&server.public), &[6u8; 16]);
        assert_ne!(a, c);
    }

    #[test]
    fn media_cipher_is_involution_and_index_bound() {
        let keys = derive_session_keys(&[1u8; 32], &[2u8; 16]);
        let cipher = MediaCipher::from_session_keys(&keys);
        let original = [42u8; PACKET_PAYLOAD_BYTES];
        let mut buf = original;
        cipher.apply(7, &mut buf);
        assert_ne!(buf, original);
        // A different packet index gives a different keystream.
        let mut other = original;
        cipher.apply(8, &mut other);
        assert_ne!(buf, other);
        // Applying again with the same index decrypts.
        cipher.apply(7, &mut buf);
        assert_eq!(buf, original);
    }
}
