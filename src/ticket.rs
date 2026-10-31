//! Session tickets: PVTP's stateless resumption.
//!
//! A ticket is an AEAD-sealed blob the *client* holds and the server
//! can open with any of its ticket keys. It carries everything needed
//! to resume a session — content, playback position, expiry — so
//! servers keep no per-session state. A single server uses one key;
//! a fleet shares the same keys; nothing else about the protocol
//! changes (spec §7).

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};

use crate::error::{PvtpError, Result};
use crate::PROTOCOL_VERSION;

/// The plaintext contents of a session ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketData {
    /// Content the session was streaming.
    pub content_id: u64,
    /// Playback position, as a packet index.
    pub position: u64,
    /// Expiry time (Unix seconds). Compared against the server's clock.
    pub expires_at: u64,
    /// Per-ticket nonce feeding session key derivation on resumption.
    pub key_nonce: [u8; 16],
}

/// One ticket sealing key. Servers may hold several at once to rotate
/// keys without invalidating outstanding tickets.
#[derive(Debug, Clone)]
pub struct TicketKey {
    /// Key identifier carried in the ticket header.
    pub id: u8,
    /// The AEAD key. Server-side secret.
    pub key: [u8; 32],
}

const TICKET_MAGIC: &[u8; 4] = b"PVTK";
const TICKET_PLAINTEXT_LEN: usize = 4 + 1 + 8 + 8 + 8 + 16;
const HEADER_LEN: usize = 1 + 1 + 12; // version ‖ key id ‖ nonce

fn ticket_plaintext(data: &TicketData) -> [u8; TICKET_PLAINTEXT_LEN] {
    let mut out = [0u8; TICKET_PLAINTEXT_LEN];
    out[0..4].copy_from_slice(TICKET_MAGIC);
    out[4] = PROTOCOL_VERSION;
    out[5..13].copy_from_slice(&data.content_id.to_be_bytes());
    out[13..21].copy_from_slice(&data.position.to_be_bytes());
    out[21..29].copy_from_slice(&data.expires_at.to_be_bytes());
    out[29..45].copy_from_slice(&data.key_nonce);
    out
}

fn parse_ticket_plaintext(bytes: &[u8]) -> Result<TicketData> {
    if bytes.len() != TICKET_PLAINTEXT_LEN || &bytes[0..4] != TICKET_MAGIC {
        return Err(PvtpError::TicketMalformed);
    }
    if bytes[4] != PROTOCOL_VERSION {
        return Err(PvtpError::UnsupportedVersion(bytes[4]));
    }
    let mut key_nonce = [0u8; 16];
    key_nonce.copy_from_slice(&bytes[29..45]);
    Ok(TicketData {
        content_id: u64::from_be_bytes(bytes[5..13].try_into().expect("fixed slice")),
        position: u64::from_be_bytes(bytes[13..21].try_into().expect("fixed slice")),
        expires_at: u64::from_be_bytes(bytes[21..29].try_into().expect("fixed slice")),
        key_nonce,
    })
}

/// Seal a ticket with a fresh random nonce.
pub fn issue_ticket(key: &TicketKey, data: &TicketData) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    issue_ticket_with_nonce(key, data, &nonce)
}

/// Seal a ticket with a caller-provided nonce (deterministic tests and
/// provisioning tools; production code should use [`issue_ticket`]).
pub fn issue_ticket_with_nonce(key: &TicketKey, data: &TicketData, nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.key));
    let header = [PROTOCOL_VERSION, key.id];
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &ticket_plaintext(data),
                aad: &header,
            },
        )
        .expect("ticket plaintext length is always valid");
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Open a ticket with any of the server's keys and check its expiry
/// against `now` (Unix seconds).
pub fn open_ticket(keys: &[TicketKey], bytes: &[u8], now: u64) -> Result<TicketData> {
    if bytes.len() < HEADER_LEN {
        return Err(PvtpError::TooShort);
    }
    if bytes[0] != PROTOCOL_VERSION {
        return Err(PvtpError::UnsupportedVersion(bytes[0]));
    }
    let key = keys
        .iter()
        .find(|k| k.id == bytes[1])
        .ok_or(PvtpError::TicketUnknownKey)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&bytes[2..14]),
            Payload {
                msg: &bytes[HEADER_LEN..],
                aad: &bytes[..2],
            },
        )
        .map_err(|_| PvtpError::DecryptFailed)?;
    let data = parse_ticket_plaintext(&plaintext)?;
    if now > data.expires_at {
        return Err(PvtpError::TicketExpired);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TicketData {
        TicketData {
            content_id: 1234,
            position: 567,
            expires_at: 2_000_000_000,
            key_nonce: [8u8; 16],
        }
    }

    #[test]
    fn ticket_roundtrip() {
        let key = TicketKey { id: 1, key: [3u8; 32] };
        let bytes = issue_ticket_with_nonce(&key, &sample(), &[4u8; 12]);
        let opened = open_ticket(&[key], &bytes, 1_900_000_000).unwrap();
        assert_eq!(opened, sample());
    }

    #[test]
    fn ticket_expiry_and_tamper() {
        let key = TicketKey { id: 1, key: [3u8; 32] };
        let bytes = issue_ticket_with_nonce(&key, &sample(), &[4u8; 12]);
        assert_eq!(
            open_ticket(&[key.clone()], &bytes, 2_000_000_001),
            Err(PvtpError::TicketExpired)
        );
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            open_ticket(&[key.clone()], &tampered, 1_900_000_000),
            Err(PvtpError::DecryptFailed)
        );
        assert_eq!(
            open_ticket(&[TicketKey { id: 2, key: [3u8; 32] }], &bytes, 1_900_000_000),
            Err(PvtpError::TicketUnknownKey)
        );
    }

    #[test]
    fn ticket_key_rotation() {
        let old = TicketKey { id: 1, key: [3u8; 32] };
        let new = TicketKey { id: 2, key: [9u8; 32] };
        let bytes = issue_ticket_with_nonce(&old, &sample(), &[4u8; 12]);
        // Both keys held: old tickets still open.
        assert!(open_ticket(&[new, old], &bytes, 1_900_000_000).is_ok());
    }
}
