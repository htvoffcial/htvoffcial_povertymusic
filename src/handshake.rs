//! Handshake messages (spec §3) and their wire formats.
//!
//! All handshake messages start with the magic `PVTP` and a version
//! byte. The flow is:
//!
//! 1. [`Hello1`] — small first hello carrying the client random.
//! 2. [`CookieReply`] — the server's reachability cookie (skipped when
//!    the client resumes with a ticket instead).
//! 3. [`ClientHello`] — cookie (or ticket), ephemeral key, content id
//!    and requested parameters.
//! 4. [`ServerHello`] — ephemeral key signed by the server's pinned
//!    identity key, granted parameters and a fresh session ticket.

use rand_core::{OsRng, RngCore};

use crate::crypto::{
    server_hello_signing_payload, verify_server_signature, EphemeralKeypair, ServerIdentity,
};
use crate::error::{PvtpError, Result};
use crate::packet::{flags_byte, parse_flags, HANDSHAKE_MAGIC};
use crate::{CipherSuite, NumberingMode, SessionKind, PROTOCOL_VERSION};

fn check_header(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 5 {
        return Err(PvtpError::TooShort);
    }
    if &bytes[0..4] != HANDSHAKE_MAGIC {
        return Err(PvtpError::BadMagic);
    }
    if bytes[4] != PROTOCOL_VERSION {
        return Err(PvtpError::UnsupportedVersion(bytes[4]));
    }
    Ok(5)
}

/// Generate a fresh 16-byte client random.
pub fn new_client_random() -> [u8; 16] {
    let mut out = [0u8; 16];
    OsRng.fill_bytes(&mut out);
    out
}

/// First hello: magic ‖ version ‖ client random (21 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello1 {
    /// The client's handshake random, reused in the ClientHello.
    pub client_random: [u8; 16],
}

impl Hello1 {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(21);
        out.extend_from_slice(HANDSHAKE_MAGIC);
        out.push(PROTOCOL_VERSION);
        out.extend_from_slice(&self.client_random);
        out
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        check_header(bytes)?;
        if bytes.len() != 21 {
            return Err(PvtpError::TooShort);
        }
        Ok(Hello1 {
            client_random: bytes[5..21].try_into().expect("fixed slice"),
        })
    }
}

/// Cookie reply: magic ‖ version ‖ cookie (21 bytes, never larger
/// than the hello it answers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieReply {
    /// The reachability cookie to echo in the ClientHello.
    pub cookie: [u8; crate::cookie::COOKIE_BYTES],
}

impl CookieReply {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(21);
        out.extend_from_slice(HANDSHAKE_MAGIC);
        out.push(PROTOCOL_VERSION);
        out.extend_from_slice(&self.cookie);
        out
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        check_header(bytes)?;
        if bytes.len() != 21 {
            return Err(PvtpError::TooShort);
        }
        Ok(CookieReply {
            cookie: bytes[5..21].try_into().expect("fixed slice"),
        })
    }
}

/// The full client hello (spec §3.1 / §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// The same random as in the [`Hello1`].
    pub client_random: [u8; 16],
    /// Media or bulk session.
    pub kind: SessionKind,
    /// Requested numbering mode.
    pub numbering: NumberingMode,
    /// Whether the insurance parity is requested.
    pub parity: bool,
    /// Requested cipher suite.
    pub cipher: CipherSuite,
    /// The client's ephemeral X25519 public key.
    pub client_ephemeral: [u8; 32],
    /// Content to stream (media) or fetch (bulk bundle id).
    pub content_id: u64,
    /// Packet index to start from (0 for new sessions).
    pub start_index: u64,
    /// Reachability cookie (new sessions).
    pub cookie: Option<[u8; crate::cookie::COOKIE_BYTES]>,
    /// Session ticket (resumption; replaces the cookie).
    pub ticket: Option<Vec<u8>>,
}

impl ClientHello {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(86 + self.ticket.as_ref().map_or(0, |t| t.len()));
        out.extend_from_slice(HANDSHAKE_MAGIC);
        out.push(PROTOCOL_VERSION);
        out.push(flags_byte(
            self.kind,
            self.numbering,
            self.parity,
            self.cipher,
            self.cookie.is_some(),
            self.ticket.is_some(),
        ));
        out.extend_from_slice(&self.client_random);
        out.extend_from_slice(&self.client_ephemeral);
        out.extend_from_slice(&self.content_id.to_be_bytes());
        out.extend_from_slice(&self.start_index.to_be_bytes());
        if let Some(cookie) = &self.cookie {
            out.extend_from_slice(cookie);
        }
        if let Some(ticket) = &self.ticket {
            out.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            out.extend_from_slice(ticket);
        }
        out
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut pos = check_header(bytes)?;
        if bytes.len() < pos + 1 + 16 + 32 + 8 + 8 {
            return Err(PvtpError::TooShort);
        }
        let (kind, numbering, parity, cipher, has_cookie, has_ticket) = parse_flags(bytes[pos]);
        pos += 1;
        let client_random: [u8; 16] = bytes[pos..pos + 16].try_into().expect("checked");
        pos += 16;
        let client_ephemeral: [u8; 32] = bytes[pos..pos + 32].try_into().expect("checked");
        pos += 32;
        let content_id = u64::from_be_bytes(bytes[pos..pos + 8].try_into().expect("checked"));
        pos += 8;
        let start_index = u64::from_be_bytes(bytes[pos..pos + 8].try_into().expect("checked"));
        pos += 8;
        let mut cookie = None;
        if has_cookie {
            if bytes.len() < pos + crate::cookie::COOKIE_BYTES {
                return Err(PvtpError::TooShort);
            }
            cookie = Some(
                bytes[pos..pos + crate::cookie::COOKIE_BYTES]
                    .try_into()
                    .expect("checked"),
            );
            pos += crate::cookie::COOKIE_BYTES;
        }
        let mut ticket = None;
        if has_ticket {
            if bytes.len() < pos + 2 {
                return Err(PvtpError::TooShort);
            }
            let len = u16::from_be_bytes(bytes[pos..pos + 2].try_into().expect("checked")) as usize;
            pos += 2;
            if bytes.len() < pos + len {
                return Err(PvtpError::TooShort);
            }
            ticket = Some(bytes[pos..pos + len].to_vec());
        }
        Ok(ClientHello {
            client_random,
            kind,
            numbering,
            parity,
            cipher,
            client_ephemeral,
            content_id,
            start_index,
            cookie,
            ticket,
        })
    }
}

/// The server's answer (spec §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// The server's ephemeral X25519 public key.
    pub server_ephemeral: [u8; 32],
    /// Identity signature over the handshake binding payload.
    pub signature: [u8; 64],
    /// Granted numbering mode (may differ from the request).
    pub numbering: NumberingMode,
    /// Whether the insurance parity will be sent.
    pub parity: bool,
    /// Packet index the stream starts from.
    pub start_index: u64,
    /// A fresh session ticket for later resumption.
    pub ticket: Vec<u8>,
}

impl ServerHello {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(107 + self.ticket.len());
        out.extend_from_slice(HANDSHAKE_MAGIC);
        out.push(PROTOCOL_VERSION);
        out.push(flags_byte(
            SessionKind::Media,
            self.numbering,
            self.parity,
            CipherSuite::ChaCha20,
            false,
            true,
        ));
        out.extend_from_slice(&self.server_ephemeral);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.start_index.to_be_bytes());
        out.extend_from_slice(&(self.ticket.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ticket);
        out
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut pos = check_header(bytes)?;
        if bytes.len() < pos + 1 + 32 + 64 + 8 + 2 {
            return Err(PvtpError::TooShort);
        }
        let (_kind, numbering, parity, _cipher, _cookie, _ticket) = parse_flags(bytes[pos]);
        pos += 1;
        let server_ephemeral: [u8; 32] = bytes[pos..pos + 32].try_into().expect("checked");
        pos += 32;
        let signature: [u8; 64] = bytes[pos..pos + 64].try_into().expect("checked");
        pos += 64;
        let start_index = u64::from_be_bytes(bytes[pos..pos + 8].try_into().expect("checked"));
        pos += 8;
        let len = u16::from_be_bytes(bytes[pos..pos + 2].try_into().expect("checked")) as usize;
        pos += 2;
        if bytes.len() < pos + len {
            return Err(PvtpError::TooShort);
        }
        Ok(ServerHello {
            server_ephemeral,
            signature,
            numbering,
            parity,
            start_index,
            ticket: bytes[pos..pos + len].to_vec(),
        })
    }

    /// Verify the identity signature against the pinned server public
    /// key and the ClientHello this answers (client side).
    pub fn verify(&self, pinned_public: &[u8; 32], hello: &ClientHello) -> Result<()> {
        let payload = server_hello_signing_payload(
            &hello.client_random,
            &hello.client_ephemeral,
            &self.server_ephemeral,
            hello.content_id,
        );
        verify_server_signature(pinned_public, &payload, &self.signature)
    }
}

/// Build a ServerHello (server side): signs the binding payload with
/// the server identity and attaches the given session ticket.
pub fn build_server_hello(
    identity: &ServerIdentity,
    hello: &ClientHello,
    server_ephemeral: &EphemeralKeypair,
    numbering: NumberingMode,
    parity: bool,
    start_index: u64,
    ticket: Vec<u8>,
) -> ServerHello {
    let payload = server_hello_signing_payload(
        &hello.client_random,
        &hello.client_ephemeral,
        &server_ephemeral.public,
        hello.content_id,
    );
    ServerHello {
        server_ephemeral: server_ephemeral.public,
        signature: identity.sign(&payload),
        numbering,
        parity,
        start_index,
        ticket,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ticket::{issue_ticket_with_nonce, TicketData, TicketKey};

    fn sample_client_hello() -> (ClientHello, EphemeralKeypair) {
        let eph = EphemeralKeypair::generate();
        (
            ClientHello {
                client_random: [1u8; 16],
                kind: SessionKind::Media,
                numbering: NumberingMode::Declared,
                parity: true,
                cipher: CipherSuite::ChaCha20,
                client_ephemeral: eph.public,
                content_id: 42,
                start_index: 0,
                cookie: Some([2u8; 16]),
                ticket: None,
            },
            eph,
        )
    }

    #[test]
    fn hello1_and_cookie_roundtrip() {
        let h = Hello1 { client_random: [9u8; 16] };
        assert_eq!(Hello1::decode(&h.encode()).unwrap(), h);
        let c = CookieReply { cookie: [3u8; 16] };
        assert_eq!(CookieReply::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn client_hello_roundtrip() {
        let (hello, _eph) = sample_client_hello();
        assert_eq!(ClientHello::decode(&hello.encode()).unwrap(), hello);
    }

    #[test]
    fn server_hello_signs_and_verifies() {
        let identity = ServerIdentity::generate();
        let (hello, _client_eph) = sample_client_hello();
        let server_eph = EphemeralKeypair::generate();
        let key = TicketKey { id: 1, key: [5u8; 32] };
        let ticket = issue_ticket_with_nonce(
            &key,
            &TicketData {
                content_id: 42,
                position: 0,
                expires_at: u64::MAX,
                key_nonce: [6u8; 16],
            },
            &[7u8; 12],
        );
        let sh = build_server_hello(
            &identity,
            &hello,
            &server_eph,
            NumberingMode::Declared,
            true,
            0,
            ticket,
        );
        let decoded = ServerHello::decode(&sh.encode()).unwrap();
        assert_eq!(decoded, sh);
        assert!(decoded.verify(&identity.public_bytes(), &hello).is_ok());
        // The pinned key of a *different* server must fail: that is the
        // fake-server protection doing its job.
        let impostor = ServerIdentity::generate();
        assert!(decoded.verify(&impostor.public_bytes(), &hello).is_err());
        // And a hello asking for other content must fail too.
        let mut other = hello.clone();
        other.content_id = 43;
        assert!(decoded.verify(&identity.public_bytes(), &other).is_err());
    }
}
