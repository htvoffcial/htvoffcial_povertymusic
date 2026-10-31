//! # PovertiseStreaming — PVTP reference library
//!
//! PVTP is a small, purpose-built UDP protocol for streaming Opus audio at
//! 6 kbps to a dedicated app from a dedicated server, designed for the
//! PovertiseStreaming project. It deliberately avoids HTTP: media, cover art
//! and metadata all travel over the same custom protocol.
//!
//! Design highlights (see `SPEC.md` in the repository for the full draft):
//!
//! * **Loss shaping instead of parity.** Frames are interleaved across
//!   packets so a lost packet becomes isolated single-frame losses that
//!   Opus PLC conceals well, at zero bytes of FEC overhead
//!   (see [`interleave`]).
//! * **Switchable packet numbering.** Either an explicit 2-byte index or
//!   an implicit, clock-derived index ("declaration mode"), negotiated in
//!   the handshake (see [`packet`]).
//! * **Stateless servers.** Session resumption state travels in an
//!   encrypted ticket held by the client, so a single server is the
//!   canonical deployment and load balancing is "run more copies"
//!   (see [`ticket`]).
//! * **Fake-server protection.** The server proves its identity with an
//!   Ed25519 key whose public half is pinned in the app (see [`crypto`]
//!   and [`handshake`]).
//! * **Amplification resistance.** A stateless reachability cookie is
//!   exchanged before any large response (see [`cookie`]).
//!
//! This crate implements the protocol building blocks — wire formats,
//! interleaving, cryptography, tickets, cookies and bulk transfer — and
//! leaves sockets and pacing to the application.

pub mod bulk;
pub mod cookie;
pub mod crypto;
pub mod error;
pub mod handshake;
pub mod interleave;
pub mod packet;
pub mod ticket;

pub use error::{PvtpError, Result};

/// PVTP protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u8 = 1;

/// Slot duration: one packet carries 120 ms of audio.
pub const SLOT_MS: u64 = 120;
/// Bytes per 20 ms Opus frame at 6 kbps CBR.
pub const FRAME_BYTES: usize = 15;
/// Frames carried by one media packet (6 × 20 ms = 120 ms).
pub const FRAMES_PER_PACKET: usize = 6;
/// Payload bytes of one media packet.
pub const PACKET_PAYLOAD_BYTES: usize = FRAME_BYTES * FRAMES_PER_PACKET;
/// Media packets per interleave group.
pub const PACKETS_PER_GROUP: usize = 5;
/// Frames per interleave group (30 × 20 ms = 600 ms).
pub const FRAMES_PER_GROUP: usize = FRAMES_PER_PACKET * PACKETS_PER_GROUP;
/// A group MAC packet follows every group of this many media packets.
pub const MAC_EVERY_PACKETS: u64 = 5;
/// An optional XOR parity packet follows every this many media packets.
pub const PARITY_EVERY_PACKETS: u64 = 25;
/// Bytes of the truncated group MAC.
pub const GROUP_MAC_BYTES: usize = 8;
/// Bytes of the explicit packet index on the wire (wraps at 2^16 packets).
pub const INDEX_BYTES: usize = 2;
/// Block size of the bulk transfer mode.
pub const BULK_BLOCK_BYTES: usize = 1024;
/// Wire length of an ERROR packet (identified by this length alone).
pub const ERROR_PACKET_BYTES: usize = 4;

/// How packet indices are conveyed, negotiated in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberingMode {
    /// Every media packet starts with a 2-byte big-endian packet index
    /// (the low 16 bits of the session packet counter). Robust default.
    Explicit,
    /// No index on media packets: indices are derived from the slot clock
    /// and re-anchored by the index carried in each group MAC packet.
    Declared,
}

impl NumberingMode {
    /// Wire length of a media (or parity) packet in this mode.
    pub fn media_wire_len(&self) -> usize {
        match self {
            NumberingMode::Explicit => INDEX_BYTES + PACKET_PAYLOAD_BYTES,
            NumberingMode::Declared => PACKET_PAYLOAD_BYTES,
        }
    }

    /// Wire length of a group MAC packet in this mode.
    pub fn group_mac_wire_len(&self) -> usize {
        match self {
            NumberingMode::Explicit => GROUP_MAC_BYTES,
            NumberingMode::Declared => INDEX_BYTES + GROUP_MAC_BYTES,
        }
    }
}

/// Which kind of session a handshake opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// Server → client media stream.
    Media,
    /// Client-pulled bulk transfer (cover art / metadata bundles).
    Bulk,
}

/// Cipher suites negotiable in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// ChaCha20 stream cipher with a per-packet nonce (default; fast on
    /// mobile CPUs without AES hardware).
    ChaCha20,
    /// AES-256-GCM, for devices with AES hardware acceleration.
    /// Reserved in the wire format; media encryption helpers currently
    /// implement ChaCha20 only.
    AesGcm,
}
