//! Wire formats for PVTP packets and control messages.
//!
//! PVTP packets carry no type byte: the kind of a packet is determined
//! by its length and by its position in the stream (spec §9). Media and
//! parity packets share a length and are told apart by position — a
//! parity packet, when enabled, directly follows media packet index
//! `25m + 24` and its group MAC packet.

use crate::error::{PvtpError, Result};
use crate::interleave::PacketPayload;
use crate::{
    CipherSuite, NumberingMode, SessionKind, ERROR_PACKET_BYTES, GROUP_MAC_BYTES, INDEX_BYTES,
    MAC_EVERY_PACKETS, PARITY_EVERY_PACKETS, PROTOCOL_VERSION,
};

/// A packet kind, as far as its wire length can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthClass {
    /// Media wire length: a media packet, or a parity packet when one
    /// is due at this stream position.
    MediaOrParity,
    /// Group MAC wire length.
    GroupMac,
    /// The fixed 4-byte ERROR packet.
    Error,
    /// Matches no PVTP packet format.
    Unknown,
}

/// Classify an incoming packet by length alone.
pub fn classify_by_length(len: usize, numbering: NumberingMode) -> LengthClass {
    if len == ERROR_PACKET_BYTES {
        LengthClass::Error
    } else if len == numbering.media_wire_len() {
        LengthClass::MediaOrParity
    } else if len == numbering.group_mac_wire_len() {
        LengthClass::GroupMac
    } else {
        LengthClass::Unknown
    }
}

/// Whether a group MAC packet directly follows this media packet index.
pub fn mac_due_after(media_index: u64) -> bool {
    (media_index + 1) % MAC_EVERY_PACKETS == 0
}

/// Whether a parity packet directly follows this media packet index
/// (after the group MAC packet, when parity is enabled).
pub fn parity_due_after(media_index: u64) -> bool {
    (media_index + 1) % PARITY_EVERY_PACKETS == 0
}

/// Encode a media packet. The explicit index is the low 16 bits of the
/// session packet counter; receivers track the high bits by continuity.
pub fn encode_media(
    numbering: NumberingMode,
    index: u64,
    payload: &PacketPayload,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(numbering.media_wire_len());
    if numbering == NumberingMode::Explicit {
        out.extend_from_slice(&(index as u16).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

/// Decode a media packet. In declared mode the returned wire index is
/// `None` and the caller derives the index from its slot clock.
pub fn decode_media(
    numbering: NumberingMode,
    bytes: &[u8],
) -> Result<(Option<u16>, PacketPayload)> {
    if bytes.len() != numbering.media_wire_len() {
        return Err(PvtpError::InvalidPacketLength);
    }
    let mut payload = [0u8; crate::PACKET_PAYLOAD_BYTES];
    match numbering {
        NumberingMode::Explicit => {
            let wire = u16::from_be_bytes([bytes[0], bytes[1]]);
            payload.copy_from_slice(&bytes[INDEX_BYTES..]);
            Ok((Some(wire), payload))
        }
        NumberingMode::Declared => {
            payload.copy_from_slice(bytes);
            Ok((None, payload))
        }
    }
}

/// The truncated group MAC: the first 8 bytes of a BLAKE3 keyed hash
/// over the group index and the group's (ciphertext) payloads.
///
/// MACs are computed over ciphertext, so a group whose MAC fails is
/// treated as lost and handed to PLC (spec §5.5).
pub fn group_mac(mac_key: &[u8; 32], group_index: u64, payloads: &[PacketPayload]) -> [u8; GROUP_MAC_BYTES] {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(b"PVTP-GMAC-V1");
    hasher.update(&group_index.to_be_bytes());
    for p in payloads {
        hasher.update(p);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; GROUP_MAC_BYTES];
    out.copy_from_slice(&digest.as_bytes()[..GROUP_MAC_BYTES]);
    out
}

/// Encode a group MAC packet. In declared mode it also carries the
/// current packet index, which receivers use to re-anchor their
/// clock-derived numbering (an amortised ~0.4 bytes per packet).
pub fn encode_group_mac(
    numbering: NumberingMode,
    current_index: u64,
    mac: &[u8; GROUP_MAC_BYTES],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(numbering.group_mac_wire_len());
    if numbering == NumberingMode::Declared {
        out.extend_from_slice(&(current_index as u16).to_be_bytes());
    }
    out.extend_from_slice(mac);
    out
}

/// Decode a group MAC packet.
pub fn decode_group_mac(
    numbering: NumberingMode,
    bytes: &[u8],
) -> Result<(Option<u16>, [u8; GROUP_MAC_BYTES])> {
    if bytes.len() != numbering.group_mac_wire_len() {
        return Err(PvtpError::InvalidPacketLength);
    }
    let mut mac = [0u8; GROUP_MAC_BYTES];
    match numbering {
        NumberingMode::Explicit => {
            mac.copy_from_slice(bytes);
            Ok((None, mac))
        }
        NumberingMode::Declared => {
            let wire = u16::from_be_bytes([bytes[0], bytes[1]]);
            mac.copy_from_slice(&bytes[INDEX_BYTES..]);
            Ok((Some(wire), mac))
        }
    }
}

/// XOR-combine payloads into a parity block; with the parity block and
/// all-but-one inputs, the same function recovers the missing input.
pub fn xor_parity(blocks: &[PacketPayload]) -> PacketPayload {
    let mut out = [0u8; crate::PACKET_PAYLOAD_BYTES];
    for b in blocks {
        for i in 0..out.len() {
            out[i] ^= b[i];
        }
    }
    out
}

/// Reason codes of the ERROR packet (spec §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Protocol version mismatch.
    VersionMismatch = 1,
    /// Session ticket invalid or expired.
    TicketInvalid = 2,
    /// The requested content does not exist.
    ContentNotFound = 3,
    /// Rate limited; honour `retry_after_secs`.
    RateLimited = 4,
    /// The server is shutting down.
    ServerShutdown = 5,
}

impl ErrorCode {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(ErrorCode::VersionMismatch),
            2 => Ok(ErrorCode::TicketInvalid),
            3 => Ok(ErrorCode::ContentNotFound),
            4 => Ok(ErrorCode::RateLimited),
            5 => Ok(ErrorCode::ServerShutdown),
            _ => Err(PvtpError::InvalidPacketLength),
        }
    }
}

/// Type byte of the ERROR packet.
pub const ERROR_TYPE_BYTE: u8 = 0x01;

/// A server → client ERROR packet: fixed 4-byte wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorPacket {
    /// Why the server is complaining.
    pub code: ErrorCode,
    /// Seconds the client should wait before retrying (0 = no hint).
    pub retry_after_secs: u8,
}

impl ErrorPacket {
    /// Encode to the fixed 4-byte wire format.
    pub fn encode(&self) -> [u8; ERROR_PACKET_BYTES] {
        [ERROR_TYPE_BYTE, self.code as u8, self.retry_after_secs, 0]
    }

    /// Decode a 4-byte wire packet.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ERROR_PACKET_BYTES || bytes[0] != ERROR_TYPE_BYTE {
            return Err(PvtpError::InvalidPacketLength);
        }
        Ok(ErrorPacket {
            code: ErrorCode::from_u8(bytes[1])?,
            retry_after_secs: bytes[2],
        })
    }
}

/// Client → server control messages (spec §8.1). The first byte is the
/// type; these are the only PVTP messages that carry one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Move the send position to this packet index.
    Seek(u64),
    /// Stop sending (session stays open).
    Pause,
    /// Resume after [`Control::Pause`].
    Resume,
    /// Re-anchor declared-mode numbering.
    Resync,
    /// Playback statistics for server-side quality observation.
    Stats {
        /// Packets declared lost so far.
        lost: u32,
        /// Packets received so far.
        received: u32,
    },
    /// End the session.
    Bye,
}

impl Control {
    /// Encode the control message.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Control::Seek(index) => {
                let mut out = vec![0x01];
                out.extend_from_slice(&index.to_be_bytes());
                out
            }
            Control::Pause => vec![0x02],
            Control::Resume => vec![0x03],
            Control::Resync => vec![0x04],
            Control::Stats { lost, received } => {
                let mut out = vec![0x05];
                out.extend_from_slice(&lost.to_be_bytes());
                out.extend_from_slice(&received.to_be_bytes());
                out
            }
            Control::Bye => vec![0x06],
        }
    }

    /// Decode a control message.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (&ty, rest) = bytes.split_first().ok_or(PvtpError::TooShort)?;
        match ty {
            0x01 => {
                if rest.len() != 8 {
                    return Err(PvtpError::InvalidControl);
                }
                Ok(Control::Seek(u64::from_be_bytes(
                    rest.try_into().map_err(|_| PvtpError::InvalidControl)?,
                )))
            }
            0x02 => Ok(Control::Pause),
            0x03 => Ok(Control::Resume),
            0x04 => Ok(Control::Resync),
            0x05 => {
                if rest.len() != 8 {
                    return Err(PvtpError::InvalidControl);
                }
                Ok(Control::Stats {
                    lost: u32::from_be_bytes(
                        rest[..4].try_into().map_err(|_| PvtpError::InvalidControl)?,
                    ),
                    received: u32::from_be_bytes(
                        rest[4..].try_into().map_err(|_| PvtpError::InvalidControl)?,
                    ),
                })
            }
            0x06 => Ok(Control::Bye),
            _ => Err(PvtpError::InvalidControl),
        }
    }
}

/// Magic prefix of handshake messages.
pub(crate) const HANDSHAKE_MAGIC: &[u8; 4] = b"PVTP";

/// Flags byte used by handshake messages (see [`crate::handshake`]).
pub(crate) fn flags_byte(
    kind: SessionKind,
    numbering: NumberingMode,
    parity: bool,
    cipher: CipherSuite,
    has_cookie: bool,
    has_ticket: bool,
) -> u8 {
    let mut f = 0u8;
    if kind == SessionKind::Bulk {
        f |= 0x01;
    }
    if numbering == NumberingMode::Declared {
        f |= 0x02;
    }
    if parity {
        f |= 0x04;
    }
    if cipher == CipherSuite::AesGcm {
        f |= 0x08;
    }
    if has_cookie {
        f |= 0x10;
    }
    if has_ticket {
        f |= 0x20;
    }
    f
}

/// Decode a handshake flags byte.
pub(crate) fn parse_flags(
    f: u8,
) -> (SessionKind, NumberingMode, bool, CipherSuite, bool, bool) {
    (
        if f & 0x01 != 0 {
            SessionKind::Bulk
        } else {
            SessionKind::Media
        },
        if f & 0x02 != 0 {
            NumberingMode::Declared
        } else {
            NumberingMode::Explicit
        },
        f & 0x04 != 0,
        if f & 0x08 != 0 {
            CipherSuite::AesGcm
        } else {
            CipherSuite::ChaCha20
        },
        f & 0x10 != 0,
        f & 0x20 != 0,
    )
}

/// The protocol version byte used on the wire.
pub(crate) fn wire_version() -> u8 {
    PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_roundtrip_both_modes() {
        let payload = [7u8; crate::PACKET_PAYLOAD_BYTES];
        let enc = encode_media(NumberingMode::Explicit, 0x1234, &payload);
        assert_eq!(enc.len(), 92);
        let (idx, dec) = decode_media(NumberingMode::Explicit, &enc).unwrap();
        assert_eq!(idx, Some(0x1234));
        assert_eq!(dec, payload);

        let enc = encode_media(NumberingMode::Declared, 0x1234, &payload);
        assert_eq!(enc.len(), 90);
        let (idx, dec) = decode_media(NumberingMode::Declared, &enc).unwrap();
        assert_eq!(idx, None);
        assert_eq!(dec, payload);
    }

    #[test]
    fn group_mac_roundtrip_and_verify() {
        let payloads = [[3u8; crate::PACKET_PAYLOAD_BYTES]; 5];
        let mac = group_mac(&[9u8; 32], 0, &payloads);
        let enc = encode_group_mac(NumberingMode::Declared, 4, &mac);
        let (anchor, dec) = decode_group_mac(NumberingMode::Declared, &enc).unwrap();
        assert_eq!(anchor, Some(4));
        assert_eq!(dec, mac);
        // A tampered payload fails the MAC.
        let mut bad = payloads;
        bad[2][0] ^= 1;
        assert_ne!(group_mac(&[9u8; 32], 0, &bad), mac);
    }

    #[test]
    fn parity_recovers_one_loss() {
        let blocks: Vec<PacketPayload> = (0..25u8)
            .map(|i| [i; crate::PACKET_PAYLOAD_BYTES])
            .collect();
        let parity = xor_parity(&blocks);
        let mut with_parity = blocks.clone();
        with_parity.push(parity);
        // Lose block 13, recover it from the other 25 inputs.
        let others: Vec<PacketPayload> = with_parity
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 13)
            .map(|(_, b)| *b)
            .collect();
        assert_eq!(xor_parity(&others), blocks[13]);
    }

    #[test]
    fn error_packet_roundtrip() {
        let p = ErrorPacket {
            code: ErrorCode::RateLimited,
            retry_after_secs: 30,
        };
        assert_eq!(ErrorPacket::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn control_roundtrip() {
        for c in [
            Control::Seek(42),
            Control::Pause,
            Control::Resume,
            Control::Resync,
            Control::Stats {
                lost: 3,
                received: 100,
            },
            Control::Bye,
        ] {
            assert_eq!(Control::decode(&c.encode()).unwrap(), c);
        }
    }

    #[test]
    fn classify_lengths() {
        assert_eq!(
            classify_by_length(92, NumberingMode::Explicit),
            LengthClass::MediaOrParity
        );
        assert_eq!(
            classify_by_length(8, NumberingMode::Explicit),
            LengthClass::GroupMac
        );
        assert_eq!(
            classify_by_length(10, NumberingMode::Declared),
            LengthClass::GroupMac
        );
        assert_eq!(
            classify_by_length(4, NumberingMode::Explicit),
            LengthClass::Error
        );
        assert_eq!(
            classify_by_length(50, NumberingMode::Explicit),
            LengthClass::Unknown
        );
    }

    #[test]
    fn schedule_helpers() {
        assert!(mac_due_after(4));
        assert!(!mac_due_after(5));
        assert!(parity_due_after(24));
        assert!(!parity_due_after(23));
    }
}
