//! Error type for the PVTP library.

use core::fmt;

/// Errors returned by PVTP parsing, verification and reassembly operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PvtpError {
    /// Input ended before a complete structure could be read.
    TooShort,
    /// A magic constant did not match.
    BadMagic,
    /// The peer uses a protocol version this library does not speak.
    UnsupportedVersion(u8),
    /// A signature did not verify against the expected public key.
    BadSignature,
    /// A session ticket could not be decrypted or parsed.
    TicketMalformed,
    /// A session ticket is past its expiry time.
    TicketExpired,
    /// A session ticket names a key id the server does not hold.
    TicketUnknownKey,
    /// An AEAD decryption failed (tampered or wrong key).
    DecryptFailed,
    /// A packet had a length that matches no PVTP packet format.
    InvalidPacketLength,
    /// A control message had an unknown type byte or bad payload.
    InvalidControl,
    /// A bulk block did not match the bundle header.
    HeaderMismatch,
    /// A bundle is missing blocks and cannot be assembled yet.
    IncompleteBundle,
    /// An assembled bundle did not match the header hash.
    HashMismatch,
    /// A caller passed an argument the API cannot accept.
    InvalidArgument(&'static str),
}

impl fmt::Display for PvtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PvtpError::TooShort => write!(f, "input too short"),
            PvtpError::BadMagic => write!(f, "bad magic"),
            PvtpError::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
            PvtpError::BadSignature => write!(f, "signature verification failed"),
            PvtpError::TicketMalformed => write!(f, "session ticket is malformed"),
            PvtpError::TicketExpired => write!(f, "session ticket has expired"),
            PvtpError::TicketUnknownKey => write!(f, "session ticket names an unknown key"),
            PvtpError::DecryptFailed => write!(f, "decryption failed"),
            PvtpError::InvalidPacketLength => write!(f, "invalid packet length"),
            PvtpError::InvalidControl => write!(f, "invalid control message"),
            PvtpError::HeaderMismatch => write!(f, "bulk block does not match bundle header"),
            PvtpError::IncompleteBundle => write!(f, "bundle is incomplete"),
            PvtpError::HashMismatch => write!(f, "bundle hash mismatch"),
            PvtpError::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
        }
    }
}

impl std::error::Error for PvtpError {}

/// Convenience alias used throughout the crate.
pub type Result<T> = core::result::Result<T, PvtpError>;
