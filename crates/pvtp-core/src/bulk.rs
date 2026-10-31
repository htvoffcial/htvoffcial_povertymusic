//! Bulk transfer mode (spec §10): cover art (AVIF) and metadata
//! bundles travel over PVTP itself — no HTTP anywhere.
//!
//! The transfer is client-pulled and stateless: a bundle is split into
//! 1024-byte blocks, the client requests the blocks it wants with a
//! range-plus-bitmap request, and any server can answer any block. A
//! small header block carries the bundle's total length, block count
//! and BLAKE3 hash for end-to-end verification.

use std::collections::BTreeMap;

use crate::error::{PvtpError, Result};
use crate::BULK_BLOCK_BYTES;

/// Wire type byte of a bulk header request/reply.
pub const BULK_MSG_HEADER: u8 = 0x10;
/// Wire type byte of a bulk block request/reply.
pub const BULK_MSG_BLOCKS: u8 = 0x11;

/// Header size: magic ‖ total length ‖ block count ‖ BLAKE3 hash.
pub const BUNDLE_HEADER_BYTES: usize = 48;

const BUNDLE_MAGIC: &[u8; 4] = b"PVB1";

/// The header describing one bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleHeader {
    /// Total data length in bytes (excluding this header).
    pub total_data_len: u64,
    /// Number of data blocks.
    pub data_block_count: u32,
    /// BLAKE3 hash of the whole data.
    pub blake3: [u8; 32],
}

impl BundleHeader {
    /// Build the header for a bundle's data.
    pub fn of(data: &[u8]) -> Self {
        BundleHeader {
            total_data_len: data.len() as u64,
            data_block_count: block_count(data.len()),
            blake3: blake3::hash(data).into(),
        }
    }

    /// Encode to the fixed 48-byte header format.
    pub fn encode(&self) -> [u8; BUNDLE_HEADER_BYTES] {
        let mut out = [0u8; BUNDLE_HEADER_BYTES];
        out[0..4].copy_from_slice(BUNDLE_MAGIC);
        out[4..12].copy_from_slice(&self.total_data_len.to_be_bytes());
        out[12..16].copy_from_slice(&self.data_block_count.to_be_bytes());
        out[16..48].copy_from_slice(&self.blake3);
        out
    }

    /// Decode a header.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BUNDLE_HEADER_BYTES {
            return Err(PvtpError::TooShort);
        }
        if &bytes[0..4] != BUNDLE_MAGIC {
            return Err(PvtpError::BadMagic);
        }
        let mut blake3 = [0u8; 32];
        blake3.copy_from_slice(&bytes[16..48]);
        Ok(BundleHeader {
            total_data_len: u64::from_be_bytes(bytes[4..12].try_into().expect("checked")),
            data_block_count: u32::from_be_bytes(bytes[12..16].try_into().expect("checked")),
            blake3,
        })
    }
}

/// Number of data blocks for a payload of `data_len` bytes.
pub fn block_count(data_len: usize) -> u32 {
    data_len.div_ceil(BULK_BLOCK_BYTES) as u32
}

/// Borrow data block `index` (1024 bytes; the last block may be
/// shorter). Returns `None` past the end.
pub fn get_block(data: &[u8], index: u32) -> Option<&[u8]> {
    let start = index as usize * BULK_BLOCK_BYTES;
    if start >= data.len() && !data.is_empty() {
        return None;
    }
    if data.is_empty() {
        return if index == 0 { Some(&[]) } else { None };
    }
    let end = (start + BULK_BLOCK_BYTES).min(data.len());
    Some(&data[start..end])
}

/// A block request: a start block plus a 64-bit bitmap of wanted
/// blocks. Keeps requests tiny and idempotent — duplicates are free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRequest {
    /// First block covered by the bitmap.
    pub start: u32,
    /// Bit i set = block `start + i` is wanted.
    pub bitmap: [u8; 8],
}

impl BlockRequest {
    /// Build a request asking for the given blocks, anchored at the
    /// smallest one. `None` if the span exceeds 64 blocks.
    pub fn from_blocks(blocks: &[u32]) -> Option<Self> {
        let start = *blocks.iter().min()?;
        let mut bitmap = [0u8; 8];
        for &b in blocks {
            let bit = b.checked_sub(start)? as usize;
            if bit >= 64 {
                return None;
            }
            bitmap[bit / 8] |= 1 << (bit % 8);
        }
        Some(BlockRequest { start, bitmap })
    }

    /// The block indices this request asks for.
    pub fn blocks(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for i in 0..64u32 {
            if self.bitmap[(i / 8) as usize] & (1 << (i % 8)) != 0 {
                out.push(self.start + i);
            }
        }
        out
    }

    /// Encode: start (4 bytes, big-endian) ‖ bitmap (8 bytes).
    pub fn encode(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.start.to_be_bytes());
        out[4..12].copy_from_slice(&self.bitmap);
        out
    }

    /// Decode a request.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 {
            return Err(PvtpError::TooShort);
        }
        Ok(BlockRequest {
            start: u32::from_be_bytes(bytes[0..4].try_into().expect("checked")),
            bitmap: bytes[4..12].try_into().expect("checked"),
        })
    }
}

/// Receiver-side bundle reassembler.
#[derive(Debug, Default)]
pub struct Reassembler {
    header: Option<BundleHeader>,
    blocks: BTreeMap<u32, Vec<u8>>,
}

impl Reassembler {
    /// An empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set (or replace) the bundle header.
    pub fn set_header(&mut self, header: BundleHeader) {
        self.header = Some(header);
    }

    /// The header, once known.
    pub fn header(&self) -> Option<&BundleHeader> {
        self.header.as_ref()
    }

    /// Record one received block. Out-of-range blocks are rejected
    /// against the header.
    pub fn push_block(&mut self, index: u32, bytes: &[u8]) -> Result<()> {
        if let Some(h) = &self.header {
            if index >= h.data_block_count {
                return Err(PvtpError::HeaderMismatch);
            }
            let expected = if index + 1 == h.data_block_count {
                (h.total_data_len as usize) - (index as usize * BULK_BLOCK_BYTES)
            } else {
                BULK_BLOCK_BYTES
            };
            if bytes.len() != expected {
                return Err(PvtpError::HeaderMismatch);
            }
        }
        self.blocks.insert(index, bytes.to_vec());
        Ok(())
    }

    /// Block indices still missing (empty until the header is known).
    pub fn missing(&self) -> Vec<u32> {
        match &self.header {
            Some(h) => (0..h.data_block_count)
                .filter(|i| !self.blocks.contains_key(i))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Whether every block has arrived.
    pub fn is_complete(&self) -> bool {
        self.header.is_some() && self.missing().is_empty()
    }

    /// Assemble the bundle, verifying length and BLAKE3 hash.
    pub fn assemble(&self) -> Result<Vec<u8>> {
        let header = self.header.as_ref().ok_or(PvtpError::IncompleteBundle)?;
        if !self.is_complete() {
            return Err(PvtpError::IncompleteBundle);
        }
        let mut out = Vec::with_capacity(header.total_data_len as usize);
        for i in 0..header.data_block_count {
            out.extend_from_slice(&self.blocks[&i]);
        }
        if out.len() as u64 != header.total_data_len {
            return Err(PvtpError::HeaderMismatch);
        }
        if blake3::hash(&out).as_bytes() != &header.blake3 {
            return Err(PvtpError::HashMismatch);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> Vec<u8> {
        (0..5000u32).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn header_roundtrip() {
        let data = sample_data();
        let h = BundleHeader::of(&data);
        assert_eq!(h.data_block_count, 5);
        assert_eq!(BundleHeader::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn request_roundtrip() {
        let req = BlockRequest::from_blocks(&[10, 11, 13, 40]).unwrap();
        assert_eq!(req.blocks(), vec![10, 11, 13, 40]);
        assert_eq!(BlockRequest::decode(&req.encode()).unwrap(), req);
        assert!(BlockRequest::from_blocks(&[0, 100]).is_none());
    }

    #[test]
    fn reassembly_with_shuffled_partial_delivery() {
        let data = sample_data();
        let header = BundleHeader::of(&data);
        let mut r = Reassembler::new();
        r.set_header(header.clone());
        // Deliver blocks out of order, one missing.
        for i in [4u32, 2, 0, 3] {
            r.push_block(i, get_block(&data, i).unwrap()).unwrap();
        }
        assert_eq!(r.missing(), vec![1]);
        assert!(!r.is_complete());
        r.push_block(1, get_block(&data, 1).unwrap()).unwrap();
        assert!(r.is_complete());
        assert_eq!(r.assemble().unwrap(), data);
        // A wrong-sized block is rejected.
        let mut r2 = Reassembler::new();
        r2.set_header(header);
        assert_eq!(r2.push_block(0, &[1, 2, 3]), Err(PvtpError::HeaderMismatch));
    }
}
