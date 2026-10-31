//! Frame interleaving: PVTP's loss-shaping mechanism.
//!
//! Instead of sending parity bytes, PVTP spreads the frames of a
//! 600 ms group across 5 packets with a stride of 5 frames:
//!
//! ```text
//! packet k of group g carries frames 30g + k + 5j   (j = 0..5)
//! ```
//!
//! Losing one packet therefore destroys 6 single frames, each isolated
//! between intact neighbours 100 ms apart — exactly the loss pattern
//! Opus PLC (packet loss concealment) handles best. A burst loss of
//! 120 ms, which PLC handles badly, never occurs from a single packet.
//! The cost is zero bytes; the latency cost is nil for pre-encoded
//! on-demand content.

use std::collections::{BTreeMap, BTreeSet};

use crate::{FRAME_BYTES, FRAMES_PER_GROUP, FRAMES_PER_PACKET, PACKETS_PER_GROUP, PACKET_PAYLOAD_BYTES};

/// One 20 ms Opus frame (15 bytes at 6 kbps CBR).
pub type Frame = [u8; FRAME_BYTES];
/// The 90-byte payload of one media packet (6 frames).
pub type PacketPayload = [u8; PACKET_PAYLOAD_BYTES];

/// Where a frame lives: `(packet index, position within the packet)`.
pub fn frame_location(frame: u64) -> (u64, usize) {
    let group = frame / FRAMES_PER_GROUP as u64;
    let r = frame % FRAMES_PER_GROUP as u64;
    let k = r % PACKETS_PER_GROUP as u64;
    let j = (r / PACKETS_PER_GROUP as u64) as usize;
    (group * PACKETS_PER_GROUP as u64 + k, j)
}

/// The 6 frame indices carried by a packet, in payload order.
pub fn packet_frames(packet: u64) -> [u64; FRAMES_PER_PACKET] {
    let group = packet / PACKETS_PER_GROUP as u64;
    let k = packet % PACKETS_PER_GROUP as u64;
    let mut out = [0u64; FRAMES_PER_PACKET];
    for (j, slot) in out.iter_mut().enumerate() {
        *slot = group * FRAMES_PER_GROUP as u64 + k + PACKETS_PER_GROUP as u64 * j as u64;
    }
    out
}

/// Split a frame sequence into packet payloads.
///
/// The input is padded with zero frames up to a whole number of groups;
/// callers that need real silence should pass Opus silence frames
/// themselves before calling. Packets are returned in index order,
/// starting at packet 0.
pub fn packetize(frames: &[Frame]) -> Vec<PacketPayload> {
    let groups = frames.len().div_ceil(FRAMES_PER_GROUP);
    let mut packets = vec![[0u8; PACKET_PAYLOAD_BYTES]; groups * PACKETS_PER_GROUP];
    for (i, frame) in frames.iter().enumerate() {
        let (packet, pos) = frame_location(i as u64);
        let payload = &mut packets[packet as usize];
        payload[pos * FRAME_BYTES..(pos + 1) * FRAME_BYTES].copy_from_slice(frame);
    }
    packets
}

/// What the receiver knows about a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameState {
    /// The frame arrived intact.
    Present(Frame),
    /// Its packet is known lost; the decoder should run PLC for it.
    Lost,
    /// Its packet has neither arrived nor been declared lost yet.
    Pending,
}

/// Receiver-side deinterleaver.
#[derive(Debug, Default)]
pub struct Deinterleaver {
    received: BTreeMap<u64, PacketPayload>,
    lost: BTreeSet<u64>,
}

impl Deinterleaver {
    /// An empty deinterleaver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the arrival of a media packet.
    pub fn push(&mut self, packet: u64, payload: PacketPayload) {
        self.lost.remove(&packet);
        self.received.insert(packet, payload);
    }

    /// Declare a packet lost (its retransmission window has passed;
    /// PVTP media is never retransmitted).
    pub fn mark_lost(&mut self, packet: u64) {
        if !self.received.contains_key(&packet) {
            self.lost.insert(packet);
        }
    }

    /// The state of one frame.
    pub fn frame(&self, frame: u64) -> FrameState {
        let (packet, pos) = frame_location(frame);
        if let Some(payload) = self.received.get(&packet) {
            let mut out = [0u8; FRAME_BYTES];
            out.copy_from_slice(&payload[pos * FRAME_BYTES..(pos + 1) * FRAME_BYTES]);
            FrameState::Present(out)
        } else if self.lost.contains(&packet) {
            FrameState::Lost
        } else {
            FrameState::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numbered_frames(n: usize) -> Vec<Frame> {
        (0..n)
            .map(|i| {
                let mut f = [0u8; FRAME_BYTES];
                f[..8].copy_from_slice(&(i as u64).to_be_bytes());
                f
            })
            .collect()
    }

    #[test]
    fn location_and_frames_are_inverse() {
        for frame in 0..600u64 {
            let (packet, pos) = frame_location(frame);
            assert_eq!(packet_frames(packet)[pos], frame);
        }
    }

    #[test]
    fn packetize_roundtrip() {
        let frames = numbered_frames(30);
        let packets = packetize(&frames);
        assert_eq!(packets.len(), PACKETS_PER_GROUP);
        let mut d = Deinterleaver::new();
        for (i, p) in packets.iter().enumerate() {
            d.push(i as u64, *p);
        }
        for (i, f) in frames.iter().enumerate() {
            assert_eq!(d.frame(i as u64), FrameState::Present(*f));
        }
    }

    #[test]
    fn one_lost_packet_scatters_single_frame_holes() {
        let frames = numbered_frames(30);
        let packets = packetize(&frames);
        let mut d = Deinterleaver::new();
        for (i, p) in packets.iter().enumerate() {
            if i == 2 {
                d.mark_lost(2);
            } else {
                d.push(i as u64, *p);
            }
        }
        let lost: Vec<u64> = (0..30u64)
            .filter(|&f| d.frame(f) == FrameState::Lost)
            .collect();
        assert_eq!(lost, vec![2, 7, 12, 17, 22, 27]);
        // No two lost frames are adjacent: every hole is PLC-friendly.
        for w in lost.windows(2) {
            assert!(w[1] - w[0] > 1);
        }
    }
}
