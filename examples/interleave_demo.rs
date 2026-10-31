//! Interleaving demo: one lost packet becomes isolated frame losses.
//!
//! Run with: `cargo run --example interleave_demo`

use povertise_streaming::interleave::{packetize, Deinterleaver, FrameState};

fn main() {
    // 30 frames (600 ms) are spread across 5 packets.
    let frames: Vec<[u8; 15]> = (0..30).map(|i| [i as u8; 15]).collect();
    let packets = packetize(&frames);

    // Packet 2 is lost in transit; the rest arrive.
    let mut rx = Deinterleaver::new();
    for (i, p) in packets.iter().enumerate() {
        if i == 2 {
            rx.mark_lost(2);
        } else {
            rx.push(i as u64, *p);
        }
    }

    assert_eq!(rx.frame(2), FrameState::Lost); // concealed by PLC
    assert!(matches!(rx.frame(3), FrameState::Present(_)));

    let lost: Vec<u64> = (0..30).filter(|&f| rx.frame(f) == FrameState::Lost).collect();
    println!("lost frames: {lost:?} (isolated, 100 ms apart — PLC-friendly)");
}
