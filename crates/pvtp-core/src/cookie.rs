//! Reachability cookies: PVTP's amplification defence (spec §3.0).
//!
//! Before any sizeable response, the server answers a first hello with
//! a small cookie — a keyed hash of the client's address and a time
//! window. The client echoes the cookie in its real ClientHello,
//! proving the address can receive packets. Until then the server
//! never sends more than it received, and keeps no state: the cookie
//! *is* the state.

/// Cookie length in bytes.
pub const COOKIE_BYTES: usize = 16;
/// Cookies are issued per 120-second window and accepted for the
/// current and previous window (up to ~4 minutes of clock slack).
pub const COOKIE_WINDOW_SECS: u64 = 120;

fn cookie_for_window(server_key: &[u8; 32], addr: &[u8], port: u16, window: u64) -> [u8; COOKIE_BYTES] {
    let mut hasher = blake3::Hasher::new_keyed(server_key);
    hasher.update(b"PVTP-COOKIE-V1");
    hasher.update(&(addr.len() as u32).to_be_bytes());
    hasher.update(addr);
    hasher.update(&port.to_be_bytes());
    hasher.update(&window.to_be_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; COOKIE_BYTES];
    out.copy_from_slice(&digest.as_bytes()[..COOKIE_BYTES]);
    out
}

/// Issue a cookie for a client address (typically the 16 octets of an
/// IPv6 address) at time `now` (Unix seconds).
pub fn issue_cookie(server_key: &[u8; 32], addr: &[u8], port: u16, now: u64) -> [u8; COOKIE_BYTES] {
    cookie_for_window(server_key, addr, port, now / COOKIE_WINDOW_SECS)
}

/// Verify a cookie echoed by a client.
pub fn verify_cookie(
    server_key: &[u8; 32],
    addr: &[u8],
    port: u16,
    cookie: &[u8; COOKIE_BYTES],
    now: u64,
) -> bool {
    let window = now / COOKIE_WINDOW_SECS;
    *cookie == cookie_for_window(server_key, addr, port, window)
        || (window > 0 && *cookie == cookie_for_window(server_key, addr, port, window - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_roundtrip_and_binding() {
        let key = [7u8; 32];
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let now = 1_700_000_000;
        let cookie = issue_cookie(&key, &addr, 4433, now);
        assert!(verify_cookie(&key, &addr, 4433, &cookie, now));
        // Slightly later, still inside the acceptance window.
        assert!(verify_cookie(&key, &addr, 4433, &cookie, now + COOKIE_WINDOW_SECS));
        // Bound to address, port and key.
        assert!(!verify_cookie(&key, &[0u8; 16], 4433, &cookie, now));
        assert!(!verify_cookie(&key, &addr, 4434, &cookie, now));
        assert!(!verify_cookie(&[8u8; 32], &addr, 4433, &cookie, now));
        // Stale: three windows later it no longer verifies.
        assert!(!verify_cookie(&key, &addr, 4433, &cookie, now + 3 * COOKIE_WINDOW_SECS));
    }
}
