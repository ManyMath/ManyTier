/// A network path to a peer (one physical address/port).
///
/// Tracks liveness, latency, and whether traffic flows directly or via relay.
use core::net::SocketAddr;

use zerotier_protocol::ZT_PATH_HEARTBEAT_PERIOD;
/// Path expiration constant from protocol constants.
use zerotier_protocol::ZT_PEER_PATH_EXPIRATION;

/// A network path to a peer (one physical address/port).
#[derive(Debug, Clone)]
pub struct Path {
    pub address: SocketAddr,
    /// Monotonic timestamp (ms) when we last sent on this path.
    pub last_send: u64,
    /// Monotonic timestamp (ms) when we last received on this path.
    pub last_receive: u64,
    /// Measured latency in milliseconds (from HELLO round-trip).
    pub latency_ms: u32,
    pub is_direct: bool,
    last_echo_request: u64,
}

impl Path {
    /// Create a new path to the given address.
    pub fn new(address: SocketAddr, now_ms: u64) -> Self {
        Path {
            address,
            last_send: 0,
            last_receive: now_ms,
            latency_ms: 0,
            is_direct: true,
            last_echo_request: 0,
        }
    }

    /// Answer at most one ECHO per path per ZT_PEER_GENERAL_RATE_LIMIT / 6
    /// (ZeroTierOne node/Path.hpp `rateGateEchoRequest`).
    pub fn rate_gate_echo_request(&mut self, now_ms: u64) -> bool {
        if self.last_echo_request != 0
            && now_ms.saturating_sub(self.last_echo_request)
                < zerotier_protocol::constants::ZT_PEER_GENERAL_RATE_LIMIT / 6
        {
            return false;
        }
        self.last_echo_request = now_ms;
        true
    }

    /// Is this path alive? Alive = received within ZT_PEER_PATH_EXPIRATION (243s).
    pub fn is_alive(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_receive) < ZT_PEER_PATH_EXPIRATION
    }

    /// Update on packet received from this path.
    pub fn received(&mut self, now_ms: u64) {
        self.last_receive = now_ms;
    }

    /// Update on packet sent via this path.
    pub fn sent(&mut self, now_ms: u64) {
        self.last_send = now_ms;
    }

    /// Path quality score: lower is better. Combines latency, relay penalty, and age.
    /// Matches official ZeroTier path scoring.
    pub fn quality_score(&self, now_ms: u64) -> u32 {
        if !self.is_alive(now_ms) {
            return u32::MAX;
        }
        let age_ms = now_ms.saturating_sub(self.last_receive) as u32;
        let age_penalty = age_ms / 1000; // 1 point per second of age
        let relay_penalty: u32 = if self.is_direct { 0 } else { 10_000 };
        self.latency_ms
            .saturating_add(relay_penalty)
            .saturating_add(age_penalty)
    }

    /// Does this path need a heartbeat? True if we haven't sent in ZT_PATH_HEARTBEAT_PERIOD.
    pub fn needs_heartbeat(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_send) >= ZT_PATH_HEARTBEAT_PERIOD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr() -> SocketAddr {
        "192.168.1.1:9993".parse().unwrap()
    }

    #[test]
    fn path_new_is_alive() {
        let p = Path::new(test_addr(), 1000);
        assert!(p.is_alive(1000));
        assert!(p.is_alive(1000 + ZT_PEER_PATH_EXPIRATION - 1));
    }

    #[test]
    fn path_expires() {
        let p = Path::new(test_addr(), 1000);
        assert!(!p.is_alive(1000 + ZT_PEER_PATH_EXPIRATION));
        assert!(!p.is_alive(1000 + ZT_PEER_PATH_EXPIRATION + 1));
    }

    #[test]
    fn path_received_refreshes() {
        let mut p = Path::new(test_addr(), 1000);
        p.received(200_000);
        assert!(p.is_alive(200_000 + ZT_PEER_PATH_EXPIRATION - 1));
    }

    #[test]
    fn path_sent_updates_timestamp() {
        let mut p = Path::new(test_addr(), 1000);
        assert_eq!(p.last_send, 0);
        p.sent(5000);
        assert_eq!(p.last_send, 5000);
    }

    #[test]
    fn quality_score_lower_latency_wins() {
        let mut p1 = Path::new(test_addr(), 1000);
        p1.latency_ms = 10;
        let mut p2 = Path::new("192.168.1.2:9993".parse().unwrap(), 1000);
        p2.latency_ms = 100;
        assert!(p1.quality_score(1000) < p2.quality_score(1000));
    }

    #[test]
    fn quality_score_direct_beats_relay() {
        let mut p_direct = Path::new(test_addr(), 1000);
        p_direct.latency_ms = 50;
        p_direct.is_direct = true;
        let mut p_relay = Path::new("192.168.1.2:9993".parse().unwrap(), 1000);
        p_relay.latency_ms = 50;
        p_relay.is_direct = false;
        assert!(p_direct.quality_score(1000) < p_relay.quality_score(1000));
    }

    #[test]
    fn quality_score_dead_path_is_max() {
        let p = Path::new(test_addr(), 1000);
        // Path expired (now > last_receive + 243s)
        assert_eq!(
            p.quality_score(1000 + ZT_PEER_PATH_EXPIRATION + 1),
            u32::MAX
        );
    }

    #[test]
    fn quality_score_age_penalty() {
        let mut p1 = Path::new(test_addr(), 1000);
        p1.latency_ms = 10;
        let mut p2 = Path::new("192.168.1.2:9993".parse().unwrap(), 1000);
        p2.latency_ms = 10;
        // p1 scored at 1000ms (age=0), p2 scored at 100000ms (age=99s -> ~99 penalty)
        assert!(p1.quality_score(1000) < p2.quality_score(100_000));
    }

    #[test]
    fn needs_heartbeat_after_period() {
        let mut p = Path::new(test_addr(), 1000);
        p.last_send = 1000;
        assert!(!p.needs_heartbeat(1000 + ZT_PATH_HEARTBEAT_PERIOD - 1));
        assert!(p.needs_heartbeat(1000 + ZT_PATH_HEARTBEAT_PERIOD));
        assert!(p.needs_heartbeat(1000 + ZT_PATH_HEARTBEAT_PERIOD + 1));
    }

    #[test]
    fn needs_heartbeat_true_when_never_sent() {
        let p = Path::new(test_addr(), 1000);
        // last_send = 0, so any time >= ZT_PATH_HEARTBEAT_PERIOD should need heartbeat
        assert!(p.needs_heartbeat(ZT_PATH_HEARTBEAT_PERIOD));
    }
}
