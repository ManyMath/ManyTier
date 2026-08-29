/// Peer state machine .
///
/// A Peer tracks the identity, session state, and network paths for a remote
/// ZeroTier node. Session establishment uses X25519 key agreement to derive
/// a shared secret for packet encryption.
extern crate alloc;

use alloc::vec::Vec;
use core::net::SocketAddr;
use zeroize::ZeroizeOnDrop;
use zerotier_crypto::identity::Identity;
use zerotier_protocol::{ZT_PATH_HELLO_RATE_LIMIT, ZT_PEER_ACTIVITY_TIMEOUT, ZT_PEER_PING_PERIOD};

use crate::path::Path;

pub const HELLO_RETRY_BACKOFF_MAX_MS: u64 = 30_000;

/// State machine for a peer's session lifecycle.
#[derive(ZeroizeOnDrop)]
pub enum PeerState {
    /// Known identity but no session yet.
    Unknown,
    /// HELLO sent, awaiting OK(HELLO).
    HelloSent {
        sent_at: u64,
        packet_id: u64,
        retry_backoff_ms: u64,
    },
    /// Active session with shared secret.
    Active {
        shared_secret: [u8; 48],
        k0: [u8; 32],
        k1: [u8; 32],
        latency_ms: u32,
        last_receive: u64,
        last_send: u64,
    },
    /// Timed out (no packets for ZT_PEER_ACTIVITY_TIMEOUT).
    Stale {
        last_active: u64,
        retry_backoff_ms: u64,
        next_retry_at: u64,
    },
}

impl core::fmt::Debug for PeerState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PeerState::Unknown => f.write_str("Unknown"),
            PeerState::HelloSent {
                sent_at,
                packet_id,
                retry_backoff_ms,
            } => f
                .debug_struct("HelloSent")
                .field("sent_at", sent_at)
                .field("packet_id", packet_id)
                .field("retry_backoff_ms", retry_backoff_ms)
                .finish(),
            PeerState::Active {
                latency_ms,
                last_receive,
                last_send,
                ..
            } => f
                .debug_struct("Active")
                .field("shared_secret", &"[REDACTED]")
                .field("k0", &"[REDACTED]")
                .field("k1", &"[REDACTED]")
                .field("latency_ms", latency_ms)
                .field("last_receive", last_receive)
                .field("last_send", last_send)
                .finish(),
            PeerState::Stale {
                last_active,
                retry_backoff_ms,
                next_retry_at,
            } => f
                .debug_struct("Stale")
                .field("last_active", last_active)
                .field("retry_backoff_ms", retry_backoff_ms)
                .field("next_retry_at", next_retry_at)
                .finish(),
        }
    }
}

impl PeerState {
    /// Create an Active state with KBKDF-derived K0/K1 keys.
    pub fn new_active(
        shared_secret: [u8; 48],
        latency_ms: u32,
        last_receive: u64,
        last_send: u64,
    ) -> Self {
        let k0_full = zerotier_crypto::kbkdf::derive_k0(&shared_secret);
        let k1_full = zerotier_crypto::kbkdf::derive_k1(&shared_secret);
        let mut k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k0.copy_from_slice(&k0_full[..32]);
        k1.copy_from_slice(&k1_full[..32]);
        PeerState::Active {
            shared_secret,
            k0,
            k1,
            latency_ms,
            last_receive,
            last_send,
        }
    }
}

/// A remote ZeroTier peer.
#[derive(Debug)]
pub struct Peer {
    pub identity: Identity,
    pub state: PeerState,
    pub paths: Vec<Path>,
    pub is_root: bool,
    /// Last PUSH_DIRECT_PATHS to this peer.
    pub last_direct_path_push: u64,
}

impl Peer {
    /// Create a new peer with the given identity.
    pub fn new(identity: Identity, is_root: bool) -> Self {
        Peer {
            identity,
            state: PeerState::Unknown,
            paths: Vec::new(),
            is_root,
            last_direct_path_push: 0,
        }
    }

    /// Derive shared secret via X25519 key agreement and transition to Active.
    pub fn establish_session(
        &mut self,
        our_secret: &x25519_dalek::StaticSecret,
        latency_ms: u32,
        now_ms: u64,
    ) {
        let their_dh_pubkey = x25519_dalek::PublicKey::from(self.identity.public_key.dh);
        let shared_secret = zerotier_crypto::key_agreement::key_agree(our_secret, &their_dh_pubkey);
        self.state = PeerState::new_active(shared_secret, latency_ms, now_ms, now_ms);
    }

    /// Get the best path for sending (prefer direct, lowest latency).
    /// Uses quality_score which combines latency, relay penalty, and age.
    pub fn best_path(&self, now_ms: u64) -> Option<&Path> {
        self.paths
            .iter()
            .filter(|p| p.is_alive(now_ms))
            .min_by_key(|p| p.quality_score(now_ms))
    }

    /// Add or update a path to this peer.
    pub fn add_path(&mut self, addr: SocketAddr, is_direct: bool, now_ms: u64) {
        if let Some(existing) = self.paths.iter_mut().find(|p| p.address == addr) {
            existing.received(now_ms);
            existing.is_direct = is_direct;
        } else {
            let mut path = Path::new(addr, now_ms);
            path.is_direct = is_direct;
            self.paths.push(path);
        }
    }

    /// Check if peer needs a ping (ping every ZT_PEER_PING_PERIOD).
    pub fn needs_ping(&self, now_ms: u64) -> bool {
        match &self.state {
            PeerState::Active { last_send, .. } => {
                now_ms.saturating_sub(*last_send) >= ZT_PEER_PING_PERIOD
            }
            PeerState::HelloSent { sent_at, .. } => {
                let retry_backoff_ms = match &self.state {
                    PeerState::HelloSent {
                        retry_backoff_ms, ..
                    } => *retry_backoff_ms,
                    _ => ZT_PATH_HELLO_RATE_LIMIT,
                };
                now_ms.saturating_sub(*sent_at) >= retry_backoff_ms
            }
            _ => false,
        }
    }

    pub fn needs_reconnect(&self, now_ms: u64) -> bool {
        match &self.state {
            PeerState::Stale { next_retry_at, .. } => now_ms >= *next_retry_at,
            _ => false,
        }
    }

    pub fn on_hello_sent(&mut self, packet_id: u64, now_ms: u64) {
        match &mut self.state {
            PeerState::Active { last_send, .. } => {
                *last_send = now_ms;
            }
            PeerState::HelloSent {
                sent_at,
                packet_id: stored_packet_id,
                retry_backoff_ms,
            } => {
                *sent_at = now_ms;
                *stored_packet_id = packet_id;
                *retry_backoff_ms = retry_backoff_ms
                    .saturating_mul(2)
                    .clamp(ZT_PATH_HELLO_RATE_LIMIT, HELLO_RETRY_BACKOFF_MAX_MS);
            }
            PeerState::Stale {
                retry_backoff_ms, ..
            } => {
                self.state = PeerState::HelloSent {
                    sent_at: now_ms,
                    packet_id,
                    retry_backoff_ms: (*retry_backoff_ms)
                        .clamp(ZT_PATH_HELLO_RATE_LIMIT, HELLO_RETRY_BACKOFF_MAX_MS),
                };
            }
            PeerState::Unknown => {
                self.state = PeerState::HelloSent {
                    sent_at: now_ms,
                    packet_id,
                    retry_backoff_ms: ZT_PATH_HELLO_RATE_LIMIT,
                };
            }
        }
    }

    /// Check if peer is stale (no activity for ZT_PEER_ACTIVITY_TIMEOUT).
    pub fn is_stale(&self, now_ms: u64) -> bool {
        match &self.state {
            PeerState::Active { last_receive, .. } => {
                now_ms.saturating_sub(*last_receive) >= ZT_PEER_ACTIVITY_TIMEOUT
            }
            PeerState::HelloSent { sent_at, .. } => {
                now_ms.saturating_sub(*sent_at) >= ZT_PEER_ACTIVITY_TIMEOUT
            }
            PeerState::Stale { .. } => true,
            PeerState::Unknown => false,
        }
    }

    /// Get shared secret if session is active.
    pub fn shared_secret(&self) -> Option<&[u8; 48]> {
        match &self.state {
            PeerState::Active { shared_secret, .. } => Some(shared_secret),
            _ => None,
        }
    }

    /// Get KBKDF-derived AES keys (K0, K1) if session is active.
    pub fn aes_keys(&self) -> Option<(&[u8; 32], &[u8; 32])> {
        match &self.state {
            PeerState::Active { k0, k1, .. } => Some((k0, k1)),
            _ => None,
        }
    }

    /// Promote a relay path to direct when we receive a direct packet.
    /// Relay-first, promote on direct packet arrival.
    pub fn promote_path(&mut self, addr: SocketAddr, now_ms: u64) {
        if let Some(path) = self.paths.iter_mut().find(|p| p.address == addr) {
            path.is_direct = true;
            path.received(now_ms);
        } else {
            // New direct path discovered
            self.add_path(addr, true, now_ms);
        }
    }

    /// Mark peer as stale, preserving identity for future reconnection.
    pub fn mark_stale(&mut self, _now_ms: u64) {
        if let PeerState::Active { last_receive, .. } = &self.state {
            self.state = PeerState::Stale {
                last_active: *last_receive,
                retry_backoff_ms: ZT_PATH_HELLO_RATE_LIMIT,
                next_retry_at: _now_ms,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerotier_crypto::identity::{Address, PublicKey};

    fn stub_peer() -> Peer {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0xe4]).unwrap();
        let pk = PublicKey::from_bytes(&[0x42u8; 64]).unwrap();
        let identity = Identity {
            address,
            public_key: pk,
            secret: None,
        };
        Peer::new(identity, false)
    }

    fn test_addr() -> SocketAddr {
        "192.168.1.1:9993".parse().unwrap()
    }

    #[test]
    fn new_peer_is_unknown() {
        let peer = stub_peer();
        assert!(matches!(peer.state, PeerState::Unknown));
        assert!(peer.paths.is_empty());
        assert!(!peer.is_root);
    }

    #[test]
    fn add_path_creates_new() {
        let mut peer = stub_peer();
        peer.add_path(test_addr(), true, 1000);
        assert_eq!(peer.paths.len(), 1);
        assert!(peer.paths[0].is_direct);
    }

    #[test]
    fn add_path_updates_existing() {
        let mut peer = stub_peer();
        peer.add_path(test_addr(), false, 1000);
        peer.add_path(test_addr(), true, 2000);
        assert_eq!(peer.paths.len(), 1);
        assert!(peer.paths[0].is_direct);
        assert_eq!(peer.paths[0].last_receive, 2000);
    }

    #[test]
    fn best_path_prefers_direct() {
        let mut peer = stub_peer();
        let relay_addr: SocketAddr = "10.0.0.1:9993".parse().unwrap();
        let direct_addr: SocketAddr = "10.0.0.2:9993".parse().unwrap();
        peer.add_path(relay_addr, false, 1000);
        peer.add_path(direct_addr, true, 1000);
        let best = peer.best_path(1000).unwrap();
        assert_eq!(best.address, direct_addr);
    }

    #[test]
    fn best_path_returns_none_when_expired() {
        let mut peer = stub_peer();
        peer.add_path(test_addr(), true, 1000);
        // Far in the future -- path expired
        assert!(peer.best_path(1_000_000).is_none());
    }

    #[test]
    fn shared_secret_none_when_unknown() {
        let peer = stub_peer();
        assert!(peer.shared_secret().is_none());
    }

    #[test]
    fn needs_ping_when_active_and_overdue() {
        let mut peer = stub_peer();
        peer.state = PeerState::new_active([0u8; 48], 10, 1000, 1000);
        assert!(!peer.needs_ping(1000 + ZT_PEER_PING_PERIOD - 1));
        assert!(peer.needs_ping(1000 + ZT_PEER_PING_PERIOD));
    }

    #[test]
    fn needs_ping_for_hello_sent_uses_backoff() {
        let mut peer = stub_peer();
        peer.state = PeerState::HelloSent {
            sent_at: 1000,
            packet_id: 1,
            retry_backoff_ms: 4000,
        };
        assert!(!peer.needs_ping(4999));
        assert!(peer.needs_ping(5000));
    }

    #[test]
    fn is_stale_when_no_recent_activity() {
        let mut peer = stub_peer();
        peer.state = PeerState::new_active([0u8; 48], 10, 1000, 1000);
        assert!(!peer.is_stale(1000 + ZT_PEER_ACTIVITY_TIMEOUT - 1));
        assert!(peer.is_stale(1000 + ZT_PEER_ACTIVITY_TIMEOUT));
    }

    #[test]
    fn promote_path_relay_to_direct() {
        let mut peer = stub_peer();
        let addr: SocketAddr = "10.0.0.1:9993".parse().unwrap();
        peer.add_path(addr, false, 1000); // relay
        assert!(!peer.paths[0].is_direct);
        peer.promote_path(addr, 2000);
        assert!(peer.paths[0].is_direct);
        assert_eq!(peer.paths[0].last_receive, 2000);
    }

    #[test]
    fn promote_path_adds_new_if_unknown() {
        let mut peer = stub_peer();
        let addr: SocketAddr = "10.0.0.5:9993".parse().unwrap();
        assert!(peer.paths.is_empty());
        peer.promote_path(addr, 3000);
        assert_eq!(peer.paths.len(), 1);
        assert!(peer.paths[0].is_direct);
    }

    #[test]
    fn mark_stale_transitions_active_to_stale() {
        let mut peer = stub_peer();
        peer.state = PeerState::new_active([0u8; 48], 10, 5000, 5000);
        peer.mark_stale(600_000);
        match peer.state {
            PeerState::Stale {
                last_active,
                retry_backoff_ms,
                next_retry_at,
            } => {
                assert_eq!(last_active, 5000);
                assert_eq!(retry_backoff_ms, ZT_PATH_HELLO_RATE_LIMIT);
                assert_eq!(next_retry_at, 600_000);
            }
            _ => panic!("expected Stale state"),
        }
    }

    #[test]
    fn on_hello_sent_doubles_backoff_for_retries() {
        let mut peer = stub_peer();
        peer.state = PeerState::HelloSent {
            sent_at: 1000,
            packet_id: 1,
            retry_backoff_ms: ZT_PATH_HELLO_RATE_LIMIT,
        };

        peer.on_hello_sent(2, 2000);

        match peer.state {
            PeerState::HelloSent {
                sent_at,
                packet_id,
                retry_backoff_ms,
            } => {
                assert_eq!(sent_at, 2000);
                assert_eq!(packet_id, 2);
                assert_eq!(retry_backoff_ms, ZT_PATH_HELLO_RATE_LIMIT * 2);
            }
            _ => panic!("expected HelloSent state"),
        }
    }

    #[test]
    fn mark_stale_noop_on_unknown() {
        let mut peer = stub_peer();
        peer.mark_stale(1000);
        assert!(matches!(peer.state, PeerState::Unknown));
    }

    #[test]
    fn best_path_uses_quality_score() {
        let mut peer = stub_peer();
        // Add a relay path with low latency
        let relay_addr: SocketAddr = "10.0.0.1:9993".parse().unwrap();
        peer.add_path(relay_addr, false, 1000);
        peer.paths[0].latency_ms = 5;

        // Add a direct path with higher latency
        let direct_addr: SocketAddr = "10.0.0.2:9993".parse().unwrap();
        peer.add_path(direct_addr, true, 1000);
        peer.paths[1].latency_ms = 50;

        // Direct path should win due to relay penalty (10000)
        let best = peer.best_path(1000).unwrap();
        assert_eq!(best.address, direct_addr);
    }
}
