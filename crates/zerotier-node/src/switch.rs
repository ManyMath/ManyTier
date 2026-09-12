/// Packet routing (switch) .
///
/// Determines how to route outbound packets: direct to peer, relay through
/// root server, or drop. Implements hop count management for relayed packets.
use zerotier_protocol::constants::ZT_RELAY_MAX_HOPS;

use crate::topology::Topology;

/// The result of a routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    /// Send directly to the peer at this address.
    Direct { address: core::net::SocketAddr },
    /// Relay through a root server.
    Relay {
        root_address: core::net::SocketAddr,
        root_zt_address: [u8; 5],
        dest_zt_address: [u8; 5],
    },
    /// No route available (drop the packet).
    Drop,
}

/// Packet routing switch.
pub struct Switch;

impl Switch {
    /// Decide how to route a packet to a destination ZT address.
    ///
    /// Relay-first, promote to direct when a direct path arrives.
    /// 1. If dest peer exists with active direct path -> Direct
    /// 2. If dest peer exists but only relay path -> Relay
    /// 3. Dest peer unknown -> Relay through best root (triggers WHOIS)
    /// 4. No root available -> Drop
    pub fn route(topology: &Topology, dest: &[u8; 5], now_ms: u64) -> RouteDecision {
        // Check if we know the destination peer
        if let Some(peer) = topology.get_peer(dest) {
            // Try to find a direct path
            if let Some(path) = peer.best_path(now_ms) {
                if path.is_direct {
                    return RouteDecision::Direct {
                        address: path.address,
                    };
                }
            }
        }

        // Relay through the best reachable root
        if let Some((root_zt_address, root)) = topology.best_root(now_ms) {
            if let Some(path) = root.best_path(now_ms).or_else(|| root.paths.first()) {
                return RouteDecision::Relay {
                    root_address: path.address,
                    root_zt_address: *root_zt_address,
                    dest_zt_address: *dest,
                };
            }
        }

        RouteDecision::Drop
    }

    /// Increment hop count in packet header (for relay).
    ///
    /// Per protocol: hops field = flags & 0x07, increment by 1, max ZT_RELAY_MAX_HOPS.
    /// Returns false if already at max hops (packet should be dropped).
    pub fn increment_hops(packet: &mut [u8]) -> bool {
        if packet.len() < 19 {
            return false;
        }
        let flags = packet[18];
        let hops = flags & 0x07;
        if hops >= ZT_RELAY_MAX_HOPS {
            return false;
        }
        // Clear lower 3 bits and set new hop count
        packet[18] = (flags & 0xf8) | (hops + 1);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::{Peer, PeerState};
    use crate::topology::Topology;
    use zerotier_crypto::identity::{Address, Identity, PublicKey};
    use zerotier_protocol::constants::ZT_RELAY_MAX_HOPS;

    fn make_identity(addr_byte: u8) -> Identity {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, addr_byte]).unwrap();
        let pk = PublicKey::from_bytes(&[addr_byte; 64]).unwrap();
        Identity {
            address,
            public_key: pk,
            secret: None,
        }
    }

    #[test]
    fn route_direct_peer() {
        let mut topo = Topology::new();
        let id = make_identity(0x01);
        let addr_bytes = *id.address.as_bytes();
        let mut peer = Peer::new(id, false);
        peer.add_path("10.0.0.1:9993".parse().unwrap(), true, 1000);
        peer.state = PeerState::new_active([0u8; 48], 10, 1000, 1000);
        topo.peers.insert(addr_bytes, peer);

        let decision = Switch::route(&topo, &addr_bytes, 1000);
        assert_eq!(
            decision,
            RouteDecision::Direct {
                address: "10.0.0.1:9993".parse().unwrap()
            }
        );
    }

    #[test]
    fn route_unknown_peer_with_root_relays() {
        let mut topo = Topology::new();
        let root_id = make_identity(0xe0);
        let root_addr = *root_id.address.as_bytes();
        let mut root = Peer::new(root_id, true);
        root.add_path("10.0.0.99:9993".parse().unwrap(), true, 1000);
        topo.peers.insert(root_addr, root);
        topo.roots.push(root_addr);

        let unknown_addr = [0x11, 0x22, 0x33, 0x44, 0x55];
        let decision = Switch::route(&topo, &unknown_addr, 1000);
        assert_eq!(
            decision,
            RouteDecision::Relay {
                root_address: "10.0.0.99:9993".parse().unwrap(),
                root_zt_address: root_addr,
                dest_zt_address: unknown_addr,
            }
        );
    }

    #[test]
    fn route_known_peer_with_only_relay_path_uses_root() {
        let mut topo = Topology::new();
        let id = make_identity(0x01);
        let addr_bytes = *id.address.as_bytes();
        let mut peer = Peer::new(id, false);
        // Peer is known, but its only recorded path is non-direct (e.g. learned
        // via a relayed HELLO), so it must not be treated as directly reachable.
        peer.add_path("10.0.0.1:9993".parse().unwrap(), false, 1000);
        peer.state = PeerState::new_active([0u8; 48], 10, 1000, 1000);
        topo.peers.insert(addr_bytes, peer);

        let root_id = make_identity(0xe0);
        let root_addr = *root_id.address.as_bytes();
        let mut root = Peer::new(root_id, true);
        root.add_path("10.0.0.99:9993".parse().unwrap(), true, 1000);
        topo.peers.insert(root_addr, root);
        topo.roots.push(root_addr);

        let decision = Switch::route(&topo, &addr_bytes, 1000);
        assert_eq!(
            decision,
            RouteDecision::Relay {
                root_address: "10.0.0.99:9993".parse().unwrap(),
                root_zt_address: root_addr,
                dest_zt_address: addr_bytes,
            }
        );
    }

    #[test]
    fn route_prefers_a_live_root_over_the_first_one() {
        let mut topo = Topology::new();
        let dead_id = make_identity(0xe0);
        let dead_addr = *dead_id.address.as_bytes();
        let mut dead = Peer::new(dead_id, true);
        dead.add_path("10.0.0.98:9993".parse().unwrap(), true, 1000);
        topo.peers.insert(dead_addr, dead);
        topo.roots.push(dead_addr);

        let live_id = make_identity(0xe1);
        let live_addr = *live_id.address.as_bytes();
        let mut live = Peer::new(live_id, true);
        live.add_path("10.0.0.99:9993".parse().unwrap(), true, 900_000);
        topo.peers.insert(live_addr, live);
        topo.roots.push(live_addr);

        let dest = [0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(
            Switch::route(&topo, &dest, 1_000_000),
            RouteDecision::Relay {
                root_address: "10.0.0.99:9993".parse().unwrap(),
                root_zt_address: live_addr,
                dest_zt_address: dest,
            }
        );
    }

    #[test]
    fn route_no_root_drops() {
        let topo = Topology::new();
        let unknown_addr = [0x11, 0x22, 0x33, 0x44, 0x55];
        let decision = Switch::route(&topo, &unknown_addr, 1000);
        assert_eq!(decision, RouteDecision::Drop);
    }

    #[test]
    fn increment_hops_works() {
        let mut packet = [0u8; 28];
        packet[18] = 0b00_001_000; // cipher suite 1, hops 0
        assert!(Switch::increment_hops(&mut packet));
        assert_eq!(packet[18] & 0x07, 1);

        assert!(Switch::increment_hops(&mut packet));
        assert_eq!(packet[18] & 0x07, 2);
    }

    #[test]
    fn increment_hops_at_max_returns_false() {
        let mut packet = [0u8; 28];
        packet[18] = ZT_RELAY_MAX_HOPS; // already at max
        assert!(!Switch::increment_hops(&mut packet));
    }

    #[test]
    fn increment_hops_preserves_upper_bits() {
        let mut packet = [0u8; 28];
        packet[18] = 0b11_101_001; // flags=11, cipher=101, hops=1
        assert!(Switch::increment_hops(&mut packet));
        assert_eq!(packet[18], 0b11_101_010); // hops incremented to 2
    }

    #[test]
    fn increment_hops_too_short_packet() {
        let mut packet = [0u8; 10];
        assert!(!Switch::increment_hops(&mut packet));
    }
}
