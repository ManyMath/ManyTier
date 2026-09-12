/// Topology: peer table and root server tracking for the ZeroTier node engine.
///
/// Manages the set of known peers, root servers (from planet/moon definitions),
/// and pending WHOIS requests for address resolution.
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use zerotier_crypto::identity::Identity;
use zerotier_protocol::world::World;

use crate::peer::Peer;

/// Topology manager: peer table and root tracking.
pub struct Topology {
    pub peers: BTreeMap<[u8; 5], Peer>,
    /// Addresses of root servers (subset of peers).
    pub roots: Vec<[u8; 5]>,
    pub planet: Option<World>,
    /// Loaded moon definitions.
    pub moons: Vec<World>,
    pub pending_whois: BTreeMap<[u8; 5], (u64, u64)>,
}

impl Default for Topology {
    fn default() -> Self {
        Self::new()
    }
}

impl Topology {
    /// Create a new empty topology.
    pub fn new() -> Self {
        Topology {
            peers: BTreeMap::new(),
            roots: Vec::new(),
            planet: None,
            moons: Vec::new(),
            pending_whois: BTreeMap::new(),
        }
    }

    /// Load a planet file and populate root peers with their endpoints.
    ///
    /// The bundled default/genesis planet is trusted unconditionally,
    /// matching upstream ZeroTier: a world's `signing_key` field names the
    /// key required to sign a *future* replacement world
    /// (`_updatesMustBeSignedBy`), not the key that signed this one, so
    /// there is no self-referential signature to check for a bootstrap
    /// world with no prior world to chain trust from.
    pub fn load_planet(&mut self, world: World) {
        for root in &world.roots {
            let addr_bytes = *root.identity.address.as_bytes();
            if !self.roots.contains(&addr_bytes) {
                self.roots.push(addr_bytes);
            }
            // Create peer entry with root endpoints
            let mut peer = Peer::new(
                Identity {
                    address: root.identity.address,
                    public_key: root.identity.public_key.clone(),
                    secret: None,
                },
                true,
            );
            for endpoint in &root.endpoints {
                if let Some(socket_addr) = endpoint.to_socket_addr() {
                    peer.add_path(socket_addr, true, 0);
                }
            }
            self.peers.insert(addr_bytes, peer);
        }
        self.planet = Some(world);
    }

    /// Load a moon and add its roots as additional root servers.
    ///
    /// Rejects (without side effects) a moon whose signature does not verify
    /// against its own embedded signing key -- see `World::verify_signature`.
    pub fn load_moon(&mut self, moon: World) -> Result<(), zerotier_protocol::ProtocolError> {
        moon.verify_signature()?;
        for root in &moon.roots {
            let addr_bytes = *root.identity.address.as_bytes();
            if !self.roots.contains(&addr_bytes) {
                self.roots.push(addr_bytes);
            }
            let mut peer = Peer::new(
                Identity {
                    address: root.identity.address,
                    public_key: root.identity.public_key.clone(),
                    secret: None,
                },
                true,
            );
            for endpoint in &root.endpoints {
                if let Some(socket_addr) = endpoint.to_socket_addr() {
                    peer.add_path(socket_addr, true, 0);
                }
            }
            self.peers.insert(addr_bytes, peer);
        }
        self.moons.push(moon);
        Ok(())
    }

    /// Unload a moon by world ID, removing its roots from the root set.
    ///
    /// Roots that also appear in the planet or another loaded moon are kept.
    /// Peer entries are left in place: an established session is still valid
    /// even if the peer is no longer treated as a root. Returns `true` if a
    /// moon with the given ID was loaded.
    pub fn unload_moon(&mut self, moon_id: u64) -> bool {
        let Some(index) = self.moons.iter().position(|m| m.id == moon_id) else {
            return false;
        };
        let moon = self.moons.remove(index);
        for root in &moon.roots {
            let addr_bytes = *root.identity.address.as_bytes();
            let still_a_root = self.planet.as_ref().is_some_and(|p| {
                p.roots
                    .iter()
                    .any(|r| r.identity.address.as_bytes() == &addr_bytes)
            }) || self.moons.iter().any(|m| {
                m.roots
                    .iter()
                    .any(|r| r.identity.address.as_bytes() == &addr_bytes)
            });
            if !still_a_root {
                self.roots.retain(|addr| addr != &addr_bytes);
            }
        }
        true
    }

    /// Get a peer by address.
    pub fn get_peer(&self, address: &[u8; 5]) -> Option<&Peer> {
        self.peers.get(address)
    }

    /// Get a mutable peer by address.
    pub fn get_peer_mut(&mut self, address: &[u8; 5]) -> Option<&mut Peer> {
        self.peers.get_mut(address)
    }

    /// Get a root peer for relaying/WHOIS.
    ///
    /// Returns the first known root regardless of reachability; use
    /// [`Topology::best_root`] to pick one to send through.
    pub fn get_root(&self) -> Option<&Peer> {
        self.roots
            .iter()
            .filter_map(|addr| self.peers.get(addr))
            .next()
    }

    /// The root to send through: the one with the best live path, else the
    /// first root with any known path (ZeroTierOne `getUpstreamPeer`).
    pub fn best_root(&self, now_ms: u64) -> Option<(&[u8; 5], &Peer)> {
        let roots = || {
            self.roots
                .iter()
                .filter_map(|addr| self.peers.get(addr).map(|peer| (addr, peer)))
        };
        roots()
            .filter_map(|(addr, peer)| {
                peer.best_path(now_ms)
                    .map(|path| (path.quality_score(now_ms), addr, peer))
            })
            .min_by_key(|(score, _, _)| *score)
            .map(|(_, addr, peer)| (addr, peer))
            .or_else(|| roots().find(|(_, peer)| !peer.paths.is_empty()))
    }

    /// Get a mutable reference to a root peer.
    pub fn get_root_mut(&mut self) -> Option<&mut Peer> {
        // Find first root address, then get mutable ref
        let root_addr = self.roots.first().copied()?;
        self.peers.get_mut(&root_addr)
    }

    /// Add or update a peer from a learned identity.
    pub fn add_peer(&mut self, identity: Identity) {
        let addr_bytes = *identity.address.as_bytes();
        self.peers
            .entry(addr_bytes)
            .or_insert_with(|| Peer::new(identity, false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerotier_crypto::identity::{Address, PublicKey};
    use zerotier_protocol::inet_address::InetAddress;
    use zerotier_protocol::world::{WorldRoot, WorldType};

    fn build_test_identity(addr_byte: u8) -> Identity {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, addr_byte]).unwrap();
        let mut pk_bytes = [0u8; 64];
        for (i, b) in pk_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(addr_byte);
        }
        let public_key = PublicKey::from_bytes(&pk_bytes).unwrap();
        Identity {
            address,
            public_key,
            secret: None,
        }
    }

    /// Build a self-consistently-signed test world so `verify_signature` (and
    /// therefore `Topology::load_moon`) accepts it.
    fn signed_test_world(
        world_type: WorldType,
        id: u64,
        timestamp: u64,
        roots: alloc::vec::Vec<WorldRoot>,
    ) -> World {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let mut public_key_bytes = [0u8; 64];
        public_key_bytes[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        let bytes = match world_type {
            WorldType::Moon => crate::controller::world_gen::generate_moon(
                id,
                timestamp,
                roots,
                &signing_key,
                &public_key_bytes,
            ),
            _ => crate::controller::world_gen::generate_planet(
                id,
                timestamp,
                roots,
                &signing_key,
                &public_key_bytes,
            ),
        };
        World::deserialize(&bytes).expect("generated test world should deserialize")
    }

    fn stub_world() -> World {
        let root_id = build_test_identity(0xe0);
        signed_test_world(
            WorldType::Planet,
            149604618,
            1000000,
            alloc::vec![WorldRoot {
                identity: root_id,
                endpoints: alloc::vec![InetAddress::V4 {
                    ip: [192, 168, 1, 1],
                    port: 9993,
                }],
            }],
        )
    }

    #[test]
    fn new_topology_is_empty() {
        let topo = Topology::new();
        assert!(topo.peers.is_empty());
        assert!(topo.roots.is_empty());
        assert!(topo.planet.is_none());
    }

    #[test]
    fn load_planet_adds_roots() {
        let mut topo = Topology::new();
        let world = stub_world();
        topo.load_planet(world);

        assert_eq!(topo.roots.len(), 1);
        assert_eq!(topo.peers.len(), 1);
        assert!(topo.planet.is_some());

        let root_addr = topo.roots[0];
        let peer = topo.get_peer(&root_addr).unwrap();
        assert!(peer.is_root);
        assert_eq!(peer.paths.len(), 1);
    }

    #[test]
    fn get_root_returns_root_peer() {
        let mut topo = Topology::new();
        topo.load_planet(stub_world());
        assert!(topo.get_root().is_some());
        assert!(topo.get_root().unwrap().is_root);
    }

    #[test]
    fn add_peer_creates_non_root() {
        let mut topo = Topology::new();
        let id = build_test_identity(0x01);
        let addr = *id.address.as_bytes();
        topo.add_peer(id);

        let peer = topo.get_peer(&addr).unwrap();
        assert!(!peer.is_root);
    }

    #[test]
    fn add_peer_does_not_overwrite() {
        let mut topo = Topology::new();
        let id = build_test_identity(0x01);
        let addr = *id.address.as_bytes();
        topo.add_peer(build_test_identity(0x01));
        // Adding again should not overwrite
        topo.add_peer(build_test_identity(0x01));
        assert_eq!(topo.peers.len(), 1);
        assert!(topo.get_peer(&addr).is_some());
    }

    #[test]
    fn load_and_unload_moon_roundtrips() {
        let mut topo = Topology::new();
        topo.load_planet(stub_world());
        let planet_roots = topo.roots.len();

        let moon_root = build_test_identity(0x99);
        let moon_root_addr = *moon_root.address.as_bytes();
        let moon = signed_test_world(
            WorldType::Moon,
            0x0000_a0b1_c2d3_0099,
            2000000,
            alloc::vec![WorldRoot {
                identity: moon_root,
                endpoints: alloc::vec![InetAddress::V4 {
                    ip: [10, 0, 0, 9],
                    port: 9993,
                }],
            }],
        );

        topo.load_moon(moon).unwrap();
        assert_eq!(topo.moons.len(), 1);
        assert_eq!(topo.roots.len(), planet_roots + 1);
        assert!(topo.roots.contains(&moon_root_addr));

        assert!(topo.unload_moon(0x0000_a0b1_c2d3_0099));
        assert_eq!(topo.moons.len(), 0);
        assert_eq!(topo.roots.len(), planet_roots);
        assert!(!topo.roots.contains(&moon_root_addr));
        // Peer entry survives unload; only root status is dropped.
        assert!(topo.get_peer(&moon_root_addr).is_some());

        // Unknown moon IDs report false.
        assert!(!topo.unload_moon(0xdead_beef));
    }
}
