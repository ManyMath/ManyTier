// World (Planet/Moon) binary format parser.
/// Binary format:
use alloc::vec::Vec;
use zerotier_crypto::identity::Identity;

use crate::constants::*;
use crate::error::ProtocolError;
use crate::identity_wire;
use crate::inet_address::InetAddress;

/// Sentinels that ZeroTier One wraps around the world body when signing it
/// (`World::serialize(b, forSign = true)`, node/World.hpp). They are not part
/// of the stored or transmitted format.
pub const WORLD_START_SENTINEL: [u8; 8] = [0x7f; 8];

pub const WORLD_END_SENTINEL: [u8; 8] = [0xf7; 8];

/// Minimum world binary size: 1 (type) + 8 (id) + 8 (ts) + 64 (signing key) + 96 (sig) + 1 (root count) = 178.
const WORLD_MIN_SIZE: usize = 178;

/// Default planet binary extracted from official ZeroTier installation.
/// Contains the official ZeroTier root server identities and endpoints.
/// Override at runtime via config file or CLI flag.
pub const DEFAULT_PLANET: &[u8] = include_bytes!("../../../tests/fixtures/planet.bin");

/// World type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorldType {
    /// Null/unknown world type.
    Null,
    /// Planet: global root server definition.
    Planet,
    /// Moon: custom root server definition.
    Moon,
}

impl WorldType {
    /// Convert a wire byte to a WorldType.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(WorldType::Null),
            1 => Some(WorldType::Planet),
            127 => Some(WorldType::Moon),
            _ => None,
        }
    }

    /// Convert to wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            WorldType::Null => 0,
            WorldType::Planet => 1,
            WorldType::Moon => 127,
        }
    }
}

/// A root server entry in a world definition.
#[derive(Debug)]
pub struct WorldRoot {
    pub identity: Identity,
    pub endpoints: Vec<InetAddress>,
}

/// A world definition (planet or moon).
#[derive(Debug)]
pub struct World {
    pub world_type: WorldType,
    /// Unique world identifier.
    pub id: u64,
    pub timestamp: u64,
    pub signing_key: [u8; 64],
    pub signature: [u8; 96],
    /// Root servers in this world.
    pub roots: Vec<WorldRoot>,
    /// Optional dictionary data (Moon-only, for future use).
    pub dict_data: Option<Vec<u8>>,
}

impl World {
    /// Deserialize a world definition from binary format.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        // Earlier ManyTier releases stored worlds wrapped in the signing
        // sentinels. Those files (including moons already deployed) stay
        // loadable: strip the wrapper and parse the upstream body.
        let body = if data.len() >= 16
            && data[0..8] == WORLD_START_SENTINEL
            && data[data.len() - 8..] == WORLD_END_SENTINEL
        {
            &data[8..data.len() - 8]
        } else {
            data
        };
        Self::deserialize_prefix(body).map(|(world, _)| world)
    }

    /// Parse one world from the start of `body`, which may hold more data
    /// after it (worlds travel back to back in OK(HELLO)). Returns the world
    /// and the number of bytes it occupied.
    pub fn deserialize_prefix(body: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if body.len() < WORLD_MIN_SIZE {
            return Err(ProtocolError::TooShort {
                need: WORLD_MIN_SIZE,
                got: body.len(),
            });
        }

        // Parse type
        let world_type = WorldType::from_byte(body[0]).ok_or(ProtocolError::InvalidPacket)?;

        // Parse world ID (u64 BE)
        let id = u64::from_be_bytes([
            body[1], body[2], body[3], body[4], body[5], body[6], body[7], body[8],
        ]);

        // Parse timestamp (u64 BE)
        let timestamp = u64::from_be_bytes([
            body[9], body[10], body[11], body[12], body[13], body[14], body[15], body[16],
        ]);

        // Copy signing key (64 bytes at offset 17)
        let mut signing_key = [0u8; 64];
        signing_key.copy_from_slice(&body[17..81]);

        // Copy signature (96 bytes at offset 81)
        let mut signature = [0u8; 96];
        signature.copy_from_slice(&body[81..177]);

        // Parse root count
        let root_count = body[177] as usize;
        if root_count > WORLD_MAX_ROOTS {
            return Err(ProtocolError::InvalidPacket);
        }

        let mut pos = 178;
        let end_pos = body.len();

        let mut roots = Vec::with_capacity(root_count);
        for _ in 0..root_count {
            if pos >= end_pos {
                return Err(ProtocolError::TooShort {
                    need: pos + 1,
                    got: end_pos,
                });
            }

            // Deserialize identity
            let (identity, id_consumed) = identity_wire::deserialize_identity(&body[pos..])?;
            pos += id_consumed;

            if pos >= end_pos {
                return Err(ProtocolError::TooShort {
                    need: pos + 1,
                    got: end_pos,
                });
            }

            // Endpoint count
            let ep_count = body[pos] as usize;
            if ep_count > WORLD_MAX_ENDPOINTS_PER_ROOT {
                return Err(ProtocolError::InvalidPacket);
            }
            pos += 1;

            let mut endpoints = Vec::with_capacity(ep_count);
            for _ in 0..ep_count {
                if pos >= end_pos {
                    return Err(ProtocolError::TooShort {
                        need: pos + 1,
                        got: end_pos,
                    });
                }
                let (addr, addr_consumed) = InetAddress::deserialize(&body[pos..end_pos])?;
                endpoints.push(addr);
                pos += addr_consumed;
            }

            roots.push(WorldRoot {
                identity,
                endpoints,
            });
        }

        // Moon dict_data
        let dict_data = if world_type == WorldType::Moon {
            if pos + 2 > end_pos {
                return Err(ProtocolError::TooShort {
                    need: pos + 2,
                    got: end_pos,
                });
            }
            let dict_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2;
            if pos + dict_len > end_pos {
                return Err(ProtocolError::TooShort {
                    need: pos + dict_len,
                    got: end_pos,
                });
            }
            let dict = body[pos..pos + dict_len].to_vec();
            pos += dict_len;
            Some(dict)
        } else {
            None
        };

        Ok((
            World {
                world_type,
                id,
                timestamp,
                signing_key,
                signature,
                roots,
                dict_data,
            },
            pos,
        ))
    }

    /// Serialize this world definition to binary format.
    ///
    /// Returns the number of bytes written, or an error if the buffer is too small.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ProtocolError> {
        let mut pos = 0;

        // Type
        buf[pos] = self.world_type.to_byte();
        pos += 1;

        // World ID
        buf[pos..pos + 8].copy_from_slice(&self.id.to_be_bytes());
        pos += 8;

        // Timestamp
        buf[pos..pos + 8].copy_from_slice(&self.timestamp.to_be_bytes());
        pos += 8;

        // Signing key
        buf[pos..pos + 64].copy_from_slice(&self.signing_key);
        pos += 64;

        // Signature
        buf[pos..pos + 96].copy_from_slice(&self.signature);
        pos += 96;

        // Root count
        buf[pos] = self.roots.len() as u8;
        pos += 1;

        // Roots
        for root in &self.roots {
            let id_written =
                identity_wire::serialize_identity_public(&root.identity, &mut buf[pos..]);
            pos += id_written;

            buf[pos] = root.endpoints.len() as u8;
            pos += 1;

            for ep in &root.endpoints {
                let ep_written = ep.serialize(&mut buf[pos..]);
                pos += ep_written;
            }
        }

        // Moon dict_data
        if self.world_type == WorldType::Moon {
            if let Some(ref dict) = self.dict_data {
                buf[pos..pos + 2].copy_from_slice(&(dict.len() as u16).to_be_bytes());
                pos += 2;
                buf[pos..pos + dict.len()].copy_from_slice(dict);
                pos += dict.len();
            } else {
                buf[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
                pos += 2;
            }
        }

        Ok(pos)
    }

    /// Serialize the signed portion of this world definition, exactly as
    /// ZeroTier One's `World::serialize(b, forSign = true)` does: the start
    /// sentinel, then type + id + timestamp + signing_key + roots (no
    /// signature), then the end sentinel. Returns the number of bytes written.
    pub fn signed_portion(&self, buf: &mut [u8]) -> usize {
        buf[0..8].copy_from_slice(&WORLD_START_SENTINEL);
        let body_len = self.signed_body(&mut buf[8..]);
        let mut pos = 8 + body_len;
        buf[pos..pos + 8].copy_from_slice(&WORLD_END_SENTINEL);
        pos += 8;
        pos
    }

    /// The signed body without the sentinels. This is what ManyTier releases
    /// before the upstream-compatible format signed; it is still accepted by
    /// [`World::verify_signature`] so moons generated by those releases keep
    /// verifying.
    fn signed_body(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;

        // Type
        buf[pos] = self.world_type.to_byte();
        pos += 1;

        // World ID
        buf[pos..pos + 8].copy_from_slice(&self.id.to_be_bytes());
        pos += 8;

        // Timestamp
        buf[pos..pos + 8].copy_from_slice(&self.timestamp.to_be_bytes());
        pos += 8;

        // Signing key
        buf[pos..pos + 64].copy_from_slice(&self.signing_key);
        pos += 64;

        // Root count
        buf[pos] = self.roots.len() as u8;
        pos += 1;

        // Roots
        for root in &self.roots {
            let id_written =
                identity_wire::serialize_identity_public(&root.identity, &mut buf[pos..]);
            pos += id_written;

            buf[pos] = root.endpoints.len() as u8;
            pos += 1;

            for ep in &root.endpoints {
                let ep_written = ep.serialize(&mut buf[pos..]);
                pos += ep_written;
            }
        }

        // Moon dict_data in signed portion
        if self.world_type == WorldType::Moon {
            if let Some(ref dict) = self.dict_data {
                buf[pos..pos + 2].copy_from_slice(&(dict.len() as u16).to_be_bytes());
                pos += 2;
                buf[pos..pos + dict.len()].copy_from_slice(dict);
                pos += dict.len();
            } else {
                buf[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
                pos += 2;
            }
        }

        pos
    }

    /// Verify this world's signature against the Ed25519 verifying key it
    /// embeds in `signing_key[32..64]`.
    ///
    /// This proves the world file is internally self-consistent (the
    /// signature matches the embedded signing key over the signed portion)
    /// and hasn't been corrupted or substituted in transit: it does not by
    /// itself prove the embedded key is one the operator has chosen to trust
    /// (that requires out-of-band key pinning, which is a separate concern).
    pub fn verify_signature(&self) -> Result<(), ProtocolError> {
        self.verify_signed_by(&self.signing_key)
    }

    /// Whether this world may replace `current`: same type and ID, newer,
    /// and signed by the key `current` names for its successors
    /// (ZeroTierOne World::shouldBeReplacedBy).
    pub fn is_valid_update_of(&self, current: &World) -> bool {
        self.world_type == current.world_type
            && self.id == current.id
            && self.timestamp > current.timestamp
            && self.verify_signed_by(&current.signing_key).is_ok()
    }

    /// Verify the signature against a C25519 public key pair, whose
    /// Ed25519 half is the last 32 bytes.
    pub fn verify_signed_by(&self, signing_key: &[u8; 64]) -> Result<(), ProtocolError> {
        let verifying_key_bytes: [u8; 32] = signing_key[32..64]
            .try_into()
            .map_err(|_| ProtocolError::InvalidPacket)?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&verifying_key_bytes)
            .map_err(|_| ProtocolError::InvalidPacket)?;
        let mut buf = [0u8; 4096];
        let len = self.signed_portion(&mut buf);
        if zerotier_crypto::signing::verify(&verifying_key, &buf[..len], &self.signature).is_ok() {
            return Ok(());
        }
        // Legacy ManyTier signature over the body alone.
        let len = self.signed_body(&mut buf);
        zerotier_crypto::signing::verify(&verifying_key, &buf[..len], &self.signature)
            .map_err(ProtocolError::CryptoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use zerotier_crypto::identity::{Address, PublicKey};

    fn fixture_identity(addr_byte: u8) -> Identity {
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

    fn new_test_world(world_type: WorldType, root_count: usize, ep_count: usize) -> World {
        let mut roots = Vec::new();
        for i in 0..root_count {
            let identity = fixture_identity(0xe0 + i as u8);
            let mut endpoints = Vec::new();
            for j in 0..ep_count {
                endpoints.push(InetAddress::V4 {
                    ip: [192, 168, i as u8, j as u8],
                    port: 9993,
                });
            }
            roots.push(WorldRoot {
                identity,
                endpoints,
            });
        }

        World {
            world_type,
            id: 149604618,
            timestamp: 1000000,
            signing_key: [0xAA; 64],
            signature: [0xBB; 96],
            roots,
            dict_data: None,
        }
    }

    /// Files written by earlier ManyTier releases carry the signing
    /// sentinels around the body; they must keep loading.
    #[test]
    fn deserialize_accepts_legacy_sentinel_wrapped_world() {
        let world = new_test_world(WorldType::Moon, 1, 1);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(&WORLD_START_SENTINEL);
        wrapped.extend_from_slice(&buf[..n]);
        wrapped.extend_from_slice(&WORLD_END_SENTINEL);
        let parsed = World::deserialize(&wrapped).unwrap();
        assert_eq!(parsed.id, world.id);
        assert_eq!(parsed.roots.len(), 1);
    }

    /// The stored/wire format has no sentinels (ZeroTier One
    /// `World::serialize(b, false)`), so serialized output starts with the
    /// type byte and ends with the last root (or the moon dictionary length).
    #[test]
    fn serialize_emits_upstream_layout_without_sentinels() {
        let world = new_test_world(WorldType::Planet, 1, 1);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        assert_eq!(buf[0], WORLD_TYPE_PLANET);
        assert_ne!(&buf[..8], &WORLD_START_SENTINEL);
        assert_ne!(&buf[n - 8..n], &WORLD_END_SENTINEL);
        assert_eq!(&buf[1..9], &world.id.to_be_bytes());
    }

    #[test]
    fn deserialize_type_planet() {
        let world = new_test_world(WorldType::Planet, 0, 0);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.world_type, WorldType::Planet);
    }

    #[test]
    fn deserialize_type_moon() {
        let mut world = new_test_world(WorldType::Moon, 0, 0);
        world.dict_data = Some(vec![]);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.world_type, WorldType::Moon);
    }

    #[test]
    fn roundtrip_planet_2_roots_2_endpoints() {
        let world = new_test_world(WorldType::Planet, 2, 2);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();

        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.world_type, world.world_type);
        assert_eq!(parsed.id, world.id);
        assert_eq!(parsed.timestamp, world.timestamp);
        assert_eq!(parsed.signing_key, world.signing_key);
        assert_eq!(parsed.signature, world.signature);
        assert_eq!(parsed.roots.len(), 2);
        for (orig, parsed_root) in world.roots.iter().zip(parsed.roots.iter()) {
            assert_eq!(orig.identity.address, parsed_root.identity.address);
            assert_eq!(orig.identity.public_key, parsed_root.identity.public_key);
            assert_eq!(orig.endpoints, parsed_root.endpoints);
        }
        assert!(parsed.dict_data.is_none());

        // Byte-for-byte round-trip
        let mut buf2 = [0u8; 2048];
        let n2 = parsed.serialize(&mut buf2).unwrap();
        assert_eq!(n, n2);
        assert_eq!(&buf[..n], &buf2[..n2]);
    }

    #[test]
    fn roundtrip_zero_roots() {
        let world = new_test_world(WorldType::Planet, 0, 0);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.roots.len(), 0);
    }

    #[test]
    fn roundtrip_moon_with_dict_data() {
        let mut world = new_test_world(WorldType::Moon, 1, 1);
        world.dict_data = Some(vec![0x01, 0x02, 0x03, 0x04]);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();

        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.world_type, WorldType::Moon);
        assert_eq!(parsed.dict_data, Some(vec![0x01, 0x02, 0x03, 0x04]));

        // Byte-for-byte round-trip
        let mut buf2 = [0u8; 2048];
        let n2 = parsed.serialize(&mut buf2).unwrap();
        assert_eq!(n, n2);
        assert_eq!(&buf[..n], &buf2[..n2]);
    }

    #[test]
    fn root_identity_parseable() {
        let world = new_test_world(WorldType::Planet, 1, 1);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        let parsed = World::deserialize(&buf[..n]).unwrap();
        // Identity was successfully parsed via identity_wire::deserialize_identity
        assert_eq!(
            parsed.roots[0].identity.address,
            world.roots[0].identity.address
        );
        assert_eq!(
            parsed.roots[0].identity.public_key,
            world.roots[0].identity.public_key
        );
    }

    #[test]
    fn root_endpoints_parseable() {
        let world = new_test_world(WorldType::Planet, 1, 2);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.roots[0].endpoints.len(), 2);
        assert_eq!(parsed.roots[0].endpoints, world.roots[0].endpoints);
    }

    #[test]
    fn default_planet_parses() {
        let world = World::deserialize(DEFAULT_PLANET).expect("default planet should parse");
        assert_eq!(world.world_type, WorldType::Planet);
        assert_eq!(world.id, WORLD_ID_EARTH); // 149604618
        assert!(
            !world.roots.is_empty(),
            "planet must have at least one root"
        );
        for root in &world.roots {
            assert!(!root.endpoints.is_empty(), "each root must have endpoints");
        }
    }

    /// The official planet is signed by the key it embeds
    /// (`attic/world/mkworld.cpp` signs with the same C25519 pair it writes
    /// into `_updatesMustBeSignedBy`), over the sentinel-wrapped body.
    #[test]
    fn default_planet_signature_verifies() {
        let world = World::deserialize(DEFAULT_PLANET).unwrap();
        assert!(world.verify_signature().is_ok());
    }

    /// The bundled fixture is the raw upstream `planet` file.
    #[test]
    fn default_planet_is_in_upstream_layout() {
        assert_eq!(DEFAULT_PLANET[0], WORLD_TYPE_PLANET);
        assert_ne!(&DEFAULT_PLANET[..8], &WORLD_START_SENTINEL);
    }

    #[test]
    fn default_planet_has_4_roots() {
        let world = World::deserialize(DEFAULT_PLANET).unwrap();
        assert_eq!(world.roots.len(), 4);
    }

    #[test]
    fn too_short_data_returns_err() {
        let data = [0u8; 10];
        assert!(World::deserialize(&data).is_err());
    }

    #[test]
    fn world_type_from_byte() {
        assert_eq!(WorldType::from_byte(0), Some(WorldType::Null));
        assert_eq!(WorldType::from_byte(1), Some(WorldType::Planet));
        assert_eq!(WorldType::from_byte(127), Some(WorldType::Moon));
        assert_eq!(WorldType::from_byte(2), None);
        assert_eq!(WorldType::from_byte(255), None);
    }

    #[test]
    fn world_type_to_byte() {
        assert_eq!(WorldType::Null.to_byte(), 0);
        assert_eq!(WorldType::Planet.to_byte(), 1);
        assert_eq!(WorldType::Moon.to_byte(), 127);
    }

    #[test]
    fn signed_portion_wraps_body_in_sentinels_and_omits_signature() {
        let world = new_test_world(WorldType::Planet, 1, 1);
        let mut buf = [0u8; 2048];
        let n = world.signed_portion(&mut buf);
        assert_eq!(&buf[..8], &WORLD_START_SENTINEL);
        assert_eq!(buf[8], WORLD_TYPE_PLANET);
        assert_eq!(&buf[n - 8..n], &WORLD_END_SENTINEL);
        // type(1) + id(8) + ts(8) + signing_key(64) + root_count(1) + root data, no signature
        let mut serialized = [0u8; 2048];
        let serialized_len = world.serialize(&mut serialized).unwrap();
        assert_eq!(n, serialized_len - 96 + 16);
    }
}
