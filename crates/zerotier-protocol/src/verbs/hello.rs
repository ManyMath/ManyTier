// HELLO verb payload codec.

use crate::error::ProtocolError;
use crate::identity_wire;
use crate::inet_address::InetAddress;
use alloc::vec::Vec;
use zerotier_crypto::identity::Identity;

pub const MANYTIER_ADVERTISED_PROTOCOL_VERSION: u8 = 11;

const MANYTIER_MAJOR: u8 = 1;
const MANYTIER_MINOR: u8 = 14;
const MANYTIER_REVISION: u16 = 2;

#[derive(Debug)]
pub struct HelloPayload {
    pub protocol_version: u8,
    pub major_version: u8,
    pub minor_version: u8,
    pub revision: u16,
    pub timestamp: u64,
    pub identity: Identity,
    pub dest_address: InetAddress,
    pub planet_world_id: u64,
    pub planet_world_timestamp: u64,
}

/// One entry of the world list a HELLO ends with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloWorld {
    pub world_type: u8,
    pub id: u64,
    pub timestamp: u64,
}

/// Serialize the world list that follows the planet timestamp in a HELLO:
/// a u16 count, then per world [1] type [8] id [8] timestamp (ZeroTierOne
/// node/Peer.cpp `sendHELLO`). On the wire this section is encrypted with
/// `Packet::cryptField`; this works on the plaintext. Returns bytes written.
pub fn serialize_hello_worlds(worlds: &[HelloWorld], buf: &mut [u8]) -> usize {
    buf[0..2].copy_from_slice(&(worlds.len() as u16).to_be_bytes());
    let mut pos = 2;
    for world in worlds {
        buf[pos] = world.world_type;
        buf[pos + 1..pos + 9].copy_from_slice(&world.id.to_be_bytes());
        buf[pos + 9..pos + 17].copy_from_slice(&world.timestamp.to_be_bytes());
        pos += 17;
    }
    pos
}

/// Parse a decrypted HELLO world list, stopping at the first truncated
/// entry as upstream's bounds-checked reads would.
pub fn deserialize_hello_worlds(data: &[u8]) -> Vec<HelloWorld> {
    let Some(count) = data.get(..2).map(|c| u16::from_be_bytes([c[0], c[1]])) else {
        return Vec::new();
    };
    data[2..]
        .chunks_exact(17)
        .take(count as usize)
        .map(|entry| HelloWorld {
            world_type: entry[0],
            id: u64::from_be_bytes(entry[1..9].try_into().unwrap_or([0; 8])),
            timestamp: u64::from_be_bytes(entry[9..17].try_into().unwrap_or([0; 8])),
        })
        .collect()
}

impl HelloPayload {
    /// Create a new HELLO payload with ManyTier defaults.
    pub fn new(identity: Identity, timestamp: u64, dest_address: InetAddress) -> Self {
        Self {
            // See ZeroTierOne 1.14.2 node/Peer.hpp:618-619.
            // Upstream enables AES_GMAC_SIV at remote protocol version >= 12.
            // ManyTier does not implement cipher suite 3 yet, so it must not
            // advertise protocol 12 capability on the wire.
            protocol_version: MANYTIER_ADVERTISED_PROTOCOL_VERSION,
            major_version: MANYTIER_MAJOR,
            minor_version: MANYTIER_MINOR,
            revision: MANYTIER_REVISION,
            timestamp,
            identity,
            dest_address,
            planet_world_id: crate::constants::WORLD_ID_EARTH,
            planet_world_timestamp: 0,
        }
    }

    /// Serialize this HELLO payload into the given buffer.
    /// Returns the number of bytes written on success.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ProtocolError> {
        // Minimum: 5 (fixed header) + 8 (timestamp) + 71 (identity) + 1 (null addr) + 16 (planet) = 101
        let mut pos = 0;

        if buf.len() < 5 + 8 {
            return Err(ProtocolError::TooShort {
                need: 13,
                got: buf.len(),
            });
        }

        buf[pos] = self.protocol_version;
        pos += 1;
        buf[pos] = self.major_version;
        pos += 1;
        buf[pos] = self.minor_version;
        pos += 1;
        buf[pos..pos + 2].copy_from_slice(&self.revision.to_be_bytes());
        pos += 2;
        buf[pos..pos + 8].copy_from_slice(&self.timestamp.to_be_bytes());
        pos += 8;

        // Identity
        let id_len = identity_wire::serialize_identity_public(&self.identity, &mut buf[pos..]);
        pos += id_len;

        // Destination address
        let addr_len = self.dest_address.serialize(&mut buf[pos..]);
        pos += addr_len;

        // Planet world info
        buf[pos..pos + 8].copy_from_slice(&self.planet_world_id.to_be_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.planet_world_timestamp.to_be_bytes());
        pos += 8;

        Ok(pos)
    }

    /// Deserialize a HELLO payload from a byte slice (after the verb byte).
    /// Returns the payload and the number of bytes consumed, which is where
    /// the encrypted world list (see [`deserialize_hello_worlds`]) starts.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if data.len() < 13 {
            return Err(ProtocolError::TooShort {
                need: 13,
                got: data.len(),
            });
        }

        let mut pos = 0;

        let protocol_version = data[pos];
        pos += 1;
        let major_version = data[pos];
        pos += 1;
        let minor_version = data[pos];
        pos += 1;
        let revision = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let timestamp = u64::from_be_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]);
        pos += 8;

        // Identity
        let (identity, id_consumed) = identity_wire::deserialize_identity(&data[pos..])?;
        pos += id_consumed;

        // Destination address
        let (dest_address, addr_consumed) = InetAddress::deserialize(&data[pos..])?;
        pos += addr_consumed;

        // Planet world info (16 bytes)
        if data.len() < pos + 16 {
            return Err(ProtocolError::TooShort {
                need: pos + 16,
                got: data.len(),
            });
        }
        let planet_world_id = u64::from_be_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]);
        pos += 8;
        let planet_world_timestamp = u64::from_be_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]);
        pos += 8;

        Ok((
            Self {
                protocol_version,
                major_version,
                minor_version,
                revision,
                timestamp,
                identity,
                dest_address,
                planet_world_id,
                planet_world_timestamp,
            },
            pos,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerotier_crypto::identity::{Address, PublicKey};

    fn build_test_identity() -> Identity {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0xe4]).unwrap();
        let mut pk_bytes = [0u8; 64];
        for (i, b) in pk_bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let public_key = PublicKey::from_bytes(&pk_bytes).unwrap();
        Identity {
            address,
            public_key,
            secret: None,
        }
    }

    #[test]
    fn hello_roundtrip() {
        let id = build_test_identity();
        let payload = HelloPayload::new(id, 1234567890123, InetAddress::Null);

        let mut buf = [0u8; 512];
        let n = payload.serialize(&mut buf).unwrap();

        let (parsed, consumed) = HelloPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(consumed, n);
        assert_eq!(parsed.protocol_version, payload.protocol_version);
        assert_eq!(parsed.major_version, payload.major_version);
        assert_eq!(parsed.minor_version, payload.minor_version);
        assert_eq!(parsed.revision, payload.revision);
        assert_eq!(parsed.timestamp, payload.timestamp);
        assert_eq!(parsed.identity.address, payload.identity.address);
        assert_eq!(parsed.identity.public_key, payload.identity.public_key);
        assert_eq!(parsed.dest_address, payload.dest_address);
        assert_eq!(parsed.planet_world_id, payload.planet_world_id);
        assert_eq!(
            parsed.planet_world_timestamp,
            payload.planet_world_timestamp
        );
    }

    #[test]
    fn hello_wire_layout() {
        let id = build_test_identity();
        let mut payload = HelloPayload::new(id, 0x0000_0123_4567_89AB, InetAddress::Null);
        payload.protocol_version = 13;
        payload.major_version = 1;
        payload.minor_version = 2;
        payload.revision = 3;

        let mut buf = [0u8; 512];
        let _n = payload.serialize(&mut buf).unwrap();

        // Check fixed header layout
        assert_eq!(buf[0], 13); // protocol_version at byte 0
        assert_eq!(buf[1], 1); // major_version at byte 1
        assert_eq!(buf[2], 2); // minor_version at byte 2
        assert_eq!(buf[3], 0x00); // revision high byte at byte 3
        assert_eq!(buf[4], 0x03); // revision low byte at byte 4
                                  // timestamp at bytes 5..13
        assert_eq!(
            u64::from_be_bytes([buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12]]),
            0x0000_0123_4567_89AB
        );
        // identity starts at byte 13
        assert_eq!(&buf[13..18], &[0xa0, 0xb1, 0xc2, 0xd3, 0xe4]); // address
    }

    /// The cleartext part ends at the planet timestamp; the world list
    /// after it is encrypted on the wire and not part of this codec.
    #[test]
    fn hello_deserialize_stops_before_the_world_list() {
        let id = build_test_identity();
        let payload = HelloPayload::new(id, 1000, InetAddress::Null);

        let mut buf = [0u8; 512];
        let n = payload.serialize(&mut buf).unwrap();
        let m = serialize_hello_worlds(&[], &mut buf[n..]);

        let (_, consumed) = HelloPayload::deserialize(&buf[..n + m]).unwrap();
        assert_eq!(consumed, n);
    }

    #[test]
    fn hello_with_planet() {
        let id = build_test_identity();
        let mut payload = HelloPayload::new(id, 5000, InetAddress::Null);
        payload.planet_world_id = 149604618;
        payload.planet_world_timestamp = 1567191349589;

        let mut buf = [0u8; 512];
        let n = payload.serialize(&mut buf).unwrap();

        let (parsed, _) = HelloPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.planet_world_id, 149604618);
        assert_eq!(parsed.planet_world_timestamp, 1567191349589);
    }

    #[test]
    fn hello_new_does_not_advertise_aes_gmac_siv_capability() {
        let id = build_test_identity();
        let payload = HelloPayload::new(id, 5000, InetAddress::Null);

        assert_eq!(
            payload.protocol_version,
            MANYTIER_ADVERTISED_PROTOCOL_VERSION
        );
        assert!(
            payload.protocol_version < crate::constants::ZT_PROTO_VERSION,
            "wire-advertised protocol version must stay below the AES_GMAC_SIV gate"
        );
    }

    #[test]
    fn hello_with_v4_dest() {
        let id = build_test_identity();
        let addr = InetAddress::V4 {
            ip: [192, 168, 1, 1],
            port: 9993,
        };
        let payload = HelloPayload::new(id, 5000, addr.clone());

        let mut buf = [0u8; 512];
        let n = payload.serialize(&mut buf).unwrap();

        let (parsed, _) = HelloPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.dest_address, addr);
    }

    #[test]
    fn hello_deserialize_too_short() {
        let data = [0u8; 10];
        assert!(HelloPayload::deserialize(&data).is_err());
    }

    /// Layout from ZeroTierOne node/Peer.cpp sendHELLO: u16 count, then
    /// [1] type [8] id [8] timestamp per world.
    #[test]
    fn hello_worlds_match_upstream_layout() {
        let worlds = [HelloWorld {
            world_type: crate::constants::WORLD_TYPE_MOON,
            id: 0x0000_0021_05b7_8c5f,
            timestamp: 0x0102_0304_0506_0708,
        }];
        let mut buf = [0u8; 64];
        let n = serialize_hello_worlds(&worlds, &mut buf);
        assert_eq!(
            &buf[..n],
            &[
                0x00, 0x01, 0x7f, 0x00, 0x00, 0x00, 0x21, 0x05, 0xb7, 0x8c, 0x5f, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07, 0x08,
            ]
        );
        assert_eq!(deserialize_hello_worlds(&buf[..n]), worlds);
        assert!(deserialize_hello_worlds(&buf[..n - 1]).is_empty());
    }
}
