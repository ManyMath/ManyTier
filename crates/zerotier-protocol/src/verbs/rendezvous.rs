/// RENDEZVOUS verb codec (verb 0x05).
///
use crate::error::ProtocolError;
use crate::inet_address::InetAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousPayload {
    pub flags: u8,
    pub peer_address: [u8; 5],
    pub address: InetAddress,
}

impl RendezvousPayload {
    /// Serialize into buffer. Returns bytes written.
    ///
    /// Layout (ZeroTierOne node/Packet.hpp, VERB_RENDEZVOUS):
    /// `[1] flags, [5] peer address, [2] port, [1] address length (4 or 16),
    /// [...] address`. A null address is encoded with port 0 and length 0.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = self.flags;
        buf[1..6].copy_from_slice(&self.peer_address);
        match &self.address {
            InetAddress::V4 { ip, port } => {
                buf[6..8].copy_from_slice(&port.to_be_bytes());
                buf[8] = 4;
                buf[9..13].copy_from_slice(ip);
                13
            }
            InetAddress::V6 { ip, port } => {
                buf[6..8].copy_from_slice(&port.to_be_bytes());
                buf[8] = 16;
                buf[9..25].copy_from_slice(ip);
                25
            }
            InetAddress::Null => {
                buf[6..8].copy_from_slice(&0u16.to_be_bytes());
                buf[8] = 0;
                9
            }
        }
    }

    /// Deserialize from wire bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 9 {
            return Err(ProtocolError::TooShort {
                need: 9,
                got: data.len(),
            });
        }
        let flags = data[0];
        let mut peer_address = [0u8; 5];
        peer_address.copy_from_slice(&data[1..6]);
        let port = u16::from_be_bytes([data[6], data[7]]);
        let addr_len = data[8] as usize;

        if data.len() < 9 + addr_len {
            return Err(ProtocolError::TooShort {
                need: 9 + addr_len,
                got: data.len(),
            });
        }

        let address = match addr_len {
            4 => {
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&data[9..13]);
                InetAddress::V4 { ip, port }
            }
            16 => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&data[9..25]);
                InetAddress::V6 { ip, port }
            }
            0 => InetAddress::Null,
            _ => return Err(ProtocolError::InvalidPacket),
        };

        Ok(RendezvousPayload {
            flags,
            peer_address,
            address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendezvous_v4_roundtrip() {
        let payload = RendezvousPayload {
            flags: 0x00,
            peer_address: [0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            address: InetAddress::V4 {
                ip: [192, 168, 1, 1],
                port: 9993,
            },
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 13);
        let parsed = RendezvousPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn rendezvous_v6_roundtrip() {
        let payload = RendezvousPayload {
            flags: 0x01,
            peer_address: [0x01, 0x02, 0x03, 0x04, 0x05],
            address: InetAddress::V6 {
                ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                port: 443,
            },
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 25);
        let parsed = RendezvousPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    /// Byte layout from ZeroTierOne node/Packet.hpp (VERB_RENDEZVOUS) and
    /// node/IncomingPacket.cpp `_doRENDEZVOUS`: the port precedes the address
    /// length, which is 4 or 16 (no address type byte).
    #[test]
    fn rendezvous_matches_upstream_byte_layout() {
        let upstream: [u8; 13] = [
            0x00, // flags
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, // peer
            0x27, 0x09, // port 9993
            0x04, // IPv4
            203, 0, 113, 7, // address
        ];
        let parsed = RendezvousPayload::deserialize(&upstream).unwrap();
        assert_eq!(parsed.peer_address, [0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        assert_eq!(
            parsed.address,
            InetAddress::V4 {
                ip: [203, 0, 113, 7],
                port: 9993,
            }
        );
        let mut buf = [0u8; 32];
        let n = parsed.serialize(&mut buf);
        assert_eq!(&buf[..n], &upstream[..]);
    }

    #[test]
    fn rendezvous_too_short() {
        assert!(RendezvousPayload::deserialize(&[0; 8]).is_err());
    }

    #[test]
    fn rendezvous_invalid_addr_len() {
        // Header-length bytes present, but addr_len (byte 8) is neither 0, 4, nor 16.
        let mut data = [0u8; 26];
        data[8] = 12;
        assert!(matches!(
            RendezvousPayload::deserialize(&data),
            Err(ProtocolError::InvalidPacket)
        ));
    }

    #[test]
    fn rendezvous_addr_len_exceeds_available_bytes() {
        // addr_len claims a V4 address (4 bytes) follows, but only 2 bytes remain.
        let mut data = [0u8; 11];
        data[8] = 4;
        assert!(matches!(
            RendezvousPayload::deserialize(&data),
            Err(ProtocolError::TooShort { need: 13, got: 11 })
        ));
    }
}
