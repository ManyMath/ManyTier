/// Multicast verb codecs: MULTICAST_LIKE (0x09), MULTICAST_GATHER (0x0d), MULTICAST_FRAME (0x0e).
///
/// MULTICAST_LIKE: repeated 18-byte tuples of (network_id, mac, adi).
/// MULTICAST_GATHER: network_id, flags, mac, adi, gather_limit, optional COM.
/// MULTICAST_FRAME: network_id, flags, conditional gather_limit/source_mac, dest_mac, adi, ethertype, payload.
extern crate alloc;

use crate::error::ProtocolError;
use crate::verbs::network_config::CertificateOfMembership;
use alloc::vec::Vec;

/// A single multicast group subscription entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastGroup {
    pub network_id: u64,
    pub mac: [u8; 6],
    pub adi: u32,
}

/// MULTICAST_LIKE payload: list of multicast group subscriptions.
///
/// Wire format: repeated 18-byte tuples (network_id:8 + mac:6 + adi:4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastLikePayload {
    pub groups: Vec<MulticastGroup>,
}

impl MulticastLikePayload {
    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        for group in &self.groups {
            buf[offset..offset + 8].copy_from_slice(&group.network_id.to_be_bytes());
            offset += 8;
            buf[offset..offset + 6].copy_from_slice(&group.mac);
            offset += 6;
            buf[offset..offset + 4].copy_from_slice(&group.adi.to_be_bytes());
            offset += 4;
        }
        offset
    }

    /// Deserialize from wire bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() % 18 != 0 {
            return Err(ProtocolError::InvalidPacket);
        }
        let count = data.len() / 18;
        let mut groups = Vec::with_capacity(count);
        let mut offset = 0;
        for _ in 0..count {
            let network_id = u64::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            offset += 8;
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&data[offset..offset + 6]);
            offset += 6;
            let adi = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            groups.push(MulticastGroup {
                network_id,
                mac,
                adi,
            });
        }
        Ok(MulticastLikePayload { groups })
    }
}

/// MULTICAST_GATHER payload.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastGatherPayload {
    pub network_id: u64,
    pub flags: u8,
    pub mac: [u8; 6],
    pub adi: u32,
    pub gather_limit: u32,
    pub com: Option<Vec<u8>>,
}

impl MulticastGatherPayload {
    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        buf[offset..offset + 8].copy_from_slice(&self.network_id.to_be_bytes());
        offset += 8;
        buf[offset] = self.flags;
        offset += 1;
        buf[offset..offset + 6].copy_from_slice(&self.mac);
        offset += 6;
        buf[offset..offset + 4].copy_from_slice(&self.adi.to_be_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.gather_limit.to_be_bytes());
        offset += 4;
        if let Some(ref com) = self.com {
            buf[offset..offset + com.len()].copy_from_slice(com);
            offset += com.len();
        }
        offset
    }

    /// Deserialize from wire bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 23 {
            return Err(ProtocolError::TooShort {
                need: 23,
                got: data.len(),
            });
        }
        let network_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let flags = data[8];
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&data[9..15]);
        let adi = u32::from_be_bytes([data[15], data[16], data[17], data[18]]);
        let gather_limit = u32::from_be_bytes([data[19], data[20], data[21], data[22]]);

        let com = if data.len() > 23 {
            Some(data[23..].to_vec())
        } else {
            None
        };

        Ok(MulticastGatherPayload {
            network_id,
            flags,
            mac,
            adi,
            gather_limit,
            com,
        })
    }
}

/// MULTICAST_FRAME payload.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastFramePayload<'a> {
    pub network_id: u64,
    pub flags: u8,
    /// A certificate of membership sent along (flag 0x01, deprecated).
    pub com: Option<CertificateOfMembership>,
    pub gather_limit: Option<u32>,
    pub source_mac: Option<[u8; 6]>,
    pub dest_mac: [u8; 6],
    pub adi: u32,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> MulticastFramePayload<'a> {
    /// Zero-copy parse from wire bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, ProtocolError> {
        if data.len() < 9 {
            return Err(ProtocolError::TooShort {
                need: 9,
                got: data.len(),
            });
        }
        let network_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let flags = data[8];
        let mut offset = 9;

        // ZeroTierOne _doMULTICAST_FRAME: the COM comes first when flagged.
        let com = if flags & 0x01 != 0 {
            let (com, used) = CertificateOfMembership::deserialize(&data[offset..])?;
            offset += used;
            Some(com)
        } else {
            None
        };

        let gather_limit = if flags & 0x02 != 0 {
            if offset + 4 > data.len() {
                return Err(ProtocolError::TooShort {
                    need: offset + 4,
                    got: data.len(),
                });
            }
            let gl = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            offset += 4;
            Some(gl)
        } else {
            None
        };

        let source_mac = if flags & 0x04 != 0 {
            if offset + 6 > data.len() {
                return Err(ProtocolError::TooShort {
                    need: offset + 6,
                    got: data.len(),
                });
            }
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&data[offset..offset + 6]);
            offset += 6;
            Some(mac)
        } else {
            None
        };

        // dest MAC + ADI + ethertype = 6 + 4 + 2 = 12
        if offset + 12 > data.len() {
            return Err(ProtocolError::TooShort {
                need: offset + 12,
                got: data.len(),
            });
        }
        let mut dest_mac = [0u8; 6];
        dest_mac.copy_from_slice(&data[offset..offset + 6]);
        offset += 6;
        let adi = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        let ethertype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let payload = &data[offset..];

        Ok(MulticastFramePayload {
            network_id,
            flags,
            com,
            gather_limit,
            source_mac,
            dest_mac,
            adi,
            ethertype,
            payload,
        })
    }

    /// Serialize into buffer, copying payload. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        buf[offset..offset + 8].copy_from_slice(&self.network_id.to_be_bytes());
        offset += 8;
        buf[offset] = self.flags & !0x01;
        offset += 1;

        if let Some(com) = &self.com {
            buf[8] |= 0x01;
            offset += com.serialize(&mut buf[offset..]);
        }
        if let Some(gl) = self.gather_limit {
            buf[offset..offset + 4].copy_from_slice(&gl.to_be_bytes());
            offset += 4;
        }
        if let Some(ref mac) = self.source_mac {
            buf[offset..offset + 6].copy_from_slice(mac);
            offset += 6;
        }

        buf[offset..offset + 6].copy_from_slice(&self.dest_mac);
        offset += 6;
        buf[offset..offset + 4].copy_from_slice(&self.adi.to_be_bytes());
        offset += 4;
        buf[offset..offset + 2].copy_from_slice(&self.ethertype.to_be_bytes());
        offset += 2;

        let plen = self.payload.len();
        buf[offset..offset + plen].copy_from_slice(self.payload);
        offset + plen
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn multicast_like_three_groups() {
        let payload = MulticastLikePayload {
            groups: vec![
                MulticastGroup {
                    network_id: 0x1234567890abcdef,
                    mac: [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01],
                    adi: 100,
                },
                MulticastGroup {
                    network_id: 0xfedcba0987654321,
                    mac: [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
                    adi: 200,
                },
                MulticastGroup {
                    network_id: 1,
                    mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                    adi: 0,
                },
            ],
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 54); // 3 * 18
        let parsed = MulticastLikePayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn multicast_like_empty() {
        let payload = MulticastLikePayload { groups: vec![] };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 0);
        let parsed = MulticastLikePayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.groups.len(), 0);
    }

    #[test]
    fn multicast_like_invalid_length() {
        assert!(MulticastLikePayload::deserialize(&[0; 10]).is_err());
    }

    #[test]
    fn multicast_gather_without_com() {
        let payload = MulticastGatherPayload {
            network_id: 0x1234567890abcdef,
            flags: 0,
            mac: [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01],
            adi: 42,
            gather_limit: 100,
            com: None,
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 23);
        let parsed = MulticastGatherPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn multicast_gather_with_com() {
        let com_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let payload = MulticastGatherPayload {
            network_id: 0xaabbccdd11223344,
            flags: 0x01,
            mac: [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
            adi: 1000,
            gather_limit: 50,
            com: Some(com_data),
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 28); // 23 + 5
        let parsed = MulticastGatherPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn multicast_gather_too_short() {
        assert!(MulticastGatherPayload::deserialize(&[0; 22]).is_err());
    }

    #[test]
    fn multicast_frame_no_optional_fields() {
        let data = [0xCC; 20];
        let payload = MulticastFramePayload {
            network_id: 0x1234567890abcdef,
            flags: 0x00,
            com: None,
            gather_limit: None,
            source_mac: None,
            dest_mac: [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01],
            adi: 42,
            ethertype: 0x0800,
            payload: &data,
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        // 8 + 1 + 6 + 4 + 2 + 20 = 41
        assert_eq!(n, 41);
        let parsed = MulticastFramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.network_id, payload.network_id);
        assert_eq!(parsed.flags, 0x00);
        assert!(parsed.gather_limit.is_none());
        assert!(parsed.source_mac.is_none());
        assert_eq!(parsed.dest_mac, payload.dest_mac);
        assert_eq!(parsed.adi, 42);
        assert_eq!(parsed.ethertype, 0x0800);
        assert_eq!(parsed.payload, &data[..]);
    }

    #[test]
    fn multicast_frame_with_gather_limit() {
        let data = [0xDD; 10];
        let payload = MulticastFramePayload {
            network_id: 1,
            flags: 0x02,
            com: None,
            gather_limit: Some(256),
            source_mac: None,
            dest_mac: [0xff; 6],
            adi: 0,
            ethertype: 0x0806,
            payload: &data,
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        // 8 + 1 + 4 + 6 + 4 + 2 + 10 = 35
        assert_eq!(n, 35);
        let parsed = MulticastFramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.gather_limit, Some(256));
        assert!(parsed.source_mac.is_none());
    }

    #[test]
    fn multicast_frame_with_source_mac() {
        let data = [0xEE; 5];
        let payload = MulticastFramePayload {
            network_id: 1,
            flags: 0x04,
            com: None,
            gather_limit: None,
            source_mac: Some([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
            dest_mac: [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01],
            adi: 77,
            ethertype: 0x0800,
            payload: &data,
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        // 8 + 1 + 6 + 6 + 4 + 2 + 5 = 32
        assert_eq!(n, 32);
        let parsed = MulticastFramePayload::parse(&buf[..n]).unwrap();
        assert!(parsed.gather_limit.is_none());
        assert_eq!(
            parsed.source_mac,
            Some([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
        );
    }

    #[test]
    fn multicast_frame_with_both_flags() {
        let data = [0xFF; 8];
        let payload = MulticastFramePayload {
            network_id: 0xdeadbeef,
            flags: 0x06, // gather_limit + source_mac
            com: None,
            gather_limit: Some(1000),
            source_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            dest_mac: [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
            adi: 999,
            ethertype: 0x86DD,
            payload: &data,
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        // 8 + 1 + 4 + 6 + 6 + 4 + 2 + 8 = 39
        assert_eq!(n, 39);
        let parsed = MulticastFramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.gather_limit, Some(1000));
        assert_eq!(
            parsed.source_mac,
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(parsed.ethertype, 0x86DD);
        assert_eq!(parsed.payload, &data[..]);
    }

    #[test]
    fn multicast_frame_too_short() {
        assert!(MulticastFramePayload::parse(&[0; 8]).is_err());
    }

    /// With flag 0x01 the COM comes before the gather limit and source MAC
    /// (ZeroTierOne _doMULTICAST_FRAME).
    #[test]
    fn multicast_frame_with_inline_com_roundtrip() {
        let com = CertificateOfMembership {
            issued_to: [1, 2, 3, 4, 5],
            qualifiers: alloc::vec![
                crate::verbs::network_config::ComQualifier {
                    id: 0,
                    value: 42,
                    max_delta: 10,
                },
                crate::verbs::network_config::ComQualifier {
                    id: 2,
                    value: 0x01_0203_0405,
                    max_delta: 0,
                },
            ],
            signer_address: [6, 7, 8, 9, 10],
            signature: [0x5a; 96],
        };
        let data = [0xCC; 3];
        let payload = MulticastFramePayload {
            network_id: 1,
            flags: 0x02,
            com: Some(com.clone()),
            gather_limit: Some(7),
            source_mac: None,
            dest_mac: [0xff; 6],
            adi: 9,
            ethertype: 0x0806,
            payload: &data,
        };
        let mut buf = [0u8; 512];
        let n = payload.serialize(&mut buf);
        assert_eq!(buf[8], 0x03);
        let parsed = MulticastFramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.com, Some(com));
        assert_eq!(parsed.gather_limit, Some(7));
        assert_eq!(parsed.adi, 9);
        assert_eq!(parsed.payload, &data[..]);
    }
}
