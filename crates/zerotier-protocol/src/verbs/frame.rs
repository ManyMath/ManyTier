/// FRAME (verb 0x06) and EXT_FRAME (verb 0x07) codecs.
///
/// FRAME wire format:
///
/// EXT_FRAME wire format:
use crate::error::ProtocolError;
use crate::verbs::network_config::CertificateOfMembership;

/// EXT_FRAME and MULTICAST_FRAME flag: a certificate of membership follows
/// the flags byte.
pub const EXT_FRAME_FLAG_COM: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramePayload<'a> {
    pub network_id: u64,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> FramePayload<'a> {
    /// Zero-copy parse from wire bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, ProtocolError> {
        if data.len() < 10 {
            return Err(ProtocolError::TooShort {
                need: 10,
                got: data.len(),
            });
        }
        let network_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let ethertype = u16::from_be_bytes([data[8], data[9]]);
        let payload = &data[10..];

        Ok(FramePayload {
            network_id,
            ethertype,
            payload,
        })
    }

    /// Serialize into buffer, copying payload. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..8].copy_from_slice(&self.network_id.to_be_bytes());
        buf[8..10].copy_from_slice(&self.ethertype.to_be_bytes());
        let plen = self.payload.len();
        buf[10..10 + plen].copy_from_slice(self.payload);
        10 + plen
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtFramePayload<'a> {
    pub network_id: u64,
    pub flags: u8,
    /// A certificate of membership sent along (flag 0x01). Deprecated
    /// upstream but still accepted from older peers.
    pub com: Option<CertificateOfMembership>,
    pub dest_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> ExtFramePayload<'a> {
    /// Zero-copy parse from wire bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, ProtocolError> {
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
        // ZeroTierOne _doEXT_FRAME: the COM, when flagged, precedes the MACs.
        let (com, at) = if flags & EXT_FRAME_FLAG_COM != 0 {
            let (com, used) = CertificateOfMembership::deserialize(&data[9..])?;
            (Some(com), 9 + used)
        } else {
            (None, 9)
        };
        if data.len() < at + 14 {
            return Err(ProtocolError::TooShort {
                need: at + 14,
                got: data.len(),
            });
        }
        let mut dest_mac = [0u8; 6];
        dest_mac.copy_from_slice(&data[at..at + 6]);
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&data[at + 6..at + 12]);
        let ethertype = u16::from_be_bytes([data[at + 12], data[at + 13]]);
        let payload = &data[at + 14..];

        Ok(ExtFramePayload {
            network_id,
            flags,
            com,
            dest_mac,
            src_mac,
            ethertype,
            payload,
        })
    }

    /// Serialize into buffer, copying payload. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..8].copy_from_slice(&self.network_id.to_be_bytes());
        let mut at = 9;
        buf[8] = self.flags & !EXT_FRAME_FLAG_COM;
        if let Some(com) = &self.com {
            buf[8] |= EXT_FRAME_FLAG_COM;
            at += com.serialize(&mut buf[9..]);
        }
        buf[at..at + 6].copy_from_slice(&self.dest_mac);
        buf[at + 6..at + 12].copy_from_slice(&self.src_mac);
        buf[at + 12..at + 14].copy_from_slice(&self.ethertype.to_be_bytes());
        let plen = self.payload.len();
        buf[at + 14..at + 14 + plen].copy_from_slice(self.payload);
        at + 14 + plen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let data = [0xAA; 100];
        let payload = FramePayload {
            network_id: 0x1234567890abcdef,
            ethertype: 0x0800,
            payload: &data,
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 110);
        let parsed = FramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.network_id, payload.network_id);
        assert_eq!(parsed.ethertype, payload.ethertype);
        assert_eq!(parsed.payload, &data[..]);
    }

    #[test]
    fn frame_empty_payload() {
        let payload = FramePayload {
            network_id: 1,
            ethertype: 0x0806,
            payload: &[],
        };
        let mut buf = [0u8; 32];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 10);
        let parsed = FramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.payload.len(), 0);
    }

    #[test]
    fn frame_too_short() {
        assert!(FramePayload::parse(&[0; 9]).is_err());
    }

    #[test]
    fn ext_frame_roundtrip() {
        let data = [0xBB; 50];
        let payload = ExtFramePayload {
            network_id: 0xfedcba9876543210,
            flags: 0x00,
            com: None,
            dest_mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            src_mac: [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            ethertype: 0x0800,
            payload: &data,
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 73);
        let parsed = ExtFramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.network_id, payload.network_id);
        assert_eq!(parsed.flags, payload.flags);
        assert_eq!(parsed.dest_mac, payload.dest_mac);
        assert_eq!(parsed.src_mac, payload.src_mac);
        assert_eq!(parsed.ethertype, payload.ethertype);
        assert_eq!(parsed.payload, &data[..]);
    }

    #[test]
    fn ext_frame_too_short() {
        assert!(ExtFramePayload::parse(&[0; 22]).is_err());
    }

    fn test_com() -> CertificateOfMembership {
        CertificateOfMembership {
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
        }
    }

    /// With flag 0x01 the COM sits between the flags and the MACs
    /// (ZeroTierOne _doEXT_FRAME).
    #[test]
    fn ext_frame_with_inline_com_roundtrip() {
        let data = [0xBB; 4];
        let payload = ExtFramePayload {
            network_id: 1,
            flags: 0,
            com: Some(test_com()),
            dest_mac: [1; 6],
            src_mac: [2; 6],
            ethertype: 0x0800,
            payload: &data,
        };
        let mut buf = [0u8; 512];
        let n = payload.serialize(&mut buf);
        assert_eq!(buf[8] & EXT_FRAME_FLAG_COM, EXT_FRAME_FLAG_COM);
        let parsed = ExtFramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.com, Some(test_com()));
        assert_eq!(parsed.dest_mac, [1; 6]);
        assert_eq!(parsed.src_mac, [2; 6]);
        assert_eq!(parsed.payload, &data[..]);
    }
}
