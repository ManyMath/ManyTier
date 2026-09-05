// Network config verb codecs.

extern crate alloc;

use crate::error::ProtocolError;
use alloc::vec::Vec;

/// NETWORK_CONFIG_REQUEST payload.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfigRequestPayload {
    pub network_id: u64,
    pub dict_data: Vec<u8>,
}

impl NetworkConfigRequestPayload {
    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..8].copy_from_slice(&self.network_id.to_be_bytes());
        let dict_len = self.dict_data.len() as u16;
        buf[8..10].copy_from_slice(&dict_len.to_be_bytes());
        buf[10..10 + self.dict_data.len()].copy_from_slice(&self.dict_data);
        10 + self.dict_data.len()
    }

    /// Deserialize from wire bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 10 {
            return Err(ProtocolError::TooShort {
                need: 10,
                got: data.len(),
            });
        }
        let network_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let dict_len = u16::from_be_bytes([data[8], data[9]]) as usize;
        if data.len() < 10 + dict_len {
            return Err(ProtocolError::TooShort {
                need: 10 + dict_len,
                got: data.len(),
            });
        }
        let dict_data = data[10..10 + dict_len].to_vec();
        Ok(NetworkConfigRequestPayload {
            network_id,
            dict_data,
        })
    }
}

/// NETWORK_CONFIG payload.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfigPayload {
    pub network_id: u64,
    pub dict_data: Vec<u8>,
    pub flags: Option<u8>,
    pub config_update_id: Option<u64>,
    pub total_length: Option<u32>,
    pub chunk_index: Option<u32>,
    pub signature_type: Option<u8>,
    pub signature: Option<Vec<u8>>,
}

impl NetworkConfigPayload {
    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..8].copy_from_slice(&self.network_id.to_be_bytes());
        let dict_len = self.dict_data.len() as u16;
        buf[8..10].copy_from_slice(&dict_len.to_be_bytes());
        let dict_end = 10 + self.dict_data.len();
        buf[10..dict_end].copy_from_slice(&self.dict_data);

        let mut offset = dict_end;
        if let (
            Some(flags),
            Some(config_update_id),
            Some(total_length),
            Some(chunk_index),
            Some(signature_type),
            Some(signature),
        ) = (
            self.flags,
            self.config_update_id,
            self.total_length,
            self.chunk_index,
            self.signature_type,
            &self.signature,
        ) {
            buf[offset] = flags;
            offset += 1;
            buf[offset..offset + 8].copy_from_slice(&config_update_id.to_be_bytes());
            offset += 8;
            buf[offset..offset + 4].copy_from_slice(&total_length.to_be_bytes());
            offset += 4;
            buf[offset..offset + 4].copy_from_slice(&chunk_index.to_be_bytes());
            offset += 4;
            buf[offset] = signature_type;
            offset += 1;
            let signature_len = signature.len() as u16;
            buf[offset..offset + 2].copy_from_slice(&signature_len.to_be_bytes());
            offset += 2;
            buf[offset..offset + signature.len()].copy_from_slice(signature);
            offset += signature.len();
        }
        offset
    }

    /// Deserialize from wire bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 10 {
            return Err(ProtocolError::TooShort {
                need: 10,
                got: data.len(),
            });
        }
        let network_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let dict_len = u16::from_be_bytes([data[8], data[9]]) as usize;
        if data.len() < 10 + dict_len {
            return Err(ProtocolError::TooShort {
                need: 10 + dict_len,
                got: data.len(),
            });
        }
        let dict_data = data[10..10 + dict_len].to_vec();
        let dict_end = 10 + dict_len;

        let (flags, config_update_id, total_length, chunk_index, signature_type, signature) =
            if data.len() == dict_end {
                (None, None, None, None, None, None)
            } else {
                if data.len() < dict_end + 20 {
                    return Err(ProtocolError::TooShort {
                        need: dict_end + 20,
                        got: data.len(),
                    });
                }
                let flags = data[dict_end];
                let config_update_id = u64::from_be_bytes([
                    data[dict_end + 1],
                    data[dict_end + 2],
                    data[dict_end + 3],
                    data[dict_end + 4],
                    data[dict_end + 5],
                    data[dict_end + 6],
                    data[dict_end + 7],
                    data[dict_end + 8],
                ]);
                let total_length = u32::from_be_bytes([
                    data[dict_end + 9],
                    data[dict_end + 10],
                    data[dict_end + 11],
                    data[dict_end + 12],
                ]);
                let chunk_index = u32::from_be_bytes([
                    data[dict_end + 13],
                    data[dict_end + 14],
                    data[dict_end + 15],
                    data[dict_end + 16],
                ]);
                let signature_type = data[dict_end + 17];
                let signature_len =
                    u16::from_be_bytes([data[dict_end + 18], data[dict_end + 19]]) as usize;
                if data.len() < dict_end + 20 + signature_len {
                    return Err(ProtocolError::TooShort {
                        need: dict_end + 20 + signature_len,
                        got: data.len(),
                    });
                }
                let signature = data[dict_end + 20..dict_end + 20 + signature_len].to_vec();
                (
                    Some(flags),
                    Some(config_update_id),
                    Some(total_length),
                    Some(chunk_index),
                    Some(signature_type),
                    Some(signature),
                )
            };

        Ok(NetworkConfigPayload {
            network_id,
            dict_data,
            flags,
            config_update_id,
            total_length,
            chunk_index,
            signature_type,
            signature,
        })
    }
}

/// A single COM qualifier tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComQualifier {
    pub id: u64,
    pub value: u64,
    pub max_delta: u64,
}

/// Certificate of Membership.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateOfMembership {
    pub issued_to: [u8; 5],
    pub qualifiers: Vec<ComQualifier>,
    pub signer_address: [u8; 5],
    pub signature: [u8; 96],
}

fn u64_to_zt_address(value: u64) -> [u8; 5] {
    let bytes = value.to_be_bytes();
    [bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
}

impl CertificateOfMembership {
    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = 1;
        let count = self.qualifiers.len() as u16;
        buf[1..3].copy_from_slice(&count.to_be_bytes());
        let mut offset = 3;

        for q in &self.qualifiers {
            buf[offset..offset + 8].copy_from_slice(&q.id.to_be_bytes());
            offset += 8;
            buf[offset..offset + 8].copy_from_slice(&q.value.to_be_bytes());
            offset += 8;
            buf[offset..offset + 8].copy_from_slice(&q.max_delta.to_be_bytes());
            offset += 8;
        }

        buf[offset..offset + 5].copy_from_slice(&self.signer_address);
        offset += 5;
        if self.signer_address != [0; 5] {
            buf[offset..offset + 96].copy_from_slice(&self.signature);
            offset += 96;
        }
        offset
    }

    /// Deserialize from wire bytes. Returns the COM and bytes consumed.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if data.len() < 8 {
            return Err(ProtocolError::TooShort {
                need: 8,
                got: data.len(),
            });
        }
        if data[0] != 1 {
            return Err(ProtocolError::InvalidPacket);
        }

        let count = u16::from_be_bytes([data[1], data[2]]) as usize;
        let base_needed = 3 + count * 24 + 5;
        if data.len() < base_needed {
            return Err(ProtocolError::TooShort {
                need: base_needed,
                got: data.len(),
            });
        }

        let mut offset = 3;
        let mut qualifiers = Vec::with_capacity(count);
        for _ in 0..count {
            let id = u64::from_be_bytes([
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
            let value = u64::from_be_bytes([
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
            let max_delta = u64::from_be_bytes([
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
            qualifiers.push(ComQualifier {
                id,
                value,
                max_delta,
            });
        }

        let mut issued_to = [0u8; 5];
        if let Some(qualifier) = qualifiers.iter().find(|q| q.id == 2) {
            issued_to = u64_to_zt_address(qualifier.value);
        }

        let mut signer_address = [0u8; 5];
        signer_address.copy_from_slice(&data[offset..offset + 5]);
        offset += 5;

        let mut signature = [0u8; 96];
        if signer_address != [0; 5] {
            let needed = offset + 96;
            if data.len() < needed {
                return Err(ProtocolError::TooShort {
                    need: needed,
                    got: data.len(),
                });
            }
            signature.copy_from_slice(&data[offset..offset + 96]);
            offset += 96;
        }

        Ok((
            CertificateOfMembership {
                issued_to,
                qualifiers,
                signer_address,
                signature,
            },
            offset,
        ))
    }
}

/// NETWORK_CREDENTIALS payload (verb 0x0a).
///
/// Wire layout (ZeroTierOne node/Packet.hpp, `VERB_NETWORK_CREDENTIALS`):
/// zero or more serialized certificates of membership, a `0x00` byte ending
/// the COM list, then four `u16`-count-prefixed sections of capabilities,
/// tags, revocations and certificates of ownership. Older peers omit the
/// sections entirely.
///
/// The sections are carried verbatim in `sections` (count prefixes
/// included): the objects are self-delimiting and only a full parser for
/// each could split them, while the node only acts on the COMs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCredentialsPayload {
    pub coms: Vec<CertificateOfMembership>,
    /// `[u16 caps][...][u16 tags][...][u16 revocations][...][u16 coos][...]`
    /// exactly as on the wire, or empty for none.
    pub sections: Vec<u8>,
}

impl NetworkCredentialsPayload {
    /// Build the trailing sections from capability and tag object bytes.
    ///
    /// `capabilities` and `tags` hold the concatenated serialized objects;
    /// the counts say how many each contains. Revocations and certificates of
    /// ownership are always sent empty.
    pub fn sections_from(
        capability_count: u16,
        capabilities: &[u8],
        tag_count: u16,
        tags: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + capabilities.len() + tags.len());
        out.extend_from_slice(&capability_count.to_be_bytes());
        out.extend_from_slice(capabilities);
        out.extend_from_slice(&tag_count.to_be_bytes());
        out.extend_from_slice(tags);
        out.extend_from_slice(&0u16.to_be_bytes()); // revocations
        out.extend_from_slice(&0u16.to_be_bytes()); // certificates of ownership
        out
    }

    /// The first certificate of membership, if any.
    pub fn com(&self) -> Option<&CertificateOfMembership> {
        self.coms.first()
    }

    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        for com in &self.coms {
            offset += com.serialize(&mut buf[offset..]);
        }
        buf[offset] = 0; // end of COM list
        offset += 1;
        buf[offset..offset + self.sections.len()].copy_from_slice(&self.sections);
        offset += self.sections.len();
        offset
    }

    /// Deserialize from wire bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.is_empty() {
            return Err(ProtocolError::TooShort { need: 1, got: 0 });
        }

        let mut offset = 0;
        let mut coms = Vec::new();
        // A COM starts with its version byte (1); 0x00 ends the list.
        while offset < data.len() && data[offset] != 0 {
            let (com, consumed) = CertificateOfMembership::deserialize(&data[offset..])?;
            offset += consumed;
            coms.push(com);
        }
        if offset < data.len() {
            offset += 1; // the terminator
        }
        let sections = data[offset..].to_vec();

        Ok(NetworkCredentialsPayload { coms, sections })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn network_config_request_roundtrip() {
        let payload = NetworkConfigRequestPayload {
            network_id: 0x1234567890abcdef,
            dict_data: vec![0x61, 0x3d, 0x62, 0x0a], // "a=b\n"
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 14);
        let parsed = NetworkConfigRequestPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn network_config_request_empty_dict() {
        let payload = NetworkConfigRequestPayload {
            network_id: 1,
            dict_data: vec![],
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 10);
        let parsed = NetworkConfigRequestPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn network_config_request_too_short() {
        assert!(NetworkConfigRequestPayload::deserialize(&[0; 9]).is_err());
    }

    #[test]
    fn network_config_single_chunk() {
        let payload = NetworkConfigPayload {
            network_id: 0xfedcba9876543210,
            dict_data: vec![1, 2, 3, 4, 5],
            flags: None,
            config_update_id: None,
            total_length: None,
            chunk_index: None,
            signature_type: None,
            signature: None,
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 15); // 8 + 2 + 5
        let parsed = NetworkConfigPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn network_config_multipart() {
        let sig = vec![0x11; 96];
        let payload = NetworkConfigPayload {
            network_id: 0x1122334455667788,
            dict_data: vec![0xAA, 0xBB],
            flags: Some(0),
            config_update_id: Some(0x0102030405060708),
            total_length: Some(4096),
            chunk_index: Some(2048),
            signature_type: Some(1),
            signature: Some(sig),
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        // 8 + 2 + 2 + 1 + 8 + 4 + 4 + 1 + 2 + 96 = 128
        assert_eq!(n, 128);
        let parsed = NetworkConfigPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn com_roundtrip() {
        let mut sig = [0u8; 96];
        for (i, b) in sig.iter_mut().enumerate() {
            *b = (i * 3) as u8;
        }
        let com = CertificateOfMembership {
            issued_to: [0x01, 0x02, 0x03, 0x04, 0x05],
            qualifiers: vec![
                ComQualifier {
                    id: 0,
                    value: 0x1234567890abcdef,
                    max_delta: 0,
                },
                ComQualifier {
                    id: 1,
                    value: 1000,
                    max_delta: 100,
                },
                ComQualifier {
                    id: 2,
                    value: 0x0102030405,
                    max_delta: 0xffffffffffffffff,
                },
            ],
            signer_address: [0xa0, 0xb1, 0xc2, 0xd3, 0xe4],
            signature: sig,
        };
        let mut buf = [0u8; 512];
        let n = com.serialize(&mut buf);
        // 1 + 2 + 3*24 + 5 + 96 = 176
        assert_eq!(n, 176);
        let (parsed, consumed) = CertificateOfMembership::deserialize(&buf[..n]).unwrap();
        assert_eq!(consumed, n);
        assert_eq!(parsed, com);
    }

    #[test]
    fn com_96_byte_signature() {
        let mut sig = [0xAA; 96];
        sig[0] = 0x01;
        sig[95] = 0xFF;
        let com = CertificateOfMembership {
            issued_to: [0; 5],
            qualifiers: vec![],
            signer_address: [0x11, 0x22, 0x33, 0x44, 0x55],
            signature: sig,
        };
        let mut buf = [0u8; 256];
        let n = com.serialize(&mut buf);
        // 1 + 2 + 0 + 5 + 96 = 104
        assert_eq!(n, 104);
        let (parsed, _) = CertificateOfMembership::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.signature[0], 0x01);
        assert_eq!(parsed.signature[95], 0xFF);
        assert_eq!(parsed.signature.len(), 96);
    }

    fn test_com() -> CertificateOfMembership {
        let mut sig = [0u8; 96];
        sig[0] = 0xDE;
        CertificateOfMembership {
            issued_to: [0x01, 0x02, 0x03, 0x04, 0x05],
            qualifiers: vec![
                ComQualifier {
                    id: 0,
                    value: 42,
                    max_delta: 10,
                },
                ComQualifier {
                    id: 2,
                    value: 0x0102030405,
                    max_delta: 0,
                },
            ],
            signer_address: [0x01, 0x02, 0x03, 0x04, 0x05],
            signature: sig,
        }
    }

    #[test]
    fn network_credentials_with_com() {
        let payload = NetworkCredentialsPayload {
            coms: vec![test_com()],
            sections: NetworkCredentialsPayload::sections_from(1, &[0x01, 0x02], 0, &[]),
        };
        let mut buf = [0u8; 512];
        let n = payload.serialize(&mut buf);
        let parsed = NetworkCredentialsPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
        assert_eq!(parsed.com(), Some(&test_com()));
    }

    /// Layout from ZeroTierOne node/Packet.hpp VERB_NETWORK_CREDENTIALS and
    /// node/IncomingPacket.cpp _doNETWORK_CREDENTIALS: COMs, a 0x00
    /// terminator, then four u16 counts (here all zero).
    #[test]
    fn network_credentials_matches_upstream_byte_layout() {
        let com = test_com();
        let mut com_bytes = [0u8; 256];
        let com_len = com.serialize(&mut com_bytes);

        let mut upstream = Vec::new();
        upstream.extend_from_slice(&com_bytes[..com_len]);
        upstream.push(0x00);
        upstream.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

        let parsed = NetworkCredentialsPayload::deserialize(&upstream).unwrap();
        assert_eq!(parsed.coms, vec![com]);
        assert_eq!(parsed.sections, vec![0u8; 8]);

        let mut buf = [0u8; 512];
        let n = parsed.serialize(&mut buf);
        assert_eq!(&buf[..n], &upstream[..]);
    }

    /// Older peers stop after the COM terminator.
    #[test]
    fn network_credentials_without_sections() {
        let com = test_com();
        let mut buf = [0u8; 256];
        let com_len = com.serialize(&mut buf);
        buf[com_len] = 0;
        let parsed = NetworkCredentialsPayload::deserialize(&buf[..com_len + 1]).unwrap();
        assert_eq!(parsed.coms.len(), 1);
        assert!(parsed.sections.is_empty());
    }

    #[test]
    fn network_credentials_without_com() {
        let payload = NetworkCredentialsPayload {
            coms: vec![],
            sections: NetworkCredentialsPayload::sections_from(0, &[], 0, &[]),
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        // 1 (terminator) + 4*2 (section counts) = 9
        assert_eq!(n, 9);
        let parsed = NetworkCredentialsPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
        assert!(parsed.com().is_none());
    }

    #[test]
    fn network_credentials_too_short() {
        assert!(NetworkCredentialsPayload::deserialize(&[]).is_err());
    }
}
