// OK verb payload codec.

use crate::error::ProtocolError;
use crate::identity_wire;
use crate::inet_address::InetAddress;
use crate::verb::Verb;
use alloc::vec::Vec;
use zerotier_crypto::identity::Identity;

#[derive(Debug)]
pub struct OkPayload {
    pub in_re_verb: Verb,
    pub in_re_packet_id: u64,
    pub sub_payload: OkSubPayload,
}

#[derive(Debug)]
pub enum OkSubPayload {
    /// OK response to HELLO.
    Hello {
        timestamp_echo: u64,
        protocol_version: u8,
        major_version: u8,
        minor_version: u8,
        revision: u16,
        /// The address the HELLO arrived from, i.e. our external surface as
        /// the responder sees it.
        external_address: Option<InetAddress>,
        /// Serialized planet/moon updates for the HELLO's sender.
        worlds: Vec<u8>,
    },
    /// OK response to WHOIS.
    Whois { identities: Vec<Identity> },
    /// Generic OK for verbs where we don't parse the sub-payload.
    Generic { data: Vec<u8> },
}

impl OkPayload {
    /// Serialize this OK payload into the given buffer.
    /// Returns the number of bytes written on success.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ProtocolError> {
        let mut pos = 0;

        buf[pos] = self.in_re_verb.to_byte();
        pos += 1;
        buf[pos..pos + 8].copy_from_slice(&self.in_re_packet_id.to_be_bytes());
        pos += 8;

        match &self.sub_payload {
            OkSubPayload::Hello {
                timestamp_echo,
                protocol_version,
                major_version,
                minor_version,
                revision,
                external_address,
                worlds,
            } => {
                buf[pos..pos + 8].copy_from_slice(&timestamp_echo.to_be_bytes());
                pos += 8;
                buf[pos] = *protocol_version;
                pos += 1;
                buf[pos] = *major_version;
                pos += 1;
                buf[pos] = *minor_version;
                pos += 1;
                buf[pos..pos + 2].copy_from_slice(&revision.to_be_bytes());
                pos += 2;
                // ZeroTierOne node/IncomingPacket.cpp _doHELLO: the sender's
                // address, then a u16-length-prefixed run of worlds.
                pos += external_address
                    .as_ref()
                    .unwrap_or(&InetAddress::Null)
                    .serialize(&mut buf[pos..]);
                buf[pos..pos + 2].copy_from_slice(&(worlds.len() as u16).to_be_bytes());
                pos += 2;
                buf[pos..pos + worlds.len()].copy_from_slice(worlds);
                pos += worlds.len();
            }
            OkSubPayload::Whois { identities } => {
                for id in identities {
                    let n = identity_wire::serialize_identity_public(id, &mut buf[pos..]);
                    pos += n;
                }
            }
            OkSubPayload::Generic { data } => {
                buf[pos..pos + data.len()].copy_from_slice(data);
                pos += data.len();
            }
        }

        Ok(pos)
    }

    /// Deserialize an OK payload from a byte slice.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 9 {
            return Err(ProtocolError::TooShort {
                need: 9,
                got: data.len(),
            });
        }

        let in_re_verb = Verb::from_byte(data[0]).ok_or(ProtocolError::InvalidVerb(data[0]))?;
        let in_re_packet_id = u64::from_be_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]);

        let sub_data = &data[9..];

        let sub_payload = match in_re_verb {
            Verb::Hello => {
                if sub_data.len() < 13 {
                    return Err(ProtocolError::TooShort {
                        need: 9 + 13,
                        got: data.len(),
                    });
                }
                let timestamp_echo = u64::from_be_bytes([
                    sub_data[0],
                    sub_data[1],
                    sub_data[2],
                    sub_data[3],
                    sub_data[4],
                    sub_data[5],
                    sub_data[6],
                    sub_data[7],
                ]);
                let protocol_version = sub_data[8];
                let major_version = sub_data[9];
                let minor_version = sub_data[10];
                let revision = u16::from_be_bytes([sub_data[11], sub_data[12]]);
                let mut rest = &sub_data[13..];
                let external_address = match InetAddress::deserialize(rest) {
                    Ok((address, used)) => {
                        rest = &rest[used..];
                        Some(address).filter(|address| *address != InetAddress::Null)
                    }
                    Err(_) => {
                        rest = &[];
                        None
                    }
                };
                let worlds = match rest {
                    [hi, lo, worlds @ ..] => {
                        let len = (u16::from_be_bytes([*hi, *lo]) as usize).min(worlds.len());
                        worlds[..len].to_vec()
                    }
                    _ => Vec::new(),
                };
                OkSubPayload::Hello {
                    timestamp_echo,
                    protocol_version,
                    major_version,
                    minor_version,
                    revision,
                    external_address,
                    worlds,
                }
            }
            Verb::Whois => {
                let mut identities = Vec::new();
                let mut pos = 0;
                while pos < sub_data.len() {
                    let (id, consumed) = identity_wire::deserialize_identity(&sub_data[pos..])?;
                    identities.push(id);
                    pos += consumed;
                }
                OkSubPayload::Whois { identities }
            }
            _ => OkSubPayload::Generic {
                data: sub_data.to_vec(),
            },
        };

        Ok(Self {
            in_re_verb,
            in_re_packet_id,
            sub_payload,
        })
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
    fn ok_hello_roundtrip() {
        let ok = OkPayload {
            in_re_verb: Verb::Hello,
            in_re_packet_id: 0xDEADBEEFCAFE0001,
            sub_payload: OkSubPayload::Hello {
                timestamp_echo: 1234567890123,
                protocol_version: 13,
                major_version: 0,
                minor_version: 1,
                revision: 0,
                external_address: None,
                worlds: Vec::new(),
            },
        };

        let mut buf = [0u8; 256];
        let n = ok.serialize(&mut buf).unwrap();

        let parsed = OkPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.in_re_verb, Verb::Hello);
        assert_eq!(parsed.in_re_packet_id, 0xDEADBEEFCAFE0001);

        if let OkSubPayload::Hello {
            timestamp_echo,
            protocol_version,
            major_version,
            minor_version,
            revision,
            external_address,
            worlds,
        } = parsed.sub_payload
        {
            assert_eq!(timestamp_echo, 1234567890123);
            assert_eq!(protocol_version, 13);
            assert_eq!(major_version, 0);
            assert_eq!(minor_version, 1);
            assert_eq!(revision, 0);
            assert!(external_address.is_none());
            assert!(worlds.is_empty());
        } else {
            panic!("expected OkSubPayload::Hello");
        }
    }

    #[test]
    fn ok_hello_with_external_address_and_worlds() {
        let world_data = alloc::vec![0x01, 0x02, 0x03, 0x04];
        let external = InetAddress::V4 {
            ip: [203, 0, 113, 9],
            port: 41234,
        };
        let ok = OkPayload {
            in_re_verb: Verb::Hello,
            in_re_packet_id: 1,
            sub_payload: OkSubPayload::Hello {
                timestamp_echo: 5000,
                protocol_version: 13,
                major_version: 1,
                minor_version: 2,
                revision: 3,
                external_address: Some(external.clone()),
                worlds: world_data.clone(),
            },
        };

        let mut buf = [0u8; 256];
        let n = ok.serialize(&mut buf).unwrap();

        let parsed = OkPayload::deserialize(&buf[..n]).unwrap();
        if let OkSubPayload::Hello {
            external_address,
            worlds,
            ..
        } = parsed.sub_payload
        {
            assert_eq!(external_address, Some(external));
            assert_eq!(worlds, world_data);
        } else {
            panic!("expected OkSubPayload::Hello");
        }
    }

    /// Older peers stop after the revision; both trailing fields are then
    /// absent.
    #[test]
    fn ok_hello_without_trailing_fields() {
        let mut data = alloc::vec![Verb::Hello.to_byte()];
        data.extend_from_slice(&7u64.to_be_bytes());
        data.extend_from_slice(&5000u64.to_be_bytes());
        data.extend_from_slice(&[13, 1, 2, 0, 3]);
        let parsed = OkPayload::deserialize(&data).unwrap();
        let OkSubPayload::Hello {
            external_address,
            worlds,
            ..
        } = parsed.sub_payload
        else {
            panic!("expected OkSubPayload::Hello");
        };
        assert!(external_address.is_none());
        assert!(worlds.is_empty());
    }

    #[test]
    fn ok_hello_wire_layout() {
        let ok = OkPayload {
            in_re_verb: Verb::Hello,
            in_re_packet_id: 0x0102030405060708,
            sub_payload: OkSubPayload::Hello {
                timestamp_echo: 0x1112131415161718,
                protocol_version: 13,
                major_version: 0,
                minor_version: 1,
                revision: 0,
                external_address: None,
                worlds: Vec::new(),
            },
        };

        let mut buf = [0u8; 256];
        let n = ok.serialize(&mut buf).unwrap();

        // Header: verb (1) + packet_id (8) + sub-payload (13), then a null
        // external address (1) and an empty world run (2) = 25
        assert_eq!(n, 25);
        assert_eq!(&buf[22..25], &[0, 0, 0]);
        assert_eq!(buf[0], Verb::Hello.to_byte()); // in_re_verb
        assert_eq!(
            &buf[1..9],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        // timestamp echo at 9..17
        assert_eq!(
            u64::from_be_bytes([
                buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16]
            ]),
            0x1112131415161718
        );
        assert_eq!(buf[17], 13); // protocol version
        assert_eq!(buf[18], 0); // major
        assert_eq!(buf[19], 1); // minor
        assert_eq!(buf[20], 0); // revision high
        assert_eq!(buf[21], 0); // revision low
    }

    #[test]
    fn ok_whois_roundtrip() {
        let id = build_test_identity();
        let expected_addr = id.address;
        let ok = OkPayload {
            in_re_verb: Verb::Whois,
            in_re_packet_id: 42,
            sub_payload: OkSubPayload::Whois {
                identities: alloc::vec![id],
            },
        };

        let mut buf = [0u8; 256];
        let n = ok.serialize(&mut buf).unwrap();

        let parsed = OkPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.in_re_verb, Verb::Whois);
        assert_eq!(parsed.in_re_packet_id, 42);

        if let OkSubPayload::Whois { identities } = parsed.sub_payload {
            assert_eq!(identities.len(), 1);
            assert_eq!(identities[0].address, expected_addr);
        } else {
            panic!("expected OkSubPayload::Whois");
        }
    }

    #[test]
    fn ok_generic_roundtrip() {
        let ok = OkPayload {
            in_re_verb: Verb::Echo,
            in_re_packet_id: 99,
            sub_payload: OkSubPayload::Generic {
                data: alloc::vec![0x01, 0x02, 0x03],
            },
        };

        let mut buf = [0u8; 256];
        let n = ok.serialize(&mut buf).unwrap();

        let parsed = OkPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.in_re_verb, Verb::Echo);
        if let OkSubPayload::Generic { data } = parsed.sub_payload {
            assert_eq!(data, alloc::vec![0x01, 0x02, 0x03]);
        } else {
            panic!("expected OkSubPayload::Generic");
        }
    }

    #[test]
    fn ok_deserialize_too_short() {
        let data = [0u8; 8];
        assert!(OkPayload::deserialize(&data).is_err());
    }

    #[test]
    fn ok_hello_deserialize_too_short_sub() {
        // Header is OK (9 bytes) but HELLO sub-payload needs 13
        let mut buf = [0u8; 20]; // 9 + 11 = not enough for HELLO sub-payload
        buf[0] = Verb::Hello.to_byte();
        assert!(OkPayload::deserialize(&buf).is_err());
    }
}
