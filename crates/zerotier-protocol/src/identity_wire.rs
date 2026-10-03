/// Identity binary wire format serialization for ZeroTier V1.
///
/// Public identity wire layout (71 bytes):
/// `[address:5][type:1][dh_pubkey:32][signing_pubkey:32][secret_len:1(=0)]`
use crate::error::ProtocolError;
use zerotier_crypto::identity::{Address, Identity, PublicKey};

/// Identity type byte for C25519-based identities.
pub const IDENTITY_TYPE_C25519: u8 = 0;

pub const IDENTITY_PUBLIC_WIRE_LEN: usize = 71;

/// Serialize a public identity to binary wire format.
///
/// Writes exactly 71 bytes: address (5) + type (1) + dh pubkey (32) + signing pubkey (32) + 0x00 (1).
/// Returns the number of bytes written (always 71).
pub fn serialize_identity_public(identity: &Identity, buf: &mut [u8]) -> usize {
    buf[0..5].copy_from_slice(identity.address.as_bytes());
    buf[5] = IDENTITY_TYPE_C25519;
    buf[6..38].copy_from_slice(&identity.public_key.dh);
    buf[38..70].copy_from_slice(&identity.public_key.signing);
    buf[70] = 0x00; // no secret key follows
    IDENTITY_PUBLIC_WIRE_LEN
}

/// Deserialize an identity from binary wire format.
///
/// Returns the identity and the number of bytes consumed.
/// If a secret key length > 0 follows, those bytes are skipped.
pub fn deserialize_identity(data: &[u8]) -> Result<(Identity, usize), ProtocolError> {
    if data.len() < IDENTITY_PUBLIC_WIRE_LEN {
        return Err(ProtocolError::TooShort {
            need: IDENTITY_PUBLIC_WIRE_LEN,
            got: data.len(),
        });
    }

    let mut addr_bytes = [0u8; 5];
    addr_bytes.copy_from_slice(&data[0..5]);
    let address = Address::new(addr_bytes).map_err(|_| ProtocolError::InvalidAddress)?;

    let id_type = data[5];
    if id_type != IDENTITY_TYPE_C25519 {
        return Err(ProtocolError::InvalidPacket);
    }

    let mut pub_bytes = [0u8; 64];
    pub_bytes[..32].copy_from_slice(&data[6..38]);
    pub_bytes[32..].copy_from_slice(&data[38..70]);
    let public_key = PublicKey::from_bytes(&pub_bytes).map_err(ProtocolError::CryptoError)?;

    // Either no private key or a full C25519 pair (ZeroTierOne
    // Identity::deserialize rejects any other length).
    let secret_len = data[70] as usize;
    if secret_len != 0 && secret_len != 64 {
        return Err(ProtocolError::InvalidPacket);
    }
    let consumed = IDENTITY_PUBLIC_WIRE_LEN + secret_len;

    if data.len() < consumed {
        return Err(ProtocolError::TooShort {
            need: consumed,
            got: data.len(),
        });
    }

    Ok((
        Identity {
            address,
            public_key,
            secret: None,
        },
        consumed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub_identity() -> Identity {
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
    fn serialize_produces_71_bytes() {
        let id = stub_identity();
        let mut buf = [0u8; 128];
        let n = serialize_identity_public(&id, &mut buf);
        assert_eq!(n, 71);
        assert_eq!(n, IDENTITY_PUBLIC_WIRE_LEN);
    }

    #[test]
    fn serialize_wire_layout() {
        let id = stub_identity();
        let mut buf = [0u8; 128];
        serialize_identity_public(&id, &mut buf);

        // address
        assert_eq!(&buf[0..5], &[0xa0, 0xb1, 0xc2, 0xd3, 0xe4]);
        // type
        assert_eq!(buf[5], IDENTITY_TYPE_C25519);
        // dh pubkey first byte
        assert_eq!(buf[6], 0x00);
        // signing pubkey first byte
        assert_eq!(buf[38], 32);
        // no-secret marker
        assert_eq!(buf[70], 0x00);
    }

    #[test]
    fn roundtrip() {
        let id = stub_identity();
        let mut buf = [0u8; 128];
        let n = serialize_identity_public(&id, &mut buf);

        let (parsed, consumed) = deserialize_identity(&buf[..n]).unwrap();
        assert_eq!(consumed, 71);
        assert_eq!(parsed.address, id.address);
        assert_eq!(parsed.public_key, id.public_key);
        assert!(parsed.secret.is_none());
    }

    #[test]
    fn deserialize_too_short() {
        let data = [0u8; 70];
        assert!(deserialize_identity(&data).is_err());
    }

    #[test]
    fn deserialize_rejects_bad_type() {
        let id = stub_identity();
        let mut buf = [0u8; 128];
        serialize_identity_public(&id, &mut buf);
        buf[5] = 0x01; // invalid type
        assert!(deserialize_identity(&buf[..71]).is_err());
    }

    #[test]
    fn deserialize_skips_secret_bytes() {
        let id = stub_identity();
        let mut buf = [0u8; 200];
        serialize_identity_public(&id, &mut buf);
        // Set secret_len to 64 (simulating a secret key follows)
        buf[70] = 64;
        // Fill 64 bytes of "secret"
        buf[71..135].fill(0xAA);
        let (parsed, consumed) = deserialize_identity(&buf[..135]).unwrap();
        assert_eq!(consumed, 71 + 64);
        assert_eq!(parsed.address, id.address);
        assert!(parsed.secret.is_none());
    }

    #[test]
    fn deserialize_rejects_reserved_address() {
        let mut buf = [0u8; 128];
        // all-zero address
        buf[5] = IDENTITY_TYPE_C25519;
        buf[70] = 0x00;
        assert!(deserialize_identity(&buf[..71]).is_err());
    }

    /// A private key is either absent or a full 64-byte C25519 pair.
    #[test]
    fn private_key_length_must_be_0_or_64() {
        let mut buf = [0u8; 256];
        let n = serialize_identity_public(&stub_identity(), &mut buf);
        assert!(deserialize_identity(&buf[..n]).is_ok());
        buf[70] = 32;
        assert!(matches!(
            deserialize_identity(&buf[..n + 32]),
            Err(ProtocolError::InvalidPacket)
        ));
        buf[70] = 64;
        assert_eq!(deserialize_identity(&buf[..n + 64]).unwrap().1, n + 64);
    }
}
