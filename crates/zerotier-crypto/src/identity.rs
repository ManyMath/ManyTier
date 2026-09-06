/// ZeroTier V1 identity types: Address, PublicKey, SecretKey, and Identity.
///
/// An identity bundles an x25519 ECDH key pair and an Ed25519 signing key pair
/// with a 40-bit (5-byte) network address derived via memory-hard proof-of-work.
///
/// Identity string format (compatible with official ZeroTier):
/// - Public:  `<10-hex-addr>:0:<128-hex-pubkey>`
/// - Secret:  `<10-hex-addr>:0:<128-hex-pubkey>:<128-hex-privkey>`
extern crate alloc;

use alloc::string::String;

use crate::error::CryptoError;
use crate::hex_util;
use crate::memory_hard;

/// A 5-byte (40-bit) ZeroTier network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address([u8; 5]);

impl Address {
    /// Create a new Address from raw bytes.
    ///
    /// Returns an error if the address is reserved: all zeros, or any
    /// address whose first byte is 0xff. The first source-address byte sits
    /// at packet offset 13, where 0xff marks a fragment, so ZeroTier One
    /// reserves the whole 0xff prefix (node/Address.hpp `isReserved`,
    /// `ZT_ADDRESS_RESERVED_PREFIX`).
    pub fn new(bytes: [u8; 5]) -> Result<Self, CryptoError> {
        if Self::is_reserved(bytes) {
            return Err(CryptoError::InvalidAddress);
        }
        Ok(Address(bytes))
    }

    /// Is this a reserved address (all zeros or 0xff-prefixed)?
    pub fn is_reserved(bytes: [u8; 5]) -> bool {
        bytes == [0x00; 5] || bytes[0] == 0xff
    }

    /// Parse a 10-character lowercase hex string into an Address.
    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        if hex.len() != 10 {
            return Err(CryptoError::InvalidFormat);
        }
        let bytes = hex_util::decode(hex)?;
        let arr: [u8; 5] = bytes.try_into().map_err(|_| CryptoError::InvalidFormat)?;
        Self::new(arr)
    }

    /// Encode this address as a 10-character lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex_util::encode(&self.0)
    }

    /// Get the raw bytes of this address.
    pub fn as_bytes(&self) -> &[u8; 5] {
        &self.0
    }
}

/// ZeroTier V1 identity public key: 32 bytes x25519 ECDH + 32 bytes Ed25519.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// X25519 Diffie-Hellman public key (first 32 bytes).
    pub dh: [u8; 32],
    /// Ed25519 signing/verification public key (last 32 bytes).
    pub signing: [u8; 32],
}

impl PublicKey {
    /// Create a PublicKey from exactly 64 bytes (32 x25519 + 32 ed25519).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut dh = [0u8; 32];
        let mut signing = [0u8; 32];
        dh.copy_from_slice(&bytes[..32]);
        signing.copy_from_slice(&bytes[32..]);
        Ok(PublicKey { dh, signing })
    }

    /// Serialize the public key to 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.dh);
        out[32..].copy_from_slice(&self.signing);
        out
    }

    /// Parse a 128-character hex string into a PublicKey.
    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        if hex.len() != 128 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let bytes = hex_util::decode(hex)?;
        Self::from_bytes(&bytes)
    }

    /// Encode the public key as a 128-character lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex_util::encode(&self.to_bytes())
    }
}

/// ZeroTier V1 identity secret key: x25519 static secret + Ed25519 signing key.
#[derive(Clone)]
pub struct SecretKey {
    /// X25519 Diffie-Hellman secret key.
    pub dh: x25519_dalek::StaticSecret,
    /// Ed25519 signing key.
    pub signing: ed25519_dalek::SigningKey,
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretKey")
            .field("dh", &"[REDACTED]")
            .field("signing", &"[REDACTED]")
            .finish()
    }
}

impl SecretKey {
    /// Create a SecretKey from 64 bytes (32 x25519 + 32 ed25519).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let dh_bytes: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        let signing_bytes: [u8; 32] = bytes[32..]
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(SecretKey {
            dh: x25519_dalek::StaticSecret::from(dh_bytes),
            signing: ed25519_dalek::SigningKey::from_bytes(&signing_bytes),
        })
    }

    /// Serialize the secret key to 64 bytes (32 x25519 + 32 ed25519).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.dh.to_bytes());
        out[32..].copy_from_slice(self.signing.as_bytes());
        out
    }

    /// Encode the secret key as a 128-character lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex_util::encode(&self.to_bytes())
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // StaticSecret and SigningKey zeroize themselves on drop because
        // x25519-dalek/ed25519-dalek are built with their "zeroize" feature
        // enabled (see the workspace Cargo.toml). No additional action needed
        // here; this explicit Drop exists as documentation of that reliance.
    }
}

/// A ZeroTier V1 identity: address + public key + optional secret key.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The 40-bit ZeroTier address derived from the public key via PoW.
    pub address: Address,
    /// The combined x25519 + Ed25519 public key.
    pub public_key: PublicKey,
    /// The secret key, if available (not present for public-only identities).
    pub secret: Option<SecretKey>,
}

impl Identity {
    /// Generate a new identity with valid proof-of-work.
    ///
    /// This loops, generating key pairs until the memory-hard hash satisfies
    /// the hashcash threshold (digest[0] < 17). The RNG must be cryptographically
    /// secure.
    ///
    /// Uses `rand_core::RngCore` to generate random bytes, then constructs
    /// dalek key types from those bytes (avoiding rand_core version conflicts
    /// between 0.6 used by dalek and 0.9 used by this crate).
    pub fn generate(rng: &mut impl rand_core::RngCore) -> Result<Self, CryptoError> {
        loop {
            // Generate 32 random bytes for x25519 secret
            let mut dh_secret_bytes = [0u8; 32];
            rng.fill_bytes(&mut dh_secret_bytes);
            let dh_secret = x25519_dalek::StaticSecret::from(dh_secret_bytes);
            let dh_public = x25519_dalek::PublicKey::from(&dh_secret);

            // Generate 32 random bytes for ed25519 signing key
            let mut signing_secret_bytes = [0u8; 32];
            rng.fill_bytes(&mut signing_secret_bytes);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_secret_bytes);
            let verifying_key = signing_key.verifying_key();

            // Concatenate public keys: x25519 (32B) + ed25519 (32B) = 64B
            let mut pub_combined = [0u8; 64];
            pub_combined[..32].copy_from_slice(dh_public.as_bytes());
            pub_combined[32..].copy_from_slice(verifying_key.as_bytes());

            // Compute memory-hard hash
            let digest = memory_hard::compute_memory_hard_hash(&pub_combined);

            // Check hashcash threshold
            if let Some(addr_bytes) = memory_hard::derive_address(&digest) {
                // Validate address
                if let Ok(address) = Address::new(addr_bytes) {
                    let public_key = PublicKey {
                        dh: *dh_public.as_bytes(),
                        signing: *verifying_key.as_bytes(),
                    };
                    let secret = SecretKey {
                        dh: dh_secret,
                        signing: signing_key,
                    };
                    return Ok(Identity {
                        address,
                        public_key,
                        secret: Some(secret),
                    });
                }
            }
            // PoW not satisfied or address invalid -- retry with new keys
        }
    }

    /// Validate that this identity's address matches its public key.
    ///
    /// Recomputes the memory-hard hash from the public key and verifies
    /// the address matches the last 5 bytes of the digest.
    pub fn validate_address(&self) -> bool {
        let pub_bytes = self.public_key.to_bytes();
        let digest = memory_hard::compute_memory_hard_hash(&pub_bytes);
        if let Some(addr_bytes) = memory_hard::derive_address(&digest) {
            addr_bytes == *self.address.as_bytes()
        } else {
            false
        }
    }

    /// Serialize to public identity string: `<address>:0:<public_key_hex>`
    pub fn to_public_string(&self) -> String {
        let mut s = String::with_capacity(10 + 1 + 1 + 1 + 128);
        s.push_str(&self.address.to_hex());
        s.push_str(":0:");
        s.push_str(&self.public_key.to_hex());
        s
    }

    /// Serialize to secret identity string: `<address>:0:<public_key_hex>:<secret_key_hex>`
    ///
    /// Returns `None` if this identity has no secret key.
    pub fn to_secret_string(&self) -> Option<String> {
        let secret = self.secret.as_ref()?;
        let mut s = String::with_capacity(10 + 1 + 1 + 1 + 128 + 1 + 128);
        s.push_str(&self.address.to_hex());
        s.push_str(":0:");
        s.push_str(&self.public_key.to_hex());
        s.push(':');
        s.push_str(&secret.to_hex());
        Some(s)
    }

    /// Parse an identity from a string.
    ///
    /// Accepts both public (`addr:0:pubkey`) and secret (`addr:0:pubkey:privkey`) formats.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let parts: alloc::vec::Vec<&str> = s.split(':').collect();
        if parts.len() < 3 || parts.len() > 4 {
            return Err(CryptoError::InvalidFormat);
        }

        // Field 0: 10-hex-char address
        let address = Address::from_hex(parts[0])?;

        // Field 1: must be "0" (V1 identity type)
        if parts[1] != "0" {
            return Err(CryptoError::UnsupportedIdentityType);
        }

        // Field 2: 128-hex-char public key
        let public_key = PublicKey::from_hex(parts[2])?;

        // Field 3 (optional): 128-hex-char secret key
        let secret = if parts.len() == 4 {
            Some(SecretKey::from_bytes(
                &hex_util::decode(parts[3]).map_err(|_| CryptoError::InvalidFormat)?,
            )?)
        } else {
            None
        };

        Ok(Identity {
            address,
            public_key,
            secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Address tests ---

    #[test]
    fn address_from_hex_valid() {
        let addr = Address::from_hex("a0b1c2d3e4").unwrap();
        assert_eq!(addr.0, [0xa0, 0xb1, 0xc2, 0xd3, 0xe4]);
    }

    #[test]
    fn address_to_hex_lowercase() {
        let addr = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0xe4]).unwrap();
        let hex = addr.to_hex();
        assert_eq!(hex, "a0b1c2d3e4");
        assert_eq!(hex.len(), 10);
    }

    #[test]
    fn address_from_hex_rejects_wrong_length() {
        assert!(Address::from_hex("abc").is_err());
        assert!(Address::from_hex("a0b1c2d3e4ff").is_err());
        assert!(Address::from_hex("").is_err());
    }

    #[test]
    fn address_rejects_all_zeros() {
        assert!(Address::new([0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn address_rejects_all_ones() {
        assert!(Address::new([0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn address_accepts_valid() {
        assert!(Address::new([0x01, 0x00, 0x00, 0x00, 0x00]).is_ok());
        assert!(Address::new([0xfe, 0xff, 0xff, 0xff, 0xff]).is_ok());
    }

    // --- PublicKey tests ---

    #[test]
    fn public_key_from_bytes_exact_64() {
        let bytes = [0x42u8; 64];
        assert!(PublicKey::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn public_key_from_bytes_rejects_wrong_length() {
        assert!(PublicKey::from_bytes(&[0u8; 63]).is_err());
        assert!(PublicKey::from_bytes(&[0u8; 65]).is_err());
        assert!(PublicKey::from_bytes(&[0u8; 32]).is_err());
    }

    #[test]
    fn public_key_roundtrip() {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let pk = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.to_bytes(), bytes);
    }

    #[test]
    fn identity_parse_validates_known_official_identity_public() {
        // Captured from a local `zerotier-one` 1.14.2 test run (identity.public format).
        // If this fails, our public-key byte ordering does not match official, which would
        // break DH shared-secret derivation and interop with official peers.
        let s = "4b9ccad987:0:ad8a2faec3b1ada48c39b28c9d07edad693279dd7f0a2d3ad718ae877ea51373c6ffccdfcaa1cf0f497ece33a949979bdf7fd564527bc5b95da3e9346912916a";
        let id = Identity::parse(s).expect("failed to parse identity.public");
        assert!(
            id.validate_address(),
            "official identity.public should validate its address against the public key"
        );
    }

    // --- SecretKey tests ---

    #[test]
    fn secret_key_roundtrip() {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let sk = SecretKey::from_bytes(&bytes).unwrap();
        let out = sk.to_bytes();
        // x25519 clamps the secret key, so bytes may differ.
        // But ed25519 portion (bytes 32..64) should roundtrip exactly.
        assert_eq!(&out[32..], &bytes[32..]);
    }

    #[test]
    fn secret_key_rejects_wrong_length() {
        assert!(SecretKey::from_bytes(&[0u8; 63]).is_err());
        assert!(SecretKey::from_bytes(&[0u8; 65]).is_err());
    }

    // --- Identity string tests ---

    #[test]
    fn identity_to_public_string_format() {
        let addr = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0xe4]).unwrap();
        let pk = PublicKey::from_bytes(&[0x42u8; 64]).unwrap();
        let id = Identity {
            address: addr,
            public_key: pk,
            secret: None,
        };
        let s = id.to_public_string();
        let parts: alloc::vec::Vec<&str> = s.split(':').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 10); // address hex
        assert_eq!(parts[1], "0"); // identity type
        assert_eq!(parts[2].len(), 128); // public key hex
    }

    #[test]
    fn identity_to_secret_string_format() {
        let addr = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0xe4]).unwrap();
        let pk = PublicKey::from_bytes(&[0x42u8; 64]).unwrap();
        let sk = SecretKey::from_bytes(&[0x01u8; 64]).unwrap();
        let id = Identity {
            address: addr,
            public_key: pk,
            secret: Some(sk),
        };
        let s = id.to_secret_string().unwrap();
        let parts: alloc::vec::Vec<&str> = s.split(':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0].len(), 10);
        assert_eq!(parts[1], "0");
        assert_eq!(parts[2].len(), 128);
        assert_eq!(parts[3].len(), 128);
    }

    #[test]
    fn identity_to_secret_string_none_without_secret() {
        let addr = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0xe4]).unwrap();
        let pk = PublicKey::from_bytes(&[0x42u8; 64]).unwrap();
        let id = Identity {
            address: addr,
            public_key: pk,
            secret: None,
        };
        assert!(id.to_secret_string().is_none());
    }

    #[test]
    fn identity_from_str_roundtrip_public() {
        let addr = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0xe4]).unwrap();
        let pk = PublicKey::from_bytes(&[0x42u8; 64]).unwrap();
        let id = Identity {
            address: addr,
            public_key: pk,
            secret: None,
        };
        let s = id.to_public_string();
        let parsed = Identity::parse(&s).unwrap();
        assert_eq!(parsed.address, id.address);
        assert_eq!(parsed.public_key, id.public_key);
        assert!(parsed.secret.is_none());
    }

    #[test]
    fn identity_from_str_roundtrip_secret() {
        let addr = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0xe4]).unwrap();
        let pk = PublicKey::from_bytes(&[0x42u8; 64]).unwrap();
        let sk = SecretKey::from_bytes(&[0x01u8; 64]).unwrap();
        let id = Identity {
            address: addr,
            public_key: pk,
            secret: Some(sk),
        };
        let s = id.to_secret_string().unwrap();
        let parsed = Identity::parse(&s).unwrap();
        assert_eq!(parsed.address, id.address);
        assert_eq!(parsed.public_key, id.public_key);
        assert!(parsed.secret.is_some());
        // Ed25519 portion of secret should roundtrip
        assert_eq!(
            &parsed.secret.unwrap().to_bytes()[32..],
            &id.secret.unwrap().to_bytes()[32..]
        );
    }

    #[test]
    fn identity_from_str_rejects_bad_type() {
        let s = "a0b1c2d3e4:1:";
        assert!(Identity::parse(s).is_err());
    }

    #[test]
    fn identity_from_str_rejects_too_few_parts() {
        assert!(Identity::parse("a0b1c2d3e4:0").is_err());
    }

    #[test]
    fn identity_from_str_rejects_too_many_parts() {
        let pk_hex = "42".repeat(64);
        let sk_hex = "01".repeat(64);
        let s = alloc::format!("a0b1c2d3e4:0:{}:{}:extra", pk_hex, sk_hex);
        assert!(Identity::parse(&s).is_err());
    }

    // --- Identity generation test (expensive!) ---

    #[test]
    fn generate_identity_produces_valid_address() {
        // Use a seeded RNG for determinism
        // We'll use a simple xorshift-based PRNG seeded from fixed value
        let mut rng = SimpleRng::new(0xDEADBEEF_CAFEBABE);
        let id = Identity::generate(&mut rng).unwrap();

        // The generated identity should have a valid address
        assert!(id.validate_address());

        // Should have a secret key
        assert!(id.secret.is_some());

        // Address should not be reserved
        assert_ne!(id.address.as_bytes(), &[0u8; 5]);
        assert_ne!(id.address.as_bytes(), &[0xff; 5]);
    }

    #[test]
    fn generated_identity_string_roundtrips() {
        let mut rng = SimpleRng::new(0x1234567890ABCDEF);
        let id = Identity::generate(&mut rng).unwrap();

        // Public string roundtrip
        let pub_str = id.to_public_string();
        let parsed_pub = Identity::parse(&pub_str).unwrap();
        assert_eq!(parsed_pub.address, id.address);
        assert_eq!(parsed_pub.public_key, id.public_key);

        // Secret string roundtrip
        let sec_str = id.to_secret_string().unwrap();
        let parsed_sec = Identity::parse(&sec_str).unwrap();
        assert_eq!(parsed_sec.address, id.address);
        assert_eq!(parsed_sec.public_key, id.public_key);
    }

    /// Simple xorshift64 PRNG for deterministic testing.
    /// NOT cryptographically secure -- only for test reproducibility.
    struct SimpleRng {
        state: u64,
    }

    impl SimpleRng {
        fn new(seed: u64) -> Self {
            SimpleRng {
                state: if seed == 0 { 1 } else { seed },
            }
        }
    }

    impl rand_core::RngCore for SimpleRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            x
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut i = 0;
            while i < dest.len() {
                let val = self.next_u64().to_le_bytes();
                let remaining = dest.len() - i;
                let to_copy = core::cmp::min(8, remaining);
                dest[i..i + to_copy].copy_from_slice(&val[..to_copy]);
                i += to_copy;
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[test]
    fn address_new_rejects_reserved_prefix() {
        assert!(Address::new([0x00; 5]).is_err());
        assert!(Address::new([0xff; 5]).is_err());
        // Any 0xff-prefixed address is reserved, not only all ones.
        assert!(Address::new([0xff, 0x01, 0x02, 0x03, 0x04]).is_err());
        assert!(Address::new([0xfe, 0xff, 0xff, 0xff, 0xff]).is_ok());
    }
}
