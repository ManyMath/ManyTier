use hmac::{Hmac, Mac};
use sha2::Sha384;

type HmacSha384 = Hmac<Sha384>;

fn kbkdf_hmac_sha384(key: &[u8; 48], label: u8) -> [u8; 48] {
    let message: [u8; 13] = [
        0x00, 0x00, 0x00, 0x00, // iter = 0 (u32 BE)
        0x5A, 0x54,  // "ZT"
        label, // b'0' for K0, b'1' for K1
        0x00,  // separator
        0x00,  // context
        0x00, 0x00, 0x01, 0x80, // output length = 384 bits (BE)
    ];

    let mut mac = HmacSha384::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(&message);
    let result = mac.finalize().into_bytes();

    let mut out = [0u8; 48];
    out.copy_from_slice(&result);
    out
}

/// Derive K0 (GMAC polynomial authentication key) from a 48-byte shared secret via KBKDF-HMAC-SHA384.
pub fn derive_k0(shared_secret: &[u8; 48]) -> [u8; 48] {
    kbkdf_hmac_sha384(shared_secret, b'0')
}

/// Derive K1 (AES-ECB tag encrypt/decrypt + AES-CTR payload key) from a 48-byte shared secret via KBKDF-HMAC-SHA384.
pub fn derive_k1(shared_secret: &[u8; 48]) -> [u8; 48] {
    kbkdf_hmac_sha384(shared_secret, b'1')
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    const TEST_SECRET: [u8; 48] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
        0x2E, 0x2F, 0x30,
    ];

    #[test]
    fn k0_and_k1_differ() {
        let k0 = derive_k0(&TEST_SECRET);
        let k1 = derive_k1(&TEST_SECRET);
        assert_ne!(k0, k1, "K0 and K1 must differ (different labels)");
    }

    #[test]
    fn output_is_48_bytes() {
        let k0 = derive_k0(&TEST_SECRET);
        let k1 = derive_k1(&TEST_SECRET);
        assert_eq!(k0.len(), 48);
        assert_eq!(k1.len(), 48);
    }

    #[test]
    fn deterministic() {
        let k0a = derive_k0(&TEST_SECRET);
        let k0b = derive_k0(&TEST_SECRET);
        let k1a = derive_k1(&TEST_SECRET);
        let k1b = derive_k1(&TEST_SECRET);
        assert_eq!(k0a, k0b, "K0 must be deterministic");
        assert_eq!(k1a, k1b, "K1 must be deterministic");
    }

    #[test]
    fn message_format_matches_vendor() {
        // HMAC-SHA384(TEST_SECRET, msg) for ZeroTierOne's 13-byte KBKDF
        // messages (SHA512.cpp KBKDFHMACSHA384): iter 0, "ZT", the label
        // ('0' for K0, '1' for K1), 0x00, context 0x00, 384 as a u32. The
        // expected keys were computed outside this crate with Python's hmac
        // module, so a wrong message layout here cannot also produce them.
        let expected_k0: [u8; 48] = [
            0xb6, 0x7c, 0x95, 0x84, 0x30, 0x98, 0x8c, 0x70, 0xac, 0x71, 0x10, 0x22, 0x39, 0xdf,
            0x57, 0x27, 0x45, 0xf7, 0x2f, 0x5d, 0x19, 0xa6, 0x47, 0xd2, 0x9e, 0x4a, 0x70, 0xa2,
            0x02, 0x6c, 0xa5, 0xf7, 0x07, 0x77, 0x78, 0x01, 0xe3, 0xac, 0x13, 0xf5, 0xe7, 0x4c,
            0x40, 0xe8, 0x9c, 0x70, 0x2c, 0x6d,
        ];
        let expected_k1: [u8; 48] = [
            0x4c, 0xb6, 0x43, 0xdb, 0xb0, 0x79, 0x7b, 0x3d, 0xa3, 0x89, 0x63, 0x6d, 0x41, 0x72,
            0x20, 0x22, 0x9d, 0x07, 0x65, 0x28, 0x8d, 0xd3, 0xb8, 0x0e, 0x1f, 0x93, 0x0b, 0x30,
            0x10, 0xd5, 0x0e, 0x3e, 0x05, 0x38, 0x69, 0x53, 0xbe, 0x85, 0x3b, 0xb4, 0x45, 0xa5,
            0x84, 0x08, 0x7e, 0x7f, 0x2f, 0xa5,
        ];
        assert_eq!(derive_k0(&TEST_SECRET), expected_k0);
        assert_eq!(derive_k1(&TEST_SECRET), expected_k1);
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let mut other_secret = TEST_SECRET;
        other_secret[0] = 0xFF;
        assert_ne!(derive_k0(&TEST_SECRET), derive_k0(&other_secret));
        assert_ne!(derive_k1(&TEST_SECRET), derive_k1(&other_secret));
    }
}
