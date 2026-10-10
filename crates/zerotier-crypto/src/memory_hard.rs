/// Memory-hard proof-of-work hash for ZeroTier V1 identity address derivation.
///
/// This implements the algorithm from ZeroTierOne/node/Identity.cpp
/// `_computeMemoryHardHash()`. The function fills a 2MB buffer via
/// Salsa20 (20 rounds) in a CBC-like chaining mode, then uses that
/// buffer as a lookup table to swap 64-bit words into the digest while
/// continuing the same Salsa20 stream.
///
/// IMPORTANT: This uses Salsa20 (20 rounds), NOT Salsa20/12. The 12-round
/// variant is used for packet encryption only (ZeroTierOne node/Identity.cpp
/// `_computeMemoryHardHash` vs. node/Packet.cpp `armor`).
extern crate alloc;
use alloc::vec;

use salsa20::Salsa20;
use sha2::{Digest, Sha512};

use cipher::{KeyIvInit, StreamCipher};

/// Size of the memory buffer used in the PoW computation (2MB).
const MEMORY_SIZE: usize = 2_097_152;

/// Number of 64-byte blocks in the memory buffer.
const NUM_BLOCKS: usize = MEMORY_SIZE / 64;

/// Hashcash threshold: digest[0] must be less than this for a valid address.
pub const HASHCASH_THRESHOLD: u8 = 17;

/// Compute the memory-hard hash of a 64-byte public key (32B x25519 + 32B ed25519).
///
/// Algorithm (from ZeroTierOne/node/Identity.cpp `_computeMemoryHardHash`):
///
/// 1. SHA-512 the public key to get a 64-byte digest
/// 2. Initialize Salsa20 with key=digest[0..32], nonce=digest[32..40]
/// 3. Fill a 2MB buffer in 64-byte blocks:
///    - First block: encrypt 64 zero bytes
///    - Subsequent blocks: copy the previous ciphertext block, then encrypt
/// 4. Iterate over the 2MB buffer as big-endian u64 pairs:
///    - First word selects one of the 8 digest u64 slots
///    - Second word selects one of the 262_144 genmem u64 slots
///    - Swap those raw 8-byte words
///    - Encrypt the 64-byte digest in place with the same Salsa20 stream
pub fn compute_memory_hard_hash(public_key: &[u8; 64]) -> [u8; 64] {
    // Step 1: SHA-512 of concatenated public keys
    let mut hasher = Sha512::new();
    hasher.update(public_key);
    let mut digest: [u8; 64] = hasher.finalize().into();

    // Step 2: Allocate 2MB buffer
    let mut genmem = vec![0u8; MEMORY_SIZE];

    // Step 3: Initialize Salsa20 (20 rounds) with key and nonce from digest.
    let key: [u8; 32] = digest[0..32].try_into().unwrap();
    let nonce: [u8; 8] = digest[32..40].try_into().unwrap();
    let mut s20 = Salsa20::new(&key.into(), &nonce.into());

    // Fill genmem in 64-byte blocks with CBC-like chaining.
    // The first block starts as zeroes, then each following block copies the
    // previous ciphertext block before being encrypted in place.
    s20.apply_keystream(&mut genmem[0..64]);
    for i in 1..NUM_BLOCKS {
        let prev_start = (i - 1) * 64;
        let curr_start = i * 64;
        let mut prev_block = [0u8; 64];
        prev_block.copy_from_slice(&genmem[prev_start..prev_start + 64]);
        genmem[curr_start..curr_start + 64].copy_from_slice(&prev_block);
        s20.apply_keystream(&mut genmem[curr_start..curr_start + 64]);
    }

    // Step 4: Use genmem as a lookup table to swap raw 64-bit words into the
    // digest, matching the official implementation's pointer-cast behavior.
    let genmem_words = MEMORY_SIZE / 8;
    let digest_words = 64 / 8;
    let mut i = 0usize;
    while i < genmem_words {
        let idx1 = u64::from_be_bytes(genmem[i * 8..i * 8 + 8].try_into().unwrap()) as usize
            % digest_words;
        i += 1;
        let idx2 = u64::from_be_bytes(genmem[i * 8..i * 8 + 8].try_into().unwrap()) as usize
            % genmem_words;
        i += 1;

        let digest_offset = idx1 * 8;
        let genmem_offset = idx2 * 8;

        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(&genmem[genmem_offset..genmem_offset + 8]);
        genmem[genmem_offset..genmem_offset + 8]
            .copy_from_slice(&digest[digest_offset..digest_offset + 8]);
        digest[digest_offset..digest_offset + 8].copy_from_slice(&tmp);

        s20.apply_keystream(&mut digest);
    }

    digest
}

/// Derive a 5-byte ZeroTier address from a memory-hard hash digest.
///
/// Returns `None` if:
/// - The hashcash PoW is not satisfied (digest[0] >= 17)
/// - The derived address is reserved (all zeros or 0xff-prefixed)
pub fn derive_address(digest: &[u8; 64]) -> Option<[u8; 5]> {
    if digest[0] >= HASHCASH_THRESHOLD {
        return None; // PoW not satisfied
    }
    let mut addr = [0u8; 5];
    addr.copy_from_slice(&digest[59..64]);
    // Reject reserved addresses (all zeros or the 0xff fragment prefix)
    if crate::identity::Address::is_reserved(addr) {
        return None;
    }
    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_memory_hard_hash_produces_64_bytes() {
        let pub_key = [0x42u8; 64];
        let digest = compute_memory_hard_hash(&pub_key);
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn compute_memory_hard_hash_deterministic() {
        let pub_key = [0x42u8; 64];
        let digest1 = compute_memory_hard_hash(&pub_key);
        let digest2 = compute_memory_hard_hash(&pub_key);
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn compute_memory_hard_hash_different_inputs_different_outputs() {
        let pub_key1 = [0x42u8; 64];
        let mut pub_key2 = [0x42u8; 64];
        pub_key2[0] = 0x43;
        let digest1 = compute_memory_hard_hash(&pub_key1);
        let digest2 = compute_memory_hard_hash(&pub_key2);
        assert_ne!(digest1, digest2);
    }

    #[test]
    fn derive_address_rejects_high_first_byte() {
        let mut digest = [0u8; 64];
        digest[0] = 17; // exactly at threshold
        assert!(derive_address(&digest).is_none());

        digest[0] = 255;
        assert!(derive_address(&digest).is_none());
    }

    #[test]
    fn derive_address_accepts_low_first_byte() {
        let mut digest = [0u8; 64];
        digest[0] = 16; // just under threshold
                        // But address would be all zeros -- reserved
                        // Set address bytes to something valid
        digest[59] = 0x01;
        digest[60] = 0x02;
        digest[61] = 0x03;
        digest[62] = 0x04;
        digest[63] = 0x05;
        let addr = derive_address(&digest);
        assert!(addr.is_some());
        assert_eq!(addr.unwrap(), [0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn derive_address_returns_last_5_bytes() {
        let mut digest = [0u8; 64];
        digest[0] = 5; // satisfies PoW
        digest[59] = 0xAA;
        digest[60] = 0xBB;
        digest[61] = 0xCC;
        digest[62] = 0xDD;
        digest[63] = 0xEE;
        assert_eq!(
            derive_address(&digest).unwrap(),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE]
        );
    }

    #[test]
    fn official_identity_vector_matches_official_address() {
        let public_key: [u8; 64] = crate::hex_util::decode(
            "32c0edec3768cd88dda9f173bab28d8dd0a449ccaf0d469fb3bdad68403b527b\
             5f795abc5445de6e5234ca6a22f43539bb4d47c4e03df4cc5d426e91db9c2def",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let digest = compute_memory_hard_hash(&public_key);
        assert_eq!(
            derive_address(&digest),
            Some([0x00, 0x7a, 0xf6, 0x4f, 0x5d])
        );
    }

    #[test]
    fn derive_address_rejects_all_zeros() {
        let mut digest = [0u8; 64];
        digest[0] = 5; // satisfies PoW
                       // address bytes are all zero (reserved)
        assert!(derive_address(&digest).is_none());
    }

    #[test]
    fn derive_address_rejects_all_ones() {
        let mut digest = [0u8; 64];
        digest[0] = 5; // satisfies PoW
        digest[59] = 0xff;
        digest[60] = 0xff;
        digest[61] = 0xff;
        digest[62] = 0xff;
        digest[63] = 0xff;
        assert!(derive_address(&digest).is_none());
    }
}
