/// ZeroTier V1 per-packet encryption using Salsa20/12 with key mangling
/// and Poly1305 MAC (truncated to 8 bytes).
///
/// This implements the full armor/dearmor encrypt-then-MAC flow as specified
/// in the ZeroTier protocol (Packet.hpp).
use cipher::{KeyIvInit, StreamCipher};
use salsa20::Salsa12;

use crate::error::CryptoError;
use crate::poly::{compute_mac, verify_mac};

// ZeroTier packet header field offsets and sizes
pub const PACKET_IV_OFFSET: usize = 0;
pub const PACKET_IV_LEN: usize = 8;
pub const PACKET_DEST_OFFSET: usize = 8;
pub const PACKET_SOURCE_OFFSET: usize = 13;
pub const PACKET_FLAGS_OFFSET: usize = 18;
pub const PACKET_MAC_OFFSET: usize = 19;
pub const PACKET_MAC_LEN: usize = 8;
pub const PACKET_VERB_OFFSET: usize = 27;
pub const PACKET_MIN_LEN: usize = 28;
pub const PACKET_HEADER_LEN: usize = 27;

/// Mangle a 32-byte shared secret with packet header metadata to produce
/// a per-packet encryption key.
///
/// The mangling XORs the shared secret with packet header fields:
/// - Bytes 0..18: XOR with IV (8 bytes) + destination (5 bytes) + source (5 bytes)
/// - Byte 18: XOR with flags byte, hop count masked off (& 0xf8)
/// - Bytes 19..21: XOR with packet size as little-endian u16
/// - Bytes 21..32: unchanged from shared secret
pub fn mangle_key(shared_secret: &[u8; 48], packet_header: &[u8], packet_size: usize) -> [u8; 32] {
    let mut key = [0u8; 32];

    // XOR first 18 bytes with packet bytes 0..18 (IV + dest + source)
    for i in 0..18 {
        key[i] = shared_secret[i] ^ packet_header[i];
    }

    // XOR byte 18 with flags (hop count masked off: & 0xf8)
    key[18] = shared_secret[18] ^ (packet_header[18] & 0xf8);

    // XOR bytes 19-20 with packet size (little-endian u16)
    let size = packet_size as u16;
    key[19] = shared_secret[19] ^ (size as u8);
    key[20] = shared_secret[20] ^ ((size >> 8) as u8);

    // Bytes 21-31 unchanged from shared secret
    key[21..32].copy_from_slice(&shared_secret[21..32]);

    key
}

fn extract_poly1305_key_and_advance(cipher: &mut Salsa12) -> [u8; 32] {
    let mut poly_key = [0u8; 32];
    cipher.apply_keystream(&mut poly_key);

    // ZeroTierOne 1.14.2 drives Salsa20 via `Salsa20::crypt12()`, which always
    // advances by a full 64-byte block even when asked to emit only the first
    // 32 bytes for the Poly1305 key. Packet payload crypt therefore begins at
    // byte 64 of the keystream, not byte 32. See node/Salsa20.cpp's
    // `bytes <= 64` early-return path.
    let mut discard = [0u8; 32];
    cipher.apply_keystream(&mut discard);

    poly_key
}

/// Encrypt a packet in-place using the ZeroTier V1 encrypt-then-MAC scheme.
///
/// 1. Mangle the shared secret with packet header to get per-packet key
/// 2. Initialize Salsa20/12 with mangled key and 8-byte IV from packet[0..8]
/// 3. Generate Poly1305 one-time key from first 32 bytes of keystream
/// 4. If `encrypt_payload` is true, encrypt verb + payload at offset 27+
/// 5. Compute Poly1305 MAC over (encrypted) payload
/// 6. Store first 8 bytes of MAC tag at packet[19..27]
pub fn armor_packet(
    shared_secret: &[u8; 48],
    packet: &mut [u8],
    encrypt_payload: bool,
) -> Result<(), CryptoError> {
    if packet.len() < PACKET_MIN_LEN {
        return Err(CryptoError::InvalidFormat);
    }

    // The cipher suite bits must say what was done, or the receiver will
    // not decrypt; set them as ZeroTierOne's Packet::armor does, before
    // they are mixed into the key.
    let suite: u8 = if encrypt_payload { 1 } else { 0 };
    packet[PACKET_FLAGS_OFFSET] = (packet[PACKET_FLAGS_OFFSET] & !0x38) | (suite << 3);

    let mangled = mangle_key(shared_secret, packet, packet.len());

    // Nonce is 8 bytes from packet[0..8] (the IV/Packet ID field)
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);

    let mut cipher = Salsa12::new(&mangled.into(), &nonce.into());

    // Generate Poly1305 one-time key from first 32 bytes of keystream
    let poly_key = extract_poly1305_key_and_advance(&mut cipher);

    // Encrypt verb + payload (offset 27+) if requested
    if encrypt_payload && packet.len() > PACKET_VERB_OFFSET {
        cipher.apply_keystream(&mut packet[PACKET_VERB_OFFSET..]);
    }

    // ZeroTier computes the Poly1305 MAC over the payload starting at the verb
    // byte. The header participates through key mangling, not by being MACed
    // directly.
    let mac = compute_mac(&poly_key, &packet[PACKET_VERB_OFFSET..]);

    // Store 8-byte MAC at packet[19..27]
    packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN].copy_from_slice(&mac);

    Ok(())
}

/// Decrypt and verify a packet in-place using an UNMANGLED key.
/// ZeroTier uses an unmangled null key `[0; 32]` for root HELLOs.
pub fn dearmor_packet_unmangled(key: &[u8; 32], packet: &mut [u8]) -> Result<(), CryptoError> {
    if packet.len() < PACKET_MIN_LEN {
        return Err(CryptoError::InvalidFormat);
    }

    let mut saved_mac = [0u8; 8];
    saved_mac.copy_from_slice(&packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN]);

    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);

    let mut cipher = Salsa12::new(&(*key).into(), &nonce.into());

    let poly_key = extract_poly1305_key_and_advance(&mut cipher);

    if !verify_mac(&poly_key, &packet[PACKET_VERB_OFFSET..], &saved_mac) {
        return Err(CryptoError::MacVerificationFailed);
    }
    // Caller decides whether to decrypt payload; this helper is only used for
    // cipher suite 0 HELLO packets, which do not encrypt the payload.

    Ok(())
}

/// Encrypt a packet in-place using an UNMANGLED key.
pub fn armor_packet_unmangled(
    key: &[u8; 32],
    packet: &mut [u8],
    encrypt_payload: bool,
) -> Result<(), CryptoError> {
    if packet.len() < PACKET_MIN_LEN {
        return Err(CryptoError::InvalidFormat);
    }

    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);

    let mut cipher = Salsa12::new(&(*key).into(), &nonce.into());

    let poly_key = extract_poly1305_key_and_advance(&mut cipher);

    if encrypt_payload && packet.len() > PACKET_VERB_OFFSET {
        cipher.apply_keystream(&mut packet[PACKET_VERB_OFFSET..]);
    }

    let mac = compute_mac(&poly_key, &packet[PACKET_VERB_OFFSET..]);

    packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN].copy_from_slice(&mac);

    Ok(())
}

/// Decrypt and verify a packet in-place using the ZeroTier V1 scheme.
///
/// 1. Save existing MAC from packet[19..27]
/// 2. Mangle key and initialize Salsa20/12
/// 3. Generate Poly1305 one-time key
/// 4. Verify MAC over encrypted payload -- if invalid, return error
/// 5. Decrypt verb + payload at offset 27+
pub fn dearmor_packet(shared_secret: &[u8; 48], packet: &mut [u8]) -> Result<(), CryptoError> {
    if packet.len() < PACKET_MIN_LEN {
        return Err(CryptoError::InvalidFormat);
    }

    // Save existing MAC
    let mut saved_mac = [0u8; 8];
    saved_mac.copy_from_slice(&packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN]);

    let mangled = mangle_key(shared_secret, packet, packet.len());

    // Nonce is 8 bytes from packet[0..8]
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);

    let mut cipher = Salsa12::new(&mangled.into(), &nonce.into());

    // Generate Poly1305 one-time key
    let poly_key = extract_poly1305_key_and_advance(&mut cipher);

    if !verify_mac(&poly_key, &packet[PACKET_VERB_OFFSET..], &saved_mac) {
        return Err(CryptoError::MacVerificationFailed);
    }

    let cipher_suite = (packet[PACKET_FLAGS_OFFSET] >> 3) & 0x07;
    if cipher_suite == 1 {
        // Decrypt verb + payload (cipher suite 1)
        cipher.apply_keystream(&mut packet[PACKET_VERB_OFFSET..]);
    }

    Ok(())
}

/// Encrypt or decrypt a subrange of a packet payload, matching ZeroTier's
/// `Packet::cryptField()` helper.
///
/// This is used for the HELLO moon-section trailer, which is field-encrypted
/// even when the outer packet uses cipher suite 0.
///
/// See ZeroTierOne 1.14.2 node/Packet.cpp:1142-1152. Upstream's
/// `Packet::cryptField` is a DISTINCT helper from `Packet::armor` /
/// `Packet::dearmor`. It intentionally:
///
/// 1. Uses the RAW `peer->key()` as the Salsa20/12 key: NO key mangling.
/// 2. Takes the 8-byte IV from `packet[0..8]` and MASKS byte 7 with `& 0xf8`,
///    clearing the low 3 bits (which are the hop-count field in the outer
///    packet header flags).
/// 3. Starts keystream from offset 0: NO skip of the first 32 bytes
///    (the Poly1305 key-material skip is specific to `armor`/`dearmor`,
///    not to `cryptField`).
///
/// This replaces an earlier ManyTier implementation that mistakenly
/// copied the `armor`/`dearmor` setup (mangled key + raw IV + 32-byte skip).
/// That divergence was silent for ManyTier-to-ManyTier traffic because both
/// sides used the same setup and self-consistently round-tripped, but it
/// caused upstream 1.14.2 `_doHELLO` to decrypt the ManyTier moon-count to
/// garbage, triggering a silent `std::out_of_range` in the moon-list loop
/// at node/IncomingPacket.cpp:489-497.
pub fn crypt_packet_field(
    shared_secret: &[u8; 48],
    packet: &mut [u8],
    start: usize,
    len: usize,
) -> Result<(), CryptoError> {
    if packet.len() < PACKET_MIN_LEN || start > packet.len() || start + len > packet.len() {
        return Err(CryptoError::InvalidFormat);
    }

    // See ZeroTierOne 1.14.2 node/Packet.cpp:1142-1152.
    // Raw IV with low 3 bits of byte 7 masked off.
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);
    nonce[7] &= 0xf8;

    // RAW shared secret (first 32 bytes) as the Salsa20/12 key: no mangling.
    // Keystream from offset 0: no 32-byte skip.
    let key: [u8; 32] = shared_secret[..32].try_into().unwrap();
    let mut cipher = Salsa12::new(&key.into(), &nonce.into());
    cipher.apply_keystream(&mut packet[start..start + len]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_cipher_suite(pkt: &mut [u8], suite: u8) {
        // Flags byte layout: FFCCCHHH (2 flag bits, 3 cipher suite, 3 hop count)
        pkt[PACKET_FLAGS_OFFSET] = (pkt[PACKET_FLAGS_OFFSET] & 0xC7) | ((suite & 0x07) << 3);
    }

    // Helper: create a minimal test packet (28 bytes minimum)
    fn make_test_packet(cipher_suite: u8) -> [u8; 64] {
        let mut pkt = [0u8; 64];
        // IV / Packet ID (bytes 0..8)
        pkt[0..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        // Destination address (bytes 8..13)
        pkt[8..13].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        // Source address (bytes 13..18)
        pkt[13..18].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);
        // Flags byte (byte 18) -- hop count 2
        pkt[18] = 0x02;
        set_cipher_suite(&mut pkt, cipher_suite);
        // MAC field (bytes 19..27) -- will be overwritten by armor
        // Verb (byte 27)
        pkt[27] = 0x05; // some verb
                        // Payload (bytes 28..64)
        for (i, b) in pkt[28..64].iter_mut().enumerate() {
            *b = ((i + 28) & 0xFF) as u8;
        }
        pkt
    }

    fn test_shared_secret() -> [u8; 48] {
        let mut secret = [0u8; 48];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(0x42);
        }
        secret
    }

    #[test]
    fn dearmor_matches_official_ok_hello_capture() {
        let shared_secret_32 = [
            0x15, 0x79, 0x95, 0x8b, 0x95, 0x6d, 0xb9, 0x4d, 0x18, 0xfa, 0xb1, 0x0f, 0x13, 0x48,
            0xcc, 0x0d, 0x98, 0x7d, 0x26, 0xa1, 0x5d, 0x24, 0x88, 0x64, 0xaf, 0xe4, 0x29, 0x41,
            0xb0, 0xa2, 0xe4, 0x9f,
        ];
        let mut shared_secret = [0u8; 48];
        shared_secret[..32].copy_from_slice(&shared_secret_32);
        let mut packet = [
            0x5f, 0x49, 0x89, 0x44, 0xa5, 0xd8, 0x1d, 0x63, 0x0f, 0x7a, 0x0b, 0x04, 0x3f, 0x46,
            0xa5, 0xb4, 0xd1, 0xe8, 0x88, 0x9e, 0x32, 0x4a, 0x99, 0x7c, 0xa9, 0x8c, 0x83, 0x1e,
            0x4a, 0xbb, 0x10, 0x84, 0x07, 0x21, 0xa0, 0x2a, 0x8a, 0x1d, 0xce, 0x12, 0x11, 0x1a,
            0xe9, 0xd4, 0x96, 0xd9, 0x00, 0x1c, 0xc4, 0x04, 0x6a, 0x2a, 0xa3, 0x8f, 0x0c, 0xca,
            0xc4, 0xfc, 0x8f,
        ];

        dearmor_packet(&shared_secret, &mut packet).expect("captured OK(HELLO) should decrypt");

        assert_eq!(packet[PACKET_VERB_OFFSET] & 0x1f, 0x03);
        assert_eq!(packet[PACKET_VERB_OFFSET + 1], 0x01);
    }

    // --- mangle_key tests ---

    #[test]
    fn mangle_key_xors_first_18_bytes() {
        let secret = test_shared_secret();
        let pkt = make_test_packet(1);
        let mangled = mangle_key(&secret, &pkt, pkt.len());

        for i in 0..18 {
            assert_eq!(mangled[i], secret[i] ^ pkt[i], "byte {} mismatch", i);
        }
    }

    #[test]
    fn mangle_key_masks_hop_count() {
        let secret = test_shared_secret();
        let pkt = make_test_packet(1);
        let mangled = mangle_key(&secret, &pkt, pkt.len());

        // Byte 18: flags & 0xf8 masks off bottom 3 bits (hop count)
        assert_eq!(mangled[18], secret[18] ^ (pkt[18] & 0xf8));
    }

    #[test]
    fn mangle_key_xors_size_little_endian() {
        let secret = test_shared_secret();
        let pkt = make_test_packet(1);
        let size = pkt.len() as u16;
        let mangled = mangle_key(&secret, &pkt, pkt.len());

        assert_eq!(mangled[19], secret[19] ^ (size as u8));
        assert_eq!(mangled[20], secret[20] ^ ((size >> 8) as u8));
    }

    #[test]
    fn mangle_key_leaves_bytes_21_to_31_unchanged() {
        let secret = test_shared_secret();
        let pkt = make_test_packet(1);
        let mangled = mangle_key(&secret, &pkt, pkt.len());

        for i in 21..32 {
            assert_eq!(mangled[i], secret[i], "byte {} should be unchanged", i);
        }
    }

    // --- armor/dearmor tests ---

    #[test]
    fn armor_encrypt_true_encrypts_payload() {
        let secret = test_shared_secret();
        let mut pkt = make_test_packet(1);
        let original_payload = pkt[27..].to_vec();

        armor_packet(&secret, &mut pkt, true).unwrap();

        // Payload should be different after encryption
        assert_ne!(&pkt[27..], &original_payload[..]);
        // MAC field should be set (not all zeros)
        assert_ne!(&pkt[19..27], &[0u8; 8]);
    }

    #[test]
    fn armor_encrypt_false_only_sets_mac() {
        let secret = test_shared_secret();
        let mut pkt = make_test_packet(0);
        let original_payload = pkt[27..].to_vec();

        armor_packet(&secret, &mut pkt, false).unwrap();

        // Payload should NOT be encrypted (cipher suite 0 = HELLO)
        assert_eq!(&pkt[27..], &original_payload[..]);
        // MAC field should still be set
        assert_ne!(&pkt[19..27], &[0u8; 8]);
    }

    #[test]
    fn dearmor_recovers_original_plaintext() {
        let secret = test_shared_secret();
        let mut pkt = make_test_packet(1);
        let original_payload = pkt[27..].to_vec();

        armor_packet(&secret, &mut pkt, true).unwrap();

        // Payload is now encrypted
        assert_ne!(&pkt[27..], &original_payload[..]);

        dearmor_packet(&secret, &mut pkt).unwrap();

        // Payload is decrypted back to original
        assert_eq!(&pkt[27..], &original_payload[..]);
    }

    #[test]
    fn crypt_packet_field_roundtrips_subrange() {
        let secret = test_shared_secret();
        let mut pkt = make_test_packet(1);
        let original = pkt[40..48].to_vec();

        crypt_packet_field(&secret, &mut pkt, 40, 8).unwrap();
        assert_ne!(&pkt[40..48], &original[..]);

        crypt_packet_field(&secret, &mut pkt, 40, 8).unwrap();
        assert_eq!(&pkt[40..48], &original[..]);
    }

    /// Byte-locking regression test: verify that
    /// `crypt_packet_field` produces the EXACT keystream that upstream
    /// `Packet::cryptField` produces.
    ///
    /// See ZeroTierOne 1.14.2 node/Packet.cpp:1142-1152. Upstream uses:
    ///   - the RAW shared secret as the Salsa20/12 key (no mangling),
    ///   - `packet[0..8]` as the 8-byte nonce with `nonce[7] &= 0xf8`
    ///     (the low 3 bits of byte 7 cleared),
    ///   - keystream starting from offset 0 (no Poly1305 key-material skip).
    ///
    /// ManyTier's previous implementation used the mangled key, the unmasked
    /// nonce, and a 32-byte keystream skip: producing ciphertext that
    /// upstream decrypted to garbage. That garbage was interpreted as a huge
    /// `numMoons` value by the upstream moon-list loop at
    /// node/IncomingPacket.cpp:489-497, which then threw `std::out_of_range`
    /// and the HELLO was silently dropped by `tryDecode`'s catch-all at
    /// node/IncomingPacket.cpp:160-164. Found by the offline replay harness
    /// in tests/upstream-dohello-replay.
    #[test]
    fn crypt_packet_field_matches_upstream_packet_crypt_field_semantics() {
        let secret = test_shared_secret();
        let mut pkt = make_test_packet(1);
        // Set byte 7 of the IV to a value with the low 3 bits non-zero, so
        // the upstream-mandated `nonce[7] &= 0xf8` masking is observable.
        pkt[7] = 0x47;

        // Known plaintext at offset 40, 8 bytes.
        let plaintext: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
        pkt[40..48].copy_from_slice(&plaintext);

        // Encrypt in-place using ManyTier's crypt_packet_field.
        crypt_packet_field(&secret, &mut pkt, 40, 8).unwrap();
        let ciphertext = pkt[40..48].to_vec();
        assert_ne!(ciphertext.as_slice(), &plaintext[..]);

        // Independent reference decrypt matching upstream Packet::cryptField
        // byte-for-byte: RAW key, masked IV, no keystream skip.
        // See ZeroTierOne 1.14.2 node/Packet.cpp:1142-1152.
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&pkt[0..8]);
        nonce[7] &= 0xf8;
        let ref_key: [u8; 32] = secret[..32].try_into().unwrap();
        let mut reference_cipher = Salsa12::new(&ref_key.into(), &nonce.into());
        let mut recovered = ciphertext.clone();
        reference_cipher.apply_keystream(&mut recovered);
        assert_eq!(
            recovered, plaintext,
            "upstream-semantics reference decrypt must recover plaintext; \
             if this fails, crypt_packet_field has diverged from \
             ZeroTierOne 1.14.2 node/Packet.cpp:1142-1152 again"
        );

        // Also verify symmetry: re-running ManyTier's crypt_packet_field on
        // the ciphertext recovers the plaintext (round-trip property).
        crypt_packet_field(&secret, &mut pkt, 40, 8).unwrap();
        assert_eq!(&pkt[40..48], &plaintext[..]);
    }

    #[test]
    fn dearmor_with_corrupted_mac_returns_error() {
        let secret = test_shared_secret();
        let mut pkt = make_test_packet(1);

        armor_packet(&secret, &mut pkt, true).unwrap();

        // Corrupt the MAC
        pkt[19] ^= 0xFF;

        let result = dearmor_packet(&secret, &mut pkt);
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::MacVerificationFailed => {}
            other => panic!("expected MacVerificationFailed, got {:?}", other),
        }
    }

    #[test]
    fn nonce_is_8_bytes_from_packet_iv() {
        // Different IVs should produce different ciphertexts
        let secret = test_shared_secret();
        let mut pkt1 = make_test_packet(1);
        let mut pkt2 = make_test_packet(1);
        pkt2[0] = 0xFF; // change IV

        armor_packet(&secret, &mut pkt1, true).unwrap();
        armor_packet(&secret, &mut pkt2, true).unwrap();

        // Different IVs -> different ciphertext
        assert_ne!(&pkt1[27..], &pkt2[27..]);
    }

    #[test]
    fn armor_rejects_too_short_packet() {
        let secret = test_shared_secret();
        let mut pkt = [0u8; 27]; // one byte too short

        let result = armor_packet(&secret, &mut pkt, true);
        assert!(result.is_err());
    }

    #[test]
    fn dearmor_rejects_too_short_packet() {
        let secret = test_shared_secret();
        let mut pkt = [0u8; 27];

        let result = dearmor_packet(&secret, &mut pkt);
        assert!(result.is_err());
    }

    #[test]
    fn armor_dearmor_with_encrypt_false_roundtrips() {
        // For HELLO packets (cipher suite 0), we only MAC, no encrypt
        let secret = test_shared_secret();
        let mut pkt = make_test_packet(0);
        let original_payload = pkt[27..].to_vec();

        armor_packet(&secret, &mut pkt, false).unwrap();
        // Verify MAC is valid by computing it manually.
        let mangled = mangle_key(&secret, &pkt, pkt.len());
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&pkt[0..8]);
        let mut cipher = Salsa12::new(&mangled.into(), &nonce.into());
        let mut poly_key = [0u8; 32];
        cipher.apply_keystream(&mut poly_key);

        let mut saved_mac = [0u8; 8];
        saved_mac.copy_from_slice(&pkt[19..27]);
        assert!(crate::poly::verify_mac(
            &poly_key,
            &pkt[PACKET_VERB_OFFSET..],
            &saved_mac
        ));
        assert_eq!(&pkt[27..], &original_payload[..]);
    }

    #[test]
    fn armor_dearmor_minimum_size_packet() {
        // Exactly 28 bytes -- 27 header + 1 verb byte, no payload
        let secret = test_shared_secret();
        let mut pkt = [0u8; 28];
        pkt[0..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        // Cipher suite 1 (Salsa20/12) so armor+dearmor will roundtrip.
        pkt[18] = 0x08;
        pkt[27] = 0x01; // verb

        let original_verb = pkt[27];

        armor_packet(&secret, &mut pkt, true).unwrap();
        dearmor_packet(&secret, &mut pkt).unwrap();

        assert_eq!(pkt[27], original_verb);
    }

    /// armor_packet sets the cipher suite bits to match what it does, so a
    /// caller cannot produce a packet the receiver would not decrypt.
    #[test]
    fn armor_sets_the_cipher_suite_bits() {
        let secret = test_shared_secret();
        let mut packet = make_test_packet(0);
        packet[PACKET_FLAGS_OFFSET] |= 0x02; // hops survive
        armor_packet(&secret, &mut packet, true).unwrap();
        assert_eq!(packet[PACKET_FLAGS_OFFSET] & 0x38, 1 << 3);
        assert_eq!(packet[PACKET_FLAGS_OFFSET] & 0x07, 0x02);
        assert!(dearmor_packet(&secret, &mut packet).is_ok());

        let mut packet = make_test_packet(1);
        armor_packet(&secret, &mut packet, false).unwrap();
        assert_eq!(packet[PACKET_FLAGS_OFFSET] & 0x38, 0);
    }
}
