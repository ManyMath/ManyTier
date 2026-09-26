/// Root server communication .
///
/// Handles building HELLO packets (cipher suite 0, MAC only) for root server
/// bootstrapping and WHOIS requests (cipher suite 1, encrypted) for address
/// resolution.
extern crate alloc;

use zerotier_crypto::identity::Identity;
use zerotier_crypto::salsa;
use zerotier_protocol::constants::*;
use zerotier_protocol::inet_address::InetAddress;
use zerotier_protocol::verb::Verb;
use zerotier_protocol::verbs::hello::{
    serialize_hello_worlds, HelloPayload, HelloWorld, MANYTIER_ADVERTISED_PROTOCOL_VERSION,
};
use zerotier_protocol::verbs::ok::OkPayload;
use zerotier_protocol::verbs::rendezvous::RendezvousPayload;
use zerotier_protocol::verbs::whois::WhoisRequest;
use zerotier_protocol::ProtocolError;

/// Root server communication manager.
///
/// Builds HELLO and WHOIS packets for bootstrapping and address resolution.
#[derive(Debug)]
pub struct RootManager {
    /// Counter for tracking HELLO retries.
    pub last_hello_sent: u64,
}

impl Default for RootManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RootManager {
    pub fn new() -> Self {
        RootManager { last_hello_sent: 0 }
    }

    /// Build a HELLO packet to send to a root server.
    ///
    /// HELLO uses cipher suite 0 (MAC only, no encryption per Pitfall 1).
    /// The shared_secret is used only for MAC computation, not encryption.
    ///
    /// `planet_world_id` must be the actual planet world id from the caller's
    /// topology. Upstream ZeroTierOne 1.14.2 emits this at
    /// `node/Peer.cpp:430`: `outp.append((uint64_t)RR->topology->planetWorldId())`.
    /// Previously this field was hardcoded to `WORLD_ID_EARTH` in `HelloPayload::new`, which
    /// made ManyTier lie about its planet when running against any non-Earth
    /// planet (e.g. the localhost M2M test planet).
    ///
    /// The verb byte at offset 27 is set to `Verb::Hello.to_byte()` with no
    /// high-nibble flags. Upstream 1.14.2 defines only `VERB_FLAG_COMPRESSED`
    /// (`0x80`) as a verb flag (`node/Packet.hpp:148`), which does not apply
    /// to HELLO; no other verb flags exist in 1.14.2.
    #[allow(clippy::too_many_arguments)]
    pub fn build_hello(
        our_identity: &Identity,
        dest_address: &[u8; 5],
        dest_physical: core::net::SocketAddr,
        now_ms: u64,
        packet_id: u64,
        shared_secret: &[u8; 48],
        buf: &mut [u8],
        planet_world_id: u64,
        planet_world_timestamp: u64,
        worlds: &[HelloWorld],
    ) -> Result<(usize, u64), ProtocolError> {
        if buf.len() < ZT_PROTO_MIN_PACKET_LENGTH + 128 {
            return Err(ProtocolError::TooShort {
                need: ZT_PROTO_MIN_PACKET_LENGTH + 128,
                got: buf.len(),
            });
        }

        // The packet ID doubles as the Salsa20 IV / Poly1305 key seed, so
        // the caller allocates it from a counter rather than the clock.
        buf[0..8].copy_from_slice(&packet_id.to_be_bytes());

        // Destination address
        buf[8..13].copy_from_slice(dest_address);

        // Source address
        buf[13..18].copy_from_slice(our_identity.address.as_bytes());

        // Flags byte: cipher suite 0 (bits 3-5 = 000), hop count 0 (bits 0-2 = 000)
        // cipher_suite_0 = no payload encryption, MAC only
        buf[18] = CIPHER_SUITE_C25519_POLY1305_NONE << 3;

        // MAC field (bytes 19..27) - will be set by armor
        buf[19..27].copy_from_slice(&[0u8; 8]);

        // Verb byte: HELLO (0x01)
        buf[27] = Verb::Hello.to_byte();

        // Build HELLO payload after the header (offset 28)
        let dest_inet = InetAddress::from_socket_addr(dest_physical);
        let mut hello = HelloPayload::new(
            Identity {
                address: our_identity.address,
                public_key: our_identity.public_key.clone(),
                secret: None, // Don't include secret in outgoing packets
            },
            now_ms,
            dest_inet,
        );
        // See ZeroTierOne 1.14.2 node/Peer.cpp:430-431
        hello.planet_world_id = planet_world_id;
        hello.planet_world_timestamp = planet_world_timestamp;

        let payload_len = hello.serialize(&mut buf[28..])?;
        // The world list we orbit follows, encrypted with cryptField as in
        // ZeroTierOne node/Peer.cpp sendHELLO, so a root can tell us about
        // newer versions of them.
        let worlds_offset = 28 + payload_len;
        let worlds_len = 2 + 17 * worlds.len();
        if buf.len() < worlds_offset + worlds_len {
            return Err(ProtocolError::TooShort {
                need: worlds_offset + worlds_len,
                got: buf.len(),
            });
        }
        serialize_hello_worlds(worlds, &mut buf[worlds_offset..]);
        let total_len = worlds_offset + worlds_len;
        salsa::crypt_packet_field(
            shared_secret,
            &mut buf[..total_len],
            worlds_offset,
            worlds_len,
        )
        .map_err(ProtocolError::CryptoError)?;

        // Armor: cipher suite 0 = MAC only, no encryption.
        // Always use the mangled-key path: the official controller verifies the
        // HELLO MAC using the DH-derived shared secret with key mangling applied.
        salsa::armor_packet(shared_secret, &mut buf[..total_len], false)
            .map_err(ProtocolError::CryptoError)?;

        Ok((total_len, packet_id))
    }

    /// Build a WHOIS request packet.
    ///
    /// WHOIS uses cipher suite 1 (Salsa20/12 + Poly1305) -- requires active session with root.
    pub fn build_whois(
        our_identity: &Identity,
        dest_address: &[u8; 5],
        addresses: &[[u8; 5]],
        shared_secret: &[u8; 48],
        packet_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, u64), ProtocolError> {
        if buf.len() < ZT_PROTO_MIN_PACKET_LENGTH + addresses.len() * 5 {
            return Err(ProtocolError::TooShort {
                need: ZT_PROTO_MIN_PACKET_LENGTH + addresses.len() * 5,
                got: buf.len(),
            });
        }

        buf[0..8].copy_from_slice(&packet_id.to_be_bytes());

        // Destination
        buf[8..13].copy_from_slice(dest_address);

        // Source
        buf[13..18].copy_from_slice(our_identity.address.as_bytes());

        // Flags: cipher suite 1 (Salsa20/12 + Poly1305), hop count 0
        buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;

        // MAC placeholder
        buf[19..27].copy_from_slice(&[0u8; 8]);

        // Verb: WHOIS
        buf[27] = Verb::Whois.to_byte();

        // WHOIS payload: list of 5-byte addresses
        let whois = WhoisRequest {
            addresses: addresses.to_vec(),
        };
        let payload_len = whois.serialize(&mut buf[28..]);
        let total_len = 28 + payload_len;

        // Armor with encryption (cipher suite 1)
        salsa::armor_packet(shared_secret, &mut buf[..total_len], true)
            .map_err(ProtocolError::CryptoError)?;

        Ok((total_len, packet_id))
    }

    /// Build an OK(HELLO) response packet.
    #[allow(clippy::too_many_arguments)]
    pub fn build_ok_hello(
        our_identity: &Identity,
        dest_address: &[u8; 5],
        in_re_packet_id: u64,
        timestamp_echo: u64,
        shared_secret: &[u8; 48],
        packet_id: u64,
        use_unmangled_null: bool,
        external_address: Option<core::net::SocketAddr>,
        worlds: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        let need = ZT_PROTO_MIN_PACKET_LENGTH + 64 + worlds.len();
        if buf.len() < need {
            return Err(ProtocolError::TooShort {
                need,
                got: buf.len(),
            });
        }

        buf[0..8].copy_from_slice(&packet_id.to_be_bytes());
        buf[8..13].copy_from_slice(dest_address);
        buf[13..18].copy_from_slice(our_identity.address.as_bytes());

        // Cipher suite 1 for OK responses
        buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;
        buf[19..27].copy_from_slice(&[0u8; 8]);
        buf[27] = Verb::Ok.to_byte();

        // OK payload
        let ok = OkPayload {
            in_re_verb: Verb::Hello,
            in_re_packet_id,
            sub_payload: zerotier_protocol::verbs::ok::OkSubPayload::Hello {
                timestamp_echo,
                // See ZeroTierOne 1.14.2 node/Peer.hpp:618-619.
                // Advertise only the protocol version ManyTier can actually
                // receive without AES_GMAC_SIV support.
                protocol_version: MANYTIER_ADVERTISED_PROTOCOL_VERSION,
                major_version: 0,
                minor_version: 1,
                revision: 0,
                external_address: external_address.map(InetAddress::from_socket_addr),
                worlds: worlds.to_vec(),
            },
        };

        let payload_len = ok.serialize(&mut buf[28..])?;
        let total_len = 28 + payload_len;

        if use_unmangled_null {
            salsa::armor_packet_unmangled(&[0u8; 32], &mut buf[..total_len], false)
                .map_err(ProtocolError::CryptoError)?;
        } else {
            salsa::armor_packet(shared_secret, &mut buf[..total_len], true)
                .map_err(ProtocolError::CryptoError)?;
        }

        Ok(total_len)
    }

    /// Build a RENDEZVOUS packet telling `dest` to contact `target_peer` at `target_address`.
    ///
    /// RENDEZVOUS uses cipher suite 1 (encrypted) since we have an active session with the peer.
    /// The root sends RENDEZVOUS to both peers to trigger mutual hole-punching.
    pub fn build_rendezvous(
        our_identity: &Identity,
        dest_address: &[u8; 5],
        target_peer_address: &[u8; 5],
        target_physical: InetAddress,
        shared_secret: &[u8; 48],
        packet_id: u64,
        buf: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        if buf.len() < ZT_PROTO_MIN_PACKET_LENGTH + 32 {
            return Err(ProtocolError::TooShort {
                need: ZT_PROTO_MIN_PACKET_LENGTH + 32,
                got: buf.len(),
            });
        }

        buf[0..8].copy_from_slice(&packet_id.to_be_bytes());
        buf[8..13].copy_from_slice(dest_address);
        buf[13..18].copy_from_slice(our_identity.address.as_bytes());

        // Cipher suite 1 (encrypted)
        buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;
        buf[19..27].copy_from_slice(&[0u8; 8]);
        buf[27] = Verb::Rendezvous.to_byte();

        let rendezvous = RendezvousPayload {
            flags: 0,
            peer_address: *target_peer_address,
            address: target_physical,
        };

        let payload_len = rendezvous.serialize(&mut buf[28..]);
        let total_len = 28 + payload_len;

        salsa::armor_packet(shared_secret, &mut buf[..total_len], true)
            .map_err(ProtocolError::CryptoError)?;

        Ok(total_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerotier_crypto::identity::{Address, PublicKey};
    use zerotier_protocol::PacketHeader;

    fn build_test_identity() -> Identity {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0xe4]).unwrap();
        let pk = PublicKey::from_bytes(&[0x42u8; 64]).unwrap();
        Identity {
            address,
            public_key: pk,
            secret: None,
        }
    }

    fn test_shared_secret() -> [u8; 48] {
        let mut s = [0u8; 48];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(0x42);
        }
        s
    }

    #[test]
    fn build_hello_produces_valid_packet() {
        let id = build_test_identity();
        let dest = [0x01, 0x02, 0x03, 0x04, 0x05];
        let dest_phys: core::net::SocketAddr = "192.168.1.1:9993".parse().unwrap();
        let secret = test_shared_secret();
        let mut buf = [0u8; 512];

        let (len, _packet_id) = RootManager::build_hello(
            &id,
            &dest,
            dest_phys,
            1000,
            0x1000_0000_0000_0000 | 1000,
            &secret,
            &mut buf,
            WORLD_ID_EARTH,
            0,
            &[],
        )
        .unwrap();

        assert!(len >= ZT_PROTO_MIN_PACKET_LENGTH);
        assert_eq!(
            len, 137,
            "HELLO ends with the encrypted world list (an empty one here)"
        );

        // Parse header -- verb is encrypted (cipher suite 0 = MAC only, verb is NOT encrypted)
        // Actually cipher suite 0 means no encryption so verb is plaintext
        // But armor_packet with encrypt_payload=false doesn't encrypt verb+payload
        // However, the verb byte IS part of the payload area (offset 27+)
        // For cipher suite 0, armor_packet(false) does NOT encrypt, so verb is readable.
        // But the MAC overwrites bytes 19..27.
        // We can read dest/source from the header
        let hdr = PacketHeader::from_bytes(&buf[..len]).unwrap();
        assert_eq!(hdr.dest, dest);
        assert_eq!(hdr.source_address(), *id.address.as_bytes());
        // Cipher suite 0
        assert_eq!(hdr.cipher_suite(), CIPHER_SUITE_C25519_POLY1305_NONE);
        // Verb is Hello (not encrypted for cipher suite 0)
        assert_eq!(hdr.verb_id(), Verb::Hello.to_byte());
        assert_eq!(buf[28], MANYTIER_ADVERTISED_PROTOCOL_VERSION);
        assert!(buf[28] < ZT_PROTO_VERSION);
    }

    #[test]
    fn build_ok_hello_avoids_aes_gmac_siv_upgrade_gate() {
        let id = build_test_identity();
        let dest = [0x01, 0x02, 0x03, 0x04, 0x05];
        let secret = test_shared_secret();
        let mut buf = [0u8; 512];

        let len = RootManager::build_ok_hello(
            &id,
            &dest,
            0x0102_0304_0506_0708,
            1234,
            &secret,
            2000,
            false,
            None,
            &[],
            &mut buf,
        )
        .unwrap();

        salsa::dearmor_packet(&secret, &mut buf[..len]).unwrap();
        let ok = OkPayload::deserialize(&buf[28..len]).unwrap();

        let zerotier_protocol::verbs::ok::OkSubPayload::Hello {
            protocol_version, ..
        } = ok.sub_payload
        else {
            panic!("expected OK(HELLO) payload");
        };

        assert_eq!(protocol_version, MANYTIER_ADVERTISED_PROTOCOL_VERSION);
        assert!(protocol_version < ZT_PROTO_VERSION);
    }

    #[test]
    fn hello_ends_with_our_encrypted_world_list() {
        // The HELLO ends with the worlds we orbit, encrypted with cryptField
        // (ZeroTierOne node/Peer.cpp sendHELLO), and nothing after them;
        // closes 2 bytes of the 17-byte gap to official zerotier-one 1.14.2.
        use zerotier_crypto::identity::Identity;

        struct XorShift(u64);
        impl rand_core::RngCore for XorShift {
            fn next_u32(&mut self) -> u32 {
                self.next_u64() as u32
            }
            fn next_u64(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                let mut pos = 0;
                while pos < dest.len() {
                    let val = self.next_u64().to_le_bytes();
                    let n = core::cmp::min(8, dest.len() - pos);
                    dest[pos..pos + n].copy_from_slice(&val[..n]);
                    pos += n;
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        let mut rng = XorShift(789);
        let client = Identity::generate(&mut rng).unwrap();
        let mut rng2 = XorShift(987);
        let server = Identity::generate(&mut rng2).unwrap();

        let client_secret = client.secret.as_ref().unwrap();
        let server_pub = x25519_dalek::PublicKey::from(server.public_key.dh);
        let shared = zerotier_crypto::key_agreement::key_agree(&client_secret.dh, &server_pub);

        let moon = HelloWorld {
            world_type: WORLD_TYPE_MOON,
            id: 0x0000_0021_05b7_8c5f,
            timestamp: 1_700_000_000_000,
        };
        let mut buf = [0u8; 512];
        let (len, _) = RootManager::build_hello(
            &client,
            server.address.as_bytes(),
            "127.0.0.1:9993".parse().unwrap(),
            1000,
            0x1000_0000_0000_0000 | 1000,
            &shared,
            &mut buf,
            WORLD_ID_EARTH,
            0,
            &[moon],
        )
        .unwrap();

        assert_eq!(len, 137 + 17, "one 17-byte world entry");

        // Receiver-side: dearmor verifies that the MAC covers the world list.
        let server_secret = server.secret.as_ref().unwrap();
        let client_pub = x25519_dalek::PublicKey::from(client.public_key.dh);
        let shared2 = zerotier_crypto::key_agreement::key_agree(&server_secret.dh, &client_pub);
        assert_eq!(shared, shared2);

        let result = salsa::dearmor_packet(&shared2, &mut buf[..len]);
        assert!(
            result.is_ok(),
            "MAC must verify across the world list: {:?}",
            result.err()
        );

        // Layout: header(28) + proto(1) + major(1) + minor(1) + rev(2) + ts(8) +
        // identity(71) + InetAddress(7 IPv4) + planet ts(8) + planet ts(8) = 135
        let moon_offset = 28 + 1 + 1 + 1 + 2 + 8 + 71 + 7 + 8 + 8;
        assert_eq!(moon_offset, 135);

        let world_len = len - moon_offset;
        salsa::crypt_packet_field(&shared2, &mut buf[..len], moon_offset, world_len).unwrap();
        assert_eq!(
            zerotier_protocol::verbs::hello::deserialize_hello_worlds(&buf[moon_offset..len]),
            [moon]
        );
    }

    #[test]
    fn hello_contains_planet_world_id_at_correct_offset() {
        // Verify that build_hello emits the caller-supplied
        // planet_world_id at the correct offset (119..127), matching upstream
        // ZeroTierOne 1.14.2 node/Peer.cpp:430 which writes planetWorldId()
        // after the sender identity and destination InetAddress.
        //
        // Layout past the 28-byte header:
        //   offset 28: proto_version (1)
        //   offset 29: vMajor (1)
        //   offset 30: vMinor (1)
        //   offset 31: vRevision (2)
        //   offset 33: timestamp (8)
        //   offset 41: identity (71) = addr(5) + type(1) + DH(32) + ED(32) + priv_len(1)
        //   offset 112: dest InetAddress (7 bytes for IPv4)
        //   offset 119: planet_world_id (8 bytes BE)   <-- this test asserts this field
        //   offset 127: planet_world_timestamp (8 bytes BE)
        //   offset 135: world count (2 bytes, cryptField-encrypted)
        //   offset 137: end (no worlds)

        use zerotier_crypto::identity::Identity;

        struct XorShift(u64);
        impl rand_core::RngCore for XorShift {
            fn next_u32(&mut self) -> u32 {
                self.next_u64() as u32
            }
            fn next_u64(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                let mut pos = 0;
                while pos < dest.len() {
                    let val = self.next_u64().to_le_bytes();
                    let n = core::cmp::min(8, dest.len() - pos);
                    dest[pos..pos + n].copy_from_slice(&val[..n]);
                    pos += n;
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        let mut rng = XorShift(0xC0DEF00D);
        let client = Identity::generate(&mut rng).unwrap();
        let mut rng2 = XorShift(0xDEADBEEF);
        let server = Identity::generate(&mut rng2).unwrap();

        let client_secret = client.secret.as_ref().unwrap();
        let server_pub = x25519_dalek::PublicKey::from(server.public_key.dh);
        let shared = zerotier_crypto::key_agreement::key_agree(&client_secret.dh, &server_pub);

        // Pick a non-Earth planet_world_id so the assertion is
        // meaningful. The value 0xDEAD_BEEF_CAFE_BABE is distinct from
        // WORLD_ID_EARTH (149_604_618) so any hardcoded-Earth fallback would
        // fail this test.
        let custom_planet_id: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let custom_planet_ts: u64 = 0x0000_0001_AABB_CCDD;

        let mut buf = [0u8; 512];
        let (len, _) = RootManager::build_hello(
            &client,
            server.address.as_bytes(),
            "127.0.0.1:9993".parse().unwrap(),
            1000,
            0x1000_0000_0000_0000 | 1000,
            &shared,
            &mut buf,
            custom_planet_id,
            custom_planet_ts,
            &[],
        )
        .unwrap();

        assert_eq!(len, 137, "HELLO length must be 137 bytes");

        // Dearmor to confirm the MAC covers the planet fields correctly.
        let server_secret = server.secret.as_ref().unwrap();
        let client_pub = x25519_dalek::PublicKey::from(client.public_key.dh);
        let shared2 = zerotier_crypto::key_agreement::key_agree(&server_secret.dh, &client_pub);
        salsa::dearmor_packet(&shared2, &mut buf[..len])
            .expect("MAC must verify across planet_world_id bytes");

        // Planet world id and timestamp sit in the plaintext region (before
        // the cryptField-encrypted moon count), so they can be read directly.
        const PLANET_ID_OFFSET: usize = 28 + 1 + 1 + 1 + 2 + 8 + 71 + 7; // 119
        const PLANET_TS_OFFSET: usize = PLANET_ID_OFFSET + 8; // 127
        assert_eq!(PLANET_ID_OFFSET, 119);
        assert_eq!(PLANET_TS_OFFSET, 127);

        let got_id = u64::from_be_bytes(
            buf[PLANET_ID_OFFSET..PLANET_ID_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let got_ts = u64::from_be_bytes(
            buf[PLANET_TS_OFFSET..PLANET_TS_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            got_id, custom_planet_id,
            "planet_world_id at offset 119..127 must match the value passed to build_hello"
        );
        assert_eq!(
            got_ts, custom_planet_ts,
            "planet_world_timestamp at offset 127..135 must match the value passed to build_hello"
        );

        // Cross-check the regression: building a HELLO with WORLD_ID_EARTH
        // must NOT collide with our custom value (sanity check that the old
        // hardcoded path would have failed this test).
        assert_ne!(custom_planet_id, WORLD_ID_EARTH);
    }

    #[test]
    fn build_whois_uses_cipher_suite_1() {
        let id = build_test_identity();
        let dest = [0x01, 0x02, 0x03, 0x04, 0x05];
        let secret = test_shared_secret();
        let addresses = [[0x11, 0x22, 0x33, 0x44, 0x55]];
        let mut buf = [0u8; 512];

        let (len, _) =
            RootManager::build_whois(&id, &dest, &addresses, &secret, 2000, &mut buf).unwrap();

        assert!(len >= ZT_PROTO_MIN_PACKET_LENGTH);

        let hdr = PacketHeader::from_bytes(&buf[..len]).unwrap();
        assert_eq!(hdr.cipher_suite(), CIPHER_SUITE_C25519_POLY1305_SALSA2012);
    }

    #[test]
    fn build_hello_mac_verifies_with_dh_key() {
        // Simulates the controller-side: build a HELLO, then verify its MAC
        // using the DH-derived shared secret (as the controller would).
        use zerotier_crypto::identity::Identity;

        struct XorShift(u64);
        impl rand_core::RngCore for XorShift {
            fn next_u32(&mut self) -> u32 {
                self.next_u64() as u32
            }
            fn next_u64(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                let mut pos = 0;
                while pos < dest.len() {
                    let val = self.next_u64().to_le_bytes();
                    let n = core::cmp::min(8, dest.len() - pos);
                    dest[pos..pos + n].copy_from_slice(&val[..n]);
                    pos += n;
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        let mut rng = XorShift(42);
        let client_id = Identity::generate(&mut rng).unwrap();
        let controller_id = Identity::generate(&mut rng).unwrap();

        // Client computes DH shared secret
        let client_secret = client_id.secret.as_ref().unwrap();
        let controller_pub = x25519_dalek::PublicKey::from(controller_id.public_key.dh);
        let client_dh =
            zerotier_crypto::key_agreement::key_agree(&client_secret.dh, &controller_pub);

        // Controller computes DH shared secret (should be the same)
        let controller_secret = controller_id.secret.as_ref().unwrap();
        let client_pub = x25519_dalek::PublicKey::from(client_id.public_key.dh);
        let controller_dh =
            zerotier_crypto::key_agreement::key_agree(&controller_secret.dh, &client_pub);

        assert_eq!(client_dh, controller_dh, "DH shared secrets must match");

        // Client builds HELLO using client-side DH key
        let mut buf = [0u8; 512];
        let (len, _) = RootManager::build_hello(
            &client_id,
            controller_id.address.as_bytes(),
            "127.0.0.1:9993".parse().unwrap(),
            1000,
            0x1000_0000_0000_0000 | 1000,
            &client_dh,
            &mut buf,
            WORLD_ID_EARTH,
            0,
            &[],
        )
        .unwrap();

        // Controller verifies MAC using controller-side DH key
        let result = zerotier_crypto::salsa::dearmor_packet(&controller_dh, &mut buf[..len]);
        assert!(
            result.is_ok(),
            "Controller should verify HELLO MAC with DH key: {:?}",
            result.err()
        );
    }

    #[test]
    fn build_hello_too_small_buffer() {
        let id = build_test_identity();
        let dest = [0x01, 0x02, 0x03, 0x04, 0x05];
        let dest_phys: core::net::SocketAddr = "192.168.1.1:9993".parse().unwrap();
        let secret = test_shared_secret();
        let mut buf = [0u8; 10];

        assert!(RootManager::build_hello(
            &id,
            &dest,
            dest_phys,
            1000,
            0x1000_0000_0000_0000 | 1000,
            &secret,
            &mut buf,
            WORLD_ID_EARTH,
            0,
            &[],
        )
        .is_err());
    }

    #[test]
    fn cross_identity_hello_mac_verifies() {
        // Uses real identities from official zerotier-one and ManyTier to prove
        // that DH key agreement and HELLO MAC are cross-compatible.
        use zerotier_crypto::identity::Identity;

        let controller_str = "fe400d805e:0:6824f76ce76976a19879f496c90a83c6fdadcf89cc556eee56fe729530bdba644e0105a6cf05486f0c27c1fa599566785ec8da9bb766f2bfa3a66d1d709776d8:9eb7e22c7ab3bddd793f8f3afa233df28ed86ce650c187e2d2e4a2f5e018a63933c4a56768a1abea9747b886b20928088ab0bd00f89c6df9f221a995c82ef0e4";
        let controller_id = Identity::parse(controller_str).expect("failed to parse controller");

        let client_str = "faa900da4a:0:fd0c3dc3ff88ff7cbac1df44f638aa22e69a13d4f9cc90f9fb15c882c4f13e732af074384f2b44a3fc211ea490259bcf1d6cd3b6aefc19a92accef90f73ca9ce:254ad73a7b1478e7283e6ab40a81b017dd2c7296b53a6f5348b30a33f890bef1e015930d2b36979bb57bd0f83ccb01c21dfdadc446d641c49a0f9c478905082a";
        let client_id = Identity::parse(client_str).expect("failed to parse client");

        let client_secret = client_id.secret.as_ref().unwrap();
        let controller_pub = x25519_dalek::PublicKey::from(controller_id.public_key.dh);
        let client_dh =
            zerotier_crypto::key_agreement::key_agree(&client_secret.dh, &controller_pub);

        let controller_secret = controller_id.secret.as_ref().unwrap();
        let client_pub = x25519_dalek::PublicKey::from(client_id.public_key.dh);
        let controller_dh =
            zerotier_crypto::key_agreement::key_agree(&controller_secret.dh, &client_pub);

        assert_eq!(client_dh, controller_dh, "DH shared secrets must match");

        let mut buf = [0u8; 512];
        let (len, _) = RootManager::build_hello(
            &client_id,
            controller_id.address.as_bytes(),
            "127.0.0.1:29993".parse().unwrap(),
            1000,
            0x1000_0000_0000_0000 | 1000,
            &client_dh,
            &mut buf,
            WORLD_ID_EARTH,
            0,
            &[],
        )
        .unwrap();

        let result = zerotier_crypto::salsa::dearmor_packet(&controller_dh, &mut buf[..len]);
        assert!(result.is_ok(), "Controller should verify client HELLO MAC");
    }

    #[test]
    fn hello_crypt_field_roundtrip() {
        // Verify that crypt_packet_field encrypts the moon section correctly
        // and that a receiver can decrypt it back to the original value.
        use zerotier_crypto::identity::Identity;

        struct XorShift(u64);
        impl rand_core::RngCore for XorShift {
            fn next_u32(&mut self) -> u32 {
                self.next_u64() as u32
            }
            fn next_u64(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                let mut pos = 0;
                while pos < dest.len() {
                    let val = self.next_u64().to_le_bytes();
                    let n = core::cmp::min(8, dest.len() - pos);
                    dest[pos..pos + n].copy_from_slice(&val[..n]);
                    pos += n;
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        let mut rng = XorShift(123);
        let client = Identity::generate(&mut rng).unwrap();
        let mut rng2 = XorShift(456);
        let server = Identity::generate(&mut rng2).unwrap();

        let client_secret = client.secret.as_ref().unwrap();
        let server_pub = x25519_dalek::PublicKey::from(server.public_key.dh);
        let shared = zerotier_crypto::key_agreement::key_agree(&client_secret.dh, &server_pub);

        let mut buf = [0u8; 512];
        let (len, _) = RootManager::build_hello(
            &client,
            server.address.as_bytes(),
            "127.0.0.1:9993".parse().unwrap(),
            1000,
            0x1000_0000_0000_0000 | 1000,
            &shared,
            &mut buf,
            WORLD_ID_EARTH,
            0,
            &[],
        )
        .unwrap();

        // Simulate receiver: dearmor then decrypt moon section
        let server_secret = server.secret.as_ref().unwrap();
        let client_pub = x25519_dalek::PublicKey::from(client.public_key.dh);
        let shared2 = zerotier_crypto::key_agreement::key_agree(&server_secret.dh, &client_pub);
        assert_eq!(shared, shared2);

        // Dearmor (verify MAC)
        let result = salsa::dearmor_packet(&shared2, &mut buf[..len]);
        assert!(result.is_ok(), "MAC should verify");

        // Find moon section: header(28) + proto(1) + major(1) + minor(1) + rev(2) + ts(8) +
        // identity(71) + InetAddress(7 for IPv4) + planet(16) = 135
        let moon_offset = 28 + 1 + 1 + 1 + 2 + 8 + 71 + 7 + 8 + 8;
        assert_eq!(moon_offset, 135);

        // Decrypt moon count
        salsa::crypt_packet_field(&shared2, &mut buf[..len], moon_offset, 2).unwrap();
        let moon_count = u16::from_be_bytes([buf[moon_offset], buf[moon_offset + 1]]);
        assert_eq!(moon_count, 0, "Moon count should be 0 after decryption");

        // COR (Certificate of Representation) bytes are plaintext and must be empty.
        assert_eq!(
            &buf[moon_offset + 2..moon_offset + 4],
            &[0x00, 0x00],
            "COR must be empty"
        );
    }
}
