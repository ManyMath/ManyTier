// ZeroTier V1 protocol constants. Values match official implementation.

// --- Protocol version ---

/// Current protocol version (V1).
pub const ZT_PROTO_VERSION: u8 = 12;

/// Minimum supported protocol version.
pub const ZT_PROTO_VERSION_MIN: u8 = 4;

// --- Packet sizes ---

/// Minimum valid packet length (28 bytes: 8 IV + 5 dest + 5 source + 1 flags + 8 MAC + 1 verb).
pub const ZT_PROTO_MIN_PACKET_LENGTH: usize = 28;

/// Minimum valid fragment length (16 bytes: 8 packet_id + 5 dest + 1 indicator + 1 fragment_info + 1 hops).
pub const ZT_PROTO_MIN_FRAGMENT_LENGTH: usize = 16;

/// Maximum number of fragments per packet.
pub const ZT_MAX_PACKET_FRAGMENTS: usize = 7;

/// Default physical MTU: packets larger than this are sent as a head plus
/// fragments. See ZeroTierOne include/ZeroTierOne.h (`ZT_DEFAULT_PHYSMTU`).
pub const ZT_DEFAULT_PHYSMTU: usize = 1432;

/// Maximum relay hops.
pub const ZT_RELAY_MAX_HOPS: u8 = 3;

/// Default MTU for ZeroTier virtual networks.
pub const ZT_DEFAULT_MTU: usize = 2800;

/// Number of Salsa20 rounds used for packet encryption.
pub const ZT_PROTO_SALSA20_ROUNDS: u32 = 12;

// --- Cipher suites ---

/// Cipher suite: C25519/Poly1305 with no payload encryption (MAC only).
pub const CIPHER_SUITE_C25519_POLY1305_NONE: u8 = 0;

/// Cipher suite: C25519/Poly1305 with Salsa20/12 payload encryption.
pub const CIPHER_SUITE_C25519_POLY1305_SALSA2012: u8 = 1;

pub const CIPHER_SUITE_NO_CRYPTO_TRUSTED_PATH: u8 = 2;

pub const CIPHER_SUITE_AES_GMAC_SIV: u8 = 3;

// --- Packet flags ---

/// See ZeroTierOne 1.14.2 node/Packet.hpp:143 (`ZT_PROTO_FLAG_FRAGMENTED`).
pub const FLAG_FRAGMENTED: u8 = 0x40;

/// See ZeroTierOne dev/node/Packet.hpp:138 (`ZT_PROTO_FLAG_EXTENDED_ARMOR`).
/// Not present in 1.14.2; reserved for future dev-branch extended-armor
/// HELLO support.
pub const FLAG_EXTENDED_ARMOR: u8 = 0x80;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:148 (`ZT_PROTO_VERB_FLAG_COMPRESSED`).
/// High bit of the verb byte indicates LZ4-compressed payload.
pub const VERB_FLAG_COMPRESSED: u8 = 0x80;

pub const FRAGMENT_INDICATOR: u8 = 0xff;

// --- Packet header field indexes ---
//
// These constants mirror upstream ZeroTierOne 1.14.2 node/Packet.hpp:223..230.
// They are currently informational (the on-disk packet layout is enforced by
// the `PacketHeader` zerocopy struct in zerotier-protocol::header), but
// expose the offsets to crate-external code that needs to peek inside a raw
// packet without constructing a `PacketHeader` (e.g. the tx/rx HELLO dumper
// in zerotier-service).

/// See ZeroTierOne 1.14.2 node/Packet.hpp:224 (`ZT_PACKET_IDX_IV`).
pub const ZT_PACKET_IDX_IV: usize = 0;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:225 (`ZT_PACKET_IDX_DEST`).
pub const ZT_PACKET_IDX_DEST: usize = 8;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:226 (`ZT_PACKET_IDX_SOURCE`).
pub const ZT_PACKET_IDX_SOURCE: usize = 13;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:227 (`ZT_PACKET_IDX_FLAGS`).
pub const ZT_PACKET_IDX_FLAGS: usize = 18;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:228 (`ZT_PACKET_IDX_MAC`).
pub const ZT_PACKET_IDX_MAC: usize = 19;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:229 (`ZT_PACKET_IDX_VERB`).
pub const ZT_PACKET_IDX_VERB: usize = 27;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:230 (`ZT_PACKET_IDX_PAYLOAD`).
pub const ZT_PACKET_IDX_PAYLOAD: usize = 28;

// --- HELLO verb field indexes (relative to `ZT_PACKET_IDX_PAYLOAD`) ---
//
// See ZeroTierOne 1.14.2 node/Packet.hpp:266..271 and node/Peer.cpp:418-461
// for the HELLO packet construction. These offsets locate the fixed-size
// HELLO header fields that precede the variable-length identity + dest_inet
// + planet + moon sections. The identity, dest_inet, planet, and moon
// offsets are variable and are computed at serialization time by
// `HelloPayload::serialize` and `RootManager::build_hello`.

/// See ZeroTierOne 1.14.2 node/Packet.hpp:266 (`ZT_PROTO_VERB_HELLO_IDX_PROTOCOL_VERSION`).
pub const ZT_PROTO_VERB_HELLO_IDX_PROTOCOL_VERSION: usize = ZT_PACKET_IDX_PAYLOAD;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:267 (`ZT_PROTO_VERB_HELLO_IDX_MAJOR_VERSION`).
pub const ZT_PROTO_VERB_HELLO_IDX_MAJOR_VERSION: usize =
    ZT_PROTO_VERB_HELLO_IDX_PROTOCOL_VERSION + 1;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:268 (`ZT_PROTO_VERB_HELLO_IDX_MINOR_VERSION`).
pub const ZT_PROTO_VERB_HELLO_IDX_MINOR_VERSION: usize = ZT_PROTO_VERB_HELLO_IDX_MAJOR_VERSION + 1;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:269 (`ZT_PROTO_VERB_HELLO_IDX_REVISION`).
pub const ZT_PROTO_VERB_HELLO_IDX_REVISION: usize = ZT_PROTO_VERB_HELLO_IDX_MINOR_VERSION + 1;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:270 (`ZT_PROTO_VERB_HELLO_IDX_TIMESTAMP`).
pub const ZT_PROTO_VERB_HELLO_IDX_TIMESTAMP: usize = ZT_PROTO_VERB_HELLO_IDX_REVISION + 2;

/// See ZeroTierOne 1.14.2 node/Packet.hpp:271 (`ZT_PROTO_VERB_HELLO_IDX_IDENTITY`).
pub const ZT_PROTO_VERB_HELLO_IDX_IDENTITY: usize = ZT_PROTO_VERB_HELLO_IDX_TIMESTAMP + 8;

// --- Timing constants (milliseconds) ---

/// How often to send keepalive/heartbeat on active paths.
pub const ZT_PATH_HEARTBEAT_PERIOD: u64 = 14_000;

/// How often to ping peers.
pub const ZT_PEER_PING_PERIOD: u64 = 60_000;

/// When a path expires if no traffic received.
pub const ZT_PEER_PATH_EXPIRATION: u64 = 243_000;

/// When a peer is considered inactive.
pub const ZT_PEER_ACTIVITY_TIMEOUT: u64 = 500_000;

pub const ZT_PATH_HELLO_RATE_LIMIT: u64 = 1_000;

/// Minimum interval between UNITE (rendezvous) messages for a peer pair.
pub const ZT_MIN_UNITE_INTERVAL: u64 = 30_000;

/// How long a physical path stays trusted for relaying after the last
/// authenticated packet on it (ZeroTierOne `ZT_TRUST_EXPIRATION`).
pub const ZT_TRUST_EXPIRATION: u64 = 600_000;

/// How often to check for peers needing pings.
pub const ZT_PING_CHECK_INTERVAL: u64 = 5_000;

/// Interval for pushing direct paths when no direct path exists.
pub const ZT_DIRECT_PATH_PUSH_INTERVAL: u64 = 15_000;

/// Interval for pushing direct paths when a direct path already exists.
pub const ZT_DIRECT_PATH_PUSH_INTERVAL_HAVEPATH: u64 = 120_000;

/// Window over which received PUSH_DIRECT_PATHS are counted (ms); see
/// ZeroTierOne node/Constants.hpp `ZT_PUSH_DIRECT_PATHS_CUTOFF_TIME`.
pub const ZT_PUSH_DIRECT_PATHS_CUTOFF_TIME: u64 = 30_000;

/// Pushes honored per peer within the cutoff window; see ZeroTierOne
/// node/Constants.hpp `ZT_PUSH_DIRECT_PATHS_CUTOFF_LIMIT`.
pub const ZT_PUSH_DIRECT_PATHS_CUTOFF_LIMIT: u8 = 8;

/// Minimum spacing of rate-limited per-peer replies such as credential
/// requests (ZeroTierOne node/Constants.hpp `ZT_PEER_GENERAL_RATE_LIMIT`).
pub const ZT_PEER_GENERAL_RATE_LIMIT: u64 = 1_000;

/// Minimum spacing of credential pushes a peer can request
/// (`ZT_PEER_CREDENTIALS_REQUEST_RATE_LIMIT`).
pub const ZT_PEER_CREDENTIALS_REQUEST_RATE_LIMIT: u64 = 1_000;

/// PUSH_DIRECT_PATHS record flag: forget this path (node/Packet.hpp).
pub const PUSH_DIRECT_PATHS_FLAG_FORGET_PATH: u8 = 0x01;

// --- World (planet/moon) constants ---

pub const WORLD_TYPE_PLANET: u8 = 1;

pub const WORLD_TYPE_MOON: u8 = 127;

/// Maximum number of roots in a world definition.
pub const WORLD_MAX_ROOTS: usize = 4;

/// Maximum number of endpoints per root.
pub const WORLD_MAX_ENDPOINTS_PER_ROOT: usize = 32;

pub const WORLD_ID_EARTH: u64 = 149604618;

// --- Address constants ---

/// Length of a ZeroTier address in bytes (40 bits).
pub const ZT_ADDRESS_LENGTH: usize = 5;

pub const ZT_ADDRESS_RESERVED_PREFIX: u8 = 0xff;

// --- Error codes (used in ERROR verb responses) ---

/// No error.
pub const ERROR_NONE: u8 = 0x00;

/// Invalid request.
pub const ERROR_INVALID_REQUEST: u8 = 0x01;

pub const ERROR_BAD_PROTOCOL_VERSION: u8 = 0x02;

/// Object not found.
pub const ERROR_OBJ_NOT_FOUND: u8 = 0x03;

/// Identity collision.
pub const ERROR_IDENTITY_COLLISION: u8 = 0x04;

/// Unsupported operation.
pub const ERROR_UNSUPPORTED_OPERATION: u8 = 0x05;

pub const ERROR_NEED_MEMBERSHIP_CERTIFICATE: u8 = 0x06;

pub const ERROR_NETWORK_ACCESS_DENIED: u8 = 0x07;

/// Unwanted multicast.
pub const ERROR_UNWANTED_MULTICAST: u8 = 0x08;

pub const ERROR_NETWORK_AUTHENTICATION_REQUIRED: u8 = 0x09;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_values() {
        assert_eq!(ZT_PROTO_VERSION, 12);
        assert_eq!(ZT_PROTO_VERSION_MIN, 4);
    }

    #[test]
    fn packet_size_values() {
        assert_eq!(ZT_PROTO_MIN_PACKET_LENGTH, 28);
        assert_eq!(ZT_PROTO_MIN_FRAGMENT_LENGTH, 16);
        assert_eq!(ZT_MAX_PACKET_FRAGMENTS, 7);
    }

    #[test]
    fn cipher_suite_values() {
        assert_eq!(CIPHER_SUITE_C25519_POLY1305_NONE, 0);
        assert_eq!(CIPHER_SUITE_C25519_POLY1305_SALSA2012, 1);
        assert_eq!(CIPHER_SUITE_NO_CRYPTO_TRUSTED_PATH, 2);
        assert_eq!(CIPHER_SUITE_AES_GMAC_SIV, 3);
    }

    #[test]
    fn timing_values() {
        assert_eq!(ZT_PATH_HEARTBEAT_PERIOD, 14_000);
        assert_eq!(ZT_PEER_PING_PERIOD, 60_000);
        assert_eq!(ZT_PEER_PATH_EXPIRATION, 243_000);
        assert_eq!(ZT_PEER_ACTIVITY_TIMEOUT, 500_000);
        assert_eq!(ZT_PATH_HELLO_RATE_LIMIT, 1_000);
        assert_eq!(ZT_MIN_UNITE_INTERVAL, 30_000);
        assert_eq!(ZT_PING_CHECK_INTERVAL, 5_000);
        assert_eq!(ZT_DIRECT_PATH_PUSH_INTERVAL, 15_000);
        assert_eq!(ZT_DIRECT_PATH_PUSH_INTERVAL_HAVEPATH, 120_000);
    }

    #[test]
    fn flag_values() {
        assert_eq!(FLAG_FRAGMENTED, 0x40);
        assert_eq!(FLAG_EXTENDED_ARMOR, 0x80);
        assert_eq!(VERB_FLAG_COMPRESSED, 0x80);
        assert_eq!(FRAGMENT_INDICATOR, 0xff);
    }

    #[test]
    fn world_values() {
        assert_eq!(WORLD_TYPE_PLANET, 1);
        assert_eq!(WORLD_TYPE_MOON, 127);
        assert_eq!(WORLD_MAX_ROOTS, 4);
        assert_eq!(WORLD_MAX_ENDPOINTS_PER_ROOT, 32);
        assert_eq!(WORLD_ID_EARTH, 149604618);
    }

    #[test]
    fn address_values() {
        assert_eq!(ZT_ADDRESS_LENGTH, 5);
        assert_eq!(ZT_ADDRESS_RESERVED_PREFIX, 0xff);
    }

    #[test]
    fn packet_header_offsets_match_upstream_1_14_2() {
        // See ZeroTierOne 1.14.2 node/Packet.hpp:224..230
        assert_eq!(ZT_PACKET_IDX_IV, 0);
        assert_eq!(ZT_PACKET_IDX_DEST, 8);
        assert_eq!(ZT_PACKET_IDX_SOURCE, 13);
        assert_eq!(ZT_PACKET_IDX_FLAGS, 18);
        assert_eq!(ZT_PACKET_IDX_MAC, 19);
        assert_eq!(ZT_PACKET_IDX_VERB, 27);
        assert_eq!(ZT_PACKET_IDX_PAYLOAD, 28);
    }

    #[test]
    fn hello_verb_field_offsets_match_upstream_1_14_2() {
        // See ZeroTierOne 1.14.2 node/Packet.hpp:266..271
        assert_eq!(ZT_PROTO_VERB_HELLO_IDX_PROTOCOL_VERSION, 28);
        assert_eq!(ZT_PROTO_VERB_HELLO_IDX_MAJOR_VERSION, 29);
        assert_eq!(ZT_PROTO_VERB_HELLO_IDX_MINOR_VERSION, 30);
        assert_eq!(ZT_PROTO_VERB_HELLO_IDX_REVISION, 31);
        assert_eq!(ZT_PROTO_VERB_HELLO_IDX_TIMESTAMP, 33);
        assert_eq!(ZT_PROTO_VERB_HELLO_IDX_IDENTITY, 41);
    }

    #[test]
    fn error_code_values() {
        assert_eq!(ERROR_NONE, 0x00);
        assert_eq!(ERROR_INVALID_REQUEST, 0x01);
        assert_eq!(ERROR_BAD_PROTOCOL_VERSION, 0x02);
        assert_eq!(ERROR_OBJ_NOT_FOUND, 0x03);
        assert_eq!(ERROR_IDENTITY_COLLISION, 0x04);
        assert_eq!(ERROR_UNSUPPORTED_OPERATION, 0x05);
        assert_eq!(ERROR_NEED_MEMBERSHIP_CERTIFICATE, 0x06);
        assert_eq!(ERROR_NETWORK_ACCESS_DENIED, 0x07);
        assert_eq!(ERROR_UNWANTED_MULTICAST, 0x08);
        assert_eq!(ERROR_NETWORK_AUTHENTICATION_REQUIRED, 0x09);
    }
}
