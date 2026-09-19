//! NetworkConfig dictionary builder.
//!
//! Builds a serialized dictionary (the `dict_data` for `NetworkConfigPayload`)
//! from controller network/member records plus a Certificate of Membership.
//!
//! This is no_std compatible (extern crate alloc).

extern crate alloc;

use super::dictionary::Dictionary;
use super::types::{ManagedRoute, MemberRecord, NetworkRecord};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use zerotier_protocol::verbs::network_config::CertificateOfMembership;

/// Build a serialized NetworkConfig dictionary from controller data.
///
/// Returns the raw dictionary bytes suitable for `NetworkConfigPayload::dict_data`.
///
/// Required text keys: nwid, n, t, v, ts, r, id, f, mtu, ml
/// Required binary keys: C (COM), R (rules), I (IP assignments), RT (routes)
///
/// `capabilities_raw`/`tags_raw` are pre-signed, concatenated
/// `Capability`/`Tag` object bytes (see
/// `super::rules::serialize_capabilities_signed`/`serialize_tags_signed`) for
/// *this requesting member's own* granted capabilities/tags. Per upstream
/// `node/NetworkConfig.cpp` (`NetworkConfig::fromDictionary`), official reads
/// its own `_config.capabilities`/`_config.tags` -- which its own outbound
/// VL2 rule filter (`Network::filterOutgoingPacket`, via `_doZtFilter` in
/// `node/Network.cpp`) consults directly -- exclusively from the `CAP`/`TAG`
/// keys of *its own* network config dictionary, not from any other
/// packet-level field. A separate `VERB_NETWORK_CREDENTIALS` push (see
/// `NetworkCredentialsPayload` elsewhere in this controller) is a distinct,
/// additional mechanism official peers use to tell EACH OTHER about their
/// own credentials once a P2P session exists; it does not substitute for
/// embedding a member's own capabilities/tags in that same member's own
/// network config dictionary, which is what populates its own
/// `_config.capabilities`/`_config.tags` for its own outbound filter to act
/// on. Passing `&[]` omits the key entirely, matching official's own
/// behavior of omitting `CAP`/`TAG` when a member holds none.
pub fn build_network_config(
    network: &NetworkRecord,
    member: &MemberRecord,
    routes: &[ManagedRoute],
    com: &CertificateOfMembership,
    now_ms: u64,
    capabilities_raw: &[u8],
    tags_raw: &[u8],
) -> Vec<u8> {
    let mut dict = Dictionary::new();

    // nwid: network ID as 16-char lowercase hex
    dict.add_text("nwid", &alloc::format!("{:016x}", network.id));

    // n: network name
    dict.add_text("n", &network.name);

    // t: network type as hex (0 = private, 1 = public)
    let net_type: u64 = if network.private { 0 } else { 1 };
    dict.add_hex("t", net_type);

    // v: config version as hex (protocol version 7)
    dict.add_hex("v", 7);

    // ts: timestamp as hex
    dict.add_hex("ts", now_ms);

    // r: revision as hex
    dict.add_hex("r", network.revision);

    // id: issued-to ZT address as 10-char lowercase hex
    dict.add_text("id", &format_address(&member.node_id));

    // f: flags as hex. Members only accept broadcast when the config says
    // so (ZT_NETWORKCONFIG_FLAG_ENABLE_BROADCAST, set by ZeroTier One's
    // controller from enableBroadcast).
    const FLAG_ENABLE_BROADCAST: u64 = 0x02;
    dict.add_hex(
        "f",
        if network.enable_broadcast {
            FLAG_ENABLE_BROADCAST
        } else {
            0
        },
    );

    // mtu: MTU as hex
    dict.add_int("mtu", network.mtu as u64);

    // ml: multicast limit as hex
    dict.add_hex("ml", network.multicast_limit as u64);

    // ctmd: credential time max delta (30 minutes upstream default)
    dict.add_hex("ctmd", 1_800_000);

    // C: COM binary
    dict.add_binary("C", serialize_com(com));

    // R: Rules binary (allow-all by default, or from network record)
    if network.rules.is_empty() {
        dict.add_binary("R", serialize_rules_allow_all());
    } else {
        dict.add_binary("R", super::rules::serialize_rules(&network.rules));
    }

    // I: IP assignments binary
    if !member.ip_assignments.is_empty() {
        dict.add_binary("I", serialize_ip_assignments(&member.ip_assignments));
    }

    // RT: Routes binary
    dict.add_binary("RT", serialize_routes(routes, &member.ip_assignments));

    // CAP: this member's own granted capabilities (see doc comment above for
    // why this must live here rather than only in a NETWORK_CREDENTIALS push).
    if !capabilities_raw.is_empty() {
        dict.add_binary("CAP", capabilities_raw.to_vec());
    }

    // TAG: this member's own assigned tags.
    if !tags_raw.is_empty() {
        dict.add_binary("TAG", tags_raw.to_vec());
    }

    dict.serialize()
}

/// Format a 5-byte ZeroTier address as a 10-char lowercase hex string.
fn format_address(addr: &[u8; 5]) -> String {
    alloc::format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}",
        addr[0],
        addr[1],
        addr[2],
        addr[3],
        addr[4]
    )
}

/// Serialize a Certificate of Membership to upstream wire format.
///
/// Format: type byte (1), qualifier count (u16 BE), qualifiers,
/// signer_address (5 bytes), then signature (96 bytes) if signed.
pub fn serialize_com(com: &CertificateOfMembership) -> Vec<u8> {
    let mut buf = vec![
        0u8;
        1 + 2
            + (com.qualifiers.len() * 24)
            + 5
            + if com.signer_address == [0; 5] { 0 } else { 96 }
    ];
    let written = com.serialize(&mut buf);
    buf.truncate(written);
    buf
}

/// Serialize the default allow-all rule.
///
/// ZeroTier rule binary format: ACTION_ACCEPT (0x01) with length byte 0x00.
pub fn serialize_rules_allow_all() -> Vec<u8> {
    alloc::vec![0x01, 0x00]
}

/// Serialize an InetAddress from an IP string and prefix length.
///
/// Format: type byte (4=IPv4, 6=IPv6) + address bytes (4 or 16) + port/prefix as u16 BE.
pub fn serialize_inet_address(ip_str: &str, prefix: u8) -> Vec<u8> {
    let mut buf = Vec::new();

    if let Some(octets) = parse_ipv4(ip_str) {
        buf.push(4); // type = IPv4
        buf.extend_from_slice(&octets);
        buf.extend_from_slice(&(prefix as u16).to_be_bytes());
    } else if let Some(octets) = parse_ipv6(ip_str) {
        buf.push(6); // type = IPv6
        buf.extend_from_slice(&octets);
        buf.extend_from_slice(&(prefix as u16).to_be_bytes());
    }

    buf
}

/// Serialize IP assignments from "ip/prefix" strings.
///
/// Each IP is serialized as an InetAddress (type + address + prefix-as-port).
pub fn serialize_ip_assignments(ips: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    for ip_str in ips {
        if let Some((addr, prefix)) = parse_ip_prefix(ip_str) {
            buf.extend(serialize_inet_address(&addr, prefix));
        }
    }
    buf
}

/// Serialize managed routes and derived IP subnet routes.
fn serialize_routes(managed: &[ManagedRoute], assignments: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();

    // 1. Add explicit managed routes
    for route in managed {
        if let Some((target, prefix)) = parse_ip_prefix(&route.target) {
            if let Some(target_octets) = parse_ipv4(&target) {
                buf.push(4); // IPv4
                buf.extend_from_slice(&target_octets);
                buf.extend_from_slice(&(prefix as u16).to_be_bytes());
            } else if let Some(target_octets) = parse_ipv6(&target) {
                buf.push(6); // IPv6
                buf.extend_from_slice(&target_octets);
                buf.extend_from_slice(&(prefix as u16).to_be_bytes());
            } else {
                continue;
            }

            if let Some(via_str) = &route.via {
                if let Some(via_octets) = parse_ipv4(via_str) {
                    buf.push(4);
                    buf.extend_from_slice(&via_octets);
                    buf.extend_from_slice(&0u16.to_be_bytes()); // port 0 for gateway
                } else if let Some(via_octets) = parse_ipv6(via_str) {
                    buf.push(6);
                    buf.extend_from_slice(&via_octets);
                    buf.extend_from_slice(&0u16.to_be_bytes());
                } else {
                    buf.push(0x00); // null via if invalid
                }
            } else {
                buf.push(0x00); // null via
            }
            buf.extend_from_slice(&0u16.to_be_bytes()); // flags
            buf.extend_from_slice(&0u16.to_be_bytes()); // metric
        }
    }

    // 2. Add derived routes from IP assignments (if not already covered)
    buf.extend(serialize_routes_from_ips(assignments));

    buf
}

/// Serialize routes derived from IP assignments.
///
/// For each IP/prefix, creates a route entry:
/// - Target: network address with prefix (InetAddress)
/// - Via: null gateway (type byte 0x00)
/// - Flags: u16 0x0000
/// - Metric: u16 0x0000
fn serialize_routes_from_ips(ips: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    for ip_str in ips {
        if let Some((addr, prefix)) = parse_ip_prefix(ip_str) {
            if let Some(octets) = parse_ipv4(&addr) {
                // Compute network address by masking
                let network = apply_ipv4_mask(&octets, prefix);
                // Target InetAddress
                buf.push(4); // IPv4
                buf.extend_from_slice(&network);
                buf.extend_from_slice(&(prefix as u16).to_be_bytes());
                // Via: null (no gateway)
                buf.push(0x00);
                // Flags
                buf.extend_from_slice(&0u16.to_be_bytes());
                // Metric
                buf.extend_from_slice(&0u16.to_be_bytes());
            } else if let Some(octets) = parse_ipv6(&addr) {
                let network = apply_ipv6_mask(&octets, prefix);
                buf.push(6); // IPv6
                buf.extend_from_slice(&network);
                buf.extend_from_slice(&(prefix as u16).to_be_bytes());
                buf.push(0x00);
                buf.extend_from_slice(&0u16.to_be_bytes());
                buf.extend_from_slice(&0u16.to_be_bytes());
            }
        }
    }
    buf
}

/// Parse "ip/prefix" into (ip_string, prefix_u8).
fn parse_ip_prefix(s: &str) -> Option<(String, u8)> {
    let parts: Vec<&str> = s.splitn(2, '/').collect();
    if parts.len() == 2 {
        let prefix: u8 = parts[1].parse().ok()?;
        Some((String::from(parts[0]), prefix))
    } else {
        // No prefix, assume /32 for IPv4, /128 for IPv6
        if s.contains(':') {
            Some((String::from(s), 128))
        } else {
            Some((String::from(s), 32))
        }
    }
}

/// Parse an IPv4 address string to 4 bytes.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part.parse().ok()?;
    }
    Some(octets)
}

/// Parse an IPv6 address string to 16 bytes (simplified: supports full form only).
fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    if !s.contains(':') {
        return None;
    }
    // Handle :: expansion
    let mut groups = [0u16; 8];
    let parts: Vec<&str> = s.split("::").collect();
    match parts.len() {
        1 => {
            // No ::: must have exactly 8 groups
            let segs: Vec<&str> = s.split(':').collect();
            if segs.len() != 8 {
                return None;
            }
            for (i, seg) in segs.iter().enumerate() {
                groups[i] = u16::from_str_radix(seg, 16).ok()?;
            }
        }
        2 => {
            // Has ::: expand
            let left: Vec<&str> = if parts[0].is_empty() {
                Vec::new()
            } else {
                parts[0].split(':').collect()
            };
            let right: Vec<&str> = if parts[1].is_empty() {
                Vec::new()
            } else {
                parts[1].split(':').collect()
            };
            let zeros = 8 - left.len() - right.len();
            for (i, seg) in left.iter().enumerate() {
                groups[i] = u16::from_str_radix(seg, 16).ok()?;
            }
            // Middle zeros are already 0
            for (i, seg) in right.iter().enumerate() {
                groups[left.len() + zeros + i] = u16::from_str_radix(seg, 16).ok()?;
            }
        }
        _ => return None,
    }

    let mut result = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        let bytes = g.to_be_bytes();
        result[i * 2] = bytes[0];
        result[i * 2 + 1] = bytes[1];
    }
    Some(result)
}

/// Apply an IPv4 subnet mask to get the network address.
fn apply_ipv4_mask(octets: &[u8; 4], prefix: u8) -> [u8; 4] {
    let ip = u32::from_be_bytes(*octets);
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    (ip & mask).to_be_bytes()
}

/// Apply an IPv6 subnet mask to get the network address.
fn apply_ipv6_mask(octets: &[u8; 16], prefix: u8) -> [u8; 16] {
    let mut result = *octets;
    for i in 0..16u8 {
        let bit_pos = i * 8;
        if bit_pos >= prefix {
            result[i as usize] = 0;
        } else if bit_pos + 8 > prefix {
            let bits_to_keep = prefix - bit_pos;
            let mask = !0u8 << (8 - bits_to_keep);
            result[i as usize] &= mask;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::dictionary::Dictionary;
    use super::*;
    use alloc::vec;
    use zerotier_protocol::verbs::network_config::{CertificateOfMembership, ComQualifier};

    fn test_network() -> NetworkRecord {
        NetworkRecord {
            id: 0xff00001234560001,
            name: String::from("test-net"),
            private: true,
            creation_time: 1000000,
            revision: 42,
            multicast_limit: 32,
            mtu: 2800,
            v4_assign_mode: String::from("zt"),
            v6_assign_mode: String::from("none"),
            rules: Vec::new(),
            capabilities: Vec::new(),
            tags: Vec::new(),
            enable_broadcast: true,
        }
    }

    fn test_member() -> MemberRecord {
        MemberRecord {
            network_id: 0xff00001234560001,
            node_id: [0xa0, 0xb1, 0xc2, 0xd3, 0xe4],
            authorized: true,
            ip_assignments: vec![String::from("192.168.192.1/24")],
            creation_time: 1000000,
            last_seen: 2000000,
            name: String::from("test-member"),
            revision: 0,
            last_authorized_time: 1000000,
            last_deauthorized_time: 0,
            active_bridge: false,
            no_auto_assign_ips: false,
            capabilities: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn test_com() -> CertificateOfMembership {
        CertificateOfMembership {
            issued_to: [0xa0, 0xb1, 0xc2, 0xd3, 0xe4],
            qualifiers: vec![
                ComQualifier {
                    id: 0,
                    value: 0xff00001234560001,
                    max_delta: 0,
                },
                ComQualifier {
                    id: 1,
                    value: 1000,
                    max_delta: 100,
                },
            ],
            signer_address: [0x01, 0x02, 0x03, 0x04, 0x05],
            signature: [0xAA; 96],
        }
    }

    #[test]
    fn build_config_has_all_required_text_keys() {
        let network = test_network();
        let member = test_member();
        let com = test_com();

        let bytes = build_network_config(&network, &member, &[], &com, 5000000, &[], &[]);
        let dict = Dictionary::deserialize(&bytes).unwrap();

        assert_eq!(dict.get_text("nwid"), Some("ff00001234560001"));
        assert_eq!(dict.get_text("n"), Some("test-net"));
        assert_eq!(dict.get_text("t"), Some("0")); // private = 0
        assert_eq!(dict.get_text("v"), Some("7"));
        assert!(dict.get_text("ts").is_some()); // timestamp
        assert_eq!(dict.get_text("r"), Some("2a")); // 42 in hex
        assert_eq!(dict.get_text("id"), Some("a0b1c2d3e4"));
        assert_eq!(dict.get_text("f"), Some("2")); // broadcast enabled
        assert_eq!(dict.get_text("mtu"), Some("af0"));
        assert_eq!(dict.get_text("ml"), Some("20")); // 32 in hex
    }

    #[test]
    fn com_serialization_roundtrip() {
        let com = test_com();
        let serialized = serialize_com(&com);

        // Deserialize using the protocol crate's method
        let (parsed, consumed) = CertificateOfMembership::deserialize(&serialized).unwrap();
        assert_eq!(consumed, serialized.len());
        assert_eq!(parsed.qualifiers.len(), 2);
        assert_eq!(parsed.qualifiers[0].id, 0);
        assert_eq!(parsed.qualifiers[0].value, 0xff00001234560001);
        assert_eq!(parsed.qualifiers[1].id, 1);
        assert_eq!(parsed.qualifiers[1].value, 1000);
        assert_eq!(parsed.signer_address, [0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(parsed.signature, [0xAA; 96]);
    }

    #[test]
    fn allow_all_rules_binary() {
        let rules = serialize_rules_allow_all();
        assert_eq!(rules, vec![0x01, 0x00]);
    }

    #[test]
    fn ip_assignment_serialization_ipv4() {
        let ips = vec![String::from("192.168.192.1/24")];
        let serialized = serialize_ip_assignments(&ips);

        // Expected: type=4, 192.168.192.1 (4 bytes), prefix=24 as u16 BE
        assert_eq!(serialized.len(), 7); // 1 + 4 + 2
        assert_eq!(serialized[0], 4); // IPv4
        assert_eq!(serialized[1], 192);
        assert_eq!(serialized[2], 168);
        assert_eq!(serialized[3], 192);
        assert_eq!(serialized[4], 1);
        assert_eq!(u16::from_be_bytes([serialized[5], serialized[6]]), 24);
    }

    #[test]
    fn route_serialization_ipv4() {
        let ips = vec![String::from("192.168.192.1/24")];
        let serialized = serialize_routes_from_ips(&ips);

        // Target: type=4, 192.168.192.0 (masked), prefix=24
        // Via: 0x00 (null)
        // Flags: 0x0000
        // Metric: 0x0000
        assert_eq!(serialized.len(), 12); // 1+4+2 + 1 + 2 + 2
        assert_eq!(serialized[0], 4); // IPv4
        assert_eq!(serialized[1], 192);
        assert_eq!(serialized[2], 168);
        assert_eq!(serialized[3], 192);
        assert_eq!(serialized[4], 0); // masked to .0
        assert_eq!(u16::from_be_bytes([serialized[5], serialized[6]]), 24);
        assert_eq!(serialized[7], 0x00); // null via
        assert_eq!(serialized[8], 0x00); // flags
        assert_eq!(serialized[9], 0x00);
        assert_eq!(serialized[10], 0x00); // metric
        assert_eq!(serialized[11], 0x00);
    }

    #[test]
    fn public_network_type() {
        let mut network = test_network();
        network.private = false;
        let member = test_member();
        let com = test_com();

        let bytes = build_network_config(&network, &member, &[], &com, 5000000, &[], &[]);
        let dict = Dictionary::deserialize(&bytes).unwrap();

        assert_eq!(dict.get_text("t"), Some("1")); // public = 1
    }

    #[test]
    fn config_contains_binary_com() {
        let network = test_network();
        let member = test_member();
        let com = test_com();

        let bytes = build_network_config(&network, &member, &[], &com, 5000000, &[], &[]);
        let dict = Dictionary::deserialize(&bytes).unwrap();

        let com_binary = dict.get_binary("C").expect("C key missing");
        // Verify it can be deserialized back
        let (parsed, _) = CertificateOfMembership::deserialize(com_binary).unwrap();
        assert_eq!(parsed.qualifiers.len(), 2);
    }

    #[test]
    fn config_contains_allow_all_rules() {
        let network = test_network();
        let member = test_member();
        let com = test_com();

        let bytes = build_network_config(&network, &member, &[], &com, 5000000, &[], &[]);
        let dict = Dictionary::deserialize(&bytes).unwrap();

        let rules = dict.get_binary("R").expect("R key missing");
        assert_eq!(rules, &[0x01, 0x00]);
    }

    #[test]
    fn config_contains_default_ctmd() {
        let network = test_network();
        let member = test_member();
        let com = test_com();

        let bytes = build_network_config(&network, &member, &[], &com, 5000000, &[], &[]);
        let dict = Dictionary::deserialize(&bytes).unwrap();

        assert_eq!(dict.get_text("ctmd"), Some("1b7740"));
    }

    #[test]
    fn ipv4_mask_application() {
        assert_eq!(apply_ipv4_mask(&[192, 168, 192, 1], 24), [192, 168, 192, 0]);
        assert_eq!(apply_ipv4_mask(&[10, 0, 1, 255], 16), [10, 0, 0, 0]);
        assert_eq!(apply_ipv4_mask(&[172, 16, 5, 3], 12), [172, 16, 0, 0]);
    }
}
