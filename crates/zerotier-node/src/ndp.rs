/// NDP (Neighbor Discovery Protocol) message parsing and response generation.
///
/// Handles ICMPv6 types 133-137 for the VL2 layer:
/// - NS (135) -> NA (136) with solicited flag and target link-layer address option
/// - RS (133) -> RA (134) with prefix information option
/// - DAD (NS from ::) -> NA with override flag
/// - RA (134), NA (136), Redirect (137) -> Ignore (informational)
extern crate alloc;

use alloc::vec::Vec;
use core::net::Ipv6Addr;

use crate::network::NetworkMembership;

/// ICMPv6 type: Router Solicitation
pub const ICMPV6_RS: u8 = 133;
/// ICMPv6 type: Router Advertisement
pub const ICMPV6_RA: u8 = 134;
/// ICMPv6 type: Neighbor Solicitation
pub const ICMPV6_NS: u8 = 135;
/// ICMPv6 type: Neighbor Advertisement
pub const ICMPV6_NA: u8 = 136;
/// ICMPv6 type: Redirect
pub const ICMPV6_REDIRECT: u8 = 137;

/// ICMPv6 next-header value in IPv6.
pub const IPV6_NEXT_HEADER_ICMPV6: u8 = 58;

/// Action to take after processing an NDP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdpAction {
    /// ICMPv6 response bytes (caller wraps in IPv6 + Ethernet).
    Reply(Vec<u8>),
    /// Not an NDP message we handle, or informational only.
    Ignore,
}

/// Compute ICMPv6 checksum over pseudo-header and body.
///
/// Pseudo-header: src_ip(16) + dst_ip(16) + payload_length(4 BE) + zeros(3) + next_header(1, =58).
/// The checksum field in icmpv6_body (bytes 2..4) must be zeroed before calling.
pub fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmpv6_body: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source address (16 bytes)
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
    }

    // Pseudo-header: destination address (16 bytes)
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }

    // Pseudo-header: payload length (4 bytes, upper layer length)
    let len = icmpv6_body.len() as u32;
    sum += len >> 16;
    sum += len & 0xFFFF;

    // Pseudo-header: next header = 58 (ICMPv6)
    sum += IPV6_NEXT_HEADER_ICMPV6 as u32;

    // ICMPv6 body
    let mut i = 0;
    while i + 1 < icmpv6_body.len() {
        sum += u16::from_be_bytes([icmpv6_body[i], icmpv6_body[i + 1]]) as u32;
        i += 2;
    }
    // If odd number of bytes, pad with zero
    if icmpv6_body.len() % 2 != 0 {
        sum += (icmpv6_body[icmpv6_body.len() - 1] as u32) << 8;
    }

    // Fold 32-bit sum to 16-bit with carry
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Build an ICMPv6 Neighbor Advertisement with Target Link-Layer Address option.
///
/// Returns the complete ICMPv6 body with correct checksum.
pub fn build_na(
    target_ip: &[u8; 16],
    target_mac: &[u8; 6],
    solicited: bool,
    override_flag: bool,
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
) -> Vec<u8> {
    // NA format:
    // Type(1) + Code(1) + Checksum(2) + Flags(4) + Target Address(16) = 24 bytes
    // + Target Link-Layer Address option: Type(1)=2 + Length(1)=1 + MAC(6) = 8 bytes
    // Total: 32 bytes
    let mut buf = Vec::with_capacity(32);

    // Type = 136 (NA)
    buf.push(ICMPV6_NA);
    // Code = 0
    buf.push(0);
    // Checksum placeholder (zeroed for computation)
    buf.push(0);
    buf.push(0);

    // Flags byte: R(0x80) S(0x40) O(0x20) + reserved bits
    let mut flags: u8 = 0;
    if solicited {
        flags |= 0x40;
    }
    if override_flag {
        flags |= 0x20;
    }
    buf.push(flags);
    // 3 reserved bytes
    buf.push(0);
    buf.push(0);
    buf.push(0);

    // Target address (16 bytes)
    buf.extend_from_slice(target_ip);

    // Target Link-Layer Address option
    buf.push(2); // Type = 2 (Target Link-Layer Address)
    buf.push(1); // Length = 1 (in units of 8 bytes)
    buf.extend_from_slice(target_mac);

    // Compute checksum
    let checksum = icmpv6_checksum(src_ip, dst_ip, &buf);
    buf[2] = (checksum >> 8) as u8;
    buf[3] = (checksum & 0xFF) as u8;

    buf
}

/// An IPv6 packet carrying `payload` as `next_header`.
pub fn ipv6_packet(
    src: &[u8; 16],
    dst: &[u8; 16],
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(40 + payload.len());
    packet.extend_from_slice(&[0x60, 0, 0, 0]);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.push(next_header);
    packet.push(hop_limit);
    packet.extend_from_slice(src);
    packet.extend_from_slice(dst);
    packet.extend_from_slice(payload);
    packet
}

/// Build an ICMPv6 Router Advertisement with Prefix Information option.
///
/// Returns the complete ICMPv6 body with correct checksum.
pub fn build_ra(
    our_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    prefix: &[u8; 16],
    prefix_len: u8,
) -> Vec<u8> {
    // RA format:
    // Type(1) + Code(1) + Checksum(2) + Cur Hop Limit(1) + Flags(1) +
    // Router Lifetime(2) + Reachable Time(4) + Retrans Timer(4) = 16 bytes
    // + Prefix Information option: Type(1)=3 + Length(1)=4 + Prefix Length(1) +
    //   Flags(1) + Valid Lifetime(4) + Preferred Lifetime(4) + Reserved(4) +
    //   Prefix(16) = 32 bytes
    // Total: 48 bytes
    let mut buf = Vec::with_capacity(48);

    // Type = 134 (RA)
    buf.push(ICMPV6_RA);
    // Code = 0
    buf.push(0);
    // Checksum placeholder
    buf.push(0);
    buf.push(0);
    // Cur Hop Limit = 64
    buf.push(64);
    // Flags = 0
    buf.push(0);
    // Router Lifetime = 1800 seconds (BE)
    buf.extend_from_slice(&1800u16.to_be_bytes());
    // Reachable Time = 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Retrans Timer = 0
    buf.extend_from_slice(&0u32.to_be_bytes());

    // Prefix Information option
    buf.push(3); // Type = 3 (Prefix Information)
    buf.push(4); // Length = 4 (in units of 8 bytes = 32 bytes)
    buf.push(prefix_len); // Prefix length
    buf.push(0xC0); // Flags: L(0x80) + A(0x40)
                    // Valid Lifetime = 86400 seconds (1 day)
    buf.extend_from_slice(&86400u32.to_be_bytes());
    // Preferred Lifetime = 14400 seconds (4 hours)
    buf.extend_from_slice(&14400u32.to_be_bytes());
    // Reserved
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Prefix (16 bytes)
    buf.extend_from_slice(prefix);

    // Compute checksum
    let checksum = icmpv6_checksum(our_ip, dst_ip, &buf);
    buf[2] = (checksum >> 8) as u8;
    buf[3] = (checksum & 0xFF) as u8;

    buf
}

/// Handle an NDP (ICMPv6) message from the virtual network.
///
/// `icmpv6_body` is the ICMPv6 payload (after IPv6 header extraction by caller).
/// First byte = type, second byte = code.
///
/// Returns `NdpAction::Reply` with the ICMPv6 response bytes for NS and RS,
/// or `NdpAction::Ignore` for all other types.
pub fn handle_ndp(
    icmpv6_body: &[u8],
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    membership: &NetworkMembership,
    our_mac: &[u8; 6],
    our_ipv6_prefix: Option<(Ipv6Addr, u8)>,
) -> NdpAction {
    if icmpv6_body.is_empty() {
        return NdpAction::Ignore;
    }

    let icmp_type = icmpv6_body[0];

    match icmp_type {
        ICMPV6_NS => handle_ns(icmpv6_body, src_ip, dst_ip, membership, our_mac),
        ICMPV6_RS => handle_rs(dst_ip, our_mac, our_ipv6_prefix),
        ICMPV6_RA | ICMPV6_NA | ICMPV6_REDIRECT => NdpAction::Ignore,
        _ => NdpAction::Ignore,
    }
}

/// Handle Neighbor Solicitation (type 135).
fn handle_ns(
    icmpv6_body: &[u8],
    src_ip: &[u8; 16],
    _dst_ip: &[u8; 16],
    membership: &NetworkMembership,
    _our_mac: &[u8; 6],
) -> NdpAction {
    // NS format: Type(1) + Code(1) + Checksum(2) + Reserved(4) + Target Address(16) = 24 bytes minimum
    if icmpv6_body.len() < 24 {
        return NdpAction::Ignore;
    }

    // Extract target address (bytes 8..24)
    let mut target_bytes = [0u8; 16];
    target_bytes.copy_from_slice(&icmpv6_body[8..24]);
    let target_ip = Ipv6Addr::from(target_bytes);

    // Look up target in membership table
    let member = match membership.lookup_ipv6(target_ip) {
        Some(m) => m,
        None => return NdpAction::Ignore,
    };

    // Check if this is DAD (Duplicate Address Detection): source is ::
    let is_dad = src_ip == &[0u8; 16];

    // For DAD: override flag set, solicited flag clear
    // For normal NS: solicited flag set, override flag set
    let solicited = !is_dad;
    let override_flag = true;

    // Build NA response
    // Source IP for the reply: use the target address (we're responding as the target)
    // Destination IP for the reply: if DAD, use all-nodes multicast (ff02::1); otherwise use the source
    let reply_src = target_bytes;
    let reply_dst = if is_dad {
        // All-nodes multicast address
        let mut addr = [0u8; 16];
        addr[0] = 0xff;
        addr[1] = 0x02;
        addr[15] = 0x01;
        addr
    } else {
        *src_ip
    };

    let na = build_na(
        &target_bytes,
        &member.mac,
        solicited,
        override_flag,
        &reply_src,
        &reply_dst,
    );
    NdpAction::Reply(na)
}

/// Handle Router Solicitation (type 133).
fn handle_rs(
    _dst_ip: &[u8; 16],
    _our_mac: &[u8; 6],
    our_ipv6_prefix: Option<(Ipv6Addr, u8)>,
) -> NdpAction {
    let (prefix_addr, prefix_len) = match our_ipv6_prefix {
        Some((addr, len)) => (addr, len),
        None => return NdpAction::Ignore,
    };

    // Use link-local all-routers as source (ff02::2 would be the group we respond from,
    // but conventionally RA source is the router's link-local. Use fe80::1 as a standard
    // router link-local for the virtual network.)
    let our_ip: [u8; 16] = {
        let mut addr = [0u8; 16];
        addr[0] = 0xfe;
        addr[1] = 0x80;
        addr[15] = 0x01;
        addr
    };

    // Destination: all-nodes multicast (ff02::1)
    let dst: [u8; 16] = {
        let mut addr = [0u8; 16];
        addr[0] = 0xff;
        addr[1] = 0x02;
        addr[15] = 0x01;
        addr
    };

    let prefix_bytes: [u8; 16] = prefix_addr.octets();

    let ra = build_ra(&our_ip, &dst, &prefix_bytes, prefix_len);
    NdpAction::Reply(ra)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet;
    use crate::network::{NetworkMember, NetworkMembership};
    use core::net::Ipv6Addr;

    fn make_membership_with_ipv6(ip: Ipv6Addr) -> (NetworkMembership, [u8; 6]) {
        let zt_addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let network_id = 0xff00000000abcdef_u64;
        let mac = ethernet::derive_mac(&zt_addr, network_id);
        let mut membership = NetworkMembership::new(network_id, 2800);
        membership.members.push(NetworkMember {
            zt_address: zt_addr,
            mac,
            ipv4: None,
            ipv6: Some((ip, 64)),
            authorized: true,
        });
        (membership, mac)
    }

    fn make_ns(target_ip: &[u8; 16]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.push(ICMPV6_NS); // Type
        buf.push(0); // Code
        buf.push(0); // Checksum (placeholder)
        buf.push(0);
        buf.extend_from_slice(&[0u8; 4]); // Reserved
        buf.extend_from_slice(target_ip); // Target address
        buf
    }

    fn make_rs() -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        buf.push(ICMPV6_RS); // Type
        buf.push(0); // Code
        buf.push(0); // Checksum
        buf.push(0);
        buf.extend_from_slice(&[0u8; 4]); // Reserved
        buf
    }

    // === ICMPv6 checksum tests ===

    #[test]
    fn checksum_basic() {
        let src = [0u8; 16];
        let dst = [0u8; 16];
        let body = [0u8; 4]; // type, code, checksum=0
        let cksum = icmpv6_checksum(&src, &dst, &body);
        // Pseudo-header contributes: payload_length=4 + next_header=58 = 62
        // Ones complement of 62 = 0xFF C1 = 65473
        assert_eq!(cksum, !62u16);
    }

    #[test]
    fn checksum_roundtrip_na() {
        // Build an NA and verify the checksum is valid (re-computing over the
        // final message with checksum included should yield 0).
        let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let target_ip = src;
        let target_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

        let na = build_na(&target_ip, &target_mac, true, true, &src, &dst);

        // Verify: checksum over the complete message (with checksum field included)
        // should produce 0 (or 0xFFFF which folds to 0).
        let verify = icmpv6_checksum(&src, &dst, &na);
        assert!(
            verify == 0 || verify == 0xFFFF,
            "checksum verification failed: {:#06x}",
            verify
        );
    }

    #[test]
    fn checksum_roundtrip_ra() {
        let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let prefix = [0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let ra = build_ra(&src, &dst, &prefix, 64);

        let verify = icmpv6_checksum(&src, &dst, &ra);
        assert!(
            verify == 0 || verify == 0xFFFF,
            "RA checksum verification failed: {:#06x}",
            verify
        );
    }

    // === Neighbor Solicitation -> Neighbor Advertisement tests ===

    #[test]
    fn ns_known_ipv6_produces_na() {
        let target_ipv6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let (membership, target_mac) = make_membership_with_ipv6(target_ipv6);

        let target_bytes = target_ipv6.octets();
        let ns = make_ns(&target_bytes);

        let src_ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let dst_ip = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let our_mac = [0xAA; 6];

        let result = handle_ndp(&ns, &src_ip, &dst_ip, &membership, &our_mac, None);

        match result {
            NdpAction::Reply(na) => {
                assert_eq!(na[0], ICMPV6_NA, "type should be NA (136)");
                assert_eq!(na[1], 0, "code should be 0");
                // Solicited flag (0x40) should be set
                assert_ne!(na[4] & 0x40, 0, "solicited flag should be set");
                // Override flag (0x20) should be set
                assert_ne!(na[4] & 0x20, 0, "override flag should be set");
                // Target address at bytes 8..24
                assert_eq!(&na[8..24], &target_bytes);
                // TLLA option: type=2 at byte 24, length=1 at byte 25, MAC at 26..32
                assert_eq!(na[24], 2, "TLLA option type");
                assert_eq!(na[25], 1, "TLLA option length");
                assert_eq!(&na[26..32], &target_mac, "TLLA should be target's MAC");
            }
            _ => panic!("expected NdpAction::Reply for known IPv6"),
        }
    }

    #[test]
    fn ns_unknown_ipv6_returns_ignore() {
        let known_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let (membership, _) = make_membership_with_ipv6(known_ip);

        let unknown = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 99);
        let ns = make_ns(&unknown.octets());

        let src_ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let dst_ip = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let result = handle_ndp(&ns, &src_ip, &dst_ip, &membership, &[0; 6], None);
        assert_eq!(result, NdpAction::Ignore);
    }

    #[test]
    fn ns_dad_source_unspecified() {
        // DAD: source address is ::
        let target_ipv6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let (membership, _) = make_membership_with_ipv6(target_ipv6);

        let target_bytes = target_ipv6.octets();
        let ns = make_ns(&target_bytes);

        let src_ip = [0u8; 16]; // :: (DAD)
        let dst_ip = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let result = handle_ndp(&ns, &src_ip, &dst_ip, &membership, &[0; 6], None);

        match result {
            NdpAction::Reply(na) => {
                assert_eq!(na[0], ICMPV6_NA);
                // Solicited flag should NOT be set for DAD
                assert_eq!(na[4] & 0x40, 0, "solicited flag should NOT be set for DAD");
                // Override flag should be set for DAD
                assert_ne!(na[4] & 0x20, 0, "override flag should be set for DAD");
            }
            _ => panic!("expected NdpAction::Reply for DAD"),
        }
    }

    // === Router Solicitation -> Router Advertisement tests ===

    #[test]
    fn rs_produces_ra_with_prefix() {
        let membership = NetworkMembership::new(0xff00000000abcdef, 2800);
        let our_mac = [0xAA; 6];
        let prefix = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);

        let rs = make_rs();
        let src_ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let dst_ip = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        let result = handle_ndp(
            &rs,
            &src_ip,
            &dst_ip,
            &membership,
            &our_mac,
            Some((prefix, 64)),
        );

        match result {
            NdpAction::Reply(ra) => {
                assert_eq!(ra[0], ICMPV6_RA, "type should be RA (134)");
                assert_eq!(ra[1], 0, "code should be 0");
                assert_eq!(ra[4], 64, "cur hop limit should be 64");
                // Router lifetime at bytes 6..8
                assert_eq!(u16::from_be_bytes([ra[6], ra[7]]), 1800, "router lifetime");
                // Prefix Information option starts at byte 16
                assert_eq!(ra[16], 3, "prefix info option type");
                assert_eq!(ra[17], 4, "prefix info option length");
                assert_eq!(ra[18], 64, "prefix length");
                assert_eq!(ra[19], 0xC0, "prefix flags L+A");
                // Valid lifetime at 20..24
                assert_eq!(u32::from_be_bytes([ra[20], ra[21], ra[22], ra[23]]), 86400);
                // Preferred lifetime at 24..28
                assert_eq!(u32::from_be_bytes([ra[24], ra[25], ra[26], ra[27]]), 14400);
                // Prefix at 32..48
                assert_eq!(&ra[32..48], &prefix.octets());
            }
            _ => panic!("expected NdpAction::Reply for RS"),
        }
    }

    #[test]
    fn rs_without_prefix_returns_ignore() {
        let membership = NetworkMembership::new(0xff00000000abcdef, 2800);
        let rs = make_rs();
        let src_ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let dst_ip = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        let result = handle_ndp(&rs, &src_ip, &dst_ip, &membership, &[0; 6], None);
        assert_eq!(result, NdpAction::Ignore);
    }

    // === Redirect and other types ===

    #[test]
    fn redirect_returns_ignore() {
        let membership = NetworkMembership::new(0xff00000000abcdef, 2800);
        let mut body = Vec::new();
        body.push(ICMPV6_REDIRECT);
        body.push(0);
        body.extend_from_slice(&[0u8; 38]); // minimum redirect body

        let src_ip = [0; 16];
        let dst_ip = [0; 16];

        let result = handle_ndp(&body, &src_ip, &dst_ip, &membership, &[0; 6], None);
        assert_eq!(result, NdpAction::Ignore);
    }

    #[test]
    fn ra_received_returns_ignore() {
        let membership = NetworkMembership::new(0xff00000000abcdef, 2800);
        let mut body = Vec::new();
        body.push(ICMPV6_RA);
        body.push(0);
        body.extend_from_slice(&[0u8; 14]);

        let result = handle_ndp(&body, &[0; 16], &[0; 16], &membership, &[0; 6], None);
        assert_eq!(result, NdpAction::Ignore);
    }

    #[test]
    fn na_received_returns_ignore() {
        let membership = NetworkMembership::new(0xff00000000abcdef, 2800);
        let mut body = Vec::new();
        body.push(ICMPV6_NA);
        body.push(0);
        body.extend_from_slice(&[0u8; 30]);

        let result = handle_ndp(&body, &[0; 16], &[0; 16], &membership, &[0; 6], None);
        assert_eq!(result, NdpAction::Ignore);
    }

    #[test]
    fn unknown_type_returns_ignore() {
        let membership = NetworkMembership::new(0xff00000000abcdef, 2800);
        let body = [128u8, 0, 0, 0]; // Echo request, not NDP

        let result = handle_ndp(&body, &[0; 16], &[0; 16], &membership, &[0; 6], None);
        assert_eq!(result, NdpAction::Ignore);
    }

    #[test]
    fn empty_body_returns_ignore() {
        let membership = NetworkMembership::new(0xff00000000abcdef, 2800);
        let result = handle_ndp(&[], &[0; 16], &[0; 16], &membership, &[0; 6], None);
        assert_eq!(result, NdpAction::Ignore);
    }

    #[test]
    fn ns_too_short_returns_ignore() {
        let membership = NetworkMembership::new(0xff00000000abcdef, 2800);
        // NS needs at least 24 bytes, provide only 20
        let mut body = Vec::new();
        body.push(ICMPV6_NS);
        body.push(0);
        body.extend_from_slice(&[0u8; 18]);

        let result = handle_ndp(&body, &[0; 16], &[0; 16], &membership, &[0; 6], None);
        assert_eq!(result, NdpAction::Ignore);
    }

    // === NDP message checksum correctness ===

    #[test]
    fn na_has_correct_checksum() {
        let target_ipv6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let (membership, _) = make_membership_with_ipv6(target_ipv6);

        let target_bytes = target_ipv6.octets();
        let ns = make_ns(&target_bytes);

        let src_ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let dst_ip = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let result = handle_ndp(&ns, &src_ip, &dst_ip, &membership, &[0; 6], None);

        if let NdpAction::Reply(na) = result {
            // The NA reply uses target_bytes as src and src_ip as dst for checksum
            let verify = icmpv6_checksum(&target_bytes, &src_ip, &na);
            assert!(
                verify == 0 || verify == 0xFFFF,
                "NA checksum should validate: {:#06x}",
                verify
            );
        }
    }

    #[test]
    fn ra_has_correct_checksum() {
        let membership = NetworkMembership::new(0xff00000000abcdef, 2800);
        let prefix = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        let rs = make_rs();

        let src_ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let dst_ip = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        let result = handle_ndp(
            &rs,
            &src_ip,
            &dst_ip,
            &membership,
            &[0; 6],
            Some((prefix, 64)),
        );

        if let NdpAction::Reply(ra) = result {
            // RA uses fe80::1 as src and ff02::1 as dst
            let ra_src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            let ra_dst = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            let verify = icmpv6_checksum(&ra_src, &ra_dst, &ra);
            assert!(
                verify == 0 || verify == 0xFFFF,
                "RA checksum should validate: {:#06x}",
                verify
            );
        }
    }
}
