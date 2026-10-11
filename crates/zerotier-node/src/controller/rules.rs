//! ZeroTier network rules engine.
//!
//! Provides types, serialization and parsing for match/action rules, tags, and
//! capabilities that are included in NetworkConfig dictionaries (R, TAG, CAP
//! keys) and NETWORK_CREDENTIALS. Evaluation lives in [`crate::filter`].
//!
//! Binary format per rule entry:
//! - `u8 type_and_flags`: bits 0-5 = rule type, bit 6 = OR flag, bit 7 = NOT flag
//! - `u8 value_length`: length of value data in bytes
//! - `[u8; value_length]`: type-specific value data

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// A single ZeroTier network rule (match condition or action).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub rule_type: u8,
    pub not_flag: bool,
    pub or_flag: bool,
    pub value: Vec<u8>,
}

/// A tag assigned to a network member.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Tag {
    pub id: u32,
    pub value: u32,
}

/// A capability granted to a network member, containing its own rule chain.
///
/// This is the network-level *definition*; a member gains the capability by
/// having its `id` listed in that member's assigned capability IDs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Capability {
    pub id: u32,
    pub rules: Vec<Rule>,
}

/// A network-level tag *definition*: the name and allowed value space for a
/// tag ID. Members carry tag *assignments* (`Tag { id, value }`) that should
/// reference one of these definitions, but the controller does not enforce
/// that binding -- it is metadata for operators/UIs, matching official's
/// `network.conf` "tags" schema.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TagDefinition {
    pub id: u32,
    pub name: String,
    /// Default value assigned to members that don't have this tag explicitly set.
    pub default: Option<u32>,
    /// Named enum values for this tag, e.g. `[("admin", 1), ("user", 2)]`.
    pub enums: Vec<(String, u32)>,
}

// ---------------------------------------------------------------------------
// Rule type constants (from ZeroTier source)
// ---------------------------------------------------------------------------

/// Actions (numeric values verified 2026-07-03 against upstream
/// `include/ZeroTierOne.h` `ZT_VirtualNetworkRuleType` at ZeroTierOne tag
/// `1.14.2` -- the previous MATCH_MAC_SOURCE..MATCH_INTEGER_RANGE values
/// below this comment were wrong by a systematic offset and would have
/// mis-encoded any non-default rule on the wire).
pub const ACTION_DROP: u8 = 0x00;
pub const ACTION_ACCEPT: u8 = 0x01;
pub const ACTION_TEE: u8 = 0x02;
pub const ACTION_WATCH: u8 = 0x03;
pub const ACTION_REDIRECT: u8 = 0x04;
pub const ACTION_BREAK: u8 = 0x05;
pub const ACTION_PRIORITY: u8 = 0x06;

/// Match conditions
pub const MATCH_SOURCE_ZEROTIER_ADDRESS: u8 = 0x18;
pub const MATCH_DEST_ZEROTIER_ADDRESS: u8 = 0x19;
pub const MATCH_VLAN_ID: u8 = 0x1a;
pub const MATCH_VLAN_PCP: u8 = 0x1b;
pub const MATCH_VLAN_DEI: u8 = 0x1c;
pub const MATCH_MAC_SOURCE: u8 = 0x1d;
pub const MATCH_MAC_DEST: u8 = 0x1e;
pub const MATCH_IPV4_SOURCE: u8 = 0x1f;
pub const MATCH_IPV4_DEST: u8 = 0x20;
pub const MATCH_IPV6_SOURCE: u8 = 0x21;
pub const MATCH_IPV6_DEST: u8 = 0x22;
pub const MATCH_IP_TOS: u8 = 0x23;
pub const MATCH_IP_PROTOCOL: u8 = 0x24;
pub const MATCH_ETHERTYPE: u8 = 0x25;
pub const MATCH_ICMP: u8 = 0x26;
pub const MATCH_IP_SOURCE_PORT_RANGE: u8 = 0x27;
pub const MATCH_IP_DEST_PORT_RANGE: u8 = 0x28;
pub const MATCH_CHARACTERISTICS: u8 = 0x29;
pub const MATCH_FRAME_SIZE_RANGE: u8 = 0x2a;
pub const MATCH_RANDOM: u8 = 0x2b;
pub const MATCH_TAGS_DIFFERENCE: u8 = 0x2c;
pub const MATCH_TAGS_BITWISE_AND: u8 = 0x2d;
pub const MATCH_TAGS_BITWISE_OR: u8 = 0x2e;
pub const MATCH_TAGS_BITWISE_XOR: u8 = 0x2f;
pub const MATCH_TAGS_EQUAL: u8 = 0x30;
pub const MATCH_TAG_SENDER: u8 = 0x31;
pub const MATCH_TAG_RECEIVER: u8 = 0x32;
pub const MATCH_INTEGER_RANGE: u8 = 0x33;

/// Map a rule-type byte (masked to bits 0-5) to official's symbolic REST name,
/// e.g. `ACTION_ACCEPT`, `MATCH_IP_PROTOCOL`. Unknown values return `"UNKNOWN"`.
pub fn rule_type_name(rule_type: u8) -> &'static str {
    match rule_type & 0x3F {
        ACTION_DROP => "ACTION_DROP",
        ACTION_ACCEPT => "ACTION_ACCEPT",
        ACTION_TEE => "ACTION_TEE",
        ACTION_WATCH => "ACTION_WATCH",
        ACTION_REDIRECT => "ACTION_REDIRECT",
        ACTION_BREAK => "ACTION_BREAK",
        ACTION_PRIORITY => "ACTION_PRIORITY",
        MATCH_SOURCE_ZEROTIER_ADDRESS => "MATCH_SOURCE_ZEROTIER_ADDRESS",
        MATCH_DEST_ZEROTIER_ADDRESS => "MATCH_DEST_ZEROTIER_ADDRESS",
        MATCH_VLAN_ID => "MATCH_VLAN_ID",
        MATCH_VLAN_PCP => "MATCH_VLAN_PCP",
        MATCH_VLAN_DEI => "MATCH_VLAN_DEI",
        MATCH_MAC_SOURCE => "MATCH_MAC_SOURCE",
        MATCH_MAC_DEST => "MATCH_MAC_DEST",
        MATCH_IPV4_SOURCE => "MATCH_IPV4_SOURCE",
        MATCH_IPV4_DEST => "MATCH_IPV4_DEST",
        MATCH_IPV6_SOURCE => "MATCH_IPV6_SOURCE",
        MATCH_IPV6_DEST => "MATCH_IPV6_DEST",
        MATCH_IP_TOS => "MATCH_IP_TOS",
        MATCH_IP_PROTOCOL => "MATCH_IP_PROTOCOL",
        MATCH_ETHERTYPE => "MATCH_ETHERTYPE",
        MATCH_ICMP => "MATCH_ICMP",
        MATCH_IP_SOURCE_PORT_RANGE => "MATCH_IP_SOURCE_PORT_RANGE",
        MATCH_IP_DEST_PORT_RANGE => "MATCH_IP_DEST_PORT_RANGE",
        MATCH_CHARACTERISTICS => "MATCH_CHARACTERISTICS",
        MATCH_FRAME_SIZE_RANGE => "MATCH_FRAME_SIZE_RANGE",
        MATCH_RANDOM => "MATCH_RANDOM",
        MATCH_TAGS_DIFFERENCE => "MATCH_TAGS_DIFFERENCE",
        MATCH_TAGS_BITWISE_AND => "MATCH_TAGS_BITWISE_AND",
        MATCH_TAGS_BITWISE_OR => "MATCH_TAGS_BITWISE_OR",
        MATCH_TAGS_BITWISE_XOR => "MATCH_TAGS_BITWISE_XOR",
        MATCH_TAGS_EQUAL => "MATCH_TAGS_EQUAL",
        MATCH_TAG_SENDER => "MATCH_TAG_SENDER",
        MATCH_TAG_RECEIVER => "MATCH_TAG_RECEIVER",
        MATCH_INTEGER_RANGE => "MATCH_INTEGER_RANGE",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// Per-rule-type field decomposition
// ---------------------------------------------------------------------------

/// A rule's `value` bytes decoded into official's typed per-rule-type fields
/// (matching the field names/shapes `EmbeddedNetworkController.cpp`'s
/// `_renderRule`/`_parseRule` expose over JSON), rather than the raw wire
/// blob. Byte layouts verified 2026-07-03 against upstream `Capability.hpp`
/// `serializeRules`/`deserializeRules` at ZeroTierOne tag `1.14.2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleFields {
    /// `ACTION_TEE` / `ACTION_WATCH` / `ACTION_REDIRECT`. `length` is only
    /// meaningful for TEE/WATCH; REDIRECT always encodes it as 0.
    Forward {
        address: u64,
        flags: u32,
        length: u16,
    },
    /// `MATCH_SOURCE_ZEROTIER_ADDRESS` / `MATCH_DEST_ZEROTIER_ADDRESS`.
    ZtAddress(u64),
    VlanId(u16),
    VlanPcp(u8),
    VlanDei(u8),
    /// `MATCH_MAC_SOURCE` / `MATCH_MAC_DEST`.
    Mac([u8; 6]),
    /// `MATCH_IPV4_SOURCE` / `MATCH_IPV4_DEST`.
    Ipv4 {
        ip: [u8; 4],
        mask: u8,
    },
    /// `MATCH_IPV6_SOURCE` / `MATCH_IPV6_DEST`.
    Ipv6 {
        ip: [u8; 16],
        mask: u8,
    },
    IpTos {
        mask: u8,
        start: u8,
        end: u8,
    },
    IpProtocol(u8),
    EtherType(u16),
    Icmp {
        icmp_type: u8,
        icmp_code: Option<u8>,
    },
    /// `MATCH_IP_SOURCE_PORT_RANGE` / `MATCH_IP_DEST_PORT_RANGE`.
    PortRange {
        start: u16,
        end: u16,
    },
    Characteristics(u64),
    FrameSizeRange {
        start: u16,
        end: u16,
    },
    RandomProbability(u32),
    /// `MATCH_TAGS_*` / `MATCH_TAG_SENDER` / `MATCH_TAG_RECEIVER`.
    Tag {
        id: u32,
        value: u32,
    },
    /// `end` is the absolute range end (already `start + delta`, matching the
    /// wire and official's JSON -- not the raw in-memory delta).
    IntegerRange {
        start: u64,
        end: u64,
        idx: u16,
        little: bool,
        bits: u8,
    },
}

/// Decode a rule's `value` bytes into typed fields for the rule's type.
/// Returns `None` for rule types with no value payload (e.g. `ACTION_DROP`,
/// `ACTION_ACCEPT`, `ACTION_BREAK`, `ACTION_PRIORITY`), unknown rule types,
/// or a `value` shorter than the type's fixed layout requires.
pub fn decode_rule_fields(rule_type: u8, value: &[u8]) -> Option<RuleFields> {
    fn u16_be(b: &[u8]) -> u16 {
        u16::from_be_bytes([b[0], b[1]])
    }
    fn u32_be(b: &[u8]) -> u32 {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }
    fn u64_be(b: &[u8]) -> u64 {
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    match rule_type & 0x3F {
        ACTION_TEE | ACTION_WATCH | ACTION_REDIRECT if value.len() >= 14 => {
            Some(RuleFields::Forward {
                address: u64_be(&value[0..8]),
                flags: u32_be(&value[8..12]),
                length: u16_be(&value[12..14]),
            })
        }
        MATCH_SOURCE_ZEROTIER_ADDRESS | MATCH_DEST_ZEROTIER_ADDRESS if value.len() >= 5 => {
            let addr = (value[0] as u64) << 32
                | (value[1] as u64) << 24
                | (value[2] as u64) << 16
                | (value[3] as u64) << 8
                | value[4] as u64;
            Some(RuleFields::ZtAddress(addr))
        }
        MATCH_VLAN_ID if value.len() >= 2 => Some(RuleFields::VlanId(u16_be(&value[0..2]))),
        MATCH_VLAN_PCP if !value.is_empty() => Some(RuleFields::VlanPcp(value[0])),
        MATCH_VLAN_DEI if !value.is_empty() => Some(RuleFields::VlanDei(value[0])),
        MATCH_MAC_SOURCE | MATCH_MAC_DEST if value.len() >= 6 => {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&value[0..6]);
            Some(RuleFields::Mac(mac))
        }
        MATCH_IPV4_SOURCE | MATCH_IPV4_DEST if value.len() >= 5 => {
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&value[0..4]);
            Some(RuleFields::Ipv4 { ip, mask: value[4] })
        }
        MATCH_IPV6_SOURCE | MATCH_IPV6_DEST if value.len() >= 17 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&value[0..16]);
            Some(RuleFields::Ipv6 {
                ip,
                mask: value[16],
            })
        }
        MATCH_IP_TOS if value.len() >= 3 => Some(RuleFields::IpTos {
            mask: value[0],
            start: value[1],
            end: value[2],
        }),
        MATCH_IP_PROTOCOL if !value.is_empty() => Some(RuleFields::IpProtocol(value[0])),
        MATCH_ETHERTYPE if value.len() >= 2 => Some(RuleFields::EtherType(u16_be(&value[0..2]))),
        MATCH_ICMP if value.len() >= 3 => Some(RuleFields::Icmp {
            icmp_type: value[0],
            icmp_code: if value[2] & 0x01 != 0 {
                Some(value[1])
            } else {
                None
            },
        }),
        MATCH_IP_SOURCE_PORT_RANGE | MATCH_IP_DEST_PORT_RANGE if value.len() >= 4 => {
            Some(RuleFields::PortRange {
                start: u16_be(&value[0..2]),
                end: u16_be(&value[2..4]),
            })
        }
        MATCH_CHARACTERISTICS if value.len() >= 8 => {
            Some(RuleFields::Characteristics(u64_be(&value[0..8])))
        }
        MATCH_FRAME_SIZE_RANGE if value.len() >= 4 => Some(RuleFields::FrameSizeRange {
            start: u16_be(&value[0..2]),
            end: u16_be(&value[2..4]),
        }),
        MATCH_RANDOM if value.len() >= 4 => {
            Some(RuleFields::RandomProbability(u32_be(&value[0..4])))
        }
        MATCH_TAGS_DIFFERENCE
        | MATCH_TAGS_BITWISE_AND
        | MATCH_TAGS_BITWISE_OR
        | MATCH_TAGS_BITWISE_XOR
        | MATCH_TAGS_EQUAL
        | MATCH_TAG_SENDER
        | MATCH_TAG_RECEIVER
            if value.len() >= 8 =>
        {
            Some(RuleFields::Tag {
                id: u32_be(&value[0..4]),
                value: u32_be(&value[4..8]),
            })
        }
        MATCH_INTEGER_RANGE if value.len() >= 19 => {
            let format = value[18];
            Some(RuleFields::IntegerRange {
                start: u64_be(&value[0..8]),
                end: u64_be(&value[8..16]),
                idx: u16_be(&value[16..18]),
                little: format & 0x80 != 0,
                bits: (format & 0x3F) + 1,
            })
        }
        _ => None,
    }
}

/// Encode typed rule fields back into wire-format `value` bytes, the inverse
/// of [`decode_rule_fields`].
pub fn encode_rule_fields(fields: &RuleFields) -> Vec<u8> {
    let mut buf = Vec::new();
    match *fields {
        RuleFields::Forward {
            address,
            flags,
            length,
        } => {
            buf.extend_from_slice(&address.to_be_bytes());
            buf.extend_from_slice(&flags.to_be_bytes());
            buf.extend_from_slice(&length.to_be_bytes());
        }
        RuleFields::ZtAddress(addr) => {
            let b = addr.to_be_bytes();
            buf.extend_from_slice(&b[3..8]);
        }
        RuleFields::VlanId(v) => buf.extend_from_slice(&v.to_be_bytes()),
        RuleFields::VlanPcp(v) => buf.push(v),
        RuleFields::VlanDei(v) => buf.push(v),
        RuleFields::Mac(mac) => buf.extend_from_slice(&mac),
        RuleFields::Ipv4 { ip, mask } => {
            buf.extend_from_slice(&ip);
            buf.push(mask);
        }
        RuleFields::Ipv6 { ip, mask } => {
            buf.extend_from_slice(&ip);
            buf.push(mask);
        }
        RuleFields::IpTos { mask, start, end } => {
            buf.push(mask);
            buf.push(start);
            buf.push(end);
        }
        RuleFields::IpProtocol(v) => buf.push(v),
        RuleFields::EtherType(v) => buf.extend_from_slice(&v.to_be_bytes()),
        RuleFields::Icmp {
            icmp_type,
            icmp_code,
        } => {
            buf.push(icmp_type);
            buf.push(icmp_code.unwrap_or(0));
            buf.push(if icmp_code.is_some() { 0x01 } else { 0x00 });
        }
        RuleFields::PortRange { start, end } => {
            buf.extend_from_slice(&start.to_be_bytes());
            buf.extend_from_slice(&end.to_be_bytes());
        }
        RuleFields::Characteristics(v) => buf.extend_from_slice(&v.to_be_bytes()),
        RuleFields::FrameSizeRange { start, end } => {
            buf.extend_from_slice(&start.to_be_bytes());
            buf.extend_from_slice(&end.to_be_bytes());
        }
        RuleFields::RandomProbability(v) => buf.extend_from_slice(&v.to_be_bytes()),
        RuleFields::Tag { id, value } => {
            buf.extend_from_slice(&id.to_be_bytes());
            buf.extend_from_slice(&value.to_be_bytes());
        }
        RuleFields::IntegerRange {
            start,
            end,
            idx,
            little,
            bits,
        } => {
            buf.extend_from_slice(&start.to_be_bytes());
            buf.extend_from_slice(&end.to_be_bytes());
            buf.extend_from_slice(&idx.to_be_bytes());
            let format = ((bits - 1) & 0x3F) | if little { 0x80 } else { 0 };
            buf.push(format);
        }
    }
    buf
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Signature type byte for an Ed25519 signature (upstream `Tag.hpp`/`Capability.hpp`).
const SIGNATURE_TYPE_ED25519: u8 = 1;

/// Length in bytes of the combined Ed25519 + digest-suffix signature (upstream `ZT_C25519_SIGNATURE_LEN`).
const SIGNATURE_LEN: usize = 96;

/// Marker upstream wraps around the "for signing" byte range of Tag/Capability
/// (`0x7f7f7f7f7f7f7f7f` in `Tag.hpp`/`Capability.hpp` `serialize(..., forSign=true)`).
const SIGN_MARKER: u64 = 0x7f7f_7f7f_7f7f_7f7f;

/// Serialize a list of rules into binary format (R dictionary key).
///
/// Each rule is encoded as:
/// - `u8`: type_and_flags (bits 0-5 = type, bit 6 = OR, bit 7 = NOT)
/// - `u8`: value length
/// - `[u8]`: value bytes
pub fn serialize_rules(rules: &[Rule]) -> Vec<u8> {
    let mut buf = Vec::new();
    for rule in rules {
        let type_byte = (rule.rule_type & 0x3F)
            | if rule.or_flag { 0x40 } else { 0 }
            | if rule.not_flag { 0x80 } else { 0 };
        buf.push(type_byte);
        buf.push(rule.value.len() as u8);
        buf.extend_from_slice(&rule.value);
    }
    buf
}

/// Create the default allow-all rule set (single ACTION_ACCEPT).
pub fn default_allow_all() -> Vec<Rule> {
    vec![Rule {
        rule_type: ACTION_ACCEPT,
        not_flag: false,
        or_flag: false,
        value: vec![],
    }]
}

/// Serialize tags for the TAG dictionary key.
///
/// Matches the wire layout of upstream `Tag::serialize` (`node/Tag.hpp`,
/// verified against the ZeroTier 1.14.2 source):
/// - network_id: u64 BE
/// - timestamp: i64 BE
/// - tag_id: u32 BE
/// - tag_value: u32 BE
/// - issued_to: 5 bytes (ZeroTier address)
/// - signed_by: 5 bytes (ZeroTier address; zero here: stub is unsigned)
/// - signature_type: u8 (0 == none, so a deserializer skips `signature_len` bytes)
/// - signature_len: u16 BE
/// - signature: `signature_len` bytes (stub: all zeros until controller signing is wired)
/// - additional_fields_len: u16 BE (currently always 0)
pub fn serialize_tags(
    tags: &[Tag],
    network_id: u64,
    issued_to: &[u8; 5],
    timestamp: u64,
) -> Vec<u8> {
    // Per-tag size: 8 + 8 + 4 + 4 + 5 + 5 + 1 + 2 + 96 + 2 = 135 bytes
    let mut buf = Vec::with_capacity(tags.len() * 135);
    for tag in tags {
        buf.extend_from_slice(&network_id.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&tag.id.to_be_bytes());
        buf.extend_from_slice(&tag.value.to_be_bytes());
        buf.extend_from_slice(issued_to);
        buf.extend_from_slice(&[0u8; 5]); // signed_by (none)
        buf.push(0); // signature_type: none
        buf.extend_from_slice(&(SIGNATURE_LEN as u16).to_be_bytes());
        buf.extend_from_slice(&[0u8; SIGNATURE_LEN]); // stub signature
        buf.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
    }
    buf
}

/// Serialize capabilities for the CAP dictionary key.
///
/// Matches the wire layout of upstream `Capability::serialize`
/// (`node/Capability.hpp`, verified against the ZeroTier 1.14.2 source):
/// - network_id: u64 BE
/// - timestamp: i64 BE
/// - cap_id: u32 BE
/// - rule_count: u16 BE
/// - rules: serialized rule chain (same per-rule `type_and_flags, value_len,
///   value` format as the R key, which matches upstream's `serializeRules`)
/// - max_custody_chain_length: u8 (always 1: ManyTier issues non-transferable
///   capabilities directly, no chain-of-custody hand-off)
/// - custody chain: terminated immediately by a 5-byte zero `to` address,
///   since this stub issues no signature
/// - additional_fields_len: u16 BE (currently always 0)
pub fn serialize_capabilities(
    caps: &[Capability],
    network_id: u64,
    _issued_to: &[u8; 5],
    timestamp: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    for cap in caps {
        buf.extend_from_slice(&network_id.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&cap.id.to_be_bytes());
        buf.extend_from_slice(&(cap.rules.len() as u16).to_be_bytes());
        buf.extend_from_slice(&serialize_rules(&cap.rules));
        buf.push(1); // max_custody_chain_length
        buf.extend_from_slice(&[0u8; 5]); // terminate custody chain (unsigned)
        buf.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
    }
    buf
}

/// Serialize tags for the TAG dictionary key, signed with the controller's key.
///
/// Byte-verified against upstream `Tag::serialize`/`Tag::sign` (`node/Tag.hpp`,
/// ZeroTier 1.14.2 source): the signed range is `0x7f7f7f7f7f7f7f7f ||
/// network_id || timestamp || tag_id || tag_value || issued_to || signed_by ||
/// additional_fields_len(0) || 0x7f7f7f7f7f7f7f7f`, signed via
/// [`zerotier_crypto::signing::sign`] (the same Ed25519 + SHA-512-digest-suffix
/// scheme already used for the Certificate of Membership). The wire form then
/// carries `network_id || timestamp || tag_id || tag_value || issued_to ||
/// signed_by || signature_type(1) || signature_len(96) || signature ||
/// additional_fields_len(0)`: see [`serialize_tags`] for the unsigned layout
/// this mirrors. `signed_by` is the controller's own ZeroTier address (the
/// public counterpart of `signing_key`).
///
/// This is now byte-format-verified against the upstream source rather than
/// guessed, but: like the rest of this module: has not been confirmed by
/// running a real official `zerotier-one` peer against it the way COM and
/// HELLO were during v1.3-v1.7 interop work.
pub fn serialize_tags_signed(
    tags: &[Tag],
    network_id: u64,
    issued_to: &[u8; 5],
    signed_by: &[u8; 5],
    timestamp: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(tags.len() * 135);
    for tag in tags {
        let signed_data = tag_signed_data(network_id, timestamp, tag, issued_to, signed_by);
        let signature = zerotier_crypto::signing::sign(signing_key, &signed_data);

        buf.extend_from_slice(&network_id.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&tag.id.to_be_bytes());
        buf.extend_from_slice(&tag.value.to_be_bytes());
        buf.extend_from_slice(issued_to);
        buf.extend_from_slice(signed_by);
        buf.push(SIGNATURE_TYPE_ED25519);
        buf.extend_from_slice(&(SIGNATURE_LEN as u16).to_be_bytes());
        buf.extend_from_slice(&signature);
        buf.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
    }
    buf
}

/// Serialize capabilities for the CAP dictionary key, signed with the controller's key.
///
/// Byte-verified against upstream `Capability::serialize`/`Capability::sign`
/// (`node/Capability.hpp`, ZeroTier 1.14.2 source): the signed range is
/// `0x7f7f7f7f7f7f7f7f || network_id || timestamp || cap_id || rule_count ||
/// rules || max_custody_chain_length(1) || additional_fields_len(0) ||
/// 0x7f7f7f7f7f7f7f7f`, signed via [`zerotier_crypto::signing::sign`]. The
/// wire form then appends a single custody-chain entry: `to(issued_to) ||
/// from(signed_by) || signature_type(1) || signature_len(96) || signature`
///: followed by the zero-address chain terminator and
/// `additional_fields_len(0)`. ManyTier only ever issues a capability
/// directly (`max_custody_chain_length` is always 1, one custody entry),
/// never a transferable multi-hop chain. See [`serialize_tags_signed`] for
/// the same not-yet-live-interop-verified caveat.
pub fn serialize_capabilities_signed(
    caps: &[Capability],
    network_id: u64,
    issued_to: &[u8; 5],
    signed_by: &[u8; 5],
    timestamp: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    let mut buf = Vec::new();
    for cap in caps {
        let signed_data = capability_signed_data(network_id, timestamp, cap, 1);
        let signature = zerotier_crypto::signing::sign(signing_key, &signed_data);

        buf.extend_from_slice(&network_id.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&cap.id.to_be_bytes());
        buf.extend_from_slice(&(cap.rules.len() as u16).to_be_bytes());
        buf.extend_from_slice(&serialize_rules(&cap.rules));
        buf.push(1); // max_custody_chain_length
        buf.extend_from_slice(issued_to); // custody[0].to
        buf.extend_from_slice(signed_by); // custody[0].from
        buf.push(SIGNATURE_TYPE_ED25519);
        buf.extend_from_slice(&(SIGNATURE_LEN as u16).to_be_bytes());
        buf.extend_from_slice(&signature);
        buf.extend_from_slice(&[0u8; 5]); // terminate custody chain
        buf.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
    }
    buf
}

/// What upstream `Tag::sign`/`Tag::verify` sign: `Tag::serialize(b, true)`.
fn tag_signed_data(
    network_id: u64,
    timestamp: u64,
    tag: &Tag,
    issued_to: &[u8; 5],
    signed_by: &[u8; 5],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(52);
    data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
    data.extend_from_slice(&network_id.to_be_bytes());
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(&tag.id.to_be_bytes());
    data.extend_from_slice(&tag.value.to_be_bytes());
    data.extend_from_slice(issued_to);
    data.extend_from_slice(signed_by);
    data.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
    data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
    data
}

/// What upstream `Capability::sign`/`Capability::verify` sign:
/// `Capability::serialize(b, true)`, which leaves out the custody chain.
fn capability_signed_data(
    network_id: u64,
    timestamp: u64,
    cap: &Capability,
    max_custody_chain_length: u8,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
    data.extend_from_slice(&network_id.to_be_bytes());
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(&cap.id.to_be_bytes());
    data.extend_from_slice(&(cap.rules.len() as u16).to_be_bytes());
    data.extend_from_slice(&serialize_rules(&cap.rules));
    data.push(max_custody_chain_length);
    data.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
    data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
    data
}

/// Upstream `Network::controllerFor`: the top 40 bits of the network ID.
fn controller_for(network_id: u64) -> [u8; 5] {
    let b = network_id.to_be_bytes();
    [b[0], b[1], b[2], b[3], b[4]]
}

// ---------------------------------------------------------------------------
// Deserialization
// ---------------------------------------------------------------------------

// Limits from upstream include/ZeroTierOne.h.
pub const MAX_NETWORK_RULES: usize = 1024;
pub const MAX_NETWORK_CAPABILITIES: usize = 128;
pub const MAX_NETWORK_TAGS: usize = 128;
pub const MAX_CAPABILITY_RULES: usize = 64;
pub const MAX_CAPABILITY_CUSTODY_CHAIN_LENGTH: u8 = 7;

/// Why a rule chain, tag or capability failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleParseError {
    /// The data ended inside an object.
    Truncated,
    /// A capability declared more than [`MAX_CAPABILITY_RULES`] rules.
    TooManyRules,
    /// A capability's custody chain length was out of range or exceeded.
    InvalidCustodyChain,
    /// An Ed25519 signature was not 96 bytes long.
    InvalidSignatureLength,
}

impl core::fmt::Display for RuleParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "data ended inside a rule or credential"),
            Self::TooManyRules => write!(f, "capability has too many rules"),
            Self::InvalidCustodyChain => write!(f, "invalid capability custody chain"),
            Self::InvalidSignatureLength => write!(f, "invalid signature length"),
        }
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], RuleParseError> {
        let out = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(RuleParseError::Truncated)?;
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, RuleParseError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RuleParseError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, RuleParseError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, RuleParseError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.bytes(8)?);
        Ok(u64::from_be_bytes(b))
    }

    fn address(&mut self) -> Result<[u8; 5], RuleParseError> {
        let mut a = [0u8; 5];
        a.copy_from_slice(self.bytes(5)?);
        Ok(a)
    }

    /// `[u8 type][u16 len][len bytes]`. Upstream keeps only type 1
    /// (Ed25519, which must be 96 bytes); anything else stays all zero.
    fn signature(&mut self) -> Result<[u8; SIGNATURE_LEN], RuleParseError> {
        let mut sig = [0u8; SIGNATURE_LEN];
        if self.u8()? == SIGNATURE_TYPE_ED25519 {
            if self.u16()? as usize != SIGNATURE_LEN {
                return Err(RuleParseError::InvalidSignatureLength);
            }
            sig.copy_from_slice(self.bytes(SIGNATURE_LEN)?);
        } else {
            let len = self.u16()? as usize;
            self.bytes(len)?;
        }
        Ok(sig)
    }

    fn skip_additional_fields(&mut self) -> Result<(), RuleParseError> {
        let len = self.u16()? as usize;
        self.bytes(len).map(|_| ())
    }
}

/// Bytes upstream `Capability::deserializeRules` reads for a rule type's
/// value, whatever the encoded field length says. Zero for types it
/// ignores, including `ACTION_PRIORITY`, whose bucket it never parses.
fn rule_value_len(rule_type: u8) -> usize {
    match rule_type & 0x3F {
        ACTION_TEE | ACTION_WATCH | ACTION_REDIRECT => 14,
        MATCH_SOURCE_ZEROTIER_ADDRESS | MATCH_DEST_ZEROTIER_ADDRESS => 5,
        MATCH_VLAN_PCP | MATCH_VLAN_DEI | MATCH_IP_PROTOCOL => 1,
        MATCH_VLAN_ID | MATCH_ETHERTYPE => 2,
        MATCH_IP_TOS | MATCH_ICMP => 3,
        MATCH_IP_SOURCE_PORT_RANGE
        | MATCH_IP_DEST_PORT_RANGE
        | MATCH_FRAME_SIZE_RANGE
        | MATCH_RANDOM => 4,
        MATCH_IPV4_SOURCE | MATCH_IPV4_DEST => 5,
        MATCH_MAC_SOURCE | MATCH_MAC_DEST => 6,
        MATCH_CHARACTERISTICS
        | MATCH_TAGS_DIFFERENCE
        | MATCH_TAGS_BITWISE_AND
        | MATCH_TAGS_BITWISE_OR
        | MATCH_TAGS_BITWISE_XOR
        | MATCH_TAGS_EQUAL
        | MATCH_TAG_SENDER
        | MATCH_TAG_RECEIVER => 8,
        MATCH_IPV6_SOURCE | MATCH_IPV6_DEST => 17,
        MATCH_INTEGER_RANGE => 19,
        _ => 0,
    }
}

/// Port of upstream `Capability::deserializeRules`: up to `max` rules,
/// stopping at the end of the buffer. Values are stored the way upstream
/// holds them in memory, so [`serialize_rules`] reproduces upstream
/// `serializeRules` output -- the bytes capability signatures cover.
fn read_rules(r: &mut Reader<'_>, max: usize) -> Result<Vec<Rule>, RuleParseError> {
    let mut rules = Vec::new();
    while rules.len() < max && r.pos < r.buf.len() {
        let t = r.u8()?;
        let field_len = r.u8()? as usize;
        let start = r.pos;
        // Upstream reads each type's fixed layout from the field start even
        // when the declared length is shorter, then skips the declared length.
        let mut value = r.bytes(rule_value_len(t))?.to_vec();
        if t & 0x3F == MATCH_INTEGER_RANGE {
            // Upstream keeps `end` as a u32 delta from `start`.
            let mut s = [0u8; 8];
            let mut e = [0u8; 8];
            s.copy_from_slice(&value[0..8]);
            e.copy_from_slice(&value[8..16]);
            let (s, e) = (u64::from_be_bytes(s), u64::from_be_bytes(e));
            let end = s.wrapping_add(e.wrapping_sub(s) as u32 as u64);
            value[8..16].copy_from_slice(&end.to_be_bytes());
        }
        r.pos = start + field_len;
        rules.push(Rule {
            rule_type: t & 0x3F,
            not_flag: t & 0x80 != 0,
            or_flag: t & 0x40 != 0,
            value,
        });
    }
    Ok(rules)
}

/// Parse a network config's `R` value (upstream
/// `NetworkConfig::fromDictionary`, at most [`MAX_NETWORK_RULES`]).
pub fn deserialize_rules(data: &[u8]) -> Result<Vec<Rule>, RuleParseError> {
    read_rules(&mut Reader::new(data), MAX_NETWORK_RULES)
}

/// A signed tag as carried in the `TAG` config key and in
/// NETWORK_CREDENTIALS (upstream `Tag`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagCredential {
    pub network_id: u64,
    pub timestamp: u64,
    pub tag: Tag,
    pub issued_to: [u8; 5],
    pub signed_by: [u8; 5],
    /// All zero unless the signature type was Ed25519.
    pub signature: [u8; SIGNATURE_LEN],
}

impl TagCredential {
    /// Port of upstream `Tag::deserialize`; returns the tag and the number
    /// of bytes it took.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), RuleParseError> {
        let mut r = Reader::new(data);
        let network_id = r.u64()?;
        let timestamp = r.u64()?;
        let id = r.u32()?;
        let value = r.u32()?;
        let issued_to = r.address()?;
        let signed_by = r.address()?;
        let signature = r.signature()?;
        r.skip_additional_fields()?;
        let tag = TagCredential {
            network_id,
            timestamp,
            tag: Tag { id, value },
            issued_to,
            signed_by,
            signature,
        };
        Ok((tag, r.pos))
    }

    /// Port of upstream `Tag::verify` given the controller's key: the tag
    /// must be signed by its network's controller.
    pub fn verify(&self, controller_key: &ed25519_dalek::VerifyingKey) -> bool {
        if self.signed_by == [0u8; 5] || self.signed_by != controller_for(self.network_id) {
            return false;
        }
        let data = tag_signed_data(
            self.network_id,
            self.timestamp,
            &self.tag,
            &self.issued_to,
            &self.signed_by,
        );
        zerotier_crypto::signing::verify(controller_key, &data, &self.signature).is_ok()
    }
}

/// One link in a capability's chain of custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyLink {
    pub to: [u8; 5],
    pub from: [u8; 5],
    /// All zero unless the signature type was Ed25519.
    pub signature: [u8; SIGNATURE_LEN],
}

/// A signed capability as carried in the `CAP` config key and in
/// NETWORK_CREDENTIALS (upstream `Capability`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityCredential {
    pub network_id: u64,
    pub timestamp: u64,
    pub capability: Capability,
    pub max_custody_chain_length: u8,
    pub custody: Vec<CustodyLink>,
}

impl CapabilityCredential {
    /// Port of upstream `Capability::deserialize`; returns the capability
    /// and the number of bytes it took.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), RuleParseError> {
        let mut r = Reader::new(data);
        let network_id = r.u64()?;
        let timestamp = r.u64()?;
        let id = r.u32()?;
        let rule_count = r.u16()? as usize;
        if rule_count > MAX_CAPABILITY_RULES {
            return Err(RuleParseError::TooManyRules);
        }
        let rules = read_rules(&mut r, rule_count)?;
        let max_custody_chain_length = r.u8()?;
        if !(1..=MAX_CAPABILITY_CUSTODY_CHAIN_LENGTH).contains(&max_custody_chain_length) {
            return Err(RuleParseError::InvalidCustodyChain);
        }
        let mut custody = Vec::new();
        loop {
            let to = r.address()?;
            if to == [0u8; 5] {
                break;
            }
            if custody.len() >= max_custody_chain_length as usize {
                return Err(RuleParseError::InvalidCustodyChain);
            }
            let from = r.address()?;
            let signature = r.signature()?;
            custody.push(CustodyLink {
                to,
                from,
                signature,
            });
        }
        r.skip_additional_fields()?;
        let cap = CapabilityCredential {
            network_id,
            timestamp,
            capability: Capability { id, rules },
            max_custody_chain_length,
            custody,
        };
        Ok((cap, r.pos))
    }

    /// The last holder in the chain of custody (upstream
    /// `Capability::issuedTo`), all zero if there is none.
    pub fn issued_to(&self) -> [u8; 5] {
        self.custody.last().map(|link| link.to).unwrap_or_default()
    }

    /// Port of upstream `Capability::verify` given the controller's key.
    /// Upstream checks later custody links against each holder's identity;
    /// controllers only issue single-link capabilities, so a link signed by
    /// anyone but the controller is rejected here.
    pub fn verify(&self, controller_key: &ed25519_dalek::VerifyingKey) -> bool {
        let mccl = self.max_custody_chain_length;
        if !(1..=MAX_CAPABILITY_CUSTODY_CHAIN_LENGTH).contains(&mccl) {
            return false;
        }
        let controller = controller_for(self.network_id);
        let data = capability_signed_data(self.network_id, self.timestamp, &self.capability, mccl);
        for c in 0..mccl as usize {
            let link = match self.custody.get(c) {
                Some(link) if link.to != [0u8; 5] => link,
                // The first link must exist; the chain may end after it.
                _ => return c > 0,
            };
            let expected_from = if c == 0 {
                controller
            } else {
                self.custody[c - 1].to
            };
            if link.from == [0u8; 5] || link.from != expected_from || link.from != controller {
                return false;
            }
            if zerotier_crypto::signing::verify(controller_key, &data, &link.signature).is_err() {
                return false;
            }
        }
        true
    }
}

/// Parse a config's `CAP` value the way upstream
/// `NetworkConfig::fromDictionary` does: capabilities before a malformed
/// one are kept, and the result is sorted by ID (evaluation order).
pub fn deserialize_capabilities(data: &[u8]) -> Vec<CapabilityCredential> {
    let mut caps = Vec::new();
    let mut pos = 0;
    while pos < data.len() && caps.len() < MAX_NETWORK_CAPABILITIES {
        match CapabilityCredential::deserialize(&data[pos..]) {
            Ok((cap, used)) => {
                pos += used;
                caps.push(cap);
            }
            Err(_) => break,
        }
    }
    caps.sort_by_key(|cap| cap.capability.id);
    caps
}

/// Parse a config's `TAG` value; same rules as [`deserialize_capabilities`].
pub fn deserialize_tags(data: &[u8]) -> Vec<TagCredential> {
    let mut tags = Vec::new();
    let mut pos = 0;
    while pos < data.len() && tags.len() < MAX_NETWORK_TAGS {
        match TagCredential::deserialize(&data[pos..]) {
            Ok((tag, used)) => {
                pos += used;
                tags.push(tag);
            }
            Err(_) => break,
        }
    }
    tags.sort_by_key(|tag| tag.tag.id);
    tags
}

/// Read the capability and tag sections of a NETWORK_CREDENTIALS payload
/// (`NetworkCredentialsPayload::sections`) as upstream
/// `IncomingPacket::_doNETWORK_CREDENTIALS` does. The revocation and
/// certificate-of-ownership sections after them are not parsed.
pub fn deserialize_credential_sections(
    sections: &[u8],
) -> Result<(Vec<CapabilityCredential>, Vec<TagCredential>), RuleParseError> {
    let mut caps = Vec::new();
    let mut tags = Vec::new();
    if sections.is_empty() {
        return Ok((caps, tags));
    }
    let mut r = Reader::new(sections);
    for _ in 0..r.u16()? {
        let (cap, used) = CapabilityCredential::deserialize(&sections[r.pos..])?;
        r.pos += used;
        caps.push(cap);
    }
    if r.pos >= sections.len() {
        return Ok((caps, tags));
    }
    for _ in 0..r.u16()? {
        let (tag, used) = TagCredential::deserialize(&sections[r.pos..])?;
        r.pos += used;
        tags.push(tag);
    }
    Ok((caps, tags))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_type_name_covers_actions_and_matches() {
        assert_eq!(rule_type_name(ACTION_ACCEPT), "ACTION_ACCEPT");
        assert_eq!(rule_type_name(ACTION_DROP), "ACTION_DROP");
        assert_eq!(rule_type_name(MATCH_IP_PROTOCOL), "MATCH_IP_PROTOCOL");
        assert_eq!(rule_type_name(MATCH_INTEGER_RANGE), "MATCH_INTEGER_RANGE");
        // NOT/OR flag bits (0x80/0x40) must be masked off before lookup.
        assert_eq!(rule_type_name(MATCH_ETHERTYPE | 0x80), "MATCH_ETHERTYPE");
        assert_eq!(rule_type_name(0x3e), "UNKNOWN");
    }

    #[test]
    fn decode_rule_fields_returns_none_for_valueless_types() {
        assert_eq!(decode_rule_fields(ACTION_DROP, &[]), None);
        assert_eq!(decode_rule_fields(ACTION_ACCEPT, &[]), None);
        assert_eq!(decode_rule_fields(ACTION_BREAK, &[]), None);
        assert_eq!(decode_rule_fields(ACTION_PRIORITY, &[]), None);
        assert_eq!(decode_rule_fields(0x3e, &[1, 2, 3]), None);
    }

    #[test]
    fn decode_rule_fields_ip_protocol_and_ethertype_match_upstream_byte_widths() {
        // MATCH_ETHERTYPE: single u16 BE (matches
        // serialize_ethertype_match_then_accept's [0x08, 0x00] fixture).
        assert_eq!(
            decode_rule_fields(MATCH_ETHERTYPE, &[0x08, 0x00]),
            Some(RuleFields::EtherType(0x0800))
        );
        assert_eq!(
            decode_rule_fields(MATCH_IP_PROTOCOL, &[6]),
            Some(RuleFields::IpProtocol(6))
        );
    }

    #[test]
    fn rule_fields_round_trip_through_encode_decode_for_every_type() {
        let cases = [
            (
                ACTION_TEE,
                RuleFields::Forward {
                    address: 0x0102030405,
                    flags: 7,
                    length: 200,
                },
            ),
            (
                MATCH_SOURCE_ZEROTIER_ADDRESS,
                RuleFields::ZtAddress(0x8899aabbcc),
            ),
            (MATCH_VLAN_ID, RuleFields::VlanId(42)),
            (MATCH_VLAN_PCP, RuleFields::VlanPcp(3)),
            (MATCH_VLAN_DEI, RuleFields::VlanDei(1)),
            (
                MATCH_MAC_SOURCE,
                RuleFields::Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ),
            (
                MATCH_IPV4_SOURCE,
                RuleFields::Ipv4 {
                    ip: [10, 0, 0, 1],
                    mask: 24,
                },
            ),
            (
                MATCH_IPV6_SOURCE,
                RuleFields::Ipv6 {
                    ip: [0xfd; 16],
                    mask: 64,
                },
            ),
            (
                MATCH_IP_TOS,
                RuleFields::IpTos {
                    mask: 0xff,
                    start: 1,
                    end: 2,
                },
            ),
            (MATCH_IP_PROTOCOL, RuleFields::IpProtocol(17)),
            (MATCH_ETHERTYPE, RuleFields::EtherType(0x86dd)),
            (
                MATCH_ICMP,
                RuleFields::Icmp {
                    icmp_type: 8,
                    icmp_code: Some(0),
                },
            ),
            (
                MATCH_ICMP,
                RuleFields::Icmp {
                    icmp_type: 8,
                    icmp_code: None,
                },
            ),
            (
                MATCH_IP_SOURCE_PORT_RANGE,
                RuleFields::PortRange {
                    start: 1024,
                    end: 2048,
                },
            ),
            (
                MATCH_CHARACTERISTICS,
                RuleFields::Characteristics(0xdead_beef_1234_5678),
            ),
            (
                MATCH_FRAME_SIZE_RANGE,
                RuleFields::FrameSizeRange {
                    start: 64,
                    end: 1500,
                },
            ),
            (MATCH_RANDOM, RuleFields::RandomProbability(0x7fff_ffff)),
            (
                MATCH_TAGS_EQUAL,
                RuleFields::Tag {
                    id: 9,
                    value: 12345,
                },
            ),
            (
                MATCH_INTEGER_RANGE,
                RuleFields::IntegerRange {
                    start: 100,
                    end: 200,
                    idx: 4,
                    little: true,
                    bits: 32,
                },
            ),
        ];
        for (rule_type, fields) in cases {
            let encoded = encode_rule_fields(&fields);
            let decoded = decode_rule_fields(rule_type, &encoded);
            assert_eq!(
                decoded,
                Some(fields),
                "round-trip mismatch for rule_type {rule_type:#x}"
            );
        }
    }

    #[test]
    fn rule_type_constants_match_upstream_zt_virtualnetworkruletype() {
        // Pinned against `include/ZeroTierOne.h` `ZT_VirtualNetworkRuleType` at
        // ZeroTierOne tag 1.14.2, fetched 2026-07-03. A prior version of these
        // constants (MATCH_MAC_SOURCE and beyond) used a wrong systematic
        // offset that would have mis-encoded non-default rules on the wire.
        assert_eq!(ACTION_DROP, 0);
        assert_eq!(ACTION_ACCEPT, 1);
        assert_eq!(ACTION_TEE, 2);
        assert_eq!(ACTION_WATCH, 3);
        assert_eq!(ACTION_REDIRECT, 4);
        assert_eq!(ACTION_BREAK, 5);
        assert_eq!(ACTION_PRIORITY, 6);
        assert_eq!(MATCH_SOURCE_ZEROTIER_ADDRESS, 24);
        assert_eq!(MATCH_DEST_ZEROTIER_ADDRESS, 25);
        assert_eq!(MATCH_VLAN_ID, 26);
        assert_eq!(MATCH_VLAN_PCP, 27);
        assert_eq!(MATCH_VLAN_DEI, 28);
        assert_eq!(MATCH_MAC_SOURCE, 29);
        assert_eq!(MATCH_MAC_DEST, 30);
        assert_eq!(MATCH_IPV4_SOURCE, 31);
        assert_eq!(MATCH_IPV4_DEST, 32);
        assert_eq!(MATCH_IPV6_SOURCE, 33);
        assert_eq!(MATCH_IPV6_DEST, 34);
        assert_eq!(MATCH_IP_TOS, 35);
        assert_eq!(MATCH_IP_PROTOCOL, 36);
        assert_eq!(MATCH_ETHERTYPE, 37);
        assert_eq!(MATCH_ICMP, 38);
        assert_eq!(MATCH_IP_SOURCE_PORT_RANGE, 39);
        assert_eq!(MATCH_IP_DEST_PORT_RANGE, 40);
        assert_eq!(MATCH_CHARACTERISTICS, 41);
        assert_eq!(MATCH_FRAME_SIZE_RANGE, 42);
        assert_eq!(MATCH_RANDOM, 43);
        assert_eq!(MATCH_TAGS_DIFFERENCE, 44);
        assert_eq!(MATCH_TAGS_BITWISE_AND, 45);
        assert_eq!(MATCH_TAGS_BITWISE_OR, 46);
        assert_eq!(MATCH_TAGS_BITWISE_XOR, 47);
        assert_eq!(MATCH_TAGS_EQUAL, 48);
        assert_eq!(MATCH_TAG_SENDER, 49);
        assert_eq!(MATCH_TAG_RECEIVER, 50);
        assert_eq!(MATCH_INTEGER_RANGE, 51);
    }

    #[test]
    fn default_allow_all_serializes_to_accept() {
        let rules = default_allow_all();
        let bytes = serialize_rules(&rules);
        assert_eq!(bytes, vec![0x01, 0x00]);
    }

    #[test]
    fn serialize_ethertype_match_then_accept() {
        // Match ethertype 0x0800 (IPv4), then accept
        let rules = vec![
            Rule {
                rule_type: MATCH_ETHERTYPE,
                not_flag: false,
                or_flag: false,
                value: vec![0x08, 0x00], // ethertype as u16 BE
            },
            Rule {
                rule_type: ACTION_ACCEPT,
                not_flag: false,
                or_flag: false,
                value: vec![],
            },
        ];
        let bytes = serialize_rules(&rules);
        // First rule: type=0x25, len=2, value=[0x08, 0x00]
        // Second rule: type=0x01, len=0
        assert_eq!(bytes, vec![0x25, 0x02, 0x08, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn serialize_rules_with_not_and_or_flags() {
        let rules = vec![
            Rule {
                rule_type: MATCH_IP_PROTOCOL,
                not_flag: true,
                or_flag: false,
                value: vec![0x06], // TCP
            },
            Rule {
                rule_type: MATCH_IP_PROTOCOL,
                not_flag: false,
                or_flag: true,
                value: vec![0x11], // UDP
            },
            Rule {
                rule_type: ACTION_DROP,
                not_flag: false,
                or_flag: false,
                value: vec![],
            },
        ];
        let bytes = serialize_rules(&rules);

        // First rule: type=0x24 | NOT(0x80) = 0xA4, len=1, value=0x06
        assert_eq!(bytes[0], 0xA4);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[2], 0x06);

        // Second rule: type=0x24 | OR(0x40) = 0x64, len=1, value=0x11
        assert_eq!(bytes[3], 0x64);
        assert_eq!(bytes[4], 0x01);
        assert_eq!(bytes[5], 0x11);

        // Third rule: type=0x00, len=0
        assert_eq!(bytes[6], 0x00);
        assert_eq!(bytes[7], 0x00);
    }

    #[test]
    fn serialize_tags_format() {
        let tags = vec![Tag { id: 1, value: 100 }, Tag { id: 2, value: 200 }];
        let network_id = 0xff00001234560001u64;
        let issued_to = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let timestamp = 1000000u64;

        let bytes = serialize_tags(&tags, network_id, &issued_to, timestamp);

        // Each tag: 8 + 8 + 4 + 4 + 5 + 5 + 1 + 2 + 96 + 2 = 135 bytes
        assert_eq!(bytes.len(), 270);

        // First tag: check network_id
        assert_eq!(
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            network_id
        );
        // First tag: check timestamp
        assert_eq!(
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            timestamp
        );
        // First tag: check id
        assert_eq!(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), 1);
        // First tag: check value
        assert_eq!(u32::from_be_bytes(bytes[20..24].try_into().unwrap()), 100);
        // First tag: check issued_to
        assert_eq!(&bytes[24..29], &issued_to);
        // First tag: signed_by is zero (unsigned stub)
        assert_eq!(&bytes[29..34], &[0u8; 5]);
        // First tag: signature_type is 0 (none)
        assert_eq!(bytes[34], 0);
        // First tag: signature_len is 96
        assert_eq!(u16::from_be_bytes(bytes[35..37].try_into().unwrap()), 96);
        // First tag: stub signature is zeros
        assert!(bytes[37..133].iter().all(|&b| b == 0));
        // First tag: additional_fields_len is 0
        assert_eq!(u16::from_be_bytes(bytes[133..135].try_into().unwrap()), 0);
    }

    #[test]
    fn serialize_capabilities_format() {
        let caps = vec![Capability {
            id: 42,
            rules: vec![Rule {
                rule_type: ACTION_ACCEPT,
                not_flag: false,
                or_flag: false,
                value: vec![],
            }],
        }];
        let network_id = 0xff00001234560001u64;
        let issued_to = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let timestamp = 1000000u64;

        let bytes = serialize_capabilities(&caps, network_id, &issued_to, timestamp);

        // Header: 8 + 8 + 4 + 2 = 22 bytes
        // Rules: 2 bytes (accept = [0x01, 0x00])
        // max_custody_chain_length: 1 byte
        // Terminator: 5 bytes (zero 'to': unsigned stub)
        // additional_fields_len: 2 bytes
        // Total: 22 + 2 + 1 + 5 + 2 = 32 bytes
        assert_eq!(bytes.len(), 32);

        // Check cap_id
        assert_eq!(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), 42);
        // Check rule_count
        assert_eq!(u16::from_be_bytes(bytes[20..22].try_into().unwrap()), 1);
        // Check rules
        assert_eq!(&bytes[22..24], &[0x01, 0x00]);
        // max_custody_chain_length
        assert_eq!(bytes[24], 1);
        // Terminator ('to' == 0)
        assert_eq!(&bytes[25..30], &[0u8; 5]);
        // additional_fields_len
        assert_eq!(u16::from_be_bytes(bytes[30..32].try_into().unwrap()), 0);
    }

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn serialize_tags_signed_produces_nonzero_verifiable_signature() {
        let tags = vec![Tag { id: 1, value: 100 }];
        let network_id = 0xff00001234560001u64;
        let issued_to = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let signed_by = [0x11, 0x22, 0x33, 0x44, 0x55];
        let timestamp = 1000000u64;
        let signing_key = test_signing_key();

        let bytes = serialize_tags_signed(
            &tags,
            network_id,
            &issued_to,
            &signed_by,
            timestamp,
            &signing_key,
        );
        assert_eq!(bytes.len(), 135);

        // network_id || timestamp || id || value || issued_to || signed_by
        assert_eq!(&bytes[24..29], &issued_to);
        assert_eq!(&bytes[29..34], &signed_by);
        assert_eq!(bytes[34], SIGNATURE_TYPE_ED25519);
        assert_eq!(u16::from_be_bytes(bytes[35..37].try_into().unwrap()), 96);
        let signature: [u8; 96] = bytes[37..133].try_into().unwrap();
        assert_eq!(u16::from_be_bytes(bytes[133..135].try_into().unwrap()), 0);
        assert!(!signature.iter().all(|&b| b == 0));

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
        signed_data.extend_from_slice(&bytes[0..34]);
        signed_data.extend_from_slice(&0u16.to_be_bytes());
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
        assert!(zerotier_crypto::signing::verify(
            &signing_key.verifying_key(),
            &signed_data,
            &signature
        )
        .is_ok());
    }

    #[test]
    fn serialize_capabilities_signed_produces_nonzero_verifiable_signature() {
        let caps = vec![Capability {
            id: 42,
            rules: vec![Rule {
                rule_type: ACTION_ACCEPT,
                not_flag: false,
                or_flag: false,
                value: vec![],
            }],
        }];
        let network_id = 0xff00001234560001u64;
        let issued_to = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let signed_by = [0x11, 0x22, 0x33, 0x44, 0x55];
        let timestamp = 1000000u64;
        let signing_key = test_signing_key();

        let bytes = serialize_capabilities_signed(
            &caps,
            network_id,
            &issued_to,
            &signed_by,
            timestamp,
            &signing_key,
        );
        // Header (22) + rules (2) + max_custody_chain_length (1) + to (5) +
        // from (5) + sig_type (1) + sig_len (2) + sig (96) + terminator (5) +
        // additional_fields_len (2) = 141 bytes
        assert_eq!(bytes.len(), 141);

        assert_eq!(bytes[24], 1); // max_custody_chain_length
        assert_eq!(&bytes[25..30], &issued_to);
        assert_eq!(&bytes[30..35], &signed_by);
        assert_eq!(bytes[35], SIGNATURE_TYPE_ED25519);
        assert_eq!(u16::from_be_bytes(bytes[36..38].try_into().unwrap()), 96);
        let signature: [u8; 96] = bytes[38..134].try_into().unwrap();
        assert_eq!(&bytes[134..139], &[0u8; 5]); // chain terminator
        assert_eq!(u16::from_be_bytes(bytes[139..141].try_into().unwrap()), 0);
        assert!(!signature.iter().all(|&b| b == 0));

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
        signed_data.extend_from_slice(&bytes[0..25]);
        signed_data.extend_from_slice(&0u16.to_be_bytes());
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
        assert!(zerotier_crypto::signing::verify(
            &signing_key.verifying_key(),
            &signed_data,
            &signature
        )
        .is_ok());
    }

    // Upstream only accepts credentials signed by Network::controllerFor(nwid).
    const NWID: u64 = 0x1122_3344_5500_0001;
    const CONTROLLER: [u8; 5] = [0x11, 0x22, 0x33, 0x44, 0x55];
    const MEMBER: [u8; 5] = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];

    fn rule(rule_type: u8, fields: Option<RuleFields>) -> Rule {
        Rule {
            rule_type,
            not_flag: false,
            or_flag: false,
            value: fields.map(|f| encode_rule_fields(&f)).unwrap_or_default(),
        }
    }

    fn one_rule_of_each_type() -> Vec<Rule> {
        let mut rules = vec![
            rule(
                ACTION_TEE,
                Some(RuleFields::Forward {
                    address: 0x0102030405,
                    flags: 0,
                    length: 64,
                }),
            ),
            rule(MATCH_DEST_ZEROTIER_ADDRESS, Some(RuleFields::ZtAddress(7))),
            rule(MATCH_VLAN_ID, Some(RuleFields::VlanId(5))),
            rule(MATCH_VLAN_PCP, Some(RuleFields::VlanPcp(1))),
            rule(MATCH_MAC_DEST, Some(RuleFields::Mac([2; 6]))),
            rule(
                MATCH_IPV4_SOURCE,
                Some(RuleFields::Ipv4 {
                    ip: [10, 0, 0, 0],
                    mask: 8,
                }),
            ),
            rule(
                MATCH_IPV6_DEST,
                Some(RuleFields::Ipv6 {
                    ip: [0xfd; 16],
                    mask: 48,
                }),
            ),
            rule(
                MATCH_IP_TOS,
                Some(RuleFields::IpTos {
                    mask: 0xfc,
                    start: 8,
                    end: 16,
                }),
            ),
            rule(MATCH_IP_PROTOCOL, Some(RuleFields::IpProtocol(6))),
            rule(MATCH_ETHERTYPE, Some(RuleFields::EtherType(0x0800))),
            rule(
                MATCH_ICMP,
                Some(RuleFields::Icmp {
                    icmp_type: 8,
                    icmp_code: Some(0),
                }),
            ),
            rule(
                MATCH_IP_DEST_PORT_RANGE,
                Some(RuleFields::PortRange { start: 22, end: 22 }),
            ),
            rule(MATCH_CHARACTERISTICS, Some(RuleFields::Characteristics(2))),
            rule(
                MATCH_FRAME_SIZE_RANGE,
                Some(RuleFields::FrameSizeRange { start: 0, end: 900 }),
            ),
            rule(MATCH_RANDOM, Some(RuleFields::RandomProbability(1 << 31))),
            rule(MATCH_TAGS_EQUAL, Some(RuleFields::Tag { id: 1, value: 2 })),
            rule(
                MATCH_INTEGER_RANGE,
                Some(RuleFields::IntegerRange {
                    start: 1,
                    end: 9,
                    idx: 3,
                    little: false,
                    bits: 16,
                }),
            ),
            rule(ACTION_BREAK, None),
            rule(ACTION_DROP, None),
            rule(ACTION_ACCEPT, None),
        ];
        rules[2].not_flag = true;
        rules[3].or_flag = true;
        rules[4].not_flag = true;
        rules[4].or_flag = true;
        rules
    }

    #[test]
    fn deserialize_rules_round_trips_every_type_and_flag() {
        let rules = one_rule_of_each_type();
        assert_eq!(deserialize_rules(&serialize_rules(&rules)), Ok(rules));
        assert_eq!(deserialize_rules(&[]), Ok(vec![]));
    }

    #[test]
    fn deserialize_rules_drops_priority_bucket_like_upstream() {
        // Capability.hpp deserializeRules has no ACTION_PRIORITY case and
        // serializeRules writes it with length 0.
        let rules = deserialize_rules(&[ACTION_PRIORITY, 1, 3, ACTION_ACCEPT, 0]).unwrap();
        assert_eq!(
            rules,
            vec![rule(ACTION_PRIORITY, None), rule(ACTION_ACCEPT, None)]
        );
        assert_eq!(
            serialize_rules(&rules),
            vec![ACTION_PRIORITY, 0, ACTION_ACCEPT, 0]
        );
    }

    #[test]
    fn deserialize_rules_skips_unknown_type_payload() {
        let rules = deserialize_rules(&[0x3e, 3, 1, 2, 3, ACTION_DROP, 0]).unwrap();
        assert_eq!(rules, vec![rule(0x3e, None), rule(ACTION_DROP, None)]);
    }

    #[test]
    fn deserialize_rules_reads_fixed_layout_past_a_short_field_length() {
        // Capability.hpp deserializeRules reads at<uint16_t>(p) for an
        // ethertype and then advances by the declared length (1), so the
        // ethertype's second byte is reread as the next rule's type.
        let rules = deserialize_rules(&[MATCH_ETHERTYPE, 1, 0x08, 0x00, 0x00]).unwrap();
        assert_eq!(
            rules,
            vec![
                rule(MATCH_ETHERTYPE, Some(RuleFields::EtherType(0x0800))),
                rule(ACTION_DROP, None),
            ]
        );
    }

    #[test]
    fn deserialize_rules_keeps_integer_range_end_as_u32_delta() {
        let mut value = Vec::new();
        value.extend_from_slice(&10u64.to_be_bytes());
        value.extend_from_slice(&(10u64 + (1 << 32) + 5).to_be_bytes());
        value.extend_from_slice(&0u16.to_be_bytes());
        value.push(7);
        let mut wire = vec![MATCH_INTEGER_RANGE, 19];
        wire.extend_from_slice(&value);
        let rules = deserialize_rules(&wire).unwrap();
        assert_eq!(
            decode_rule_fields(rules[0].rule_type, &rules[0].value),
            Some(RuleFields::IntegerRange {
                start: 10,
                end: 15,
                idx: 0,
                little: false,
                bits: 8,
            })
        );
    }

    #[test]
    fn deserialize_rules_rejects_truncated_input() {
        assert_eq!(
            deserialize_rules(&[MATCH_ETHERTYPE]),
            Err(RuleParseError::Truncated)
        );
        assert_eq!(
            deserialize_rules(&[MATCH_ETHERTYPE, 2, 0x08]),
            Err(RuleParseError::Truncated)
        );
        // Upstream only throws when a read crosses the end, not when the
        // declared length does.
        assert_eq!(
            deserialize_rules(&[ACTION_ACCEPT, 9]),
            Ok(vec![rule(ACTION_ACCEPT, None)])
        );
    }

    fn signed_tag_bytes(tag: Tag, signed_by: &[u8; 5]) -> Vec<u8> {
        serialize_tags_signed(&[tag], NWID, &MEMBER, signed_by, 5000, &test_signing_key())
    }

    fn signed_capability_bytes(cap: &Capability) -> Vec<u8> {
        serialize_capabilities_signed(
            core::slice::from_ref(cap),
            NWID,
            &MEMBER,
            &CONTROLLER,
            5000,
            &test_signing_key(),
        )
    }

    #[test]
    fn tag_credential_parses_and_verifies_signed_tags() {
        let key = test_signing_key().verifying_key();
        let bytes = signed_tag_bytes(Tag { id: 3, value: 42 }, &CONTROLLER);
        let (tag, used) = TagCredential::deserialize(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(tag.network_id, NWID);
        assert_eq!(tag.timestamp, 5000);
        assert_eq!(tag.tag, Tag { id: 3, value: 42 });
        assert_eq!(tag.issued_to, MEMBER);
        assert_eq!(tag.signed_by, CONTROLLER);
        assert!(tag.verify(&key));

        let mut tampered = tag.clone();
        tampered.tag.value = 43;
        assert!(!tampered.verify(&key));

        let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        assert!(!tag.verify(&wrong_key));
    }

    #[test]
    fn tag_credential_requires_the_network_controller_as_signer() {
        // Tag.cpp verify: signedBy must equal Network::controllerFor(nwid).
        let key = test_signing_key().verifying_key();
        let bytes = signed_tag_bytes(Tag { id: 3, value: 42 }, &[9; 5]);
        let (tag, _) = TagCredential::deserialize(&bytes).unwrap();
        assert!(!tag.verify(&key));
    }

    #[test]
    fn unsigned_tags_parse_but_do_not_verify() {
        let bytes = serialize_tags(&[Tag { id: 1, value: 1 }], NWID, &MEMBER, 1);
        let (tag, used) = TagCredential::deserialize(&bytes).unwrap();
        assert_eq!(used, 135);
        assert_eq!(tag.signature, [0u8; 96]);
        assert!(!tag.verify(&test_signing_key().verifying_key()));
    }

    #[test]
    fn tag_credential_rejects_bad_signature_length_and_truncation() {
        let mut bytes = signed_tag_bytes(Tag { id: 3, value: 42 }, &CONTROLLER);
        assert_eq!(
            TagCredential::deserialize(&bytes[..134]),
            Err(RuleParseError::Truncated)
        );
        bytes[36] = 95; // signature length low byte
        assert_eq!(
            TagCredential::deserialize(&bytes),
            Err(RuleParseError::InvalidSignatureLength)
        );
    }

    #[test]
    fn capability_credential_parses_and_verifies_signed_capabilities() {
        let key = test_signing_key().verifying_key();
        let cap = Capability {
            id: 77,
            rules: one_rule_of_each_type(),
        };
        let bytes = signed_capability_bytes(&cap);
        let (parsed, used) = CapabilityCredential::deserialize(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(parsed.network_id, NWID);
        assert_eq!(parsed.timestamp, 5000);
        assert_eq!(parsed.capability, cap);
        assert_eq!(parsed.max_custody_chain_length, 1);
        assert_eq!(parsed.custody.len(), 1);
        assert_eq!(parsed.custody[0].from, CONTROLLER);
        assert_eq!(parsed.issued_to(), MEMBER);
        assert!(parsed.verify(&key));

        let mut tampered = parsed.clone();
        tampered.capability.rules.pop();
        assert!(!tampered.verify(&key));

        let mut forged = parsed.clone();
        forged.custody[0].from = [9; 5];
        assert!(!forged.verify(&key));
    }

    #[test]
    fn unsigned_capabilities_parse_but_do_not_verify() {
        let cap = Capability {
            id: 1,
            rules: default_allow_all(),
        };
        let bytes = serialize_capabilities(core::slice::from_ref(&cap), NWID, &MEMBER, 1);
        let (parsed, used) = CapabilityCredential::deserialize(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(parsed.capability, cap);
        assert!(parsed.custody.is_empty());
        assert_eq!(parsed.issued_to(), [0u8; 5]);
        assert!(!parsed.verify(&test_signing_key().verifying_key()));
    }

    #[test]
    fn capability_credential_rejects_bad_headers() {
        let cap = Capability {
            id: 1,
            rules: default_allow_all(),
        };
        let bytes = signed_capability_bytes(&cap);
        // Byte 24 is max_custody_chain_length; upstream accepts 1..=7.
        for bad in [0u8, 8] {
            let mut b = bytes.clone();
            b[24] = bad;
            assert_eq!(
                CapabilityCredential::deserialize(&b),
                Err(RuleParseError::InvalidCustodyChain)
            );
        }
        let mut too_many = bytes.clone();
        too_many[20..22].copy_from_slice(&65u16.to_be_bytes());
        assert_eq!(
            CapabilityCredential::deserialize(&too_many),
            Err(RuleParseError::TooManyRules)
        );
        // A second custody link with max_custody_chain_length 1.
        let mut long_chain = bytes[..134].to_vec();
        long_chain.extend_from_slice(&bytes[25..134]);
        long_chain.extend_from_slice(&bytes[134..]);
        assert_eq!(
            CapabilityCredential::deserialize(&long_chain),
            Err(RuleParseError::InvalidCustodyChain)
        );
        assert_eq!(
            CapabilityCredential::deserialize(&bytes[..bytes.len() - 1]),
            Err(RuleParseError::Truncated)
        );
    }

    #[test]
    fn deserialize_capabilities_keeps_the_valid_prefix_sorted_by_id() {
        let mut data = signed_capability_bytes(&Capability {
            id: 9,
            rules: default_allow_all(),
        });
        data.extend_from_slice(&signed_capability_bytes(&Capability {
            id: 3,
            rules: vec![],
        }));
        data.extend_from_slice(&[0xff; 7]);
        let ids: Vec<u32> = deserialize_capabilities(&data)
            .iter()
            .map(|cap| cap.capability.id)
            .collect();
        assert_eq!(ids, vec![3, 9]);
    }

    #[test]
    fn deserialize_tags_keeps_the_valid_prefix_sorted_by_id() {
        let mut data = signed_tag_bytes(Tag { id: 20, value: 1 }, &CONTROLLER);
        data.extend_from_slice(&signed_tag_bytes(Tag { id: 10, value: 2 }, &CONTROLLER));
        data.extend_from_slice(&[0x00; 30]);
        let tags: Vec<Tag> = deserialize_tags(&data).into_iter().map(|t| t.tag).collect();
        assert_eq!(
            tags,
            vec![Tag { id: 10, value: 2 }, Tag { id: 20, value: 1 }]
        );
    }

    #[test]
    fn credential_sections_round_trip_through_network_credentials_layout() {
        use zerotier_protocol::verbs::network_config::NetworkCredentialsPayload;
        let cap = Capability {
            id: 4,
            rules: default_allow_all(),
        };
        let cap_bytes = signed_capability_bytes(&cap);
        let mut tag_bytes = signed_tag_bytes(Tag { id: 1, value: 2 }, &CONTROLLER);
        tag_bytes.extend_from_slice(&signed_tag_bytes(Tag { id: 2, value: 3 }, &CONTROLLER));
        let sections = NetworkCredentialsPayload::sections_from(1, &cap_bytes, 2, &tag_bytes);

        let (caps, tags) = deserialize_credential_sections(&sections).unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].capability, cap);
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[1].tag, Tag { id: 2, value: 3 });

        // Older peers send no sections; a capability section alone is fine.
        assert_eq!(deserialize_credential_sections(&[]), Ok((vec![], vec![])));
        let mut caps_only = 1u16.to_be_bytes().to_vec();
        caps_only.extend_from_slice(&cap_bytes);
        let (caps, tags) = deserialize_credential_sections(&caps_only).unwrap();
        assert_eq!((caps.len(), tags.len()), (1, 0));
        assert_eq!(
            deserialize_credential_sections(&sections[..sections.len() - 50]),
            Err(RuleParseError::Truncated)
        );
    }
}
