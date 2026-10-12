//! VL2 flow rule evaluation, ported from ZeroTier One's `_doZtFilter`,
//! `Network::filterOutgoingPacket` and `Network::filterIncomingPacket`
//! (node/Network.cpp, 1.14.x).
//!
//! The engine does no I/O: it returns a [`FilterDecision`] saying whether
//! to deliver the frame and which copies (TEE, WATCH, REDIRECT) the caller
//! should send as EXT_FRAME packets.

extern crate alloc;

use alloc::vec::Vec;

use crate::controller::dictionary::Dictionary;
use crate::controller::rules::{
    self, decode_rule_fields, Capability, CapabilityCredential, Rule, RuleFields, RuleParseError,
    TagCredential, ACTION_ACCEPT, ACTION_BREAK, ACTION_DROP, ACTION_PRIORITY, ACTION_REDIRECT,
    ACTION_TEE, ACTION_WATCH, MATCH_IPV4_SOURCE, MATCH_IPV6_SOURCE, MATCH_IP_DEST_PORT_RANGE,
    MATCH_MAC_SOURCE, MATCH_SOURCE_ZEROTIER_ADDRESS, MATCH_TAGS_BITWISE_AND, MATCH_TAGS_BITWISE_OR,
    MATCH_TAGS_BITWISE_XOR, MATCH_TAGS_DIFFERENCE, MATCH_TAGS_EQUAL, MATCH_TAG_RECEIVER,
    MATCH_TAG_SENDER,
};
use crate::ethernet::{ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6};

// ZT_RULE_PACKET_CHARACTERISTICS_* (include/ZeroTierOne.h). The low 12
// bits are the TCP flags.
pub const CHARACTERISTICS_INBOUND: u64 = 0x8000_0000_0000_0000;
pub const CHARACTERISTICS_MULTICAST: u64 = 0x4000_0000_0000_0000;
pub const CHARACTERISTICS_BROADCAST: u64 = 0x2000_0000_0000_0000;
pub const CHARACTERISTICS_SENDER_IP_AUTHENTICATED: u64 = 0x1000_0000_0000_0000;
pub const CHARACTERISTICS_SENDER_MAC_AUTHENTICATED: u64 = 0x0800_0000_0000_0000;

/// `ZT_NETWORKCONFIG_FLAG_RULES_RESULT_OF_UNSUPPORTED_MATCH`: the result of
/// a MATCH type this node does not know.
pub const NETWORK_FLAG_RULES_RESULT_OF_UNSUPPORTED_MATCH: u64 = 0x08;

// ZT_NETWORK_RULE_ACTION__MAX_ID: types up to here are actions.
const ACTION_MAX_ID: u8 = 15;
const DEFAULT_QOS_BUCKET: u8 = 4;

// EXT_FRAME flag bytes upstream sends filter copies with.
const EXT_FRAME_TEE_OUTBOUND: u8 = 0x02;
const EXT_FRAME_WATCH_OUTBOUND: u8 = 0x16;
const EXT_FRAME_REDIRECT_OUTBOUND: u8 = 0x04;
const EXT_FRAME_TEE_INBOUND: u8 = 0x08;
const EXT_FRAME_WATCH_INBOUND: u8 = 0x1c;
const EXT_FRAME_REDIRECT_INBOUND: u8 = 0x0a;

/// The parts of our network config the filter reads (upstream
/// `NetworkConfig`'s rules, capabilities, tags, flags, timestamp and
/// credential time window).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkRules {
    pub network_id: u64,
    pub timestamp: u64,
    pub credential_time_max_delta: u64,
    pub flags: u64,
    pub rules: Vec<Rule>,
    /// Our own capabilities, in evaluation (ID) order.
    pub capabilities: Vec<CapabilityCredential>,
    /// Our own tags, sorted by ID.
    pub tags: Vec<TagCredential>,
}

impl NetworkRules {
    /// Read the filter's fields from a network config dictionary, as
    /// upstream `NetworkConfig::fromDictionary` does. Without an `R` key
    /// there are no rules and every frame is dropped, as upstream.
    pub fn from_dictionary(dict: &Dictionary) -> Result<Self, RuleParseError> {
        let rules = match dict.get_binary("R") {
            Some(data) => rules::deserialize_rules(data)?,
            None => Vec::new(),
        };
        Ok(NetworkRules {
            network_id: dict.get_hex_u64("nwid").unwrap_or(0),
            timestamp: dict.get_hex_u64("ts").unwrap_or(0),
            credential_time_max_delta: dict.get_hex_u64("ctmd").unwrap_or(0),
            flags: dict.get_hex_u64("f").unwrap_or(0),
            rules,
            capabilities: dict
                .get_binary("CAP")
                .map(rules::deserialize_capabilities)
                .unwrap_or_default(),
            tags: dict
                .get_binary("TAG")
                .map(rules::deserialize_tags)
                .unwrap_or_default(),
        })
    }

    /// Upstream `Membership::_isCredentialTimestampValid` (no revocations):
    /// a peer's credential counts only within the config's time window.
    pub fn credential_timestamp_valid(&self, timestamp: u64) -> bool {
        timestamp.abs_diff(self.timestamp) <= self.credential_time_max_delta
    }

    fn local_tag(&self, id: u32) -> Option<u32> {
        self.tags
            .iter()
            .find(|t| t.tag.id == id)
            .map(|t| t.tag.value)
    }
}

/// Outcome of offering a peer's credential to [`PeerCredentials`]
/// (upstream `Membership::AddCredentialResult`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddCredentialResult {
    Rejected,
    AcceptedNew,
    AcceptedRedundant,
}

/// Tags and capabilities one member presented via NETWORK_CREDENTIALS:
/// the filter's half of upstream `Membership` (`_remoteTags`,
/// `_remoteCaps`). Upstream files a credential under its `issued_to`
/// member, not under whoever sent it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerCredentials {
    pub tags: Vec<TagCredential>,
    /// Kept sorted by ID; upstream iterates a hash table instead.
    pub capabilities: Vec<CapabilityCredential>,
}

impl PeerCredentials {
    /// Port of `Network::addCredential(Tag)` and `_addCredImpl`, minus
    /// revocation checks.
    pub fn add_tag(
        &mut self,
        config: &NetworkRules,
        tag: TagCredential,
        controller_key: &ed25519_dalek::VerifyingKey,
    ) -> AddCredentialResult {
        if tag.network_id != config.network_id {
            return AddCredentialResult::Rejected;
        }
        let slot = self.tags.iter().position(|t| t.tag.id == tag.tag.id);
        if let Some(i) = slot {
            if self.tags[i].timestamp > tag.timestamp {
                return AddCredentialResult::Rejected;
            }
            if self.tags[i] == tag {
                return AddCredentialResult::AcceptedRedundant;
            }
        }
        if !tag.verify(controller_key) {
            return AddCredentialResult::Rejected;
        }
        match slot {
            Some(i) => self.tags[i] = tag,
            None => self.tags.push(tag),
        }
        AddCredentialResult::AcceptedNew
    }

    /// Port of `Network::addCredential(Capability)` and `_addCredImpl`,
    /// minus revocation checks.
    pub fn add_capability(
        &mut self,
        config: &NetworkRules,
        cap: CapabilityCredential,
        controller_key: &ed25519_dalek::VerifyingKey,
    ) -> AddCredentialResult {
        if cap.network_id != config.network_id {
            return AddCredentialResult::Rejected;
        }
        let id = cap.capability.id;
        let slot = self.capabilities.iter().position(|c| c.capability.id == id);
        if let Some(i) = slot {
            if self.capabilities[i].timestamp > cap.timestamp {
                return AddCredentialResult::Rejected;
            }
            if self.capabilities[i] == cap {
                return AddCredentialResult::AcceptedRedundant;
            }
        }
        if !cap.verify(controller_key) {
            return AddCredentialResult::Rejected;
        }
        match slot {
            Some(i) => self.capabilities[i] = cap,
            None => {
                self.capabilities.push(cap);
                self.capabilities.sort_by_key(|c| c.capability.id);
            }
        }
        AddCredentialResult::AcceptedNew
    }

    /// Upstream `Membership::clean`: drop credentials outside the current
    /// config's time window.
    pub fn clean(&mut self, config: &NetworkRules) {
        self.tags
            .retain(|t| config.credential_timestamp_valid(t.timestamp));
        self.capabilities
            .retain(|c| config.credential_timestamp_valid(c.timestamp));
    }

    // Membership::getTag
    fn tag(&self, config: &NetworkRules, id: u32) -> Option<u32> {
        self.tags
            .iter()
            .find(|t| t.tag.id == id && config.credential_timestamp_valid(t.timestamp))
            .map(|t| t.tag.value)
    }

    // Membership::CapabilityIterator
    fn valid_capabilities<'a>(
        &'a self,
        config: &'a NetworkRules,
    ) -> impl Iterator<Item = &'a Capability> + 'a {
        self.capabilities
            .iter()
            .filter(|c| config.credential_timestamp_valid(c.timestamp))
            .map(|c| &c.capability)
    }
}

/// Certificate-of-ownership lookups behind the SENDER_IP_AUTHENTICATED and
/// SENDER_MAC_AUTHENTICATED characteristics: our config's certificates on
/// outbound frames, the sender's (upstream
/// `Membership::hasCertificateOfOwnershipFor`) on inbound ones.
pub trait OwnershipCheck {
    /// `ip` is 4 or 16 bytes.
    fn owns_ip(&self, ip: &[u8]) -> bool;
    fn owns_mac(&self, mac: &[u8; 6]) -> bool;
}

/// Our side of the network, as the filter needs it.
#[derive(Clone, Copy)]
pub struct FilterEnv<'a> {
    pub config: &'a NetworkRules,
    pub our_address: [u8; 5],
    /// The other member: the destination of an outbound frame (`None` if
    /// it has no single ZeroTier destination), the sender of an inbound one.
    pub peer: Option<&'a PeerCredentials>,
    /// `None` when there are no certificates of ownership; then only
    /// upstream's neighbor-solicitation exception authenticates anything.
    pub ownership: Option<&'a dyn OwnershipCheck>,
}

/// An Ethernet frame as the filter sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub zt_source: [u8; 5],
    /// `None` for multicast, or bridged frames before a bridge is chosen.
    pub zt_dest: Option<[u8; 5]>,
    pub mac_source: [u8; 6],
    pub mac_dest: [u8; 6],
    pub ethertype: u16,
    /// Upstream always passes 0.
    pub vlan_id: u16,
    /// The Ethernet payload, without the 14-byte header.
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Drop,
    Accept,
    /// Inbound only: we are a TEE/WATCH/REDIRECT target, so deliver even
    /// where bridging or MAC checks would refuse (upstream return value 2).
    SuperAccept,
}

/// A copy of the frame to send to another member as EXT_FRAME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameCopy {
    pub to: [u8; 5],
    /// How many leading payload bytes to include.
    pub length: usize,
    /// The EXT_FRAME flags byte upstream sends with this copy.
    pub ext_frame_flags: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterDecision {
    /// What to do with the frame itself. A redirected frame is dropped.
    pub verdict: Verdict,
    /// TEE/WATCH copy asked for by the capability that accepted the frame.
    pub capability_tee: Option<FrameCopy>,
    /// TEE/WATCH copy asked for by the network rules.
    pub tee: Option<FrameCopy>,
    /// Where a REDIRECT sends the whole frame instead.
    pub redirect: Option<FrameCopy>,
    /// Outbound QoS bucket set by ACTION_PRIORITY, if one fired.
    pub qos_bucket: Option<u8>,
    /// The capability whose rules accepted the frame.
    pub capability_id: Option<u32>,
}

impl FilterDecision {
    fn dropped() -> Self {
        FilterDecision {
            verdict: Verdict::Drop,
            capability_tee: None,
            tee: None,
            redirect: None,
            qos_bucket: None,
            capability_id: None,
        }
    }

    /// The copies to send, in the order upstream sends them.
    pub fn copies(&self) -> impl Iterator<Item = &FrameCopy> {
        self.capability_tee
            .iter()
            .chain(self.tee.iter())
            .chain(self.redirect.iter())
    }
}

/// Port of `Network::filterOutgoingPacket`: network rules, then our own
/// capabilities. `no_tee` suppresses TEE/WATCH copies, as upstream does
/// for per-recipient multicast and bridge passes.
pub fn filter_outgoing(
    env: &FilterEnv<'_>,
    frame: &Frame<'_>,
    no_tee: bool,
    rng: &mut dyn FnMut() -> u32,
) -> FilterDecision {
    let eval = Eval {
        env: *env,
        frame,
        inbound: false,
    };
    let zt_dest = frame.zt_dest.as_ref().map_or(0, addr_u64);
    let mut final_dest = zt_dest;
    let mut cc = None;
    let mut qos = None;
    let mut decision = FilterDecision::dropped();

    match eval.run(&env.config.rules, &mut final_dest, &mut cc, &mut qos, rng) {
        ZtFilterResult::Drop => return decision,
        ZtFilterResult::NoMatch => {
            let mut accepted = false;
            for cap in &env.config.capabilities {
                final_dest = zt_dest;
                let mut cc2 = None;
                let rules = &cap.capability.rules;
                match eval.run(rules, &mut final_dest, &mut cc2, &mut qos, rng) {
                    // A DROP in a capability only ends that capability.
                    ZtFilterResult::NoMatch | ZtFilterResult::Drop => {}
                    _ => {
                        accepted = true;
                        decision.capability_id = Some(cap.capability.id);
                        if !no_tee {
                            decision.capability_tee = tee_copy(cc2, false);
                        }
                        break;
                    }
                }
            }
            if !accepted {
                return decision;
            }
        }
        // There is no outbound super-accept.
        _ => {}
    }

    decision.qos_bucket = qos;
    if !no_tee {
        decision.tee = tee_copy(cc, false);
    }
    finish(decision, frame, zt_dest, final_dest, Verdict::Accept, false)
}

/// Port of `Network::filterIncomingPacket`: network rules, then the
/// capabilities the sender presented (`env.peer`).
pub fn filter_incoming(
    env: &FilterEnv<'_>,
    frame: &Frame<'_>,
    rng: &mut dyn FnMut() -> u32,
) -> FilterDecision {
    let eval = Eval {
        env: *env,
        frame,
        inbound: true,
    };
    let zt_dest = frame.zt_dest.as_ref().map_or(0, addr_u64);
    let mut final_dest = zt_dest;
    let mut cc = None;
    // Upstream passes a dummy bucket for inbound frames.
    let mut qos = None;
    let mut decision = FilterDecision::dropped();

    let verdict = match eval.run(&env.config.rules, &mut final_dest, &mut cc, &mut qos, rng) {
        ZtFilterResult::Drop => return decision,
        ZtFilterResult::NoMatch => {
            let caps = env
                .peer
                .into_iter()
                .flat_map(|peer| peer.valid_capabilities(env.config));
            let mut verdict = None;
            for cap in caps {
                final_dest = zt_dest;
                let mut cc2 = None;
                verdict = match eval.run(&cap.rules, &mut final_dest, &mut cc2, &mut qos, rng) {
                    ZtFilterResult::NoMatch | ZtFilterResult::Drop => None,
                    ZtFilterResult::SuperAccept => Some(Verdict::SuperAccept),
                    _ => Some(Verdict::Accept),
                };
                if verdict.is_some() {
                    decision.capability_id = Some(cap.id);
                    decision.capability_tee = tee_copy(cc2, true);
                    break;
                }
            }
            match verdict {
                Some(verdict) => verdict,
                None => return decision,
            }
        }
        ZtFilterResult::SuperAccept => Verdict::SuperAccept,
        _ => Verdict::Accept,
    };

    decision.tee = tee_copy(cc, true);
    finish(decision, frame, zt_dest, final_dest, verdict, true)
}

fn finish(
    mut decision: FilterDecision,
    frame: &Frame<'_>,
    zt_dest: u64,
    final_dest: u64,
    verdict: Verdict,
    inbound: bool,
) -> FilterDecision {
    if final_dest != zt_dest && final_dest != 0 {
        decision.redirect = Some(FrameCopy {
            to: addr_bytes(final_dest),
            length: frame.payload.len(),
            ext_frame_flags: if inbound {
                EXT_FRAME_REDIRECT_INBOUND
            } else {
                EXT_FRAME_REDIRECT_OUTBOUND
            },
        });
        decision.verdict = Verdict::Drop;
    } else {
        decision.verdict = verdict;
    }
    decision
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZtFilterResult {
    NoMatch,
    Drop,
    Redirect,
    Accept,
    SuperAccept,
}

#[derive(Debug, Clone, Copy)]
struct Tee {
    to: u64,
    length: usize,
    watch: bool,
}

fn tee_copy(cc: Option<Tee>, inbound: bool) -> Option<FrameCopy> {
    // Upstream only sends when the address is non-zero.
    let cc = cc.filter(|cc| cc.to != 0)?;
    let ext_frame_flags = match (inbound, cc.watch) {
        (false, false) => EXT_FRAME_TEE_OUTBOUND,
        (false, true) => EXT_FRAME_WATCH_OUTBOUND,
        (true, false) => EXT_FRAME_TEE_INBOUND,
        (true, true) => EXT_FRAME_WATCH_INBOUND,
    };
    Some(FrameCopy {
        to: addr_bytes(cc.to),
        length: cc.length,
        ext_frame_flags,
    })
}

fn addr_u64(a: &[u8; 5]) -> u64 {
    a.iter().fold(0, |acc, &b| (acc << 8) | b as u64)
}

fn addr_bytes(a: u64) -> [u8; 5] {
    let b = a.to_be_bytes();
    [b[3], b[4], b[5], b[6], b[7]]
}

// Rule values are a zero-initialized union upstream; pad short ones alike.
fn rule_fields(rule: &Rule) -> Option<RuleFields> {
    let mut value = [0u8; 19];
    let n = rule.value.len().min(value.len());
    value[..n].copy_from_slice(&rule.value[..n]);
    decode_rule_fields(rule.rule_type, &value)
}

// `Address(rules[rn].v.fwd.address)`: masked to 40 bits.
fn forward_target(rule: &Rule) -> (u64, u16) {
    match rule_fields(rule) {
        Some(RuleFields::Forward {
            address, length, ..
        }) => (address & 0xff_ffff_ffff, length),
        _ => (0, 0),
    }
}

/// Port of `_ipv6GetPayload`: walk hop-by-hop, routing, destination
/// options and mobility headers. Returns the payload offset and protocol.
fn ipv6_payload(p: &[u8]) -> Option<(usize, u8)> {
    if p.len() < 40 {
        return None;
    }
    let mut pos = 40;
    let mut proto = p[6];
    while pos <= p.len() {
        match proto {
            0 | 43 | 60 | 135 => {
                if pos + 8 > p.len() {
                    return None;
                }
                proto = p[pos];
                pos += p[pos + 1] as usize * 8 + 8;
            }
            // Fragments (44) and IPsec (50, 51) stop the walk too.
            _ => return Some((pos, proto)),
        }
    }
    None
}

// InetAddress::containsAddress for IPv4: compare the top `bits` bits.
fn ipv4_contains(net: [u8; 4], bits: u8, addr: &[u8]) -> bool {
    let bits = bits.min(32) as u32;
    if bits == 0 {
        return true;
    }
    let a = u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]);
    let n = u32::from_be_bytes(net);
    a >> (32 - bits) == n >> (32 - bits)
}

// InetAddress::containsAddress for IPv6 masks only the packet's address,
// so a rule address with host bits set never matches.
fn ipv6_contains(net: [u8; 16], bits: u8, addr: &[u8]) -> bool {
    let mask = u128::MAX
        .checked_shl(128 - bits.min(128) as u32)
        .unwrap_or(0);
    let mut a = [0u8; 16];
    a.copy_from_slice(&addr[..16]);
    u128::from_be_bytes(a) & mask == u128::from_be_bytes(net)
}

fn is_port_protocol(proto: u8) -> bool {
    // TCP, UDP, SCTP and UDP-Lite all start with source and dest ports.
    matches!(proto, 0x06 | 0x11 | 0x84 | 0x88)
}

struct Eval<'a> {
    env: FilterEnv<'a>,
    frame: &'a Frame<'a>,
    inbound: bool,
}

impl Eval<'_> {
    /// Port of `_doZtFilter`. `zt_dest` changes on REDIRECT, `cc` is set
    /// by TEE/WATCH and `qos` by PRIORITY.
    fn run(
        &self,
        rules: &[Rule],
        zt_dest: &mut u64,
        cc: &mut Option<Tee>,
        qos: &mut Option<u8>,
        rng: &mut dyn FnMut() -> u32,
    ) -> ZtFilterResult {
        let zt_source = addr_u64(&self.frame.zt_source);
        let our_address = addr_u64(&self.env.our_address);
        let frame_len = self.frame.payload.len();
        let mut super_accept = false;
        // An action with no MATCH before it is always taken.
        let mut this_set_matches = true;
        let mut skip_drop = false;

        for rule in rules {
            let rt = rule.rule_type & 0x3F;

            if rt <= ACTION_MAX_ID {
                if this_set_matches {
                    match rt {
                        ACTION_PRIORITY => {
                            let bucket = rule.value.first().copied().unwrap_or(0);
                            *qos = Some(if bucket <= 8 {
                                bucket
                            } else {
                                DEFAULT_QOS_BUCKET
                            });
                            return ZtFilterResult::Accept;
                        }
                        ACTION_DROP => {
                            if skip_drop {
                                skip_drop = false;
                                continue;
                            }
                            return ZtFilterResult::Drop;
                        }
                        ACTION_ACCEPT => {
                            return if super_accept {
                                ZtFilterResult::SuperAccept
                            } else {
                                ZtFilterResult::Accept
                            };
                        }
                        ACTION_TEE | ACTION_WATCH | ACTION_REDIRECT => {
                            // Upstream checks our address before ztDest, which
                            // is also us on inbound frames.
                            let (fwd, length) = forward_target(rule);
                            if fwd == zt_source {
                                // No-op: the target sent the frame.
                            } else if fwd == our_address {
                                if self.inbound {
                                    return ZtFilterResult::SuperAccept;
                                }
                            } else if fwd == *zt_dest {
                                // No-op: the target already gets the frame.
                            } else if rt == ACTION_REDIRECT {
                                *zt_dest = fwd;
                                return ZtFilterResult::Redirect;
                            } else {
                                // Only the last TEE/WATCH taken survives.
                                *cc = Some(Tee {
                                    to: fwd,
                                    length: if length != 0 {
                                        frame_len.min(length as usize)
                                    } else {
                                        frame_len
                                    },
                                    watch: rt == ACTION_WATCH,
                                });
                            }
                        }
                        ACTION_BREAK => return ZtFilterResult::NoMatch,
                        // Unknown actions are no-ops.
                        _ => {}
                    }
                } else {
                    // Network.cpp:188: being the target of a TEE/WATCH/
                    // REDIRECT whose set did not match still makes a later
                    // ACCEPT a super-accept.
                    if self.inbound
                        && matches!(rt, ACTION_TEE | ACTION_WATCH | ACTION_REDIRECT)
                        && forward_target(rule).0 == our_address
                    {
                        super_accept = true;
                    }
                    this_set_matches = true;
                }
                continue;
            }

            // Anything AND false is false: skip, unless this is an OR.
            if !this_set_matches && !rule.or_flag {
                continue;
            }

            let matched = self.rule_matches(rule, *zt_dest, super_accept, &mut skip_drop, rng);
            if rule.or_flag {
                this_set_matches |= matched ^ rule.not_flag;
            } else {
                this_set_matches &= matched ^ rule.not_flag;
            }
        }

        ZtFilterResult::NoMatch
    }

    /// One MATCH, before its NOT flag is applied. `hard_yes`/`hard_no`
    /// come out true/false after NOT, as upstream uses them for frames a
    /// rule cannot apply to.
    fn rule_matches(
        &self,
        rule: &Rule,
        zt_dest: u64,
        super_accept: bool,
        skip_drop: &mut bool,
        rng: &mut dyn FnMut() -> u32,
    ) -> bool {
        let rt = rule.rule_type & 0x3F;
        let hard_yes = !rule.not_flag;
        let hard_no = rule.not_flag;
        let f = self.frame;
        let p = f.payload;
        let len = p.len();
        let et = f.ethertype;
        let ipv4 = et == ETHERTYPE_IPV4 && len >= 20;

        match rule_fields(rule) {
            Some(RuleFields::ZtAddress(addr)) => {
                if rt == MATCH_SOURCE_ZEROTIER_ADDRESS {
                    addr == addr_u64(&f.zt_source)
                } else {
                    addr == zt_dest
                }
            }
            Some(RuleFields::VlanId(id)) => id == f.vlan_id,
            // Not supported upstream either: only a 0 rule value matches.
            Some(RuleFields::VlanPcp(v) | RuleFields::VlanDei(v)) => v == 0,
            Some(RuleFields::Mac(mac)) => {
                if rt == MATCH_MAC_SOURCE {
                    mac == f.mac_source
                } else {
                    mac == f.mac_dest
                }
            }
            Some(RuleFields::Ipv4 { ip, mask }) => {
                if ipv4 {
                    let at = if rt == MATCH_IPV4_SOURCE { 12 } else { 16 };
                    ipv4_contains(ip, mask, &p[at..at + 4])
                } else {
                    hard_no
                }
            }
            Some(RuleFields::Ipv6 { ip, mask }) => {
                if et == ETHERTYPE_IPV6 && len >= 40 {
                    let at = if rt == MATCH_IPV6_SOURCE { 8 } else { 24 };
                    ipv6_contains(ip, mask, &p[at..at + 16])
                } else {
                    hard_no
                }
            }
            Some(RuleFields::IpTos { mask, start, end }) => {
                let tos = if ipv4 {
                    p[1]
                } else if et == ETHERTYPE_IPV6 && len >= 40 {
                    ((p[0] << 4) & 0xf0) | ((p[1] >> 4) & 0x0f)
                } else {
                    return hard_no;
                };
                let tos = tos & mask;
                tos >= start && tos <= end
            }
            Some(RuleFields::IpProtocol(proto)) => {
                if ipv4 {
                    p[9] == proto
                } else if et == ETHERTYPE_IPV6 {
                    match ipv6_payload(p) {
                        Some((_, next)) => next == proto,
                        None => hard_no,
                    }
                } else {
                    hard_no
                }
            }
            Some(RuleFields::EtherType(t)) => t == et,
            Some(RuleFields::Icmp {
                icmp_type,
                icmp_code,
            }) => {
                let at = if ipv4 {
                    if p[9] != 0x01 {
                        return hard_no;
                    }
                    (p[0] & 0x0f) as usize * 4
                } else if et == ETHERTYPE_IPV6 {
                    match ipv6_payload(p) {
                        Some((pos, 0x3a)) => pos,
                        _ => return hard_no,
                    }
                } else {
                    return hard_no;
                };
                if len < at + 2 || p[at] != icmp_type {
                    return hard_no;
                }
                match icmp_code {
                    Some(code) => p[at + 1] == code,
                    None => hard_yes,
                }
            }
            Some(RuleFields::PortRange { start, end }) => {
                let dest = rt == MATCH_IP_DEST_PORT_RANGE;
                let read_port = |at: usize, proto: u8| {
                    if is_port_protocol(proto) && len > at + 4 {
                        let at = at + if dest { 2 } else { 0 };
                        Some(u16::from_be_bytes([p[at], p[at + 1]]))
                    } else {
                        None
                    }
                };
                if ipv4 {
                    // Network.cpp:365: a protocol without ports is a plain
                    // non-match here, not hard_no.
                    let header_len = (p[0] & 0x0f) as usize * 4;
                    read_port(header_len, p[9]).is_some_and(|port| port >= start && port <= end)
                } else if et == ETHERTYPE_IPV6 {
                    match ipv6_payload(p) {
                        // Network.cpp:385 tests `p > 0`, so port 0 never
                        // matches over IPv6.
                        Some((pos, proto)) => read_port(pos, proto)
                            .is_some_and(|port| port > 0 && port >= start && port <= end),
                        None => hard_no,
                    }
                } else {
                    hard_no
                }
            }
            Some(RuleFields::Characteristics(c)) => self.characteristics() & c != 0,
            Some(RuleFields::FrameSizeRange { start, end }) => {
                len >= start as usize && len <= end as usize
            }
            Some(RuleFields::RandomProbability(probability)) => rng() <= probability,
            Some(RuleFields::Tag { id, value }) => {
                self.tag_matches(rule, id, value, super_accept, skip_drop)
            }
            Some(RuleFields::IntegerRange {
                start,
                end,
                idx,
                little,
                bits,
            }) => {
                let bits = bits as u32;
                let bytes = bits.div_ceil(8) as usize;
                let mut integer = 0u64;
                if little {
                    let at = idx as usize;
                    if let Some(b) = p.get(at..at + bytes) {
                        for &byte in b {
                            integer = (integer >> 8) | ((byte as u64) << 56);
                        }
                    }
                    integer >>= 64 - bits;
                } else {
                    // Network.cpp:566 starts big-endian reads `8 - bytes`
                    // past idx.
                    let at = idx as usize + (8 - bytes);
                    if let Some(b) = p.get(at..at + bytes) {
                        for &byte in b {
                            integer = (integer << 8) | byte as u64;
                        }
                    }
                    integer &= u64::MAX >> (64 - bits);
                }
                // Upstream holds the range end as a u32 delta from start.
                let delta = end.wrapping_sub(start) as u32 as u64;
                integer >= start && integer <= start.wrapping_add(delta)
            }
            // Unknown MATCH types: the network decides.
            _ => self.env.config.flags & NETWORK_FLAG_RULES_RESULT_OF_UNSUPPORTED_MATCH != 0,
        }
    }

    fn tag_matches(
        &self,
        rule: &Rule,
        id: u32,
        value: u32,
        super_accept: bool,
        skip_drop: &mut bool,
    ) -> bool {
        let rt = rule.rule_type & 0x3F;
        let hard_yes = !rule.not_flag;
        let hard_no = rule.not_flag;
        let config = self.env.config;
        let local = config.local_tag(id);
        let remote = self.env.peer.and_then(|peer| peer.tag(config, id));

        if rt == MATCH_TAG_SENDER || rt == MATCH_TAG_RECEIVER {
            if super_accept {
                *skip_drop = true;
                return hard_yes;
            }
            let checks_remote = (rt == MATCH_TAG_SENDER) == self.inbound;
            if !checks_remote {
                return local.map_or(hard_no, |l| l == value);
            }
            return match remote {
                Some(r) => r == value,
                // Outbound, we may not know the receiver's tag yet.
                None if rt == MATCH_TAG_RECEIVER => {
                    *skip_drop = true;
                    hard_yes
                }
                None => hard_no,
            };
        }

        let Some(l) = local else {
            return hard_no;
        };
        let Some(r) = remote else {
            if self.inbound && !super_accept {
                return hard_no;
            }
            // Network.cpp:507: outbound (or as a TEE/REDIRECT target) we may
            // not have the other side's tag yet; it filters on its end.
            *skip_drop = true;
            return hard_yes;
        };
        match rt {
            MATCH_TAGS_DIFFERENCE => l.abs_diff(r) <= value,
            MATCH_TAGS_BITWISE_AND => l & r == value,
            MATCH_TAGS_BITWISE_OR => l | r == value,
            MATCH_TAGS_BITWISE_XOR => l ^ r == value,
            MATCH_TAGS_EQUAL => l == value && r == value,
            _ => hard_no,
        }
    }

    /// The `MATCH_CHARACTERISTICS` bits for this frame.
    fn characteristics(&self) -> u64 {
        let f = self.frame;
        let p = f.payload;
        let len = p.len();
        let et = f.ethertype;

        let mut cf = if self.inbound {
            CHARACTERISTICS_INBOUND
        } else {
            0
        };
        if f.mac_dest[0] & 0x01 != 0 {
            cf |= CHARACTERISTICS_MULTICAST;
        }
        if f.mac_dest == [0xff; 6] {
            cf |= CHARACTERISTICS_BROADCAST;
        }

        let mut src: Option<&[u8]> = None;
        if et == ETHERTYPE_IPV4 && len >= 20 {
            src = Some(&p[12..16]);
        } else if et == ETHERTYPE_IPV6 && len >= 40 {
            if len >= 40 + 8 + 16 && p[6] == 0x3a && (p[40] == 0x87 || p[40] == 0x88) {
                if p[40] == 0x87 {
                    // Network.cpp:409: neighbor solicitations carry no
                    // reliable source, so upstream counts them as
                    // authenticated.
                    cf |= CHARACTERISTICS_SENDER_IP_AUTHENTICATED;
                } else {
                    // Neighbor advertisements: check the target address.
                    src = Some(&p[48..64]);
                }
            } else {
                src = Some(&p[8..24]);
            }
        } else if et == ETHERTYPE_ARP && len >= 28 {
            src = Some(&p[14..18]);
        }
        if let Some(ownership) = self.env.ownership {
            if src.is_some_and(|ip| ownership.owns_ip(ip)) {
                cf |= CHARACTERISTICS_SENDER_IP_AUTHENTICATED;
            }
            if ownership.owns_mac(&f.mac_source) {
                cf |= CHARACTERISTICS_SENDER_MAC_AUTHENTICATED;
            }
        }

        if et == ETHERTYPE_IPV4 && len >= 20 && p[9] == 0x06 {
            let header_len = (p[0] & 0x0f) as usize * 4;
            // Upstream reads the TCP flags without a length check.
            if let Some(flags) = p.get(header_len + 12..header_len + 14) {
                cf |= flags[1] as u64 | ((flags[0] & 0x0f) as u64) << 8;
            }
        } else if et == ETHERTYPE_IPV6 {
            if let Some((pos, 0x06)) = ipv6_payload(p) {
                if len > pos + 14 {
                    cf |= p[pos + 13] as u64 | ((p[pos + 12] & 0x0f) as u64) << 8;
                }
            }
        }
        cf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::rules::{
        encode_rule_fields, serialize_capabilities_signed, serialize_rules, serialize_tags_signed,
        Tag, ACTION_PRIORITY, MATCH_CHARACTERISTICS, MATCH_DEST_ZEROTIER_ADDRESS, MATCH_ETHERTYPE,
        MATCH_FRAME_SIZE_RANGE, MATCH_ICMP, MATCH_INTEGER_RANGE, MATCH_IPV4_DEST, MATCH_IPV6_DEST,
        MATCH_IP_PROTOCOL, MATCH_IP_SOURCE_PORT_RANGE, MATCH_IP_TOS, MATCH_MAC_DEST, MATCH_RANDOM,
        MATCH_VLAN_DEI, MATCH_VLAN_ID, MATCH_VLAN_PCP,
    };
    use alloc::vec;
    use core::cell::Cell;

    const NWID: u64 = 0x1122_3344_5500_0001;
    const CONTROLLER: [u8; 5] = [0x11, 0x22, 0x33, 0x44, 0x55];
    const ME: [u8; 5] = [0x0a, 0, 0, 0, 1];
    const PEER: [u8; 5] = [0x0b, 0, 0, 0, 2];
    const OTHER: [u8; 5] = [0x0c, 0, 0, 0, 3];
    const OTHER2: [u8; 5] = [0x0c, 0, 0, 0, 4];
    const TS: u64 = 10_000;

    const V4_SRC: [u8; 4] = [10, 1, 2, 3];
    const V4_DST: [u8; 4] = [192, 168, 7, 9];
    const V6_SRC: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const V6_DST: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    const ETHERTYPE_TEST: u16 = 0x88b5;

    fn rule(rule_type: u8, fields: RuleFields) -> Rule {
        Rule {
            rule_type,
            not_flag: false,
            or_flag: false,
            value: encode_rule_fields(&fields),
        }
    }

    fn action(rule_type: u8) -> Rule {
        Rule {
            rule_type,
            not_flag: false,
            or_flag: false,
            value: vec![],
        }
    }

    fn not(mut r: Rule) -> Rule {
        r.not_flag = true;
        r
    }

    fn or(mut r: Rule) -> Rule {
        r.or_flag = true;
        r
    }

    fn accept() -> Rule {
        action(ACTION_ACCEPT)
    }

    fn drop_rule() -> Rule {
        action(ACTION_DROP)
    }

    fn ethertype(t: u16) -> Rule {
        rule(MATCH_ETHERTYPE, RuleFields::EtherType(t))
    }

    fn forward(rule_type: u8, to: [u8; 5], length: u16) -> Rule {
        let fields = RuleFields::Forward {
            address: addr_u64(&to),
            flags: 0,
            length,
        };
        rule(rule_type, fields)
    }

    fn tag_rule(rule_type: u8, id: u32, value: u32) -> Rule {
        rule(rule_type, RuleFields::Tag { id, value })
    }

    fn priority(value: &[u8]) -> Rule {
        Rule {
            value: value.to_vec(),
            ..action(ACTION_PRIORITY)
        }
    }

    fn dport(start: u16, end: u16) -> Rule {
        rule(
            MATCH_IP_DEST_PORT_RANGE,
            RuleFields::PortRange { start, end },
        )
    }

    fn sport(start: u16, end: u16) -> Rule {
        rule(
            MATCH_IP_SOURCE_PORT_RANGE,
            RuleFields::PortRange { start, end },
        )
    }

    fn peer_tags(tags: Vec<TagCredential>) -> PeerCredentials {
        PeerCredentials {
            tags,
            ..Default::default()
        }
    }

    fn peer_caps(capabilities: Vec<CapabilityCredential>) -> PeerCredentials {
        PeerCredentials {
            capabilities,
            ..Default::default()
        }
    }

    fn config(rules: Vec<Rule>) -> NetworkRules {
        NetworkRules {
            network_id: NWID,
            timestamp: TS,
            credential_time_max_delta: 1_000,
            rules,
            ..Default::default()
        }
    }

    // The filter does not check signatures; PeerCredentials::add_* does.
    fn tag(id: u32, value: u32, timestamp: u64) -> TagCredential {
        TagCredential {
            network_id: NWID,
            timestamp,
            tag: Tag { id, value },
            issued_to: PEER,
            signed_by: CONTROLLER,
            signature: [0; 96],
        }
    }

    fn cap(id: u32, rules: Vec<Rule>, timestamp: u64) -> CapabilityCredential {
        CapabilityCredential {
            network_id: NWID,
            timestamp,
            capability: Capability { id, rules },
            max_custody_chain_length: 1,
            custody: vec![],
        }
    }

    fn mac(a: [u8; 5]) -> [u8; 6] {
        crate::ethernet::derive_mac(&a, NWID)
    }

    fn ipv4(proto: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
        p.extend_from_slice(&V4_SRC);
        p.extend_from_slice(&V4_DST);
        p.extend_from_slice(body);
        p
    }

    fn ipv6(next: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, 0, next, 64];
        p.extend_from_slice(&V6_SRC);
        p.extend_from_slice(&V6_DST);
        p.extend_from_slice(body);
        p
    }

    fn udp(src: u16, dst: u16) -> Vec<u8> {
        let mut h = vec![0u8; 8];
        h[0..2].copy_from_slice(&src.to_be_bytes());
        h[2..4].copy_from_slice(&dst.to_be_bytes());
        h
    }

    fn tcp(src: u16, dst: u16, flags: u16) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0..2].copy_from_slice(&src.to_be_bytes());
        h[2..4].copy_from_slice(&dst.to_be_bytes());
        h[12] = 0x50 | ((flags >> 8) as u8 & 0x0f);
        h[13] = flags as u8;
        h
    }

    /// An IPv6 extension header of `(units + 1) * 8` bytes.
    fn ext(next: u8, units: u8) -> Vec<u8> {
        let mut h = vec![0u8; (units as usize + 1) * 8];
        h[0] = next;
        h[1] = units;
        h
    }

    /// Outbound, from us to PEER.
    fn frame(ethertype: u16, payload: &[u8]) -> Frame<'_> {
        Frame {
            zt_source: ME,
            zt_dest: Some(PEER),
            mac_source: mac(ME),
            mac_dest: mac(PEER),
            ethertype,
            vlan_id: 0,
            payload,
        }
    }

    /// Inbound, from PEER to us.
    fn inbound(ethertype: u16, payload: &[u8]) -> Frame<'_> {
        Frame {
            zt_source: PEER,
            zt_dest: Some(ME),
            mac_source: mac(PEER),
            mac_dest: mac(ME),
            ethertype,
            vlan_id: 0,
            payload,
        }
    }

    fn env<'a>(config: &'a NetworkRules, peer: Option<&'a PeerCredentials>) -> FilterEnv<'a> {
        FilterEnv {
            config,
            our_address: ME,
            peer,
            ownership: None,
        }
    }

    fn out(config: &NetworkRules, peer: Option<&PeerCredentials>, f: &Frame) -> FilterDecision {
        filter_outgoing(&env(config, peer), f, false, &mut || 0u32)
    }

    fn inc(config: &NetworkRules, peer: Option<&PeerCredentials>, f: &Frame) -> FilterDecision {
        filter_incoming(&env(config, peer), f, &mut || 0u32)
    }

    fn verdict_out(rules: Vec<Rule>, f: &Frame) -> Verdict {
        out(&config(rules), None, f).verdict
    }

    fn verdict_in(rules: Vec<Rule>, peer: Option<&PeerCredentials>, f: &Frame) -> Verdict {
        inc(&config(rules), peer, f).verdict
    }

    /// Whether `[rule, ACCEPT]` accepts the outbound frame.
    fn matches(rule: &Rule, f: &Frame) -> bool {
        verdict_out(vec![rule.clone(), accept()], f) == Verdict::Accept
    }

    fn check(cases: &[(&str, Rule, &Frame, bool)]) {
        for (name, rule, f, want) in cases {
            assert_eq!(matches(rule, f), *want, "{name}");
        }
    }

    #[test]
    fn address_vlan_mac_ethertype_and_size_matches() {
        let raw = [0u8; 100];
        let f = frame(ETHERTYPE_TEST, &raw);
        let multicast = Frame { zt_dest: None, ..f };
        let zt = |t, a: [u8; 5]| rule(t, RuleFields::ZtAddress(addr_u64(&a)));
        let size = |start, end| {
            rule(
                MATCH_FRAME_SIZE_RANGE,
                RuleFields::FrameSizeRange { start, end },
            )
        };
        check(&[
            ("zt source", zt(MATCH_SOURCE_ZEROTIER_ADDRESS, ME), &f, true),
            (
                "zt source other",
                zt(MATCH_SOURCE_ZEROTIER_ADDRESS, PEER),
                &f,
                false,
            ),
            ("zt dest", zt(MATCH_DEST_ZEROTIER_ADDRESS, PEER), &f, true),
            (
                "zt dest unknown",
                zt(MATCH_DEST_ZEROTIER_ADDRESS, PEER),
                &multicast,
                false,
            ),
            (
                "not zt dest unknown",
                not(zt(MATCH_DEST_ZEROTIER_ADDRESS, PEER)),
                &multicast,
                true,
            ),
            (
                "vlan 0",
                rule(MATCH_VLAN_ID, RuleFields::VlanId(0)),
                &f,
                true,
            ),
            (
                "vlan 7",
                rule(MATCH_VLAN_ID, RuleFields::VlanId(7)),
                &f,
                false,
            ),
            // Network.cpp:233: PCP/DEI are unsupported; only 0 matches.
            (
                "pcp 0",
                rule(MATCH_VLAN_PCP, RuleFields::VlanPcp(0)),
                &f,
                true,
            ),
            (
                "pcp 3",
                rule(MATCH_VLAN_PCP, RuleFields::VlanPcp(3)),
                &f,
                false,
            ),
            (
                "dei 0",
                rule(MATCH_VLAN_DEI, RuleFields::VlanDei(0)),
                &f,
                true,
            ),
            (
                "dei 1",
                rule(MATCH_VLAN_DEI, RuleFields::VlanDei(1)),
                &f,
                false,
            ),
            (
                "mac source",
                rule(MATCH_MAC_SOURCE, RuleFields::Mac(mac(ME))),
                &f,
                true,
            ),
            (
                "mac dest",
                rule(MATCH_MAC_DEST, RuleFields::Mac(mac(PEER))),
                &f,
                true,
            ),
            (
                "mac dest is not source",
                rule(MATCH_MAC_DEST, RuleFields::Mac(mac(ME))),
                &f,
                false,
            ),
            ("ethertype", ethertype(ETHERTYPE_TEST), &f, true),
            ("other ethertype", ethertype(ETHERTYPE_IPV4), &f, false),
            (
                "not other ethertype",
                not(ethertype(ETHERTYPE_IPV4)),
                &f,
                true,
            ),
            ("size exact", size(100, 100), &f, true),
            ("size below", size(0, 99), &f, false),
            ("size above", size(101, 1500), &f, false),
        ]);
    }

    #[test]
    fn ipv4_address_tos_and_protocol_matches() {
        let udp4 = ipv4(17, &udp(5000, 53));
        let f = frame(ETHERTYPE_IPV4, &udp4);
        let mut tos = udp4.clone();
        tos[1] = 0xb9; // DSCP 46, ECN 1
        let f_tos = frame(ETHERTYPE_IPV4, &tos);
        let arp = [0u8; 28];
        let f_arp = frame(ETHERTYPE_ARP, &arp);
        let short = frame(ETHERTYPE_IPV4, &udp4[..19]);
        let src = |ip, mask| rule(MATCH_IPV4_SOURCE, RuleFields::Ipv4 { ip, mask });
        let dst = |ip, mask| rule(MATCH_IPV4_DEST, RuleFields::Ipv4 { ip, mask });
        let tos_rule =
            |mask, start, end| rule(MATCH_IP_TOS, RuleFields::IpTos { mask, start, end });
        let proto = |p| rule(MATCH_IP_PROTOCOL, RuleFields::IpProtocol(p));
        check(&[
            ("src /32", src(V4_SRC, 32), &f, true),
            ("src /24", src([10, 1, 2, 0], 24), &f, true),
            ("src other /24", src([10, 1, 3, 0], 24), &f, false),
            // IPv4 compares prefixes, so host bits in the rule are ignored.
            ("src host bits /8", src([10, 9, 9, 9], 8), &f, true),
            ("src /0", src([1, 2, 3, 4], 0), &f, true),
            ("dst /24", dst([192, 168, 7, 0], 24), &f, true),
            ("dst is not src", dst(V4_SRC, 32), &f, false),
            ("tos masked", tos_rule(0xfc, 0xb8, 0xb8), &f_tos, true),
            ("tos unmasked", tos_rule(0xff, 0xb8, 0xb8), &f_tos, false),
            ("tos range", tos_rule(0xfc, 0, 0x10), &f_tos, false),
            ("udp", proto(17), &f, true),
            ("not tcp", proto(6), &f, false),
            // hard_no: a rule that cannot apply is false even under NOT.
            ("src on arp", src([0, 0, 0, 0], 0), &f_arp, false),
            ("not src on arp", not(src([1, 1, 1, 1], 32)), &f_arp, false),
            ("not tos on arp", not(tos_rule(0xff, 1, 1)), &f_arp, false),
            ("not proto on arp", not(proto(6)), &f_arp, false),
            ("short header", src([0, 0, 0, 0], 0), &short, false),
        ]);
    }

    #[test]
    fn ipv6_address_traffic_class_and_protocol_matches() {
        let udp6 = ipv6(17, &udp(5000, 53));
        let f = frame(ETHERTYPE_IPV6, &udp6);
        let mut tc = udp6.clone();
        tc[0] = 0x6b;
        tc[1] = 0x80; // traffic class 0xb8
        let f_tc = frame(ETHERTYPE_IPV6, &tc);
        let udp4 = ipv4(17, &udp(5000, 53));
        let f4 = frame(ETHERTYPE_IPV4, &udp4);
        let fd00 = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let src = |ip, mask| rule(MATCH_IPV6_SOURCE, RuleFields::Ipv6 { ip, mask });
        let dst = |ip, mask| rule(MATCH_IPV6_DEST, RuleFields::Ipv6 { ip, mask });
        check(&[
            ("src /128", src(V6_SRC, 128), &f, true),
            ("src /16", src(fd00, 16), &f, true),
            // InetAddress::containsAddress masks only the packet address,
            // so a rule address with host bits set never matches.
            ("src host bits /64", src(V6_SRC, 64), &f, false),
            ("src ::/0", src([0; 16], 0), &f, true),
            ("src fd00::/0", src(fd00, 0), &f, false),
            ("dst /128", dst(V6_DST, 128), &f, true),
            ("dst is not src", dst(V6_SRC, 128), &f, false),
            (
                "traffic class",
                rule(
                    MATCH_IP_TOS,
                    RuleFields::IpTos {
                        mask: 0xff,
                        start: 0xb8,
                        end: 0xb8,
                    },
                ),
                &f_tc,
                true,
            ),
            (
                "udp",
                rule(MATCH_IP_PROTOCOL, RuleFields::IpProtocol(17)),
                &f,
                true,
            ),
            ("v6 rule on v4", src([0; 16], 0), &f4, false),
            ("not v6 rule on v4", not(src(V6_SRC, 128)), &f4, false),
        ]);
    }

    #[test]
    fn ipv6_extension_headers_are_walked_like_ipv6_get_payload() {
        let chain = [ext(43, 0), ext(60, 1), ext(17, 0), udp(1000, 2000)].concat();
        let walked = ipv6(0, &chain);
        let f = frame(ETHERTYPE_IPV6, &walked);
        // Fragment headers (44) are not walked (Network.cpp:64).
        let fragment = ipv6(44, &[ext(17, 0), udp(1000, 2000)].concat());
        let f_frag = frame(ETHERTYPE_IPV6, &fragment);
        let truncated = ipv6(0, &[17, 0, 0, 0]);
        let f_trunc = frame(ETHERTYPE_IPV6, &truncated);
        // Header length points past the end of the frame.
        let overrun = ipv6(0, &ext(17, 5)[..8]);
        let f_overrun = frame(ETHERTYPE_IPV6, &overrun);
        let no_next = ipv6(59, &[]);
        let f_no_next = frame(ETHERTYPE_IPV6, &no_next);
        let proto = |p| rule(MATCH_IP_PROTOCOL, RuleFields::IpProtocol(p));
        check(&[
            ("udp after three headers", proto(17), &f, true),
            ("not the first header", proto(0), &f, false),
            ("dest port", dport(2000, 2000), &f, true),
            ("source port", sport(1000, 1000), &f, true),
            ("fragment protocol", proto(44), &f_frag, true),
            ("udp behind fragment", proto(17), &f_frag, false),
            ("no ports behind fragment", dport(0, 65535), &f_frag, false),
            ("truncated header", proto(0), &f_trunc, false),
            ("not on truncated header", not(proto(17)), &f_trunc, false),
            ("overrunning header", not(proto(17)), &f_overrun, false),
            ("no next header", proto(59), &f_no_next, true),
        ]);
    }

    #[test]
    fn icmp_type_and_code_matches() {
        let echo4 = ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]);
        let f = frame(ETHERTYPE_IPV4, &echo4);
        // IHL 6: the ICMP header starts at byte 24.
        let mut long_hdr = ipv4(1, &[0, 0, 0, 0, 8, 3]);
        long_hdr[0] = 0x46;
        let f_long = frame(ETHERTYPE_IPV4, &long_hdr);
        let udp4 = ipv4(17, &udp(1, 2));
        let f_udp = frame(ETHERTYPE_IPV4, &udp4);
        let echo6 = ipv6(0, &[ext(58, 0), vec![128, 0, 0, 0]].concat());
        let f6 = frame(ETHERTYPE_IPV6, &echo6);
        let short6 = ipv6(58, &[128]);
        let f6_short = frame(ETHERTYPE_IPV6, &short6);
        let icmp = |icmp_type, icmp_code| {
            rule(
                MATCH_ICMP,
                RuleFields::Icmp {
                    icmp_type,
                    icmp_code,
                },
            )
        };
        check(&[
            ("type and code", icmp(8, Some(0)), &f, true),
            ("type only", icmp(8, None), &f, true),
            ("wrong code", icmp(8, Some(1)), &f, false),
            ("wrong type", icmp(0, None), &f, false),
            // Network.cpp:315: a type mismatch is hard_no, so NOT is false too.
            ("not wrong type", not(icmp(0, None)), &f, false),
            ("not wrong code", not(icmp(8, Some(1))), &f, true),
            ("honours ihl", icmp(8, Some(3)), &f_long, true),
            ("not icmp", icmp(8, None), &f_udp, false),
            ("not on udp", not(icmp(8, None)), &f_udp, false),
            ("icmpv6 after hop-by-hop", icmp(128, Some(0)), &f6, true),
            ("icmpv6 too short", not(icmp(1, None)), &f6_short, false),
        ]);
    }

    #[test]
    fn port_range_matches() {
        let tcp4 = ipv4(6, &tcp(40000, 22, 0x002));
        let f = frame(ETHERTYPE_IPV4, &tcp4);
        let sctp = ipv4(0x84, &udp(9, 53));
        let udplite = ipv4(0x88, &udp(9, 53));
        let icmp4 = ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]);
        let short = ipv4(17, &udp(9, 53)[..4]);
        let zero4 = ipv4(17, &udp(0, 0));
        let udp6 = ipv6(17, &udp(0, 53));
        let zero6 = ipv6(17, &udp(9, 0));
        let arp = [0u8; 28];
        check(&[
            ("tcp dest", dport(22, 22), &f, true),
            ("tcp dest outside", dport(1, 21), &f, false),
            ("tcp source", sport(40000, 40100), &f, true),
            ("sctp", dport(53, 53), &frame(ETHERTYPE_IPV4, &sctp), true),
            (
                "udplite",
                dport(53, 53),
                &frame(ETHERTYPE_IPV4, &udplite),
                true,
            ),
            (
                "icmp has no ports",
                dport(0, 65535),
                &frame(ETHERTYPE_IPV4, &icmp4),
                false,
            ),
            // Network.cpp:365: a portless IPv4 protocol is a plain non-match,
            // not hard_no, so NOT matches it.
            (
                "not on icmp",
                not(dport(0, 65535)),
                &frame(ETHERTYPE_IPV4, &icmp4),
                true,
            ),
            // Upstream needs more than four bytes after the IP header.
            (
                "ports only",
                dport(53, 53),
                &frame(ETHERTYPE_IPV4, &short),
                false,
            ),
            (
                "v4 port 0",
                dport(0, 10),
                &frame(ETHERTYPE_IPV4, &zero4),
                true,
            ),
            (
                "v6 dest",
                dport(53, 53),
                &frame(ETHERTYPE_IPV6, &udp6),
                true,
            ),
            // Network.cpp:385 tests `p > 0` for IPv6.
            (
                "v6 source port 0",
                sport(0, 10),
                &frame(ETHERTYPE_IPV6, &udp6),
                false,
            ),
            (
                "v6 dest port 0",
                dport(0, 10),
                &frame(ETHERTYPE_IPV6, &zero6),
                false,
            ),
            ("arp", dport(0, 65535), &frame(ETHERTYPE_ARP, &arp), false),
            (
                "not on arp",
                not(dport(0, 65535)),
                &frame(ETHERTYPE_ARP, &arp),
                false,
            ),
        ]);
    }

    struct Owns {
        ip: Vec<u8>,
        mac: [u8; 6],
    }

    impl OwnershipCheck for Owns {
        fn owns_ip(&self, ip: &[u8]) -> bool {
            ip == self.ip.as_slice()
        }
        fn owns_mac(&self, mac: &[u8; 6]) -> bool {
            *mac == self.mac
        }
    }

    #[test]
    fn characteristics_bits() {
        let chr = |bits| rule(MATCH_CHARACTERISTICS, RuleFields::Characteristics(bits));
        let syn4 = ipv4(6, &tcp(1, 2, 0x002));
        let ns4 = ipv4(6, &tcp(1, 2, 0x100));
        let syn6 = ipv6(0, &[ext(6, 0), tcp(1, 2, 0x002)].concat());
        let header_only = ipv4(6, &[]);
        let raw = [0u8; 10];
        let mut multicast = frame(ETHERTYPE_TEST, &raw);
        multicast.mac_dest = [0x33, 0x33, 0, 0, 0, 1];
        let mut broadcast = multicast;
        broadcast.mac_dest = [0xff; 6];
        let target = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let solicit = ipv6(58, &[&[0x87, 0, 0, 0, 0, 0, 0, 0][..], &target].concat());
        let advert = ipv6(58, &[&[0x88, 0, 0, 0, 0, 0, 0, 0][..], &target].concat());
        check(&[
            ("tcp syn", chr(0x002), &frame(ETHERTYPE_IPV4, &syn4), true),
            ("tcp ack", chr(0x010), &frame(ETHERTYPE_IPV4, &syn4), false),
            ("tcp ns", chr(0x100), &frame(ETHERTYPE_IPV4, &ns4), true),
            (
                "tcp syn v6",
                chr(0x002),
                &frame(ETHERTYPE_IPV6, &syn6),
                true,
            ),
            (
                "truncated tcp",
                chr(0xfff),
                &frame(ETHERTYPE_IPV4, &header_only),
                false,
            ),
            (
                "outbound",
                chr(CHARACTERISTICS_INBOUND),
                &frame(ETHERTYPE_TEST, &raw),
                false,
            ),
            (
                "multicast",
                chr(CHARACTERISTICS_MULTICAST),
                &multicast,
                true,
            ),
            (
                "not broadcast",
                chr(CHARACTERISTICS_BROADCAST),
                &multicast,
                false,
            ),
            (
                "broadcast",
                chr(CHARACTERISTICS_BROADCAST),
                &broadcast,
                true,
            ),
            (
                "broadcast is multicast",
                chr(CHARACTERISTICS_MULTICAST),
                &broadcast,
                true,
            ),
            // Network.cpp:409: solicitations count as IP-authenticated.
            (
                "neighbor solicitation",
                chr(CHARACTERISTICS_SENDER_IP_AUTHENTICATED),
                &frame(ETHERTYPE_IPV6, &solicit),
                true,
            ),
            (
                "neighbor advertisement",
                chr(CHARACTERISTICS_SENDER_IP_AUTHENTICATED),
                &frame(ETHERTYPE_IPV6, &advert),
                false,
            ),
        ]);

        let inbound_rules = config(vec![chr(CHARACTERISTICS_INBOUND), accept()]);
        let f = inbound(ETHERTYPE_TEST, &raw);
        assert_eq!(inc(&inbound_rules, None, &f).verdict, Verdict::Accept);

        // Ownership: an advertisement is checked by its target address,
        // ARP by its sender protocol address, IPv4 by its source.
        let auth_ip = config(vec![chr(CHARACTERISTICS_SENDER_IP_AUTHENTICATED), accept()]);
        let auth_mac = config(vec![
            chr(CHARACTERISTICS_SENDER_MAC_AUTHENTICATED),
            accept(),
        ]);
        let mut arp = [0u8; 28];
        arp[14..18].copy_from_slice(&V4_SRC);
        let udp4 = ipv4(17, &udp(1, 2));
        let owns = |ip: &[u8]| Owns {
            ip: ip.to_vec(),
            mac: mac(ME),
        };
        for (name, owner, payload, et) in [
            ("advert target", owns(&target), &advert, ETHERTYPE_IPV6),
            ("arp sender", owns(&V4_SRC), &arp.to_vec(), ETHERTYPE_ARP),
            ("ipv4 source", owns(&V4_SRC), &udp4, ETHERTYPE_IPV4),
        ] {
            let mut e = env(&auth_ip, None);
            e.ownership = Some(&owner);
            let f = frame(et, payload);
            assert_eq!(
                filter_outgoing(&e, &f, false, &mut || 0u32).verdict,
                Verdict::Accept,
                "{name}"
            );
            assert_eq!(
                filter_outgoing(&env(&auth_ip, None), &f, false, &mut || 0u32).verdict,
                Verdict::Drop,
                "{name} without ownership"
            );
            let mut e = env(&auth_mac, None);
            e.ownership = Some(&owner);
            assert_eq!(
                filter_outgoing(&e, &f, false, &mut || 0u32).verdict,
                Verdict::Accept,
                "{name} mac"
            );
        }
    }

    #[test]
    fn random_compares_the_prng_against_the_probability() {
        let raw = [0u8; 10];
        let f = frame(ETHERTYPE_TEST, &raw);
        for (probability, want) in [
            (100, Verdict::Accept),
            (99, Verdict::Drop),
            (u32::MAX, Verdict::Accept),
        ] {
            let rules = config(vec![
                rule(MATCH_RANDOM, RuleFields::RandomProbability(probability)),
                accept(),
            ]);
            let got = filter_outgoing(&env(&rules, None), &f, false, &mut || 100u32);
            assert_eq!(got.verdict, want, "probability {probability}");
        }
    }

    #[test]
    fn integer_range_reads_like_upstream() {
        let int = |start, end, idx, little, bits| {
            rule(
                MATCH_INTEGER_RANGE,
                RuleFields::IntegerRange {
                    start,
                    end,
                    idx,
                    little,
                    bits,
                },
            )
        };
        let raw = [0x12, 0x34, 0x34, 0x12, 0, 0, 0xab, 0xcd, 0, 0];
        let f = frame(ETHERTYPE_TEST, &raw);
        let mut wide = int(0, 5, 0, true, 8);
        // Upstream keeps the range end as a u32 delta from start.
        wide.value[8..16].copy_from_slice(&((1u64 << 32) + 5).to_be_bytes());
        check(&[
            ("le 16 at 2", int(0x1234, 0x1234, 2, true, 16), &f, true),
            ("le is not be", int(0x3412, 0x3412, 2, true, 16), &f, false),
            // Network.cpp:566 starts big-endian reads `8 - bytes` past idx,
            // so a 16-bit read at 0 sees bytes 6..8.
            ("be 16 at 0", int(0xabcd, 0xabcd, 0, false, 16), &f, true),
            (
                "be 16 at 0 not bytes 0..2",
                int(0x1234, 0x1234, 0, false, 16),
                &f,
                false,
            ),
            (
                "be 64 at 0",
                int(0x1234_3412_0000_abcd, 0x1234_3412_0000_abcd, 0, false, 64),
                &f,
                true,
            ),
            ("be 12 masks", int(0xbcd, 0xbcd, 0, false, 12), &f, true),
            (
                "le 12 keeps top bits",
                int(0x123, 0x123, 2, true, 12),
                &f,
                true,
            ),
            ("out of frame reads 0", int(0, 0, 100, false, 32), &f, true),
            ("out of frame not 1..5", int(1, 5, 100, true, 32), &f, false),
            ("range", int(0x1000, 0x2000, 2, true, 16), &f, true),
            ("u32 delta", wide, &frame(ETHERTYPE_TEST, &[6]), false),
        ]);
    }

    #[test]
    fn tag_operators_compare_local_and_remote_values() {
        let raw = [0u8; 10];
        let f = frame(ETHERTYPE_TEST, &raw);
        let mut cfg = config(vec![]);
        cfg.tags = vec![tag(1, 12, TS)];
        let mut peer = peer_tags(vec![tag(1, 10, TS)]);
        let cases = [
            ("difference", tag_rule(MATCH_TAGS_DIFFERENCE, 1, 2), true),
            (
                "difference too far",
                tag_rule(MATCH_TAGS_DIFFERENCE, 1, 1),
                false,
            ),
            ("and", tag_rule(MATCH_TAGS_BITWISE_AND, 1, 8), true),
            ("and wrong", tag_rule(MATCH_TAGS_BITWISE_AND, 1, 12), false),
            ("or", tag_rule(MATCH_TAGS_BITWISE_OR, 1, 14), true),
            ("xor", tag_rule(MATCH_TAGS_BITWISE_XOR, 1, 6), true),
            ("equal needs both", tag_rule(MATCH_TAGS_EQUAL, 1, 12), false),
            ("no local tag", tag_rule(MATCH_TAGS_EQUAL, 2, 0), false),
            (
                "not no local tag",
                not(tag_rule(MATCH_TAGS_EQUAL, 2, 0)),
                false,
            ),
        ];
        for (name, r, want) in cases {
            cfg.rules = vec![r, accept()];
            let got = out(&cfg, Some(&peer), &f).verdict == Verdict::Accept;
            assert_eq!(got, want, "{name}");
        }
        peer.tags = vec![tag(1, 12, TS)];
        cfg.rules = vec![tag_rule(MATCH_TAGS_EQUAL, 1, 12), accept()];
        assert_eq!(out(&cfg, Some(&peer), &f).verdict, Verdict::Accept);
    }

    #[test]
    fn unknown_remote_tag_is_lenient_outbound_and_strict_inbound() {
        let raw = [0u8; 10];
        let f_out = frame(ETHERTYPE_TEST, &raw);
        let f_in = inbound(ETHERTYPE_TEST, &raw);
        let mut cfg = config(vec![tag_rule(MATCH_TAGS_EQUAL, 1, 12), accept()]);
        cfg.tags = vec![tag(1, 12, TS)];
        assert_eq!(out(&cfg, None, &f_out).verdict, Verdict::Accept);
        assert_eq!(inc(&cfg, None, &f_in).verdict, Verdict::Drop);

        // A tag outside the credential window counts as unknown.
        let stale = peer_tags(vec![tag(1, 12, TS + 5_000)]);
        assert_eq!(inc(&cfg, Some(&stale), &f_in).verdict, Verdict::Drop);

        // Network.cpp:512: the lenient match also skips the next DROP, so
        // these rules only drop once the peer's tag is known.
        cfg.rules = vec![tag_rule(MATCH_TAGS_EQUAL, 1, 12), drop_rule(), accept()];
        assert_eq!(out(&cfg, None, &f_out).verdict, Verdict::Accept);
        let peer = peer_tags(vec![tag(1, 12, TS)]);
        assert_eq!(out(&cfg, Some(&peer), &f_out).verdict, Verdict::Drop);

        // skipDrop is only cleared by the DROP it skips, even one in a
        // later rule set (Network.cpp:136).
        cfg.rules = vec![
            tag_rule(MATCH_TAGS_EQUAL, 1, 12),
            ethertype(ETHERTYPE_IPV6),
            drop_rule(),
            drop_rule(),
            accept(),
        ];
        assert_eq!(out(&cfg, None, &f_out).verdict, Verdict::Accept);

        // As a TEE target, inbound matching is lenient too (Network.cpp:501).
        cfg.rules = vec![
            ethertype(ETHERTYPE_IPV6),
            forward(ACTION_TEE, ME, 0),
            tag_rule(MATCH_TAGS_EQUAL, 1, 12),
            accept(),
        ];
        assert_eq!(inc(&cfg, None, &f_in).verdict, Verdict::SuperAccept);
    }

    #[test]
    fn tag_sender_and_receiver_pick_the_right_side() {
        let raw = [0u8; 10];
        let f_out = frame(ETHERTYPE_TEST, &raw);
        let f_in = inbound(ETHERTYPE_TEST, &raw);
        let mut cfg = config(vec![]);
        cfg.tags = vec![tag(1, 5, TS)];
        let peer = peer_tags(vec![tag(1, 7, TS)]);
        let cases = [
            (
                "out sender is us",
                true,
                tag_rule(MATCH_TAG_SENDER, 1, 5),
                Some(&peer),
                true,
            ),
            (
                "out sender not peer",
                true,
                tag_rule(MATCH_TAG_SENDER, 1, 7),
                Some(&peer),
                false,
            ),
            (
                "out receiver is peer",
                true,
                tag_rule(MATCH_TAG_RECEIVER, 1, 7),
                Some(&peer),
                true,
            ),
            (
                "out receiver not us",
                true,
                tag_rule(MATCH_TAG_RECEIVER, 1, 5),
                Some(&peer),
                false,
            ),
            (
                "out receiver unknown",
                true,
                tag_rule(MATCH_TAG_RECEIVER, 1, 7),
                None,
                true,
            ),
            (
                "out sender no local tag",
                true,
                tag_rule(MATCH_TAG_SENDER, 2, 0),
                None,
                false,
            ),
            (
                "in sender is peer",
                false,
                tag_rule(MATCH_TAG_SENDER, 1, 7),
                Some(&peer),
                true,
            ),
            (
                "in sender unknown",
                false,
                tag_rule(MATCH_TAG_SENDER, 1, 7),
                None,
                false,
            ),
            (
                "in receiver is us",
                false,
                tag_rule(MATCH_TAG_RECEIVER, 1, 5),
                Some(&peer),
                true,
            ),
        ];
        for (name, outbound, r, peer, want) in cases {
            cfg.rules = vec![r, accept()];
            let got = if outbound {
                out(&cfg, peer, &f_out).verdict
            } else {
                inc(&cfg, peer, &f_in).verdict
            };
            assert_eq!(got == Verdict::Accept, want, "{name}");
        }
        // The lenient receiver match skips the next DROP as well.
        cfg.rules = vec![tag_rule(MATCH_TAG_RECEIVER, 1, 7), drop_rule(), accept()];
        assert_eq!(out(&cfg, None, &f_out).verdict, Verdict::Accept);
    }

    #[test]
    fn not_and_or_evaluate_left_to_right() {
        let raw = [0u8; 10];
        let f = frame(ETHERTYPE_TEST, &raw);
        let t = || ethertype(ETHERTYPE_TEST);
        let fl = || ethertype(ETHERTYPE_IPV4);
        let cases = [
            ("F or T", vec![fl(), or(t()), accept()], Verdict::Accept),
            // No precedence: (T and F) or T.
            (
                "T F or T",
                vec![t(), fl(), or(t()), accept()],
                Verdict::Accept,
            ),
            (
                "T or T F",
                vec![t(), or(t()), fl(), accept()],
                Verdict::Drop,
            ),
            (
                "F or not F",
                vec![fl(), or(not(fl())), accept()],
                Verdict::Accept,
            ),
            ("not T", vec![not(t()), accept()], Verdict::Drop),
            ("not F", vec![not(fl()), accept()], Verdict::Accept),
            (
                "sets reset after an action",
                vec![fl(), accept(), t(), accept()],
                Verdict::Accept,
            ),
            (
                "unmatched drop",
                vec![fl(), drop_rule(), accept()],
                Verdict::Accept,
            ),
            ("bare accept", vec![accept()], Verdict::Accept),
            ("bare drop", vec![drop_rule(), accept()], Verdict::Drop),
            ("no rules", vec![], Verdict::Drop),
            ("nothing matches", vec![fl(), accept()], Verdict::Drop),
            (
                "unknown action is a no-op",
                vec![action(0x0a), accept()],
                Verdict::Accept,
            ),
        ];
        for (name, rules, want) in cases {
            assert_eq!(verdict_out(rules, &f), want, "{name}");
        }
        assert_eq!(
            verdict_in(vec![], None, &inbound(ETHERTYPE_TEST, &raw)),
            Verdict::Drop
        );
    }

    #[test]
    fn and_short_circuits_but_or_is_always_evaluated() {
        // Network.cpp:212: a false set skips ANDed matches but still
        // evaluates ORed ones, which matters for side effects.
        let raw = [0u8; 10];
        let f = frame(ETHERTYPE_TEST, &raw);
        let random = || rule(MATCH_RANDOM, RuleFields::RandomProbability(u32::MAX));
        let cases = [
            (
                vec![ethertype(ETHERTYPE_IPV4), random(), accept()],
                0,
                Verdict::Drop,
            ),
            (
                vec![ethertype(ETHERTYPE_IPV4), or(random()), accept()],
                1,
                Verdict::Accept,
            ),
            (
                vec![ethertype(ETHERTYPE_TEST), random(), accept()],
                1,
                Verdict::Accept,
            ),
        ];
        for (rules, calls, want) in cases {
            let cfg = config(rules);
            let count = Cell::new(0);
            let mut rng = || {
                count.set(count.get() + 1);
                0u32
            };
            let got = filter_outgoing(&env(&cfg, None), &f, false, &mut rng).verdict;
            assert_eq!((got, count.get()), (want, calls));
        }
    }

    #[test]
    fn unsupported_matches_take_the_network_flag() {
        let raw = [0u8; 10];
        let f = frame(ETHERTYPE_TEST, &raw);
        for rule_type in [20u8, 62] {
            let mut cfg = config(vec![action(rule_type), accept()]);
            assert_eq!(out(&cfg, None, &f).verdict, Verdict::Drop);
            cfg.flags = NETWORK_FLAG_RULES_RESULT_OF_UNSUPPORTED_MATCH;
            assert_eq!(out(&cfg, None, &f).verdict, Verdict::Accept);
        }
    }

    #[test]
    fn break_and_capabilities() {
        let raw = [0u8; 10];
        let f = frame(ETHERTYPE_TEST, &raw);
        let t = || ethertype(ETHERTYPE_TEST);
        let brk = || action(ACTION_BREAK);

        // BREAK ends the network rules with no verdict.
        let mut cfg = config(vec![t(), brk(), accept()]);
        assert_eq!(out(&cfg, None, &f).verdict, Verdict::Drop);
        cfg.capabilities = vec![cap(1, vec![accept()], TS)];
        let d = out(&cfg, None, &f);
        assert_eq!((d.verdict, d.capability_id), (Verdict::Accept, Some(1)));
        cfg.rules = vec![ethertype(ETHERTYPE_IPV4), brk(), accept()];
        assert_eq!(out(&cfg, None, &f).capability_id, None);

        // Capabilities run in order; BREAK or DROP only ends that one.
        cfg.rules = vec![];
        cfg.capabilities = vec![
            cap(1, vec![t(), brk(), accept()], TS),
            cap(2, vec![drop_rule()], TS),
            cap(3, vec![t(), accept()], TS),
            cap(4, vec![accept()], TS),
        ];
        let d = out(&cfg, None, &f);
        assert_eq!((d.verdict, d.capability_id), (Verdict::Accept, Some(3)));

        // A DROP in the network rules is final.
        cfg.rules = vec![drop_rule()];
        assert_eq!(out(&cfg, None, &f).verdict, Verdict::Drop);
    }

    #[test]
    fn inbound_frames_use_the_senders_capabilities() {
        let raw = [0u8; 10];
        let f_in = inbound(ETHERTYPE_TEST, &raw);
        let f_out = frame(ETHERTYPE_TEST, &raw);
        let mut cfg = config(vec![]);
        cfg.capabilities = vec![cap(1, vec![accept()], TS)];
        assert_eq!(inc(&cfg, None, &f_in).verdict, Verdict::Drop);

        let mut peer = peer_caps(vec![cap(5, vec![accept()], TS)]);
        let d = inc(&config(vec![]), Some(&peer), &f_in);
        assert_eq!((d.verdict, d.capability_id), (Verdict::Accept, Some(5)));
        // Outbound only uses our own capabilities.
        assert_eq!(
            out(&config(vec![]), Some(&peer), &f_out).verdict,
            Verdict::Drop
        );

        peer.capabilities = vec![cap(5, vec![accept()], TS - 1_001)];
        assert_eq!(
            inc(&config(vec![]), Some(&peer), &f_in).verdict,
            Verdict::Drop
        );
    }

    #[test]
    fn tee_and_watch_return_copies() {
        let raw = [0u8; 100];
        let f = frame(ETHERTYPE_TEST, &raw);
        let f_in = inbound(ETHERTYPE_TEST, &raw);
        let copy = |to, length, ext_frame_flags| {
            Some(FrameCopy {
                to,
                length,
                ext_frame_flags,
            })
        };
        let cases = [
            (
                "tee",
                vec![forward(ACTION_TEE, OTHER, 0), accept()],
                copy(OTHER, 100, 0x02),
            ),
            (
                "tee prefix",
                vec![forward(ACTION_TEE, OTHER, 40), accept()],
                copy(OTHER, 40, 0x02),
            ),
            (
                "tee long",
                vec![forward(ACTION_TEE, OTHER, 400), accept()],
                copy(OTHER, 100, 0x02),
            ),
            (
                "watch",
                vec![forward(ACTION_WATCH, OTHER, 0), accept()],
                copy(OTHER, 100, 0x16),
            ),
            (
                "to source",
                vec![forward(ACTION_TEE, ME, 0), accept()],
                None,
            ),
            (
                "to dest",
                vec![forward(ACTION_TEE, PEER, 0), accept()],
                None,
            ),
            (
                "last tee wins",
                vec![
                    forward(ACTION_TEE, OTHER, 0),
                    forward(ACTION_WATCH, OTHER2, 8),
                    accept(),
                ],
                copy(OTHER2, 8, 0x16),
            ),
        ];
        for (name, rules, want) in cases {
            let d = out(&config(rules), None, &f);
            assert_eq!((d.verdict, d.tee), (Verdict::Accept, want), "{name}");
        }

        let tee = config(vec![forward(ACTION_TEE, OTHER, 0), accept()]);
        assert_eq!(inc(&tee, None, &f_in).tee, copy(OTHER, 100, 0x08));
        let watch = config(vec![forward(ACTION_WATCH, OTHER, 0), accept()]);
        assert_eq!(inc(&watch, None, &f_in).tee, copy(OTHER, 100, 0x1c));

        let d = filter_outgoing(&env(&tee, None), &f, true, &mut || 0u32);
        assert_eq!((d.verdict, d.tee), (Verdict::Accept, None), "no_tee");

        // Copies only go out when the frame is accepted.
        for rules in [
            vec![forward(ACTION_TEE, OTHER, 0), drop_rule()],
            vec![forward(ACTION_TEE, OTHER, 0)],
        ] {
            let d = out(&config(rules), None, &f);
            assert_eq!((d.verdict, d.copies().count()), (Verdict::Drop, 0));
        }

        // A network-rule TEE survives into a capability's accept, and the
        // capability's own copy is sent first.
        let mut cfg = config(vec![forward(ACTION_TEE, OTHER, 0)]);
        cfg.capabilities = vec![cap(
            1,
            vec![forward(ACTION_WATCH, OTHER2, 10), accept()],
            TS,
        )];
        let d = out(&cfg, None, &f);
        let copies: Vec<FrameCopy> = d.copies().copied().collect();
        assert_eq!(
            copies,
            vec![
                copy(OTHER2, 10, 0x16).unwrap(),
                copy(OTHER, 100, 0x02).unwrap()
            ]
        );

        // A capability that does not accept loses its TEE.
        cfg.capabilities = vec![
            cap(
                1,
                vec![forward(ACTION_TEE, OTHER2, 0), action(ACTION_BREAK)],
                TS,
            ),
            cap(2, vec![accept()], TS),
        ];
        let d = out(&cfg, None, &f);
        assert_eq!((d.capability_id, d.capability_tee), (Some(2), None));
    }

    #[test]
    fn redirect_drops_locally_and_returns_the_target() {
        let raw = [0u8; 100];
        let f = frame(ETHERTYPE_TEST, &raw);
        let f_in = inbound(ETHERTYPE_TEST, &raw);
        let redirect = |to| forward(ACTION_REDIRECT, to, 0);
        let copy = |to, ext_frame_flags| {
            Some(FrameCopy {
                to,
                length: 100,
                ext_frame_flags,
            })
        };

        let d = out(&config(vec![redirect(OTHER)]), None, &f);
        assert_eq!((d.verdict, d.redirect), (Verdict::Drop, copy(OTHER, 0x04)));
        let d = inc(&config(vec![redirect(OTHER)]), None, &f_in);
        assert_eq!((d.verdict, d.redirect), (Verdict::Drop, copy(OTHER, 0x0a)));

        // Redirecting to the destination, or to ourselves outbound, is a
        // no-op; inbound, being the target super-accepts.
        assert_eq!(
            verdict_out(vec![redirect(PEER), accept()], &f),
            Verdict::Accept
        );
        assert_eq!(verdict_out(vec![redirect(ME)], &f), Verdict::Drop);
        let d = inc(&config(vec![redirect(ME)]), None, &f_in);
        assert_eq!((d.verdict, d.redirect), (Verdict::SuperAccept, None));

        let mut cfg = config(vec![]);
        cfg.capabilities = vec![cap(7, vec![redirect(OTHER)], TS)];
        let d = out(&cfg, None, &f);
        assert_eq!(
            (d.verdict, d.capability_id, d.redirect),
            (Verdict::Drop, Some(7), copy(OTHER, 0x04))
        );

        let d = out(
            &config(vec![forward(ACTION_TEE, OTHER2, 0), redirect(OTHER)]),
            None,
            &f,
        );
        let to: Vec<[u8; 5]> = d.copies().map(|c| c.to).collect();
        assert_eq!((d.verdict, to), (Verdict::Drop, vec![OTHER2, OTHER]));
    }

    #[test]
    fn inbound_forward_targets_super_accept() {
        let raw = [0u8; 10];
        let f = frame(ETHERTYPE_TEST, &raw);
        let f_in = inbound(ETHERTYPE_TEST, &raw);
        let miss = || ethertype(ETHERTYPE_IPV4);
        // Network.cpp:163: a taken TEE to us super-accepts at once.
        assert_eq!(
            verdict_in(vec![forward(ACTION_TEE, ME, 0)], None, &f_in),
            Verdict::SuperAccept
        );
        // Network.cpp:191: so does a later ACCEPT after an untaken one.
        let rules = vec![miss(), forward(ACTION_WATCH, ME, 0), accept()];
        assert_eq!(verdict_in(rules.clone(), None, &f_in), Verdict::SuperAccept);
        assert_eq!(verdict_out(rules, &f), Verdict::Accept);
        let rules = vec![miss(), forward(ACTION_WATCH, OTHER, 0), accept()];
        assert_eq!(verdict_in(rules, None, &f_in), Verdict::Accept);
    }

    #[test]
    fn priority_sets_the_qos_bucket() {
        let raw = [0u8; 10];
        let f = frame(ETHERTYPE_TEST, &raw);
        let cases = [
            (vec![priority(&[2])], Some(2)),
            (vec![priority(&[9])], Some(DEFAULT_QOS_BUCKET)),
            // What a PRIORITY parsed off the wire carries.
            (vec![priority(&[])], Some(0)),
            (
                vec![ethertype(ETHERTYPE_IPV4), priority(&[2]), accept()],
                None,
            ),
        ];
        for (rules, want) in cases {
            let d = out(&config(rules), None, &f);
            assert_eq!((d.verdict, d.qos_bucket), (Verdict::Accept, want));
        }
        let d = inc(
            &config(vec![priority(&[2])]),
            None,
            &inbound(ETHERTYPE_TEST, &raw),
        );
        assert_eq!((d.verdict, d.qos_bucket), (Verdict::Accept, None));
    }

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn network_rules_from_a_config_dictionary() {
        let key = signing_key();
        let caps = [Capability {
            id: 1,
            rules: vec![ethertype(ETHERTYPE_IPV4), accept()],
        }];
        let tags = [Tag { id: 2, value: 5 }, Tag { id: 1, value: 7 }];
        let mut dict = Dictionary::new();
        dict.add_text("nwid", &alloc::format!("{NWID:016x}"));
        dict.add_hex("ts", TS);
        dict.add_hex("ctmd", 1_000);
        dict.add_hex("f", NETWORK_FLAG_RULES_RESULT_OF_UNSUPPORTED_MATCH);
        dict.add_binary("R", serialize_rules(&[ethertype(ETHERTYPE_ARP), accept()]));
        dict.add_binary(
            "CAP",
            serialize_capabilities_signed(&caps, NWID, &ME, &CONTROLLER, TS, &key),
        );
        dict.add_binary(
            "TAG",
            serialize_tags_signed(&tags, NWID, &ME, &CONTROLLER, TS, &key),
        );
        let dict = Dictionary::deserialize(&dict.serialize()).unwrap();

        let cfg = NetworkRules::from_dictionary(&dict).unwrap();
        assert_eq!(cfg.network_id, NWID);
        assert_eq!(cfg.timestamp, TS);
        assert_eq!(cfg.credential_time_max_delta, 1_000);
        assert_eq!(cfg.flags, NETWORK_FLAG_RULES_RESULT_OF_UNSUPPORTED_MATCH);
        assert_eq!(cfg.rules, vec![ethertype(ETHERTYPE_ARP), accept()]);
        assert_eq!(cfg.capabilities.len(), 1);
        assert!(cfg.capabilities[0].verify(&key.verifying_key()));
        let tag_ids: Vec<u32> = cfg.tags.iter().map(|t| t.tag.id).collect();
        assert_eq!(tag_ids, vec![1, 2]);
        assert_eq!(cfg.local_tag(2), Some(5));

        let v4 = ipv4(17, &udp(1, 2));
        let v6 = ipv6(17, &udp(1, 2));
        let d = out(&cfg, None, &frame(ETHERTYPE_IPV4, &v4));
        assert_eq!((d.verdict, d.capability_id), (Verdict::Accept, Some(1)));
        assert_eq!(
            out(&cfg, None, &frame(ETHERTYPE_IPV6, &v6)).verdict,
            Verdict::Drop
        );

        // No R key: no rules, so everything is dropped.
        let empty = NetworkRules::from_dictionary(&Dictionary::new()).unwrap();
        assert!(empty.rules.is_empty());
        let raw = [0u8; 4];
        assert_eq!(
            out(&empty, None, &frame(ETHERTYPE_TEST, &raw)).verdict,
            Verdict::Drop
        );

        let mut bad = Dictionary::new();
        bad.add_binary("R", vec![MATCH_ETHERTYPE]);
        assert_eq!(
            NetworkRules::from_dictionary(&bad),
            Err(RuleParseError::Truncated)
        );
    }

    #[test]
    fn peer_credentials_follow_upstream_add_rules() {
        let key = signing_key();
        let vk = key.verifying_key();
        let cfg = config(vec![]);
        let signed_tag = |value, ts| {
            let bytes =
                serialize_tags_signed(&[Tag { id: 1, value }], NWID, &PEER, &CONTROLLER, ts, &key);
            TagCredential::deserialize(&bytes).unwrap().0
        };
        let mut peer = PeerCredentials::default();
        assert_eq!(
            peer.add_tag(&cfg, signed_tag(5, TS), &vk),
            AddCredentialResult::AcceptedNew
        );
        assert_eq!(
            peer.add_tag(&cfg, signed_tag(5, TS), &vk),
            AddCredentialResult::AcceptedRedundant
        );
        assert_eq!(
            peer.add_tag(&cfg, signed_tag(6, TS - 1), &vk),
            AddCredentialResult::Rejected
        );
        assert_eq!(
            peer.add_tag(&cfg, signed_tag(6, TS + 1), &vk),
            AddCredentialResult::AcceptedNew
        );
        assert_eq!(peer.tag(&cfg, 1), Some(6));

        let mut forged = signed_tag(9, TS + 2);
        forged.tag.value = 10;
        assert_eq!(
            peer.add_tag(&cfg, forged, &vk),
            AddCredentialResult::Rejected
        );
        let mut foreign = signed_tag(9, TS + 2);
        foreign.network_id = NWID + 1;
        assert_eq!(
            peer.add_tag(&cfg, foreign, &vk),
            AddCredentialResult::Rejected
        );

        let signed_cap = |id, ts| {
            let caps = [Capability {
                id,
                rules: vec![accept()],
            }];
            let bytes = serialize_capabilities_signed(&caps, NWID, &PEER, &CONTROLLER, ts, &key);
            CapabilityCredential::deserialize(&bytes).unwrap().0
        };
        assert_eq!(
            peer.add_capability(&cfg, signed_cap(9, TS), &vk),
            AddCredentialResult::AcceptedNew
        );
        assert_eq!(
            peer.add_capability(&cfg, signed_cap(3, TS), &vk),
            AddCredentialResult::AcceptedNew
        );
        assert_eq!(
            peer.add_capability(&cfg, signed_cap(3, TS), &vk),
            AddCredentialResult::AcceptedRedundant
        );
        let ids: Vec<u32> = peer.capabilities.iter().map(|c| c.capability.id).collect();
        assert_eq!(ids, vec![3, 9]);

        let later = NetworkRules {
            timestamp: TS + 1_000,
            ..config(vec![])
        };
        assert_eq!(
            peer.add_capability(&later, signed_cap(4, TS - 5), &vk),
            AddCredentialResult::AcceptedNew
        );
        peer.clean(&later);
        let ids: Vec<u32> = peer.capabilities.iter().map(|c| c.capability.id).collect();
        assert_eq!((ids, peer.tags.len()), (vec![3, 9], 1));
    }
}
