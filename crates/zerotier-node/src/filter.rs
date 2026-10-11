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
