/// VL2 frame processing: handles inbound/outbound Ethernet frames over ZeroTier.
///
/// This module connects the VL2 components (network membership, COM verification,
/// ARP/NDP interception, multicast) into the Node's receive/dispatch path.
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::net::SocketAddr;

use core::net::IpAddr;
use zerotier_crypto::salsa;
use zerotier_protocol::constants::{
    CIPHER_SUITE_C25519_POLY1305_SALSA2012, FLAG_FRAGMENTED, ZT_DEFAULT_PHYSMTU,
};
use zerotier_protocol::fragment::fragment_packet;
use zerotier_protocol::verb::Verb;
use zerotier_protocol::verbs::frame::{ExtFramePayload, FramePayload};
use zerotier_protocol::verbs::multicast::{
    MulticastFramePayload, MulticastGatherPayload, MulticastLikePayload,
};
use zerotier_protocol::verbs::ok::{OkPayload, OkSubPayload};

use crate::arp;
use crate::ethernet;
use crate::filter::{self, FilterDecision, FilterEnv, Frame, Verdict};
use crate::ndp;
use crate::node::{Node, NodeAction};

/// Build a complete ZT packet containing an EXT_FRAME verb payload.
///
/// Returns the armored packet bytes ready to send, or None on error.
pub(crate) fn build_encrypted_verb_packet(
    packet_id: u64,
    our_address: &[u8; 5],
    dest_address: &[u8; 5],
    verb: Verb,
    payload: &[u8],
    shared_secret: &[u8; 48],
) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 28 + payload.len()];

    buf[0..8].copy_from_slice(&packet_id.to_be_bytes());
    buf[8..13].copy_from_slice(dest_address);
    buf[13..18].copy_from_slice(our_address);
    buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;
    buf[19..27].copy_from_slice(&[0u8; 8]);
    buf[27] = verb.to_byte();
    buf[28..28 + payload.len()].copy_from_slice(payload);
    let total_len = 28 + payload.len();
    // A packet larger than the physical MTU goes out as a head plus
    // fragments; the head's flag must be set before armoring since the
    // flags byte feeds the MAC (ZeroTierOne node/Switch.cpp).
    if total_len > ZT_DEFAULT_PHYSMTU {
        buf[18] |= FLAG_FRAGMENTED;
    }

    salsa::armor_packet(shared_secret, &mut buf[..total_len], true).ok()?;

    buf.truncate(total_len);
    Some(buf)
}

fn build_ext_frame_packet(
    packet_id: u64,
    our_address: &[u8; 5],
    dest_address: &[u8; 5],
    ext: &ExtFramePayload<'_>,
    shared_secret: &[u8; 48],
) -> Option<Vec<u8>> {
    let mut payload = vec![0u8; 23 + ext.payload.len()];
    let payload_len = ext.serialize(&mut payload);
    payload.truncate(payload_len);
    build_encrypted_verb_packet(
        packet_id,
        our_address,
        dest_address,
        Verb::ExtFrame,
        &payload,
        shared_secret,
    )
}

fn push_fragmented_send(
    actions: &mut Vec<NodeAction>,
    packet: Vec<u8>,
    address: SocketAddr,
    mtu: usize,
) {
    match fragment_packet(&packet, mtu) {
        Some(fragments) => {
            for data in fragments {
                actions.push(NodeAction::SendTo { data, address });
            }
        }
        None => {
            tracing::warn!(
                target: "manytier",
                event = "fragmentation_failed",
                pkt_len = packet.len(),
                mtu,
                "failed to fragment outbound packet"
            );
        }
    }
}

fn path_and_secret(node: &Node, address: &[u8; 5], now_ms: u64) -> Option<(SocketAddr, [u8; 48])> {
    node.topology.get_peer(address).and_then(|peer| {
        peer.best_path(now_ms)
            .and_then(|path| peer.shared_secret().map(|secret| (path.address, *secret)))
    })
}

#[derive(Clone, Copy)]
enum FilterDirection {
    /// `no_tee` suppresses TEE and WATCH copies, as upstream does when it
    /// filters a multicast once more per recipient.
    Outbound {
        no_tee: bool,
    },
    Inbound,
}

/// Run a frame through the network's rules, then send the TEE, WATCH and
/// REDIRECT copies they ask for, as ZeroTierOne's Network::filterOutgoingPacket
/// and filterIncomingPacket do. False when the frame itself must go no
/// further. A network whose config carried no rules passes everything.
fn filter_frame(
    node: &mut Node,
    actions: &mut Vec<NodeAction>,
    network_id: u64,
    frame: &Frame<'_>,
    direction: FilterDirection,
    now_ms: u64,
) -> bool {
    let Some(decision) = evaluate_rules(node, network_id, frame, direction) else {
        return true;
    };
    send_filter_copies(node, actions, network_id, frame, &decision, now_ms);
    if decision.verdict == Verdict::Drop {
        tracing::debug!(
            target: "manytier",
            event = "vl2_frame_filtered",
            inbound = matches!(direction, FilterDirection::Inbound),
            redirected = decision.redirect.is_some(),
            ethertype = frame.ethertype,
            "network rules stopped a frame"
        );
        return false;
    }
    true
}

fn evaluate_rules(
    node: &mut Node,
    network_id: u64,
    frame: &Frame<'_>,
    direction: FilterDirection,
) -> Option<FilterDecision> {
    let net = node
        .networks
        .iter()
        .find(|net| net.network_id == network_id)?;
    let config = net.rules.as_ref()?;
    // The other member: whose tags the rules compare ours with.
    let peer = match direction {
        FilterDirection::Outbound { .. } => frame.zt_dest,
        FilterDirection::Inbound => Some(frame.zt_source),
    };
    let env = FilterEnv {
        config,
        our_address: *node.identity.address.as_bytes(),
        peer: peer.and_then(|peer| net.peer_credentials.get(&peer)),
        ownership: None,
    };
    let state = &mut node.filter_rng;
    let mut rng = || {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        (*state >> 32) as u32
    };
    Some(match direction {
        FilterDirection::Outbound { no_tee } => {
            filter::filter_outgoing(&env, frame, no_tee, &mut rng)
        }
        FilterDirection::Inbound => filter::filter_incoming(&env, frame, &mut rng),
    })
}

fn send_filter_copies(
    node: &mut Node,
    actions: &mut Vec<NodeAction>,
    network_id: u64,
    frame: &Frame<'_>,
    decision: &FilterDecision,
    now_ms: u64,
) {
    let our_address = *node.identity.address.as_bytes();
    for copy in decision.copies() {
        if copy.to == our_address {
            continue;
        }
        let Some((path_address, shared_secret)) = path_and_secret(node, &copy.to, now_ms) else {
            actions.push(NodeAction::WhoisNeeded {
                addresses: alloc::vec![copy.to],
            });
            continue;
        };
        let ext = ExtFramePayload {
            network_id,
            flags: copy.ext_frame_flags,
            com: None,
            dest_mac: frame.mac_dest,
            src_mac: frame.mac_source,
            ethertype: frame.ethertype,
            payload: &frame.payload[..copy.length.min(frame.payload.len())],
        };
        let packet_id = node.allocate_packet_id();
        if let Some(packet) =
            build_ext_frame_packet(packet_id, &our_address, &copy.to, &ext, &shared_secret)
        {
            push_fragmented_send(actions, packet, path_address, ZT_DEFAULT_PHYSMTU);
        }
    }
}

/// Inbound counterpart of [`filter_frame`]; copies go out as node actions.
fn filter_inbound(node: &mut Node, network_id: u64, frame: &Frame<'_>, now_ms: u64) -> bool {
    let mut actions = Vec::new();
    let pass = filter_frame(
        node,
        &mut actions,
        network_id,
        frame,
        FilterDirection::Inbound,
        now_ms,
    );
    for action in actions {
        node.push_action(action);
    }
    pass
}

/// Handle an inbound FRAME verb (0x06).
///
/// FRAME carries an Ethernet payload with implicit src/dest from the packet header.
/// The sender's ZT address is used to derive the source MAC.
pub fn handle_frame(
    node: &mut Node,
    sender_address: &[u8; 5],
    payload_data: &[u8],
    from: SocketAddr,
    now_ms: u64,
    packet_id: u64,
) {
    let frame = match FramePayload::parse(payload_data) {
        Ok(f) => f,
        Err(_) => return,
    };

    // Find the network
    let network = match node.find_network(frame.network_id) {
        Some(n) => n,
        None => return,
    };

    // Verify sender's COM
    let has_valid_com = has_peer_com(node, network.network_id, sender_address);
    if !has_valid_com {
        let network_id = network.network_id;
        node.request_credentials(
            sender_address,
            Verb::Frame,
            packet_id,
            network_id,
            from,
            now_ms,
        );
        return;
    }

    // Derive MACs: sender MAC from sender's ZT address, dest MAC is our MAC
    let src_mac = ethernet::derive_mac(sender_address, frame.network_id);
    let our_address = *node.identity.address.as_bytes();
    let dest_mac = network.our_mac(&our_address);

    let filtered = Frame {
        zt_source: *sender_address,
        zt_dest: Some(our_address),
        mac_source: src_mac,
        mac_dest: dest_mac,
        ethertype: frame.ethertype,
        vlan_id: 0,
        payload: frame.payload,
    };
    if !filter_inbound(node, frame.network_id, &filtered, now_ms) {
        return;
    }

    if answer_address_resolution(
        node,
        frame.network_id,
        sender_address,
        src_mac,
        frame.ethertype,
        frame.payload,
        now_ms,
    ) {
        return;
    }

    node.push_action(NodeAction::FrameReceived {
        network_id: frame.network_id,
        src_mac,
        dest_mac,
        ethertype: frame.ethertype,
        payload: frame.payload.to_vec(),
    });
}

/// Handle an inbound EXT_FRAME verb (0x07).
///
/// EXT_FRAME carries explicit src/dest MAC addresses and supports bridging.
pub fn handle_ext_frame(
    node: &mut Node,
    sender_address: &[u8; 5],
    payload_data: &[u8],
    from: SocketAddr,
    now_ms: u64,
    packet_id: u64,
) {
    let ext = match ExtFramePayload::parse(payload_data) {
        Ok(e) => e,
        Err(_) => return,
    };
    note_inline_com(node, ext.network_id, sender_address, ext.com.clone());

    // Find the network
    let network = match node.find_network(ext.network_id) {
        Some(n) => n,
        None => return,
    };

    // Verify sender's COM
    let has_valid_com = has_peer_com(node, network.network_id, sender_address);
    if !has_valid_com {
        let network_id = network.network_id;
        node.request_credentials(
            sender_address,
            Verb::ExtFrame,
            packet_id,
            network_id,
            from,
            now_ms,
        );
        return;
    }

    let filtered = Frame {
        zt_source: *sender_address,
        zt_dest: Some(*node.identity.address.as_bytes()),
        mac_source: ext.src_mac,
        mac_dest: ext.dest_mac,
        ethertype: ext.ethertype,
        vlan_id: 0,
        payload: ext.payload,
    };
    if !filter_inbound(node, ext.network_id, &filtered, now_ms) {
        return;
    }

    if answer_address_resolution(
        node,
        ext.network_id,
        sender_address,
        ext.src_mac,
        ext.ethertype,
        ext.payload,
        now_ms,
    ) {
        return;
    }

    node.push_action(NodeAction::FrameReceived {
        network_id: ext.network_id,
        src_mac: ext.src_mac,
        dest_mac: ext.dest_mac,
        ethertype: ext.ethertype,
        payload: ext.payload.to_vec(),
    });
}

/// Handle an inbound MULTICAST_LIKE verb (0x09).
///
/// Records multicast group subscriptions from the sender.
pub fn handle_multicast_like(
    node: &mut Node,
    sender_address: &[u8; 5],
    payload_data: &[u8],
    now_ms: u64,
) {
    let like = match MulticastLikePayload::deserialize(payload_data) {
        Ok(l) => l,
        Err(_) => return,
    };

    let mut network_ids = Vec::new();
    for group in &like.groups {
        if !network_ids.contains(&group.network_id) {
            network_ids.push(group.network_id);
        }
    }

    for network_id in network_ids {
        if !may_share_multicast(node, network_id, sender_address) {
            continue;
        }
        let groups: Vec<_> = like
            .groups
            .iter()
            .filter(|group| group.network_id == network_id)
            .cloned()
            .collect();
        node.multicast_manager
            .replace_subscriptions(network_id, *sender_address, &groups, now_ms);
    }
}

/// Handle an inbound MULTICAST_GATHER verb (0x0d).
///
/// Responds with known subscribers for the requested multicast group.
pub fn handle_multicast_gather(
    node: &mut Node,
    sender_address: &[u8; 5],
    payload_data: &[u8],
    from: SocketAddr,
    _now_ms: u64,
    in_re_packet_id: u64,
) {
    let gather = match MulticastGatherPayload::deserialize(payload_data) {
        Ok(g) => g,
        Err(_) => return,
    };
    if !may_share_multicast(node, gather.network_id, sender_address) {
        return;
    }

    // Like ZeroTier One's Multicaster::gather: ourselves first if we are in
    // the group, then the members we know of, never the asker itself.
    let limit = gather.gather_limit as usize;
    let our_address = *node.identity.address.as_bytes();
    let we_subscribe = node.find_network(gather.network_id).is_some_and(|net| {
        net.multicast_groups
            .iter()
            .any(|group| group.mac == gather.mac && group.adi == gather.adi)
    });
    let mut subscribers = Vec::new();
    if we_subscribe && limit > 0 {
        subscribers.push(our_address);
    }
    subscribers.extend(node.multicast_manager.get_replication_targets(
        gather.network_id,
        &gather.mac,
        gather.adi,
        sender_address,
        limit.saturating_sub(subscribers.len()),
    ));

    // Upstream sends no OK when nothing was gathered (ZeroTierOne
    // node/IncomingPacket.cpp _doMULTICAST_GATHER).
    if subscribers.is_empty() {
        return;
    }

    // Build OK(MULTICAST_GATHER) response with subscriber list. Wire format
    // after the OK in-re header (node/Packet.hpp VERB_MULTICAST_GATHER,
    // node/Multicaster.cpp gather): network id (8), group MAC (6), ADI (4),
    // total known members (u32), gathered count (u16), 5-byte addresses.
    let total_known = node
        .multicast_manager
        .get_subscribers(gather.network_id, &gather.mac, gather.adi, usize::MAX)
        .len() as u32
        + u32::from(we_subscribe);
    let count = subscribers.len() as u16;
    let response_len = 24 + subscribers.len() * 5;
    let mut response = Vec::with_capacity(response_len);
    response.extend_from_slice(&gather.network_id.to_be_bytes());
    response.extend_from_slice(&gather.mac);
    response.extend_from_slice(&gather.adi.to_be_bytes());
    response.extend_from_slice(&total_known.to_be_bytes());
    response.extend_from_slice(&count.to_be_bytes());
    for addr in &subscribers {
        response.extend_from_slice(addr);
    }

    let ok = OkPayload {
        in_re_verb: Verb::MulticastGather,
        in_re_packet_id,
        sub_payload: OkSubPayload::Generic { data: response },
    };
    let mut payload = vec![0u8; 9 + response_len];
    let payload_len = match ok.serialize(&mut payload) {
        Ok(payload_len) => payload_len,
        Err(_) => return,
    };
    payload.truncate(payload_len);

    let shared_secret = match node.shared_secret_for_peer(sender_address) {
        Some(secret) => secret,
        None => return,
    };
    let packet_id = node.allocate_packet_id();
    let our_address = *node.identity.address.as_bytes();
    let packet = match build_encrypted_verb_packet(
        packet_id,
        &our_address,
        sender_address,
        Verb::Ok,
        &payload,
        &shared_secret,
    ) {
        Some(packet) => packet,
        None => return,
    };

    tracing::debug!(
        target: "manytier",
        event = "multicast_gather_response_sent",
        response_count = subscribers.len(),
        "sent OK(MULTICAST_GATHER)"
    );
    node.push_action(NodeAction::SendTo {
        data: packet,
        address: from,
    });
}

/// Handle an inbound MULTICAST_FRAME verb (0x0e).
///
/// Decapsulates a multicast frame and delivers it to the TUN device.
pub fn handle_multicast_frame(
    node: &mut Node,
    sender_address: &[u8; 5],
    payload_data: &[u8],
    from: SocketAddr,
    now_ms: u64,
    packet_id: u64,
) {
    let mf = match MulticastFramePayload::parse(payload_data) {
        Ok(m) => m,
        Err(_) => return,
    };
    note_inline_com(node, mf.network_id, sender_address, mf.com.clone());

    // Find the network
    let network = match node.find_network(mf.network_id) {
        Some(n) => n,
        None => return,
    };

    // Verify sender's COM
    let has_valid_com = has_peer_com(node, network.network_id, sender_address);
    if !has_valid_com {
        let network_id = network.network_id;
        node.request_credentials(
            sender_address,
            Verb::MulticastFrame,
            packet_id,
            network_id,
            from,
            now_ms,
        );
        return;
    }

    // Derive source MAC from sender or explicit source_mac in frame
    let src_mac = mf
        .source_mac
        .unwrap_or_else(|| ethernet::derive_mac(sender_address, mf.network_id));

    let filtered = Frame {
        zt_source: *sender_address,
        zt_dest: Some(*node.identity.address.as_bytes()),
        mac_source: src_mac,
        mac_dest: mf.dest_mac,
        ethertype: mf.ethertype,
        vlan_id: 0,
        payload: mf.payload,
    };
    if !filter_inbound(node, mf.network_id, &filtered, now_ms) {
        return;
    }

    if answer_address_resolution(
        node,
        mf.network_id,
        sender_address,
        src_mac,
        mf.ethertype,
        mf.payload,
        now_ms,
    ) {
        return;
    }

    node.push_action(NodeAction::FrameReceived {
        network_id: mf.network_id,
        src_mac,
        dest_mac: mf.dest_mac,
        ethertype: mf.ethertype,
        payload: mf.payload.to_vec(),
    });
}

/// Process an outbound frame from the TUN device for transmission on the virtual network.
///
/// This is called when the TUN device reads an IP packet that needs to be sent.
/// It handles:
/// - ARP interception (resolve locally if possible, otherwise multicast)
/// - Unicast IPv4/IPv6 (look up dest, build EXT_FRAME)
/// - Multicast/broadcast frames
///
/// Returns a list of actions (SendTo with EXT_FRAME packets, or LocalReply for ARP).
pub fn process_outbound_frame(
    node: &mut Node,
    network_id: u64,
    ethertype: u16,
    payload: &[u8],
    our_zt_address: &[u8; 5],
    now_ms: u64,
) -> Vec<NodeAction> {
    let mut actions = Vec::new();

    let network = match node.find_network(network_id) {
        Some(n) => n,
        None => return actions,
    };

    let our_mac = network.our_mac(our_zt_address);
    // Destination IP not in the member directory.
    let mut unknown_destination = false;

    match ethertype {
        ethernet::ETHERTYPE_ARP => {
            // Try to resolve ARP locally
            if let Some(arp_pkt) = arp::ArpPacket::parse(payload) {
                if let Some(reply) = arp::handle_arp_request(&arp_pkt, network) {
                    // Resolved locally -- return as LocalReply
                    let mut buf = [0u8; 28];
                    let n = reply.serialize(&mut buf);
                    actions.push(NodeAction::LocalReply {
                        network_id,
                        ethertype: ethernet::ETHERTYPE_ARP,
                        payload: buf[..n].to_vec(),
                    });
                    return actions;
                }
            }
            // Not resolved locally: multicast it to the group the target's
            // owner subscribes for ARP (broadcast MAC, the address as ADI).
            if payload.len() >= 28 {
                let target =
                    u32::from_be_bytes([payload[24], payload[25], payload[26], payload[27]]);
                send_multicast_frame(
                    node,
                    &mut actions,
                    network_id,
                    ([0xff; 6], target),
                    ethertype,
                    payload,
                    now_ms,
                );
            }
        }
        ethernet::ETHERTYPE_IPV4 => {
            // Look up destination IP -> member -> ZT address -> physical path
            if payload.len() >= 20 {
                let dest_ip =
                    core::net::Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
                match network.lookup_ipv4(dest_ip) {
                    Some(member) => {
                        let (member_address, member_mac) = (member.zt_address, member.mac);
                        send_unicast_frame(
                            node,
                            &mut actions,
                            network_id,
                            (member_address, member_mac),
                            our_mac,
                            ethertype,
                            payload,
                            now_ms,
                        );
                    }
                    None => match network.gateway_for(IpAddr::V4(dest_ip)) {
                        Some(Some(gateway)) => {
                            let (member_address, member_mac) = (gateway.zt_address, gateway.mac);
                            send_unicast_frame(
                                node,
                                &mut actions,
                                network_id,
                                (member_address, member_mac),
                                our_mac,
                                ethertype,
                                payload,
                                now_ms,
                            );
                        }
                        Some(None) => unknown_destination = true,
                        None => {
                            let broadcast = dest_ip.is_broadcast()
                                || is_directed_broadcast_v4(network, dest_ip);
                            let group = if dest_ip.is_multicast() {
                                let o = dest_ip.octets();
                                Some(([0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]], 0))
                            } else if broadcast && network.broadcast_enabled {
                                Some(([0xff; 6], 0))
                            } else {
                                None
                            };
                            unknown_destination = !dest_ip.is_multicast() && !broadcast;
                            if let Some(group) = group {
                                send_multicast_frame(
                                    node,
                                    &mut actions,
                                    network_id,
                                    group,
                                    ethertype,
                                    payload,
                                    now_ms,
                                );
                            }
                        }
                    },
                }
            }
        }
        ethernet::ETHERTYPE_IPV6 => {
            // Look up destination IPv6 -> member -> ZT address -> physical path
            if payload.len() >= 40 {
                let mut dst_bytes = [0u8; 16];
                dst_bytes.copy_from_slice(&payload[24..40]);
                let dest_ip = core::net::Ipv6Addr::from(dst_bytes);
                match network.lookup_ipv6(dest_ip) {
                    Some(member) => {
                        let (member_address, member_mac) = (member.zt_address, member.mac);
                        send_unicast_frame(
                            node,
                            &mut actions,
                            network_id,
                            (member_address, member_mac),
                            our_mac,
                            ethertype,
                            payload,
                            now_ms,
                        );
                    }
                    None => match network.gateway_for(IpAddr::V6(dest_ip)) {
                        Some(Some(gateway)) => {
                            let (member_address, member_mac) = (gateway.zt_address, gateway.mac);
                            send_unicast_frame(
                                node,
                                &mut actions,
                                network_id,
                                (member_address, member_mac),
                                our_mac,
                                ethertype,
                                payload,
                                now_ms,
                            );
                        }
                        Some(None) => unknown_destination = true,
                        None if dest_ip.is_multicast() => {
                            let o = dest_ip.octets();
                            send_multicast_frame(
                                node,
                                &mut actions,
                                network_id,
                                ([0x33, 0x33, o[12], o[13], o[14], o[15]], 0),
                                ethertype,
                                payload,
                                now_ms,
                            );
                        }
                        None => unknown_destination = true,
                    },
                }
            }
        }
        _ => {
            // Unknown ethertype -- drop
        }
    }

    if unknown_destination {
        // Ask for a fresh config; the caller holds the packet.
        node.note_unknown_destination(network_id, now_ms);
        actions.push(NodeAction::DestinationUnknown { network_id });
    }

    actions
}

/// Send `payload` to one member as an EXT_FRAME, if the network's rules
/// let it go. Our credentials go first when the member has not had them
/// recently, as ZeroTier One does before every unicast (node/Switch.cpp
/// `pushCredentialsIfNeeded`): a peer that lacks our COM drops the frame.
#[allow(clippy::too_many_arguments)]
fn send_unicast_frame(
    node: &mut Node,
    actions: &mut Vec<NodeAction>,
    network_id: u64,
    (member_address, member_mac): ([u8; 5], [u8; 6]),
    our_mac: [u8; 6],
    ethertype: u16,
    payload: &[u8],
    now_ms: u64,
) {
    let our_zt_address = *node.identity.address.as_bytes();
    let frame = Frame {
        zt_source: our_zt_address,
        zt_dest: Some(member_address),
        mac_source: our_mac,
        mac_dest: member_mac,
        ethertype,
        vlan_id: 0,
        payload,
    };
    let outbound = FilterDirection::Outbound { no_tee: false };
    if !filter_frame(node, actions, network_id, &frame, outbound, now_ms) {
        return;
    }
    let Some((path_address, shared_secret)) = path_and_secret(node, &member_address, now_ms) else {
        actions.push(NodeAction::WhoisNeeded {
            addresses: alloc::vec![member_address],
        });
        return;
    };
    actions.extend(node.credentials_if_needed(network_id, &member_address, now_ms));
    let ext = ExtFramePayload {
        network_id,
        flags: 0,
        com: None,
        dest_mac: member_mac,
        src_mac: our_mac,
        ethertype,
        payload,
    };
    let packet_id = node.allocate_packet_id();
    if let Some(pkt) = build_ext_frame_packet(
        packet_id,
        &our_zt_address,
        &member_address,
        &ext,
        &shared_secret,
    ) {
        tracing::info!(
            target: "manytier",
            event = "vl2_ext_frame_out",
            dest_addr = %path_address,
            pkt_len = pkt.len(),
            "sending EXT_FRAME"
        );
        push_fragmented_send(actions, pkt, path_address, ZT_DEFAULT_PHYSMTU);
    }
}

/// Send `payload` as a MULTICAST_FRAME to the known members of a group
/// (the network's multicast limit at most), as ZeroTier One's
/// Multicaster::send does with the members it has gathered. The rules see
/// the frame once as a whole and once per recipient, as upstream's do.
/// Credentials go first where needed, as for unicast.
#[allow(clippy::too_many_arguments)]
fn send_multicast_frame(
    node: &mut Node,
    actions: &mut Vec<NodeAction>,
    network_id: u64,
    (group_mac, adi): ([u8; 6], u32),
    ethertype: u16,
    payload: &[u8],
    now_ms: u64,
) {
    let our_zt_address = *node.identity.address.as_bytes();
    let Some((limit, our_mac)) = node
        .find_network(network_id)
        .map(|net| (net.multicast_limit, net.our_mac(&our_zt_address)))
    else {
        return;
    };
    let mut filtered = Frame {
        zt_source: our_zt_address,
        zt_dest: None,
        mac_source: our_mac,
        mac_dest: group_mac,
        ethertype,
        vlan_id: 0,
        payload,
    };
    let outbound = FilterDirection::Outbound { no_tee: false };
    if !filter_frame(node, actions, network_id, &filtered, outbound, now_ms) {
        return;
    }
    let targets = node.multicast_manager.get_replication_targets(
        network_id,
        &group_mac,
        adi,
        &our_zt_address,
        limit as usize,
    );
    if targets.is_empty() {
        return;
    }
    // Our MAC is derived from our address, so receivers derive it too and
    // no source MAC (flag 0x04) is sent.
    let frame = MulticastFramePayload {
        network_id,
        flags: 0,
        com: None,
        gather_limit: None,
        source_mac: None,
        dest_mac: group_mac,
        adi,
        ethertype,
        payload,
    };
    let mut body = vec![0u8; 64 + payload.len()];
    let body_len = frame.serialize(&mut body);
    body.truncate(body_len);

    for target in targets {
        filtered.zt_dest = Some(target);
        let per_recipient = FilterDirection::Outbound { no_tee: true };
        if !filter_frame(node, actions, network_id, &filtered, per_recipient, now_ms) {
            continue;
        }
        let Some((path_address, shared_secret)) = path_and_secret(node, &target, now_ms) else {
            continue;
        };
        actions.extend(node.credentials_if_needed(network_id, &target, now_ms));
        let packet_id = node.allocate_packet_id();
        if let Some(packet) = build_encrypted_verb_packet(
            packet_id,
            &our_zt_address,
            &target,
            Verb::MulticastFrame,
            &body,
            &shared_secret,
        ) {
            push_fragmented_send(actions, packet, path_address, ZT_DEFAULT_PHYSMTU);
        }
    }
}

/// Answer an ARP request or IPv6 neighbor solicitation for one of our own
/// addresses. On an Ethernet tap the OS would; our TUN device is layer 3
/// and never sees them, and without an answer an upstream member cannot
/// reach us. Returns true when the frame was address resolution traffic,
/// which has no use on the TUN device either way.
#[allow(clippy::too_many_arguments)]
fn answer_address_resolution(
    node: &mut Node,
    network_id: u64,
    sender_address: &[u8; 5],
    sender_mac: [u8; 6],
    ethertype: u16,
    payload: &[u8],
    now_ms: u64,
) -> bool {
    let our_address = *node.identity.address.as_bytes();
    let Some(network) = node.find_network(network_id) else {
        return false;
    };
    let our_mac = network.our_mac(&our_address);
    let (our_v4, our_v6) = network.our_ips(&our_address);

    let (reply_to_mac, reply_ethertype, reply) = match ethertype {
        ethernet::ETHERTYPE_ARP => {
            let Some(request) = arp::ArpPacket::parse(payload) else {
                return true;
            };
            let target = core::net::Ipv4Addr::from(request.target_proto);
            if request.operation != arp::ARP_OP_REQUEST || !our_v4.contains(&target) {
                return true;
            }
            let reply = arp::ArpPacket {
                hw_type: 0x0001,
                proto_type: 0x0800,
                hw_len: 6,
                proto_len: 4,
                operation: arp::ARP_OP_REPLY,
                sender_hw: our_mac,
                sender_proto: request.target_proto,
                target_hw: request.sender_hw,
                target_proto: request.sender_proto,
            };
            let mut buf = [0u8; 28];
            let n = reply.serialize(&mut buf);
            (
                request.sender_hw,
                ethernet::ETHERTYPE_ARP,
                buf[..n].to_vec(),
            )
        }
        ethernet::ETHERTYPE_IPV6 => {
            // A neighbor solicitation: ICMPv6 type 135 right after the
            // fixed header, with the target address at offset 8.
            if payload.len() < 64
                || payload[6] != ndp::IPV6_NEXT_HEADER_ICMPV6
                || payload[40] != ndp::ICMPV6_NS
            {
                return false;
            }
            let mut source = [0u8; 16];
            source.copy_from_slice(&payload[8..24]);
            let mut target = [0u8; 16];
            target.copy_from_slice(&payload[48..64]);
            // Duplicate address detection (unspecified source) is not ours
            // to answer.
            if source == [0u8; 16] || !our_v6.contains(&core::net::Ipv6Addr::from(target)) {
                return true;
            }
            let na = ndp::build_na(&target, &our_mac, true, true, &target, &source);
            let packet = ndp::ipv6_packet(&target, &source, ndp::IPV6_NEXT_HEADER_ICMPV6, 255, &na);
            (sender_mac, ethernet::ETHERTYPE_IPV6, packet)
        }
        _ => return false,
    };

    let mut actions = Vec::new();
    send_unicast_frame(
        node,
        &mut actions,
        network_id,
        (*sender_address, reply_to_mac),
        our_mac,
        reply_ethertype,
        &reply,
        now_ms,
    );
    for action in actions {
        node.push_action(action);
    }
    true
}

/// Directed broadcast of any member's IPv4 prefix.
fn is_directed_broadcast_v4(
    network: &crate::network::NetworkMembership,
    ip: core::net::Ipv4Addr,
) -> bool {
    network.members.iter().any(|member| match member.ipv4 {
        Some((addr, prefix)) if prefix < 32 => {
            let host_bits = u32::MAX >> prefix;
            u32::from(ip) == (u32::from(addr) | host_bits)
        }
        _ => false,
    })
}

/// Whether a peer's MULTICAST_LIKE is recorded and its MULTICAST_GATHER
/// answered for a network: it holds a valid certificate for it, or we are a
/// root or the network's controller (ZeroTierOne _doMULTICAST_LIKE,
/// _doMULTICAST_GATHER). Anyone else could fill our subscription table or
/// read a network's member list.
fn may_share_multicast(node: &Node, network_id: u64, sender_address: &[u8; 5]) -> bool {
    let our_address = node.identity.address.as_bytes();
    has_peer_com(node, network_id, sender_address)
        || node.topology.roots.contains(our_address)
        || crate::node::controller_address_from_network_id(network_id) == *our_address
}

/// A COM sent inside a frame (flag 0x01, deprecated but still sent by
/// older peers) is the sender's credential, as if it had arrived in
/// NETWORK_CREDENTIALS (ZeroTierOne `network->addCredential(com)`). It is
/// verified when the frame is gated.
fn note_inline_com(
    node: &mut Node,
    network_id: u64,
    sender_address: &[u8; 5],
    com: Option<zerotier_protocol::verbs::network_config::CertificateOfMembership>,
) {
    let Some(com) = com else {
        return;
    };
    let for_network = com
        .qualifiers
        .iter()
        .any(|q| q.id == 1 && q.value == network_id);
    if com.issued_to != *sender_address || !for_network {
        return;
    }
    if let Some(net) = node.find_network_mut(network_id) {
        net.peer_coms
            .retain(|(address, _)| address != sender_address);
        net.peer_coms.push((*sender_address, com));
    }
}

/// Check if a peer has a valid COM stored in the network's peer_coms list,
/// and if so verify it against our own COM and the network's actual
/// controller signing key (resolved via `node`'s topology).
fn has_peer_com(node: &Node, network_id: u64, peer_address: &[u8; 5]) -> bool {
    let network = match node.find_network(network_id) {
        Some(n) => n,
        None => return false,
    };
    // Find the peer's COM in the network's stored COMs
    let peer_com = match network
        .peer_coms
        .iter()
        .find(|(addr, _)| addr == peer_address)
    {
        Some((_, com)) => com,
        None => return false,
    };
    let controller_address = crate::node::controller_address_from_network_id(network_id);
    let controller_verifying_key = node
        .topology
        .get_peer(&controller_address)
        .and_then(|p| ed25519_dalek::VerifyingKey::from_bytes(&p.identity.public_key.signing).ok());
    network.verify_peer_com(
        peer_address,
        peer_com,
        &controller_address,
        controller_verifying_key.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet;
    use crate::multicast::MulticastManager;
    use crate::network::{NetworkMember, NetworkMembership};
    use crate::node::Node;
    use crate::peer::PeerState;
    use alloc::vec;
    use core::net::{Ipv4Addr, SocketAddr};
    use zerotier_crypto::identity::{Address, Identity, PublicKey};
    use zerotier_protocol::inet_address::InetAddress;
    use zerotier_protocol::world::WorldRoot;

    /// Build a Node with a joined network whose `our_com` is signed by a real
    /// Ed25519 key, and register that key's identity as the network's
    /// resolved controller peer -- matching what `has_peer_com` needs to
    /// verify a peer's COM signature.
    fn make_node_with_com(network_id: u64) -> (Node, ed25519_dalek::SigningKey, [u8; 5]) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x55; 32]);
        let planet = make_synthetic_planet();
        let mut node = Node::new(test_identity(0x01), &planet, 1).unwrap();

        let controller_address = crate::node::controller_address_from_network_id(network_id);
        let mut controller_pk_bytes = [0u8; 64];
        controller_pk_bytes[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        let controller_identity = Identity {
            address: Address::new(controller_address).unwrap(),
            public_key: PublicKey::from_bytes(&controller_pk_bytes).unwrap(),
            secret: None,
        };
        node.topology.add_peer(controller_identity);

        let our_com = crate::controller::engine::build_signed_com(
            &signing_key,
            &controller_address,
            network_id,
            0,
            1000,
        );
        let mut net = NetworkMembership::new(network_id, 2800);
        net.our_com = Some(our_com);
        node.networks.push(net);

        (node, signing_key, controller_address)
    }

    fn add_peer_com(
        node: &mut Node,
        network_id: u64,
        signing_key: &ed25519_dalek::SigningKey,
        controller_address: &[u8; 5],
        peer_addr: &[u8; 5],
    ) {
        let com = crate::controller::engine::build_signed_com(
            signing_key,
            controller_address,
            network_id,
            crate::controller::engine::zt_address_to_u64(peer_addr),
            1050,
        );
        let net = node.find_network_mut(network_id).unwrap();
        net.peer_coms.push((*peer_addr, com));
    }

    fn test_identity(addr_byte: u8) -> Identity {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, addr_byte]).unwrap();
        let mut pk_bytes = [0u8; 64];
        for (i, b) in pk_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(addr_byte);
        }
        let public_key = PublicKey::from_bytes(&pk_bytes).unwrap();
        Identity {
            address,
            public_key,
            secret: None,
        }
    }

    fn make_synthetic_planet() -> Vec<u8> {
        let root_id = test_identity(0xe0);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let mut public_key_bytes = [0u8; 64];
        public_key_bytes[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        crate::controller::world_gen::generate_planet(
            149604618,
            1000000,
            alloc::vec![WorldRoot {
                identity: root_id,
                endpoints: alloc::vec![InetAddress::V4 {
                    ip: [192, 168, 1, 1],
                    port: 9993,
                }],
            }],
            &signing_key,
            &public_key_bytes,
        )
    }

    fn ipv4_packet_to(dst: [u8; 4]) -> alloc::vec::Vec<u8> {
        let mut packet = alloc::vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 147, 20, 1]);
        packet[16..20].copy_from_slice(&dst);
        packet
    }

    #[test]
    fn outbound_frame_to_unknown_member_requests_config_refresh() {
        let network_id = 0xfe00000000abcdef_u64;
        let our_addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let (mut node, _signing_key, _controller) = make_node_with_com(network_id);
        {
            let net = node.find_network_mut(network_id).unwrap();
            net.members.push(NetworkMember {
                zt_address: our_addr,
                mac: ethernet::derive_mac(&our_addr, network_id),
                ipv4: Some((core::net::Ipv4Addr::new(10, 147, 20, 1), 24)),
                ipv6: None,
                authorized: true,
            });
            net.pending_config_request = false;
            net.last_config_request = 10_000;
        }

        // A unicast address nobody in the directory owns: hold and refresh
        // (the refresh is allowed once the 30 s backoff since the last
        // request has passed).
        let actions = process_outbound_frame(
            &mut node,
            network_id,
            ethernet::ETHERTYPE_IPV4,
            &ipv4_packet_to([10, 147, 20, 9]),
            &our_addr,
            45_000,
        );
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, NodeAction::DestinationUnknown { network_id: id } if *id == network_id)),
            "unknown unicast destination must be reported, got {actions:?}"
        );
        let net = node.find_network(network_id).unwrap();
        assert!(net.pending_config_request);
        assert_eq!(
            net.last_config_request, 0,
            "refresh must bypass the rate limit"
        );

        // Multicast and broadcast never trigger a refresh.
        let net = node.find_network_mut(network_id).unwrap();
        net.pending_config_request = false;
        for dst in [[224, 0, 0, 251], [255, 255, 255, 255], [10, 147, 20, 255]] {
            let actions = process_outbound_frame(
                &mut node,
                network_id,
                ethernet::ETHERTYPE_IPV4,
                &ipv4_packet_to(dst),
                &our_addr,
                30_000,
            );
            assert!(
                !actions
                    .iter()
                    .any(|action| matches!(action, NodeAction::DestinationUnknown { .. })),
                "{dst:?} must not be treated as an unknown member"
            );
        }
        assert!(
            !node
                .find_network(network_id)
                .unwrap()
                .pending_config_request
        );
    }

    #[test]
    fn ext_frame_with_valid_com_produces_frame_received() {
        let network_id = 0xfe00000000abcdef_u64;
        let sender = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        let our_addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let our_mac = ethernet::derive_mac(&our_addr, network_id);
        let sender_mac = ethernet::derive_mac(&sender, network_id);

        // Build EXT_FRAME payload
        let ext = ExtFramePayload {
            network_id,
            flags: 0,
            com: None,
            dest_mac: our_mac,
            src_mac: sender_mac,
            ethertype: 0x0800,
            payload: &[0xDE, 0xAD],
        };
        let mut buf = [0u8; 256];
        let n = ext.serialize(&mut buf);

        let (mut node, signing_key, controller_address) = make_node_with_com(network_id);
        add_peer_com(
            &mut node,
            network_id,
            &signing_key,
            &controller_address,
            &sender,
        );

        let from: SocketAddr = "10.0.0.60:9993".parse().unwrap();
        handle_ext_frame(&mut node, &sender, &buf[..n], from, 2000, 1);
        let actions = node.drain_actions();
        assert!(
            actions.iter().any(|action| matches!(
                action,
                NodeAction::FrameReceived { network_id: id, ethertype: 0x0800, payload, .. }
                    if *id == network_id && payload == &[0xDE, 0xAD]
            )),
            "got {actions:?}"
        );
    }

    #[test]
    fn ext_frame_without_com_is_rejected() {
        let network_id = 0xfe00000000abcdef_u64;
        let sender = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];

        let (node, _signing_key, _controller_address) = make_node_with_com(network_id);
        // No peer COM added for sender
        assert!(!has_peer_com(&node, network_id, &sender));
    }

    #[test]
    fn multicast_like_records_subscriptions() {
        let mut mgr = MulticastManager::new();
        let sender = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        let network_id = 0xfe00000000abcdef_u64;

        // Build MULTICAST_LIKE payload
        let like = MulticastLikePayload {
            groups: vec![zerotier_protocol::verbs::multicast::MulticastGroup {
                network_id,
                mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                adi: 0x0806,
            }],
        };
        let mut buf = [0u8; 64];
        let n = like.serialize(&mut buf);
        let parsed = MulticastLikePayload::deserialize(&buf[..n]).unwrap();

        // Simulate what handle_multicast_like does
        for group in &parsed.groups {
            mgr.subscribe(group.network_id, group.mac, group.adi, sender, 1000);
        }

        let subs = mgr.get_subscribers(network_id, &[0xff; 6], 0x0806, 100);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0], sender);
    }

    #[test]
    fn multicast_gather_returns_subscribers() {
        let mut mgr = MulticastManager::new();
        let network_id = 0xfe00000000abcdef_u64;
        let peer1 = [0x01, 0x02, 0x03, 0x04, 0x05];
        let peer2 = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];

        mgr.subscribe(network_id, [0xff; 6], 0x0806, peer1, 1000);
        mgr.subscribe(network_id, [0xff; 6], 0x0806, peer2, 1000);

        let subs = mgr.get_subscribers(network_id, &[0xff; 6], 0x0806, 100);
        assert_eq!(subs.len(), 2);
    }

    #[test]
    fn arp_outbound_resolved_locally() {
        let network_id = 0xfe00000000abcdef_u64;
        let our_addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let peer_addr = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        let peer_mac = ethernet::derive_mac(&peer_addr, network_id);

        let mut net = NetworkMembership::new(network_id, 2800);
        net.members.push(NetworkMember {
            zt_address: peer_addr,
            mac: peer_mac,
            ipv4: Some((Ipv4Addr::new(10, 147, 20, 1), 24)),
            ipv6: None,
            authorized: true,
        });

        // Build ARP request for 10.147.20.1
        let arp_req = arp::ArpPacket {
            hw_type: 0x0001,
            proto_type: 0x0800,
            hw_len: 6,
            proto_len: 4,
            operation: arp::ARP_OP_REQUEST,
            sender_hw: ethernet::derive_mac(&our_addr, network_id),
            sender_proto: [10, 147, 20, 2],
            target_hw: [0x00; 6],
            target_proto: [10, 147, 20, 1],
        };

        let reply = arp::handle_arp_request(&arp_req, &net);
        assert!(reply.is_some());
        let reply = reply.unwrap();
        assert_eq!(reply.operation, arp::ARP_OP_REPLY);
        assert_eq!(reply.sender_hw, peer_mac);
    }

    #[test]
    fn outbound_frame_uses_live_backup_path_when_primary_expired() {
        let planet = make_synthetic_planet();
        let mut node = Node::new(test_identity(0x01), &planet, 1).unwrap();
        let peer_id = test_identity(0x42);
        let peer_address = *peer_id.address.as_bytes();
        let our_address = *node.identity.address.as_bytes();
        let network_id = 0xfe00000000abcdef_u64;

        node.topology.add_peer(peer_id);
        let peer = node.topology.get_peer_mut(&peer_address).unwrap();
        let stale_primary: SocketAddr = "10.0.0.10:9993".parse().unwrap();
        let live_backup: SocketAddr = "10.0.0.11:9993".parse().unwrap();
        peer.add_path(stale_primary, true, 1000);
        peer.add_path(live_backup, false, 999_900);
        peer.state = PeerState::new_active([0x55; 48], 10, 999_900, 999_900);

        let mut membership = NetworkMembership::new(network_id, 2800);
        membership.members.push(NetworkMember {
            zt_address: peer_address,
            mac: ethernet::derive_mac(&peer_address, network_id),
            ipv4: Some((Ipv4Addr::new(10, 147, 20, 2), 24)),
            ipv6: None,
            authorized: true,
        });
        node.join_network(membership);

        let mut ipv4_packet = [0u8; 20];
        ipv4_packet[0] = 0x45;
        ipv4_packet[16..20].copy_from_slice(&[10, 147, 20, 2]);

        let actions = process_outbound_frame(
            &mut node,
            network_id,
            ethernet::ETHERTYPE_IPV4,
            &ipv4_packet,
            &our_address,
            1_000_000,
        );

        assert!(
            actions.iter().any(
                |action| matches!(action, NodeAction::SendTo { address, .. } if *address == live_backup)
            ),
            "outbound traffic should fail over to the live backup path"
        );
    }

    /// OK(MULTICAST_GATHER) carries network id, group MAC, ADI, the total
    /// number of known members (u32) and the gathered count (u16) before
    /// the addresses (ZeroTierOne node/Multicaster.cpp gather); nothing is
    /// sent when nothing was gathered.
    #[test]
    fn multicast_gather_ok_uses_upstream_layout() {
        let network_id = 0xfe00000000abcdef_u64;
        let (mut node, signing_key, controller) = make_node_with_com(network_id);
        let sender = test_identity(0x33);
        let sender_addr = *sender.address.as_bytes();
        add_peer_com(
            &mut node,
            network_id,
            &signing_key,
            &controller,
            &sender_addr,
        );
        let from: SocketAddr = "203.0.113.30:9993".parse().unwrap();
        let shared_secret = [0x66; 48];
        node.topology.add_peer(sender);
        {
            let peer = node.topology.get_peer_mut(&sender_addr).unwrap();
            peer.add_path(from, true, 1000);
            peer.state = PeerState::new_active(shared_secret, 10, 1000, 1000);
        }
        let group_mac = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
        let adi = 0x1234_5678u32;
        let request = MulticastGatherPayload {
            network_id,
            flags: 0,
            mac: group_mac,
            adi,
            gather_limit: 1,
            com: None,
        };
        let mut request_buf = [0u8; 64];
        let request_len = request.serialize(&mut request_buf);

        // Nothing subscribed: no OK at all.
        handle_multicast_gather(
            &mut node,
            &sender_addr,
            &request_buf[..request_len],
            from,
            2000,
            7,
        );
        assert!(node.drain_actions().is_empty());

        let member_a = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        let member_b = [0x1a, 0x1b, 0x1c, 0x1d, 0x1e];
        node.multicast_manager
            .subscribe(network_id, group_mac, adi, member_a, 1000);
        node.multicast_manager
            .subscribe(network_id, group_mac, adi, member_b, 1000);
        handle_multicast_gather(
            &mut node,
            &sender_addr,
            &request_buf[..request_len],
            from,
            2000,
            7,
        );
        let actions = node.drain_actions();
        let NodeAction::SendTo { data, address } = &actions[0] else {
            panic!("expected OK(MULTICAST_GATHER), got {actions:?}");
        };
        assert_eq!(*address, from);
        let mut packet = data.clone();
        salsa::dearmor_packet(&shared_secret, &mut packet).unwrap();
        assert_eq!(packet[27] & 0x1f, Verb::Ok.to_byte());
        let ok = &packet[28..];
        assert_eq!(ok[0], Verb::MulticastGather.to_byte());
        assert_eq!(&ok[1..9], &7u64.to_be_bytes());
        let body = &ok[9..];
        assert_eq!(&body[0..8], &network_id.to_be_bytes());
        assert_eq!(&body[8..14], &group_mac);
        assert_eq!(&body[14..18], &adi.to_be_bytes());
        assert_eq!(&body[18..22], &2u32.to_be_bytes(), "total known");
        assert_eq!(&body[22..24], &1u16.to_be_bytes(), "gathered within limit");
        assert_eq!(body.len(), 24 + 5);
    }

    fn decrypted_verb(data: &[u8], secret: &[u8; 48]) -> Option<(Verb, Vec<u8>)> {
        let mut packet = data.to_vec();
        salsa::dearmor_packet(secret, &mut packet).ok()?;
        Some((Verb::from_byte(packet[27] & 0x1f)?, packet[28..].to_vec()))
    }

    /// Our COM goes to a member before its first frame (ZeroTierOne pushes
    /// credentials before every unicast if they are stale), then not again
    /// until ZT_PEER_ACTIVITY_TIMEOUT has passed.
    #[test]
    fn unicast_frame_is_preceded_by_our_credentials() {
        use zerotier_protocol::constants::ZT_PEER_ACTIVITY_TIMEOUT;

        let network_id = 0xfe00000000abcdef_u64;
        let (mut node, _signing_key, _controller) = make_node_with_com(network_id);
        let our_address = *node.identity.address.as_bytes();
        let peer_id = test_identity(0x42);
        let peer_address = *peer_id.address.as_bytes();
        let path: SocketAddr = "10.0.0.10:9993".parse().unwrap();
        let secret = [0x55; 48];
        node.topology.add_peer(peer_id);
        {
            let peer = node.topology.get_peer_mut(&peer_address).unwrap();
            peer.add_path(path, true, 1000);
            peer.state = PeerState::new_active(secret, 10, 1000, 1000);
        }
        node.find_network_mut(network_id)
            .unwrap()
            .members
            .push(NetworkMember {
                zt_address: peer_address,
                mac: ethernet::derive_mac(&peer_address, network_id),
                ipv4: Some((Ipv4Addr::new(10, 147, 20, 2), 24)),
                ipv6: None,
                authorized: true,
            });
        let mut ipv4_packet = [0u8; 20];
        ipv4_packet[0] = 0x45;
        ipv4_packet[16..20].copy_from_slice(&[10, 147, 20, 2]);

        let verbs_at = |node: &mut Node, now_ms: u64| -> Vec<Verb> {
            process_outbound_frame(
                node,
                network_id,
                ethernet::ETHERTYPE_IPV4,
                &ipv4_packet,
                &our_address,
                now_ms,
            )
            .iter()
            .filter_map(|action| match action {
                NodeAction::SendTo { data, .. } => decrypted_verb(data, &secret).map(|(v, _)| v),
                _ => None,
            })
            .collect()
        };

        assert_eq!(
            verbs_at(&mut node, 2000),
            vec![Verb::NetworkCredentials, Verb::ExtFrame]
        );
        assert_eq!(verbs_at(&mut node, 3000), vec![Verb::ExtFrame]);
        let later = 3000 + ZT_PEER_ACTIVITY_TIMEOUT;
        node.topology
            .get_peer_mut(&peer_address)
            .unwrap()
            .add_path(path, true, later);
        assert_eq!(
            verbs_at(&mut node, later),
            vec![Verb::NetworkCredentials, Verb::ExtFrame]
        );
    }

    /// A frame from a peer we hold no COM for is dropped and answered with
    /// ERROR(NEED_MEMBERSHIP_CERTIFICATE), at most once per second.
    #[test]
    fn frame_without_com_requests_credentials_once_per_second() {
        let network_id = 0xfe00000000abcdef_u64;
        let (mut node, _signing_key, _controller) = make_node_with_com(network_id);
        let sender = test_identity(0x43);
        let sender_address = *sender.address.as_bytes();
        let from: SocketAddr = "10.0.0.12:9993".parse().unwrap();
        let secret = [0x56; 48];
        node.topology.add_peer(sender);
        {
            let peer = node.topology.get_peer_mut(&sender_address).unwrap();
            peer.add_path(from, true, 1000);
            peer.state = PeerState::new_active(secret, 10, 1000, 1000);
        }
        let our_mac = node
            .find_network(network_id)
            .unwrap()
            .our_mac(node.identity.address.as_bytes());
        let ext = ExtFramePayload {
            network_id,
            flags: 0,
            com: None,
            dest_mac: our_mac,
            src_mac: ethernet::derive_mac(&sender_address, network_id),
            ethertype: 0x0800,
            payload: &[0x45, 0, 0, 20],
        };
        let mut buf = [0u8; 128];
        let n = ext.serialize(&mut buf);

        handle_ext_frame(&mut node, &sender_address, &buf[..n], from, 2000, 77);
        let actions = node.drain_actions();
        assert_eq!(actions.len(), 1, "frame must be dropped, got {actions:?}");
        let NodeAction::SendTo { data, address } = &actions[0] else {
            panic!("expected an ERROR, got {actions:?}");
        };
        assert_eq!(*address, from);
        let (verb, body) = decrypted_verb(data, &secret).unwrap();
        assert_eq!(verb, Verb::Error);
        assert_eq!(body[0], Verb::ExtFrame.to_byte());
        assert_eq!(&body[1..9], &77u64.to_be_bytes());
        assert_eq!(body[9], 0x06);
        assert_eq!(&body[10..18], &network_id.to_be_bytes());

        handle_ext_frame(&mut node, &sender_address, &buf[..n], from, 2500, 78);
        assert!(node.drain_actions().is_empty());
        handle_ext_frame(&mut node, &sender_address, &buf[..n], from, 3100, 79);
        assert_eq!(node.drain_actions().len(), 1);
    }

    /// A destination no member owns but a managed route covers goes to the
    /// member that owns that route's gateway, via the most specific route.
    #[test]
    fn routed_destination_is_sent_to_the_gateway_member() {
        use crate::network::Route;

        let network_id = 0xfe00000000abcdef_u64;
        let (mut node, _signing_key, _controller) = make_node_with_com(network_id);
        let our_address = *node.identity.address.as_bytes();
        let gateway_id = test_identity(0x44);
        let gateway_address = *gateway_id.address.as_bytes();
        let path: SocketAddr = "10.0.0.20:9993".parse().unwrap();
        let secret = [0x57; 48];
        node.topology.add_peer(gateway_id);
        {
            let peer = node.topology.get_peer_mut(&gateway_address).unwrap();
            peer.add_path(path, true, 1000);
            peer.state = PeerState::new_active(secret, 10, 1000, 1000);
        }
        let net = node.find_network_mut(network_id).unwrap();
        net.members.push(NetworkMember {
            zt_address: gateway_address,
            mac: ethernet::derive_mac(&gateway_address, network_id),
            ipv4: Some((Ipv4Addr::new(10, 147, 20, 1), 24)),
            ipv6: None,
            authorized: true,
        });
        net.routes = vec![
            Route {
                target: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                prefix: 0,
                via: Some(IpAddr::V4(Ipv4Addr::new(10, 147, 20, 99))),
            },
            Route {
                target: IpAddr::V4(Ipv4Addr::new(192, 168, 50, 0)),
                prefix: 24,
                via: Some(IpAddr::V4(Ipv4Addr::new(10, 147, 20, 1))),
            },
        ];

        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&[192, 168, 50, 9]);
        let actions = process_outbound_frame(
            &mut node,
            network_id,
            ethernet::ETHERTYPE_IPV4,
            &packet,
            &our_address,
            2000,
        );
        let frames: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                NodeAction::SendTo { data, address } => {
                    decrypted_verb(data, &secret).map(|(verb, _)| (verb, *address))
                }
                _ => None,
            })
            .collect();
        assert!(frames.contains(&(Verb::ExtFrame, path)), "got {actions:?}");

        // The default route's gateway is not a known member: refresh.
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
        let actions = process_outbound_frame(
            &mut node,
            network_id,
            ethernet::ETHERTYPE_IPV4,
            &packet,
            &our_address,
            2000,
        );
        assert!(actions
            .iter()
            .any(|action| matches!(action, NodeAction::DestinationUnknown { .. })));
    }

    /// A network with our address in the directory, plus an authenticated
    /// peer holding a valid COM, for address resolution tests.
    fn resolution_env(
        our_v4: Ipv4Addr,
        our_v6: core::net::Ipv6Addr,
    ) -> (Node, u64, [u8; 5], SocketAddr, [u8; 48]) {
        let network_id = 0xfe00000000abcdef_u64;
        let (mut node, signing_key, controller_address) = make_node_with_com(network_id);
        let our_address = *node.identity.address.as_bytes();
        let peer_id = test_identity(0x45);
        let peer_address = *peer_id.address.as_bytes();
        let path: SocketAddr = "10.0.0.30:9993".parse().unwrap();
        let secret = [0x58; 48];
        node.topology.add_peer(peer_id);
        {
            let peer = node.topology.get_peer_mut(&peer_address).unwrap();
            peer.add_path(path, true, 1000);
            peer.state = PeerState::new_active(secret, 10, 1000, 1000);
        }
        add_peer_com(
            &mut node,
            network_id,
            &signing_key,
            &controller_address,
            &peer_address,
        );
        node.find_network_mut(network_id)
            .unwrap()
            .members
            .push(NetworkMember {
                zt_address: our_address,
                mac: ethernet::derive_mac(&our_address, network_id),
                ipv4: Some((our_v4, 24)),
                ipv6: Some((our_v6, 64)),
                authorized: true,
            });
        (node, network_id, peer_address, path, secret)
    }

    fn multicast_frame_bytes(
        network_id: u64,
        mac: [u8; 6],
        adi: u32,
        ethertype: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let frame = MulticastFramePayload {
            network_id,
            flags: 0,
            com: None,
            gather_limit: None,
            source_mac: None,
            dest_mac: mac,
            adi,
            ethertype,
            payload,
        };
        let mut buf = vec![0u8; 64 + payload.len()];
        let n = frame.serialize(&mut buf);
        buf.truncate(n);
        buf
    }

    /// Upstream members find us by ARP: an ARP request for our IPv4 address,
    /// multicast to our resolution group, is answered with a unicast reply
    /// carrying our MAC, and is not handed to the TUN device.
    #[test]
    fn arp_request_for_our_address_is_answered() {
        let our_v4 = Ipv4Addr::new(10, 147, 20, 5);
        let (mut node, network_id, peer, path, secret) =
            resolution_env(our_v4, "fd00::5".parse().unwrap());
        let our_mac = node
            .find_network(network_id)
            .unwrap()
            .our_mac(node.identity.address.as_bytes());
        let peer_mac = ethernet::derive_mac(&peer, network_id);
        let request = arp::ArpPacket {
            hw_type: 1,
            proto_type: 0x0800,
            hw_len: 6,
            proto_len: 4,
            operation: arp::ARP_OP_REQUEST,
            sender_hw: peer_mac,
            sender_proto: [10, 147, 20, 7],
            target_hw: [0; 6],
            target_proto: our_v4.octets(),
        };
        let mut arp_buf = [0u8; 28];
        request.serialize(&mut arp_buf);
        let payload =
            multicast_frame_bytes(network_id, [0xff; 6], u32::from(our_v4), 0x0806, &arp_buf);

        handle_multicast_frame(&mut node, &peer, &payload, path, 2000, 1);
        let actions = node.drain_actions();
        assert!(!actions
            .iter()
            .any(|a| matches!(a, NodeAction::FrameReceived { .. })));
        let reply = actions
            .iter()
            .find_map(|a| match a {
                NodeAction::SendTo { data, address } if *address == path => {
                    decrypted_verb(data, &secret).filter(|(verb, _)| *verb == Verb::ExtFrame)
                }
                _ => None,
            })
            .expect("ARP reply EXT_FRAME");
        let ext = ExtFramePayload::parse(&reply.1).unwrap();
        assert_eq!(ext.dest_mac, peer_mac);
        assert_eq!(ext.src_mac, our_mac);
        assert_eq!(ext.ethertype, 0x0806);
        let answer = arp::ArpPacket::parse(ext.payload).unwrap();
        assert_eq!(answer.operation, arp::ARP_OP_REPLY);
        assert_eq!(answer.sender_hw, our_mac);
        assert_eq!(answer.sender_proto, our_v4.octets());
        assert_eq!(answer.target_proto, [10, 147, 20, 7]);

        // A request for someone else's address is not answered.
        let mut other = request;
        other.target_proto = [10, 147, 20, 8];
        other.serialize(&mut arp_buf);
        let payload = multicast_frame_bytes(network_id, [0xff; 6], 0, 0x0806, &arp_buf);
        handle_multicast_frame(&mut node, &peer, &payload, path, 2100, 2);
        assert!(node.drain_actions().is_empty());
    }

    /// A neighbor solicitation for our IPv6 address is answered with a
    /// solicited, override neighbor advertisement with a valid checksum.
    #[test]
    fn neighbor_solicitation_for_our_address_is_answered() {
        let our_v6: core::net::Ipv6Addr = "fd00::1:2:5".parse().unwrap();
        let (mut node, network_id, peer, path, secret) =
            resolution_env(Ipv4Addr::new(10, 147, 20, 5), our_v6);
        let peer_v6: [u8; 16] = "fd00::1:2:7"
            .parse::<core::net::Ipv6Addr>()
            .unwrap()
            .octets();
        let target = our_v6.octets();
        let mut ns = vec![ndp::ICMPV6_NS, 0, 0, 0, 0, 0, 0, 0];
        ns.extend_from_slice(&target);
        let solicited_node = [
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, target[13], target[14], target[15],
        ];
        let checksum = ndp::icmpv6_checksum(&peer_v6, &solicited_node, &ns);
        ns[2..4].copy_from_slice(&checksum.to_be_bytes());
        let packet = ndp::ipv6_packet(&peer_v6, &solicited_node, 58, 255, &ns);
        let group = [0x33, 0x33, 0xff, target[13], target[14], target[15]];
        let payload = multicast_frame_bytes(network_id, group, 0, 0x86dd, &packet);

        handle_multicast_frame(&mut node, &peer, &payload, path, 2000, 1);
        let actions = node.drain_actions();
        let reply = actions
            .iter()
            .find_map(|a| match a {
                NodeAction::SendTo { data, .. } => {
                    decrypted_verb(data, &secret).filter(|(verb, _)| *verb == Verb::ExtFrame)
                }
                _ => None,
            })
            .expect("NA EXT_FRAME");
        let ext = ExtFramePayload::parse(&reply.1).unwrap();
        assert_eq!(ext.ethertype, 0x86dd);
        let ipv6 = ext.payload;
        assert_eq!(&ipv6[8..24], &target);
        assert_eq!(&ipv6[24..40], &peer_v6);
        assert_eq!(ipv6[7], 255);
        let na = &ipv6[40..];
        assert_eq!(na[0], ndp::ICMPV6_NA);
        assert_eq!(na[4] & 0x60, 0x60, "solicited and override");
        assert_eq!(&na[8..24], &target);
        let mut zeroed = na.to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;
        assert_eq!(
            ndp::icmpv6_checksum(&target, &peer_v6, &zeroed).to_be_bytes(),
            [na[2], na[3]]
        );
    }

    /// Outbound broadcast and multicast go out as MULTICAST_FRAME to the
    /// members subscribed to the group upstream derives for the address,
    /// and broadcast only when the network enables it.
    #[test]
    fn outbound_multicast_and_broadcast_reach_group_subscribers() {
        let network_id = 0xfe00000000abcdef_u64;
        let (mut node, _signing_key, _controller) = make_node_with_com(network_id);
        let our_address = *node.identity.address.as_bytes();
        let peer_id = test_identity(0x46);
        let peer = *peer_id.address.as_bytes();
        let path: SocketAddr = "10.0.0.40:9993".parse().unwrap();
        let secret = [0x59; 48];
        node.topology.add_peer(peer_id);
        {
            let p = node.topology.get_peer_mut(&peer).unwrap();
            p.add_path(path, true, 1000);
            p.state = PeerState::new_active(secret, 10, 1000, 1000);
        }
        let mdns_group = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
        let v6_group = [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb];
        for mac in [mdns_group, [0xff; 6], v6_group] {
            node.multicast_manager
                .subscribe(network_id, mac, 0, peer, 1000);
        }

        let send = |node: &mut Node, ethertype: u16, packet: &[u8]| -> Vec<([u8; 6], u32)> {
            process_outbound_frame(node, network_id, ethertype, packet, &our_address, 2000)
                .iter()
                .filter_map(|action| match action {
                    NodeAction::SendTo { data, address } if *address == path => {
                        decrypted_verb(data, &secret)
                    }
                    _ => None,
                })
                .filter(|(verb, _)| *verb == Verb::MulticastFrame)
                .map(|(_, body)| {
                    let frame = MulticastFramePayload::parse(&body).unwrap();
                    (frame.dest_mac, frame.adi)
                })
                .collect()
        };

        let mut v4 = [0u8; 20];
        v4[0] = 0x45;
        v4[16..20].copy_from_slice(&[224, 0, 0, 251]);
        assert_eq!(send(&mut node, 0x0800, &v4), vec![(mdns_group, 0)]);

        v4[16..20].copy_from_slice(&[255, 255, 255, 255]);
        assert_eq!(send(&mut node, 0x0800, &v4), vec![([0xff; 6], 0)]);
        node.find_network_mut(network_id).unwrap().broadcast_enabled = false;
        assert!(send(&mut node, 0x0800, &v4).is_empty());

        let mut v6 = [0u8; 40];
        v6[0] = 0x60;
        v6[24..40].copy_from_slice(&"ff02::fb".parse::<core::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(send(&mut node, 0x86dd, &v6), vec![(v6_group, 0)]);
    }

    /// An EXT_FRAME carrying the sender's COM inline (flag 0x01) is
    /// accepted without a separate NETWORK_CREDENTIALS.
    #[test]
    fn ext_frame_with_inline_com_is_accepted() {
        let network_id = 0xfe00000000abcdef_u64;
        let (mut node, signing_key, controller_address) = make_node_with_com(network_id);
        let sender = test_identity(0x47);
        let sender_address = *sender.address.as_bytes();
        let from: SocketAddr = "10.0.0.50:9993".parse().unwrap();
        node.topology.add_peer(sender);
        {
            let peer = node.topology.get_peer_mut(&sender_address).unwrap();
            peer.add_path(from, true, 1000);
            peer.state = PeerState::new_active([0x5a; 48], 10, 1000, 1000);
        }
        let com = crate::controller::engine::build_signed_com(
            &signing_key,
            &controller_address,
            network_id,
            crate::controller::engine::zt_address_to_u64(&sender_address),
            1050,
        );
        let our_mac = node
            .find_network(network_id)
            .unwrap()
            .our_mac(node.identity.address.as_bytes());
        let ext = ExtFramePayload {
            network_id,
            flags: 0,
            com: Some(com),
            dest_mac: our_mac,
            src_mac: ethernet::derive_mac(&sender_address, network_id),
            ethertype: 0x0800,
            payload: &[0x45, 0, 0, 20],
        };
        let mut buf = [0u8; 512];
        let n = ext.serialize(&mut buf);

        handle_ext_frame(&mut node, &sender_address, &buf[..n], from, 2000, 1);
        assert!(node
            .drain_actions()
            .iter()
            .any(|a| matches!(a, NodeAction::FrameReceived { .. })));
    }

    /// A MULTICAST_LIKE from a peer without a certificate for the network is
    /// not recorded (ZeroTierOne _doMULTICAST_LIKE gates on membership).
    #[test]
    fn multicast_like_from_a_non_member_is_ignored() {
        let network_id = 0xfe00000000abcdef_u64;
        let (mut node, signing_key, controller) = make_node_with_com(network_id);
        let like = MulticastLikePayload {
            groups: vec![zerotier_protocol::verbs::multicast::MulticastGroup {
                network_id,
                mac: [0xff; 6],
                adi: 0,
            }],
        };
        let mut buf = [0u8; 64];
        let n = like.serialize(&mut buf);
        let stranger = [0x0c; 5];
        handle_multicast_like(&mut node, &stranger, &buf[..n], 1000);
        assert!(node
            .multicast_manager
            .get_subscribers(network_id, &[0xff; 6], 0, 10)
            .is_empty());

        let member = [0x0d; 5];
        add_peer_com(&mut node, network_id, &signing_key, &controller, &member);
        handle_multicast_like(&mut node, &member, &buf[..n], 1000);
        assert_eq!(
            node.multicast_manager
                .get_subscribers(network_id, &[0xff; 6], 0, 10),
            vec![member]
        );
    }

    fn action_rule(rule_type: u8) -> crate::controller::rules::Rule {
        crate::controller::rules::Rule {
            rule_type,
            not_flag: false,
            or_flag: false,
            value: vec![],
        }
    }

    fn address_rule(
        rule_type: u8,
        fields: crate::controller::rules::RuleFields,
    ) -> crate::controller::rules::Rule {
        crate::controller::rules::Rule {
            value: crate::controller::rules::encode_rule_fields(&fields),
            ..action_rule(rule_type)
        }
    }

    /// TEE, WATCH or REDIRECT to `to`, the whole frame.
    fn forward_rule(rule_type: u8, to: &[u8; 5]) -> crate::controller::rules::Rule {
        let fields = crate::controller::rules::RuleFields::Forward {
            address: crate::controller::engine::zt_address_to_u64(to),
            flags: 0,
            length: 0,
        };
        address_rule(rule_type, fields)
    }

    fn network_rules(
        rules: Vec<crate::controller::rules::Rule>,
    ) -> Option<crate::filter::NetworkRules> {
        Some(crate::filter::NetworkRules {
            rules,
            ..Default::default()
        })
    }

    /// An active peer at `path` sharing `secret` with us.
    fn add_reachable_peer(
        node: &mut Node,
        id: Identity,
        path: SocketAddr,
        secret: [u8; 48],
    ) -> [u8; 5] {
        let address = *id.address.as_bytes();
        node.topology.add_peer(id);
        let peer = node.topology.get_peer_mut(&address).unwrap();
        peer.add_path(path, true, 1000);
        peer.state = PeerState::new_active(secret, 10, 1000, 1000);
        address
    }

    /// Where each EXT_FRAME in `actions` went, with its flags and payload.
    fn ext_frames_sent(
        actions: &[NodeAction],
        secret: &[u8; 48],
    ) -> Vec<(SocketAddr, u8, Vec<u8>)> {
        actions
            .iter()
            .filter_map(|action| match action {
                NodeAction::SendTo { data, address } => decrypted_verb(data, secret)
                    .filter(|(verb, _)| *verb == Verb::ExtFrame)
                    .map(|(_, body)| {
                        let ext = ExtFramePayload::parse(&body).unwrap();
                        (*address, ext.flags, ext.payload.to_vec())
                    }),
                _ => None,
            })
            .collect()
    }

    /// The network's rules decide whether a unicast goes out, before our
    /// credentials do; TEE and REDIRECT send the frame to another member
    /// as an EXT_FRAME with upstream's flags. A network without rules (a
    /// static config) filters nothing.
    #[test]
    fn network_rules_gate_outbound_unicast() {
        use crate::controller::rules::{ACTION_ACCEPT, ACTION_DROP, ACTION_REDIRECT, ACTION_TEE};

        let network_id = 0xfe00000000abcdef_u64;
        let (mut node, _signing_key, _controller) = make_node_with_com(network_id);
        let our_address = *node.identity.address.as_bytes();
        let secret = [0x5a; 48];
        let member_path: SocketAddr = "10.0.0.50:9993".parse().unwrap();
        let observer_path: SocketAddr = "10.0.0.51:9993".parse().unwrap();
        let member = add_reachable_peer(&mut node, test_identity(0x50), member_path, secret);
        let observer = add_reachable_peer(&mut node, test_identity(0x51), observer_path, secret);
        node.find_network_mut(network_id)
            .unwrap()
            .members
            .push(NetworkMember {
                zt_address: member,
                mac: ethernet::derive_mac(&member, network_id),
                ipv4: Some((Ipv4Addr::new(10, 147, 20, 2), 24)),
                ipv6: None,
                authorized: true,
            });
        let packet = ipv4_packet_to([10, 147, 20, 2]);
        let send = |node: &mut Node, rules| {
            node.find_network_mut(network_id).unwrap().rules = rules;
            process_outbound_frame(node, network_id, 0x0800, &packet, &our_address, 2000)
        };

        let actions = send(&mut node, network_rules(vec![action_rule(ACTION_DROP)]));
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, NodeAction::SendTo { .. })),
            "a dropped frame sends nothing, credentials included: {actions:?}"
        );
        let actions = send(&mut node, network_rules(vec![]));
        assert!(
            ext_frames_sent(&actions, &secret).is_empty(),
            "no rules match: drop"
        );

        let whole = |path| (path, 0u8, packet.clone());
        let actions = send(&mut node, network_rules(vec![action_rule(ACTION_ACCEPT)]));
        assert_eq!(ext_frames_sent(&actions, &secret), vec![whole(member_path)]);
        let actions = send(&mut node, None);
        assert_eq!(ext_frames_sent(&actions, &secret), vec![whole(member_path)]);

        let tee = vec![
            forward_rule(ACTION_TEE, &observer),
            action_rule(ACTION_ACCEPT),
        ];
        let actions = send(&mut node, network_rules(tee));
        assert_eq!(
            ext_frames_sent(&actions, &secret),
            vec![(observer_path, 0x02, packet.clone()), whole(member_path)]
        );
        let redirect = vec![forward_rule(ACTION_REDIRECT, &observer)];
        let actions = send(&mut node, network_rules(redirect));
        assert_eq!(
            ext_frames_sent(&actions, &secret),
            vec![(observer_path, 0x04, packet.clone())]
        );
    }

    /// Inbound frames meet the same rules before delivery; an inbound TEE
    /// or REDIRECT copy carries upstream's inbound flags.
    #[test]
    fn network_rules_gate_inbound_frames() {
        use crate::controller::rules::{ACTION_ACCEPT, ACTION_DROP, ACTION_REDIRECT, ACTION_TEE};

        let network_id = 0xfe00000000abcdef_u64;
        let (mut node, signing_key, controller) = make_node_with_com(network_id);
        let secret = [0x5b; 48];
        let from: SocketAddr = "10.0.0.52:9993".parse().unwrap();
        let observer_path: SocketAddr = "10.0.0.53:9993".parse().unwrap();
        let sender = add_reachable_peer(&mut node, test_identity(0x52), from, secret);
        let observer = add_reachable_peer(&mut node, test_identity(0x53), observer_path, secret);
        add_peer_com(&mut node, network_id, &signing_key, &controller, &sender);
        let ext = ExtFramePayload {
            network_id,
            flags: 0,
            com: None,
            dest_mac: node
                .find_network(network_id)
                .unwrap()
                .our_mac(node.identity.address.as_bytes()),
            src_mac: ethernet::derive_mac(&sender, network_id),
            ethertype: 0x0800,
            payload: &[0x45, 0, 0, 20],
        };
        let mut buf = [0u8; 256];
        let n = ext.serialize(&mut buf);
        let receive = |node: &mut Node, rules| {
            node.find_network_mut(network_id).unwrap().rules = rules;
            handle_ext_frame(node, &sender, &buf[..n], from, 2000, 1);
            let actions = node.drain_actions();
            let delivered = actions
                .iter()
                .any(|a| matches!(a, NodeAction::FrameReceived { .. }));
            let copies: Vec<_> = ext_frames_sent(&actions, &secret)
                .into_iter()
                .map(|(path, flags, _)| (path, flags))
                .collect();
            (delivered, copies)
        };

        assert_eq!(
            receive(&mut node, network_rules(vec![action_rule(ACTION_DROP)])),
            (false, vec![])
        );
        assert_eq!(
            receive(&mut node, network_rules(vec![action_rule(ACTION_ACCEPT)])),
            (true, vec![])
        );
        let tee = vec![
            forward_rule(ACTION_TEE, &observer),
            action_rule(ACTION_ACCEPT),
        ];
        assert_eq!(
            receive(&mut node, network_rules(tee)),
            (true, vec![(observer_path, 0x08)])
        );
        let redirect = vec![forward_rule(ACTION_REDIRECT, &observer)];
        assert_eq!(
            receive(&mut node, network_rules(redirect)),
            (false, vec![(observer_path, 0x0a)])
        );
    }

    /// A multicast meets the rules once as a whole and again per recipient,
    /// so a rule on the destination address leaves out just that member.
    #[test]
    fn multicast_rules_apply_per_recipient() {
        use crate::controller::rules::{
            RuleFields, ACTION_ACCEPT, ACTION_DROP, MATCH_DEST_ZEROTIER_ADDRESS,
        };

        let network_id = 0xfe00000000abcdef_u64;
        let (mut node, _signing_key, _controller) = make_node_with_com(network_id);
        let our_address = *node.identity.address.as_bytes();
        let secret = [0x5c; 48];
        let kept_path: SocketAddr = "10.0.0.54:9993".parse().unwrap();
        let skipped_path: SocketAddr = "10.0.0.55:9993".parse().unwrap();
        let kept = add_reachable_peer(&mut node, test_identity(0x54), kept_path, secret);
        let skipped = add_reachable_peer(&mut node, test_identity(0x55), skipped_path, secret);
        let group = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
        for member in [kept, skipped] {
            node.multicast_manager
                .subscribe(network_id, group, 0, member, 1000);
        }
        let skipped_u64 = crate::controller::engine::zt_address_to_u64(&skipped);
        node.find_network_mut(network_id).unwrap().rules = network_rules(vec![
            address_rule(
                MATCH_DEST_ZEROTIER_ADDRESS,
                RuleFields::ZtAddress(skipped_u64),
            ),
            action_rule(ACTION_DROP),
            action_rule(ACTION_ACCEPT),
        ]);

        let mut v4 = [0u8; 20];
        v4[0] = 0x45;
        v4[16..20].copy_from_slice(&[224, 0, 0, 251]);
        let actions =
            process_outbound_frame(&mut node, network_id, 0x0800, &v4, &our_address, 2000);
        let frames: Vec<SocketAddr> = actions
            .iter()
            .filter_map(|action| match action {
                NodeAction::SendTo { data, address } => decrypted_verb(data, &secret)
                    .filter(|(verb, _)| *verb == Verb::MulticastFrame)
                    .map(|_| *address),
                _ => None,
            })
            .collect();
        assert_eq!(frames, vec![kept_path]);
    }
}
