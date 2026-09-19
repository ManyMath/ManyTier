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
    let dest_mac = network.our_mac(node.identity.address.as_bytes());

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

    let limit = gather.gather_limit as usize;
    let subscribers =
        node.multicast_manager
            .get_subscribers(gather.network_id, &gather.mac, gather.adi, limit);

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
        .len() as u32;
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
            // Not resolved locally -- send as multicast to ARP group
            // Build EXT_FRAME to broadcast MAC
            let dest_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
            let ext = ExtFramePayload {
                network_id,
                flags: 0,
                dest_mac,
                src_mac: our_mac,
                ethertype,
                payload,
            };
            let mut buf = [0u8; 2048];
            let n = ext.serialize(&mut buf);
            // For multicast, we'd need to send to all known subscribers.
            // For now, build a single SendTo action (the transport layer
            // would need to handle multicast distribution).
            let targets = node.multicast_manager.get_replication_targets(
                network_id,
                &dest_mac,
                ethernet::ETHERTYPE_ARP as u32,
                our_zt_address,
                64,
            );
            for target_addr in &targets {
                // We'd need to look up the target's physical address from topology.
                // For now, push the frame data -- the caller resolves physical addresses.
                if let Some(peer) = node.topology.get_peer(target_addr) {
                    if let Some(path) = peer.best_path(now_ms) {
                        actions.push(NodeAction::SendTo {
                            data: buf[..n].to_vec(),
                            address: path.address,
                        });
                    }
                }
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
                            unknown_destination = !dest_ip.is_multicast()
                                && !dest_ip.is_broadcast()
                                && !is_directed_broadcast_v4(network, dest_ip);
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
                        None => unknown_destination = !dest_ip.is_multicast(),
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

/// Send `payload` to one member as an EXT_FRAME. Our credentials go first
/// when the member has not had them recently, as ZeroTier One does before
/// every unicast (node/Switch.cpp `pushCredentialsIfNeeded`): a peer that
/// lacks our COM drops the frame.
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
    let path_and_secret = node.topology.get_peer(&member_address).and_then(|peer| {
        peer.best_path(now_ms)
            .and_then(|path| peer.shared_secret().map(|secret| (path.address, *secret)))
    });
    let Some((path_address, shared_secret)) = path_and_secret else {
        actions.push(NodeAction::WhoisNeeded {
            addresses: alloc::vec![member_address],
        });
        return;
    };
    if let Some(push) = node.credentials_if_needed(network_id, &member_address, now_ms) {
        actions.push(push);
    }
    let our_zt_address = *node.identity.address.as_bytes();
    let ext = ExtFramePayload {
        network_id,
        flags: 0,
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
            dest_mac: our_mac,
            src_mac: sender_mac,
            ethertype: 0x0800,
            payload: &[0xDE, 0xAD],
        };
        let mut buf = [0u8; 256];
        let n = ext.serialize(&mut buf);

        // Test the has_peer_com helper and parsing logic directly.
        let (mut node, signing_key, controller_address) = make_node_with_com(network_id);
        add_peer_com(
            &mut node,
            network_id,
            &signing_key,
            &controller_address,
            &sender,
        );

        // Verify COM check works
        assert!(has_peer_com(&node, network_id, &sender));

        // Verify parsing works
        let parsed = ExtFramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.network_id, network_id);
        assert_eq!(parsed.payload, &[0xDE, 0xAD]);
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
        let (mut node, _signing_key, _controller) = make_node_with_com(network_id);
        let sender = test_identity(0x33);
        let sender_addr = *sender.address.as_bytes();
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
}
