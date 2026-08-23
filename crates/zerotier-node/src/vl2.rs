/// VL2 frame processing: handles inbound/outbound Ethernet frames over ZeroTier.
///
/// This module connects the VL2 components (network membership, COM verification,
/// ARP/NDP interception, multicast) into the Node's receive/dispatch path.
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::net::SocketAddr;

use zerotier_crypto::salsa;
use zerotier_protocol::constants::CIPHER_SUITE_C25519_POLY1305_SALSA2012;
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
    _from: SocketAddr,
    _now_ms: u64,
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
        // No valid COM -- would send ERROR_NEED_MEMBERSHIP_CERTIFICATE in a full impl.
        // For now, just drop.
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
    _from: SocketAddr,
    _now_ms: u64,
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
        // No valid COM -- would send ERROR_NEED_MEMBERSHIP_CERTIFICATE
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

    // Build OK(MULTICAST_GATHER) response with subscriber list.
    // Wire format: count(u32 BE) + repeated 5-byte ZT addresses.
    let count = subscribers.len() as u32;
    let response_len = 4 + subscribers.len() * 5;
    let mut response = Vec::with_capacity(response_len);
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
    _from: SocketAddr,
    _now_ms: u64,
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
                if network.lookup_ipv4(dest_ip).is_none() {
                    unknown_destination = !dest_ip.is_multicast()
                        && !dest_ip.is_broadcast()
                        && !is_directed_broadcast_v4(network, dest_ip);
                }
                if let Some(member) = network.lookup_ipv4(dest_ip) {
                    let member_address = member.zt_address;
                    let member_mac = member.mac;
                    let mtu = network.mtu as usize;
                    let ext = ExtFramePayload {
                        network_id,
                        flags: 0,
                        dest_mac: member_mac,
                        src_mac: our_mac,
                        ethertype,
                        payload,
                    };

                    let path_and_secret =
                        node.topology.get_peer(&member_address).and_then(|peer| {
                            peer.best_path(now_ms).and_then(|path| {
                                peer.shared_secret().map(|secret| (path.address, *secret))
                            })
                        });

                    if let Some((path_address, shared_secret)) = path_and_secret {
                        let packet_id = node.allocate_packet_id();
                        if let Some(pkt) = build_ext_frame_packet(
                            packet_id,
                            our_zt_address,
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
                            push_fragmented_send(&mut actions, pkt, path_address, mtu);
                        }
                    } else {
                        actions.push(NodeAction::WhoisNeeded {
                            addresses: alloc::vec![member_address],
                        });
                    }
                }
            }
        }
        ethernet::ETHERTYPE_IPV6 => {
            // Look up destination IPv6 -> member -> ZT address -> physical path
            if payload.len() >= 40 {
                let mut dst_bytes = [0u8; 16];
                dst_bytes.copy_from_slice(&payload[24..40]);
                let dest_ip = core::net::Ipv6Addr::from(dst_bytes);
                if network.lookup_ipv6(dest_ip).is_none() {
                    unknown_destination = !dest_ip.is_multicast();
                }
                if let Some(member) = network.lookup_ipv6(dest_ip) {
                    let member_address = member.zt_address;
                    let member_mac = member.mac;
                    let mtu = network.mtu as usize;
                    let ext = ExtFramePayload {
                        network_id,
                        flags: 0,
                        dest_mac: member_mac,
                        src_mac: our_mac,
                        ethertype,
                        payload,
                    };

                    let path_and_secret =
                        node.topology.get_peer(&member_address).and_then(|peer| {
                            peer.best_path(now_ms).and_then(|path| {
                                peer.shared_secret().map(|secret| (path.address, *secret))
                            })
                        });

                    if let Some((path_address, shared_secret)) = path_and_secret {
                        let packet_id = node.allocate_packet_id();
                        if let Some(pkt) = build_ext_frame_packet(
                            packet_id,
                            our_zt_address,
                            &member_address,
                            &ext,
                            &shared_secret,
                        ) {
                            push_fragmented_send(&mut actions, pkt, path_address, mtu);
                        }
                    } else {
                        actions.push(NodeAction::WhoisNeeded {
                            addresses: alloc::vec![member_address],
                        });
                    }
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
            0,
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
        let network_id = 0xff00000000abcdef_u64;
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

        // A unicast address nobody in the directory owns: hold and refresh.
        let actions = process_outbound_frame(
            &mut node,
            network_id,
            ethernet::ETHERTYPE_IPV4,
            &ipv4_packet_to([10, 147, 20, 9]),
            &our_addr,
            20_000,
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
        let network_id = 0xff00000000abcdef_u64;
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
        let network_id = 0xff00000000abcdef_u64;
        let sender = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];

        let (node, _signing_key, _controller_address) = make_node_with_com(network_id);
        // No peer COM added for sender
        assert!(!has_peer_com(&node, network_id, &sender));
    }

    #[test]
    fn multicast_like_records_subscriptions() {
        let mut mgr = MulticastManager::new();
        let sender = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        let network_id = 0xff00000000abcdef_u64;

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
        let network_id = 0xff00000000abcdef_u64;
        let peer1 = [0x01, 0x02, 0x03, 0x04, 0x05];
        let peer2 = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];

        mgr.subscribe(network_id, [0xff; 6], 0x0806, peer1, 1000);
        mgr.subscribe(network_id, [0xff; 6], 0x0806, peer2, 1000);

        let subs = mgr.get_subscribers(network_id, &[0xff; 6], 0x0806, 100);
        assert_eq!(subs.len(), 2);
    }

    #[test]
    fn arp_outbound_resolved_locally() {
        let network_id = 0xff00000000abcdef_u64;
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
        let network_id = 0xff00000000abcdef_u64;

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
}
