//! GET/POST/DELETE /network handlers.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;

use super::{types::NetworkResponse, AppState};

/// Format a MAC address as "aa:bb:cc:dd:ee:ff".
fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Build a NetworkResponse from a NetworkMembership and our address.
fn membership_to_response(
    net: &zerotier_node::network::NetworkMembership,
    our_addr: &[u8; 5],
    port_device_name: String,
) -> NetworkResponse {
    // Collect assigned addresses from members matching our address.
    // Dynamic controller-delivered assignments are tracked directly on the
    // membership, so include those as the source of truth for live joins.
    let mut assigned = Vec::new();
    if let Some(member) = net.members.iter().find(|m| m.zt_address == *our_addr) {
        if let Some((ip, prefix)) = &member.ipv4 {
            assigned.push(format!("{}/{}", ip, prefix));
        }
        if let Some((ip, prefix)) = &member.ipv6 {
            assigned.push(format!("{}/{}", ip, prefix));
        }
    }
    if let Some(ip) = net.assigned_ipv4 {
        let ip = format!("{}/32", ip);
        if !assigned.contains(&ip) {
            assigned.push(ip);
        }
    }
    if let Some(ip) = net.assigned_ipv6 {
        let ip = format!("{}/128", ip);
        if !assigned.contains(&ip) {
            assigned.push(ip);
        }
    }

    let mac = zerotier_node::ethernet::derive_mac(our_addr, net.network_id);
    let status = if net.our_com.is_some() {
        "OK"
    } else {
        "REQUESTING_CONFIGURATION"
    };

    NetworkResponse {
        id: format!("{:016x}", net.network_id),
        name: String::new(), // Network name not stored in membership yet
        status: status.to_string(),
        assigned_addresses: assigned,
        mac: format_mac(&mac),
        mtu: net.mtu,
        port_device_name,
    }
}

/// The TUN interface name the service recorded for `network_id`, if any.
fn port_device_name(state: &AppState, network_id: u64) -> String {
    state
        .tun_names
        .lock()
        .ok()
        .and_then(|names| names.get(&network_id).cloned())
        .unwrap_or_default()
}

/// List all joined networks.
pub async fn list_networks(State(state): State<Arc<AppState>>) -> Json<Vec<NetworkResponse>> {
    let node = state.node.lock().await;
    let our_addr = node.identity.address.as_bytes();

    let networks: Vec<NetworkResponse> = node
        .networks
        .iter()
        .map(|net| {
            let device = port_device_name(&state, net.network_id);
            membership_to_response(net, our_addr, device)
        })
        .collect();

    Json(networks)
}

/// Join a network by ID (16-char hex).
pub async fn join_network(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<NetworkResponse>, StatusCode> {
    let network_id = u64::from_str_radix(&id, 16).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut node = state.node.lock().await;
    let our_addr = *node.identity.address.as_bytes();

    if let Some(existing) = node.find_network_mut(network_id) {
        existing.our_com = None;
        existing.peer_coms.clear();
        existing.members.clear();
        existing.pending_config_request = true;
        existing.last_config_request = 0;
        let device = port_device_name(&state, network_id);
        return Ok(Json(membership_to_response(existing, &our_addr, device)));
    }

    // Create empty membership -- config will come from controller
    let membership = zerotier_node::network::NetworkMembership::new(network_id, 2800);
    node.join_network(membership);

    let mac = zerotier_node::ethernet::derive_mac(&our_addr, network_id);

    Ok(Json(NetworkResponse {
        id: format!("{:016x}", network_id),
        name: String::new(),
        status: "REQUESTING_CONFIGURATION".to_string(),
        assigned_addresses: vec![],
        mac: format_mac(&mac),
        mtu: 2800,
        port_device_name: String::new(),
    }))
}

/// Leave a network by ID (16-char hex).
pub async fn leave_network(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let network_id = u64::from_str_radix(&id, 16).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut node = state.node.lock().await;
    node.networks.retain(|n| n.network_id != network_id);
    Ok(StatusCode::OK)
}
