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
        // Re-request the config; keep certificates and members until it lands.
        existing.pending_config_request = true;
        existing.last_config_request = 0;
        let device = port_device_name(&state, network_id);
        return Ok(Json(membership_to_response(existing, &our_addr, device)));
    }

    // Create empty membership -- config will come from controller
    let membership =
        zerotier_node::network::NetworkMembership::new(network_id, DEFAULT_NETWORK_MTU);
    node.join_network(membership);
    remember_network(&state.data_dir, network_id);

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
    forget_network(&state.data_dir, network_id);
    Ok(StatusCode::OK)
}

/// MTU used for a membership until the controller's config replaces it.
pub const DEFAULT_NETWORK_MTU: u16 = 2800;

/// Directory of join markers, one empty `<network-id>.conf` per joined
/// network, the same layout official ZeroTier keeps so a restart re-joins
/// everything the node was on. The file contents are not read.
fn networks_dir(data_dir: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(data_dir).join("networks.d")
}

fn network_marker_path(data_dir: &str, network_id: u64) -> std::path::PathBuf {
    networks_dir(data_dir).join(format!("{:016x}.conf", network_id))
}

/// Record `network_id` in `networks.d` so the service re-joins it after a
/// restart. Failure is logged, not returned: the in-memory join succeeded and
/// the node keeps working until the next restart.
fn remember_network(data_dir: &str, network_id: u64) {
    let dir = networks_dir(data_dir);
    let path = network_marker_path(data_dir, network_id);
    if let Err(error) = std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&path, b"")) {
        tracing::warn!(
            network_id = %format!("{:016x}", network_id),
            path = %path.display(),
            error = %error,
            "could not remember joined network; it will not be re-joined after a restart"
        );
    }
}

fn forget_network(data_dir: &str, network_id: u64) {
    let path = network_marker_path(data_dir, network_id);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(
            network_id = %format!("{:016x}", network_id),
            path = %path.display(),
            error = %error,
            "could not remove join marker; the network will be re-joined after a restart"
        ),
    }
}

/// Network IDs remembered in `networks.d`, sorted, ignoring files that are
/// not `<16 hex digits>.conf`.
pub fn remembered_networks(data_dir: &str) -> Vec<u64> {
    let Ok(entries) = std::fs::read_dir(networks_dir(data_dir)) else {
        return Vec::new();
    };
    let mut ids: Vec<u64> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let stem = name.strip_suffix(".conf")?;
            if stem.len() != 16 {
                return None;
            }
            u64::from_str_radix(stem, 16).ok()
        })
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::Mutex;
    use zerotier_crypto::identity::{Address, Identity, PublicKey};
    use zerotier_node::network::NetworkMember;
    use zerotier_node::node::Node;
    use zerotier_protocol::world::DEFAULT_PLANET;

    fn test_identity() -> Identity {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0x11]).unwrap();
        let mut pk_bytes = [0u8; 64];
        for (i, b) in pk_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x11);
        }
        Identity {
            address,
            public_key: PublicKey::from_bytes(&pk_bytes).unwrap(),
            secret: None,
        }
    }

    fn app_state() -> Arc<AppState> {
        let node = Node::new(test_identity(), DEFAULT_PLANET, 1).expect("node");
        // Join writes networks.d markers under data_dir.
        let data_dir = std::env::temp_dir().join(format!(
            "manytier-network-api-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&data_dir).expect("temp data dir");
        Arc::new(AppState {
            node: Arc::new(Mutex::new(node)),
            auth_token: "test-token".to_string(),
            controller: None,
            data_dir: data_dir.to_string_lossy().to_string(),
            tun_names: Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    #[tokio::test]
    async fn rejoining_requests_fresh_config_without_dropping_membership_state() {
        const NETWORK_ID: u64 = 0xa0b1c2d3e4000001;
        let state = app_state();
        let id = format!("{NETWORK_ID:016x}");

        let first = join_network(State(Arc::clone(&state)), Path(id.clone()))
            .await
            .expect("first join");
        assert_eq!(first.0.status, "REQUESTING_CONFIGURATION");
        {
            let mut node = state.node.lock().await;
            let net = node.find_network_mut(NETWORK_ID).expect("joined network");
            net.members.push(NetworkMember {
                zt_address: [1, 2, 3, 4, 5],
                mac: [0; 6],
                ipv4: None,
                ipv6: None,
                authorized: true,
            });
            net.pending_config_request = false;
            net.last_config_request = 42;
        }

        let rejoined = join_network(State(Arc::clone(&state)), Path(id))
            .await
            .expect("rejoin");
        assert_eq!(rejoined.0.id, format!("{NETWORK_ID:016x}"));

        let node = state.node.lock().await;
        let net = node.find_network(NETWORK_ID).expect("network still joined");
        assert_eq!(
            net.members.len(),
            1,
            "re-joining must keep the member directory until the new config lands"
        );
        assert!(
            net.pending_config_request,
            "re-joining must request a fresh config"
        );
        assert_eq!(
            net.last_config_request, 0,
            "the request must not be rate limited"
        );
    }

    #[test]
    fn join_markers_round_trip_through_networks_d() {
        let dir = std::env::temp_dir().join(format!(
            "manytier-networks-d-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let data_dir = dir.to_str().unwrap().to_string();
        assert!(remembered_networks(&data_dir).is_empty());

        remember_network(&data_dir, 0x2105b78c5f78ff8e);
        remember_network(&data_dir, 0x1111111111111111);
        remember_network(&data_dir, 0x2105b78c5f78ff8e);
        std::fs::write(dir.join("networks.d").join("junk.txt"), b"x").unwrap();
        std::fs::write(dir.join("networks.d").join("abc.conf"), b"x").unwrap();
        assert_eq!(
            remembered_networks(&data_dir),
            vec![0x1111111111111111, 0x2105b78c5f78ff8e]
        );

        forget_network(&data_dir, 0x1111111111111111);
        forget_network(&data_dir, 0x1111111111111111);
        assert_eq!(remembered_networks(&data_dir), vec![0x2105b78c5f78ff8e]);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
