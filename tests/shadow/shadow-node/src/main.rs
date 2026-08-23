//! Shadow test binary for ManyTier protocol simulation.
//!
//! Purpose-built for Shadow network simulation:
//! - No TUN/TAP, no CLI overhead
//! - Drives the Node engine with real UDP transport
//! - Uses JSON tracing for structured log validation
//!
//! Usage:
//!   shadow-node --role root --identity root.identity --port 9993
//!   shadow-node --role peer --identity peer1.identity --planet planet.bin --port 9993
//!   shadow-node --role vl2-peer --identity peer1.identity --planet planet.bin \
//!               --network-config net.json --peer-ip 10.147.20.2 --port 9993
//!   shadow-node --role vl2-controller --identity ctrl.identity --planet planet.bin \
//!               --network-config net-controller.json --port 9993
//!   shadow-node --role controller --identity ctrl.identity --planet planet.bin \
//!               --port 9993 --peer-count 10

use clap::Parser;
use std::net::SocketAddr;
use tracing_subscriber::fmt::format::FmtSpan;
use zerotier_node::controller::storage::ControllerStorage;
use zerotier_node::node::{Node, NodeAction};
use zerotier_node::traits::Transport;
use zerotier_protocol::constants::ZT_PING_CHECK_INTERVAL;

#[derive(Parser)]
#[command(name = "shadow-node", about = "ManyTier Shadow test node")]
struct Args {
    /// Node role: "root", "peer", "vl2-peer", "vl2-controller", "controller", or "dynamic-peer"
    #[arg(long)]
    role: String,

    /// Path to identity file (generated if missing)
    #[arg(long)]
    identity: String,

    /// Root server address (for peers)
    #[arg(long)]
    root_addr: Option<String>,

    /// UDP port to bind
    #[arg(long, default_value = "9993")]
    port: u16,

    /// Path to planet file (binary)
    #[arg(long)]
    planet: Option<String>,

    /// Path to static network config JSON (for vl2-peer role)
    #[arg(long)]
    network_config: Option<String>,

    /// Target peer IP for VL2 ping (for vl2-peer role)
    #[arg(long)]
    peer_ip: Option<String>,

    /// ICMP payload size for VL2 ping generation
    #[arg(long, default_value = "16")]
    ping_payload_bytes: usize,

    /// Expected number of peers (for controller role)
    #[arg(long)]
    peer_count: Option<u32>,

    /// Advertised network MTU (for controller role)
    #[arg(long)]
    mtu: Option<u16>,

    /// Network ID to join (hex, for vl2-peer in dynamic mode)
    #[arg(long)]
    network_id: Option<String>,

    /// Target IP for VL2 ping (for vl2-peer in dynamic mode, alternative to --peer-ip)
    #[arg(long)]
    target_ip: Option<String>,
}

#[allow(dead_code)]
#[path = "../../../../tests/fixtures/gen_test_config.rs"]
mod gen_test_config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize JSON tracing subscriber (structured tracing with JSON output)
    tracing_subscriber::fmt()
        .json()
        .with_target(true)
        .with_span_events(FmtSpan::CLOSE)
        .with_max_level(tracing::Level::INFO)
        .init();

    let args = Args::parse();

    // Load or generate identity
    let identity = if std::path::Path::new(&args.identity).exists() {
        let id_str = std::fs::read_to_string(&args.identity)?;
        zerotier_crypto::identity::Identity::parse(id_str.trim())
            .map_err(|e| anyhow::anyhow!("failed to parse identity: {e}"))?
    } else {
        // Use getrandom-backed RNG to avoid rand_core 0.6/0.9 version conflicts
        // (dalek crates pull rand_core 0.6 transitively)
        let mut rng = GetrandomRng;
        let identity = zerotier_crypto::identity::Identity::generate(&mut rng)
            .map_err(|e| anyhow::anyhow!("failed to generate identity: {e}"))?;
        // to_secret_string returns Option<String> -- unwrap since we just generated it
        std::fs::write(&args.identity, identity.to_secret_string().unwrap())?;
        identity
    };

    tracing::info!(
        address = %identity.address.to_hex(),
        role = %args.role,
        event = "node_starting",
        "node starting"
    );

    // Load planet data
    let planet_data = if let Some(planet_path) = &args.planet {
        std::fs::read(planet_path)?
    } else {
        build_test_planet(&identity, &args)?
    };

    let our_zt_address = *identity.address.as_bytes();
    let initial_packet_id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        & 0x0000_FFFF_FFFF_FFFF) as u64;
    let mut node = Node::new(identity, &planet_data, initial_packet_id)
        .map_err(|e| anyhow::anyhow!("failed to create node: {e}"))?;

    // VL2 controller setup: join network and prepare to respond to NETWORK_CONFIG_REQUEST
    let controller_state = if args.role == "vl2-controller" {
        let config_path = args
            .network_config
            .as_ref()
            .expect("vl2-controller requires --network-config");
        let config_json = std::fs::read(config_path)?;
        let static_config = zerotier_node::network_config::load_from_json(&config_json)
            .map_err(|e| anyhow::anyhow!("config error: {}", e))?;
        let network_id = u64::from_str_radix(&static_config.network_id, 16)
            .map_err(|e| anyhow::anyhow!("invalid network_id: {}", e))?;

        // Join the network ourselves so peers can exchange frames with us
        let membership = zerotier_node::network::NetworkMembership::from_static_config(
            &static_config,
            &our_zt_address,
        )
        .map_err(|e| anyhow::anyhow!("config error: {}", e))?;
        node.join_network(membership);

        // Extract the controller signing key from node's identity secret
        let signing_key = node
            .identity
            .secret
            .as_ref()
            .expect("controller needs secret identity")
            .signing
            .clone();

        tracing::info!(
            network_id = %format!("{:016x}", network_id),
            event = "controller_started",
            "VL2 controller started"
        );

        Some(ControllerState {
            network_id,
            static_config_json: config_json,
            signing_key,
        })
    } else {
        None
    };

    // Dynamic controller setup: uses Controller engine with InMemoryStorage
    let dynamic_controller_state = if args.role == "controller" {
        let expected_peers = args.peer_count.unwrap_or(10);

        // Extract the controller signing key from node's identity secret
        let signing_key = node
            .identity
            .secret
            .as_ref()
            .expect("controller needs secret identity")
            .signing
            .clone();

        // Create Controller engine with InMemoryStorage
        let storage = zerotier_service::storage::InMemoryStorage::new();
        let controller = zerotier_node::controller::engine::Controller::new(
            our_zt_address,
            signing_key.clone(),
            storage,
        );

        // Create a public network (auto-authorize all peers)
        let random_suffix: u32 = 0x000001; // Deterministic for testing
        let network_id = controller
            .create_network(random_suffix, now_ms())
            .await
            .expect("failed to create network");

        // Make it public so peers are auto-authorized
        {
            let mut net = controller
                .storage
                .get_network(network_id)
                .await
                .unwrap()
                .unwrap();
            net.private = false;
            if let Some(mtu) = args.mtu {
                net.mtu = mtu;
            }
            controller.storage.update_network(&net).await.unwrap();
        }

        // Set up IP pool: 192.168.200.1 - 192.168.200.254
        controller
            .storage
            .set_ip_pools(
                network_id,
                &[zerotier_node::controller::types::IpPool {
                    range_start: [192, 168, 200, 1],
                    range_end: [192, 168, 200, 254],
                }],
            )
            .await
            .unwrap();

        tracing::info!(
            network_id = %format!("{:016x}", network_id),
            mtu = args.mtu.unwrap_or(2800),
            expected_peers = expected_peers,
            event = "controller_started",
            "Dynamic controller started with public network"
        );

        Some(DynamicControllerState {
            controller,
            network_id,
            expected_peers,
            peers_joined: std::collections::HashSet::new(),
            signing_key,
        })
    } else {
        None
    };

    // VL2 peer setup: join network from static config
    let vl2_state = if args.role == "vl2-peer" {
        let config_path = args
            .network_config
            .as_ref()
            .expect("vl2-peer requires --network-config");
        let peer_ip_str = args.peer_ip.as_ref().expect("vl2-peer requires --peer-ip");
        let peer_ip: std::net::Ipv4Addr = peer_ip_str.parse().expect("invalid --peer-ip address");

        let config_json = std::fs::read(config_path)?;
        let static_config = zerotier_node::network_config::load_from_json(&config_json)
            .map_err(|e| anyhow::anyhow!("config error: {}", e))?;
        let network_id = u64::from_str_radix(&static_config.network_id, 16)
            .map_err(|e| anyhow::anyhow!("invalid network_id: {}", e))?;

        let membership = zerotier_node::network::NetworkMembership::from_static_config(
            &static_config,
            &our_zt_address,
        )
        .map_err(|e| anyhow::anyhow!("config error: {}", e))?;
        node.join_network(membership);

        tracing::info!(
            network_id = %format!("{:016x}", network_id),
            peer_ip = %peer_ip,
            event = "vl2_network_joined",
            "joined VL2 network"
        );

        tracing::info!(
            network_id = %format!("{:016x}", network_id),
            event = "peer_config_received",
            "peer received network configuration"
        );

        tracing::info!(
            network_id = %format!("{:016x}", network_id),
            event = "peer_online",
            "peer is online and operational"
        );

        Some(Vl2PeerState {
            network_id,
            target_ip: peer_ip,
            ping_payload_bytes: args.ping_payload_bytes,
            ping_sent: false,
            ping_received: false,
        })
    } else if args.role == "dynamic-peer" {
        // Dynamic peer: join network by ID, receive config from controller dynamically
        let network_id_hex = args
            .network_id
            .as_ref()
            .expect("dynamic-peer requires --network-id");
        let network_id =
            u64::from_str_radix(network_id_hex, 16).expect("invalid --network-id hex string");
        let peer_ip_str = args
            .peer_ip
            .as_ref()
            .or(args.target_ip.as_ref())
            .expect("dynamic-peer requires --peer-ip or --target-ip");
        let peer_ip: std::net::Ipv4Addr = peer_ip_str.parse().expect("invalid --peer-ip address");

        // Join with empty membership (no static config) -- tick() will send
        // NETWORK_CONFIG_REQUEST and the controller's NETWORK_CONFIG/NETWORK_CREDENTIALS
        // response will populate the membership dynamically.
        let membership = zerotier_node::network::NetworkMembership::new(network_id, 2800);
        node.join_network(membership);

        tracing::info!(
            network_id = %format!("{:016x}", network_id),
            peer_ip = %peer_ip,
            event = "dynamic_peer_joined",
            "dynamic peer joined network (awaiting config from controller)"
        );

        Some(Vl2PeerState {
            network_id,
            target_ip: peer_ip,
            ping_payload_bytes: args.ping_payload_bytes,
            ping_sent: false,
            ping_received: false,
        })
    } else {
        None
    };

    // Bind UDP transport
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let transport = zerotier_service::NativeTransport::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind UDP: {}", e))?;

    tracing::info!(
        addr = %transport.local_addr().unwrap(),
        event = "transport_bound",
        "transport bound"
    );

    // Execute bootstrap actions (sends initial HELLO to roots)
    let bootstrap_actions = node.bootstrap(now_ms());
    execute_actions(&transport, &bootstrap_actions).await;

    // Main event loop
    let mut buf = [0u8; 4096];
    let mut tick_interval =
        tokio::time::interval(std::time::Duration::from_millis(ZT_PING_CHECK_INTERVAL));

    // VL2 peer state (mutable in loop)
    let mut vl2 = vl2_state;
    // Dynamic controller state (mutable in loop)
    let mut dyn_ctrl = dynamic_controller_state;
    // Track ticks for VL2 ping timing
    let mut tick_count: u64 = 0;

    loop {
        tokio::select! {
            result = transport.recv_from(&mut buf) => {
                match result {
                    Ok((n, from)) => {
                        let actions = node.receive_packet(&mut buf[..n], from, now_ms());
                        // Check for dynamic config receipt (dynamic-peer role)
                        if args.role == "dynamic-peer" {
                            for action in &actions {
                                if let NodeAction::NetworkConfigured { network_id, .. } = action {
                                    tracing::info!(
                                        target: "manytier",
                                        event = "dynamic_config_received",
                                        network_id = %format!("{:016x}", network_id),
                                        "received dynamic network configuration from controller"
                                    );
                                }
                            }
                        }
                        // Check for VL2 frame events before executing
                        if let Some(ref mut state) = vl2 {
                            handle_vl2_actions(&actions, state, &mut node, &our_zt_address);
                        }
                        // Handle static controller actions (NETWORK_CONFIG_REQUEST)
                        if let Some(ref ctrl) = controller_state {
                            handle_controller_actions(
                                &actions, ctrl, &mut node,
                                &our_zt_address,
                            );
                        }
                        // Handle dynamic controller actions (NETWORK_CONFIG_REQUEST)
                        if let Some(ref mut dc) = dyn_ctrl {
                            handle_dynamic_controller_actions(
                                &actions, dc, &mut node,
                                &our_zt_address,
                            ).await;
                        }
                        execute_actions(&transport, &actions).await;
                        // Execute any new actions generated by VL2 or controller handling
                        if vl2.is_some() || controller_state.is_some() || dyn_ctrl.is_some() {
                            let pending = node.drain_actions();
                            execute_actions(&transport, &pending).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, event = "recv_error", "UDP recv error");
                    }
                }
            }
            _ = tick_interval.tick() => {
                let actions = node.tick(now_ms());
                execute_actions(&transport, &actions).await;

                tick_count += 1;

                // VL2: try sending ping every tick until received
                if let Some(ref mut state) = vl2 {
                    if !state.ping_received && tick_count >= 3 {
                        try_send_ping(state, &mut node, &our_zt_address, &transport).await;
                    }
                }
            }
        }
    }
}

/// VL2 peer state for ping test.
struct Vl2PeerState {
    network_id: u64,
    target_ip: std::net::Ipv4Addr,
    ping_payload_bytes: usize,
    ping_sent: bool,
    ping_received: bool,
}

/// VL2 controller state for interop test.
///
/// Responds to NETWORK_CONFIG_REQUEST with NETWORK_CONFIG + NETWORK_CREDENTIALS.
struct ControllerState {
    network_id: u64,
    /// Raw JSON bytes of the static config (used to build responses).
    static_config_json: Vec<u8>,
    /// Ed25519 signing key for signing COMs.
    signing_key: ed25519_dalek::SigningKey,
}

/// Dynamic controller state using Controller engine with InMemoryStorage.
///
/// Used by the `controller` role for planet simulation. Auto-authorizes peers
/// and assigns IPs dynamically from a pool.
#[allow(dead_code)]
struct DynamicControllerState {
    controller:
        zerotier_node::controller::engine::Controller<zerotier_service::storage::InMemoryStorage>,
    network_id: u64,
    expected_peers: u32,
    peers_joined: std::collections::HashSet<[u8; 5]>,
    signing_key: ed25519_dalek::SigningKey,
}

/// Handle VL2-specific actions from received packets.
///
/// Checks for FrameReceived with ICMP echo request (respond with reply)
/// or ICMP echo reply (log vl2_ping_success).
fn handle_vl2_actions(
    actions: &[NodeAction],
    state: &mut Vl2PeerState,
    node: &mut Node,
    our_zt_address: &[u8; 5],
) {
    for action in actions {
        if let NodeAction::FrameReceived {
            network_id,
            ethertype,
            payload,
            ..
        } = action
        {
            if *network_id != state.network_id || *ethertype != 0x0800 {
                continue;
            }
            // Parse minimal IPv4 header
            if payload.len() < 20 {
                continue;
            }
            let protocol = payload[9];
            if protocol != 1 {
                // Not ICMP
                continue;
            }
            let ihl = (payload[0] & 0x0f) as usize * 4;
            if payload.len() < ihl + 8 {
                continue;
            }
            let icmp_type = payload[ihl];
            let icmp_code = payload[ihl + 1];

            if icmp_type == 0 && icmp_code == 0 {
                // ICMP echo reply received -- ping success!
                if !state.ping_received {
                    state.ping_received = true;
                    tracing::info!(
                        network_id = %format!("{:016x}", state.network_id),
                        event = "vl2_ping_success",
                        "VL2 ping success: received ICMP echo reply"
                    );
                }
            } else if icmp_type == 8 && icmp_code == 0 {
                // ICMP echo request -- build and send reply
                tracing::info!(
                    event = "vl2_echo_request_received",
                    "received ICMP echo request, sending reply"
                );

                // Build echo reply from the request
                let reply_payload = build_icmp_echo_reply(payload, ihl);
                if let Some(reply) = reply_payload {
                    // Inject reply as outbound frame
                    let out_actions = zerotier_node::vl2::process_outbound_frame(
                        node,
                        state.network_id,
                        0x0800,
                        &reply,
                        our_zt_address,
                        now_ms(),
                    );
                    for a in out_actions {
                        node.push_action(a);
                    }
                }
            }
        }
    }
}

/// Handle controller-specific actions from received packets.
///
/// When a NETWORK_CONFIG_REQUEST is received, builds a NETWORK_CONFIG response
/// and NETWORK_CREDENTIALS with signed COM for the requesting member.
fn handle_controller_actions(
    actions: &[NodeAction],
    ctrl: &ControllerState,
    node: &mut Node,
    our_zt_address: &[u8; 5],
) {
    use zerotier_protocol::verbs::network_config::{
        NetworkConfigPayload, NetworkCredentialsPayload,
    };

    // Clone identity public info needed for packet building (avoids borrow conflict)
    let our_public_key = node.identity.public_key.clone();
    // Build a public-only identity for packet construction
    let our_identity_for_packets = zerotier_crypto::identity::Identity {
        address: node.identity.address,
        public_key: our_public_key,
        secret: None,
    };

    for action in actions {
        if let NodeAction::NetworkConfigRequested {
            requester_address,
            network_id,
            from,
            ..
        } = action
        {
            if *network_id != ctrl.network_id {
                tracing::warn!(
                    event = "config_request_wrong_network",
                    requested = %format!("{:016x}", network_id),
                    expected = %format!("{:016x}", ctrl.network_id),
                    "NETWORK_CONFIG_REQUEST for unknown network"
                );
                continue;
            }

            tracing::info!(
                event = "network_config_request_received",
                requester = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                    requester_address[0], requester_address[1], requester_address[2],
                    requester_address[3], requester_address[4]),
                network_id = %format!("{:016x}", network_id),
                "received NETWORK_CONFIG_REQUEST"
            );

            // Load static config to get member info
            let static_config = match zerotier_node::network_config::load_from_json(
                &ctrl.static_config_json,
            ) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(event = "config_parse_error", error = %e, "failed to parse static config");
                    continue;
                }
            };

            // Build NetworkConfig dictionary response
            // ZeroTier text dictionary format: key=value pairs separated by newlines
            let requester_addr_u64 = zt_address_to_u64(requester_address);

            // Find the requester in our member list to get their IP assignment
            let requester_member = static_config.members.iter().find(|m| {
                let addr = parse_hex_address_safe(&m.address);
                addr.map(|a| a == *requester_address).unwrap_or(false)
            });

            let ip_assignments = if let Some(member) = requester_member {
                let mut ips = Vec::new();
                if let Some(ref ipv4) = member.ipv4 {
                    ips.push(ipv4.clone());
                }
                if let Some(ref ipv6) = member.ipv6 {
                    ips.push(ipv6.clone());
                }
                serde_json::to_string(&ips).unwrap_or_else(|_| "[]".to_string())
            } else {
                "[]".to_string()
            };

            let now_ms_val = now_ms();
            let dict = format!(
                "nwid={:016x}\nn=manytier-test\nt={}\nv=1\nmtu={}\nmulticastLimit=32\ntype=1\nipAssignments={}\n",
                network_id, now_ms_val, static_config.mtu, ip_assignments,
            );
            let dict_bytes = dict.as_bytes().to_vec();

            // Build NETWORK_CONFIG payload
            let nc_payload = NetworkConfigPayload {
                network_id: *network_id,
                dict_data: dict_bytes,
                flags: None,
                config_update_id: None,
                total_length: None,
                chunk_index: None,
                signature_type: None,
                signature: None,
            };

            // Extract shared secret before mutable borrow of node
            let shared_secret = node
                .topology
                .get_peer(requester_address)
                .and_then(|peer| peer.shared_secret().copied());

            if let Some(ref shared_secret) = shared_secret {
                // Build and send NETWORK_CONFIG packet
                let mut pkt_buf = [0u8; 2048];
                let nc_len = build_verb_packet(
                    &our_identity_for_packets,
                    requester_address,
                    zerotier_protocol::verb::Verb::NetworkConfig,
                    shared_secret,
                    now_ms_val,
                    &nc_payload,
                    &mut pkt_buf,
                );
                if let Some(len) = nc_len {
                    node.push_action(NodeAction::SendTo {
                        data: pkt_buf[..len].to_vec(),
                        address: *from,
                    });

                    tracing::info!(
                        event = "network_config_sent",
                        requester = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                            requester_address[0], requester_address[1], requester_address[2],
                            requester_address[3], requester_address[4]),
                        "sent NETWORK_CONFIG response"
                    );
                }

                // Build and send NETWORK_CREDENTIALS with signed COM
                let com = build_signed_com(
                    &ctrl.signing_key,
                    our_zt_address,
                    *network_id,
                    requester_addr_u64,
                    now_ms_val,
                );

                let creds_payload = NetworkCredentialsPayload {
                    com: Some(com),
                    capabilities_raw: Vec::new(),
                    tags_raw: Vec::new(),
                    revocations_raw: Vec::new(),
                    coo_raw: Vec::new(),
                };

                let mut creds_buf = [0u8; 2048];
                let creds_len = build_verb_packet(
                    &our_identity_for_packets,
                    requester_address,
                    zerotier_protocol::verb::Verb::NetworkCredentials,
                    shared_secret,
                    now_ms_val + 1, // Slightly different packet ID
                    &creds_payload,
                    &mut creds_buf,
                );
                if let Some(len) = creds_len {
                    node.push_action(NodeAction::SendTo {
                        data: creds_buf[..len].to_vec(),
                        address: *from,
                    });

                    tracing::info!(
                        event = "network_credentials_sent",
                        requester = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                            requester_address[0], requester_address[1], requester_address[2],
                            requester_address[3], requester_address[4]),
                        "sent NETWORK_CREDENTIALS with signed COM"
                    );
                }
            }
        }
    }
}

/// Handle dynamic controller actions from received packets.
///
/// When a NETWORK_CONFIG_REQUEST is received, uses the Controller engine
/// to dynamically generate config with auto-authorization and IP assignment.
async fn handle_dynamic_controller_actions(
    actions: &[NodeAction],
    dc: &mut DynamicControllerState,
    node: &mut Node,
    _our_zt_address: &[u8; 5],
) {
    // Clone identity public info needed for packet building (avoids borrow conflict)
    let our_public_key = node.identity.public_key.clone();
    let our_identity_for_packets = zerotier_crypto::identity::Identity {
        address: node.identity.address,
        public_key: our_public_key,
        secret: None,
    };

    for action in actions {
        if let NodeAction::NetworkConfigRequested {
            requester_address,
            network_id,
            from,
            ..
        } = action
        {
            if *network_id != dc.network_id {
                tracing::warn!(
                    event = "config_request_wrong_network",
                    requested = %format!("{:016x}", network_id),
                    expected = %format!("{:016x}", dc.network_id),
                    "NETWORK_CONFIG_REQUEST for unknown network"
                );
                continue;
            }

            tracing::info!(
                event = "network_config_request_received",
                requester = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                    requester_address[0], requester_address[1], requester_address[2],
                    requester_address[3], requester_address[4]),
                network_id = %format!("{:016x}", network_id),
                "received NETWORK_CONFIG_REQUEST (dynamic controller)"
            );

            // Use Controller engine to handle the request
            let now = now_ms();
            let response = dc
                .controller
                .handle_config_request(*network_id, requester_address, now)
                .await;

            let response = match response {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(
                        event = "controller_error",
                        error = %e,
                        "controller engine error"
                    );
                    continue;
                }
            };

            // Extract shared secret before mutable borrow of node
            let shared_secret = node
                .topology
                .get_peer(requester_address)
                .and_then(|peer| peer.shared_secret().copied());

            if let Some(ref shared_secret) = shared_secret {
                // Build and send NETWORK_CONFIG packet
                let nc_payload = response.config;
                let mut pkt_buf = [0u8; 2048];
                let nc_len = build_verb_packet(
                    &our_identity_for_packets,
                    requester_address,
                    zerotier_protocol::verb::Verb::NetworkConfig,
                    shared_secret,
                    now,
                    &nc_payload,
                    &mut pkt_buf,
                );
                if let Some(len) = nc_len {
                    node.push_action(NodeAction::SendTo {
                        data: pkt_buf[..len].to_vec(),
                        address: *from,
                    });

                    tracing::info!(
                        event = "controller_config_sent",
                        requester = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                            requester_address[0], requester_address[1], requester_address[2],
                            requester_address[3], requester_address[4]),
                        "sent NETWORK_CONFIG response (dynamic)"
                    );
                }

                // Build and send NETWORK_CREDENTIALS
                let creds_payload = response.credentials;
                let mut creds_buf = [0u8; 2048];
                let creds_len = build_verb_packet(
                    &our_identity_for_packets,
                    requester_address,
                    zerotier_protocol::verb::Verb::NetworkCredentials,
                    shared_secret,
                    now + 1,
                    &creds_payload,
                    &mut creds_buf,
                );
                if let Some(len) = creds_len {
                    node.push_action(NodeAction::SendTo {
                        data: creds_buf[..len].to_vec(),
                        address: *from,
                    });

                    tracing::info!(
                        event = "network_credentials_sent",
                        requester = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                            requester_address[0], requester_address[1], requester_address[2],
                            requester_address[3], requester_address[4]),
                        "sent NETWORK_CREDENTIALS with signed COM (dynamic)"
                    );
                }
            }

            // Track peer joins
            dc.peers_joined.insert(*requester_address);
            if dc.peers_joined.len() as u32 >= dc.expected_peers {
                tracing::info!(
                    event = "controller_all_peers_joined",
                    count = dc.peers_joined.len(),
                    expected = dc.expected_peers,
                    "all expected peers have requested config"
                );
            }
        }
    }
}

/// Build a signed Certificate of Membership for a specific member.
fn build_signed_com(
    signing_key: &ed25519_dalek::SigningKey,
    signer_address: &[u8; 5],
    network_id: u64,
    issued_to: u64,
    timestamp: u64,
) -> zerotier_protocol::verbs::network_config::CertificateOfMembership {
    use zerotier_protocol::verbs::network_config::{CertificateOfMembership, ComQualifier};

    let qualifiers = vec![
        ComQualifier {
            id: 0,
            value: timestamp,
            max_delta: 360000,
        },
        ComQualifier {
            id: 1,
            value: network_id,
            max_delta: 0,
        },
        ComQualifier {
            id: 2,
            value: issued_to,
            max_delta: 0,
        },
    ];

    // Build canonical signed data (sorted by qualifier ID, each as id+value+max_delta in BE)
    let mut signed_data = Vec::with_capacity(3 * 24);
    for q in &qualifiers {
        signed_data.extend_from_slice(&q.id.to_be_bytes());
        signed_data.extend_from_slice(&q.value.to_be_bytes());
        signed_data.extend_from_slice(&q.max_delta.to_be_bytes());
    }

    let signature = zerotier_crypto::signing::sign(signing_key, &signed_data);

    CertificateOfMembership {
        issued_to: u64_to_zt_address(issued_to),
        qualifiers,
        signer_address: *signer_address,
        signature,
    }
}

/// Trait for serializable verb payloads.
trait VerbPayloadSerialize {
    fn serialize_payload(&self, buf: &mut [u8]) -> usize;
}

impl VerbPayloadSerialize for zerotier_protocol::verbs::network_config::NetworkConfigPayload {
    fn serialize_payload(&self, buf: &mut [u8]) -> usize {
        self.serialize(buf)
    }
}

impl VerbPayloadSerialize for zerotier_protocol::verbs::network_config::NetworkCredentialsPayload {
    fn serialize_payload(&self, buf: &mut [u8]) -> usize {
        self.serialize(buf)
    }
}

/// Build and armor a packet with the given verb and payload.
///
/// Returns the total packet length, or None on failure.
fn build_verb_packet<P: VerbPayloadSerialize>(
    our_identity: &zerotier_crypto::identity::Identity,
    dest_address: &[u8; 5],
    verb: zerotier_protocol::verb::Verb,
    shared_secret: &[u8; 48],
    now_ms: u64,
    payload: &P,
    buf: &mut [u8],
) -> Option<usize> {
    use zerotier_protocol::constants::*;

    if buf.len() < ZT_PROTO_MIN_PACKET_LENGTH {
        return None;
    }

    // Packet ID
    buf[0..8].copy_from_slice(&now_ms.to_be_bytes());
    // Destination
    buf[8..13].copy_from_slice(dest_address);
    // Source
    buf[13..18].copy_from_slice(our_identity.address.as_bytes());
    // Flags: cipher suite 1 (Salsa20/12 + Poly1305), hop count 0
    buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;
    // MAC placeholder
    buf[19..27].copy_from_slice(&[0u8; 8]);
    // Verb
    buf[27] = verb.to_byte();

    // Payload
    let payload_len = payload.serialize_payload(&mut buf[28..]);
    let total_len = 28 + payload_len;

    // Armor with encryption
    match zerotier_crypto::salsa::armor_packet(shared_secret, &mut buf[..total_len], true) {
        Ok(()) => Some(total_len),
        Err(_) => None,
    }
}

/// Convert a 5-byte ZT address to u64 (zero-padded in high bytes).
fn zt_address_to_u64(addr: &[u8; 5]) -> u64 {
    (addr[0] as u64) << 32
        | (addr[1] as u64) << 24
        | (addr[2] as u64) << 16
        | (addr[3] as u64) << 8
        | (addr[4] as u64)
}

fn u64_to_zt_address(addr: u64) -> [u8; 5] {
    [
        (addr >> 32) as u8,
        (addr >> 24) as u8,
        (addr >> 16) as u8,
        (addr >> 8) as u8,
        addr as u8,
    ]
}

/// Parse a hex address string into 5 bytes, returning None on failure.
fn parse_hex_address_safe(hex: &str) -> Option<[u8; 5]> {
    let hex = hex.trim();
    if hex.len() != 10 {
        return None;
    }
    let mut addr = [0u8; 5];
    for (i, byte) in addr.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(addr)
}

/// Try to send a VL2 ICMP ping to the target peer.
async fn try_send_ping(
    state: &mut Vl2PeerState,
    node: &mut Node,
    our_zt_address: &[u8; 5],
    transport: &zerotier_service::NativeTransport,
) {
    // Find our own IP from the network membership
    let our_ip = {
        let network = match node.find_network(state.network_id) {
            Some(n) => n,
            None => return,
        };
        let member = network
            .members
            .iter()
            .find(|m| &m.zt_address == our_zt_address);
        match member.and_then(|m| m.ipv4.map(|(ip, _)| ip)) {
            Some(ip) => ip,
            None => return,
        }
    };

    // Build ICMP echo request as IPv4 packet
    let icmp_payload = vec![0x5a; state.ping_payload_bytes];
    let ipv4_packet = build_icmp_echo_request(
        our_ip,
        state.target_ip,
        1, // id
        1, // seq
        &icmp_payload,
    );

    // Send as outbound frame through VL2 path
    let actions = zerotier_node::vl2::process_outbound_frame(
        node,
        state.network_id,
        0x0800,
        &ipv4_packet,
        our_zt_address,
        now_ms(),
    );

    // Check if any action is WhoisNeeded: send WHOIS and retry later
    let has_whois = actions
        .iter()
        .any(|a| matches!(a, NodeAction::WhoisNeeded { .. }));
    if has_whois {
        for action in &actions {
            if let NodeAction::WhoisNeeded { addresses } = action {
                tracing::info!(
                    count = addresses.len(),
                    event = "whois_sending",
                    "Sending WHOIS for peer discovery"
                );
                let whois_actions = node.send_whois(addresses, now_ms());
                execute_actions(transport, &whois_actions).await;
            }
        }
        // Don't mark ping_sent: retry after WHOIS resolves
        return;
    }

    if !actions.is_empty() {
        state.ping_sent = true;
        tracing::info!(
            target_ip = %state.target_ip,
            actions = actions.len(),
            payload_bytes = state.ping_payload_bytes,
            event = "vl2_ping_sent",
            "VL2 ping sent"
        );
        execute_actions(transport, &actions).await;
    } else {
        tracing::debug!(
            target_ip = %state.target_ip,
            event = "vl2_ping_no_route",
            "VL2 ping: no route to peer (VL1 not ready or peer unknown)"
        );
    }
}

/// Build a minimal ICMP echo request wrapped in an IPv4 packet.
fn build_icmp_echo_request(
    src_ip: std::net::Ipv4Addr,
    dst_ip: std::net::Ipv4Addr,
    id: u16,
    seq: u16,
    data: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + data.len();
    let total_len = 20 + icmp_len;
    let mut pkt = vec![0u8; total_len];

    // IPv4 header (20 bytes)
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[1] = 0; // DSCP/ECN
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = total_len as u8;
    pkt[4] = 0;
    pkt[5] = 0; // identification
    pkt[6] = 0x40; // flags: don't fragment
    pkt[7] = 0; // fragment offset
    pkt[8] = 64; // TTL
    pkt[9] = 1; // protocol: ICMP
    pkt[10] = 0;
    pkt[11] = 0; // header checksum (filled below)
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    // IPv4 header checksum
    let ip_cksum = ipv4_checksum(&pkt[..20]);
    pkt[10] = (ip_cksum >> 8) as u8;
    pkt[11] = ip_cksum as u8;

    // ICMP echo request
    pkt[20] = 8; // type: echo request
    pkt[21] = 0; // code
    pkt[22] = 0;
    pkt[23] = 0; // checksum (filled below)
    pkt[24] = (id >> 8) as u8;
    pkt[25] = id as u8;
    pkt[26] = (seq >> 8) as u8;
    pkt[27] = seq as u8;
    pkt[28..28 + data.len()].copy_from_slice(data);

    // ICMP checksum
    let icmp_cksum = internet_checksum(&pkt[20..]);
    pkt[22] = (icmp_cksum >> 8) as u8;
    pkt[23] = icmp_cksum as u8;

    pkt
}

/// Build an ICMP echo reply from a received echo request IPv4 packet.
///
/// Swaps src/dst IPs, changes ICMP type from 8 to 0, recalculates checksums.
fn build_icmp_echo_reply(request: &[u8], ihl: usize) -> Option<Vec<u8>> {
    if request.len() < ihl + 8 {
        return None;
    }
    let mut reply = request.to_vec();

    // Swap src and dst IP
    let mut src_ip = [0u8; 4];
    let mut dst_ip = [0u8; 4];
    src_ip.copy_from_slice(&request[12..16]);
    dst_ip.copy_from_slice(&request[16..20]);
    reply[12..16].copy_from_slice(&dst_ip);
    reply[16..20].copy_from_slice(&src_ip);

    // Recalculate IPv4 header checksum
    reply[10] = 0;
    reply[11] = 0;
    let ip_cksum = ipv4_checksum(&reply[..ihl]);
    reply[10] = (ip_cksum >> 8) as u8;
    reply[11] = ip_cksum as u8;

    // Change ICMP type from 8 (request) to 0 (reply)
    reply[ihl] = 0;
    // Recalculate ICMP checksum
    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    let icmp_cksum = internet_checksum(&reply[ihl..]);
    reply[ihl + 2] = (icmp_cksum >> 8) as u8;
    reply[ihl + 3] = icmp_cksum as u8;

    Some(reply)
}

/// Compute IPv4 header checksum (ones' complement of ones' complement sum of 16-bit words).
fn ipv4_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

/// Compute internet checksum (RFC 1071).
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

async fn execute_actions(transport: &zerotier_service::NativeTransport, actions: &[NodeAction]) {
    for action in actions {
        match action {
            NodeAction::SendTo { data, address } => {
                if let Err(e) = transport.send_to(data, *address).await {
                    tracing::warn!(error = %e, addr = %address, "send failed");
                }
            }
            NodeAction::WhoisNeeded { addresses } => {
                tracing::debug!(
                    count = addresses.len(),
                    event = "whois_needed",
                    "WHOIS needed for addresses"
                );
            }
            NodeAction::FrameReceived {
                network_id,
                src_mac,
                dest_mac: _,
                ethertype,
                payload,
            } => {
                tracing::info!(
                    network_id = %format!("{:016x}", network_id),
                    src_mac = %format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]),
                    ethertype = %format!("0x{:04x}", ethertype),
                    payload_len = payload.len(),
                    event = "frame_received",
                    "VL2 frame received"
                );
            }
            NodeAction::LocalReply {
                network_id,
                ethertype,
                payload,
            } => {
                tracing::debug!(
                    network_id = %format!("{:016x}", network_id),
                    ethertype = %format!("0x{:04x}", ethertype),
                    payload_len = payload.len(),
                    event = "local_reply",
                    "local reply generated"
                );
            }
            NodeAction::NetworkConfigRequested {
                requester_address,
                network_id,
                ..
            } => {
                tracing::debug!(
                    network_id = %format!("{:016x}", network_id),
                    requester = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                        requester_address[0], requester_address[1], requester_address[2],
                        requester_address[3], requester_address[4]),
                    event = "network_config_request_action",
                    "NETWORK_CONFIG_REQUEST action (handled by controller)"
                );
            }
            NodeAction::NetworkConfigured { network_id, .. } => {
                tracing::info!(
                    network_id = %format!("{:016x}", network_id),
                    event = "network_configured_action",
                    "NETWORK_CONFIG received and applied"
                );
            }
            NodeAction::UserMessageReceived {
                origin,
                type_id,
                data,
            } => {
                tracing::debug!(
                    origin = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                        origin[0], origin[1], origin[2], origin[3], origin[4]),
                    type_id,
                    data_len = data.len(),
                    event = "user_message_action",
                    "USER_MESSAGE received"
                );
            }
            NodeAction::RemoteTraceReceived { origin, data } => {
                tracing::debug!(
                    origin = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                        origin[0], origin[1], origin[2], origin[3], origin[4]),
                    data_len = data.len(),
                    event = "remote_trace_action",
                    "REMOTE_TRACE received"
                );
            }
            NodeAction::DestinationUnknown { network_id } => {
                tracing::debug!(
                    network_id = %format!("{network_id:016x}"),
                    event = "destination_unknown_action",
                    "outbound packet for an address not in the member directory; config refresh requested"
                );
            }
            NodeAction::PathNegotiationReceived { origin, utility } => {
                tracing::debug!(
                    origin = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                        origin[0], origin[1], origin[2], origin[3], origin[4]),
                    utility,
                    event = "path_negotiation_action",
                    "PATH_NEGOTIATION_REQUEST received"
                );
            }
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// RNG wrapper using getrandom for OS entropy.
///
/// This avoids the rand_core 0.6/0.9 version conflict caused by dalek crates
/// pulling rand_core 0.6 transitively. We implement rand_core 0.9's RngCore
/// trait using getrandom directly.
struct GetrandomRng;

impl rand_core::RngCore for GetrandomRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(|_| {
            rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            )
        })
    }
}

impl rand_core::CryptoRng for GetrandomRng {}

/// Build a synthetic planet for testing.
///
/// For the root role: planet contains this node's own identity and binds to 0.0.0.0:port.
/// For peers: the planet file should be provided via --planet flag (pre-generated by the
/// test harness with the root's identity and endpoint).
///
/// When no --planet is provided for a root, we build a minimal planet with our own
/// identity as the sole root server.
fn build_test_planet(
    identity: &zerotier_crypto::identity::Identity,
    args: &Args,
) -> anyhow::Result<Vec<u8>> {
    use zerotier_protocol::inet_address::InetAddress;
    use zerotier_protocol::world::{World, WorldRoot, WorldType};

    if args.role != "root" {
        return Err(anyhow::anyhow!(
            "Peers must provide a --planet file (pre-generated with root identity)"
        ));
    }

    // For root nodes: build a planet with our own identity
    // The endpoint is 0.0.0.0:port since Shadow assigns virtual IPs
    let endpoint = InetAddress::V4 {
        ip: [0, 0, 0, 0],
        port: args.port,
    };

    let root = WorldRoot {
        identity: zerotier_crypto::identity::Identity::parse(&identity.to_public_string())
            .map_err(|e| anyhow::anyhow!("failed to derive public identity: {e}"))?,
        endpoints: vec![endpoint],
    };

    let world = World {
        world_type: WorldType::Planet,
        id: 0x4d414e59_54494552, // "MANYTIER" as u64
        timestamp: now_ms(),
        signing_key: [0u8; 64], // Test planet -- no real signing key
        signature: [0u8; 96],   // Test planet -- no real signature
        roots: vec![root],
        dict_data: None,
    };

    let mut buf = [0u8; 2048];
    let n = world
        .serialize(&mut buf)
        .map_err(|e| anyhow::anyhow!("failed to serialize world: {e}"))?;

    Ok(buf[..n].to_vec())
}
