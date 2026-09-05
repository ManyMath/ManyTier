//! Controller engine: core logic for network creation, member authorization,
//! IP assignment, and NETWORK_CONFIG_REQUEST processing.
//!
//! This is the brain of the controller, combining storage, config building,
//! and COM signing into a coherent API. Both the REST API and Shadow tests
//! can call these methods directly.
//!
//! This module is no_std compatible (using alloc).

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::config_builder::{build_network_config, serialize_com, serialize_inet_address};
use super::dictionary::Dictionary;
use super::ip_pool;
use super::storage::ControllerStorage;
use super::types::{MemberRecord, NetworkRecord};
use zerotier_protocol::verbs::network_config::{
    CertificateOfMembership, ComQualifier, NetworkConfigPayload, NetworkCredentialsPayload,
};

/// Errors produced by the controller engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerError {
    NetworkNotFound,
    MemberNotAuthorized,
    NoAvailableIp,
    StorageError(String),
}

impl core::fmt::Display for ControllerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ControllerError::NetworkNotFound => f.write_str("network not found"),
            ControllerError::MemberNotAuthorized => f.write_str("member not authorized"),
            ControllerError::NoAvailableIp => f.write_str("no available IP in pool"),
            ControllerError::StorageError(error) => write!(f, "storage error: {error}"),
        }
    }
}

/// The controller engine manages networks, members, and config requests.
pub struct Controller<S: ControllerStorage> {
    pub address: [u8; 5],
    pub signing_key: ed25519_dalek::SigningKey,
    pub storage: S,
}

/// Result of handling a config request: the network config payload and credentials.
pub struct ConfigResponse {
    pub config: NetworkConfigPayload,
    pub credentials: NetworkCredentialsPayload,
}

impl<S: ControllerStorage> Controller<S> {
    /// Create a new controller instance.
    pub fn new(address: [u8; 5], signing_key: ed25519_dalek::SigningKey, storage: S) -> Self {
        Self {
            address,
            signing_key,
            storage,
        }
    }

    /// Create a new network with default settings.
    ///
    /// Network ID is constructed as `(controller_address << 24) | random_24_bits`.
    /// The `random_24_bits` parameter is caller-provided for no_std compatibility.
    pub async fn create_network(
        &self,
        random_24_bits: u32,
        now_ms: u64,
    ) -> Result<u64, ControllerError> {
        let addr_u64 = zt_address_to_u64(&self.address);
        let network_id = (addr_u64 << 24) | (random_24_bits as u64 & 0x00FFFFFF);

        let network = NetworkRecord {
            id: network_id,
            name: String::new(),
            private: true,
            creation_time: now_ms,
            revision: 1,
            multicast_limit: 32,
            mtu: 2800,
            v4_assign_mode: String::from("zt"),
            v6_assign_mode: String::from("none"),
            rules: Vec::new(),
            capabilities: Vec::new(),
            tags: Vec::new(),
            enable_broadcast: true,
        };

        self.storage
            .create_network(&network)
            .await
            .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?;

        Ok(network_id)
    }

    /// Handle a NETWORK_CONFIG_REQUEST from a node.
    ///
    /// Looks up or creates the member record, enforces authorization policy,
    /// auto-assigns IPs if needed, builds a signed COM, and returns the
    /// config + credentials payloads.
    pub async fn handle_config_request(
        &self,
        network_id: u64,
        requester: &[u8; 5],
        now_ms: u64,
    ) -> Result<ConfigResponse, ControllerError> {
        // Look up network
        let network = self
            .storage
            .get_network(network_id)
            .await
            .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?
            .ok_or(ControllerError::NetworkNotFound)?;

        // Look up or create member
        let mut member = match self
            .storage
            .get_member(network_id, requester)
            .await
            .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?
        {
            Some(m) => m,
            None => {
                let m = MemberRecord {
                    network_id,
                    node_id: *requester,
                    authorized: false,
                    ip_assignments: Vec::new(),
                    creation_time: now_ms,
                    last_seen: now_ms,
                    name: String::new(),
                    revision: 0,
                    last_authorized_time: 0,
                    last_deauthorized_time: 0,
                    active_bridge: false,
                    no_auto_assign_ips: false,
                    capabilities: Vec::new(),
                    tags: Vec::new(),
                };
                self.storage
                    .upsert_member(&m)
                    .await
                    .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?;
                m
            }
        };

        // Authorization policy
        if network.private {
            if !member.authorized {
                return Err(ControllerError::MemberNotAuthorized);
            }
        } else {
            // Public networks auto-authorize
            if !member.authorized {
                member.authorized = true;
                self.storage
                    .upsert_member(&member)
                    .await
                    .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?;
            }
        }

        // Auto-assign IP if needed
        if member.ip_assignments.is_empty() && network.v4_assign_mode == "zt" {
            let pools = self
                .storage
                .get_ip_pools(network_id)
                .await
                .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?;

            if !pools.is_empty() {
                let assigned = self
                    .storage
                    .get_assigned_ips(network_id)
                    .await
                    .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?;

                if let Some(ip) = ip_pool::allocate_ipv4(&pools, &assigned) {
                    // Use /24 prefix by default (most common ZeroTier config)
                    let ip_str = alloc::format!("{}/24", ip_pool::format_ipv4(ip));
                    member.ip_assignments.push(ip_str);
                    self.storage
                        .upsert_member(&member)
                        .await
                        .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?;
                }
            }
        }

        // Update last_seen
        member.last_seen = now_ms;
        self.storage
            .upsert_member(&member)
            .await
            .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?;

        // Fetch routes
        let routes = self
            .storage
            .get_routes(network_id)
            .await
            .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?;

        // Build signed COM
        let issued_to = zt_address_to_u64(requester);
        let com = build_signed_com(
            &self.signing_key,
            &self.address,
            network_id,
            issued_to,
            now_ms,
        );

        // Only the capability definitions this member is granted are
        // issued to it, signed with the controller's key. These must be
        // embedded directly in *this member's own* network config dictionary
        // (`CAP`/`TAG` keys, below) -- not only carried in the separate
        // `NetworkCredentialsPayload` -- because upstream
        // `NetworkConfig::fromDictionary` populates a node's own
        // `_config.capabilities`/`_config.tags` (which its own outbound VL2
        // rule filter consults) exclusively from its own network config
        // dictionary. See `build_network_config`'s doc comment for the full
        // citation; this was confirmed live via
        // `test_official_capability_gates_data_plane_frame_delivery`, which
        // observed zero data-plane delivery until this embedding was added.
        let member_caps: Vec<super::rules::Capability> = network
            .capabilities
            .iter()
            .filter(|cap| member.capabilities.contains(&cap.id))
            .cloned()
            .collect();
        let capabilities_raw = if member_caps.is_empty() {
            Vec::new()
        } else {
            super::rules::serialize_capabilities_signed(
                &member_caps,
                network_id,
                requester,
                &self.address,
                now_ms,
                &self.signing_key,
            )
        };
        let tags_raw = if member.tags.is_empty() {
            Vec::new()
        } else {
            super::rules::serialize_tags_signed(
                &member.tags,
                network_id,
                requester,
                &self.address,
                now_ms,
                &self.signing_key,
            )
        };

        // Build network config dictionary
        let dict_data = build_network_config(
            &network,
            &member,
            &routes,
            &com,
            now_ms,
            &capabilities_raw,
            &tags_raw,
        );
        let member_ids = self
            .storage
            .list_members(network_id)
            .await
            .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?;
        let mut members = Vec::with_capacity(member_ids.len());
        for member_id in member_ids {
            if let Some(record) = self
                .storage
                .get_member(network_id, &member_id)
                .await
                .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?
            {
                members.push(record);
            }
        }
        let dict_data = append_peer_directory(
            dict_data,
            &members,
            network_id,
            now_ms,
            &self.signing_key,
            &self.address,
        )?;

        let config = NetworkConfigPayload {
            network_id,
            dict_data,
            flags: None,
            config_update_id: None,
            total_length: None,
            chunk_index: None,
            signature_type: None,
            signature: None,
        };

        // `capabilities_raw`/`tags_raw` were already computed above (needed
        // earlier now to embed into this member's own network config dict).
        let credentials = NetworkCredentialsPayload {
            coms: vec![com],
            sections: NetworkCredentialsPayload::sections_from(
                member_caps.len() as u16,
                &capabilities_raw,
                member.tags.len() as u16,
                &tags_raw,
            ),
        };

        Ok(ConfigResponse {
            config,
            credentials,
        })
    }

    /// Authorize a member on a network.
    pub async fn authorize_member(
        &self,
        network_id: u64,
        node_id: &[u8; 5],
    ) -> Result<(), ControllerError> {
        let mut member = self
            .storage
            .get_member(network_id, node_id)
            .await
            .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?
            .ok_or(ControllerError::NetworkNotFound)?;

        member.authorized = true;
        self.storage
            .upsert_member(&member)
            .await
            .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?;

        Ok(())
    }

    /// Deauthorize a member on a network.
    pub async fn deauthorize_member(
        &self,
        network_id: u64,
        node_id: &[u8; 5],
    ) -> Result<(), ControllerError> {
        let mut member = self
            .storage
            .get_member(network_id, node_id)
            .await
            .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?
            .ok_or(ControllerError::NetworkNotFound)?;

        member.authorized = false;
        self.storage
            .upsert_member(&member)
            .await
            .map_err(|e| ControllerError::StorageError(alloc::format!("{}", e)))?;

        Ok(())
    }
}

fn append_peer_directory(
    dict_data: Vec<u8>,
    members: &[MemberRecord],
    network_id: u64,
    now_ms: u64,
    signing_key: &ed25519_dalek::SigningKey,
    controller_address: &[u8; 5],
) -> Result<Vec<u8>, ControllerError> {
    let mut dict = Dictionary::deserialize(&dict_data).map_err(|e| {
        ControllerError::StorageError(alloc::format!("dict deserialize failed: {e}"))
    })?;
    let directory =
        serialize_peer_directory(members, network_id, now_ms, signing_key, controller_address);
    if !directory.is_empty() {
        dict.add_binary("PM", directory);
    }
    Ok(dict.serialize())
}

fn serialize_peer_directory(
    members: &[MemberRecord],
    network_id: u64,
    now_ms: u64,
    signing_key: &ed25519_dalek::SigningKey,
    controller_address: &[u8; 5],
) -> Vec<u8> {
    let eligible: Vec<_> = members
        .iter()
        .filter(|member| member.authorized && !member.ip_assignments.is_empty())
        .collect();
    let mut buf = Vec::new();
    buf.extend_from_slice(&(eligible.len() as u16).to_be_bytes());

    for member in eligible {
        buf.extend_from_slice(&member.node_id);
        buf.extend(serialize_assignment_inet(
            member
                .ip_assignments
                .iter()
                .find(|assignment| !assignment.contains(':'))
                .map(|assignment| assignment.as_str()),
        ));
        buf.extend(serialize_assignment_inet(
            member
                .ip_assignments
                .iter()
                .find(|assignment| assignment.contains(':'))
                .map(|assignment| assignment.as_str()),
        ));

        let com = build_signed_com(
            signing_key,
            controller_address,
            network_id,
            zt_address_to_u64(&member.node_id),
            now_ms,
        );
        buf.extend_from_slice(&serialize_com(&com));
    }

    buf
}

fn serialize_assignment_inet(assignment: Option<&str>) -> Vec<u8> {
    let Some(assignment) = assignment else {
        return vec![0x00];
    };

    let mut parts = assignment.splitn(2, '/');
    let ip = parts.next().unwrap_or_default();
    let prefix = parts
        .next()
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or_else(|| if ip.contains(':') { 128 } else { 32 });
    serialize_inet_address(ip, prefix)
}

/// Convert a 5-byte ZeroTier address to a u64 (zero-extended).
pub fn zt_address_to_u64(addr: &[u8; 5]) -> u64 {
    (addr[0] as u64) << 32
        | (addr[1] as u64) << 24
        | (addr[2] as u64) << 16
        | (addr[3] as u64) << 8
        | (addr[4] as u64)
}

pub fn u64_to_zt_address(addr: u64) -> [u8; 5] {
    [
        (addr >> 32) as u8,
        (addr >> 24) as u8,
        (addr >> 16) as u8,
        (addr >> 8) as u8,
        addr as u8,
    ]
}

/// Build a signed Certificate of Membership.
///
/// Qualifiers:
/// - id=0: timestamp with max_delta=360000 (6 minutes)
/// - id=1: network_id with max_delta=0
/// - id=2: issued_to (node address as u64) with max_delta=u64::MAX (matches
///   upstream `CertificateOfMembership::CertificateOfMembership` -- this
///   qualifier differs for every member by definition, so it must not
///   participate in `agreesWith`'s delta check)
///
/// Signature is computed over canonical qualifier data (sorted by ID,
/// each as id + value + max_delta in big-endian).
pub fn build_signed_com(
    signing_key: &ed25519_dalek::SigningKey,
    signer_address: &[u8; 5],
    network_id: u64,
    issued_to: u64,
    timestamp: u64,
) -> CertificateOfMembership {
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
            // Upstream `CertificateOfMembership::CertificateOfMembership(timestamp,
            // timestampMaxDelta, nwid, issuedTo)` (node/CertificateOfMembership.cpp)
            // sets this qualifier's max_delta to `0xffffffffffffffff` (u64::MAX),
            // not 0. `CertificateOfMembership::agreesWith` requires
            // `|mine - theirs| <= max_delta` for every qualifier ID present, and
            // "issued to" is by definition a different ZT address for every pair
            // of members -- a max_delta of 0 here made `agreesWith` fail for any
            // two distinct members, permanently blocking member-to-member COM
            // agreement (and therefore all VL2 frame delivery) once more than one
            // member ever tried to talk to another. Confirmed live: this was
            // masked in every prior single-peer test (a lone official talking
            // only to the controller never exercises peer-to-peer COM
            // cross-validation) and only surfaced once a real two-official-peer
            // data-plane test was added (the privileged-Docker capability
            // rule-enforcement check).
            max_delta: u64::MAX,
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

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use alloc::string::String;
    use alloc::vec::Vec;
    use core::fmt;

    use super::super::storage::ControllerStorage;
    use super::super::types::{IpPool, ManagedRoute, MemberRecord, NetworkRecord};

    // --- Minimal in-memory storage for tests ---

    #[derive(Debug)]
    struct TestError(String);

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    struct InMemoryStorage {
        networks: std::sync::Mutex<Vec<NetworkRecord>>,
        members: std::sync::Mutex<Vec<MemberRecord>>,
        pools: std::sync::Mutex<Vec<(u64, Vec<IpPool>)>>,
        routes: std::sync::Mutex<Vec<(u64, Vec<ManagedRoute>)>>,
    }

    impl InMemoryStorage {
        fn new() -> Self {
            Self {
                networks: std::sync::Mutex::new(Vec::new()),
                members: std::sync::Mutex::new(Vec::new()),
                pools: std::sync::Mutex::new(Vec::new()),
                routes: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl ControllerStorage for InMemoryStorage {
        type Error = TestError;

        async fn get_network(&self, id: u64) -> Result<Option<NetworkRecord>, Self::Error> {
            let nets = self.networks.lock().unwrap();
            Ok(nets.iter().find(|n| n.id == id).cloned())
        }

        async fn create_network(&self, network: &NetworkRecord) -> Result<(), Self::Error> {
            self.networks.lock().unwrap().push(network.clone());
            Ok(())
        }

        async fn update_network(&self, network: &NetworkRecord) -> Result<(), Self::Error> {
            let mut nets = self.networks.lock().unwrap();
            if let Some(n) = nets.iter_mut().find(|n| n.id == network.id) {
                *n = network.clone();
            }
            Ok(())
        }

        async fn delete_network(&self, id: u64) -> Result<(), Self::Error> {
            self.networks.lock().unwrap().retain(|n| n.id != id);
            Ok(())
        }

        async fn list_networks(&self) -> Result<Vec<u64>, Self::Error> {
            Ok(self.networks.lock().unwrap().iter().map(|n| n.id).collect())
        }

        async fn get_member(
            &self,
            network_id: u64,
            node_id: &[u8; 5],
        ) -> Result<Option<MemberRecord>, Self::Error> {
            let mems = self.members.lock().unwrap();
            Ok(mems
                .iter()
                .find(|m| m.network_id == network_id && m.node_id == *node_id)
                .cloned())
        }

        async fn upsert_member(&self, member: &MemberRecord) -> Result<(), Self::Error> {
            let mut mems = self.members.lock().unwrap();
            if let Some(m) = mems
                .iter_mut()
                .find(|m| m.network_id == member.network_id && m.node_id == member.node_id)
            {
                *m = member.clone();
            } else {
                mems.push(member.clone());
            }
            Ok(())
        }

        async fn delete_member(
            &self,
            network_id: u64,
            node_id: &[u8; 5],
        ) -> Result<(), Self::Error> {
            self.members
                .lock()
                .unwrap()
                .retain(|m| !(m.network_id == network_id && m.node_id == *node_id));
            Ok(())
        }

        async fn list_members(&self, network_id: u64) -> Result<Vec<[u8; 5]>, Self::Error> {
            Ok(self
                .members
                .lock()
                .unwrap()
                .iter()
                .filter(|m| m.network_id == network_id)
                .map(|m| m.node_id)
                .collect())
        }

        async fn get_ip_pools(&self, network_id: u64) -> Result<Vec<IpPool>, Self::Error> {
            let pools = self.pools.lock().unwrap();
            Ok(pools
                .iter()
                .find(|(nid, _)| *nid == network_id)
                .map(|(_, p)| p.clone())
                .unwrap_or_default())
        }

        async fn set_ip_pools(
            &self,
            network_id: u64,
            new_pools: &[IpPool],
        ) -> Result<(), Self::Error> {
            let mut pools = self.pools.lock().unwrap();
            pools.retain(|(nid, _)| *nid != network_id);
            pools.push((network_id, new_pools.to_vec()));
            Ok(())
        }

        async fn get_routes(&self, network_id: u64) -> Result<Vec<ManagedRoute>, Self::Error> {
            let routes = self.routes.lock().unwrap();
            Ok(routes
                .iter()
                .find(|(nid, _)| *nid == network_id)
                .map(|(_, r)| r.clone())
                .unwrap_or_default())
        }

        async fn set_routes(
            &self,
            network_id: u64,
            new_routes: &[ManagedRoute],
        ) -> Result<(), Self::Error> {
            let mut routes = self.routes.lock().unwrap();
            routes.retain(|(nid, _)| *nid != network_id);
            routes.push((network_id, new_routes.to_vec()));
            Ok(())
        }

        async fn get_assigned_ips(&self, network_id: u64) -> Result<Vec<String>, Self::Error> {
            let mems = self.members.lock().unwrap();
            let mut ips = Vec::new();
            for m in mems.iter().filter(|m| m.network_id == network_id) {
                ips.extend(m.ip_assignments.iter().cloned());
            }
            Ok(ips)
        }
    }

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn test_address() -> [u8; 5] {
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee]
    }

    #[tokio::test]
    async fn engine_create_network_has_correct_upper_bits() {
        let storage = InMemoryStorage::new();
        let ctrl = Controller::new(test_address(), test_signing_key(), storage);

        let network_id = ctrl.create_network(0x123456, 1000).await.unwrap();

        // Upper 40 bits should be the controller address
        let upper = network_id >> 24;
        let expected = zt_address_to_u64(&test_address());
        assert_eq!(upper, expected);

        // Lower 24 bits should be the random value
        let lower = network_id & 0x00FFFFFF;
        assert_eq!(lower, 0x123456);
    }

    #[tokio::test]
    async fn engine_public_network_auto_authorizes() {
        let storage = InMemoryStorage::new();
        let ctrl = Controller::new(test_address(), test_signing_key(), storage);

        let nid = ctrl.create_network(0x000001, 1000).await.unwrap();

        // Make it public
        {
            let mut nets = ctrl.storage.networks.lock().unwrap();
            nets[0].private = false;
        }

        let requester = [0x11, 0x22, 0x33, 0x44, 0x55];
        let response = ctrl.handle_config_request(nid, &requester, 2000).await;
        assert!(response.is_ok());

        // Member should now be authorized in storage
        let member = ctrl
            .storage
            .get_member(nid, &requester)
            .await
            .unwrap()
            .unwrap();
        assert!(member.authorized);
    }

    #[tokio::test]
    async fn engine_private_network_rejects_unauthorized() {
        let storage = InMemoryStorage::new();
        let ctrl = Controller::new(test_address(), test_signing_key(), storage);

        let nid = ctrl.create_network(0x000002, 1000).await.unwrap();
        // Network is private by default

        let requester = [0x11, 0x22, 0x33, 0x44, 0x55];
        let result = ctrl.handle_config_request(nid, &requester, 2000).await;
        assert!(matches!(result, Err(ControllerError::MemberNotAuthorized)));
    }

    #[tokio::test]
    async fn engine_auto_assigns_ip_from_pool() {
        let storage = InMemoryStorage::new();
        let ctrl = Controller::new(test_address(), test_signing_key(), storage);

        let nid = ctrl.create_network(0x000003, 1000).await.unwrap();

        // Make it public so auto-authorize works
        {
            let mut nets = ctrl.storage.networks.lock().unwrap();
            nets[0].private = false;
        }

        // Set up IP pool
        ctrl.storage
            .set_ip_pools(
                nid,
                &[IpPool {
                    range_start: [192, 168, 192, 1],
                    range_end: [192, 168, 192, 254],
                }],
            )
            .await
            .unwrap();

        let requester = [0x11, 0x22, 0x33, 0x44, 0x55];
        let response = ctrl
            .handle_config_request(nid, &requester, 2000)
            .await
            .unwrap();

        // Member should have an IP assignment
        let member = ctrl
            .storage
            .get_member(nid, &requester)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(member.ip_assignments.len(), 1);
        assert_eq!(member.ip_assignments[0], "192.168.192.1/24");

        // Config should contain the network ID
        assert_eq!(response.config.network_id, nid);

        // Credentials should have a COM
        assert!(response.credentials.com().is_some());
    }

    #[test]
    fn engine_build_signed_com_has_3_qualifiers_and_96_byte_sig() {
        let key = test_signing_key();
        let addr = test_address();
        let com = build_signed_com(&key, &addr, 0x1234567890, 0xABCDEF, 5000);

        assert_eq!(com.qualifiers.len(), 3);
        assert_eq!(com.qualifiers[0].id, 0);
        assert_eq!(com.qualifiers[0].value, 5000); // timestamp
        assert_eq!(com.qualifiers[0].max_delta, 360000);
        assert_eq!(com.qualifiers[1].id, 1);
        assert_eq!(com.qualifiers[1].value, 0x1234567890); // network_id
        assert_eq!(com.qualifiers[1].max_delta, 0);
        assert_eq!(com.qualifiers[2].id, 2);
        assert_eq!(com.qualifiers[2].value, 0xABCDEF); // issued_to
        assert_eq!(com.qualifiers[2].max_delta, u64::MAX);
        assert_eq!(com.signature.len(), 96);
        assert_eq!(com.signer_address, addr);

        // Verify signature is valid (not all zeros)
        assert!(com.signature.iter().any(|&b| b != 0));
    }

    #[test]
    fn engine_zt_address_to_u64() {
        assert_eq!(zt_address_to_u64(&[0x00, 0x00, 0x00, 0x00, 0x01]), 1);
        assert_eq!(
            zt_address_to_u64(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            0xaabbccddee
        );
        assert_eq!(
            zt_address_to_u64(&[0xff, 0xff, 0xff, 0xff, 0xff]),
            0xffffffffff
        );
    }

    #[tokio::test]
    async fn engine_authorize_deauthorize_member() {
        let storage = InMemoryStorage::new();
        let ctrl = Controller::new(test_address(), test_signing_key(), storage);

        let nid = ctrl.create_network(0x000004, 1000).await.unwrap();

        // Create a member (unauthorized by default on private network)
        let requester = [0x11, 0x22, 0x33, 0x44, 0x55];
        let _ = ctrl.handle_config_request(nid, &requester, 2000).await;

        // Authorize
        ctrl.authorize_member(nid, &requester).await.unwrap();
        let member = ctrl
            .storage
            .get_member(nid, &requester)
            .await
            .unwrap()
            .unwrap();
        assert!(member.authorized);

        // Deauthorize
        ctrl.deauthorize_member(nid, &requester).await.unwrap();
        let member = ctrl
            .storage
            .get_member(nid, &requester)
            .await
            .unwrap()
            .unwrap();
        assert!(!member.authorized);
    }
}
