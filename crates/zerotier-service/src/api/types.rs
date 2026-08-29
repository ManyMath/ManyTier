//! JSON response types for the service REST API.
//!
//! These types are serialized directly to JSON for API responses.
//! Field names use camelCase via serde rename where needed to match
//! the official ZeroTier API format.

use serde::{Deserialize, Serialize};

/// Response for GET /status.
#[derive(Serialize)]
pub struct StatusResponse {
    pub address: String,
    pub version: String,
    pub online: bool,
    /// Full public identity string (address:0:pubkey_hex).
    #[serde(rename = "publicIdentity")]
    pub public_identity: String,
}

/// Response for GET /peer (each element in the array).
#[derive(Serialize)]
pub struct PeerResponse {
    pub address: String,
    pub paths: Vec<PathResponse>,
    pub latency: i64,
    /// "LEAF" or "ROOT".
    pub role: String,
}

/// A network path to a peer.
#[derive(Serialize)]
pub struct PathResponse {
    pub address: String,
    pub active: bool,
    /// Timestamp of last received packet on this path.
    #[serde(rename = "lastReceive")]
    pub last_receive: u64,
}

/// Response for GET /network and POST /network/{id}.
#[derive(Serialize)]
pub struct NetworkResponse {
    pub id: String,
    pub name: String,
    /// "OK" or "REQUESTING_CONFIGURATION".
    pub status: String,
    /// Assigned IP addresses with prefix length.
    #[serde(rename = "assignedAddresses")]
    pub assigned_addresses: Vec<String>,
    pub mac: String,
    pub mtu: u16,
    /// TUN interface name; empty until created.
    #[serde(rename = "portDeviceName")]
    pub port_device_name: String,
}

// --- Controller API types (Plan 05) ---

/// Response for GET /controller/network/{nwid}.
#[derive(Serialize)]
pub struct ControllerNetworkResponse {
    pub id: String,
    pub name: String,
    /// Whether members must be explicitly authorized.
    pub private: bool,
    /// Creation time in milliseconds since epoch.
    #[serde(rename = "creationTime")]
    pub creation_time: u64,
    pub revision: u64,
    /// Maximum number of multicast recipients.
    #[serde(rename = "multicastLimit")]
    pub multicast_limit: u32,
    pub mtu: u16,
    /// IPv4 assignment mode, e.g., {"zt": true}.
    #[serde(rename = "v4AssignMode")]
    pub v4_assign_mode: serde_json::Value,
    /// IPv6 assignment mode, e.g., {"zt": false, "6plane": false, "rfc4193": false}.
    #[serde(rename = "v6AssignMode")]
    pub v6_assign_mode: serde_json::Value,
    /// IP auto-assignment pools.
    #[serde(rename = "ipAssignmentPools")]
    pub ip_assignment_pools: Vec<IpPoolResponse>,
    /// Whether broadcast is enabled.
    #[serde(rename = "enableBroadcast")]
    pub enable_broadcast: bool,
    pub routes: Vec<RouteResponse>,
    /// Network-wide match/action rule chain. Empty means allow-all.
    ///
    /// This is still ManyTier's own rule JSON shape (`ruleType`/`not`/`or`/`value`)
    /// with an added `type` field carrying official's symbolic rule-type name for
    /// readability (e.g. `"ACTION_ACCEPT"`, `"MATCH_IP_PROTOCOL"`). It is not yet
    /// official's fully per-rule-type schema (e.g. `{"type": "MATCH_IP_PROTOCOL",
    /// "ipProtocol": 6}` with type-specific field names instead of a raw `value` blob).
    pub rules: Vec<RuleResponse>,
    /// Network-level capability definitions.
    pub capabilities: Vec<CapabilityResponse>,
    /// Network-level tag definitions (name/default/enums metadata).
    pub tags: Vec<TagDefinitionResponse>,
}

/// A single match/action rule.
#[derive(Serialize, Deserialize)]
pub struct RuleResponse {
    #[serde(rename = "ruleType")]
    pub rule_type: u8,
    /// Official's symbolic rule-type name (e.g. `"MATCH_IP_PROTOCOL"`), derived
    /// from `rule_type` for readability. Ignored on input; recomputed on output.
    #[serde(rename = "type", default)]
    pub type_name: String,
    pub not: bool,
    #[serde(rename = "or")]
    pub or_flag: bool,
    /// Raw wire-format value bytes. Always the authoritative, lossless
    /// representation; recomputed on every GET from the rule's actual bytes.
    pub value: Vec<u8>,
    /// The same value decoded into official's type-specific named fields
    /// (e.g. `{"ipProtocol": 6}` for `MATCH_IP_PROTOCOL`), nested here rather
    /// than flattened to avoid colliding with `value` (official's own flat
    /// schema reuses `"value"` for `MATCH_TAG*` rules' tag value). `None` for
    /// rule types with no value payload or an unrecognized type. On input,
    /// used only when `value` is empty -- an explicit `value` always wins.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fields: Option<serde_json::Value>,
}

/// A network-level capability definition (id + rule chain).
#[derive(Serialize, Deserialize)]
pub struct CapabilityResponse {
    pub id: u32,
    pub rules: Vec<RuleResponse>,
}

/// A tag id/value pair assigned to a member.
#[derive(Serialize, Deserialize)]
pub struct TagResponse {
    pub id: u32,
    pub value: u32,
}

/// A network-level tag definition (name/default/enums metadata).
#[derive(Serialize, Deserialize)]
pub struct TagDefinitionResponse {
    pub id: u32,
    pub name: String,
    pub default: Option<u32>,
    /// Named enum values as `{name: value}`.
    pub enums: std::collections::BTreeMap<String, u32>,
}

/// An IP assignment pool range.
#[derive(Serialize, Deserialize)]
pub struct IpPoolResponse {
    /// Start of IP range as dotted-decimal string.
    #[serde(rename = "ipRangeStart")]
    pub ip_range_start: String,
    /// End of IP range as dotted-decimal string.
    #[serde(rename = "ipRangeEnd")]
    pub ip_range_end: String,
}

/// A managed route entry.
#[derive(Serialize, Deserialize)]
pub struct RouteResponse {
    pub target: String,
    /// Gateway address, or null for local routes.
    pub via: Option<String>,
}

/// Response for GET /controller/network/{nwid}/member/{nodeId}.
#[derive(Serialize)]
pub struct ControllerMemberResponse {
    pub id: String,
    /// 16-character hex network ID.
    #[serde(rename = "networkId")]
    pub network_id: String,
    pub authorized: bool,
    /// Assigned IP addresses with prefix length.
    #[serde(rename = "ipAssignments")]
    pub ip_assignments: Vec<String>,
    /// Creation time in milliseconds since epoch.
    #[serde(rename = "creationTime")]
    pub creation_time: u64,
    /// Last seen timestamp in milliseconds since epoch.
    #[serde(rename = "lastSeen")]
    pub last_seen: u64,
    pub name: String,
    pub revision: u64,
    /// Whether this member acts as an active bridge for the network.
    #[serde(rename = "activeBridge")]
    pub active_bridge: bool,
    /// If true, this member does not receive IPs from the network's auto-assign pools.
    #[serde(rename = "noAutoAssignIps")]
    pub no_auto_assign_ips: bool,
    /// Milliseconds since epoch of the most recent authorization, or 0 if never authorized.
    #[serde(rename = "lastAuthorizedTime")]
    pub last_authorized_time: u64,
    /// Milliseconds since epoch of the most recent deauthorization, or 0 if never deauthorized.
    #[serde(rename = "lastDeauthorizedTime")]
    pub last_deauthorized_time: u64,
    /// Peer protocol/version fields; -1 (unknown) until version tracking lands.
    #[serde(rename = "vMajor")]
    pub v_major: i32,
    #[serde(rename = "vMinor")]
    pub v_minor: i32,
    #[serde(rename = "vRev")]
    pub v_rev: i32,
    #[serde(rename = "vProto")]
    pub v_proto: i32,
    /// IDs of network-level capability definitions granted to this member.
    pub capabilities: Vec<u32>,
    /// Tag id/value pairs assigned to this member.
    pub tags: Vec<TagResponse>,
}

/// Request body for POST /controller/network/{nwid} (partial update).
#[derive(Deserialize)]
pub struct UpdateNetworkRequest {
    pub name: Option<String>,
    /// New privacy setting.
    pub private: Option<bool>,
    /// New multicast limit.
    #[serde(rename = "multicastLimit")]
    pub multicast_limit: Option<u32>,
    pub mtu: Option<u16>,
    /// New v4 assignment mode.
    #[serde(rename = "v4AssignMode")]
    pub v4_assign_mode: Option<serde_json::Value>,
    /// New IP assignment pools.
    #[serde(rename = "ipAssignmentPools")]
    pub ip_assignment_pools: Option<Vec<IpPoolResponse>>,
    pub routes: Option<Vec<RouteResponse>>,
    /// New broadcast setting.
    #[serde(rename = "enableBroadcast")]
    pub enable_broadcast: Option<bool>,
    /// New rule chain.
    pub rules: Option<Vec<RuleResponse>>,
    /// New capability definitions.
    pub capabilities: Option<Vec<CapabilityResponse>>,
    /// New tag definitions.
    pub tags: Option<Vec<TagDefinitionResponse>>,
}

/// Request body for POST /controller/network/{nwid}/member/{nodeId} (partial update).
#[derive(Deserialize)]
pub struct UpdateMemberRequest {
    /// New authorization status.
    pub authorized: Option<bool>,
    /// New IP assignments.
    #[serde(rename = "ipAssignments")]
    pub ip_assignments: Option<Vec<String>>,
    pub name: Option<String>,
    /// New active-bridge setting.
    #[serde(rename = "activeBridge")]
    pub active_bridge: Option<bool>,
    /// New no-auto-assign-ips setting.
    #[serde(rename = "noAutoAssignIps")]
    pub no_auto_assign_ips: Option<bool>,
    /// New set of granted capability IDs.
    pub capabilities: Option<Vec<u32>>,
    /// New set of assigned tag id/value pairs.
    pub tags: Option<Vec<TagResponse>>,
}
