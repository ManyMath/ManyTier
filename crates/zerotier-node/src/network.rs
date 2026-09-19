/// Network membership state, COM verification, and member lookup.
///
/// Provides the core VL2 types for tracking which peers are members of a
/// virtual network, verifying Certificates of Membership, and looking up
/// members by IP or MAC address.
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use zerotier_protocol::verbs::network_config::{CertificateOfMembership, ComQualifier};

use crate::ethernet;

pub const COM_QUALIFIER_TIMESTAMP_ID: u64 = 0;
pub const COM_REFRESH_MARGIN_CAP_MS: u64 = 60_000;

/// A member of a virtual network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkMember {
    pub zt_address: [u8; 5],
    pub mac: [u8; 6],
    pub ipv4: Option<(Ipv4Addr, u8)>,
    pub ipv6: Option<(Ipv6Addr, u8)>,
    pub authorized: bool,
}

/// A managed route of a virtual network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub target: IpAddr,
    pub prefix: u8,
    /// Gateway, or `None` for an on-link route.
    pub via: Option<IpAddr>,
}

impl Route {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.target, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => ipv4_in_prefix(ip, net, self.prefix),
            (IpAddr::V6(net), IpAddr::V6(ip)) => ipv6_in_prefix(ip, net, self.prefix),
            _ => false,
        }
    }
}

/// Parse a config's `RT` value as ZeroTier One writes it
/// (node/NetworkConfig.cpp): per route a target InetAddress whose port is
/// the prefix length, a gateway InetAddress (null for on-link), then u16
/// flags and u16 metric. Stops at the first malformed entry.
pub fn parse_routes(data: &[u8]) -> Vec<Route> {
    use zerotier_protocol::inet_address::InetAddress;

    let ip = |address: &InetAddress| match address {
        InetAddress::V4 { ip, port } => Some((IpAddr::V4(Ipv4Addr::from(*ip)), *port)),
        InetAddress::V6 { ip, port } => Some((IpAddr::V6(Ipv6Addr::from(*ip)), *port)),
        InetAddress::Null => None,
    };
    let mut routes = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let Ok((target, used)) = InetAddress::deserialize(&data[pos..]) else {
            break;
        };
        pos += used;
        let Ok((via, used)) = InetAddress::deserialize(&data[pos..]) else {
            break;
        };
        pos += used;
        if pos + 4 > data.len() {
            break;
        }
        pos += 4; // flags, metric
        let Some((target, prefix)) = ip(&target) else {
            continue;
        };
        let max_prefix = if target.is_ipv4() { 32 } else { 128 };
        routes.push(Route {
            target,
            prefix: prefix.min(max_prefix) as u8,
            via: ip(&via).map(|(gateway, _)| gateway),
        });
    }
    routes
}

/// Why the controller refused us a config, as ZeroTier One tracks it
/// (`Network::_netconfFailure`). Cleared when a config is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigFailure {
    #[default]
    None,
    AccessDenied,
    NotFound,
    AuthenticationRequired,
}

/// Network membership state: tracks members, COMs, and provides lookups.
#[derive(Debug, Clone)]
pub struct NetworkMembership {
    pub network_id: u64,
    pub members: Vec<NetworkMember>,
    pub our_com: Option<CertificateOfMembership>,
    pub peer_coms: Vec<([u8; 5], CertificateOfMembership)>,
    pub mtu: u16,
    pub assigned_ipv4: Option<Ipv4Addr>,
    pub assigned_ipv6: Option<Ipv6Addr>,
    pub routes: Vec<Route>,
    pub pending_config_request: bool,
    pub last_config_request: u64,
    pub last_multicast_like: u64,
    pub last_multicast_gather: u64,
    pub config_failure: ConfigFailure,
    /// When our credentials were last pushed to each peer. Cleared when a
    /// new config arrives so every peer gets the new COM.
    pub credentials_pushed: BTreeMap<[u8; 5], u64>,
}

impl NetworkMembership {
    /// Create a new empty network membership.
    pub fn new(network_id: u64, mtu: u16) -> Self {
        NetworkMembership {
            network_id,
            members: Vec::new(),
            our_com: None,
            peer_coms: Vec::new(),
            mtu,
            assigned_ipv4: None,
            assigned_ipv6: None,
            routes: Vec::new(),
            pending_config_request: false,
            last_config_request: 0,
            last_multicast_like: 0,
            last_multicast_gather: 0,
            config_failure: ConfigFailure::None,
            credentials_pushed: BTreeMap::new(),
        }
    }

    /// Network status as ZeroTier One names it (`ZT_VirtualNetworkStatus`).
    pub fn status_name(&self) -> &'static str {
        match self.config_failure {
            ConfigFailure::AccessDenied => "ACCESS_DENIED",
            ConfigFailure::NotFound => "NOT_FOUND",
            ConfigFailure::AuthenticationRequired => "AUTHENTICATION_REQUIRED",
            ConfigFailure::None if self.our_com.is_some() => "OK",
            ConfigFailure::None => "REQUESTING_CONFIGURATION",
        }
    }

    /// Look up a member by IPv4 address.
    /// Is `ip` inside this network's managed address space, i.e. within the
    /// prefix of any member's assigned address or equal to our own?
    pub fn covers_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                self.assigned_ipv4 == Some(v4)
                    || self.members.iter().any(|member| {
                        member
                            .ipv4
                            .is_some_and(|(addr, prefix)| ipv4_in_prefix(v4, addr, prefix))
                    })
            }
            IpAddr::V6(v6) => {
                self.assigned_ipv6 == Some(v6)
                    || self.members.iter().any(|member| {
                        member
                            .ipv6
                            .is_some_and(|(addr, prefix)| ipv6_in_prefix(v6, addr, prefix))
                    })
            }
        }
    }

    pub fn lookup_ipv4(&self, ip: Ipv4Addr) -> Option<&NetworkMember> {
        self.members.iter().find(|m| {
            m.ipv4
                .as_ref()
                .map(|(addr, _)| *addr == ip)
                .unwrap_or(false)
        })
    }

    /// Look up a member by IPv6 address.
    pub fn lookup_ipv6(&self, ip: Ipv6Addr) -> Option<&NetworkMember> {
        self.members.iter().find(|m| {
            m.ipv6
                .as_ref()
                .map(|(addr, _)| *addr == ip)
                .unwrap_or(false)
        })
    }

    /// Look up a member by MAC address.
    pub fn lookup_mac(&self, mac: &[u8; 6]) -> Option<&NetworkMember> {
        self.members.iter().find(|m| &m.mac == mac)
    }

    pub fn our_mac(&self, our_zt_address: &[u8; 5]) -> [u8; 6] {
        ethernet::derive_mac(our_zt_address, self.network_id)
    }

    /// Verify a peer's COM: qualifiers must agree with our own COM (same
    /// network, timestamp within tolerance) AND the COM's Ed25519 signature
    /// must verify against the network's actual controller key, with
    /// `signer_address` matching the network's structural controller
    /// address. Qualifier agreement alone only proves the peer *constructed*
    /// a COM that happens to match our expectations, not that the network
    /// controller ever issued it.
    ///
    /// `controller_verifying_key` is `None` when the controller's identity
    /// hasn't been resolved yet (e.g. no HELLO/WHOIS exchange with it yet) --
    /// in that case the COM is rejected rather than trusted on qualifiers
    /// alone.
    pub fn verify_peer_com(
        &self,
        peer_address: &[u8; 5],
        peer_com: &CertificateOfMembership,
        controller_address: &[u8; 5],
        controller_verifying_key: Option<&ed25519_dalek::VerifyingKey>,
    ) -> bool {
        // A COM issued to another member proves nothing about this peer.
        if peer_com.issued_to != *peer_address {
            return false;
        }
        let our = match &self.our_com {
            Some(our) => our,
            None => return false,
        };
        if !peer_com_agrees_with(our, peer_com) {
            return false;
        }
        let verifying_key = match controller_verifying_key {
            Some(key) => key,
            None => return false,
        };
        peer_com.signer_address == *controller_address
            && com_verify_signature(peer_com, verifying_key)
    }

    pub fn our_com_timestamp_qualifier(&self) -> Option<&ComQualifier> {
        self.our_com
            .as_ref()?
            .qualifiers
            .iter()
            .find(|q| q.id == COM_QUALIFIER_TIMESTAMP_ID)
    }

    /// Returns the proactive refresh margin derived from the COM lifetime.
    ///
    /// Exact zerotier-one refresh timing is still unknown in-tree. We use a
    /// bounded assumption based on the observed qualifier-0 lifetime:
    /// refresh during the final quarter of the lifetime, capped at 60s.
    pub fn our_com_refresh_margin_ms(&self) -> Option<u64> {
        let qualifier = self.our_com_timestamp_qualifier()?;
        Some(
            qualifier
                .max_delta
                .saturating_div(4)
                .clamp(1_000, COM_REFRESH_MARGIN_CAP_MS),
        )
    }

    pub fn our_com_refresh_due(&self, now_ms: u64) -> bool {
        let qualifier = match self.our_com_timestamp_qualifier() {
            Some(qualifier) => qualifier,
            None => return self.our_com.is_none(),
        };

        let refresh_margin = self.our_com_refresh_margin_ms().unwrap_or(0);
        let refresh_at = qualifier
            .value
            .saturating_add(qualifier.max_delta.saturating_sub(refresh_margin));
        now_ms >= refresh_at
    }
}

fn ipv4_in_prefix(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let prefix = prefix.min(32) as u32;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn ipv6_in_prefix(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let prefix = prefix.min(128) as u32;
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(ip) & mask) == (u128::from(network) & mask)
}

fn peer_com_agrees_with(ours: &CertificateOfMembership, theirs: &CertificateOfMembership) -> bool {
    for our_q in &ours.qualifiers {
        // `issued_to` is peer-specific and must not be compared across members.
        if our_q.id == 2 {
            continue;
        }
        match theirs.qualifiers.iter().find(|oq| oq.id == our_q.id) {
            None => return false,
            Some(other_q) => {
                let delta = our_q.value.abs_diff(other_q.value);
                if delta > our_q.max_delta {
                    return false;
                }
            }
        }
    }
    true
}

/// Check if two COMs agree: all qualifiers in `ours` must have a matching
/// qualifier (by ID) in `theirs` with |value difference| <= max_delta.
pub fn com_agrees_with(ours: &CertificateOfMembership, theirs: &CertificateOfMembership) -> bool {
    for our_q in &ours.qualifiers {
        match theirs.qualifiers.iter().find(|oq| oq.id == our_q.id) {
            None => return false,
            Some(other_q) => {
                let delta = our_q.value.abs_diff(other_q.value);
                if delta > our_q.max_delta {
                    return false;
                }
            }
        }
    }
    true
}

/// Verify a COM's Ed25519 signature.
///
/// The signed data is: qualifiers sorted by ID ascending, each serialized as
/// id(u64 BE) + value(u64 BE) + max_delta(u64 BE) concatenated.
pub fn com_verify_signature(
    com: &CertificateOfMembership,
    signer_verifying_key: &ed25519_dalek::VerifyingKey,
) -> bool {
    // Sort qualifiers by ID
    let mut sorted: Vec<&ComQualifier> = com.qualifiers.iter().collect();
    sorted.sort_by_key(|q| q.id);

    // Build signed data: each qualifier as (id, value, max_delta) in BE
    let mut signed_data = Vec::with_capacity(sorted.len() * 24);
    for q in &sorted {
        signed_data.extend_from_slice(&q.id.to_be_bytes());
        signed_data.extend_from_slice(&q.value.to_be_bytes());
        signed_data.extend_from_slice(&q.max_delta.to_be_bytes());
    }

    zerotier_crypto::signing::verify(signer_verifying_key, &signed_data, &com.signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn make_com(qualifiers: Vec<ComQualifier>) -> CertificateOfMembership {
        CertificateOfMembership {
            issued_to: [0; 5],
            qualifiers,
            signer_address: [0; 5],
            signature: [0; 96],
        }
    }

    /// Build a COM signed by `signing_key`, matching the wire format
    /// `com_verify_signature` checks (qualifiers sorted by ID ascending).
    fn signed_com(
        signing_key: &ed25519_dalek::SigningKey,
        signer_address: [u8; 5],
        qualifiers: Vec<ComQualifier>,
    ) -> CertificateOfMembership {
        let mut sorted = qualifiers.clone();
        sorted.sort_by_key(|q| q.id);
        let mut signed_data = Vec::with_capacity(sorted.len() * 24);
        for q in &sorted {
            signed_data.extend_from_slice(&q.id.to_be_bytes());
            signed_data.extend_from_slice(&q.value.to_be_bytes());
            signed_data.extend_from_slice(&q.max_delta.to_be_bytes());
        }
        let signature = zerotier_crypto::signing::sign(signing_key, &signed_data);
        CertificateOfMembership {
            issued_to: [0; 5],
            qualifiers,
            signer_address,
            signature,
        }
    }

    // === com_agrees_with tests ===

    #[test]
    fn agrees_with_matching_qualifiers() {
        let ours = make_com(vec![
            ComQualifier {
                id: 0,
                value: 1000,
                max_delta: 100,
            },
            ComQualifier {
                id: 1,
                value: 0xff,
                max_delta: 0,
            },
        ]);
        let theirs = make_com(vec![
            ComQualifier {
                id: 0,
                value: 1050,
                max_delta: 100,
            },
            ComQualifier {
                id: 1,
                value: 0xff,
                max_delta: 0,
            },
        ]);
        assert!(com_agrees_with(&ours, &theirs));
    }

    #[test]
    fn agrees_with_exact_delta_boundary() {
        let ours = make_com(vec![ComQualifier {
            id: 0,
            value: 1000,
            max_delta: 100,
        }]);
        let theirs = make_com(vec![ComQualifier {
            id: 0,
            value: 1100,
            max_delta: 100,
        }]);
        assert!(com_agrees_with(&ours, &theirs));
    }

    #[test]
    fn rejects_exceeding_delta() {
        let ours = make_com(vec![ComQualifier {
            id: 0,
            value: 1000,
            max_delta: 100,
        }]);
        let theirs = make_com(vec![ComQualifier {
            id: 0,
            value: 1101,
            max_delta: 100,
        }]);
        assert!(!com_agrees_with(&ours, &theirs));
    }

    #[test]
    fn rejects_missing_qualifier() {
        let ours = make_com(vec![
            ComQualifier {
                id: 0,
                value: 1000,
                max_delta: 100,
            },
            ComQualifier {
                id: 1,
                value: 0xff,
                max_delta: 0,
            },
        ]);
        let theirs = make_com(vec![
            ComQualifier {
                id: 0,
                value: 1000,
                max_delta: 100,
            },
            // Missing qualifier ID 1
        ]);
        assert!(!com_agrees_with(&ours, &theirs));
    }

    #[test]
    fn com_refresh_due_with_missing_com() {
        let net = NetworkMembership::new(1, 2800);
        assert!(net.our_com_refresh_due(1000));
    }

    #[test]
    fn com_refresh_due_before_expiry_with_bounded_margin() {
        let mut net = NetworkMembership::new(1, 2800);
        net.our_com = Some(make_com(vec![ComQualifier {
            id: COM_QUALIFIER_TIMESTAMP_ID,
            value: 1_000,
            max_delta: 360_000,
        }]));

        assert_eq!(net.our_com_refresh_margin_ms(), Some(60_000));
        assert!(!net.our_com_refresh_due(300_999));
        assert!(net.our_com_refresh_due(301_000));
    }

    #[test]
    fn com_refresh_margin_scales_for_short_lifetime() {
        let mut net = NetworkMembership::new(1, 2800);
        net.our_com = Some(make_com(vec![ComQualifier {
            id: COM_QUALIFIER_TIMESTAMP_ID,
            value: 5_000,
            max_delta: 20_000,
        }]));

        assert_eq!(net.our_com_refresh_margin_ms(), Some(5_000));
        assert!(!net.our_com_refresh_due(19_999));
        assert!(net.our_com_refresh_due(20_000));
    }

    #[test]
    fn agrees_with_empty_qualifiers() {
        let ours = make_com(vec![]);
        let theirs = make_com(vec![ComQualifier {
            id: 0,
            value: 999,
            max_delta: 0,
        }]);
        assert!(com_agrees_with(&ours, &theirs));
    }

    #[test]
    fn rejects_network_id_mismatch() {
        let ours = make_com(vec![ComQualifier {
            id: 1,
            value: 0xaabbccdd,
            max_delta: 0,
        }]);
        let theirs = make_com(vec![ComQualifier {
            id: 1,
            value: 0xaabbccde,
            max_delta: 0,
        }]);
        assert!(!com_agrees_with(&ours, &theirs));
    }

    // === com_verify_signature tests ===

    #[test]
    fn verify_valid_signature() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        // Build qualifiers
        let qualifiers = vec![
            ComQualifier {
                id: 0,
                value: 1711500000000,
                max_delta: 360000,
            },
            ComQualifier {
                id: 1,
                value: 0xff00000000abcdef,
                max_delta: 0,
            },
            ComQualifier {
                id: 2,
                value: 0xa0b1c2d3e4,
                max_delta: 0,
            },
        ];

        // Build signed data (qualifiers already sorted by ID)
        let mut signed_data = Vec::new();
        for q in &qualifiers {
            signed_data.extend_from_slice(&q.id.to_be_bytes());
            signed_data.extend_from_slice(&q.value.to_be_bytes());
            signed_data.extend_from_slice(&q.max_delta.to_be_bytes());
        }

        let signature = zerotier_crypto::signing::sign(&signing_key, &signed_data);

        let com = CertificateOfMembership {
            issued_to: [0; 5],
            qualifiers,
            signer_address: [0xa0, 0xb1, 0xc2, 0xd3, 0xe4],
            signature,
        };

        assert!(com_verify_signature(&com, &verifying_key));
    }

    #[test]
    fn reject_invalid_signature() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[0x43u8; 32]);
        let wrong_verifying = wrong_key.verifying_key();

        let qualifiers = vec![ComQualifier {
            id: 0,
            value: 100,
            max_delta: 10,
        }];

        let mut signed_data = Vec::new();
        for q in &qualifiers {
            signed_data.extend_from_slice(&q.id.to_be_bytes());
            signed_data.extend_from_slice(&q.value.to_be_bytes());
            signed_data.extend_from_slice(&q.max_delta.to_be_bytes());
        }

        let signature = zerotier_crypto::signing::sign(&signing_key, &signed_data);

        let com = CertificateOfMembership {
            issued_to: [0; 5],
            qualifiers,
            signer_address: [0; 5],
            signature,
        };

        assert!(!com_verify_signature(&com, &wrong_verifying));
    }

    #[test]
    fn verify_signature_sorts_by_id() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        // Qualifiers in sorted order for signing
        let sorted_qualifiers = vec![
            ComQualifier {
                id: 0,
                value: 100,
                max_delta: 10,
            },
            ComQualifier {
                id: 1,
                value: 200,
                max_delta: 0,
            },
            ComQualifier {
                id: 2,
                value: 300,
                max_delta: 0,
            },
        ];

        let mut signed_data = Vec::new();
        for q in &sorted_qualifiers {
            signed_data.extend_from_slice(&q.id.to_be_bytes());
            signed_data.extend_from_slice(&q.value.to_be_bytes());
            signed_data.extend_from_slice(&q.max_delta.to_be_bytes());
        }
        let signature = zerotier_crypto::signing::sign(&signing_key, &signed_data);

        // Create COM with qualifiers in UNSORTED order
        let com = CertificateOfMembership {
            issued_to: [0; 5],
            qualifiers: vec![
                ComQualifier {
                    id: 2,
                    value: 300,
                    max_delta: 0,
                },
                ComQualifier {
                    id: 0,
                    value: 100,
                    max_delta: 10,
                },
                ComQualifier {
                    id: 1,
                    value: 200,
                    max_delta: 0,
                },
            ],
            signer_address: [0; 5],
            signature,
        };

        // Should still verify because com_verify_signature sorts before verifying
        assert!(com_verify_signature(&com, &verifying_key));
    }

    // === NetworkMembership lookup tests ===

    #[test]
    fn lookup_ipv4_found() {
        let mut net = NetworkMembership::new(0xff00000000abcdef, 2800);
        net.members.push(NetworkMember {
            zt_address: [0xa0, 0xb1, 0xc2, 0xd3, 0xe4],
            mac: ethernet::derive_mac(&[0xa0, 0xb1, 0xc2, 0xd3, 0xe4], 0xff00000000abcdef),
            ipv4: Some((Ipv4Addr::new(10, 147, 20, 1), 24)),
            ipv6: None,
            authorized: true,
        });

        let member = net.lookup_ipv4(Ipv4Addr::new(10, 147, 20, 1));
        assert!(member.is_some());
        assert_eq!(member.unwrap().zt_address, [0xa0, 0xb1, 0xc2, 0xd3, 0xe4]);
    }

    #[test]
    fn lookup_ipv4_not_found() {
        let net = NetworkMembership::new(0xff00000000abcdef, 2800);
        assert!(net.lookup_ipv4(Ipv4Addr::new(10, 0, 0, 1)).is_none());
    }

    #[test]
    fn lookup_mac_found() {
        let mac = ethernet::derive_mac(&[0xa0, 0xb1, 0xc2, 0xd3, 0xe4], 0xff00000000abcdef);
        let mut net = NetworkMembership::new(0xff00000000abcdef, 2800);
        net.members.push(NetworkMember {
            zt_address: [0xa0, 0xb1, 0xc2, 0xd3, 0xe4],
            mac,
            ipv4: None,
            ipv6: None,
            authorized: true,
        });

        let member = net.lookup_mac(&mac);
        assert!(member.is_some());
        assert_eq!(member.unwrap().zt_address, [0xa0, 0xb1, 0xc2, 0xd3, 0xe4]);
    }

    #[test]
    fn lookup_mac_not_found() {
        let net = NetworkMembership::new(0xff00000000abcdef, 2800);
        assert!(net.lookup_mac(&[0xff; 6]).is_none());
    }

    #[test]
    fn our_mac_uses_derive_mac() {
        let net = NetworkMembership::new(0xff00000000abcdef, 2800);
        let addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let expected = ethernet::derive_mac(&addr, 0xff00000000abcdef);
        assert_eq!(net.our_mac(&addr), expected);
    }

    #[test]
    fn verify_peer_com_no_our_com() {
        let net = NetworkMembership::new(0xff00000000abcdef, 2800);
        let peer_com = make_com(vec![ComQualifier {
            id: 0,
            value: 1000,
            max_delta: 100,
        }]);
        assert!(!net.verify_peer_com(&[0x01; 5], &peer_com, &[0; 5], None));
    }

    #[test]
    fn verify_peer_com_with_matching_com() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
        let verifying_key = signing_key.verifying_key();
        let controller_address = [0xc0, 0xc1, 0xc2, 0xc3, 0xc4];

        let mut net = NetworkMembership::new(0xff00000000abcdef, 2800);
        net.our_com = Some(signed_com(
            &signing_key,
            controller_address,
            vec![
                ComQualifier {
                    id: 0,
                    value: 1000,
                    max_delta: 100,
                },
                ComQualifier {
                    id: 1,
                    value: 0xff,
                    max_delta: 0,
                },
            ],
        ));
        let mut peer_com = signed_com(
            &signing_key,
            controller_address,
            vec![
                ComQualifier {
                    id: 0,
                    value: 1050,
                    max_delta: 100,
                },
                ComQualifier {
                    id: 1,
                    value: 0xff,
                    max_delta: 0,
                },
            ],
        );
        peer_com.issued_to = [0x01; 5];
        assert!(net.verify_peer_com(
            &[0x01; 5],
            &peer_com,
            &controller_address,
            Some(&verifying_key)
        ));
        // The same COM proves nothing about a different peer.
        assert!(!net.verify_peer_com(
            &[0x02; 5],
            &peer_com,
            &controller_address,
            Some(&verifying_key)
        ));

        // Same qualifiers, but signed by a different key: signature no longer
        // matches, so it must be rejected even though qualifiers agree.
        let other_key = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
        let forged_com = signed_com(
            &other_key,
            controller_address,
            vec![
                ComQualifier {
                    id: 0,
                    value: 1050,
                    max_delta: 100,
                },
                ComQualifier {
                    id: 1,
                    value: 0xff,
                    max_delta: 0,
                },
            ],
        );
        assert!(!net.verify_peer_com(
            &[0x01; 5],
            &forged_com,
            &controller_address,
            Some(&verifying_key)
        ));

        // Same qualifiers and correctly signed, but claiming a signer address
        // that doesn't match the network's actual controller address.
        let wrong_signer_com = signed_com(
            &signing_key,
            [0x99; 5],
            vec![
                ComQualifier {
                    id: 0,
                    value: 1050,
                    max_delta: 100,
                },
                ComQualifier {
                    id: 1,
                    value: 0xff,
                    max_delta: 0,
                },
            ],
        );
        assert!(!net.verify_peer_com(
            &[0x01; 5],
            &wrong_signer_com,
            &controller_address,
            Some(&verifying_key)
        ));

        // Qualifiers agree and signature verifies, but the controller's
        // identity hasn't been resolved yet -- must fail closed.
        assert!(!net.verify_peer_com(&[0x01; 5], &peer_com, &controller_address, None));
    }

    #[test]
    fn verify_peer_com_does_not_compare_issued_to_across_members() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
        let verifying_key = signing_key.verifying_key();
        let controller_address = [0xc0, 0xc1, 0xc2, 0xc3, 0xc4];

        let mut net = NetworkMembership::new(0xff00000000abcdef, 2800);
        net.our_com = Some(signed_com(
            &signing_key,
            controller_address,
            vec![
                ComQualifier {
                    id: 0,
                    value: 1000,
                    max_delta: 100,
                },
                ComQualifier {
                    id: 1,
                    value: 0xff00000000abcdef,
                    max_delta: 0,
                },
                ComQualifier {
                    id: 2,
                    value: 0x00a0b1c2d3e4,
                    max_delta: 0,
                },
            ],
        ));
        let mut peer_com = signed_com(
            &signing_key,
            controller_address,
            vec![
                ComQualifier {
                    id: 0,
                    value: 1050,
                    max_delta: 100,
                },
                ComQualifier {
                    id: 1,
                    value: 0xff00000000abcdef,
                    max_delta: 0,
                },
                ComQualifier {
                    id: 2,
                    value: 0x00f0e1d2c3b4,
                    max_delta: 0,
                },
            ],
        );
        peer_com.issued_to = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4];
        assert!(net.verify_peer_com(
            &[0xf0, 0xe1, 0xd2, 0xc3, 0xb4],
            &peer_com,
            &controller_address,
            Some(&verifying_key)
        ));
    }

    #[test]
    fn lookup_ipv6_found() {
        let mut net = NetworkMembership::new(0xff00000000abcdef, 2800);
        let addr6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        net.members.push(NetworkMember {
            zt_address: [0xa0, 0xb1, 0xc2, 0xd3, 0xe4],
            mac: [0; 6],
            ipv4: None,
            ipv6: Some((addr6, 64)),
            authorized: true,
        });
        assert!(net.lookup_ipv6(addr6).is_some());
    }

    /// `RT` as ZeroTier One writes it: target (port = prefix), via (null
    /// for on-link), u16 flags, u16 metric, repeated.
    #[test]
    fn parse_routes_reads_the_upstream_layout() {
        let data = [
            0x04, 10, 147, 20, 0, 0, 24,   // target 10.147.20.0/24
            0x00, // on-link
            0, 0, 0, 0, // flags, metric
            0x04, 192, 168, 50, 0, 0, 24, // target 192.168.50.0/24
            0x04, 10, 147, 20, 1, 0, 0, // via 10.147.20.1
            0, 0, 0, 1, // flags, metric
        ];
        let routes = parse_routes(&data);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].target, IpAddr::V4(Ipv4Addr::new(10, 147, 20, 0)));
        assert_eq!(routes[0].prefix, 24);
        assert_eq!(routes[0].via, None);
        assert_eq!(
            routes[1].via,
            Some(IpAddr::V4(Ipv4Addr::new(10, 147, 20, 1)))
        );
        assert!(routes[1].contains(IpAddr::V4(Ipv4Addr::new(192, 168, 50, 9))));
        assert!(!routes[1].contains(IpAddr::V4(Ipv4Addr::new(192, 168, 51, 9))));
    }
}
