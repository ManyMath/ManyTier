/// Multicast group management: subscription tracking, group discovery, and frame replication.
///
/// Tracks which ZeroTier peers are subscribed to which multicast groups on each network,
/// supports querying subscribers with limits, expiring stale entries, and building
/// MULTICAST_LIKE payloads.
extern crate alloc;

use alloc::vec::Vec;
use zerotier_protocol::verbs::multicast::{MulticastGroup, MulticastLikePayload};

/// Key identifying a multicast group on a specific network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastGroupKey {
    pub network_id: u64,
    pub mac: [u8; 6],
    pub adi: u32,
}

/// A subscriber to a multicast group.
struct Subscriber {
    zt_address: [u8; 5],
    subscribed_at_ms: u64,
}

/// Manages multicast group subscriptions for all networks.
///
/// Uses a simple `Vec` of (group, subscribers) pairs since the number of
/// multicast groups per network is typically small (<50).
pub struct MulticastManager {
    subscriptions: Vec<(MulticastGroupKey, Vec<Subscriber>)>,
}

impl Default for MulticastManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MulticastManager {
    /// Create a new empty multicast manager.
    pub fn new() -> Self {
        MulticastManager {
            subscriptions: Vec::new(),
        }
    }

    /// Subscribe a peer to a multicast group. If the peer is already subscribed,
    /// updates the timestamp without duplicating.
    pub fn subscribe(
        &mut self,
        network_id: u64,
        mac: [u8; 6],
        adi: u32,
        zt_address: [u8; 5],
        now_ms: u64,
    ) {
        let key = MulticastGroupKey {
            network_id,
            mac,
            adi,
        };

        // Find existing group or create new
        let group_subs = match self.subscriptions.iter_mut().find(|(k, _)| k == &key) {
            Some((_, subs)) => subs,
            None => {
                self.subscriptions.push((key, Vec::new()));
                &mut self.subscriptions.last_mut().unwrap().1
            }
        };

        // Update existing subscriber or add new
        match group_subs.iter_mut().find(|s| s.zt_address == zt_address) {
            Some(existing) => {
                existing.subscribed_at_ms = now_ms;
            }
            None => {
                group_subs.push(Subscriber {
                    zt_address,
                    subscribed_at_ms: now_ms,
                });
            }
        }
    }

    /// Replace a peer's subscription snapshot for a network with the groups
    /// currently advertised in its MULTICAST_LIKE.
    pub fn replace_subscriptions(
        &mut self,
        network_id: u64,
        zt_address: [u8; 5],
        groups: &[MulticastGroup],
        now_ms: u64,
    ) {
        for (key, subs) in &mut self.subscriptions {
            if key.network_id != network_id {
                continue;
            }

            let keep = groups.iter().any(|group| {
                group.network_id == key.network_id && group.mac == key.mac && group.adi == key.adi
            });
            if !keep {
                subs.retain(|subscriber| subscriber.zt_address != zt_address);
            }
        }
        self.subscriptions.retain(|(_, subs)| !subs.is_empty());

        for group in groups {
            self.subscribe(group.network_id, group.mac, group.adi, zt_address, now_ms);
        }
    }

    /// Remove all subscriptions for a given peer address.
    pub fn unsubscribe_all(&mut self, zt_address: &[u8; 5]) {
        for (_, subs) in &mut self.subscriptions {
            subs.retain(|s| &s.zt_address != zt_address);
        }
        // Remove empty groups
        self.subscriptions.retain(|(_, subs)| !subs.is_empty());
    }

    /// Get subscribers for a multicast group, up to `limit`.
    /// Returns an empty list for unknown groups.
    pub fn get_subscribers(
        &self,
        network_id: u64,
        mac: &[u8; 6],
        adi: u32,
        limit: usize,
    ) -> Vec<[u8; 5]> {
        let key = MulticastGroupKey {
            network_id,
            mac: *mac,
            adi,
        };
        match self.subscriptions.iter().find(|(k, _)| k == &key) {
            Some((_, subs)) => subs.iter().take(limit).map(|s| s.zt_address).collect(),
            None => Vec::new(),
        }
    }

    /// Get replication targets for a multicast frame, excluding the sender.
    /// Returns up to `limit` subscriber addresses.
    pub fn get_replication_targets(
        &self,
        network_id: u64,
        mac: &[u8; 6],
        adi: u32,
        exclude: &[u8; 5],
        limit: usize,
    ) -> Vec<[u8; 5]> {
        let key = MulticastGroupKey {
            network_id,
            mac: *mac,
            adi,
        };
        match self.subscriptions.iter().find(|(k, _)| k == &key) {
            Some((_, subs)) => subs
                .iter()
                .filter(|s| &s.zt_address != exclude)
                .take(limit)
                .map(|s| s.zt_address)
                .collect(),
            None => Vec::new(),
        }
    }

    /// Remove subscriptions older than `max_age_ms` relative to `now_ms`.
    pub fn expire_old(&mut self, now_ms: u64, max_age_ms: u64) {
        for (_, subs) in &mut self.subscriptions {
            subs.retain(|s| now_ms.saturating_sub(s.subscribed_at_ms) <= max_age_ms);
        }
        // Remove empty groups
        self.subscriptions.retain(|(_, subs)| !subs.is_empty());
    }

    /// Return all multicast group keys for a given network.
    pub fn groups_for_network(&self, network_id: u64) -> Vec<MulticastGroupKey> {
        self.subscriptions
            .iter()
            .filter(|(k, _)| k.network_id == network_id)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Return the multicast groups a specific subscriber is currently a member of
    /// on a given network.
    pub fn groups_for_subscriber(
        &self,
        network_id: u64,
        zt_address: &[u8; 5],
    ) -> Vec<MulticastGroupKey> {
        self.subscriptions
            .iter()
            .filter(|(k, subs)| {
                k.network_id == network_id
                    && subs
                        .iter()
                        .any(|subscriber| &subscriber.zt_address == zt_address)
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Build a MULTICAST_LIKE payload for all groups this node is subscribed to
    /// on the given network.
    pub fn build_multicast_like(
        &self,
        network_id: u64,
        zt_address: &[u8; 5],
    ) -> MulticastLikePayload {
        let groups = self
            .groups_for_subscriber(network_id, zt_address)
            .into_iter()
            .map(|k| MulticastGroup {
                network_id: k.network_id,
                mac: k.mac,
                adi: k.adi,
            })
            .collect();
        MulticastLikePayload { groups }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn subscribe_adds_to_group() {
        let mut mgr = MulticastManager::new();
        mgr.subscribe(1, [0xff; 6], 100, [0x01, 0x02, 0x03, 0x04, 0x05], 1000);
        let subs = mgr.get_subscribers(1, &[0xff; 6], 100, 100);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0], [0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn subscribe_same_group_address_deduplicates() {
        let mut mgr = MulticastManager::new();
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05];
        mgr.subscribe(1, [0xff; 6], 100, addr, 1000);
        mgr.subscribe(1, [0xff; 6], 100, addr, 2000);
        let subs = mgr.get_subscribers(1, &[0xff; 6], 100, 100);
        assert_eq!(
            subs.len(),
            1,
            "duplicate subscribe must not create second entry"
        );
    }

    #[test]
    fn get_subscribers_with_limit() {
        let mut mgr = MulticastManager::new();
        for i in 0..10u8 {
            mgr.subscribe(1, [0xff; 6], 100, [0x00, 0x00, 0x00, 0x00, i], 1000);
        }
        let subs = mgr.get_subscribers(1, &[0xff; 6], 100, 3);
        assert_eq!(subs.len(), 3, "limit must be respected");
    }

    #[test]
    fn get_subscribers_unknown_group_returns_empty() {
        let mgr = MulticastManager::new();
        let subs = mgr.get_subscribers(999, &[0x01; 6], 42, 100);
        assert!(subs.is_empty());
    }

    #[test]
    fn unsubscribe_all_removes_from_all_groups() {
        let mut mgr = MulticastManager::new();
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05];
        mgr.subscribe(1, [0xff; 6], 100, addr, 1000);
        mgr.subscribe(1, [0x01; 6], 200, addr, 1000);
        mgr.subscribe(2, [0xff; 6], 100, addr, 1000);

        mgr.unsubscribe_all(&addr);

        assert!(mgr.get_subscribers(1, &[0xff; 6], 100, 100).is_empty());
        assert!(mgr.get_subscribers(1, &[0x01; 6], 200, 100).is_empty());
        assert!(mgr.get_subscribers(2, &[0xff; 6], 100, 100).is_empty());
    }

    #[test]
    fn unsubscribe_all_preserves_other_peers() {
        let mut mgr = MulticastManager::new();
        let addr1 = [0x01, 0x02, 0x03, 0x04, 0x05];
        let addr2 = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        mgr.subscribe(1, [0xff; 6], 100, addr1, 1000);
        mgr.subscribe(1, [0xff; 6], 100, addr2, 1000);

        mgr.unsubscribe_all(&addr1);

        let subs = mgr.get_subscribers(1, &[0xff; 6], 100, 100);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0], addr2);
    }

    #[test]
    fn build_multicast_like_for_network() {
        let mut mgr = MulticastManager::new();
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05];
        mgr.subscribe(1, [0xff; 6], 100, addr, 1000);
        mgr.subscribe(1, [0x01; 6], 200, addr, 1000);
        mgr.subscribe(2, [0xff; 6], 100, addr, 1000); // different network

        let like = mgr.build_multicast_like(1, &addr);
        assert_eq!(like.groups.len(), 2, "should only include network 1 groups");
        assert!(like.groups.iter().all(|g| g.network_id == 1));
    }

    #[test]
    fn expire_old_removes_stale() {
        let mut mgr = MulticastManager::new();
        let addr1 = [0x01, 0x02, 0x03, 0x04, 0x05];
        let addr2 = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        mgr.subscribe(1, [0xff; 6], 100, addr1, 1000); // old
        mgr.subscribe(1, [0xff; 6], 100, addr2, 5000); // recent

        // expire anything older than 3000ms at time 6000
        mgr.expire_old(6000, 3000);

        let subs = mgr.get_subscribers(1, &[0xff; 6], 100, 100);
        assert_eq!(subs.len(), 1, "stale entry should be removed");
        assert_eq!(subs[0], addr2);
    }

    #[test]
    fn expire_old_keeps_fresh() {
        let mut mgr = MulticastManager::new();
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05];
        mgr.subscribe(1, [0xff; 6], 100, addr, 5000);

        mgr.expire_old(6000, 3000);

        let subs = mgr.get_subscribers(1, &[0xff; 6], 100, 100);
        assert_eq!(subs.len(), 1, "fresh entry should remain");
    }

    #[test]
    fn get_replication_targets_excludes_sender() {
        let mut mgr = MulticastManager::new();
        let sender = [0x01, 0x02, 0x03, 0x04, 0x05];
        let peer1 = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        let peer2 = [0x0f, 0x10, 0x11, 0x12, 0x13];
        mgr.subscribe(1, [0xff; 6], 100, sender, 1000);
        mgr.subscribe(1, [0xff; 6], 100, peer1, 1000);
        mgr.subscribe(1, [0xff; 6], 100, peer2, 1000);

        let targets = mgr.get_replication_targets(1, &[0xff; 6], 100, &sender, 100);
        assert_eq!(targets.len(), 2);
        assert!(!targets.contains(&sender));
        assert!(targets.contains(&peer1));
        assert!(targets.contains(&peer2));
    }

    #[test]
    fn get_replication_targets_respects_limit() {
        let mut mgr = MulticastManager::new();
        let sender = [0x01, 0x02, 0x03, 0x04, 0x05];
        for i in 0..10u8 {
            mgr.subscribe(1, [0xff; 6], 100, [0x0a, 0x0b, 0x0c, 0x0d, i], 1000);
        }
        mgr.subscribe(1, [0xff; 6], 100, sender, 1000);

        let targets = mgr.get_replication_targets(1, &[0xff; 6], 100, &sender, 5);
        assert_eq!(targets.len(), 5);
        assert!(!targets.contains(&sender));
    }

    #[test]
    fn get_replication_targets_unknown_group() {
        let mgr = MulticastManager::new();
        let targets = mgr.get_replication_targets(999, &[0xff; 6], 42, &[0x01; 5], 100);
        assert!(targets.is_empty());
    }

    #[test]
    fn groups_for_network_filters_correctly() {
        let mut mgr = MulticastManager::new();
        let addr = [0x01; 5];
        mgr.subscribe(1, [0xff; 6], 100, addr, 1000);
        mgr.subscribe(1, [0x01; 6], 200, addr, 1000);
        mgr.subscribe(2, [0xff; 6], 100, addr, 1000);

        let groups = mgr.groups_for_network(1);
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|g| g.network_id == 1));

        let groups2 = mgr.groups_for_network(2);
        assert_eq!(groups2.len(), 1);

        let groups3 = mgr.groups_for_network(999);
        assert!(groups3.is_empty());
    }

    #[test]
    fn subscribe_updates_timestamp() {
        let mut mgr = MulticastManager::new();
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05];
        mgr.subscribe(1, [0xff; 6], 100, addr, 1000);
        mgr.subscribe(1, [0xff; 6], 100, addr, 5000); // update timestamp

        // After expiring at 6000 with max_age 3000, the entry should survive
        // because timestamp was updated to 5000
        mgr.expire_old(6000, 3000);
        let subs = mgr.get_subscribers(1, &[0xff; 6], 100, 100);
        assert_eq!(subs.len(), 1, "subscribe should update timestamp");
    }

    #[test]
    fn replace_subscriptions_prunes_absent_groups() {
        let mut mgr = MulticastManager::new();
        let addr = [0x01, 0x02, 0x03, 0x04, 0x05];
        mgr.subscribe(1, [0xff; 6], 100, addr, 1000);
        mgr.subscribe(1, [0x01; 6], 200, addr, 1000);

        mgr.replace_subscriptions(
            1,
            addr,
            &[MulticastGroup {
                network_id: 1,
                mac: [0x01; 6],
                adi: 200,
            }],
            2000,
        );

        assert!(mgr.get_subscribers(1, &[0xff; 6], 100, 10).is_empty());
        assert_eq!(mgr.get_subscribers(1, &[0x01; 6], 200, 10), vec![addr]);
    }
}
