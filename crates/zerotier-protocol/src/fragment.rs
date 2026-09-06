//! Fragment reassembly buffer for ZeroTier V1 fragmented packets.
//!
//! ZeroTier One sends a packet larger than the physical MTU as a *head* (the
//! first `mtu` bytes of the armored packet, with `FLAG_FRAGMENTED` set in its
//! header) followed by up to six Fragment packets numbered 1..n-1
//! (node/Switch.cpp `_sendViaSpecificPath`; fragment 0 is never sent, the
//! head takes its place). The reassembly buffer collects the head and the
//! fragments keyed by packet ID and returns the complete packet once all
//! pieces arrive. Stale entries are evicted after a configurable timeout.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::constants::{FRAGMENT_INDICATOR, ZT_MAX_PACKET_FRAGMENTS, ZT_PROTO_MIN_FRAGMENT_LENGTH};
use crate::header::PacketHeader;

struct FragmentSlot {
    head: Option<Vec<u8>>,
    /// Index 0 is unused: fragment 0 is the head.
    fragments: [Option<Vec<u8>>; ZT_MAX_PACKET_FRAGMENTS],
    /// Total pieces including the head; 0 until a fragment says.
    total_expected: u8,
    received_fragments: u8,
    created_at: u64,
}

impl FragmentSlot {
    fn new(now_ms: u64) -> Self {
        const NONE: Option<Vec<u8>> = None;
        FragmentSlot {
            head: None,
            fragments: [NONE; ZT_MAX_PACKET_FRAGMENTS],
            total_expected: 0,
            received_fragments: 0,
            created_at: now_ms,
        }
    }

    fn is_complete(&self) -> bool {
        self.head.is_some()
            && self.total_expected > 1
            && self.received_fragments + 1 >= self.total_expected
    }

    fn assemble(self) -> Vec<u8> {
        let mut assembled = self.head.unwrap_or_default();
        for data in self
            .fragments
            .iter()
            .take(self.total_expected as usize)
            .skip(1)
            .flatten()
        {
            assembled.extend_from_slice(data);
        }
        assembled
    }
}

/// Reassembly buffer that collects packet heads and fragments and returns
/// complete packets.
pub struct ReassemblyBuffer {
    pending: BTreeMap<u64, FragmentSlot>,
    max_pending: usize,
}

impl ReassemblyBuffer {
    /// Create a new reassembly buffer with the given maximum pending entries.
    pub fn new(max_pending: usize) -> Self {
        ReassemblyBuffer {
            pending: BTreeMap::new(),
            max_pending,
        }
    }

    fn slot(&mut self, packet_id: u64, now_ms: u64) -> &mut FragmentSlot {
        // Evict oldest if at capacity
        if !self.pending.contains_key(&packet_id) && self.pending.len() >= self.max_pending {
            let oldest_id = self
                .pending
                .iter()
                .min_by_key(|(_, slot)| slot.created_at)
                .map(|(&id, _)| id);
            if let Some(id) = oldest_id {
                self.pending.remove(&id);
            }
        }
        self.pending
            .entry(packet_id)
            .or_insert_with(|| FragmentSlot::new(now_ms))
    }

    fn complete(&mut self, packet_id: u64) -> Option<Vec<u8>> {
        if self.pending.get(&packet_id)?.is_complete() {
            self.pending.remove(&packet_id).map(FragmentSlot::assemble)
        } else {
            None
        }
    }

    /// Insert the head of a fragmented packet (the packet whose header has
    /// `FLAG_FRAGMENTED` set). Returns the reassembled packet if every
    /// fragment has already arrived.
    pub fn insert_head(&mut self, packet_id: u64, head: Vec<u8>, now_ms: u64) -> Option<Vec<u8>> {
        let slot = self.slot(packet_id, now_ms);
        if slot.head.is_none() {
            slot.head = Some(head);
        }
        self.complete(packet_id)
    }

    /// Insert a fragment. Returns the reassembled packet if the head and all
    /// other fragments have arrived.
    ///
    /// `packet_id`: identifies which packet this fragment belongs to.
    /// `fragment_number`: 1-based index of this fragment (0 is the head and
    /// is rejected, as upstream does).
    /// `total_fragments`: total number of pieces including the head.
    /// `data`: the fragment payload bytes.
    /// `now_ms`: current monotonic time in milliseconds.
    pub fn insert(
        &mut self,
        packet_id: u64,
        fragment_number: u8,
        total_fragments: u8,
        data: Vec<u8>,
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        if total_fragments < 2
            || total_fragments as usize > ZT_MAX_PACKET_FRAGMENTS
            || fragment_number == 0
            || fragment_number >= total_fragments
        {
            return None;
        }

        let slot = self.slot(packet_id, now_ms);
        if slot.total_expected == 0 {
            slot.total_expected = total_fragments;
        } else if slot.total_expected != total_fragments {
            return None; // disagrees with the fragments already held
        }

        let idx = fragment_number as usize;
        if slot.fragments[idx].is_none() {
            slot.fragments[idx] = Some(data);
            slot.received_fragments += 1;
        }

        self.complete(packet_id)
    }

    /// Evict stale entries older than `timeout_ms`.
    pub fn evict_stale(&mut self, now_ms: u64, timeout_ms: u64) {
        self.pending
            .retain(|_, slot| now_ms.saturating_sub(slot.created_at) < timeout_ms);
    }
}

/// Split an armored ZeroTier packet into the pieces that fit within `mtu`:
/// the head (the first `mtu` bytes, sent as an ordinary packet) followed by
/// Fragment packets numbered 1..n-1, matching ZeroTierOne node/Switch.cpp
/// `_sendViaSpecificPath`. Fragments carry hop count 0 like upstream's
/// `Packet::Fragment::init`.
///
/// A packet that fits is returned as is. The caller must have set
/// `FLAG_FRAGMENTED` in the header *before* armoring a packet that needs
/// splitting, since the flags byte feeds the MAC.
pub fn fragment_packet(packet: &[u8], mtu: usize) -> Option<Vec<Vec<u8>>> {
    if packet.len() <= mtu {
        return Some(alloc::vec![packet.to_vec()]);
    }
    if mtu <= ZT_PROTO_MIN_FRAGMENT_LENGTH {
        return None;
    }

    let header = PacketHeader::from_bytes(packet)?;
    let fragment_payload = mtu - ZT_PROTO_MIN_FRAGMENT_LENGTH;
    let remaining = packet.len() - mtu;
    let fragment_count = remaining.div_ceil(fragment_payload);
    let total = fragment_count + 1;
    if total > ZT_MAX_PACKET_FRAGMENTS {
        return None;
    }

    let packet_id = header.packet_id();
    let dest = header.dest_address();

    let mut pieces = Vec::with_capacity(total);
    pieces.push(packet[..mtu].to_vec());
    let mut start = mtu;
    for fragment_number in 1..total {
        let end = core::cmp::min(start + fragment_payload, packet.len());
        let payload = &packet[start..end];

        let mut fragment = Vec::with_capacity(ZT_PROTO_MIN_FRAGMENT_LENGTH + payload.len());
        fragment.extend_from_slice(&packet_id.to_be_bytes());
        fragment.extend_from_slice(&dest);
        fragment.push(FRAGMENT_INDICATOR);
        fragment.push(((total as u8) << 4) | fragment_number as u8);
        fragment.push(0); // hops
        fragment.extend_from_slice(payload);
        pieces.push(fragment);
        start = end;
    }

    Some(pieces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn head_then_fragment_in_order() {
        let mut buf = ReassemblyBuffer::new(256);
        assert!(buf.insert_head(1, vec![0x01, 0x02], 100).is_none());
        let result = buf.insert(1, 1, 2, vec![0x03, 0x04], 100);
        assert_eq!(result.unwrap(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn fragments_before_head() {
        let mut buf = ReassemblyBuffer::new(256);
        assert!(buf.insert(1, 2, 3, vec![0x05], 100).is_none());
        assert!(buf.insert(1, 1, 3, vec![0x03, 0x04], 100).is_none());
        let result = buf.insert_head(1, vec![0x01, 0x02], 100);
        assert_eq!(result.unwrap(), vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn returns_none_until_all_arrive() {
        let mut buf = ReassemblyBuffer::new(256);
        assert!(buf.insert_head(1, vec![0x01], 100).is_none());
        assert!(buf.insert(1, 2, 3, vec![0x03], 100).is_none());
        let result = buf.insert(1, 1, 3, vec![0x02], 100);
        assert_eq!(result.unwrap(), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn duplicate_fragment_ignored() {
        let mut buf = ReassemblyBuffer::new(256);
        assert!(buf.insert(1, 1, 3, vec![0x02], 100).is_none());
        assert!(buf.insert(1, 1, 3, vec![0xFF], 100).is_none());
        assert!(buf.insert_head(1, vec![0x01], 100).is_none());
        let result = buf.insert(1, 2, 3, vec![0x03], 100);
        assert_eq!(result.unwrap(), vec![0x01, 0x02, 0x03]);
    }

    /// Fragment 0 is the head and never arrives as a Fragment packet
    /// (ZeroTierOne node/Switch.cpp requires `fragmentNumber > 0`).
    #[test]
    fn fragment_zero_and_single_piece_series_are_rejected() {
        let mut buf = ReassemblyBuffer::new(256);
        assert!(buf.insert(1, 0, 2, vec![0x01], 100).is_none());
        assert!(buf.insert(1, 1, 1, vec![0x01], 100).is_none());
        assert!(buf.insert(1, 2, 2, vec![0x01], 100).is_none());
        assert!(buf.pending.is_empty());
    }

    #[test]
    fn total_mismatch_is_ignored() {
        let mut buf = ReassemblyBuffer::new(256);
        assert!(buf.insert(1, 1, 3, vec![0x02], 100).is_none());
        assert!(buf.insert(1, 1, 2, vec![0x02], 100).is_none());
        assert!(buf.insert_head(1, vec![0x01], 100).is_none());
        assert_eq!(buf.pending.len(), 1);
    }

    #[test]
    fn evicts_stale_entries() {
        let mut buf = ReassemblyBuffer::new(256);
        buf.insert(1, 1, 2, vec![0x01], 100);
        buf.insert(2, 1, 2, vec![0x01], 5000);
        buf.evict_stale(6000, 2000);
        assert!(buf.insert_head(1, vec![0x00], 6000).is_none());
        assert_eq!(
            buf.insert_head(2, vec![0x00], 6000).unwrap(),
            vec![0x00, 0x01]
        );
    }

    #[test]
    fn evicts_oldest_at_capacity() {
        let mut buf = ReassemblyBuffer::new(2);
        buf.insert(1, 1, 2, vec![0x01], 100);
        buf.insert(2, 1, 2, vec![0x02], 200);
        buf.insert(3, 1, 2, vec![0x03], 300);
        assert!(!buf.pending.contains_key(&1));
        assert!(buf.pending.contains_key(&2));
        assert!(buf.pending.contains_key(&3));
    }

    fn armored_looking_packet(len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; len];
        packet[0..8].copy_from_slice(&0x0102030405060708u64.to_be_bytes());
        packet[8..13].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        packet[13..18].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);
        packet[18] = 0x48; // cipher suite 1, FLAG_FRAGMENTED
        for (i, b) in packet.iter_mut().enumerate().skip(28) {
            *b = i as u8;
        }
        packet
    }

    #[test]
    fn small_packet_is_not_fragmented() {
        let packet = armored_looking_packet(100);
        let pieces = fragment_packet(&packet, 1432).unwrap();
        assert_eq!(pieces, vec![packet]);
    }

    /// Head is the first `mtu` bytes verbatim; fragments are numbered from
    /// 1 with the total in the high nibble and hop count 0.
    #[test]
    fn fragment_packet_emits_head_and_numbered_fragments() {
        let packet = armored_looking_packet(3000);
        let mtu = 1432;
        let pieces = fragment_packet(&packet, mtu).unwrap();
        assert_eq!(pieces.len(), 3);
        assert_eq!(pieces[0], packet[..mtu].to_vec());
        for (n, fragment) in pieces.iter().enumerate().skip(1) {
            assert_eq!(&fragment[0..8], &packet[0..8]);
            assert_eq!(&fragment[8..13], &packet[8..13]);
            assert_eq!(fragment[13], FRAGMENT_INDICATOR);
            assert_eq!(fragment[14], (3 << 4) | n as u8);
            assert_eq!(fragment[15], 0);
            assert!(fragment.len() <= mtu);
        }
        assert_eq!(pieces[1].len(), mtu);

        let mut buf = ReassemblyBuffer::new(4);
        let mut result = buf.insert(0x0102030405060708, 2, 3, pieces[2][16..].to_vec(), 0);
        assert!(result.is_none());
        result = buf.insert_head(0x0102030405060708, pieces[0].clone(), 0);
        assert!(result.is_none());
        result = buf.insert(0x0102030405060708, 1, 3, pieces[1][16..].to_vec(), 0);
        assert_eq!(result.unwrap(), packet);
    }

    #[test]
    fn fragment_packet_rejects_too_many_pieces() {
        let packet = armored_looking_packet(20_000);
        assert!(fragment_packet(&packet, 1432).is_none());
    }
}
