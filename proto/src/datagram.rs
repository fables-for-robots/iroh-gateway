//! The UDP datagram format: one visitor packet travels as one or more QUIC datagrams.
//!
//! Every datagram starts with an 18-byte big-endian header: listener id `u32`, flow id `u64`,
//! packet id `u32`, fragment index `u8`, fragment count `u8`. The payload follows. Delivery is as
//! unreliable and unordered as UDP itself: a packet with a missing fragment is simply lost.

use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes, BytesMut};

pub const HEADER_LEN: usize = 18;
/// The largest UDP payload.
pub const MAX_PACKET: usize = 65_535;
pub const MAX_FRAGMENTS: usize = 64;
/// How long the fragments of one packet may take to arrive.
pub const REASSEMBLY_WINDOW: Duration = Duration::from_secs(1);
/// How many payload bytes reassembly holds for incomplete packets.
pub const REASSEMBLY_BYTES: usize = 4 * 1024 * 1024;
/// A flow is forgotten after this long without a packet in either direction.
pub const UDP_FLOW_IDLE: Duration = Duration::from_secs(60);
/// How many flows one side tracks; at the cap a new flow replaces the least recently used one.
pub const MAX_UDP_FLOWS: usize = 4096;

/// What one incomplete packet is assumed to cost besides its payload; bounds how many a flood of
/// tiny fragments can make [`Reassembler`] track.
const ENTRY_COST: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub listener_id: u32,
    pub flow_id: u64,
    pub packet_id: u32,
    pub index: u8,
    pub count: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DatagramError {
    #[error("datagram shorter than its header")]
    Short,
    #[error("invalid fragment numbers")]
    BadFragment,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SplitError {
    #[error("packet too large to send")]
    TooLarge,
    #[error("no room for a payload")]
    NoRoom,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0; HEADER_LEN];
        out[0..4].copy_from_slice(&self.listener_id.to_be_bytes());
        out[4..12].copy_from_slice(&self.flow_id.to_be_bytes());
        out[12..16].copy_from_slice(&self.packet_id.to_be_bytes());
        out[16] = self.index;
        out[17] = self.count;
        out
    }

    /// The header and the payload after it. `BadFragment` for count 0, count > `MAX_FRAGMENTS`,
    /// index >= count.
    pub fn decode(mut datagram: Bytes) -> Result<(Header, Bytes), DatagramError> {
        if datagram.len() < HEADER_LEN {
            return Err(DatagramError::Short);
        }
        let header = Header {
            listener_id: datagram.get_u32(),
            flow_id: datagram.get_u64(),
            packet_id: datagram.get_u32(),
            index: datagram.get_u8(),
            count: datagram.get_u8(),
        };
        if header.count == 0
            || usize::from(header.count) > MAX_FRAGMENTS
            || header.index >= header.count
        {
            return Err(DatagramError::BadFragment);
        }
        Ok((header, datagram))
    }
}

/// The datagrams that carry `payload`, each at most `max_datagram` bytes, in fragment order.
pub fn split(
    listener_id: u32,
    flow_id: u64,
    packet_id: u32,
    payload: &[u8],
    max_datagram: usize,
) -> Result<Vec<Bytes>, SplitError> {
    if max_datagram <= HEADER_LEN {
        return Err(SplitError::NoRoom);
    }
    if payload.len() > MAX_PACKET {
        return Err(SplitError::TooLarge);
    }
    let room = max_datagram - HEADER_LEN;
    let count = payload.len().div_ceil(room).max(1);
    if count > MAX_FRAGMENTS {
        return Err(SplitError::TooLarge);
    }
    let mut chunks = payload.chunks(room);
    Ok((0..count)
        .map(|index| {
            let chunk = chunks.next().unwrap_or_default();
            let header = Header {
                listener_id,
                flow_id,
                packet_id,
                index: index as u8,
                count: count as u8,
            };
            let mut datagram = BytesMut::with_capacity(HEADER_LEN + chunk.len());
            datagram.extend_from_slice(&header.encode());
            datagram.extend_from_slice(chunk);
            datagram.freeze()
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub listener_id: u32,
    pub flow_id: u64,
    pub payload: Bytes,
}

struct Entry {
    listener_id: u32,
    count: u8,
    first_seen: Instant,
    /// Arrival rank of the entry, the key in `Reassembler::order`.
    rank: u64,
    /// Bytes held; the sum of `parts`.
    bytes: usize,
    /// `(index, payload)` of the fragments that arrived, fewer than `count`.
    parts: Vec<(u8, Bytes)>,
}

/// Puts the fragments of packets back together, within a time window and a memory budget.
pub struct Reassembler {
    max_bytes: usize,
    window: Duration,
    buffered: usize,
    next_rank: u64,
    entries: HashMap<(u64, u32), Entry>,
    /// Entries, oldest first.
    order: BTreeMap<u64, (u64, u32)>,
}

impl Reassembler {
    pub fn new(max_bytes: usize, window: Duration) -> Self {
        Reassembler {
            max_bytes,
            window,
            buffered: 0,
            next_rank: 0,
            entries: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    /// Takes one decoded datagram; the whole packet once its last missing fragment arrives.
    ///
    /// Stored fragments are copied, so one never keeps its whole datagram's buffer alive.
    pub fn push(&mut self, header: Header, payload: Bytes, now: Instant) -> Option<Packet> {
        if header.count == 1 {
            return Some(Packet {
                listener_id: header.listener_id,
                flow_id: header.flow_id,
                payload,
            });
        }
        self.expire(now);
        let key = (header.flow_id, header.packet_id);
        if let Some(entry) = self.entries.get(&key) {
            if entry.count != header.count || entry.listener_id != header.listener_id {
                self.remove(&key);
                return None;
            }
            if entry.parts.iter().any(|(index, _)| *index == header.index) {
                return None;
            }
            if entry.bytes + payload.len() > MAX_PACKET {
                self.remove(&key);
                return None;
            }
        }
        // Every fragment but the last is full, and no packet ends in an empty one.
        if payload.is_empty() || payload.len() > MAX_PACKET || payload.len() > self.max_bytes {
            return None;
        }
        // Make room, oldest first. The packet being extended may be the oldest; dropping it
        // drops this fragment with it.
        // A fragment that completes its packet is not stored, so it needs no room.
        let is_new = !self.entries.contains_key(&key);
        let completes = self
            .entries
            .get(&key)
            .is_some_and(|entry| entry.parts.len() + 1 == usize::from(entry.count));
        let max_entries = (self.max_bytes / ENTRY_COST).max(1);
        while !completes
            && (self.buffered + payload.len() > self.max_bytes
                || (is_new && self.entries.len() >= max_entries))
        {
            let (_, oldest) = self.order.pop_first()?;
            self.forget(&oldest);
            if oldest == key {
                return None;
            }
        }
        let entry = self.entries.entry(key).or_insert_with(|| {
            let rank = self.next_rank;
            self.next_rank += 1;
            self.order.insert(rank, key);
            Entry {
                listener_id: header.listener_id,
                count: header.count,
                first_seen: now,
                rank,
                bytes: 0,
                parts: Vec::new(),
            }
        });
        entry.bytes += payload.len();
        entry
            .parts
            .push((header.index, Bytes::copy_from_slice(&payload)));
        self.buffered += payload.len();
        if entry.parts.len() < usize::from(entry.count) {
            return None;
        }
        let mut entry = self.remove(&key)?;
        entry.parts.sort_by_key(|(index, _)| *index);
        let mut whole = BytesMut::with_capacity(entry.bytes);
        for (_, part) in &entry.parts {
            whole.extend_from_slice(part);
        }
        Some(Packet {
            listener_id: entry.listener_id,
            flow_id: key.0,
            payload: whole.freeze(),
        })
    }

    /// Payload bytes held for incomplete packets.
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// Incomplete packets held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.buffered = 0;
    }

    /// Drops the entries first seen `window` or longer ago.
    fn expire(&mut self, now: Instant) {
        while let Some((_, key)) = self.order.first_key_value() {
            let key = *key;
            if now.saturating_duration_since(self.entries[&key].first_seen) < self.window {
                break;
            }
            self.remove(&key);
        }
    }

    /// Removes an entry from the map and the order index.
    fn remove(&mut self, key: &(u64, u32)) -> Option<Entry> {
        let entry = self.forget(key)?;
        self.order.remove(&entry.rank);
        Some(entry)
    }

    /// Removes an entry from the map only; the caller has taken it out of `order`.
    fn forget(&mut self, key: &(u64, u32)) -> Option<Entry> {
        let entry = self.entries.remove(key)?;
        self.buffered -= entry.bytes;
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use proptest::prelude::*;

    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;

    fn datagrams(flow: u64, packet: u32, len: usize, max: usize) -> Vec<(Header, Bytes)> {
        split(7, flow, packet, &vec![packet as u8; len], max)
            .unwrap()
            .into_iter()
            .map(|d| Header::decode(d).unwrap())
            .collect()
    }

    #[test]
    fn header_wire_format() {
        let h = Header {
            listener_id: 1,
            flow_id: 0x0102030405060708,
            packet_id: 0x0a0b0c0d,
            index: 2,
            count: 3,
        };
        assert_eq!(
            hex::encode(h.encode()),
            "0000000101020304050607080a0b0c0d0203"
        );
        let mut d = h.encode().to_vec();
        d.extend_from_slice(b"xy");
        assert_eq!(
            Header::decode(Bytes::from(d)).unwrap(),
            (h, Bytes::from_static(b"xy"))
        );
    }

    #[test]
    fn decode_refuses_short_and_bad_fragment_numbers() {
        let h = Header {
            listener_id: 1,
            flow_id: 1,
            packet_id: 1,
            index: 0,
            count: 1,
        };
        let short = Bytes::copy_from_slice(&h.encode()[..HEADER_LEN - 1]);
        assert_eq!(Header::decode(short), Err(DatagramError::Short));
        assert_eq!(Header::decode(Bytes::new()), Err(DatagramError::Short));
        for (index, count) in [(0, 0), (0, 65), (3, 3), (4, 3)] {
            let h = Header { index, count, ..h };
            assert_eq!(
                Header::decode(Bytes::copy_from_slice(&h.encode())),
                Err(DatagramError::BadFragment),
                "index {index} count {count}"
            );
        }
        let h = Header {
            index: 63,
            count: 64,
            ..h
        };
        assert!(Header::decode(Bytes::copy_from_slice(&h.encode())).is_ok());
    }

    #[test]
    fn small_packet_is_one_datagram() {
        let d = split(1, 2, 3, &[9; 100], 1200).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].len(), 118);
        let (h, p) = Header::decode(d[0].clone()).unwrap();
        assert_eq!((h.listener_id, h.flow_id, h.packet_id), (1, 2, 3));
        assert_eq!((h.index, h.count), (0, 1));
        assert_eq!(p.as_ref(), &[9; 100][..]);
    }

    #[test]
    fn empty_packet_is_one_datagram_of_header_length() {
        let d = split(1, 2, 3, &[], 1200).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].len(), HEADER_LEN);
        let (h, p) = Header::decode(d[0].clone()).unwrap();
        assert_eq!((h.index, h.count), (0, 1));
        assert!(p.is_empty());
        let mut r = Reassembler::new(8192, REASSEMBLY_WINDOW);
        let packet = r.push(h, p, Instant::now()).unwrap();
        assert!(packet.payload.is_empty());
    }

    #[test]
    fn packet_one_byte_over_is_two_datagrams() {
        let d = split(1, 2, 3, &[5; 1183], 1200).unwrap();
        assert_eq!(d.iter().map(Bytes::len).collect::<Vec<_>>(), [1200, 19]);
        let counts: Vec<_> = d
            .iter()
            .map(|d| Header::decode(d.clone()).unwrap().0)
            .map(|h| (h.index, h.count))
            .collect();
        assert_eq!(counts, [(0, 2), (1, 2)]);
    }

    #[test]
    fn split_refuses_what_cannot_be_sent() {
        assert_eq!(
            split(1, 1, 1, &[0; 10], HEADER_LEN),
            Err(SplitError::NoRoom)
        );
        assert_eq!(split(1, 1, 1, &[0; 10], 0), Err(SplitError::NoRoom));
        assert_eq!(
            split(1, 1, 1, &vec![0; MAX_PACKET + 1], 1200),
            Err(SplitError::TooLarge)
        );
        assert_eq!(
            split(1, 1, 1, &vec![0; 64 * 100 + 1], HEADER_LEN + 100),
            Err(SplitError::TooLarge)
        );
        assert_eq!(
            split(1, 1, 1, &vec![0; 64 * 100], HEADER_LEN + 100)
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            split(1, 1, 1, &vec![0; MAX_PACKET], 1200).unwrap().len(),
            56
        );
    }

    #[test]
    fn incomplete_packet_is_dropped_after_the_window() {
        let t = Instant::now();
        let mut r = Reassembler::new(8192, S(1));
        let d = datagrams(1, 1, 2500, 1200);
        assert_eq!(d.len(), 3);
        let last_len = d[2].1.len();
        assert!(r.push(d[0].0, d[0].1.clone(), t).is_none());
        assert!(r.push(d[1].0, d[1].1.clone(), t).is_none());
        assert_eq!(r.buffered(), 2 * (1200 - HEADER_LEN));
        assert!(r.push(d[2].0, d[2].1.clone(), t + S(1)).is_none());
        assert_eq!(r.buffered(), last_len);
    }

    #[test]
    fn packet_completes_just_inside_the_window() {
        let t = Instant::now();
        let mut r = Reassembler::new(8192, S(1));
        let d = datagrams(1, 1, 2500, 1200);
        assert!(r.push(d[0].0, d[0].1.clone(), t).is_none());
        assert!(r.push(d[1].0, d[1].1.clone(), t).is_none());
        let p = r
            .push(d[2].0, d[2].1.clone(), t + Duration::from_millis(999))
            .unwrap();
        assert_eq!(p.payload.len(), 2500);
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn budget_drops_the_oldest_incomplete_packets() {
        let t = Instant::now();
        let mut r = Reassembler::new(3000, S(1));
        let mut packets = Vec::new();
        for packet in 0..3u32 {
            let h = Header {
                listener_id: 7,
                flow_id: 1,
                packet_id: packet,
                index: 0,
                count: 2,
            };
            assert!(
                r.push(h, Bytes::from(vec![packet as u8; 1500]), t)
                    .is_none()
            );
            assert!(r.buffered() <= 3000);
            packets.push(h);
        }
        assert_eq!(r.buffered(), 3000);
        // The newest first: the last fragment of the dropped packet would only start a new one.
        let mut done = Vec::new();
        for h in packets.into_iter().rev() {
            let h = Header { index: 1, ..h };
            done.push(r.push(h, Bytes::from_static(b"z"), t).is_some());
        }
        assert_eq!(done, [true, true, false]);
    }

    #[test]
    fn fragment_larger_than_the_budget_is_dropped() {
        let mut r = Reassembler::new(1000, S(1));
        let h = Header {
            listener_id: 7,
            flow_id: 1,
            packet_id: 1,
            index: 0,
            count: 2,
        };
        assert!(
            r.push(h, Bytes::from(vec![0; 1001]), Instant::now())
                .is_none()
        );
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn packet_above_the_maximum_is_dropped() {
        let t = Instant::now();
        let mut r = Reassembler::new(1 << 20, S(1));
        let h = Header {
            listener_id: 7,
            flow_id: 1,
            packet_id: 1,
            index: 0,
            count: 3,
        };
        assert!(r.push(h, Bytes::from(vec![0; 40_000]), t).is_none());
        let h1 = Header { index: 1, ..h };
        assert!(r.push(h1, Bytes::from(vec![0; 40_000]), t).is_none());
        assert_eq!(r.buffered(), 0);
        let h2 = Header { index: 2, ..h };
        assert!(r.push(h2, Bytes::from_static(b"x"), t).is_none());
    }

    #[test]
    fn mismatched_count_or_listener_drops_the_packet() {
        let t = Instant::now();
        let h = Header {
            listener_id: 7,
            flow_id: 1,
            packet_id: 1,
            index: 0,
            count: 3,
        };
        for other in [
            Header {
                count: 4,
                index: 1,
                ..h
            },
            Header {
                listener_id: 8,
                index: 1,
                ..h
            },
        ] {
            let mut r = Reassembler::new(8192, S(1));
            assert!(r.push(h, Bytes::from_static(b"aa"), t).is_none());
            assert!(r.push(other, Bytes::from_static(b"bb"), t).is_none());
            assert_eq!(r.buffered(), 0);
            // The packet is gone: its remaining fragments cannot complete it.
            for index in [1, 2] {
                let h = Header { index, ..h };
                assert!(r.push(h, Bytes::from_static(b"cc"), t).is_none());
            }
        }
    }

    #[test]
    fn repeated_fragment_is_ignored() {
        let t = Instant::now();
        let mut r = Reassembler::new(8192, S(1));
        let h = Header {
            listener_id: 7,
            flow_id: 1,
            packet_id: 1,
            index: 0,
            count: 2,
        };
        assert!(r.push(h, Bytes::from_static(b"ab"), t).is_none());
        assert!(r.push(h, Bytes::from_static(b"XYZ"), t).is_none());
        assert_eq!(r.buffered(), 2);
        let p = r
            .push(Header { index: 1, ..h }, Bytes::from_static(b"cd"), t)
            .unwrap();
        assert_eq!(
            p,
            Packet {
                listener_id: 7,
                flow_id: 1,
                payload: Bytes::from_static(b"abcd")
            }
        );
    }

    #[test]
    fn packets_of_two_flows_with_the_same_packet_id_do_not_mix() {
        let t = Instant::now();
        let mut r = Reassembler::new(8192, S(1));
        let a = datagrams(1, 5, 2000, 1200);
        let b = datagrams(2, 5, 2000, 1200);
        let mut done = Vec::new();
        for (x, y) in a.iter().zip(&b) {
            done.extend(r.push(x.0, x.1.clone(), t));
            done.extend(r.push(y.0, y.1.clone(), t));
        }
        assert_eq!(done.len(), 2);
        assert_eq!(done[0].flow_id, 1);
        assert_eq!(done[1].flow_id, 2);
        assert!(done.iter().all(|p| p.payload.len() == 2000));
    }

    #[test]
    fn clear_forgets_everything() {
        let t = Instant::now();
        let mut r = Reassembler::new(8192, S(1));
        let d = datagrams(1, 1, 2500, 1200);
        r.push(d[0].0, d[0].1.clone(), t);
        r.clear();
        assert_eq!(r.buffered(), 0);
        assert!(r.push(d[1].0, d[1].1.clone(), t).is_none());
        assert!(r.push(d[2].0, d[2].1.clone(), t).is_none());
    }

    #[test]
    fn many_tiny_fragments_cannot_exhaust_memory() {
        let t = Instant::now();
        let mut r = Reassembler::new(REASSEMBLY_BYTES, S(1));
        for packet in 0..200_000u32 {
            let h = Header {
                listener_id: 7,
                flow_id: 1,
                packet_id: packet,
                index: 0,
                count: 2,
            };
            r.push(h, Bytes::from_static(b"x"), t);
        }
        assert!(r.buffered() <= REASSEMBLY_BYTES);
        assert!(r.len() <= REASSEMBLY_BYTES / 64);
    }

    /// A small deterministic shuffle; the tests need no more randomness than the seed.
    fn shuffle<T>(v: &mut [T], mut seed: u64) {
        for i in (1..v.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            v.swap(i, (seed % (i as u64 + 1)) as usize);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Duplicates may arrive anywhere before the packet completes; one that arrives after it
        /// starts a new, incomplete packet, which is correct (the window drops it), so the last
        /// fragment to arrive is never repeated.
        #[test]
        fn split_then_reassemble(
            payload in proptest::collection::vec(any::<u8>(), 0..=MAX_PACKET),
            max in 1100usize..=1500,
            seed in 1u64..,
            dups in proptest::collection::vec(any::<bool>(), 64),
        ) {
            let d = split(9, 0xdead_beef_0000_0001, 77, &payload, max).unwrap();
            prop_assert!(d.iter().all(|d| d.len() <= max));
            let mut order: Vec<usize> = (0..d.len()).collect();
            shuffle(&mut order, seed);
            let last = order.pop().unwrap();
            let mut body = order.clone();
            body.extend(order.iter().zip(&dups).filter(|(_, d)| **d).map(|(i, _)| *i));
            shuffle(&mut body, seed.rotate_left(17));
            body.push(last);

            let t = Instant::now();
            let mut r = Reassembler::new(REASSEMBLY_BYTES, REASSEMBLY_WINDOW);
            let mut out = Vec::new();
            for i in body {
                let (h, p) = Header::decode(d[i].clone()).unwrap();
                out.extend(r.push(h, p, t));
            }
            prop_assert_eq!(out.len(), 1);
            prop_assert_eq!(out[0].listener_id, 9);
            prop_assert_eq!(out[0].flow_id, 0xdead_beef_0000_0001);
            prop_assert_eq!(out[0].payload.as_ref(), payload.as_slice());
            prop_assert_eq!(r.buffered(), 0);
        }

        #[test]
        fn a_missing_fragment_yields_nothing(
            len in 1200usize..=MAX_PACKET,
            max in 1100usize..=1500,
            seed in 1u64..,
        ) {
            let d = split(9, 1, 1, &vec![3; len], max).unwrap();
            prop_assume!(d.len() >= 2);
            let skip = (seed % d.len() as u64) as usize;
            let mut order: Vec<usize> = (0..d.len()).filter(|i| *i != skip).collect();
            shuffle(&mut order, seed);
            let mut r = Reassembler::new(REASSEMBLY_BYTES, REASSEMBLY_WINDOW);
            for i in order {
                let (h, p) = Header::decode(d[i].clone()).unwrap();
                prop_assert!(r.push(h, p, Instant::now()).is_none());
            }
        }

        #[test]
        fn header_roundtrip(
            listener_id: u32,
            flow_id: u64,
            packet_id: u32,
            count in 1u8..=64,
            index_seed: u8,
            payload in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let h = Header { listener_id, flow_id, packet_id, index: index_seed % count, count };
            let mut d = h.encode().to_vec();
            d.extend_from_slice(&payload);
            let (got, p) = Header::decode(Bytes::from(d)).unwrap();
            prop_assert_eq!(got, h);
            prop_assert_eq!(p.as_ref(), payload.as_slice());
        }

        #[test]
        fn arbitrary_datagrams_never_panic_or_exceed_the_budget(
            datagrams in proptest::collection::vec(
                prop_oneof![
                    proptest::collection::vec(any::<u8>(), 0..=2000),
                    // Plausible headers, so that reassembly is reached.
                    (0u8..4, 0u32..4, 0u8..4, 1u8..4, proptest::collection::vec(any::<u8>(), 0..=2000))
                        .prop_map(|(flow, packet, index, count, rest)| {
                            let h = Header {
                                listener_id: 1,
                                flow_id: flow as u64,
                                packet_id: packet,
                                index,
                                count,
                            };
                            let mut d = h.encode().to_vec();
                            d.extend(rest);
                            d
                        }),
                ],
                0..=200,
            ),
        ) {
            let mut r = Reassembler::new(8192, REASSEMBLY_WINDOW);
            let t = Instant::now();
            for d in datagrams {
                if let Ok((h, p)) = Header::decode(Bytes::from(d)) {
                    r.push(h, p, t);
                }
                prop_assert!(r.buffered() <= 8192);
            }
        }
    }
}
