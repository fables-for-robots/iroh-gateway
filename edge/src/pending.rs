//! Which pending handshake to give up when too many are in progress.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};

/// Handshakes in progress, in start order, each under its source: an IPv4 address, or the /64
/// prefix of an IPv6 address, since one host commonly holds a whole /64.
///
/// At the cap, a newcomer evicts the oldest handshake of the source that holds the most slots;
/// between sources holding equally many, the one whose oldest handshake is the oldest. A flood
/// from one source then evicts only its own handshakes.
pub(crate) struct PendingHandshakes<T> {
    cap: usize,
    /// Oldest first, under [`source`] of the address.
    entries: VecDeque<(IpAddr, T)>,
}

/// The eviction key of `ip`: an IPv4 address (IPv4-mapped IPv6 included) as it is, an IPv6
/// address with its low 64 bits zeroed.
fn source(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
        v4 => v4,
    }
}

impl<T> PendingHandshakes<T> {
    pub(crate) fn new(cap: usize) -> Self {
        assert!(cap > 0, "a handshake cap of 0 admits nothing");
        Self {
            cap,
            entries: VecDeque::with_capacity(cap),
        }
    }

    /// Admits `item` from `ip`; returns the handshake it evicted if the set was full.
    pub(crate) fn admit(&mut self, ip: IpAddr, item: T) -> Option<T> {
        let evicted = if self.entries.len() >= self.cap {
            self.evict()
        } else {
            None
        };
        self.entries.push_back((source(ip), item));
        evicted
    }

    /// Removes the first handshake `matches` accepts, if any: one that has finished.
    pub(crate) fn remove(&mut self, mut matches: impl FnMut(&T) -> bool) -> Option<T> {
        let i = self.entries.iter().position(|(_, item)| matches(item))?;
        self.entries.remove(i).map(|(_, item)| item)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    fn evict(&mut self) -> Option<T> {
        let mut slots = HashMap::<IpAddr, usize>::new();
        for (ip, _) in &self.entries {
            *slots.entry(*ip).or_default() += 1;
        }
        let most = slots.values().copied().max()?;
        // In start order, the first handshake from a source holding `most` slots is that
        // source's oldest, and its source is the one whose oldest is the oldest.
        let i = self.entries.iter().position(|(ip, _)| slots[ip] == most)?;
        self.entries.remove(i).map(|(_, item)| item)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const CAP: usize = 64;

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n))
    }

    #[test]
    fn below_the_cap_nothing_is_evicted() {
        let mut set = PendingHandshakes::new(CAP);
        for n in 0..CAP as u32 {
            assert_eq!(set.admit(ip(n % 3), n), None);
        }
        assert_eq!(set.len(), CAP);
    }

    #[test]
    fn a_flood_from_one_ip_evicts_only_its_own() {
        let (a, b) = (ip(1), ip(2));
        let mut set = PendingHandshakes::new(CAP);
        assert_eq!(set.admit(a, 0), None);
        let mut evicted = Vec::new();
        for n in 1..=200 {
            evicted.extend(set.admit(b, n));
            assert!(set.len() <= CAP);
        }
        // B's first 63 fill the set; each of B's later handshakes evicts B's oldest.
        assert_eq!(evicted, (1..=200 - (CAP as u32 - 1)).collect::<Vec<_>>());
        assert_eq!(
            set.remove(|&n| n == 0),
            Some(0),
            "A's handshake was evicted"
        );
    }

    #[test]
    fn the_ip_with_the_most_slots_loses_its_oldest() {
        let (a, b, c) = (ip(1), ip(2), ip(3));
        let mut set = PendingHandshakes::new(CAP);
        // A's handshakes are older, so B's oldest is not the oldest overall.
        for n in 0..10 {
            assert_eq!(set.admit(a, n), None);
        }
        for n in 10..64 {
            assert_eq!(set.admit(b, n), None);
        }
        assert_eq!(set.admit(c, 64), Some(10));
        assert_eq!(set.len(), CAP);
    }

    #[test]
    fn tie_goes_to_the_ip_with_the_oldest_handshake() {
        let mut set = PendingHandshakes::new(CAP);
        for n in 0..CAP as u32 {
            assert_eq!(set.admit(ip(100 + n), n), None);
        }
        assert_eq!(set.admit(ip(1), 64), Some(0));
        // The next tie is between the 63 remaining single handshakes and the newcomer.
        assert_eq!(set.admit(ip(2), 65), Some(1));
    }

    #[test]
    fn ipv4_mapped_addresses_count_as_ipv4() {
        let a = Ipv4Addr::new(192, 0, 2, 1);
        let mapped = IpAddr::V6(a.to_ipv6_mapped());
        let (a, b) = (IpAddr::V4(a), ip(2));
        let mut set = PendingHandshakes::new(5);
        set.admit(b, 0);
        set.admit(b, 1);
        set.admit(a, 2);
        set.admit(mapped, 3);
        set.admit(mapped, 4);
        // As one address A holds 3 slots and loses its oldest; split, B's oldest would go.
        assert_eq!(set.admit(IpAddr::V6(Ipv6Addr::LOCALHOST), 5), Some(2));
    }

    #[test]
    fn an_ipv6_slash_64_counts_as_one_source() {
        let prefix: u128 = 0x2001_0db8_0000_0001 << 64;
        let other = IpAddr::V6(Ipv6Addr::from(0x2001_0db8_0000_0002_u128 << 64 | 1));
        let mut set = PendingHandshakes::new(CAP);
        assert_eq!(set.admit(other, 0), None);
        let mut evicted = Vec::new();
        for n in 1..=200u32 {
            let ip = IpAddr::V6(Ipv6Addr::from(prefix | u128::from(n) << 32 | 7));
            evicted.extend(set.admit(ip, n));
        }
        // The /64 evicts only its own handshakes, oldest first.
        assert_eq!(evicted, (1..=200 - (CAP as u32 - 1)).collect::<Vec<_>>());
        assert_eq!(
            set.remove(|&n| n == 0),
            Some(0),
            "the other prefix was evicted"
        );
    }

    #[test]
    fn ipv4_addresses_are_not_grouped() {
        // Neighbouring IPv4 addresses are separate sources: the tie rule applies.
        let mut set = PendingHandshakes::new(CAP);
        for n in 0..CAP as u32 {
            assert_eq!(set.admit(ip(n), n), None);
        }
        assert_eq!(set.admit(ip(1000), 64), Some(0));
    }

    #[test]
    fn removing_a_finished_handshake_frees_its_slot() {
        let mut set = PendingHandshakes::new(CAP);
        for n in 0..CAP as u32 {
            set.admit(ip(1), n);
        }
        assert_eq!(set.remove(|&n| n == 30), Some(30));
        assert_eq!(set.len(), CAP - 1);
        assert_eq!(set.remove(|&n| n == 30), None);
        assert_eq!(set.admit(ip(1), 64), None);
        assert_eq!(set.len(), CAP);
    }
}
