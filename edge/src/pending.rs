//! Which pending handshake to give up when too many are in progress.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// Handshakes in progress, in start order, each under its source IP.
///
/// At the cap, a newcomer evicts the oldest handshake of the source IP that holds the most
/// slots; between IPs holding equally many, the one whose oldest handshake is the oldest. A
/// flood from one IP then evicts only its own handshakes.
pub(crate) struct PendingHandshakes<T> {
    cap: usize,
    /// Oldest first; IPv4-mapped IPv6 addresses are stored as IPv4.
    entries: VecDeque<(IpAddr, T)>,
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
        self.entries.push_back((ip.to_canonical(), item));
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
        // In start order, the first handshake from an IP holding `most` slots is that IP's
        // oldest, and its IP is the one whose oldest is the oldest.
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
