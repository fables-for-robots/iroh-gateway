//! A bounded map that replaces its least recently used entry at capacity and gives up its idle
//! entries on request. It is a plain data structure: the caller passes the time and decides when
//! to expire.

use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
    time::{Duration, Instant},
};

struct Slot<V> {
    value: V,
    used: Instant,
    /// Tie-breaker among equal `used`: the entry touched first goes first.
    seq: u64,
}

pub struct IdleMap<K, V> {
    capacity: usize,
    idle: Duration,
    next_seq: u64,
    entries: HashMap<K, Slot<V>>,
    /// Keys, least recently used first.
    order: BTreeMap<(Instant, u64), K>,
}

impl<K: Hash + Eq + Clone, V> IdleMap<K, V> {
    /// Panics if `capacity` is 0.
    pub fn new(capacity: usize, idle: Duration) -> Self {
        assert!(capacity > 0, "an IdleMap needs room for one entry");
        IdleMap {
            capacity,
            idle,
            next_seq: 0,
            entries: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Without marking it used.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|slot| &slot.value)
    }

    /// Marks the entry used at `now`.
    pub fn touch(&mut self, key: &K, now: Instant) -> Option<&mut V> {
        let slot = self.entries.get_mut(key)?;
        let k = self.order.remove(&(slot.used, slot.seq))?;
        slot.used = now;
        slot.seq = self.next_seq;
        self.next_seq += 1;
        self.order.insert((now, slot.seq), k);
        Some(&mut slot.value)
    }

    /// Inserts as used at `now`. Returns what it pushed out: the entry that had this key, or, when
    /// the map was full, the least recently used one.
    pub fn insert(&mut self, key: K, value: V, now: Instant) -> Option<(K, V)> {
        let pushed = match self.remove(&key) {
            Some(old) => Some((key.clone(), old)),
            None if self.entries.len() >= self.capacity => self.pop_oldest(),
            None => None,
        };
        let seq = self.next_seq;
        self.next_seq += 1;
        self.order.insert((now, seq), key.clone());
        self.entries.insert(
            key,
            Slot {
                value,
                used: now,
                seq,
            },
        );
        pushed
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let slot = self.entries.remove(key)?;
        self.order.remove(&(slot.used, slot.seq));
        Some(slot.value)
    }

    /// Removes and returns the entries `keep` refuses.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) -> Vec<(K, V)> {
        let refused: Vec<K> = self
            .entries
            .iter()
            .filter(|(k, slot)| !keep(k, &slot.value))
            .map(|(k, _)| k.clone())
            .collect();
        refused
            .into_iter()
            .filter_map(|k| self.remove(&k).map(|v| (k, v)))
            .collect()
    }

    /// Removes and returns every entry not used for `idle` or longer at `now`, least recently
    /// used first.
    pub fn expire(&mut self, now: Instant) -> Vec<(K, V)> {
        let mut gone = Vec::new();
        while let Some(((used, _), _)) = self.order.first_key_value() {
            if now.saturating_duration_since(*used) < self.idle {
                break;
            }
            gone.extend(self.pop_oldest());
        }
        gone
    }

    /// When the least recently used entry becomes idle.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.order
            .first_key_value()
            .map(|((used, _), _)| *used + self.idle)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    fn pop_oldest(&mut self) -> Option<(K, V)> {
        let (_, key) = self.order.pop_first()?;
        let slot = self.entries.remove(&key)?;
        Some((key, slot.value))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn at_capacity_the_least_recently_used_entry_is_replaced() {
        let t = Instant::now();
        let mut m = IdleMap::new(2, S(60));
        assert_eq!(m.insert("a", 1, t), None);
        assert_eq!(m.insert("b", 2, t + S(1)), None);
        m.touch(&"a", t + S(2)).unwrap();
        assert_eq!(m.insert("c", 3, t + S(3)), Some(("b", 2)));
        assert_eq!(m.len(), 2);
        assert_eq!(m.get(&"a"), Some(&1));
        assert_eq!(m.get(&"b"), None);
    }

    #[test]
    fn ties_go_to_the_entry_touched_first() {
        let t = Instant::now();
        let mut m = IdleMap::new(2, S(60));
        m.insert("a", 1, t);
        m.insert("b", 2, t);
        assert_eq!(m.insert("c", 3, t), Some(("a", 1)));
    }

    #[test]
    fn inserting_an_existing_key_returns_the_old_entry_and_evicts_nothing_else() {
        let t = Instant::now();
        let mut m = IdleMap::new(2, S(60));
        m.insert("a", 1, t);
        m.insert("b", 2, t + S(1));
        assert_eq!(m.insert("a", 10, t + S(2)), Some(("a", 1)));
        assert_eq!(m.len(), 2);
        assert_eq!(m.get(&"a"), Some(&10));
        assert_eq!(m.get(&"b"), Some(&2));
        // "b" is now the least recently used.
        assert_eq!(m.insert("c", 3, t + S(3)), Some(("b", 2)));
    }

    #[test]
    fn expire_returns_exactly_the_idle_entries() {
        let t = Instant::now();
        let mut m = IdleMap::new(8, S(60));
        m.insert("a", 1, t);
        m.insert("b", 2, t + S(30));
        assert_eq!(m.next_expiry(), Some(t + S(60)));
        assert_eq!(m.expire(t + S(59)), vec![]);
        assert_eq!(m.expire(t + S(60)), vec![("a", 1)]);
        assert_eq!(m.next_expiry(), Some(t + S(90)));
        assert_eq!(m.len(), 1);
        assert_eq!(m.expire(t + S(90)), vec![("b", 2)]);
        assert!(m.is_empty());
        assert_eq!(m.next_expiry(), None);
    }

    #[test]
    fn touch_postpones_expiry_and_get_does_not() {
        let t = Instant::now();
        let mut m = IdleMap::new(8, S(60));
        m.insert("a", 1, t);
        m.insert("b", 2, t);
        *m.touch(&"a", t + S(50)).unwrap() += 1;
        assert_eq!(m.get(&"b"), Some(&2));
        assert_eq!(m.expire(t + S(60)), vec![("b", 2)]);
        assert_eq!(m.get(&"a"), Some(&2));
        assert_eq!(m.next_expiry(), Some(t + S(110)));
        assert!(m.touch(&"missing", t).is_none());
    }

    #[test]
    fn retain_returns_what_it_removed() {
        let t = Instant::now();
        let mut m = IdleMap::new(8, S(60));
        for (i, k) in ["a", "b", "c", "d"].into_iter().enumerate() {
            m.insert(k, i, t + S(i as u64));
        }
        let mut gone = m.retain(|_, v| v % 2 == 0);
        gone.sort();
        assert_eq!(gone, vec![("b", 1), ("d", 3)]);
        assert_eq!(m.len(), 2);
        assert_eq!(m.next_expiry(), Some(t + S(60)));
        assert_eq!(m.expire(t + S(62)), vec![("a", 0), ("c", 2)]);
    }

    #[test]
    fn remove_and_clear_leave_no_expiry_behind() {
        let t = Instant::now();
        let mut m = IdleMap::new(8, S(60));
        m.insert("a", 1, t);
        assert_eq!(m.remove(&"a"), Some(1));
        assert_eq!(m.remove(&"a"), None);
        assert_eq!(m.next_expiry(), None);
        assert_eq!(m.expire(t + S(600)), vec![]);
        m.insert("b", 2, t);
        m.insert("c", 3, t);
        m.clear();
        assert!(m.is_empty());
        assert_eq!(m.next_expiry(), None);
        assert_eq!(m.expire(t + S(600)), vec![]);
        assert_eq!(m.insert("d", 4, t), None);
    }

    #[test]
    #[should_panic]
    fn zero_capacity_panics() {
        let _ = IdleMap::<u8, u8>::new(0, S(1));
    }
}
