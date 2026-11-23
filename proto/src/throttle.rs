//! Rate limiting for log lines about errors that can repeat many times a second.

use std::time::{Duration, Instant};

/// How often one source may log a repeating error.
pub const LOG_EVERY: Duration = Duration::from_secs(10);

/// Lets one line through per `every`, counting the occurrences it holds back.
#[derive(Debug)]
pub struct LogThrottle {
    every: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl LogThrottle {
    pub fn new(every: Duration) -> Self {
        Self {
            every,
            last: None,
            suppressed: 0,
        }
    }

    /// Records one occurrence now; see [`LogThrottle::hit_at`].
    pub fn hit(&mut self) -> Option<u64> {
        self.hit_at(Instant::now())
    }

    /// Records one occurrence at `now`. `Some(n)` means log it, with `n` occurrences held back
    /// since the last line logged; `None` means stay quiet.
    pub fn hit_at(&mut self, now: Instant) -> Option<u64> {
        match self.last {
            Some(last) if now.saturating_duration_since(last) < self.every => {
                self.suppressed += 1;
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.suppressed))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_hit_logs_then_one_line_per_period_with_the_count() {
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let mut t = LogThrottle::new(Duration::from_secs(10));
        assert_eq!(t.hit_at(at(0)), Some(0));
        assert_eq!(t.hit_at(at(1)), None);
        assert_eq!(t.hit_at(at(9_999)), None);
        assert_eq!(t.hit_at(at(10_000)), Some(2));
        assert_eq!(t.hit_at(at(10_001)), None);
        // A quiet stretch: the next occurrence logs at once.
        assert_eq!(t.hit_at(at(60_000)), Some(1));
        assert_eq!(t.hit_at(at(60_000)), None);
    }
}
