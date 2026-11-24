//! HTTP-specific parts of the model: which hosts a listener or a route answers for.

use std::fmt;
use std::net::IpAddr;

/// Which request hosts a listener or a route answers for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostMatch {
    Any,
    /// Lower case.
    Exact(String),
    /// `*.example.com`, held as the suffix `.example.com`. Matches hosts with at least one more
    /// label.
    Wildcard(String),
}

impl HostMatch {
    /// `None` and `""` give `Any`. Lower-cases. `Err` (a message) unless the rest is a DNS name of
    /// labels `[a-z0-9-]` (1 to 63 characters, not starting or ending with `-`, at most 253 in
    /// all), optionally after `*.`. An IP address is an error.
    pub fn parse(hostname: Option<&str>) -> Result<Self, String> {
        let Some(raw) = hostname.filter(|h| !h.is_empty()) else {
            return Ok(Self::Any);
        };
        let lower = raw.to_ascii_lowercase();
        let (wildcard, name) = match lower.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, lower.as_str()),
        };
        let bad = |why: &str| Err(format!("hostname {raw:?} is not valid: {why}"));
        if name.len() > 253 {
            return bad("longer than 253 characters");
        }
        if name.parse::<IpAddr>().is_ok() {
            return bad("an IP address is not a hostname");
        }
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return bad("each label must have 1 to 63 characters");
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return bad("labels may contain only letters, digits and '-'");
            }
            if label.starts_with('-') || label.ends_with('-') {
                return bad("a label may not start or end with '-'");
            }
        }
        Ok(if wildcard {
            Self::Wildcard(format!(".{name}"))
        } else {
            Self::Exact(name.to_owned())
        })
    }

    /// What both match: the more specific of the two, or `None` when no host matches both.
    pub fn intersect(&self, other: &HostMatch) -> Option<HostMatch> {
        use HostMatch::*;
        match (self, other) {
            (Any, x) | (x, Any) => Some(x.clone()),
            (Exact(a), Exact(b)) => (a == b).then(|| self.clone()),
            (Exact(h), Wildcard(s)) | (Wildcard(s), Exact(h)) => {
                (h.len() > s.len() && h.ends_with(s.as_str())).then(|| Exact(h.clone()))
            }
            (Wildcard(a), Wildcard(b)) => {
                if a.ends_with(b.as_str()) {
                    Some(self.clone())
                } else if b.ends_with(a.as_str()) {
                    Some(other.clone())
                } else {
                    None
                }
            }
        }
    }
}

impl fmt::Display for HostMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostMatch::Any => f.write_str("(any)"),
            HostMatch::Exact(h) => f.write_str(h),
            HostMatch::Wildcard(s) => write!(f, "*{s}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(h: &str) -> HostMatch {
        HostMatch::Exact(h.into())
    }
    fn wildcard(s: &str) -> HostMatch {
        HostMatch::Wildcard(s.into())
    }

    #[test]
    fn host_match_parse() {
        assert_eq!(HostMatch::parse(None), Ok(HostMatch::Any));
        assert_eq!(HostMatch::parse(Some("")), Ok(HostMatch::Any));
        assert_eq!(
            HostMatch::parse(Some("Example.COM")),
            Ok(HostMatch::Exact("example.com".into()))
        );
        assert_eq!(
            HostMatch::parse(Some("*.Example.com")),
            Ok(HostMatch::Wildcard(".example.com".into()))
        );
        for bad in [
            "*",
            "*.",
            "a.*.com",
            "10.0.0.1",
            "exa mple.com",
            "example.com.",
            "-a.com",
            "a..com",
            "ex'ample.com",
        ] {
            assert!(HostMatch::parse(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn host_match_parse_limits() {
        let label63 = "a".repeat(63);
        assert!(HostMatch::parse(Some(&label63)).is_ok());
        assert!(HostMatch::parse(Some(&format!("{label63}a"))).is_err());
        assert!(HostMatch::parse(Some("a-.com")).is_err());
        assert!(HostMatch::parse(Some("a-b.com")).is_ok());
        // 4 labels of 63 and dots: 4 * 63 + 3 = 255 > 253.
        let long = [label63.as_str(); 4].join(".");
        assert!(HostMatch::parse(Some(&long)).is_err());
        let ok = format!("{}.{}.{}.{}", label63, label63, label63, "a".repeat(61));
        assert_eq!(ok.len(), 253);
        assert!(HostMatch::parse(Some(&ok)).is_ok());
        assert!(HostMatch::parse(Some("::1")).is_err());
    }

    #[test]
    fn host_match_intersect() {
        let (any, a, wild) = (
            HostMatch::Any,
            exact("a.example.com"),
            wildcard(".example.com"),
        );
        assert_eq!(any.intersect(&a), Some(a.clone()));
        assert_eq!(a.intersect(&wild), Some(a.clone()));
        assert_eq!(wild.intersect(&a), Some(a.clone()));
        assert_eq!(exact("example.com").intersect(&wild), None);
        assert_eq!(
            wildcard(".a.example.com").intersect(&wild),
            Some(wildcard(".a.example.com"))
        );
        assert_eq!(
            wild.intersect(&wildcard(".a.example.com")),
            Some(wildcard(".a.example.com"))
        );
        assert_eq!(wild.intersect(&wildcard(".example.org")), None);
        assert_eq!(a.intersect(&exact("b.example.com")), None);
        assert_eq!(any.intersect(&any), Some(HostMatch::Any));
        assert_eq!(wild.intersect(&wild), Some(wild.clone()));
    }

    #[test]
    fn host_match_displays_as_written() {
        assert_eq!(HostMatch::Any.to_string(), "(any)");
        assert_eq!(exact("a.com").to_string(), "a.com");
        assert_eq!(wildcard(".a.com").to_string(), "*.a.com");
    }
}
