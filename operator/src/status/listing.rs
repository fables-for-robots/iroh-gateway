//! Which edges' addresses a Gateway lists: those of connected edges, and for the address grace
//! those of an edge that has just disconnected.
//!
//! [`Listing`] remembers, between passes, since when a disconnected edge is held. The only state
//! it takes from outside is what the Gateway's status listed when it first saw an edge, so that
//! an operator restart withdraws nothing before the edges had the grace to reconnect.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use tokio::time::Instant;
use tracing::info;

use super::Facts;
use crate::model::{GatewayAddress, Model, ObjRef, Snapshot};

/// One accepted edge bound to a Gateway, as a pass sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeView {
    pub key: ObjRef,
    /// The edge's link is connected.
    pub connected: bool,
    /// The Gateway's status, as last read, lists one of the edge's public addresses.
    pub in_status: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// Connected at the last pass.
    Listed,
    /// Disconnected, and listed until `until`.
    Held { until: Instant },
    /// Disconnected for longer than the grace, or never seen connected.
    Withdrawn,
}

/// One view per accepted edge bound to a Gateway of the model: whether `facts` has its link
/// connected, and whether that Gateway's status in `snapshot` lists one of its public addresses.
pub fn views(model: &Model, facts: &Facts, snapshot: &Snapshot) -> Vec<EdgeView> {
    let mut views = Vec::new();
    for gateway in &model.gateways {
        let in_status: BTreeSet<GatewayAddress> = snapshot
            .gateways
            .iter()
            .filter(|g| ObjRef::of(*g) == gateway.key)
            .filter_map(|g| g.status.as_ref()?.addresses.as_ref())
            .flatten()
            .filter_map(|a| GatewayAddress::parse(&a.value))
            .collect();
        for edge in model
            .edges
            .iter()
            .filter(|e| gateway.edges.contains(&e.key))
        {
            views.push(EdgeView {
                key: edge.key.clone(),
                connected: facts.edges.get(&edge.key).is_some_and(|s| s.connected),
                in_status: edge.public_addresses.iter().any(|a| in_status.contains(a)),
            });
        }
    }
    views
}

/// Decides at each pass which edges are listed.
#[derive(Debug)]
pub struct Listing {
    grace: Duration,
    edges: BTreeMap<ObjRef, Seen>,
}

impl Listing {
    pub fn new(grace: Duration) -> Self {
        Self {
            grace,
            edges: BTreeMap::new(),
        }
    }

    /// The edges whose addresses are listed at `now`.
    ///
    /// A connected edge is listed. An edge that was listed and is no longer connected stays
    /// listed for the grace, counted from the first pass that saw it disconnected. An edge that
    /// is not connected when first seen is held for one grace if `in_status`, and is not listed
    /// otherwise. Edges absent from `edges` are forgotten.
    pub fn update(&mut self, now: Instant, edges: &[EdgeView]) -> BTreeSet<ObjRef> {
        let mut seen = BTreeMap::new();
        let mut listed = BTreeSet::new();
        for edge in edges {
            let before = self.edges.get(&edge.key).copied();
            let after = self.step(now, edge, before);
            if Some(after) != before {
                log_change(&edge.key, before, after, self.grace);
            }
            if after != Seen::Withdrawn {
                listed.insert(edge.key.clone());
            }
            seen.insert(edge.key.clone(), after);
        }
        self.edges = seen;
        listed
    }

    /// What an edge that was `before` is at `now`.
    fn step(&self, now: Instant, edge: &EdgeView, before: Option<Seen>) -> Seen {
        if edge.connected {
            return Seen::Listed;
        }
        let held = match before {
            Some(Seen::Held { until }) => until,
            Some(Seen::Listed) => now + self.grace,
            None if edge.in_status => now + self.grace,
            Some(Seen::Withdrawn) | None => return Seen::Withdrawn,
        };
        if now < held {
            Seen::Held { until: held }
        } else {
            Seen::Withdrawn
        }
    }

    /// When the earliest grace of a held edge ends: the next moment at which [`Listing::update`]
    /// answers differently with nothing else changed.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.edges
            .values()
            .filter_map(|seen| match seen {
                Seen::Held { until } => Some(*until),
                Seen::Listed | Seen::Withdrawn => None,
            })
            .min()
    }
}

fn log_change(edge: &ObjRef, before: Option<Seen>, after: Seen, grace: Duration) {
    match (before, after) {
        (_, Seen::Listed) => info!(%edge, "edge connected: its addresses are listed"),
        (_, Seen::Held { .. }) => info!(
            %edge,
            ?grace,
            "edge not connected: its addresses stay listed for the address grace"
        ),
        // Never listed by this operator, and not in the status: nothing changes for a reader.
        (None, Seen::Withdrawn) => {}
        (Some(_), Seen::Withdrawn) => {
            info!(%edge, "edge still not connected: its addresses are withdrawn");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRACE: Duration = Duration::from_secs(30);

    fn key(name: &str) -> ObjRef {
        ObjRef::new("gw", name)
    }

    fn view(name: &str, connected: bool, in_status: bool) -> EdgeView {
        EdgeView {
            key: key(name),
            connected,
            in_status,
        }
    }

    fn up(name: &str) -> EdgeView {
        view(name, true, true)
    }

    /// Disconnected, with its address in the Gateway's status.
    fn down(name: &str) -> EdgeView {
        view(name, false, true)
    }

    fn set(names: &[&str]) -> BTreeSet<ObjRef> {
        names.iter().map(|n| key(n)).collect()
    }

    #[test]
    fn views_say_who_is_connected_and_whose_address_the_status_lists() {
        use crate::model::fixtures::{EdgeExt, GatewayExt, class, edge, gateway, settings};
        use crate::tunnel::EdgeState;
        use gateway_api::gateways::v1::GatewayStatus;
        use serde_json::json;

        let mut gw = gateway("gw", "public").listener("web", 80, "HTTP");
        gw.status = Some(GatewayStatus {
            addresses: Some(
                serde_json::from_value(json!([
                    { "type": "IPAddress", "value": "203.0.113.7" },
                    { "type": "Hostname", "value": "edge-c.example.com" },
                ]))
                .unwrap(),
            ),
            ..Default::default()
        });
        let snapshot = Snapshot {
            gateway_classes: vec![class("ours")],
            gateways: vec![gw, gateway("gw", "other").listener("web", 81, "HTTP")],
            edges: vec![
                // Its address is in the status.
                edge("gw", "a", 1).address("203.0.113.7:7842"),
                // Its address is not.
                edge("gw", "b", 2).address("203.0.113.8:7842"),
                // One of its public addresses is, as a host name written in another case.
                edge("gw", "c", 3)
                    .address("203.0.113.9:7842")
                    .public("198.51.100.1")
                    .public("Edge-C.example.com"),
                // Bound to a gateway whose status lists nothing, although the other one's does.
                edge("gw", "d", 4)
                    .address("203.0.113.7:7842")
                    .gateway("other"),
                // Bound to a gateway that does not exist: not accepted, so no view.
                edge("gw", "e", 5)
                    .address("203.0.113.7:7842")
                    .gateway("missing"),
            ],
            ..Default::default()
        };
        let model = crate::model::build(&snapshot, &settings(&["gw"]));
        let facts = Facts {
            operator_id: iroh::SecretKey::from_bytes(&[1; 32]).public(),
            haproxy: Ok(()),
            edges: [(
                key("b"),
                EdgeState {
                    connected: true,
                    ..Default::default()
                },
            )]
            .into(),
        };
        let mut got = views(&model, &facts, &snapshot);
        got.sort_by(|x, y| x.key.cmp(&y.key));
        assert_eq!(
            got,
            [
                view("a", false, true),
                view("b", true, false),
                view("c", false, true),
                view("d", false, false),
            ]
        );
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn a_connected_edge_is_listed() {
        let t0 = Instant::now();
        let mut listing = Listing::new(GRACE);
        assert_eq!(listing.update(t0, &[up("a")]), set(&["a"]));
        assert_eq!(listing.next_expiry(), None);
    }

    #[test]
    fn a_disconnect_is_held_for_the_grace_then_withdrawn() {
        let t0 = Instant::now();
        let mut listing = Listing::new(GRACE);
        listing.update(t0 - secs(100), &[up("a")]);

        assert_eq!(listing.update(t0, &[down("a")]), set(&["a"]));
        assert_eq!(listing.next_expiry(), Some(t0 + GRACE));
        assert_eq!(listing.update(t0 + secs(29), &[down("a")]), set(&["a"]));
        assert_eq!(listing.next_expiry(), Some(t0 + GRACE));

        assert_eq!(listing.update(t0 + GRACE, &[down("a")]), set(&[]));
        assert_eq!(listing.next_expiry(), None);
        // Withdrawn stays withdrawn, although the status may still list the address for a moment.
        assert_eq!(listing.update(t0 + secs(31), &[down("a")]), set(&[]));
    }

    #[test]
    fn a_reconnect_within_the_grace_stays_listed() {
        let t0 = Instant::now();
        let mut listing = Listing::new(GRACE);
        listing.update(t0, &[up("a")]);
        assert_eq!(listing.update(t0 + secs(1), &[down("a")]), set(&["a"]));
        assert_eq!(listing.update(t0 + secs(20), &[up("a")]), set(&["a"]));
        assert_eq!(listing.next_expiry(), None);

        // A later disconnect starts a new grace: the first one, long past, does not count.
        assert_eq!(listing.update(t0 + secs(100), &[down("a")]), set(&["a"]));
        assert_eq!(listing.next_expiry(), Some(t0 + secs(100) + GRACE));
    }

    #[test]
    fn a_withdrawn_edge_is_listed_again_when_it_connects() {
        let t0 = Instant::now();
        let mut listing = Listing::new(GRACE);
        listing.update(t0, &[up("a")]);
        listing.update(t0 + secs(1), &[down("a")]);
        assert_eq!(listing.update(t0 + secs(60), &[down("a")]), set(&[]));
        assert_eq!(listing.update(t0 + secs(61), &[up("a")]), set(&["a"]));
    }

    #[test]
    fn first_seen_disconnected_and_in_status_is_held() {
        let t0 = Instant::now();
        let mut listing = Listing::new(GRACE);
        assert_eq!(listing.update(t0, &[view("a", false, true)]), set(&["a"]));
        assert_eq!(listing.next_expiry(), Some(t0 + GRACE));
        assert_eq!(
            listing.update(t0 + GRACE, &[view("a", false, true)]),
            set(&[])
        );
    }

    #[test]
    fn first_seen_disconnected_and_not_in_status_is_withdrawn() {
        let t0 = Instant::now();
        let mut listing = Listing::new(GRACE);
        assert_eq!(listing.update(t0, &[view("a", false, false)]), set(&[]));
        assert_eq!(listing.next_expiry(), None);
        // Another edge's equal address turning up in the status later does not list it.
        assert_eq!(
            listing.update(t0 + secs(1), &[view("a", false, true)]),
            set(&[])
        );
    }

    #[test]
    fn a_zero_grace_withdraws_at_once() {
        let t0 = Instant::now();
        let mut listing = Listing::new(Duration::ZERO);
        assert_eq!(listing.update(t0, &[up("a")]), set(&["a"]));
        assert_eq!(listing.update(t0 + secs(1), &[down("a")]), set(&[]));
        assert_eq!(listing.next_expiry(), None);
        // Nor does a restart hold anything.
        let mut listing = Listing::new(Duration::ZERO);
        assert_eq!(listing.update(t0, &[view("b", false, true)]), set(&[]));
    }

    #[test]
    fn an_edge_that_is_gone_is_forgotten() {
        let t0 = Instant::now();
        let mut listing = Listing::new(GRACE);
        listing.update(t0, &[up("a"), up("b")]);
        assert_eq!(
            listing.update(t0 + secs(1), &[down("a"), up("b")]),
            set(&["a", "b"])
        );
        assert_eq!(listing.update(t0 + secs(2), &[up("b")]), set(&["b"]));
        assert_eq!(listing.next_expiry(), None);
        // Back, disconnected, its address no longer in the status: a new edge, not a held one.
        assert_eq!(
            listing.update(t0 + secs(3), &[view("a", false, false), up("b")]),
            set(&["b"])
        );
    }

    #[test]
    fn the_earliest_expiry_is_reported() {
        let t0 = Instant::now();
        let mut listing = Listing::new(GRACE);
        listing.update(t0, &[up("a"), up("b"), up("c")]);
        listing.update(t0 + secs(5), &[up("a"), down("b"), up("c")]);
        listing.update(t0 + secs(9), &[down("a"), down("b"), up("c")]);
        assert_eq!(listing.next_expiry(), Some(t0 + secs(5) + GRACE));

        assert_eq!(
            listing.update(t0 + secs(35), &[down("a"), down("b"), up("c")]),
            set(&["a", "c"])
        );
        assert_eq!(listing.next_expiry(), Some(t0 + secs(9) + GRACE));
    }
}
