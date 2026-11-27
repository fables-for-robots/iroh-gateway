//! Edges and the gateways they serve.

use std::collections::BTreeMap;

use iroh::EndpointId;
use kube::ResourceExt;

use super::generation;
use super::{EdgeModel, GatewayAddress, GatewayModel, ObjRef, Reject, Settings, Snapshot};
use crate::crd::Edge;
use crate::staticcfg::check_address;
use iroh_gateway_proto::transport::Relay;

/// Every edge, by key.
pub(super) fn edges(
    snapshot: &Snapshot,
    settings: &Settings,
    gateways: &[GatewayModel],
) -> Vec<EdgeModel> {
    let mut pairs: Vec<(&Edge, EdgeModel)> = snapshot
        .edges
        .iter()
        .map(|e| (e, edge(e, settings, gateways)))
        .collect();
    pairs.sort_by(|a, b| a.1.key.cmp(&b.1.key));
    refuse_duplicates(&mut pairs);
    pairs.into_iter().map(|(_, m)| m).collect()
}

/// Among the edges that passed every other check and share an endpoint id, only the oldest is
/// accepted: earliest creation time (none counts as newest), then smallest key. An edge
/// rejected for another reason neither competes nor loses its reason.
fn refuse_duplicates(pairs: &mut [(&Edge, EdgeModel)]) {
    let mut by_id: BTreeMap<EndpointId, Vec<usize>> = BTreeMap::new();
    for (i, (_, m)) in pairs.iter().enumerate() {
        if let (Ok(()), Some(id)) = (&m.accepted, m.endpoint_id) {
            by_id.entry(id).or_default().push(i);
        }
    }
    for members in by_id.into_values().filter(|m| m.len() > 1) {
        let order = |i: usize| {
            let ts = pairs[i].0.creation_timestamp();
            (ts.is_none(), ts, pairs[i].1.key.clone())
        };
        let winner = *members
            .iter()
            .min_by_key(|&&i| order(i))
            .expect("non-empty");
        let older = pairs[winner].1.key.clone();
        for i in members.into_iter().filter(|&i| i != winner) {
            pairs[i].1.accepted = Err(Reject::new(
                "DuplicateEndpointId",
                format!("edge {older} has the same endpoint id and is older"),
            ));
        }
    }
}

fn edge(e: &Edge, settings: &Settings, gateways: &[GatewayModel]) -> EdgeModel {
    let key = ObjRef::of(e);
    let spec = &e.spec;
    let endpoint_id = spec.endpoint_id.parse::<EndpointId>().ok();
    let gateway = (!spec.gateway_ref.name.is_empty())
        .then(|| ObjRef::new(&key.namespace, &spec.gateway_ref.name));
    let public_addresses = public_addresses(e);

    let accepted = (|| -> Result<(), Reject> {
        if !settings.gateway_namespaces.contains(&key.namespace) {
            return Err(Reject::new(
                "NamespaceNotAllowed",
                format!(
                    "namespace {:?} is not served by this operator",
                    key.namespace
                ),
            ));
        }
        if endpoint_id.is_none() {
            return Err(Reject::new(
                "InvalidEndpointId",
                format!("{:?} is not an endpoint id", spec.endpoint_id),
            ));
        }
        match &spec.address {
            None if settings.relay == Relay::Disabled => {
                return Err(Reject::new(
                    "NoAddress",
                    "address is required because the operator does not use a relay",
                ));
            }
            None if spec.public_addresses.is_empty() => {
                return Err(Reject::new(
                    "NoPublicAddress",
                    "without an address, publicAddresses must say where visitors connect",
                ));
            }
            _ => {}
        }
        if let Some(bad) = spec
            .public_addresses
            .iter()
            .find(|a| GatewayAddress::parse(a).is_none())
        {
            return Err(Reject::new(
                "InvalidPublicAddress",
                format!(
                    "publicAddresses entry {bad:?} is neither an IP address nor a DNS name \
                     (without a port)"
                ),
            ));
        }
        if let Some(a) = &spec.address {
            check_address(a).map_err(|err| Reject::new("InvalidAddress", err.to_string()))?;
            if address_host(a).is_none() {
                return Err(Reject::new(
                    "InvalidAddress",
                    format!("address {a:?}: the host is not a valid DNS name"),
                ));
            }
        }
        let gw = gateway
            .as_ref()
            .and_then(|k| gateways.iter().find(|g| &g.key == k));
        let Some(gw) = gw else {
            return Err(Reject::new(
                "GatewayNotFound",
                format!(
                    "no gateway {:?} of ours in namespace {:?}",
                    spec.gateway_ref.name, key.namespace
                ),
            ));
        };
        if gw.accepted.is_err() {
            return Err(Reject::new(
                "GatewayNotAccepted",
                format!("gateway {} is not accepted", gw.key),
            ));
        }
        Ok(())
    })();

    EdgeModel {
        key,
        generation: generation(e),
        accepted,
        endpoint_id,
        address: spec.address.clone(),
        gateway,
        public_addresses,
    }
}

/// `spec.publicAddresses` normalised, or the normalised host of `address`; the entries that are
/// valid only (an edge with an invalid one is not accepted).
fn public_addresses(e: &Edge) -> Vec<GatewayAddress> {
    if !e.spec.public_addresses.is_empty() {
        return e
            .spec
            .public_addresses
            .iter()
            .filter_map(|a| GatewayAddress::parse(a))
            .collect();
    }
    e.spec
        .address
        .as_deref()
        .filter(|a| check_address(a).is_ok())
        .and_then(address_host)
        .into_iter()
        .collect()
}

/// The host of an `address` that passed [`check_address`], normalised; `None` when it cannot be.
fn address_host(address: &str) -> Option<GatewayAddress> {
    if let Ok(sock) = address.parse::<std::net::SocketAddr>() {
        return GatewayAddress::parse(&sock.ip().to_string());
    }
    let (host, _) = address.rsplit_once(':')?;
    GatewayAddress::parse(host)
}

/// Record on each gateway the accepted edges that serve it.
pub(super) fn bind(gateways: &mut [GatewayModel], edges: &[EdgeModel]) {
    for gw in gateways {
        gw.edges = edges
            .iter()
            .filter(|e| e.accepted.is_ok() && e.gateway.as_ref() == Some(&gw.key))
            .map(|e| e.key.clone())
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::*;
    use super::super::{AddressKind, EdgeModel, GatewayAddress, Model, ObjRef, Settings, Snapshot};
    use super::super::{addresses_of, build};
    use iroh_gateway_proto::transport::Relay;

    fn snap(edges: Vec<crate::crd::Edge>) -> Snapshot {
        Snapshot {
            gateway_classes: vec![class("ours"), foreign_class("theirs")],
            gateways: vec![gateway("infra", "public").listener("pg", 5432, "TCP")],
            edges,
            ..Default::default()
        }
    }

    fn run(edges: Vec<crate::crd::Edge>) -> Model {
        build(&snap(edges), &settings(&["infra"]))
    }

    /// The addresses the first gateway lists when all its edges are listed, and how many more
    /// its edges have.
    fn listed(m: &Model) -> (Vec<GatewayAddress>, usize) {
        let gw = &m.gateways[0];
        addresses_of(m.edges.iter().filter(|e| gw.edges.contains(&e.key)))
    }

    fn addresses(m: &Model) -> Vec<GatewayAddress> {
        listed(m).0
    }

    fn reason(m: &EdgeModel) -> &str {
        match &m.accepted {
            Ok(()) => "Ok",
            Err(r) => &r.reason,
        }
    }

    fn good(name: &str, seed: u8) -> crate::crd::Edge {
        edge("infra", name, seed)
            .address("203.0.113.7:7842")
            .gateway("public")
    }

    fn ip(v: &str) -> GatewayAddress {
        GatewayAddress {
            kind: AddressKind::IpAddress,
            value: v.into(),
        }
    }

    #[test]
    fn edge_binds_to_its_gateway() {
        let m = run(vec![good("fsn1", 1)]);
        assert_eq!(reason(&m.edges[0]), "Ok");
        assert_eq!(m.gateways[0].edges, [ObjRef::new("infra", "fsn1")]);
        assert_eq!(addresses(&m), [ip("203.0.113.7")]);
        assert_eq!(m.edges[0].gateway, Some(ObjRef::new("infra", "public")));
        assert_eq!(m.edges[0].address.as_deref(), Some("203.0.113.7:7842"));
        assert!(m.edges[0].endpoint_id.is_some());
    }

    #[test]
    fn edge_rejections() {
        let cases: Vec<(&str, crate::crd::Edge, Settings)> = vec![
            (
                "NamespaceNotAllowed",
                {
                    let mut e = good("e", 1);
                    e.metadata.namespace = Some("other".into());
                    e
                },
                settings(&["infra"]),
            ),
            (
                "InvalidEndpointId",
                {
                    let mut e = good("e", 1);
                    e.spec.endpoint_id = "nope".into();
                    e
                },
                settings(&["infra"]),
            ),
            (
                "NoAddress",
                edge("infra", "e", 1)
                    .no_address()
                    .gateway("public")
                    .public("198.51.100.1"),
                settings(&["infra"]),
            ),
            (
                "NoPublicAddress",
                edge("infra", "e", 1).no_address().gateway("public"),
                relay_settings(),
            ),
            (
                "GatewayNotAccepted",
                good("e", 1).gateway("broken"),
                settings(&["infra"]),
            ),
            (
                "InvalidAddress",
                good("e", 1).address("203.0.113.7"),
                settings(&["infra"]),
            ),
            (
                "InvalidAddress",
                good("e", 1).address("203.0.113.7:0"),
                settings(&["infra"]),
            ),
            (
                "InvalidAddress",
                good("e", 1).address("203.0.113.7:70000"),
                settings(&["infra"]),
            ),
            (
                "InvalidPublicAddress",
                good("e", 1).public("198.51.100.1:443"),
                settings(&["infra"]),
            ),
            (
                "GatewayNotFound",
                good("e", 1).gateway("absent"),
                settings(&["infra"]),
            ),
            ("Ok", good("e", 1), settings(&["infra"])),
        ];
        for (want, e, settings) in cases {
            let mut s = snap(vec![e]);
            s.gateways
                .push(gateway("infra", "broken").listener("a", 80, "TLS"));
            let m = build(&s, &settings);
            assert_eq!(reason(&m.edges[0]), want);
        }
    }

    #[test]
    fn edge_checks_run_in_table_order() {
        let bad_id = |mut e: crate::crd::Edge| {
            e.spec.endpoint_id = "nope".into();
            e
        };
        let relay = relay_settings();
        let plain = settings(&["infra"]);
        let cases: Vec<(&str, crate::crd::Edge, &Settings)> = vec![
            (
                "NamespaceNotAllowed",
                {
                    let mut e = bad_id(good("e", 1));
                    e.metadata.namespace = Some("other".into());
                    e
                },
                &plain,
            ),
            (
                "InvalidEndpointId",
                bad_id(edge("infra", "e", 1).no_address().gateway("public")),
                &plain,
            ),
            (
                "NoAddress",
                edge("infra", "e", 1).no_address().gateway("public"),
                &plain,
            ),
            (
                "NoPublicAddress",
                edge("infra", "e", 1).no_address().gateway("absent"),
                &relay,
            ),
            (
                "InvalidPublicAddress",
                edge("infra", "e", 1)
                    .no_address()
                    .gateway("absent")
                    .public("bad_name"),
                &relay,
            ),
            (
                "InvalidAddress",
                good("e", 1).address("203.0.113.7").gateway("absent"),
                &plain,
            ),
            ("GatewayNotFound", good("e", 1).gateway("absent"), &plain),
        ];
        for (want, e, settings) in cases {
            let m = build(&snap(vec![e]), settings);
            assert_eq!(reason(&m.edges[0]), want);
        }

        // An unaccepted gateway is reported before a duplicate id.
        let mut s = snap(vec![
            good("older", 1).gateway("broken").created(10),
            good("younger", 1).gateway("broken").created(20),
        ]);
        s.gateways
            .push(gateway("infra", "broken").listener("a", 80, "TLS"));
        let m = build(&s, &settings(&["infra"]));
        assert_eq!(reason(&m.edges[0]), "GatewayNotAccepted");
        assert_eq!(reason(&m.edges[1]), "GatewayNotAccepted");
    }

    fn relay_settings() -> Settings {
        Settings {
            relay: Relay::N0,
            ..settings(&["infra"])
        }
    }

    #[test]
    fn rejected_edge_keeps_what_it_knows() {
        let m = run(vec![good("e", 4).gateway("absent")]);
        let e = &m.edges[0];
        assert_eq!(reason(e), "GatewayNotFound");
        assert!(e.endpoint_id.is_some());
        assert_eq!(e.gateway, Some(ObjRef::new("infra", "absent")));
        assert!(m.gateways[0].edges.is_empty());
        assert!(addresses(&m).is_empty());
    }

    #[test]
    fn edge_of_unaccepted_gateway() {
        let mut s = snap(vec![good("e", 1)]);
        s.gateways = vec![gateway("infra", "public").listener("a", 80, "TLS")];
        let m = build(&s, &settings(&["infra"]));
        assert_eq!(reason(&m.edges[0]), "GatewayNotAccepted");
        assert!(m.gateways[0].edges.is_empty());
    }

    #[test]
    fn hostname_address_is_published_as_hostname() {
        let m = run(vec![good("e", 1).address("edge.example.com:7842")]);
        assert_eq!(
            addresses(&m),
            [GatewayAddress {
                kind: AddressKind::Hostname,
                value: "edge.example.com".into()
            }]
        );
    }

    #[test]
    fn public_addresses_override_the_address() {
        let m = run(vec![
            good("e", 1)
                .public("198.51.100.1")
                .public("edge.example.com"),
        ]);
        assert_eq!(reason(&m.edges[0]), "Ok");
        assert_eq!(
            addresses(&m),
            [
                ip("198.51.100.1"),
                GatewayAddress {
                    kind: AddressKind::Hostname,
                    value: "edge.example.com".into()
                }
            ]
        );
    }

    #[test]
    fn no_address_is_fine_in_relay_mode_with_public_addresses() {
        let e = edge("infra", "e", 1)
            .no_address()
            .gateway("public")
            .public("198.51.100.1");
        let m = build(&snap(vec![e]), &relay_settings());
        assert_eq!(reason(&m.edges[0]), "Ok");
        assert_eq!(m.edges[0].address, None);
        assert_eq!(addresses(&m), [ip("198.51.100.1")]);
    }

    #[test]
    fn addresses_are_deduplicated_and_sorted() {
        let m = run(vec![
            good("a", 1).address("203.0.113.9:7842"),
            good("b", 2).address("203.0.113.7:7842"),
            good("c", 3).address("203.0.113.7:7843"),
        ]);
        assert_eq!(addresses(&m), [ip("203.0.113.7"), ip("203.0.113.9")]);
        assert_eq!(m.gateways[0].edges.len(), 3);
    }

    #[test]
    fn ipv6_address_host_has_no_brackets() {
        let m = run(vec![good("e", 1).address("[2001:db8::1]:7842")]);
        assert_eq!(addresses(&m), [ip("2001:db8::1")]);
    }

    fn host(v: &str) -> GatewayAddress {
        GatewayAddress {
            kind: AddressKind::Hostname,
            value: v.into(),
        }
    }

    #[test]
    fn public_addresses_are_normalised() {
        let m = run(vec![
            good("e", 1)
                .public("198.51.100.1")
                .public("2001:DB8:0:0::1")
                .public("::ffff:192.0.2.1")
                .public("Edge.Example.COM.")
                .public("xn--bcher-kva.example"),
        ]);
        assert_eq!(reason(&m.edges[0]), "Ok");
        assert_eq!(
            addresses(&m),
            [
                ip("198.51.100.1"),
                ip("2001:db8::1"),
                ip("::ffff:192.0.2.1"),
                host("edge.example.com"),
                host("xn--bcher-kva.example"),
            ]
        );
    }

    #[test]
    fn invalid_public_addresses_are_refused() {
        let long_label = format!("{}.example.com", "a".repeat(64));
        let long_name = format!("{}.{}", "a".repeat(63), "b.".repeat(100));
        assert!(long_name.trim_end_matches('.').len() > 253);
        for bad in [
            "203.0.113.7:8080",
            "edge.example.com:8080",
            "[2001:db8::1]",
            "[2001:db8::1]:443",
            "under_score.example.com",
            "-lead.example.com",
            "trail-.example.com",
            "a..b",
            "",
            ".",
            "edge.example.com..",
            "exa mple.com",
            "*.example.com",
            "fe80::1%en0",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            let m = run(vec![good("e", 1).public("198.51.100.1").public(bad)]);
            assert_eq!(reason(&m.edges[0]), "InvalidPublicAddress", "{bad:?}");
            assert!(addresses(&m).is_empty(), "{bad:?}");
            assert!(m.gateways[0].edges.is_empty(), "{bad:?}");
        }
    }

    #[test]
    fn longest_valid_names_are_kept() {
        // 253 characters, one label of 63; the trailing dot does not count.
        let name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(name.len(), 253);
        let m = run(vec![good("e", 1).public(&format!("{name}."))]);
        assert_eq!(reason(&m.edges[0]), "Ok");
        assert_eq!(addresses(&m), [host(&name)]);

        let m = run(vec![good("e", 1).public(&format!("{name}x"))]);
        assert_eq!(reason(&m.edges[0]), "InvalidPublicAddress");
    }

    #[test]
    fn address_host_is_normalised() {
        let m = run(vec![good("e", 1).address("Edge.Example.COM.:7842")]);
        assert_eq!(reason(&m.edges[0]), "Ok");
        assert_eq!(addresses(&m), [host("edge.example.com")]);
        // The address is dialled as written.
        assert_eq!(
            m.edges[0].address.as_deref(),
            Some("Edge.Example.COM.:7842")
        );

        let m = run(vec![good("e", 1).address("[2001:DB8::0:1]:7842")]);
        assert_eq!(addresses(&m), [ip("2001:db8::1")]);
    }

    #[test]
    fn invalid_public_address_is_checked_after_no_public_address() {
        let relay = relay_settings();
        let plain = settings(&["infra"]);
        let cases: Vec<(&str, crate::crd::Edge, &Settings)> = vec![
            (
                "NoAddress",
                edge("infra", "e", 1)
                    .no_address()
                    .gateway("public")
                    .public("x:1"),
                &plain,
            ),
            (
                "InvalidPublicAddress",
                edge("infra", "e", 1)
                    .no_address()
                    .gateway("absent")
                    .public("x:1"),
                &relay,
            ),
            (
                "InvalidPublicAddress",
                good("e", 1).address("203.0.113.7").public("x:1"),
                &plain,
            ),
            (
                "InvalidPublicAddress",
                good("e", 1).gateway("absent").public("x:1"),
                &plain,
            ),
        ];
        for (want, e, settings) in cases {
            let m = build(&snap(vec![e]), settings);
            assert_eq!(reason(&m.edges[0]), want);
        }
    }

    #[test]
    fn a_gateway_lists_at_most_16_addresses() {
        let edges: Vec<crate::crd::Edge> = (1..=17u8)
            .map(|n| good(&format!("e{n:02}"), n).address(&format!("203.0.113.{n}:7842")))
            .collect();
        let m = run(edges);
        assert_eq!(m.gateways[0].edges.len(), 17);
        let (listed_addresses, dropped) = listed(&m);
        assert_eq!(listed_addresses.len(), 16);
        assert_eq!(dropped, 1);
        // The first 16 after sorting: "203.0.113.9" sorts last and is left out.
        assert!(
            !listed_addresses.contains(&ip("203.0.113.9")),
            "{listed_addresses:?}"
        );
        let mut sorted = listed_addresses.clone();
        sorted.sort();
        assert_eq!(sorted, listed_addresses);

        let m = run((1..=16u8)
            .map(|n| good(&format!("e{n:02}"), n).address(&format!("203.0.113.{n}:7842")))
            .collect());
        assert_eq!(listed(&m), (addresses(&m), 0));
        assert_eq!(addresses(&m).len(), 16);
    }

    #[test]
    fn duplicate_endpoint_id_oldest_wins() {
        let m = run(vec![good("a", 1).created(10), good("b", 1).created(20)]);
        assert_eq!(reason(&m.edges[0]), "Ok");
        assert_eq!(reason(&m.edges[1]), "DuplicateEndpointId");
        assert_eq!(m.gateways[0].edges, [ObjRef::new("infra", "a")]);

        let m = run(vec![good("a", 1).created(20), good("b", 1).created(10)]);
        assert_eq!(reason(&m.edges[0]), "DuplicateEndpointId");
        assert_eq!(reason(&m.edges[1]), "Ok");
    }

    #[test]
    fn duplicate_endpoint_id_ties_and_missing_times() {
        // Same time: the smaller key wins.
        let m = run(vec![good("b", 1).created(10), good("a", 1).created(10)]);
        assert_eq!(reason(&m.edges[0]), "Ok");
        assert_eq!(reason(&m.edges[1]), "DuplicateEndpointId");
        // No creation time counts as newest.
        let m = run(vec![good("a", 1), good("b", 1).created(10)]);
        assert_eq!(reason(&m.edges[0]), "DuplicateEndpointId");
        assert_eq!(reason(&m.edges[1]), "Ok");
    }

    #[test]
    fn rejected_older_edge_does_not_block_a_valid_younger_one() {
        let m = run(vec![
            good("a", 1).gateway("absent").created(10),
            good("b", 1).created(20),
        ]);
        assert_eq!(reason(&m.edges[0]), "GatewayNotFound");
        assert_eq!(reason(&m.edges[1]), "Ok");
        assert_eq!(m.gateways[0].edges, [ObjRef::new("infra", "b")]);
    }

    #[test]
    fn three_way_duplicate() {
        let m = run(vec![
            good("c", 1).created(30),
            good("a", 1).created(20),
            good("b", 1).created(10),
        ]);
        assert_eq!(reason(&m.edges[0]), "DuplicateEndpointId");
        assert_eq!(reason(&m.edges[1]), "Ok");
        assert_eq!(reason(&m.edges[2]), "DuplicateEndpointId");
        assert_eq!(m.gateways[0].edges, [ObjRef::new("infra", "b")]);
    }

    #[test]
    fn edge_for_foreign_gateway_is_refused() {
        let mut s = snap(vec![good("e", 1).gateway("theirs")]);
        s.gateways = vec![
            gateway("infra", "theirs")
                .class("theirs")
                .listener("pg", 5432, "TCP"),
        ];
        let m = build(&s, &settings(&["infra"]));
        assert_eq!(reason(&m.edges[0]), "GatewayNotFound");
    }

    #[test]
    fn edge_cannot_reach_a_gateway_in_another_namespace() {
        let mut s = snap(vec![good("e", 1)]);
        s.gateways = vec![gateway("elsewhere", "public").listener("pg", 5432, "TCP")];
        let m = build(&s, &settings(&["infra", "elsewhere"]));
        assert_eq!(reason(&m.edges[0]), "GatewayNotFound");
    }

    #[test]
    fn build_is_deterministic() {
        let mut s = snap(vec![
            good("a", 1),
            good("b", 2),
            good("c", 3).gateway("absent"),
        ]);
        s.gateways
            .push(gateway("infra", "alpha").listener("x", 1, "TCP"));
        s.gateway_classes.push(class("also"));
        s.gateways.push(
            gateway("infra", "zeta")
                .class("also")
                .listener("x", 1, "TCP"),
        );
        let expected = build(&s, &settings(&["infra"]));
        assert_eq!(expected.gateways.len(), 3);
        let mut r = s.clone();
        r.edges.reverse();
        r.gateways.reverse();
        r.gateway_classes.reverse();
        assert_eq!(build(&r, &settings(&["infra"])), expected);
        assert!(expected.routes.is_empty());
    }
}
