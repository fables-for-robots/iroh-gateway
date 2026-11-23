//! Edges and the gateways they serve.

use std::collections::BTreeSet;

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
    let mut out: Vec<EdgeModel> = snapshot
        .edges
        .iter()
        .map(|e| edge(e, snapshot, settings, gateways))
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

fn edge(
    e: &Edge,
    snapshot: &Snapshot,
    settings: &Settings,
    gateways: &[GatewayModel],
) -> EdgeModel {
    let key = ObjRef::of(e);
    let spec = &e.spec;
    let endpoint_id = spec.endpoint_id.parse::<EndpointId>().ok();
    let gateway = (!spec.gateway_ref.name.is_empty())
        .then(|| ObjRef::new(&key.namespace, &spec.gateway_ref.name));
    let public_addresses = public_addresses(e);

    let accepted = (|| {
        if !settings.gateway_namespaces.contains(&key.namespace) {
            return Err(Reject::new(
                "NamespaceNotAllowed",
                format!(
                    "namespace {:?} is not served by this operator",
                    key.namespace
                ),
            ));
        }
        let Some(id) = endpoint_id else {
            return Err(Reject::new(
                "InvalidEndpointId",
                format!("{:?} is not an endpoint id", spec.endpoint_id),
            ));
        };
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
            Some(a) => {
                if let Err(err) = check_address(a) {
                    return Err(Reject::new("InvalidAddress", err.to_string()));
                }
            }
            None => {}
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
        if let Some(older) = older_duplicate(e, id, snapshot) {
            return Err(Reject::new(
                "DuplicateEndpointId",
                format!("edge {older} has the same endpoint id and is older"),
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

/// An edge with the same endpoint id that is older: earlier creation time (none counts as
/// newest), then smaller key.
fn older_duplicate(e: &Edge, id: EndpointId, snapshot: &Snapshot) -> Option<ObjRef> {
    let order = |x: &Edge| {
        (
            x.creation_timestamp().is_none(),
            x.creation_timestamp(),
            ObjRef::of(x),
        )
    };
    let mine = order(e);
    snapshot
        .edges
        .iter()
        .filter(|o| o.spec.endpoint_id.parse::<EndpointId>().ok() == Some(id))
        .filter(|o| order(o) < mine)
        .map(ObjRef::of)
        .min()
}

/// `spec.publicAddresses`, or the host of `address`.
fn public_addresses(e: &Edge) -> Vec<GatewayAddress> {
    if !e.spec.public_addresses.is_empty() {
        return e
            .spec
            .public_addresses
            .iter()
            .map(|a| GatewayAddress::classify(a))
            .collect();
    }
    let Some(address) = e.spec.address.as_deref() else {
        return Vec::new();
    };
    if let Ok(sock) = address.parse::<std::net::SocketAddr>() {
        return vec![GatewayAddress::classify(&sock.ip().to_string())];
    }
    match address.rsplit_once(':') {
        Some((host, _)) if check_address(address).is_ok() => vec![GatewayAddress::classify(host)],
        _ => Vec::new(),
    }
}

/// Record on each gateway the accepted edges that serve it and their public addresses.
pub(super) fn bind(gateways: &mut [GatewayModel], edges: &[EdgeModel]) {
    for gw in gateways {
        let mine: Vec<&EdgeModel> = edges
            .iter()
            .filter(|e| e.accepted.is_ok() && e.gateway.as_ref() == Some(&gw.key))
            .collect();
        gw.edges = mine.iter().map(|e| e.key.clone()).collect();
        let addresses: BTreeSet<GatewayAddress> = mine
            .iter()
            .flat_map(|e| e.public_addresses.iter().cloned())
            .collect();
        gw.addresses = addresses.into_iter().collect();
    }
}

#[cfg(test)]
mod tests {
    use super::super::build;
    use super::super::fixtures::*;
    use super::super::{AddressKind, EdgeModel, GatewayAddress, Model, ObjRef, Settings, Snapshot};
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
        assert_eq!(m.gateways[0].addresses, [ip("203.0.113.7")]);
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
                "GatewayNotFound",
                good("e", 1).gateway("absent"),
                settings(&["infra"]),
            ),
            ("Ok", good("e", 1), settings(&["infra"])),
        ];
        for (want, e, settings) in cases {
            let m = build(&snap(vec![e]), &settings);
            assert_eq!(reason(&m.edges[0]), want);
        }
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
        assert!(m.gateways[0].addresses.is_empty());
    }

    #[test]
    fn edge_of_unaccepted_gateway() {
        let mut s = snap(vec![good("e", 1)]);
        s.gateways = vec![gateway("infra", "public").listener("a", 80, "HTTP")];
        let m = build(&s, &settings(&["infra"]));
        assert_eq!(reason(&m.edges[0]), "GatewayNotAccepted");
        assert!(m.gateways[0].edges.is_empty());
    }

    #[test]
    fn hostname_address_is_published_as_hostname() {
        let m = run(vec![good("e", 1).address("edge.example.com:7842")]);
        assert_eq!(
            m.gateways[0].addresses,
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
            m.gateways[0].addresses,
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
        assert_eq!(m.gateways[0].addresses, [ip("198.51.100.1")]);
    }

    #[test]
    fn addresses_are_deduplicated_and_sorted() {
        let m = run(vec![
            good("a", 1).address("203.0.113.9:7842"),
            good("b", 2).address("203.0.113.7:7842"),
            good("c", 3).address("203.0.113.7:7843"),
        ]);
        assert_eq!(
            m.gateways[0].addresses,
            [ip("203.0.113.7"), ip("203.0.113.9")]
        );
        assert_eq!(m.gateways[0].edges.len(), 3);
    }

    #[test]
    fn ipv6_address_host_has_no_brackets() {
        let m = run(vec![good("e", 1).address("[2001:db8::1]:7842")]);
        assert_eq!(m.gateways[0].addresses, [ip("2001:db8::1")]);
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
