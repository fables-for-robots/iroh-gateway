//! Classes, gateways and listeners.

use std::collections::BTreeMap;

use kube::ResourceExt;

use gateway_api::gateways::v1::{
    GatewayListenersAllowedRoutesNamespaces, GatewayListenersAllowedRoutesNamespacesFrom as From,
};

use super::generation;
use super::{
    ClassModel, GatewayModel, LabelRequirement, LabelSelector, ListenerModel, ObjRef, Reject,
    RouteNamespaces, Settings, Snapshot,
};

pub(super) const ROUTE_GROUP: &str = "gateway.networking.k8s.io";
pub(super) const ROUTE_KIND: &str = "TCPRoute";

/// Every class with our controller name, by name.
pub(super) fn classes(snapshot: &Snapshot, settings: &Settings) -> Vec<ClassModel> {
    let mut classes: Vec<ClassModel> = snapshot
        .gateway_classes
        .iter()
        .filter(|c| c.spec.controller_name == settings.controller_name)
        .map(|c| ClassModel {
            name: c.name_any(),
            generation: generation(c),
        })
        .collect();
    classes.sort_by(|a, b| a.name.cmp(&b.name));
    classes
}

/// Every gateway whose class is ours, by key. Edges are bound later.
pub(super) fn gateways(
    snapshot: &Snapshot,
    settings: &Settings,
    classes: &[ClassModel],
) -> Vec<GatewayModel> {
    let mut out: Vec<GatewayModel> = snapshot
        .gateways
        .iter()
        .filter(|g| classes.iter().any(|c| c.name == g.spec.gateway_class_name))
        .map(|g| gateway(g, settings))
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

fn gateway(gw: &gateway_api::gateways::v1::Gateway, settings: &Settings) -> GatewayModel {
    let key = ObjRef::of(gw);
    let listeners = listeners(&gw.spec.listeners);
    let accepted = if !settings.gateway_namespaces.contains(&key.namespace) {
        Err(Reject::new(
            "NamespaceNotAllowed",
            format!(
                "namespace {:?} is not served by this operator",
                key.namespace
            ),
        ))
    } else if gw.spec.addresses.as_ref().is_some_and(|a| !a.is_empty()) {
        Err(Reject::new(
            "UnsupportedAddress",
            "requesting addresses is not supported; addresses come from the edges",
        ))
    } else if !listeners
        .iter()
        .any(|l| l.accepted.is_ok() && l.conflicted.is_none())
    {
        Err(Reject::new(
            "ListenersNotValid",
            "no listener is both accepted and free of conflicts",
        ))
    } else {
        Ok(())
    };
    GatewayModel {
        key,
        generation: generation(gw),
        accepted,
        listeners,
        edges: Vec::new(),
        addresses: Vec::new(),
        addresses_dropped: 0,
    }
}

fn listeners(specs: &[gateway_api::gateways::v1::GatewayListeners]) -> Vec<ListenerModel> {
    let mut out: Vec<ListenerModel> = specs.iter().map(listener).collect();

    // Listeners sharing a port conflict: on the hostname when the protocol is the same, on
    // the protocol otherwise.
    let mut by_port: BTreeMap<u16, Vec<usize>> = BTreeMap::new();
    for (i, l) in out.iter().enumerate() {
        // Listeners with an invalid port (stored as 0) are already refused; they share nothing.
        if l.port == 0 {
            continue;
        }
        by_port.entry(l.port).or_default().push(i);
    }
    for (port, members) in by_port.into_iter().filter(|(_, m)| m.len() > 1) {
        let same = members
            .iter()
            .all(|&i| out[i].protocol == out[members[0]].protocol);
        let reject = if same {
            Reject::new(
                "HostnameConflict",
                format!(
                    "several listeners use port {port} with protocol {}",
                    out[members[0]].protocol
                ),
            )
        } else {
            Reject::new(
                "ProtocolConflict",
                format!("listeners use port {port} with different protocols"),
            )
        };
        for i in members {
            out[i].conflicted = Some(reject.clone());
        }
    }
    out
}

fn listener(spec: &gateway_api::gateways::v1::GatewayListeners) -> ListenerModel {
    let mut accepted = Ok(());
    let mut resolved_refs = Ok(());
    let mut supported_kinds = vec![ROUTE_KIND.to_owned()];

    let port = match u16::try_from(spec.port) {
        Ok(p) if p != 0 => p,
        _ => {
            accepted = Err(Reject::new(
                "PortUnavailable",
                format!("port {} is not between 1 and 65535", spec.port),
            ));
            0
        }
    };
    if spec.protocol != "TCP" {
        // An invalid port keeps its own rejection.
        if accepted.is_ok() {
            accepted = Err(Reject::new(
                "UnsupportedProtocol",
                format!("protocol {:?} is not supported; only TCP is", spec.protocol),
            ));
        }
        supported_kinds.clear();
    } else if let Some(kinds) = spec
        .allowed_routes
        .as_ref()
        .and_then(|a| a.kinds.as_ref())
        .filter(|k| !k.is_empty())
    {
        let tcp = kinds.iter().any(|k| {
            k.kind == ROUTE_KIND && k.group.as_deref().unwrap_or(ROUTE_GROUP) == ROUTE_GROUP
        });
        if !tcp {
            resolved_refs = Err(Reject::new(
                "InvalidRouteKinds",
                "allowedRoutes.kinds does not include TCPRoute",
            ));
            supported_kinds.clear();
        }
    }

    ListenerModel {
        name: spec.name.clone(),
        port,
        protocol: spec.protocol.clone(),
        accepted,
        conflicted: None,
        resolved_refs,
        supported_kinds,
        allowed_namespaces: route_namespaces(
            spec.allowed_routes
                .as_ref()
                .and_then(|a| a.namespaces.as_ref()),
        ),
        attached_routes: 0,
        backends: Vec::new(),
    }
}

/// A listener's `allowedRoutes.namespaces`; absent means the Gateway's own namespace.
fn route_namespaces(rule: Option<&GatewayListenersAllowedRoutesNamespaces>) -> RouteNamespaces {
    match rule.and_then(|r| r.from.as_ref()) {
        None | Some(From::Same) => RouteNamespaces::Same,
        Some(From::All) => RouteNamespaces::All,
        Some(From::Selector) => {
            RouteNamespaces::Selector(rule.and_then(|r| r.selector.as_ref()).map(|selector| {
                LabelSelector {
                    match_labels: selector.match_labels.clone().unwrap_or_default(),
                    match_expressions: selector
                        .match_expressions
                        .iter()
                        .flatten()
                        .map(|r| LabelRequirement {
                            key: r.key.clone(),
                            operator: r.operator.clone(),
                            values: r.values.clone().unwrap_or_default(),
                        })
                        .collect(),
                }
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::build;
    use super::super::fixtures::*;
    use super::super::{GatewayModel, Model, Reject};

    fn model_of(s: &super::Snapshot) -> Model {
        build(s, &settings(&["infra"]))
    }

    fn reason(r: &Result<(), Reject>) -> &str {
        &r.as_ref().unwrap_err().reason
    }

    fn one(s: &super::Snapshot) -> GatewayModel {
        let m = model_of(s);
        assert_eq!(m.gateways.len(), 1);
        m.gateways.into_iter().next().unwrap()
    }

    fn snap(gw: gateway_api::gateways::v1::Gateway) -> super::Snapshot {
        super::Snapshot {
            gateway_classes: vec![class("ours")],
            gateways: vec![gw],
            ..Default::default()
        }
    }

    #[test]
    fn class_with_our_controller_name_is_listed() {
        let s = super::Snapshot {
            gateway_classes: vec![foreign_class("b"), class("a")],
            ..Default::default()
        };
        let m = model_of(&s);
        let names: Vec<_> = m.classes.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a"]);
        assert_eq!(m.classes[0].generation, 0);
    }

    #[test]
    fn gateway_of_foreign_class_is_ignored() {
        let mut s = snap(
            gateway("infra", "gw")
                .class("theirs")
                .listener("pg", 5432, "TCP"),
        );
        s.gateway_classes.push(foreign_class("theirs"));
        assert!(model_of(&s).gateways.is_empty());
    }

    #[test]
    fn gateway_of_unknown_class_is_ignored() {
        let s = snap(
            gateway("infra", "gw")
                .class("missing")
                .listener("pg", 5432, "TCP"),
        );
        assert!(model_of(&s).gateways.is_empty());
    }

    #[test]
    fn tcp_listener_is_accepted() {
        let g = one(&snap(gateway("infra", "gw").listener("pg", 5432, "TCP")));
        assert_eq!(g.accepted, Ok(()));
        let l = &g.listeners[0];
        assert_eq!(l.accepted, Ok(()));
        assert_eq!(l.resolved_refs, Ok(()));
        assert_eq!(l.conflicted, None);
        assert_eq!(l.supported_kinds, ["TCPRoute"]);
        assert_eq!((l.port, l.attached_routes), (5432, 0));
        assert!(!l.serving());
    }

    #[test]
    fn other_protocols_are_unsupported() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("pg", 5432, "TCP")
                .listener("a", 80, "HTTP")
                .listener("b", 443, "HTTPS")
                .listener("c", 853, "TLS")
                .listener("d", 53, "UDP"),
        ));
        assert_eq!(g.accepted, Ok(()));
        for l in &g.listeners[1..] {
            assert_eq!(reason(&l.accepted), "UnsupportedProtocol", "{}", l.name);
            assert!(l.supported_kinds.is_empty());
        }
    }

    #[test]
    fn gateway_with_no_valid_listener_is_not_accepted() {
        let g = one(&snap(gateway("infra", "gw").listener("a", 80, "HTTP")));
        assert_eq!(reason(&g.accepted), "ListenersNotValid");
    }

    #[test]
    fn gateway_outside_allowed_namespaces() {
        let g = one(&snap(gateway("other", "gw").listener("pg", 5432, "TCP")));
        assert_eq!(reason(&g.accepted), "NamespaceNotAllowed");
    }

    #[test]
    fn requested_addresses_are_unsupported() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("pg", 5432, "TCP")
                .requested_address("203.0.113.9"),
        ));
        assert_eq!(reason(&g.accepted), "UnsupportedAddress");
    }

    #[test]
    fn same_port_same_protocol_conflicts() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a", 5432, "TCP")
                .listener("b", 5432, "TCP")
                .listener("c", 6379, "TCP"),
        ));
        assert_eq!(
            reason(&Err(g.listeners[0].conflicted.clone().unwrap())),
            "HostnameConflict"
        );
        assert_eq!(
            reason(&Err(g.listeners[1].conflicted.clone().unwrap())),
            "HostnameConflict"
        );
        assert_eq!(g.listeners[2].conflicted, None);
        assert_eq!(g.accepted, Ok(()));
    }

    #[test]
    fn same_port_different_protocol_conflicts() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a", 53, "TCP")
                .listener("b", 53, "UDP"),
        ));
        for l in &g.listeners {
            assert_eq!(l.conflicted.as_ref().unwrap().reason, "ProtocolConflict");
        }
        assert_eq!(reason(&g.accepted), "ListenersNotValid");
    }

    #[test]
    fn invalid_port_is_port_unavailable() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("ok", 5432, "TCP")
                .listener("zero", 0, "TCP")
                .listener("big", 70000, "TCP")
                .listener("neg", -1, "TCP"),
        ));
        for l in &g.listeners[1..] {
            assert_eq!(reason(&l.accepted), "PortUnavailable", "{}", l.name);
            assert_eq!(l.conflicted, None);
        }
        assert_eq!(g.listeners[0].accepted, Ok(()));
    }

    #[test]
    fn invalid_port_wins_over_unsupported_protocol() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("ok", 5432, "TCP")
                .listener("bad", 0, "HTTP"),
        ));
        assert_eq!(reason(&g.listeners[1].accepted), "PortUnavailable");
        assert!(g.listeners[1].supported_kinds.is_empty());
    }

    #[test]
    fn invalid_port_listeners_do_not_conflict() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a", 0, "TCP")
                .listener("b", 0, "TCP")
                .listener("ok", 5432, "TCP"),
        ));
        for l in &g.listeners[..2] {
            assert_eq!(reason(&l.accepted), "PortUnavailable");
            assert_eq!(l.conflicted, None);
        }
        assert_eq!(g.listeners[2].accepted, Ok(()));
        assert_eq!(g.listeners[2].conflicted, None);
        assert_eq!(g.accepted, Ok(()));
    }

    #[test]
    fn allowed_kinds_without_tcproute() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("pg", 5432, "TCP")
                .allowed_kinds(&[("gateway.networking.k8s.io", "HTTPRoute")]),
        ));
        let l = &g.listeners[0];
        assert_eq!(reason(&l.resolved_refs), "InvalidRouteKinds");
        assert!(l.supported_kinds.is_empty());
    }

    #[test]
    fn allowed_kinds_with_tcproute_is_fine() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("pg", 5432, "TCP")
                .allowed_kinds(&[("gateway.networking.k8s.io", "TCPRoute")]),
        ));
        assert_eq!(g.listeners[0].resolved_refs, Ok(()));
        assert_eq!(g.listeners[0].supported_kinds, ["TCPRoute"]);
    }

    #[test]
    fn generation_comes_from_metadata() {
        let mut gw = gateway("infra", "gw").listener("pg", 5432, "TCP");
        gw.metadata.generation = Some(7);
        assert_eq!(one(&snap(gw)).generation, 7);
    }
}
