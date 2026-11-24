//! Classes, gateways and listeners.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Secret;
use kube::ResourceExt;

use gateway_api::gateways::v1::{
    GatewayListenersAllowedRoutesNamespaces, GatewayListenersAllowedRoutesNamespacesFrom as From,
    GatewayListenersTlsMode,
};
use iroh_gateway_proto::control::Protocol;

use super::certs;
use super::generation;
use super::{
    ClassModel, GatewayModel, HostMatch, LabelRequirement, LabelSelector, ListenerModel, ObjRef,
    Reject, RouteKind, RouteNamespaces, Settings, Snapshot,
};

pub(super) const ROUTE_GROUP: &str = "gateway.networking.k8s.io";

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
    let secrets: BTreeMap<ObjRef, &Secret> = snapshot
        .secrets
        .iter()
        .map(|s| (ObjRef::of(s), s))
        .collect();
    let mut out: Vec<GatewayModel> = snapshot
        .gateways
        .iter()
        .filter(|g| classes.iter().any(|c| c.name == g.spec.gateway_class_name))
        .map(|g| gateway(g, settings, &secrets))
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

fn gateway(
    gw: &gateway_api::gateways::v1::Gateway,
    settings: &Settings,
    secrets: &BTreeMap<ObjRef, &Secret>,
) -> GatewayModel {
    let key = ObjRef::of(gw);
    let served = settings.gateway_namespaces.contains(&key.namespace);
    let listeners = listeners(&gw.spec.listeners, &key.namespace, served, secrets);
    let accepted = if !served {
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
        http_ports: Vec::new(),
    }
}

fn listeners(
    specs: &[gateway_api::gateways::v1::GatewayListeners],
    gateway_ns: &str,
    served: bool,
    secrets: &BTreeMap<ObjRef, &Secret>,
) -> Vec<ListenerModel> {
    let mut out: Vec<ListenerModel> = specs
        .iter()
        .map(|spec| listener(spec, gateway_ns, served, secrets))
        .collect();

    // Listeners sharing a port of one transport conflict: on the protocol when it differs; on
    // the hostname when it is HTTP or HTTPS, where several hostnames can share a port; on the
    // port otherwise. A UDP listener and a TCP, HTTP or HTTPS one share a port number freely.
    let mut by_port: BTreeMap<(u16, bool), Vec<usize>> = BTreeMap::new();
    for (i, l) in out.iter().enumerate() {
        // Listeners with an invalid port (stored as 0) are already refused; they share nothing.
        if l.port == 0 {
            continue;
        }
        let udp = l.transport() == Protocol::Udp;
        by_port.entry((l.port, udp)).or_default().push(i);
    }
    for ((port, _), members) in by_port.into_iter().filter(|(_, m)| m.len() > 1) {
        let protocol = out[members[0]].protocol.clone();
        if members.iter().any(|&i| out[i].protocol != protocol) {
            let reject = Reject::new(
                "ProtocolConflict",
                format!("listeners use port {port} with different protocols"),
            );
            for i in members {
                out[i].conflicted = Some(reject.clone());
            }
        } else if protocol == "HTTP" || protocol == "HTTPS" {
            // Only listeners that are otherwise valid take part: a refused hostname is not one.
            for &i in &members {
                if out[i].accepted.is_err() {
                    continue;
                }
                let hostname = out[i].hostname.clone();
                let twins = members
                    .iter()
                    .filter(|&&j| out[j].accepted.is_ok() && out[j].hostname == hostname)
                    .count();
                if twins > 1 {
                    out[i].conflicted = Some(Reject::new(
                        "HostnameConflict",
                        format!("several listeners use port {port} with hostname {hostname}"),
                    ));
                }
            }
        } else {
            let reject = Reject::new(
                "HostnameConflict",
                format!("several listeners use port {port} with protocol {protocol}"),
            );
            for i in members {
                out[i].conflicted = Some(reject.clone());
            }
        }
    }
    out
}

/// One listener; `served` says whether the Gateway's namespace is one the operator serves.
fn listener(
    spec: &gateway_api::gateways::v1::GatewayListeners,
    gateway_ns: &str,
    served: bool,
    secrets: &BTreeMap<ObjRef, &Secret>,
) -> ListenerModel {
    let mut accepted = Ok(());
    let mut resolved_refs = Ok(());
    let mut hostname = HostMatch::Any;

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

    let kind = match spec.protocol.as_str() {
        "TCP" => Some(RouteKind::Tcp),
        "UDP" => Some(RouteKind::Udp),
        "HTTP" | "HTTPS" => Some(RouteKind::Http),
        _ => None,
    };
    // An invalid port keeps its own rejection; the first problem found is the one reported.
    let mut refuse = |reason: &str, message: String| {
        if accepted.is_ok() {
            accepted = Err(Reject::new(reason, message));
        }
    };
    match spec.protocol.as_str() {
        "TCP" | "UDP" => {}
        "HTTP" | "HTTPS" => {
            match HostMatch::parse(spec.hostname.as_deref()) {
                Ok(h) => hostname = h,
                Err(message) => refuse("UnsupportedValue", message),
            }
            let passthrough = spec
                .tls
                .as_ref()
                .is_some_and(|t| matches!(t.mode, Some(GatewayListenersTlsMode::Passthrough)));
            if spec.protocol == "HTTPS" && passthrough {
                refuse(
                    "UnsupportedProtocol",
                    "tls.mode Passthrough is not supported; only Terminate is".into(),
                );
            }
        }
        other => refuse(
            "UnsupportedProtocol",
            format!("protocol {other:?} is not supported; TCP, UDP, HTTP and HTTPS are"),
        ),
    }

    let mut supported_kinds = Vec::new();
    if let Some(kind) = kind {
        let name = kind.as_str();
        supported_kinds.push(name.to_owned());
        if let Some(kinds) = spec
            .allowed_routes
            .as_ref()
            .and_then(|a| a.kinds.as_ref())
            .filter(|k| !k.is_empty())
        {
            let is_ours = |k: &&gateway_api::gateways::v1::GatewayListenersAllowedRoutesKinds| {
                k.kind == name && k.group.as_deref().unwrap_or(ROUTE_GROUP) == ROUTE_GROUP
            };
            if !kinds.iter().any(|k| is_ours(&k)) {
                supported_kinds.clear();
            }
            if kinds.iter().any(|k| !is_ours(&k)) {
                resolved_refs = Err(Reject::new(
                    "InvalidRouteKinds",
                    format!("allowedRoutes.kinds lists kinds other than {name}"),
                ));
            }
        }
    }

    // Only an accepted HTTPS listener of a served Gateway has its certificates resolved. A
    // certificate problem is the one that stops the listener, so it replaces an
    // `InvalidRouteKinds` found above.
    let mut certificates = Vec::new();
    if spec.protocol == "HTTPS" && accepted.is_ok() && served {
        match certs::resolve(spec.tls.as_ref(), gateway_ns, secrets) {
            Ok(c) => certificates = c,
            Err(reject) => resolved_refs = Err(reject),
        }
    }

    ListenerModel {
        name: spec.name.clone(),
        port,
        protocol: spec.protocol.clone(),
        hostname,
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
        certificates,
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
    use super::super::{GatewayModel, HostMatch, Model, Reject};
    use gateway_api::gateways::v1::{GatewayListenersTls, GatewayListenersTlsMode};
    use iroh_gateway_proto::control::Protocol;

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
    fn udp_listener_is_accepted_and_supports_udp_routes() {
        let g = one(&snap(gateway("infra", "gw").listener("dns", 53, "UDP")));
        assert_eq!(g.accepted, Ok(()));
        let l = &g.listeners[0];
        assert_eq!(l.accepted, Ok(()));
        assert_eq!(l.resolved_refs, Ok(()));
        assert_eq!(l.conflicted, None);
        assert_eq!(l.supported_kinds, ["UDPRoute"]);
        assert_eq!(l.transport(), Protocol::Udp);
        assert_eq!((l.port, l.attached_routes), (53, 0));
        assert!(!l.serving());
    }

    #[test]
    fn tls_listener_is_unsupported() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("pg", 5432, "TCP")
                .listener("c", 853, "TLS"),
        ));
        assert_eq!(g.accepted, Ok(()));
        let l = &g.listeners[1];
        assert_eq!(reason(&l.accepted), "UnsupportedProtocol");
        assert_eq!(
            l.accepted.as_ref().unwrap_err().message,
            r#"protocol "TLS" is not supported; TCP, UDP, HTTP and HTTPS are"#
        );
        assert!(l.supported_kinds.is_empty());
        // Whatever it is, a listener that is not UDP is bound over TCP.
        assert_eq!(l.transport(), Protocol::Tcp);
        assert_eq!(g.listeners[0].transport(), Protocol::Tcp);
    }

    #[test]
    fn tcp_and_udp_listeners_share_a_port() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("dns-tcp", 53, "TCP")
                .listener("dns-udp", 53, "UDP"),
        ));
        for l in &g.listeners {
            assert_eq!(l.accepted, Ok(()), "{}", l.name);
            assert_eq!(l.conflicted, None, "{}", l.name);
        }
        assert_eq!(g.listeners[0].supported_kinds, ["TCPRoute"]);
        assert_eq!(g.listeners[1].supported_kinds, ["UDPRoute"]);
        assert_eq!(g.accepted, Ok(()));
    }

    #[test]
    fn http_and_udp_listeners_share_a_port() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("web", 443, "HTTPS")
                .hostname("app.example.com")
                .listener("quic", 443, "UDP"),
        ));
        for l in &g.listeners {
            assert_eq!(l.accepted, Ok(()), "{}", l.name);
            assert_eq!(l.conflicted, None, "{}", l.name);
        }
        assert_eq!(g.accepted, Ok(()));
    }

    #[test]
    fn two_udp_listeners_on_one_port_conflict() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a", 53, "UDP")
                .listener("b", 53, "UDP")
                .listener("tcp", 53, "TCP"),
        ));
        for l in &g.listeners[..2] {
            let c = l.conflicted.as_ref().unwrap();
            assert_eq!(c.reason, "HostnameConflict", "{}", l.name);
            assert_eq!(c.message, "several listeners use port 53 with protocol UDP");
        }
        // As two TCP listeners on one port get.
        let tcp = one(&snap(
            gateway("infra", "gw")
                .listener("a", 53, "TCP")
                .listener("b", 53, "TCP"),
        ));
        assert_eq!(
            tcp.listeners[0].conflicted.as_ref().unwrap().message,
            "several listeners use port 53 with protocol TCP"
        );
        // The TCP listener beside them is not conflicted.
        assert_eq!(g.listeners[2].conflicted, None);
        assert_eq!(g.listeners[2].accepted, Ok(()));
        assert_eq!(g.accepted, Ok(()));
    }

    #[test]
    fn udp_listener_ignores_its_hostname() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("dns", 53, "UDP")
                .hostname("not a hostname!"),
        ));
        assert_eq!(g.listeners[0].accepted, Ok(()));
        assert_eq!(g.listeners[0].hostname, HostMatch::Any);
    }

    #[test]
    fn http_listener_is_accepted_and_supports_http_routes() {
        let g = one(&snap(gateway("infra", "gw").listener("web", 80, "HTTP")));
        assert_eq!(g.accepted, Ok(()));
        let l = &g.listeners[0];
        assert_eq!(l.accepted, Ok(()));
        assert_eq!(l.resolved_refs, Ok(()));
        assert_eq!(l.conflicted, None);
        assert_eq!(l.supported_kinds, ["HTTPRoute"]);
        assert_eq!(l.hostname, HostMatch::Any);
        assert_eq!((l.port, l.attached_routes), (80, 0));
    }

    #[test]
    fn https_listener_is_accepted() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("tls", 443, "HTTPS")
                .hostname("app.example.com")
                .tls(GatewayListenersTls {
                    mode: Some(GatewayListenersTlsMode::Terminate),
                    ..Default::default()
                }),
        ));
        assert_eq!(g.accepted, Ok(()));
        let l = &g.listeners[0];
        assert_eq!(l.accepted, Ok(()));
        assert_eq!(l.conflicted, None);
        assert_eq!(l.supported_kinds, ["HTTPRoute"]);
        assert_eq!(l.hostname, HostMatch::Exact("app.example.com".into()));
    }

    #[test]
    fn https_with_passthrough_is_refused() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("ok", 80, "HTTP")
                .listener("tls", 443, "HTTPS")
                .tls(GatewayListenersTls {
                    mode: Some(GatewayListenersTlsMode::Passthrough),
                    ..Default::default()
                }),
        ));
        let reject = g.listeners[1].accepted.as_ref().unwrap_err();
        assert_eq!(reject.reason, "UnsupportedProtocol");
        assert_eq!(
            reject.message,
            "tls.mode Passthrough is not supported; only Terminate is"
        );
    }

    #[test]
    fn hostname_is_lower_cased() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a", 80, "HTTP")
                .hostname("App.Example.COM")
                .listener("b", 81, "HTTP")
                .hostname("*.Example.com"),
        ));
        assert_eq!(
            g.listeners[0].hostname,
            HostMatch::Exact("app.example.com".into())
        );
        assert_eq!(
            g.listeners[1].hostname,
            HostMatch::Wildcard(".example.com".into())
        );
    }

    #[test]
    fn tcp_listener_ignores_its_hostname() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("pg", 5432, "TCP")
                .hostname("not a hostname!"),
        ));
        assert_eq!(g.listeners[0].accepted, Ok(()));
        assert_eq!(g.listeners[0].hostname, HostMatch::Any);
    }

    #[test]
    fn invalid_hostname_refuses_the_listener() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("ok", 80, "HTTP")
                .listener("bad", 81, "HTTP")
                .hostname("ex'ample.com")
                .listener("ip", 82, "HTTPS")
                .hostname("10.0.0.1"),
        ));
        for l in &g.listeners[1..] {
            assert_eq!(reason(&l.accepted), "UnsupportedValue", "{}", l.name);
        }
        assert_eq!(g.listeners[0].accepted, Ok(()));
    }

    #[test]
    fn http_listeners_with_different_hostnames_share_a_port() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a", 80, "HTTP")
                .hostname("a.example.com")
                .listener("b", 80, "HTTP")
                .hostname("b.example.com")
                .listener("w", 80, "HTTP")
                .hostname("*.example.com")
                .listener("any", 80, "HTTP"),
        ));
        for l in &g.listeners {
            assert_eq!(l.conflicted, None, "{}", l.name);
        }
        assert_eq!(g.accepted, Ok(()));
    }

    #[test]
    fn http_listeners_with_the_same_hostname_conflict() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a1", 80, "HTTP")
                .hostname("a.example.com")
                .listener("a2", 80, "HTTP")
                .hostname("A.example.com")
                .listener("b", 80, "HTTP")
                .hostname("b.example.com"),
        ));
        for l in &g.listeners[..2] {
            let c = l.conflicted.as_ref().unwrap();
            assert_eq!(c.reason, "HostnameConflict");
            assert_eq!(
                c.message,
                "several listeners use port 80 with hostname a.example.com"
            );
        }
        assert_eq!(g.listeners[2].conflicted, None);
        assert_eq!(g.accepted, Ok(()));
    }

    #[test]
    fn two_http_listeners_without_hostname_conflict() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a", 80, "HTTP")
                .listener("b", 80, "HTTP"),
        ));
        for l in &g.listeners {
            let c = l.conflicted.as_ref().unwrap();
            assert_eq!(c.reason, "HostnameConflict");
            assert_eq!(
                c.message,
                "several listeners use port 80 with hostname (any)"
            );
        }
        assert_eq!(reason(&g.accepted), "ListenersNotValid");
    }

    #[test]
    fn refused_listener_takes_no_part_in_hostname_conflicts() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("any", 80, "HTTP")
                .listener("bad", 80, "HTTP")
                .hostname("ex'ample.com"),
        ));
        assert_eq!(reason(&g.listeners[1].accepted), "UnsupportedValue");
        // Both would answer for any host if the refused one counted; it does not.
        assert_eq!(g.listeners[0].accepted, Ok(()));
        assert_eq!(g.listeners[0].conflicted, None);
        assert_eq!(g.listeners[1].conflicted, None);
        assert_eq!(g.accepted, Ok(()));
    }

    #[test]
    fn https_listeners_share_a_port_by_hostname() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a", 443, "HTTPS")
                .hostname("a.example.com")
                .listener("b", 443, "HTTPS")
                .hostname("b.example.com")
                .listener("c", 443, "HTTPS")
                .hostname("b.example.com"),
        ));
        assert_eq!(g.listeners[0].conflicted, None);
        assert!(g.listeners[1].conflicted.is_some());
        assert!(g.listeners[2].conflicted.is_some());
    }

    #[test]
    fn http_and_https_on_one_port_conflict() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a", 80, "HTTP")
                .hostname("a.example.com")
                .listener("b", 80, "HTTPS")
                .hostname("b.example.com"),
        ));
        for l in &g.listeners {
            assert_eq!(l.conflicted.as_ref().unwrap().reason, "ProtocolConflict");
        }
    }

    #[test]
    fn tcp_and_http_on_one_port_conflict() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a", 80, "TCP")
                .listener("b", 80, "HTTP"),
        ));
        for l in &g.listeners {
            assert_eq!(l.conflicted.as_ref().unwrap().reason, "ProtocolConflict");
        }
    }

    #[test]
    fn two_tcp_listeners_on_one_port_still_conflict() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("a", 5432, "TCP")
                .listener("b", 5432, "TCP"),
        ));
        for l in &g.listeners {
            assert_eq!(l.conflicted.as_ref().unwrap().reason, "HostnameConflict");
        }
    }

    #[test]
    fn allowed_kinds_with_an_unsupported_kind_keep_the_supported_one() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("pg", 5432, "TCP")
                .allowed_kinds(&[
                    ("gateway.networking.k8s.io", "TCPRoute"),
                    ("gateway.networking.k8s.io", "HTTPRoute"),
                    ("gateway.networking.k8s.io", "TCPRoute"),
                ]),
        ));
        let l = &g.listeners[0];
        assert_eq!(reason(&l.resolved_refs), "InvalidRouteKinds");
        assert_eq!(l.supported_kinds, ["TCPRoute"]);
        assert_eq!(l.accepted, Ok(()));
    }

    #[test]
    fn allowed_kinds_of_another_group_are_invalid() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("web", 80, "HTTP")
                .allowed_kinds(&[("example.com", "HTTPRoute")]),
        ));
        let l = &g.listeners[0];
        assert_eq!(reason(&l.resolved_refs), "InvalidRouteKinds");
        assert!(l.supported_kinds.is_empty());
    }

    #[test]
    fn http_listener_with_http_route_kind_is_fine() {
        let g = one(&snap(
            gateway("infra", "gw")
                .listener("web", 80, "HTTP")
                .allowed_kinds(&[("gateway.networking.k8s.io", "HTTPRoute")]),
        ));
        assert_eq!(g.listeners[0].resolved_refs, Ok(()));
        assert_eq!(g.listeners[0].supported_kinds, ["HTTPRoute"]);
    }

    #[test]
    fn http_listener_serves_once_a_route_is_attached() {
        let mut g = one(&snap(gateway("infra", "gw").listener("web", 80, "HTTP")));
        let l = &mut g.listeners[0];
        assert!(!l.serving());
        l.attached_routes = 1;
        assert!(l.serving());
        l.conflicted = Some(Reject::new("HostnameConflict", "x"));
        assert!(!l.serving());
    }

    #[test]
    fn gateway_with_no_valid_listener_is_not_accepted() {
        let g = one(&snap(gateway("infra", "gw").listener("a", 80, "TLS")));
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
                .listener("b", 53, "TLS"),
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
                .listener("bad", 0, "TLS"),
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
