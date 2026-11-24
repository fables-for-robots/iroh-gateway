//! Builders for real Gateway API and `Edge` objects, so tests read like the cases they cover.

use std::collections::BTreeMap;

use gateway_api::gatewayclasses::v1::{GatewayClass, GatewayClassSpec};
use gateway_api::gateways::v1::{
    Gateway, GatewayAddresses, GatewayListeners, GatewayListenersAllowedRoutes,
    GatewayListenersAllowedRoutesKinds, GatewayListenersAllowedRoutesNamespaces,
    GatewayListenersAllowedRoutesNamespacesFrom, GatewayListenersAllowedRoutesNamespacesSelector,
    GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions, GatewayListenersTls,
    GatewaySpec,
};
use gateway_api::httproutes::v1::{HttpRoute, HttpRouteParentRefs, HttpRouteSpec};
use gateway_api::tcproutes::v1::{
    TcpRoute, TcpRouteParentRefs, TcpRouteRules, TcpRouteRulesBackendRefs, TcpRouteSpec,
};
use iroh_gateway_proto::transport::Relay;
use k8s_openapi::api::core::v1::{Namespace, Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

use super::Settings;
use crate::crd::{Edge, EdgeGatewayRef, EdgeSpec};

pub const CONTROLLER: &str = "gateway.fables-for-robots.ch/controller";

pub fn class(name: &str) -> GatewayClass {
    class_of(name, CONTROLLER)
}

pub fn foreign_class(name: &str) -> GatewayClass {
    class_of(name, "example.com/other-controller")
}

fn class_of(name: &str, controller: &str) -> GatewayClass {
    GatewayClass::new(
        name,
        GatewayClassSpec {
            controller_name: controller.into(),
            ..Default::default()
        },
    )
}

/// A gateway of class `ours`, with no listeners.
pub fn gateway(ns: &str, name: &str) -> Gateway {
    let mut gw = Gateway::new(
        name,
        GatewaySpec {
            gateway_class_name: "ours".into(),
            ..Default::default()
        },
    );
    gw.metadata.namespace = Some(ns.into());
    gw
}

pub trait GatewayExt: Sized {
    fn class(self, name: &str) -> Self;
    fn listener(self, name: &str, port: i32, protocol: &str) -> Self;
    /// Applies to the last listener.
    /// Sets the hostname of the last listener.
    fn hostname(self, hostname: &str) -> Self;
    /// Sets `tls` on the last listener.
    fn tls(self, tls: GatewayListenersTls) -> Self;
    fn allowed_kinds(self, kinds: &[(&str, &str)]) -> Self;
    fn allow_all_namespaces(self) -> Self;
    fn allow_selector(self, labels: &[(&str, &str)]) -> Self;
    /// `from: Selector` with only `matchExpressions`: (key, operator, values).
    fn allow_expressions(self, exprs: &[(&str, &str, &[&str])]) -> Self;
    /// `from: Selector` with the given selector, `None` for no selector at all.
    fn allow_raw_selector(
        self,
        selector: Option<GatewayListenersAllowedRoutesNamespacesSelector>,
    ) -> Self;
    fn requested_address(self, value: &str) -> Self;
}

fn last(gw: &mut Gateway) -> &mut GatewayListeners {
    gw.spec.listeners.last_mut().expect("add a listener first")
}

fn namespaces(l: &mut GatewayListeners) -> &mut GatewayListenersAllowedRoutesNamespaces {
    l.allowed_routes
        .get_or_insert_with(GatewayListenersAllowedRoutes::default)
        .namespaces
        .get_or_insert_with(GatewayListenersAllowedRoutesNamespaces::default)
}

impl GatewayExt for Gateway {
    fn class(mut self, name: &str) -> Self {
        self.spec.gateway_class_name = name.into();
        self
    }

    fn listener(mut self, name: &str, port: i32, protocol: &str) -> Self {
        self.spec.listeners.push(GatewayListeners {
            name: name.into(),
            port,
            protocol: protocol.into(),
            ..Default::default()
        });
        self
    }

    fn hostname(mut self, hostname: &str) -> Self {
        last(&mut self).hostname = Some(hostname.into());
        self
    }

    fn tls(mut self, tls: GatewayListenersTls) -> Self {
        last(&mut self).tls = Some(tls);
        self
    }

    fn allowed_kinds(mut self, kinds: &[(&str, &str)]) -> Self {
        last(&mut self)
            .allowed_routes
            .get_or_insert_with(GatewayListenersAllowedRoutes::default)
            .kinds = Some(
            kinds
                .iter()
                .map(|(g, k)| GatewayListenersAllowedRoutesKinds {
                    group: Some((*g).into()),
                    kind: (*k).into(),
                })
                .collect(),
        );
        self
    }

    fn allow_all_namespaces(mut self) -> Self {
        namespaces(last(&mut self)).from = Some(GatewayListenersAllowedRoutesNamespacesFrom::All);
        self
    }

    fn allow_selector(mut self, labels: &[(&str, &str)]) -> Self {
        let ns = namespaces(last(&mut self));
        ns.from = Some(GatewayListenersAllowedRoutesNamespacesFrom::Selector);
        ns.selector = Some(GatewayListenersAllowedRoutesNamespacesSelector {
            match_labels: Some(
                labels
                    .iter()
                    .map(|(k, v)| ((*k).into(), (*v).into()))
                    .collect(),
            ),
            ..Default::default()
        });
        self
    }

    fn allow_expressions(self, exprs: &[(&str, &str, &[&str])]) -> Self {
        self.allow_raw_selector(Some(GatewayListenersAllowedRoutesNamespacesSelector {
            match_expressions: Some(
                exprs
                    .iter()
                    .map(|(key, operator, values)| {
                        GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions {
                            key: (*key).into(),
                            operator: (*operator).into(),
                            values: (!values.is_empty())
                                .then(|| values.iter().map(|v| (*v).into()).collect()),
                        }
                    })
                    .collect(),
            ),
            match_labels: None,
        }))
    }

    fn allow_raw_selector(
        mut self,
        selector: Option<GatewayListenersAllowedRoutesNamespacesSelector>,
    ) -> Self {
        let ns = namespaces(last(&mut self));
        ns.from = Some(GatewayListenersAllowedRoutesNamespacesFrom::Selector);
        ns.selector = selector;
        self
    }

    fn requested_address(mut self, value: &str) -> Self {
        self.spec
            .addresses
            .get_or_insert_with(Vec::new)
            .push(GatewayAddresses {
                value: Some(value.into()),
                ..Default::default()
            });
        self
    }
}

/// An edge whose endpoint id is derived from `key_seed`, with an address, bound to gateway
/// `public`.
pub fn edge(ns: &str, name: &str, key_seed: u8) -> Edge {
    let id = iroh::SecretKey::from_bytes(&[key_seed; 32]).public();
    let mut e = Edge::new(
        name,
        EdgeSpec {
            endpoint_id: id.to_string(),
            address: Some("203.0.113.7:7842".into()),
            gateway_ref: EdgeGatewayRef {
                name: "public".into(),
            },
            public_addresses: Vec::new(),
        },
    );
    e.metadata.namespace = Some(ns.into());
    e
}

pub trait EdgeExt: Sized {
    fn address(self, address: &str) -> Self;
    fn no_address(self) -> Self;
    fn gateway(self, name: &str) -> Self;
    fn public(self, address: &str) -> Self;
    /// Creation time, in seconds after the epoch.
    fn created(self, seconds: i64) -> Self;
}

impl EdgeExt for Edge {
    fn address(mut self, address: &str) -> Self {
        self.spec.address = Some(address.into());
        self
    }

    fn no_address(mut self) -> Self {
        self.spec.address = None;
        self
    }

    fn gateway(mut self, name: &str) -> Self {
        self.spec.gateway_ref.name = name.into();
        self
    }

    fn public(mut self, address: &str) -> Self {
        self.spec.public_addresses.push(address.into());
        self
    }

    fn created(mut self, seconds: i64) -> Self {
        self.metadata.creation_timestamp = Some(time(seconds));
        self
    }
}

/// Our controller, no relay, serving the given namespaces.
pub fn settings(namespaces: &[&str]) -> Settings {
    Settings {
        controller_name: CONTROLLER.into(),
        gateway_namespaces: namespaces.iter().map(|n| (*n).to_owned()).collect(),
        relay: Relay::Disabled,
    }
}

pub fn ns(name: &str, labels: &[(&str, &str)]) -> Namespace {
    let labels: BTreeMap<String, String> = labels
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect();
    Namespace {
        metadata: ObjectMeta {
            name: Some(name.into()),
            labels: Some(labels),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// A route with one empty rule and no parents.
pub fn tcp_route(ns: &str, name: &str) -> TcpRoute {
    let mut r = TcpRoute::new(
        name,
        TcpRouteSpec {
            parent_refs: None,
            rules: vec![TcpRouteRules::default()],
        },
    );
    r.metadata.namespace = Some(ns.into());
    r
}

pub trait RouteExt: Sized {
    /// A parent gateway in the route's namespace.
    fn parent(self, gateway: &str) -> Self;
    fn parent_in(self, ns: &str, gateway: &str) -> Self;
    /// Applies to the last parent.
    fn section(self, name: &str) -> Self;
    /// Applies to the last parent.
    fn port(self, port: i32) -> Self;
    /// Applies to the last rule, as do the other backend builders.
    fn backend(self, service: &str, port: i32) -> Self;
    fn weighted(self, service: &str, port: i32, weight: i32) -> Self;
    fn backend_in(self, ns: &str, service: &str, port: i32) -> Self;
    /// A backend of another group and kind, on port 5432.
    fn backend_kind(self, group: &str, kind: &str, name: &str) -> Self;
    /// Starts a new, empty rule.
    fn second_rule(self) -> Self;
    /// Creation time, in seconds after the epoch.
    fn created(self, seconds: i64) -> Self;
}

fn last_parent(r: &mut TcpRoute) -> &mut TcpRouteParentRefs {
    r.spec
        .parent_refs
        .as_mut()
        .and_then(|p| p.last_mut())
        .expect("add a parent first")
}

fn push_backend(mut r: TcpRoute, b: TcpRouteRulesBackendRefs) -> TcpRoute {
    r.spec
        .rules
        .last_mut()
        .expect("a route has a rule")
        .backend_refs
        .push(b);
    r
}

impl RouteExt for TcpRoute {
    fn parent(mut self, gateway: &str) -> Self {
        self.spec
            .parent_refs
            .get_or_insert_with(Vec::new)
            .push(TcpRouteParentRefs {
                name: gateway.into(),
                ..Default::default()
            });
        self
    }

    fn parent_in(mut self, ns: &str, gateway: &str) -> Self {
        self = self.parent(gateway);
        last_parent(&mut self).namespace = Some(ns.into());
        self
    }

    fn section(mut self, name: &str) -> Self {
        last_parent(&mut self).section_name = Some(name.into());
        self
    }

    fn port(mut self, port: i32) -> Self {
        last_parent(&mut self).port = Some(port);
        self
    }

    fn backend(self, service: &str, port: i32) -> Self {
        push_backend(
            self,
            TcpRouteRulesBackendRefs {
                name: service.into(),
                port: Some(port),
                ..Default::default()
            },
        )
    }

    fn weighted(self, service: &str, port: i32, weight: i32) -> Self {
        push_backend(
            self,
            TcpRouteRulesBackendRefs {
                name: service.into(),
                port: Some(port),
                weight: Some(weight),
                ..Default::default()
            },
        )
    }

    fn backend_in(self, ns: &str, service: &str, port: i32) -> Self {
        push_backend(
            self,
            TcpRouteRulesBackendRefs {
                name: service.into(),
                namespace: Some(ns.into()),
                port: Some(port),
                ..Default::default()
            },
        )
    }

    fn backend_kind(self, group: &str, kind: &str, name: &str) -> Self {
        push_backend(
            self,
            TcpRouteRulesBackendRefs {
                group: Some(group.into()),
                kind: Some(kind.into()),
                name: name.into(),
                port: Some(5432),
                ..Default::default()
            },
        )
    }

    fn second_rule(mut self) -> Self {
        self.spec.rules.push(TcpRouteRules::default());
        self
    }

    fn created(mut self, seconds: i64) -> Self {
        self.metadata.creation_timestamp = Some(time(seconds));
        self
    }
}

/// An HTTPRoute with no parents, hostnames or rules.
pub fn http_route(ns: &str, name: &str) -> HttpRoute {
    let mut r = HttpRoute::new(name, HttpRouteSpec::default());
    r.metadata.namespace = Some(ns.into());
    r
}

pub trait HttpRouteExt: Sized {
    /// A parent gateway in the route's namespace.
    fn parent(self, gateway: &str) -> Self;
    /// Applies to the last parent.
    fn section(self, name: &str) -> Self;
}

impl HttpRouteExt for HttpRoute {
    fn parent(mut self, gateway: &str) -> Self {
        self.spec
            .parent_refs
            .get_or_insert_with(Vec::new)
            .push(HttpRouteParentRefs {
                name: gateway.into(),
                ..Default::default()
            });
        self
    }

    fn section(mut self, name: &str) -> Self {
        self.spec
            .parent_refs
            .as_mut()
            .and_then(|p| p.last_mut())
            .expect("add a parent first")
            .section_name = Some(name.into());
        self
    }
}

fn time(seconds: i64) -> Time {
    Time(k8s_openapi::jiff::Timestamp::from_second(seconds).expect("in range"))
}

/// A `ClusterIP` service with TCP ports.
pub fn service(ns: &str, name: &str, cluster_ip: &str, ports: &[i32]) -> Service {
    Service {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".into()),
            cluster_ip: Some(cluster_ip.into()),
            ports: Some(
                ports
                    .iter()
                    .map(|&port| ServicePort {
                        port,
                        ..Default::default()
                    })
                    .collect(),
            ),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub trait ServiceExt: Sized {
    /// Type `ExternalName`; the cluster IP is left as it was.
    fn external_name(self) -> Self;
}

impl ServiceExt for Service {
    fn external_name(mut self) -> Self {
        let spec = self.spec.get_or_insert_with(ServiceSpec::default);
        spec.type_ = Some("ExternalName".into());
        spec.external_name = Some("db.example.com".into());
        self
    }
}
