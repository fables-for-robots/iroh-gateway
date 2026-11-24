//! Builders for real Gateway API and `Edge` objects, so tests read like the cases they cover.

use std::collections::BTreeMap;

use gateway_api::gatewayclasses::v1::{GatewayClass, GatewayClassSpec};
use gateway_api::gateways::v1::{
    Gateway, GatewayAddresses, GatewayListeners, GatewayListenersAllowedRoutes,
    GatewayListenersAllowedRoutesKinds, GatewayListenersAllowedRoutesNamespaces,
    GatewayListenersAllowedRoutesNamespacesFrom, GatewayListenersAllowedRoutesNamespacesSelector,
    GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions, GatewayListenersTls,
    GatewayListenersTlsCertificateRefs, GatewaySpec,
};
use gateway_api::httproutes::v1::{
    HttpRoute, HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs,
    HttpRouteRulesFilters, HttpRouteRulesMatches, HttpRouteSpec,
};
use gateway_api::tcproutes::v1::{
    TcpRoute, TcpRouteParentRefs, TcpRouteRules, TcpRouteRulesBackendRefs, TcpRouteSpec,
};
use gateway_api::udproutes::v1::{
    UdpRoute, UdpRouteParentRefs, UdpRouteRules, UdpRouteRulesBackendRefs, UdpRouteSpec,
};
use iroh_gateway_proto::transport::Relay;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::{Namespace, Secret, Service, ServicePort, ServiceSpec};
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
    /// Sets the hostname of the last listener.
    fn hostname(self, hostname: &str) -> Self;
    /// Sets `tls` on the last listener.
    fn tls(self, tls: GatewayListenersTls) -> Self;
    /// Adds a `certificateRef` to the Secret `name`, group and kind left out, to the last
    /// listener's `tls`.
    fn certificate(self, name: &str) -> Self;
    /// Sets `allowedRoutes.kinds` of the last listener: (group, kind).
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

    fn certificate(mut self, name: &str) -> Self {
        last(&mut self)
            .tls
            .get_or_insert_with(GatewayListenersTls::default)
            .certificate_refs
            .get_or_insert_with(Vec::new)
            .push(GatewayListenersTlsCertificateRefs {
                name: name.into(),
                ..Default::default()
            });
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

/// A UDPRoute with one empty rule and no parents; built on as a [`tcp_route`] is.
pub fn udp_route(ns: &str, name: &str) -> UdpRoute {
    let mut r = UdpRoute::new(
        name,
        UdpRouteSpec {
            parent_refs: None,
            rules: vec![UdpRouteRules::default()],
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

/// `RouteExt` for a generated route type with `parentRefs` and `rules` of `backendRefs`, as
/// `TCPRoute` and `UDPRoute` have, in a module of its own.
macro_rules! route_ext {
    ($module:ident, $route:ident, $parent:ident, $rules:ident, $backend:ident) => {
        mod $module {
            use super::*;

            fn last_parent(r: &mut $route) -> &mut $parent {
                r.spec
                    .parent_refs
                    .as_mut()
                    .and_then(|p| p.last_mut())
                    .expect("add a parent first")
            }

            fn push_backend(mut r: $route, b: $backend) -> $route {
                r.spec
                    .rules
                    .last_mut()
                    .expect("a route has a rule")
                    .backend_refs
                    .push(b);
                r
            }

            impl RouteExt for $route {
                fn parent(mut self, gateway: &str) -> Self {
                    self.spec
                        .parent_refs
                        .get_or_insert_with(Vec::new)
                        .push($parent {
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
                        $backend {
                            name: service.into(),
                            port: Some(port),
                            ..Default::default()
                        },
                    )
                }

                fn weighted(self, service: &str, port: i32, weight: i32) -> Self {
                    push_backend(
                        self,
                        $backend {
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
                        $backend {
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
                        $backend {
                            group: Some(group.into()),
                            kind: Some(kind.into()),
                            name: name.into(),
                            port: Some(5432),
                            ..Default::default()
                        },
                    )
                }

                fn second_rule(mut self) -> Self {
                    self.spec.rules.push($rules::default());
                    self
                }

                fn created(mut self, seconds: i64) -> Self {
                    self.metadata.creation_timestamp = Some(time(seconds));
                    self
                }
            }
        }
    };
}

route_ext!(
    tcp,
    TcpRoute,
    TcpRouteParentRefs,
    TcpRouteRules,
    TcpRouteRulesBackendRefs
);
route_ext!(
    udp,
    UdpRoute,
    UdpRouteParentRefs,
    UdpRouteRules,
    UdpRouteRulesBackendRefs
);

/// An HTTPRoute with no parents, hostnames or rules.
pub fn http_route(ns: &str, name: &str) -> HttpRoute {
    let mut r = HttpRoute::new(name, HttpRouteSpec::default());
    r.metadata.namespace = Some(ns.into());
    r
}

pub trait HttpRouteExt: Sized {
    /// A parent gateway in the route's namespace.
    fn parent(self, gateway: &str) -> Self;
    fn parent_in(self, ns: &str, gateway: &str) -> Self;
    /// Applies to the last parent.
    fn section(self, name: &str) -> Self;
    /// Adds an entry to `hostnames`.
    fn hostname(self, hostname: &str) -> Self;
    /// Starts a new, empty rule.
    fn rule(self) -> Self;
    /// Adds a match to the last rule, as do the filter and backend builders; they start a rule
    /// if there is none.
    fn matching(self, m: HttpRouteRulesMatches) -> Self;
    fn filter(self, f: HttpRouteRulesFilters) -> Self;
    fn backend(self, service: &str, port: i32) -> Self;
    fn weighted(self, service: &str, port: i32, weight: i32) -> Self;
    fn backend_in(self, ns: &str, service: &str, port: i32) -> Self;
    /// Creation time, in seconds after the epoch.
    fn created(self, seconds: i64) -> Self;
}

fn last_http_rule(r: &mut HttpRoute) -> &mut HttpRouteRules {
    let rules = r.spec.rules.get_or_insert_with(Vec::new);
    if rules.is_empty() {
        rules.push(HttpRouteRules::default());
    }
    rules.last_mut().expect("just ensured")
}

fn push_http_backend(mut r: HttpRoute, b: HttpRouteRulesBackendRefs) -> HttpRoute {
    last_http_rule(&mut r)
        .backend_refs
        .get_or_insert_with(Vec::new)
        .push(b);
    r
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

    fn parent_in(self, ns: &str, gateway: &str) -> Self {
        let mut r = self.parent(gateway);
        r.spec
            .parent_refs
            .as_mut()
            .and_then(|p| p.last_mut())
            .expect("just added")
            .namespace = Some(ns.into());
        r
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

    fn hostname(mut self, hostname: &str) -> Self {
        self.spec
            .hostnames
            .get_or_insert_with(Vec::new)
            .push(hostname.into());
        self
    }

    fn rule(mut self) -> Self {
        self.spec
            .rules
            .get_or_insert_with(Vec::new)
            .push(HttpRouteRules::default());
        self
    }

    fn matching(mut self, m: HttpRouteRulesMatches) -> Self {
        last_http_rule(&mut self)
            .matches
            .get_or_insert_with(Vec::new)
            .push(m);
        self
    }

    fn filter(mut self, f: HttpRouteRulesFilters) -> Self {
        last_http_rule(&mut self)
            .filters
            .get_or_insert_with(Vec::new)
            .push(f);
        self
    }

    fn backend(self, service: &str, port: i32) -> Self {
        push_http_backend(
            self,
            HttpRouteRulesBackendRefs {
                name: service.into(),
                port: Some(port),
                ..Default::default()
            },
        )
    }

    fn weighted(self, service: &str, port: i32, weight: i32) -> Self {
        push_http_backend(
            self,
            HttpRouteRulesBackendRefs {
                name: service.into(),
                port: Some(port),
                weight: Some(weight),
                ..Default::default()
            },
        )
    }

    fn backend_in(self, ns: &str, service: &str, port: i32) -> Self {
        push_http_backend(
            self,
            HttpRouteRulesBackendRefs {
                name: service.into(),
                namespace: Some(ns.into()),
                port: Some(port),
                ..Default::default()
            },
        )
    }

    fn created(mut self, seconds: i64) -> Self {
        self.metadata.creation_timestamp = Some(time(seconds));
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
    /// Adds a port with `protocol: UDP`.
    fn udp_port(self, port: i32) -> Self;
}

impl ServiceExt for Service {
    fn udp_port(mut self, port: i32) -> Self {
        self.spec
            .get_or_insert_with(ServiceSpec::default)
            .ports
            .get_or_insert_with(Vec::new)
            .push(ServicePort {
                port,
                protocol: Some("UDP".into()),
                ..Default::default()
            });
        self
    }

    fn external_name(mut self) -> Self {
        let spec = self.spec.get_or_insert_with(ServiceSpec::default);
        spec.type_ = Some("ExternalName".into());
        spec.external_name = Some("db.example.com".into());
        self
    }
}

/// A Secret of type `kubernetes.io/tls` with the given `tls.crt` and `tls.key`.
pub fn tls_secret(ns: &str, name: &str, crt_pem: &str, key_pem: &str) -> Secret {
    Secret {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            ..Default::default()
        },
        type_: Some("kubernetes.io/tls".into()),
        data: Some(BTreeMap::from([
            (
                "tls.crt".to_owned(),
                ByteString(crt_pem.as_bytes().to_vec()),
            ),
            (
                "tls.key".to_owned(),
                ByteString(key_pem.as_bytes().to_vec()),
            ),
        ])),
        ..Default::default()
    }
}

/// A fresh self-signed certificate for `app.example.com` and its ECDSA P-256 key, as PEM:
/// (certificate, key).
pub fn self_signed() -> (String, String) {
    self_signed_with(&rcgen::PKCS_ECDSA_P256_SHA256)
}

/// [`self_signed`] with a key of the given algorithm.
pub fn self_signed_with(alg: &'static rcgen::SignatureAlgorithm) -> (String, String) {
    let key = rcgen::KeyPair::generate_for(alg).expect("generate a key");
    let cert = rcgen::CertificateParams::new(vec!["app.example.com".to_owned()])
        .expect("valid names")
        .self_signed(&key)
        .expect("sign");
    (cert.pem(), key.serialize_pem())
}
