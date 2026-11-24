//! The model: what the cluster asks for, reduced by pure functions to what the operator will do.
//!
//! [`build`] takes a [`Snapshot`] of the watched resources and the operator's [`Settings`] and
//! returns a [`Model`]. It does no I/O and reads no clock, so equal inputs give equal models.

mod edges;
#[cfg(test)]
pub(crate) mod fixtures;
mod gateways;
mod http;
mod routes;

use std::collections::BTreeSet;
use std::fmt::{self, Debug};
use std::net::IpAddr;

use gateway_api::gatewayclasses::v1::GatewayClass;
use gateway_api::gateways::v1::Gateway;
use gateway_api::httproutes::v1::{
    HttpRoute, HttpRouteParentRefs, HttpRouteStatusParents, HttpRouteStatusParentsParentRef,
};
use gateway_api::tcproutes::v1::{
    TcpRoute, TcpRouteParentRefs, TcpRouteStatusParents, TcpRouteStatusParentsParentRef,
};
use iroh_gateway_proto::transport::Relay;
use k8s_openapi::api::core::v1::{Namespace, Secret, Service};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::ResourceExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::crd::Edge;

pub use http::HostMatch;
pub(crate) use routes::parent_key;

/// A namespaced object, by name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjRef {
    pub namespace: String,
    pub name: String,
}

impl ObjRef {
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }

    /// The reference to a namespaced Kubernetes object.
    pub(crate) fn of<K: ResourceExt>(object: &K) -> Self {
        Self::new(object.namespace().unwrap_or_default(), object.name_any())
    }
}

impl fmt::Display for ObjRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// What the operator was started with.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The `controllerName` of the `GatewayClass`es this operator owns.
    pub controller_name: String,
    /// Namespaces in which `Gateway`s and `Edge`s are honoured.
    pub gateway_namespaces: BTreeSet<String>,
    pub relay: Relay,
}

/// Everything the operator watches, as last seen.
#[derive(Default, Clone)]
pub struct Snapshot {
    pub gateway_classes: Vec<GatewayClass>,
    pub gateways: Vec<Gateway>,
    pub tcp_routes: Vec<TcpRoute>,
    pub http_routes: Vec<HttpRoute>,
    pub edges: Vec<Edge>,
    pub services: Vec<Service>,
    pub namespaces: Vec<Namespace>,
    pub secrets: Vec<Secret>,
}

/// The kinds of route the operator attaches to listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RouteKind {
    Tcp,
    Http,
}

impl RouteKind {
    /// The resource's `kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::Tcp => "TCPRoute",
            RouteKind::Http => "HTTPRoute",
        }
    }
}

/// A `parentRef`, in a route's spec or in its status, as written. Absent fields are not serialised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParentRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
}

/// One entry of a route's `status.parents`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParentStatus {
    pub parent_ref: ParentRef,
    pub controller_name: String,
    pub conditions: Vec<Condition>,
}

/// What the model and the status writer need from a route resource.
pub trait RouteResource:
    kube::Resource<DynamicType = ()> + Clone + DeserializeOwned + Debug + Send + Sync + 'static
{
    const KIND: RouteKind;
    /// `spec.parentRefs`, in order.
    fn parent_refs(&self) -> Vec<ParentRef>;
    /// `status.parents`, in order.
    fn status_parents(&self) -> Vec<ParentStatus>;
}

/// `From<&$t> for ParentRef` for the generated `parentRef` types, which all have the same fields.
macro_rules! parent_ref_from {
    ($($t:ty),*) => {$(
        impl From<&$t> for ParentRef {
            fn from(p: &$t) -> Self {
                Self {
                    group: p.group.clone(),
                    kind: p.kind.clone(),
                    namespace: p.namespace.clone(),
                    name: p.name.clone(),
                    section_name: p.section_name.clone(),
                    port: p.port,
                }
            }
        }
    )*};
}

parent_ref_from!(
    TcpRouteParentRefs,
    TcpRouteStatusParentsParentRef,
    HttpRouteParentRefs,
    HttpRouteStatusParentsParentRef
);

/// `From<&$t> for ParentStatus` for the generated status entry types.
macro_rules! parent_status_from {
    ($($t:ty),*) => {$(
        impl From<&$t> for ParentStatus {
            fn from(p: &$t) -> Self {
                Self {
                    parent_ref: ParentRef::from(&p.parent_ref),
                    controller_name: p.controller_name.clone(),
                    conditions: p.conditions.clone(),
                }
            }
        }
    )*};
}

parent_status_from!(TcpRouteStatusParents, HttpRouteStatusParents);

impl RouteResource for TcpRoute {
    const KIND: RouteKind = RouteKind::Tcp;

    fn parent_refs(&self) -> Vec<ParentRef> {
        self.spec
            .parent_refs
            .iter()
            .flatten()
            .map(ParentRef::from)
            .collect()
    }

    fn status_parents(&self) -> Vec<ParentStatus> {
        self.status
            .iter()
            .flat_map(|s| &s.parents)
            .map(ParentStatus::from)
            .collect()
    }
}

impl RouteResource for HttpRoute {
    const KIND: RouteKind = RouteKind::Http;

    fn parent_refs(&self) -> Vec<ParentRef> {
        self.spec
            .parent_refs
            .iter()
            .flatten()
            .map(ParentRef::from)
            .collect()
    }

    fn status_parents(&self) -> Vec<ParentStatus> {
        self.status
            .iter()
            .flat_map(|s| &s.parents)
            .map(ParentStatus::from)
            .collect()
    }
}

/// Why something was refused: a Gateway API reason and a human readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject {
    pub reason: String,
    pub message: String,
}

impl Reject {
    pub(crate) fn new(reason: &str, message: impl Into<String>) -> Self {
        Self {
            reason: reason.to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    /// Every `GatewayClass` with our controller name, by name.
    pub classes: Vec<ClassModel>,
    /// Every `Gateway` whose class is ours, by key.
    pub gateways: Vec<GatewayModel>,
    /// Every `Edge`, by key.
    pub edges: Vec<EdgeModel>,
    /// Every `TCPRoute` with a `parentRef` naming one of our gateways, by kind, then key.
    pub routes: Vec<RouteModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassModel {
    pub name: String,
    pub generation: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayModel {
    pub key: ObjRef,
    pub generation: i64,
    pub accepted: Result<(), Reject>,
    pub listeners: Vec<ListenerModel>,
    /// Accepted edges bound to this gateway.
    pub edges: Vec<ObjRef>,
    /// The first [`MAX_GATEWAY_ADDRESSES`] of the edges' public addresses, sorted.
    pub addresses: Vec<GatewayAddress>,
    /// How many more addresses the edges have than `addresses` lists.
    pub addresses_dropped: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AddressKind {
    IpAddress,
    Hostname,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GatewayAddress {
    pub kind: AddressKind,
    pub value: String,
}

/// The most addresses a Gateway's status may list.
pub const MAX_GATEWAY_ADDRESSES: usize = 16;

impl GatewayAddress {
    /// An IP address in its canonical text form, or a host name in lower case with one trailing
    /// dot removed: at most 253 characters in labels of 1 to 63 characters of `[a-z0-9-]`, none
    /// starting or ending with `-`. `None` for anything else, a port included.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Some(Self {
                kind: AddressKind::IpAddress,
                value: ip.to_string(),
            });
        }
        let name = value.to_ascii_lowercase();
        let name = name.strip_suffix('.').unwrap_or(&name);
        let label_ok = |l: &str| {
            (1..=63).contains(&l.len())
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        };
        (name.len() <= 253 && name.split('.').all(label_ok)).then(|| Self {
            kind: AddressKind::Hostname,
            value: name.to_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerModel {
    pub name: String,
    pub port: u16,
    pub protocol: String,
    /// The hosts the listener answers for; always `Any` for TCP.
    pub hostname: HostMatch,
    pub accepted: Result<(), Reject>,
    pub conflicted: Option<Reject>,
    pub resolved_refs: Result<(), Reject>,
    pub supported_kinds: Vec<String>,
    /// Its `allowedRoutes.namespaces`: where routes may come from.
    pub allowed_namespaces: RouteNamespaces,
    pub attached_routes: i32,
    pub backends: Vec<Backend>,
}

/// The namespaces a listener admits routes from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RouteNamespaces {
    /// Only the Gateway's own namespace; the default.
    #[default]
    Same,
    All,
    /// The namespaces the selector selects; `None`, no selector given, selects none.
    Selector(Option<LabelSelector>),
}

/// A label selector: every `match_labels` entry and every requirement must hold. The empty
/// selector selects everything.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LabelSelector {
    pub match_labels: std::collections::BTreeMap<String, String>,
    pub match_expressions: Vec<LabelRequirement>,
}

/// One `matchExpressions` requirement, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelRequirement {
    pub key: String,
    pub operator: String,
    pub values: Vec<String>,
}

impl ListenerModel {
    /// Accepted, not conflicted, and ready for traffic: a TCP listener needs a backend, an HTTP
    /// one a route (which can answer without a backend, like a redirect), an HTTPS one cannot
    /// serve yet. Only serving listeners get an HAProxy frontend and an open port on the edges.
    pub fn serving(&self) -> bool {
        if self.accepted.is_err() || self.conflicted.is_some() {
            return false;
        }
        match self.protocol.as_str() {
            "HTTP" => self.attached_routes > 0,
            "HTTPS" => false,
            _ => !self.backends.is_empty(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    pub service: ObjRef,
    pub ip: IpAddr,
    pub port: u16,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeModel {
    pub key: ObjRef,
    pub generation: i64,
    pub accepted: Result<(), Reject>,
    /// Set whenever the spec's `endpointId` parses, even if the edge is rejected later.
    pub endpoint_id: Option<iroh::EndpointId>,
    /// The spec's `address` as given.
    pub address: Option<String>,
    /// The gateway the edge names, in the edge's namespace, whether or not it exists.
    pub gateway: Option<ObjRef>,
    /// Normalised by [`GatewayAddress::parse`]: the valid entries of `publicAddresses`, or the
    /// host of `address` when there are none.
    pub public_addresses: Vec<GatewayAddress>,
}

/// A route parent reference, as written in the route (namespace defaulted).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ParentKey {
    pub group: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub section_name: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteModel {
    pub kind: RouteKind,
    pub key: ObjRef,
    pub generation: i64,
    pub parents: Vec<RouteParent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteParent {
    pub parent: ParentKey,
    pub accepted: Result<(), Reject>,
    pub resolved_refs: Result<(), Reject>,
}

/// `metadata.generation`, 0 when absent.
pub(crate) fn generation<K: ResourceExt>(object: &K) -> i64 {
    object.meta().generation.unwrap_or(0)
}

/// Reduce the snapshot to the model.
pub fn build(snapshot: &Snapshot, settings: &Settings) -> Model {
    let classes = gateways::classes(snapshot, settings);

    // Gateways pass: which gateways and listeners are accepted.
    let mut gateways = gateways::gateways(snapshot, settings, &classes);

    // Edges pass: which edges are valid and which accepted gateway each one serves.
    let edges = edges::edges(snapshot, settings, &gateways);
    edges::bind(&mut gateways, &edges);

    // Routes pass: attach TCPRoutes to listeners, fill `attached_routes` and `backends`.
    let mut routes = routes::routes(snapshot, &mut gateways);
    routes.sort_by(|a, b| (a.kind, &a.key).cmp(&(b.kind, &b.key)));

    Model {
        classes,
        gateways,
        edges,
        routes,
    }
}

#[cfg(test)]
mod tests {
    use gateway_api::httproutes::v1::{
        HttpRouteParentRefs, HttpRouteStatus, HttpRouteStatusParents,
        HttpRouteStatusParentsParentRef,
    };
    use gateway_api::tcproutes::v1::{
        TcpRouteParentRefs, TcpRouteStatus, TcpRouteStatusParents, TcpRouteStatusParentsParentRef,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

    use super::fixtures::{http_route, tcp_route};
    use super::{ParentRef, ParentStatus, RouteKind, RouteResource};

    fn full() -> ParentRef {
        ParentRef {
            group: Some("gateway.networking.k8s.io".into()),
            kind: Some("Gateway".into()),
            namespace: Some("gw".into()),
            name: "public".into(),
            section_name: Some("web".into()),
            port: Some(443),
        }
    }

    fn name_only(name: &str) -> ParentRef {
        ParentRef {
            group: None,
            kind: None,
            namespace: None,
            name: name.into(),
            section_name: None,
            port: None,
        }
    }

    fn condition(reason: &str) -> Condition {
        Condition {
            type_: "Accepted".into(),
            status: "True".into(),
            reason: reason.into(),
            message: format!("because {reason}"),
            observed_generation: Some(3),
            last_transition_time: Time(k8s_openapi::jiff::Timestamp::from_second(7).unwrap()),
        }
    }

    #[test]
    fn route_kinds_name_their_resources() {
        assert_eq!(RouteKind::Tcp.as_str(), "TCPRoute");
        assert_eq!(RouteKind::Http.as_str(), "HTTPRoute");
        assert!(RouteKind::Tcp < RouteKind::Http);
        assert_eq!(
            <gateway_api::tcproutes::v1::TcpRoute as RouteResource>::KIND,
            RouteKind::Tcp
        );
        assert_eq!(
            <gateway_api::httproutes::v1::HttpRoute as RouteResource>::KIND,
            RouteKind::Http
        );
    }

    #[test]
    fn parent_ref_serialises_like_the_api() {
        assert_eq!(
            serde_json::to_string(&name_only("gw")).unwrap(),
            r#"{"name":"gw"}"#
        );
        assert_eq!(
            serde_json::to_string(&full()).unwrap(),
            r#"{"group":"gateway.networking.k8s.io","kind":"Gateway","namespace":"gw","name":"public","sectionName":"web","port":443}"#
        );
        // And reads back what the API server sends.
        let read: ParentRef = serde_json::from_str(
            r#"{"port":443,"sectionName":"web","name":"public","namespace":"gw","kind":"Gateway","group":"gateway.networking.k8s.io"}"#,
        )
        .unwrap();
        assert_eq!(read, full());
        let read: ParentRef = serde_json::from_str(r#"{"name":"gw"}"#).unwrap();
        assert_eq!(read, name_only("gw"));
    }

    #[test]
    fn tcp_and_http_routes_expose_their_parent_refs() {
        let want = vec![full(), name_only("other")];

        let mut tcp = tcp_route("apps", "r");
        assert_eq!(tcp.parent_refs(), []);
        tcp.spec.parent_refs = Some(vec![
            TcpRouteParentRefs {
                group: Some("gateway.networking.k8s.io".into()),
                kind: Some("Gateway".into()),
                namespace: Some("gw".into()),
                name: "public".into(),
                section_name: Some("web".into()),
                port: Some(443),
            },
            TcpRouteParentRefs {
                name: "other".into(),
                ..Default::default()
            },
        ]);
        assert_eq!(tcp.parent_refs(), want);

        let mut http = http_route("apps", "r");
        assert_eq!(http.parent_refs(), []);
        http.spec.parent_refs = Some(vec![
            HttpRouteParentRefs {
                group: Some("gateway.networking.k8s.io".into()),
                kind: Some("Gateway".into()),
                namespace: Some("gw".into()),
                name: "public".into(),
                section_name: Some("web".into()),
                port: Some(443),
            },
            HttpRouteParentRefs {
                name: "other".into(),
                ..Default::default()
            },
        ]);
        assert_eq!(http.parent_refs(), want);
    }

    #[test]
    fn status_parents_roundtrip() {
        let want = vec![
            ParentStatus {
                parent_ref: full(),
                controller_name: "example.com/a".into(),
                conditions: vec![condition("One")],
            },
            ParentStatus {
                parent_ref: name_only("other"),
                controller_name: "example.com/b".into(),
                conditions: vec![condition("Two"), condition("Three")],
            },
        ];

        let mut tcp = tcp_route("apps", "r");
        assert_eq!(tcp.status_parents(), []);
        tcp.status = Some(TcpRouteStatus {
            parents: vec![
                TcpRouteStatusParents {
                    conditions: vec![condition("One")],
                    controller_name: "example.com/a".into(),
                    parent_ref: TcpRouteStatusParentsParentRef {
                        group: Some("gateway.networking.k8s.io".into()),
                        kind: Some("Gateway".into()),
                        namespace: Some("gw".into()),
                        name: "public".into(),
                        section_name: Some("web".into()),
                        port: Some(443),
                    },
                },
                TcpRouteStatusParents {
                    conditions: vec![condition("Two"), condition("Three")],
                    controller_name: "example.com/b".into(),
                    parent_ref: TcpRouteStatusParentsParentRef {
                        name: "other".into(),
                        ..Default::default()
                    },
                },
            ],
        });
        assert_eq!(tcp.status_parents(), want);
        // Serialised, an entry reads as the API's own type does.
        assert_eq!(
            serde_json::to_value(&want).unwrap(),
            serde_json::to_value(&tcp.status.as_ref().unwrap().parents).unwrap()
        );

        let mut http = http_route("apps", "r");
        assert_eq!(http.status_parents(), []);
        http.status = Some(HttpRouteStatus {
            parents: vec![
                HttpRouteStatusParents {
                    conditions: vec![condition("One")],
                    controller_name: "example.com/a".into(),
                    parent_ref: HttpRouteStatusParentsParentRef {
                        group: Some("gateway.networking.k8s.io".into()),
                        kind: Some("Gateway".into()),
                        namespace: Some("gw".into()),
                        name: "public".into(),
                        section_name: Some("web".into()),
                        port: Some(443),
                    },
                },
                HttpRouteStatusParents {
                    conditions: vec![condition("Two"), condition("Three")],
                    controller_name: "example.com/b".into(),
                    parent_ref: HttpRouteStatusParentsParentRef {
                        name: "other".into(),
                        ..Default::default()
                    },
                },
            ],
        });
        assert_eq!(http.status_parents(), want);
        assert_eq!(
            serde_json::to_value(&want).unwrap(),
            serde_json::to_value(&http.status.as_ref().unwrap().parents).unwrap()
        );
    }
}
