//! The model: what the cluster asks for, reduced by pure functions to what the operator will do.
//!
//! [`build`] takes a [`Snapshot`] of the watched resources and the operator's [`Settings`] and
//! returns a [`Model`]. It does no I/O and reads no clock, so equal inputs give equal models.

mod edges;
#[cfg(test)]
pub(crate) mod fixtures;
mod gateways;
mod routes;

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use gateway_api::gatewayclasses::v1::GatewayClass;
use gateway_api::gateways::v1::Gateway;
use gateway_api::tcproutes::v1::TcpRoute;
use iroh_gateway_proto::transport::Relay;
use k8s_openapi::api::core::v1::{Namespace, Service};
use kube::ResourceExt;

use crate::crd::Edge;

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
    pub edges: Vec<Edge>,
    pub services: Vec<Service>,
    pub namespaces: Vec<Namespace>,
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
    /// Every `TCPRoute` with a `parentRef` naming one of our gateways, by key.
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
    /// Accepted, not conflicted, and with at least one backend. Only serving listeners get an
    /// HAProxy frontend and an open port on the edges.
    pub fn serving(&self) -> bool {
        self.accepted.is_ok() && self.conflicted.is_none() && !self.backends.is_empty()
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
    let routes = routes::routes(snapshot, &mut gateways);

    Model {
        classes,
        gateways,
        edges,
        routes,
    }
}
