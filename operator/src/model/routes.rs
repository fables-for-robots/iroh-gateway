//! TCPRoutes: which route binds to which listener, and the backends each listener gets; and the
//! parent and backend checks, and the snapshot lookups, that every route kind shares.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use gateway_api::tcproutes::v1::TcpRoute;
use k8s_openapi::api::core::v1::Service;
use kube::ResourceExt;

use super::gateways::ROUTE_GROUP;
use super::{
    Backend, GatewayModel, LabelRequirement, LabelSelector, ObjRef, ParentKey, ParentRef, Reject,
    RouteKind, RouteModel, RouteNamespaces, RouteParent, RouteResource, Snapshot, generation,
};

const GATEWAY_KIND: &str = "Gateway";

pub(super) type Labels = BTreeMap<String, String>;

/// A listener slot: index of the gateway in the model, index of the listener in that gateway.
pub(super) type Slot = (usize, usize);

/// The labels of every namespace in the snapshot, by name.
pub(super) fn namespace_labels(snapshot: &Snapshot) -> BTreeMap<String, Labels> {
    snapshot
        .namespaces
        .iter()
        .map(|n| (n.name_any(), n.metadata.labels.clone().unwrap_or_default()))
        .collect()
}

/// The services of the snapshot by key; of two with one key, the first.
pub(super) fn services_by_key(snapshot: &Snapshot) -> BTreeMap<ObjRef, &Service> {
    let mut services: BTreeMap<ObjRef, &Service> = BTreeMap::new();
    for svc in &snapshot.services {
        services.entry(ObjRef::of(svc)).or_insert(svc);
    }
    services
}

/// Every route that names one of our gateways, by key. Fills `attached_routes` and `backends`
/// of the listeners the routes win.
pub(super) fn routes(snapshot: &Snapshot, gateways: &mut [GatewayModel]) -> Vec<RouteModel> {
    let mut routes: Vec<(ObjRef, &TcpRoute)> = snapshot
        .tcp_routes
        .iter()
        .map(|r| (ObjRef::of(r), r))
        .collect();
    routes.sort_by(|a, b| a.0.cmp(&b.0));

    let namespaces = namespace_labels(snapshot);
    let services = services_by_key(snapshot);

    let resolved: Vec<Resolved> = routes
        .iter()
        .map(|(key, r)| resolve(r, &key.namespace, &services))
        .collect();
    let parents: Vec<Vec<Attachment>> = routes
        .iter()
        .map(|(key, r)| attachments(r, &key.namespace, gateways, &namespaces))
        .collect();

    // Per listener, the oldest route among those that passed every other check wins.
    let order = |i: usize| {
        let ts = routes[i].1.creation_timestamp();
        (ts.is_none(), ts, &routes[i].0)
    };
    let mut winners: BTreeMap<Slot, usize> = BTreeMap::new();
    for (i, attachments) in parents.iter().enumerate() {
        for slot in attachments.iter().flat_map(|a| a.slots.iter().flatten()) {
            let winner = winners.entry(*slot).or_insert(i);
            if order(i) < order(*winner) {
                *winner = i;
            }
        }
    }
    for (&(g, l), &i) in &winners {
        let listener = &mut gateways[g].listeners[l];
        listener.attached_routes = 1;
        listener.backends = resolved[i].backends.clone();
    }

    routes
        .iter()
        .zip(parents)
        .zip(resolved)
        .enumerate()
        .filter(|(_, ((_, parents), _))| !parents.is_empty())
        .map(|(i, (((key, r), parents), resolved))| RouteModel {
            kind: TcpRoute::KIND,
            key: key.clone(),
            generation: generation(*r),
            parents: parents
                .into_iter()
                .map(|a| RouteParent {
                    parent: a.parent,
                    accepted: a.slots.and_then(|slots| {
                        if slots.iter().any(|s| winners.get(s) == Some(&i)) {
                            Ok(())
                        } else {
                            Err(Reject::new(
                                "UnsupportedValue",
                                "another TCPRoute is already bound to this listener",
                            ))
                        }
                    }),
                    resolved_refs: resolved.resolved_refs.clone(),
                })
                .collect(),
        })
        .collect()
}

/// One `parentRef` naming one of our gateways, and the listeners it may compete for.
struct Attachment {
    parent: ParentKey,
    slots: Result<Vec<Slot>, Reject>,
}

/// The route's `parentRef`s that name a gateway in the model, in order, without repeats.
fn attachments(
    route: &TcpRoute,
    route_ns: &str,
    gateways: &[GatewayModel],
    namespaces: &BTreeMap<String, Labels>,
) -> Vec<Attachment> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for parent in route.parent_refs() {
        let Some(parent) = parent_key(&parent, route_ns) else {
            continue;
        };
        if !seen.insert(parent.clone()) {
            continue;
        }
        let key = ObjRef::new(&parent.namespace, &parent.name);
        let Some(g) = gateways.iter().position(|gw| gw.key == key) else {
            continue;
        };
        let slots = attach(route, route_ns, &parent, &gateways[g], namespaces)
            .map(|ls| ls.into_iter().map(|l| (g, l)).collect());
        out.push(Attachment { parent, slots });
    }
    out
}

/// The key of a `parentRef` to a Gateway, defaults filled in; `None` for other kinds.
pub(crate) fn parent_key(parent: &ParentRef, route_ns: &str) -> Option<ParentKey> {
    let group = parent.group.as_deref().unwrap_or(ROUTE_GROUP);
    let kind = parent.kind.as_deref().unwrap_or(GATEWAY_KIND);
    if group != ROUTE_GROUP || kind != GATEWAY_KIND {
        return None;
    }
    Some(ParentKey {
        group: group.to_owned(),
        kind: kind.to_owned(),
        namespace: parent.namespace.as_deref().unwrap_or(route_ns).to_owned(),
        name: parent.name.clone(),
        section_name: parent.section_name.clone(),
        // A port outside 1..=65535 is kept as 0, which matches no listener.
        port: parent.port.map(|p| u16::try_from(p).unwrap_or(0)),
    })
}

/// The listeners of `gw` that the TCPRoute may compete for, or why there are none.
fn attach(
    route: &TcpRoute,
    route_ns: &str,
    parent: &ParentKey,
    gw: &GatewayModel,
    namespaces: &BTreeMap<String, Labels>,
) -> Result<Vec<usize>, Reject> {
    let kept = admitted(TcpRoute::KIND, route_ns, parent, gw, namespaces)?;
    if route.spec.rules.len() > 1 {
        return Err(Reject::new(
            "UnsupportedValue",
            "a TCPRoute may have one rule",
        ));
    }
    Ok(kept)
}

/// The listeners of `gw` a route of `kind` from `route_ns` may attach to through `parent`:
/// `NoMatchingParent` or `NotAllowedByListeners` otherwise.
pub(super) fn admitted(
    kind: RouteKind,
    route_ns: &str,
    parent: &ParentKey,
    gw: &GatewayModel,
    namespaces: &BTreeMap<String, Labels>,
) -> Result<Vec<usize>, Reject> {
    let candidates: Vec<usize> = gw
        .listeners
        .iter()
        .enumerate()
        .filter(|(_, l)| parent.section_name.as_ref().is_none_or(|s| &l.name == s))
        .filter(|(_, l)| parent.port.is_none_or(|p| p != 0 && l.port == p))
        .map(|(i, _)| i)
        .collect();
    if candidates.is_empty() {
        return Err(Reject::new(
            "NoMatchingParent",
            format!(
                "gateway {} has no listener matching sectionName and port",
                gw.key
            ),
        ));
    }

    let kept: Vec<usize> = candidates
        .into_iter()
        .filter(|&i| {
            let l = &gw.listeners[i];
            gw.accepted.is_ok()
                && l.accepted.is_ok()
                && l.conflicted.is_none()
                && l.supported_kinds.iter().any(|k| k == kind.as_str())
                && admits(
                    &l.allowed_namespaces,
                    &gw.key.namespace,
                    route_ns,
                    namespaces,
                )
        })
        .collect();
    if kept.is_empty() {
        return Err(Reject::new(
            "NotAllowedByListeners",
            format!(
                "no accepted listener of gateway {} admits {}s from namespace {route_ns:?}",
                gw.key,
                kind.as_str()
            ),
        ));
    }
    Ok(kept)
}

/// Whether a listener with namespace policy `rule` admits routes from `route_ns`.
fn admits(
    rule: &RouteNamespaces,
    gateway_ns: &str,
    route_ns: &str,
    namespaces: &BTreeMap<String, Labels>,
) -> bool {
    match rule {
        RouteNamespaces::Same => route_ns == gateway_ns,
        RouteNamespaces::All => true,
        // No selector selects nothing; a namespace we have not seen is not selected.
        RouteNamespaces::Selector(selector) => match (selector, namespaces.get(route_ns)) {
            (Some(selector), Some(labels)) => selects(selector, labels),
            _ => false,
        },
    }
}

/// A label selector: every `matchLabels` entry and every `matchExpressions` requirement holds.
/// The empty selector selects everything.
fn selects(selector: &LabelSelector, labels: &Labels) -> bool {
    let match_labels = selector
        .match_labels
        .iter()
        .all(|(k, v)| labels.get(k) == Some(v));
    let match_expressions = selector
        .match_expressions
        .iter()
        .all(|r| requirement(r, labels));
    match_labels && match_expressions
}

/// One `matchExpressions` requirement. A malformed one (unknown operator, values missing for
/// `In`/`NotIn` or given for `Exists`/`DoesNotExist`) holds for no namespace.
fn requirement(r: &LabelRequirement, labels: &Labels) -> bool {
    let values = r.values.as_slice();
    let value = labels.get(&r.key);
    match (r.operator.as_str(), values.is_empty()) {
        ("In", false) => value.is_some_and(|v| values.contains(v)),
        ("NotIn", false) => value.is_none_or(|v| !values.contains(v)),
        ("Exists", true) => value.is_some(),
        ("DoesNotExist", true) => value.is_none(),
        _ => false,
    }
}

/// The backends of a route's rules and the first problem found among its `backendRef`s.
struct Resolved {
    backends: Vec<Backend>,
    resolved_refs: Result<(), Reject>,
}

fn resolve(route: &TcpRoute, route_ns: &str, services: &BTreeMap<ObjRef, &Service>) -> Resolved {
    let mut backends = Vec::new();
    let mut resolved_refs = Ok(());
    for b in route.spec.rules.iter().flat_map(|r| &r.backend_refs) {
        let b = BackendRef {
            group: b.group.as_deref(),
            kind: b.kind.as_deref(),
            namespace: b.namespace.as_deref(),
            name: &b.name,
            port: b.port,
            weight: b.weight,
        };
        match backend(&b, route_ns, services) {
            Ok(Some(backend)) => backends.push(backend),
            Ok(None) => {}
            Err(reject) => {
                if resolved_refs.is_ok() {
                    resolved_refs = Err(reject);
                }
            }
        }
    }
    Resolved {
        backends,
        resolved_refs,
    }
}

/// A route's `backendRef`, whatever the route's kind, as written.
pub(super) struct BackendRef<'a> {
    pub group: Option<&'a str>,
    pub kind: Option<&'a str>,
    pub namespace: Option<&'a str>,
    pub name: &'a str,
    pub port: Option<i32>,
    pub weight: Option<i32>,
}

/// One `backendRef`: a backend, `None` if it has weight 0, or why it was refused.
pub(super) fn backend(
    b: &BackendRef<'_>,
    route_ns: &str,
    services: &BTreeMap<ObjRef, &Service>,
) -> Result<Option<Backend>, Reject> {
    let group = b.group.unwrap_or("");
    let kind = b.kind.unwrap_or("Service");
    if !group.is_empty() || kind != "Service" {
        return Err(Reject::new(
            "InvalidKind",
            format!(
                "backend {:?} is a {kind} of group {group:?}; only core Services are supported",
                b.name
            ),
        ));
    }
    if let Some(ns) = b.namespace.filter(|ns| *ns != route_ns) {
        return Err(Reject::new(
            "RefNotPermitted",
            format!(
                "backend {ns}/{} is in another namespace than the route",
                b.name
            ),
        ));
    }
    let Some(port) = b
        .port
        .and_then(|p| u16::try_from(p).ok())
        .filter(|&p| p != 0)
    else {
        return Err(Reject::new(
            "UnsupportedValue",
            format!("backend {:?} needs a port between 1 and 65535", b.name),
        ));
    };
    let key = ObjRef::new(route_ns, b.name);
    let Some(svc) = services.get(&key) else {
        return Err(Reject::new(
            "BackendNotFound",
            format!("service {key} not found"),
        ));
    };
    let spec = svc.spec.as_ref();
    if spec.and_then(|s| s.type_.as_deref()) == Some("ExternalName") {
        return Err(Reject::new(
            "BackendNotFound",
            format!("service {key} is of type ExternalName"),
        ));
    }
    let Some(ip) = spec
        .and_then(|s| s.cluster_ip.as_deref())
        .and_then(|ip| ip.parse::<IpAddr>().ok())
    else {
        return Err(Reject::new(
            "BackendNotFound",
            format!("service {key} has no cluster IP"),
        ));
    };
    let has_port = spec
        .and_then(|s| s.ports.as_ref())
        .into_iter()
        .flatten()
        .any(|p| {
            p.port == i32::from(port) && !matches!(p.protocol.as_deref(), Some("UDP" | "SCTP"))
        });
    if !has_port {
        return Err(Reject::new(
            "BackendNotFound",
            format!("service {key} has no TCP port {port}"),
        ));
    }
    let weight = b.weight.unwrap_or(1);
    let Ok(weight) = u32::try_from(weight) else {
        return Ok(None);
    };
    if weight == 0 {
        return Ok(None);
    }
    Ok(Some(Backend {
        service: key,
        ip,
        port,
        weight,
    }))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use gateway_api::gateways::v1::{Gateway, GatewayListenersAllowedRoutesNamespacesSelector};
    use gateway_api::tcproutes::v1::TcpRoute;
    use k8s_openapi::api::core::v1::Service;

    use super::super::build;
    use super::super::fixtures::*;
    use super::super::{Backend, ListenerModel, Model, ObjRef, ParentKey, Reject, RouteModel};
    use super::Snapshot;

    const GROUP: &str = "gateway.networking.k8s.io";

    fn reason(r: &Result<(), Reject>) -> &str {
        match r {
            Ok(()) => "Ok",
            Err(r) => &r.reason,
        }
    }

    fn snap(gateways: Vec<Gateway>, routes: Vec<TcpRoute>, services: Vec<Service>) -> Snapshot {
        Snapshot {
            gateway_classes: vec![class("ours")],
            gateways,
            tcp_routes: routes,
            services,
            namespaces: vec![
                ns("gw", &[]),
                ns("apps", &[("expose", "yes"), ("team", "db")]),
                ns("other", &[("team", "web")]),
            ],
            ..Default::default()
        }
    }

    fn run(gateways: Vec<Gateway>, routes: Vec<TcpRoute>, services: Vec<Service>) -> Model {
        build(&snap(gateways, routes, services), &settings(&["gw"]))
    }

    /// gw/public with listener pg:5432.
    fn public() -> Gateway {
        gateway("gw", "public").listener("pg", 5432, "TCP")
    }

    fn db() -> Service {
        service("gw", "db", "10.43.0.12", &[5432])
    }

    fn route<'m>(m: &'m Model, ns: &str, name: &str) -> &'m RouteModel {
        let key = ObjRef::new(ns, name);
        m.routes
            .iter()
            .find(|r| r.key == key)
            .unwrap_or_else(|| panic!("route {key} not in the model"))
    }

    fn listener<'m>(m: &'m Model, gw: &str, name: &str) -> &'m ListenerModel {
        m.gateways
            .iter()
            .find(|g| g.key.name == gw)
            .and_then(|g| g.listeners.iter().find(|l| l.name == name))
            .expect("listener")
    }

    /// The reason of the only parent of route `ns/name`.
    fn accepted(m: &Model, ns: &str, name: &str) -> String {
        let r = route(m, ns, name);
        assert_eq!(r.parents.len(), 1, "{:?}", r.parents);
        reason(&r.parents[0].accepted).to_owned()
    }

    fn resolved(m: &Model, ns: &str, name: &str) -> String {
        let r = route(m, ns, name);
        assert_eq!(r.parents.len(), 1, "{:?}", r.parents);
        reason(&r.parents[0].resolved_refs).to_owned()
    }

    fn backend(ns: &str, name: &str, ip: &str, port: u16, weight: u32) -> Backend {
        Backend {
            service: ObjRef::new(ns, name),
            ip: ip.parse().unwrap(),
            port,
            weight,
        }
    }

    #[test]
    fn route_binds_and_listener_serves() {
        let mut r = tcp_route("gw", "r").parent("public").backend("db", 5432);
        r.metadata.generation = Some(3);
        let m = run(vec![public()], vec![r], vec![db()]);
        let rm = route(&m, "gw", "r");
        assert_eq!(rm.generation, 3);
        assert_eq!(
            rm.parents[0].parent,
            ParentKey {
                group: GROUP.into(),
                kind: "Gateway".into(),
                namespace: "gw".into(),
                name: "public".into(),
                section_name: None,
                port: None,
            }
        );
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        assert_eq!(resolved(&m, "gw", "r"), "Ok");
        let l = listener(&m, "public", "pg");
        assert_eq!(l.attached_routes, 1);
        assert_eq!(l.backends, [backend("gw", "db", "10.43.0.12", 5432, 1)]);
        assert!(l.serving());
    }

    #[test]
    fn section_name_and_port_narrow_the_listeners() {
        let gw = public().listener("redis", 6379, "TCP");
        let svcs = vec![db(), service("gw", "cache", "10.43.0.13", &[6379])];
        let m = run(
            vec![gw.clone()],
            vec![
                tcp_route("gw", "a")
                    .parent("public")
                    .section("redis")
                    .backend("cache", 6379),
                tcp_route("gw", "b")
                    .parent("public")
                    .port(5432)
                    .backend("db", 5432),
                tcp_route("gw", "c")
                    .parent("public")
                    .port(7000)
                    .backend("db", 5432),
                tcp_route("gw", "d")
                    .parent("public")
                    .section("redis")
                    .port(5432)
                    .backend("db", 5432),
                tcp_route("gw", "e")
                    .parent("public")
                    .section("missing")
                    .backend("db", 5432),
            ],
            svcs,
        );
        assert_eq!(accepted(&m, "gw", "a"), "Ok");
        assert_eq!(accepted(&m, "gw", "b"), "Ok");
        assert_eq!(accepted(&m, "gw", "c"), "NoMatchingParent");
        assert_eq!(accepted(&m, "gw", "d"), "NoMatchingParent");
        assert_eq!(accepted(&m, "gw", "e"), "NoMatchingParent");
        let p = &route(&m, "gw", "a").parents[0].parent;
        assert_eq!(p.section_name.as_deref(), Some("redis"));
        assert_eq!(route(&m, "gw", "b").parents[0].parent.port, Some(5432));
        assert_eq!(
            listener(&m, "public", "redis").backends,
            [backend("gw", "cache", "10.43.0.13", 6379, 1)]
        );
        assert_eq!(
            listener(&m, "public", "pg").backends,
            [backend("gw", "db", "10.43.0.12", 5432, 1)]
        );
    }

    #[test]
    fn route_without_section_wins_every_listener() {
        let gw = public().listener("alt", 15432, "TCP");
        let m = run(
            vec![gw],
            vec![tcp_route("gw", "r").parent("public").backend("db", 5432)],
            vec![db()],
        );
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        for name in ["pg", "alt"] {
            let l = listener(&m, "public", name);
            assert_eq!(l.attached_routes, 1, "{name}");
            assert_eq!(l.backends, [backend("gw", "db", "10.43.0.12", 5432, 1)]);
            assert!(l.serving());
        }
    }

    #[test]
    fn default_allows_only_the_gateways_namespace() {
        let m = run(
            vec![public()],
            vec![
                tcp_route("apps", "r")
                    .parent_in("gw", "public")
                    .backend("db", 5432),
            ],
            vec![service("apps", "db", "10.43.0.20", &[5432])],
        );
        assert_eq!(accepted(&m, "apps", "r"), "NotAllowedByListeners");
        let l = listener(&m, "public", "pg");
        assert_eq!(l.attached_routes, 0);
        assert!(l.backends.is_empty());
        assert!(!l.serving());
    }

    #[test]
    fn all_namespaces_allows_any() {
        let m = run(
            vec![public().allow_all_namespaces()],
            vec![
                tcp_route("apps", "r")
                    .parent_in("gw", "public")
                    .backend("db", 5432),
            ],
            vec![service("apps", "db", "10.43.0.20", &[5432])],
        );
        assert_eq!(accepted(&m, "apps", "r"), "Ok");
        let p = &route(&m, "apps", "r").parents[0].parent;
        assert_eq!(p.namespace, "gw");
        assert_eq!(
            listener(&m, "public", "pg").backends,
            [backend("apps", "db", "10.43.0.20", 5432, 1)]
        );
    }

    #[test]
    fn parent_namespace_defaults_to_the_routes() {
        // apps/r names "public" without a namespace: that is apps/public, which does not exist.
        let m = run(
            vec![public().allow_all_namespaces()],
            vec![tcp_route("apps", "r").parent("public").backend("db", 5432)],
            vec![service("apps", "db", "10.43.0.20", &[5432])],
        );
        assert!(m.routes.is_empty());
        assert!(!listener(&m, "public", "pg").serving());
    }

    #[test]
    fn selector_matches_namespace_labels() {
        let gw = public()
            .allow_selector(&[("expose", "yes")])
            .listener("alt", 15432, "TCP")
            .allow_selector(&[("expose", "yes"), ("team", "web")]);
        let m = run(
            vec![gw],
            vec![
                tcp_route("apps", "a")
                    .parent_in("gw", "public")
                    .section("pg")
                    .backend("db", 5432),
                tcp_route("other", "b")
                    .parent_in("gw", "public")
                    .section("pg")
                    .backend("db", 5432),
                tcp_route("apps", "c")
                    .parent_in("gw", "public")
                    .section("alt")
                    .backend("db", 5432),
                // gw itself has no labels: a selector does not admit the gateway's namespace.
                tcp_route("gw", "d")
                    .parent("public")
                    .section("pg")
                    .backend("db", 5432),
            ],
            vec![
                db(),
                service("apps", "db", "10.43.0.20", &[5432]),
                service("other", "db", "10.43.0.30", &[5432]),
            ],
        );
        assert_eq!(accepted(&m, "apps", "a"), "Ok");
        assert_eq!(accepted(&m, "other", "b"), "NotAllowedByListeners");
        // All matchLabels must match.
        assert_eq!(accepted(&m, "apps", "c"), "NotAllowedByListeners");
        assert_eq!(accepted(&m, "gw", "d"), "NotAllowedByListeners");
    }

    #[test]
    fn selector_match_expressions() {
        // apps: {expose: yes, team: db}; other: {team: web}.
        type Exprs<'a> = &'a [(&'a str, &'a str, &'a [&'a str])];
        let cases: Vec<(Exprs, bool, bool)> = vec![
            (&[("team", "In", &["db", "x"])], true, false),
            (&[("team", "NotIn", &["db"])], false, true),
            (&[("expose", "NotIn", &["no"])], true, true),
            (&[("expose", "Exists", &[])], true, false),
            (&[("expose", "DoesNotExist", &[])], false, true),
            (
                &[("team", "Exists", &[]), ("expose", "DoesNotExist", &[])],
                false,
                true,
            ),
            // Malformed requirements admit nothing.
            (&[("team", "In", &[])], false, false),
            (&[("team", "NotIn", &[])], false, false),
            (&[("team", "Exists", &["db"])], false, false),
            (&[("team", "DoesNotExist", &["x"])], false, false),
            (&[("team", "Equals", &["db"])], false, false),
        ];
        for (exprs, apps, other) in cases {
            let m = run(
                vec![public().allow_expressions(exprs)],
                vec![
                    tcp_route("apps", "r")
                        .parent_in("gw", "public")
                        .backend("db", 5432),
                    tcp_route("other", "r")
                        .parent_in("gw", "public")
                        .backend("db", 5432),
                ],
                vec![
                    service("apps", "db", "10.43.0.20", &[5432]),
                    service("other", "db", "10.43.0.30", &[5432]),
                ],
            );
            let want = |ok: bool| if ok { "Ok" } else { "NotAllowedByListeners" };
            // Both may be admitted; then the older (equal time, smaller key: apps) wins.
            let other_want = if apps && other {
                "UnsupportedValue"
            } else {
                want(other)
            };
            assert_eq!(accepted(&m, "apps", "r"), want(apps), "{exprs:?}");
            assert_eq!(accepted(&m, "other", "r"), other_want, "{exprs:?}");
        }
    }

    #[test]
    fn empty_selector_admits_all_and_missing_selector_admits_none() {
        let routes = || {
            vec![
                tcp_route("apps", "r")
                    .parent_in("gw", "public")
                    .backend("db", 5432),
            ]
        };
        let svcs = || vec![service("apps", "db", "10.43.0.20", &[5432])];
        let all = public().allow_raw_selector(Some(
            GatewayListenersAllowedRoutesNamespacesSelector::default(),
        ));
        let m = run(vec![all], routes(), svcs());
        assert_eq!(accepted(&m, "apps", "r"), "Ok");
        let none = public().allow_raw_selector(None);
        let m = run(vec![none], routes(), svcs());
        assert_eq!(accepted(&m, "apps", "r"), "NotAllowedByListeners");
    }

    #[test]
    fn selector_needs_the_namespace_in_the_snapshot() {
        let gw = public().allow_raw_selector(Some(
            GatewayListenersAllowedRoutesNamespacesSelector::default(),
        ));
        let mut s = snap(
            vec![gw],
            vec![
                tcp_route("ghost", "r")
                    .parent_in("gw", "public")
                    .backend("db", 5432),
            ],
            vec![service("ghost", "db", "10.43.0.20", &[5432])],
        );
        s.namespaces
            .retain(|n| n.metadata.name.as_deref() != Some("ghost"));
        let m = build(&s, &settings(&["gw"]));
        assert_eq!(accepted(&m, "ghost", "r"), "NotAllowedByListeners");
    }

    #[test]
    fn oldest_route_wins_a_listener() {
        let routes = |a: i64, b: i64| {
            vec![
                tcp_route("gw", "a")
                    .parent("public")
                    .backend("db", 5432)
                    .created(a),
                tcp_route("gw", "b")
                    .parent("public")
                    .backend("other", 5432)
                    .created(b),
            ]
        };
        let svcs = || vec![db(), service("gw", "other", "10.43.0.99", &[5432])];
        let m = run(vec![public()], routes(10, 20), svcs());
        assert_eq!(accepted(&m, "gw", "a"), "Ok");
        assert_eq!(accepted(&m, "gw", "b"), "UnsupportedValue");
        assert_eq!(
            route(&m, "gw", "b").parents[0]
                .accepted
                .as_ref()
                .unwrap_err()
                .message,
            "another TCPRoute is already bound to this listener"
        );
        let l = listener(&m, "public", "pg");
        assert_eq!(l.attached_routes, 1);
        assert_eq!(l.backends, [backend("gw", "db", "10.43.0.12", 5432, 1)]);

        let m = run(vec![public()], routes(20, 10), svcs());
        assert_eq!(accepted(&m, "gw", "a"), "UnsupportedValue");
        assert_eq!(accepted(&m, "gw", "b"), "Ok");
        assert_eq!(
            listener(&m, "public", "pg").backends,
            [backend("gw", "other", "10.43.0.99", 5432, 1)]
        );
    }

    #[test]
    fn route_ties_and_missing_creation_times() {
        let svcs = || vec![db()];
        // Same time: the smaller key wins.
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "b")
                    .parent("public")
                    .backend("db", 5432)
                    .created(10),
                tcp_route("gw", "a")
                    .parent("public")
                    .backend("db", 5432)
                    .created(10),
            ],
            svcs(),
        );
        assert_eq!(accepted(&m, "gw", "a"), "Ok");
        assert_eq!(accepted(&m, "gw", "b"), "UnsupportedValue");
        // No creation time counts as newest.
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "a").parent("public").backend("db", 5432),
                tcp_route("gw", "b")
                    .parent("public")
                    .backend("db", 5432)
                    .created(10),
            ],
            svcs(),
        );
        assert_eq!(accepted(&m, "gw", "a"), "UnsupportedValue");
        assert_eq!(accepted(&m, "gw", "b"), "Ok");
    }

    #[test]
    fn route_that_wins_one_listener_is_accepted() {
        // a holds pg; b (younger, no sectionName) loses pg but wins alt.
        let gw = public().listener("alt", 15432, "TCP");
        let m = run(
            vec![gw],
            vec![
                tcp_route("gw", "a")
                    .parent("public")
                    .section("pg")
                    .backend("db", 5432)
                    .created(10),
                tcp_route("gw", "b")
                    .parent("public")
                    .backend("other", 5432)
                    .created(20),
            ],
            vec![db(), service("gw", "other", "10.43.0.99", &[5432])],
        );
        assert_eq!(accepted(&m, "gw", "a"), "Ok");
        assert_eq!(accepted(&m, "gw", "b"), "Ok");
        assert_eq!(
            listener(&m, "public", "pg").backends,
            [backend("gw", "db", "10.43.0.12", 5432, 1)]
        );
        assert_eq!(
            listener(&m, "public", "alt").backends,
            [backend("gw", "other", "10.43.0.99", 5432, 1)]
        );
        assert_eq!(listener(&m, "public", "alt").attached_routes, 1);
    }

    #[test]
    fn two_rules_are_unsupported() {
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "r")
                    .parent("public")
                    .backend("db", 5432)
                    .second_rule()
                    .backend("db", 5432),
            ],
            vec![db()],
        );
        assert_eq!(accepted(&m, "gw", "r"), "UnsupportedValue");
        assert_eq!(
            route(&m, "gw", "r").parents[0]
                .accepted
                .as_ref()
                .unwrap_err()
                .message,
            "a TCPRoute may have one rule"
        );
        let l = listener(&m, "public", "pg");
        assert_eq!(l.attached_routes, 0);
        assert!(!l.serving());
    }

    #[test]
    fn refused_older_route_does_not_block_a_younger_one() {
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "a")
                    .parent("public")
                    .backend("db", 5432)
                    .second_rule()
                    .created(10),
                tcp_route("gw", "b")
                    .parent("public")
                    .backend("db", 5432)
                    .created(20),
            ],
            vec![db()],
        );
        assert_eq!(accepted(&m, "gw", "a"), "UnsupportedValue");
        assert_eq!(accepted(&m, "gw", "b"), "Ok");
        assert!(listener(&m, "public", "pg").serving());
    }

    #[test]
    fn attachment_checks_run_in_order() {
        let two = |r: TcpRoute| r.backend("db", 5432).second_rule();
        let m = run(
            vec![public()],
            vec![
                // No matching listener beats a refused namespace and two rules.
                two(tcp_route("apps", "a").parent_in("gw", "public").port(1)),
                // A refused namespace beats two rules.
                two(tcp_route("apps", "b").parent_in("gw", "public")),
            ],
            vec![db()],
        );
        assert_eq!(accepted(&m, "apps", "a"), "NoMatchingParent");
        assert_eq!(accepted(&m, "apps", "b"), "NotAllowedByListeners");
    }

    #[test]
    fn route_to_unknown_gateway_is_not_in_the_model() {
        let foreign = gateway("gw", "theirs")
            .class("theirs")
            .listener("pg", 5432, "TCP");
        let mut s = snap(
            vec![public(), foreign],
            vec![
                tcp_route("gw", "missing")
                    .parent("absent")
                    .backend("db", 5432),
                tcp_route("gw", "foreign")
                    .parent("theirs")
                    .backend("db", 5432),
                tcp_route("gw", "orphan").backend("db", 5432),
                // Only the parentRef that names our gateway is listed.
                tcp_route("gw", "mixed")
                    .parent("absent")
                    .parent("public")
                    .backend("db", 5432),
            ],
            vec![db()],
        );
        s.gateway_classes.push(foreign_class("theirs"));
        let m = build(&s, &settings(&["gw"]));
        let keys: Vec<_> = m.routes.iter().map(|r| r.key.name.as_str()).collect();
        assert_eq!(keys, ["mixed"]);
        assert_eq!(accepted(&m, "gw", "mixed"), "Ok");
        assert_eq!(route(&m, "gw", "mixed").parents[0].parent.name, "public");
    }

    #[test]
    fn parent_of_another_group_or_kind_is_not_ours() {
        let mut r = tcp_route("gw", "r")
            .parent("public")
            .parent("public")
            .parent("public")
            .backend("db", 5432);
        let refs = r.spec.parent_refs.as_mut().unwrap();
        refs[0].kind = Some("Service".into());
        refs[1].group = Some("example.com".into());
        refs[2].group = Some(GROUP.into());
        refs[2].kind = Some("Gateway".into());
        let m = run(vec![public()], vec![r], vec![db()]);
        let parents = &route(&m, "gw", "r").parents;
        assert_eq!(parents.len(), 1);
        assert_eq!(reason(&parents[0].accepted), "Ok");
    }

    #[test]
    fn route_to_conflicted_listener_is_not_allowed() {
        let gw = public()
            .listener("pg2", 5432, "TCP")
            .listener("ok", 6379, "TCP");
        let m = run(
            vec![gw],
            vec![
                tcp_route("gw", "r")
                    .parent("public")
                    .section("pg")
                    .backend("db", 5432),
            ],
            vec![db()],
        );
        assert_eq!(accepted(&m, "gw", "r"), "NotAllowedByListeners");
        assert!(!listener(&m, "public", "pg").serving());
        assert_eq!(listener(&m, "public", "pg").attached_routes, 0);
    }

    #[test]
    fn route_to_unaccepted_listener_is_not_allowed() {
        // `bad` fails only the listener's own `accepted` check: TCP, admits the namespace,
        // supports TCPRoute. `pg` keeps the Gateway accepted and admits no TCPRoute.
        let gw = gateway("gw", "public")
            .listener("bad", 0, "TCP")
            .listener("pg", 5432, "TCP")
            .allowed_kinds(&[(GROUP, "HTTPRoute")]);
        let m = run(
            vec![gw],
            vec![tcp_route("gw", "r").parent("public").backend("db", 5432)],
            vec![db()],
        );
        let bad = listener(&m, "public", "bad");
        assert_eq!(reason(&bad.accepted), "PortUnavailable");
        assert_eq!(bad.conflicted, None);
        assert_eq!(bad.supported_kinds, ["TCPRoute"]);
        assert_eq!(m.gateways[0].accepted, Ok(()));
        assert_eq!(accepted(&m, "gw", "r"), "NotAllowedByListeners");
        assert_eq!(bad.attached_routes, 0);
        assert!(bad.backends.is_empty());
    }

    #[test]
    fn listener_model_carries_its_namespace_policy() {
        use super::super::{LabelRequirement, LabelSelector, RouteNamespaces};
        let gw = gateway("gw", "public")
            .listener("same", 1, "TCP")
            .listener("all", 2, "TCP")
            .allow_all_namespaces()
            .listener("sel", 3, "TCP")
            .allow_selector(&[("team", "a")])
            .listener("expr", 4, "TCP")
            .allow_expressions(&[("env", "In", &["prod"])])
            .listener("none", 5, "TCP")
            .allow_raw_selector(None);
        let m = run(vec![gw], vec![], vec![]);
        let policy = |name| listener(&m, "public", name).allowed_namespaces.clone();
        assert_eq!(policy("same"), RouteNamespaces::Same);
        assert_eq!(policy("all"), RouteNamespaces::All);
        assert_eq!(
            policy("sel"),
            RouteNamespaces::Selector(Some(LabelSelector {
                match_labels: [("team".to_owned(), "a".to_owned())].into(),
                match_expressions: vec![],
            }))
        );
        assert_eq!(
            policy("expr"),
            RouteNamespaces::Selector(Some(LabelSelector {
                match_labels: Default::default(),
                match_expressions: vec![LabelRequirement {
                    key: "env".into(),
                    operator: "In".into(),
                    values: vec!["prod".into()],
                }],
            }))
        );
        assert_eq!(policy("none"), RouteNamespaces::Selector(None));
    }

    #[test]
    fn listener_without_tcproute_kind_never_serves() {
        let gw = public().allowed_kinds(&[(GROUP, "HTTPRoute")]);
        let m = run(
            vec![gw],
            vec![tcp_route("gw", "r").parent("public").backend("db", 5432)],
            vec![db()],
        );
        let l = listener(&m, "public", "pg");
        assert!(l.supported_kinds.is_empty());
        assert_eq!(reason(&l.resolved_refs), "InvalidRouteKinds");
        assert_eq!(accepted(&m, "gw", "r"), "NotAllowedByListeners");
        assert_eq!(resolved(&m, "gw", "r"), "Ok");
        assert_eq!(l.attached_routes, 0);
        assert!(l.backends.is_empty());
        assert!(!l.serving());
    }

    #[test]
    fn weights_are_kept_and_zero_is_dropped() {
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "r")
                    .parent("public")
                    .weighted("db", 5432, 3)
                    .weighted("db2", 5432, 1)
                    .weighted("db3", 5432, 0),
            ],
            vec![
                db(),
                service("gw", "db2", "10.43.0.13", &[5432]),
                service("gw", "db3", "10.43.0.14", &[5432]),
            ],
        );
        assert_eq!(resolved(&m, "gw", "r"), "Ok");
        assert_eq!(
            listener(&m, "public", "pg").backends,
            [
                backend("gw", "db", "10.43.0.12", 5432, 3),
                backend("gw", "db2", "10.43.0.13", 5432, 1),
            ]
        );
    }

    #[test]
    fn only_zero_weights_do_not_serve() {
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "r")
                    .parent("public")
                    .weighted("db", 5432, 0),
            ],
            vec![db()],
        );
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        assert_eq!(resolved(&m, "gw", "r"), "Ok");
        assert_eq!(listener(&m, "public", "pg").attached_routes, 1);
        assert!(!listener(&m, "public", "pg").serving());
    }

    #[test]
    fn cross_namespace_backend_is_refused() {
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "r")
                    .parent("public")
                    .backend_in("apps", "db", 5432),
            ],
            vec![service("apps", "db", "10.43.0.20", &[5432])],
        );
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        assert_eq!(resolved(&m, "gw", "r"), "RefNotPermitted");
        let l = listener(&m, "public", "pg");
        assert!(l.backends.is_empty());
        assert!(!l.serving());
    }

    #[test]
    fn backend_namespace_equal_to_the_routes_is_fine() {
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "r")
                    .parent("public")
                    .backend_in("gw", "db", 5432),
            ],
            vec![db()],
        );
        assert_eq!(resolved(&m, "gw", "r"), "Ok");
        assert!(listener(&m, "public", "pg").serving());
    }

    #[test]
    fn missing_service_and_missing_port() {
        // No such service; a service of that name in another namespace does not count.
        let m = run(
            vec![public()],
            vec![tcp_route("gw", "r").parent("public").backend("db", 5432)],
            vec![service("apps", "db", "10.43.0.20", &[5432])],
        );
        assert_eq!(resolved(&m, "gw", "r"), "BackendNotFound");
        assert!(!listener(&m, "public", "pg").serving());
        // The service has no such port; targetPort and nodePort do not count.
        let mut svc = service("gw", "db", "10.43.0.12", &[5433]);
        let port = &mut svc.spec.as_mut().unwrap().ports.as_mut().unwrap()[0];
        port.target_port =
            Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(5432));
        port.node_port = Some(5432);
        let m = run(
            vec![public()],
            vec![tcp_route("gw", "r").parent("public").backend("db", 5432)],
            vec![svc],
        );
        assert_eq!(resolved(&m, "gw", "r"), "BackendNotFound");
        assert!(!listener(&m, "public", "pg").serving());
        // No port on the backendRef at all.
        let mut r = tcp_route("gw", "r").parent("public").backend("db", 5432);
        r.spec.rules[0].backend_refs[0].port = None;
        let m = run(vec![public()], vec![r], vec![db()]);
        assert_eq!(resolved(&m, "gw", "r"), "UnsupportedValue");
        assert!(!listener(&m, "public", "pg").serving());
    }

    #[test]
    fn udp_and_sctp_service_ports_do_not_count() {
        for proto in ["UDP", "SCTP"] {
            let mut svc = db();
            svc.spec.as_mut().unwrap().ports.as_mut().unwrap()[0].protocol = Some(proto.into());
            let m = run(
                vec![public()],
                vec![tcp_route("gw", "r").parent("public").backend("db", 5432)],
                vec![svc],
            );
            assert_eq!(resolved(&m, "gw", "r"), "BackendNotFound", "{proto}");
            assert!(!listener(&m, "public", "pg").serving());
        }
        // An explicit TCP port is fine.
        let mut svc = db();
        svc.spec.as_mut().unwrap().ports.as_mut().unwrap()[0].protocol = Some("TCP".into());
        let m = run(
            vec![public()],
            vec![tcp_route("gw", "r").parent("public").backend("db", 5432)],
            vec![svc],
        );
        assert!(listener(&m, "public", "pg").serving());
    }

    #[test]
    fn non_service_backend_is_invalid_kind() {
        // Only the empty group is the core group.
        let cases = [
            ("", "ConfigMap"),
            ("apps", "Deployment"),
            ("example.com", "Service"),
            ("core", "Service"),
        ];
        for (group, kind) in cases {
            let m = run(
                vec![public()],
                vec![
                    tcp_route("gw", "r")
                        .parent("public")
                        .backend_kind(group, kind, "db"),
                ],
                vec![db()],
            );
            assert_eq!(resolved(&m, "gw", "r"), "InvalidKind", "{group}/{kind}");
            assert!(!listener(&m, "public", "pg").serving());
        }
        // The empty group and kind Service, spelled out, are fine.
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "r")
                    .parent("public")
                    .backend_kind("", "Service", "db"),
            ],
            vec![db()],
        );
        assert_eq!(resolved(&m, "gw", "r"), "Ok");
        assert!(listener(&m, "public", "pg").serving());
    }

    #[test]
    fn headless_and_external_name_services_are_refused() {
        let cases = [
            ("headless", service("gw", "db", "None", &[5432])),
            ("empty", service("gw", "db", "", &[5432])),
            ("garbage", service("gw", "db", "not-an-ip", &[5432])),
            ("external", db().external_name()),
            ("no spec", {
                let mut s = db();
                s.spec = None;
                s
            }),
            ("no cluster ip", {
                let mut s = db();
                s.spec.as_mut().unwrap().cluster_ip = None;
                s
            }),
        ];
        for (what, svc) in cases {
            let m = run(
                vec![public()],
                vec![tcp_route("gw", "r").parent("public").backend("db", 5432)],
                vec![svc],
            );
            assert_eq!(resolved(&m, "gw", "r"), "BackendNotFound", "{what}");
            let l = listener(&m, "public", "pg");
            assert!(l.backends.is_empty(), "{what}");
            assert!(!l.serving(), "{what}");
        }
    }

    #[test]
    fn valid_backends_survive_an_invalid_sibling() {
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "r")
                    .parent("public")
                    .backend("db", 5432)
                    .backend("missing", 5432),
            ],
            vec![db()],
        );
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        assert_eq!(resolved(&m, "gw", "r"), "BackendNotFound");
        let l = listener(&m, "public", "pg");
        assert_eq!(l.backends, [backend("gw", "db", "10.43.0.12", 5432, 1)]);
        assert!(l.serving());
    }

    #[test]
    fn resolved_refs_reports_the_first_problem() {
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "r")
                    .parent("public")
                    .backend("db", 5432)
                    .backend_in("apps", "db", 5432)
                    .backend("missing", 5432)
                    .backend_kind("", "ConfigMap", "db"),
            ],
            vec![db()],
        );
        assert_eq!(resolved(&m, "gw", "r"), "RefNotPermitted");
    }

    #[test]
    fn backend_checks_run_in_table_order() {
        // Each backendRef fails several checks; the earliest in the table is reported.
        let cases: Vec<(&str, TcpRoute)> = vec![
            ("InvalidKind", {
                let mut r = tcp_route("gw", "r")
                    .parent("public")
                    .backend_in("apps", "x", 1);
                r.spec.rules[0].backend_refs[0].kind = Some("ConfigMap".into());
                r.spec.rules[0].backend_refs[0].port = None;
                r
            }),
            ("RefNotPermitted", {
                let mut r = tcp_route("gw", "r")
                    .parent("public")
                    .backend_in("apps", "x", 1);
                r.spec.rules[0].backend_refs[0].port = None;
                r
            }),
            ("UnsupportedValue", {
                let mut r = tcp_route("gw", "r").parent("public").backend("x", 1);
                r.spec.rules[0].backend_refs[0].port = None;
                r
            }),
            (
                "BackendNotFound",
                tcp_route("gw", "r").parent("public").weighted("x", 1, 0),
            ),
        ];
        for (want, r) in cases {
            let m = run(vec![public()], vec![r], vec![]);
            assert_eq!(resolved(&m, "gw", "r"), want);
        }
    }

    #[test]
    fn refused_parent_still_reports_backends() {
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "r")
                    .parent("public")
                    .section("pg")
                    .parent("public")
                    .port(1)
                    .backend("missing", 5432),
            ],
            vec![],
        );
        let parents = &route(&m, "gw", "r").parents;
        assert_eq!(parents.len(), 2);
        assert_eq!(reason(&parents[0].accepted), "Ok");
        assert_eq!(reason(&parents[1].accepted), "NoMatchingParent");
        assert_eq!(reason(&parents[0].resolved_refs), "BackendNotFound");
        assert_eq!(parents[0].resolved_refs, parents[1].resolved_refs);
    }

    #[test]
    fn duplicate_parent_refs_are_listed_once() {
        let m = run(
            vec![public()],
            vec![
                tcp_route("gw", "r")
                    .parent("public")
                    .parent_in("gw", "public")
                    .backend("db", 5432),
            ],
            vec![db()],
        );
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        assert_eq!(listener(&m, "public", "pg").attached_routes, 1);
    }

    #[test]
    fn ipv6_cluster_ip_is_parsed() {
        let m = run(
            vec![public()],
            vec![tcp_route("gw", "r").parent("public").backend("db", 5432)],
            vec![service("gw", "db", "fd00::12", &[5432])],
        );
        let l = listener(&m, "public", "pg");
        assert_eq!(l.backends.len(), 1);
        assert_eq!(l.backends[0].ip, "fd00::12".parse::<IpAddr>().unwrap());
        assert!(l.backends[0].ip.is_ipv6());
    }

    #[test]
    fn route_in_allowed_namespace_cannot_use_a_gateway_outside_gateway_namespaces() {
        // gw is served; "other" is not, so other/public is not accepted even though it would
        // admit routes from any namespace.
        let m = run(
            vec![
                gateway("other", "public")
                    .listener("pg", 5432, "TCP")
                    .allow_all_namespaces(),
            ],
            vec![
                tcp_route("gw", "r")
                    .parent_in("other", "public")
                    .backend("db", 5432),
            ],
            vec![db()],
        );
        assert_eq!(
            reason(&m.gateways[0].accepted),
            "NamespaceNotAllowed",
            "precondition"
        );
        assert_eq!(accepted(&m, "gw", "r"), "NotAllowedByListeners");
        let l = listener(&m, "public", "pg");
        assert_eq!(l.attached_routes, 0);
        assert!(!l.serving());
    }

    #[test]
    fn build_is_deterministic() {
        let gw = public()
            .allow_all_namespaces()
            .listener("alt", 15432, "TCP")
            .allow_all_namespaces();
        let s = snap(
            vec![gw, gateway("gw", "second").listener("x", 7000, "TCP")],
            vec![
                tcp_route("gw", "a")
                    .parent("public")
                    .weighted("db", 5432, 2)
                    .backend("db2", 5432)
                    .created(10),
                tcp_route("apps", "b")
                    .parent_in("gw", "public")
                    .section("alt")
                    .backend("db", 5432),
                tcp_route("gw", "c")
                    .parent("second")
                    .parent("public")
                    .section("alt")
                    .backend("db2", 5432)
                    .created(5),
                tcp_route("gw", "d").parent("absent").backend("db", 5432),
            ],
            vec![
                db(),
                service("gw", "db2", "10.43.0.13", &[5432]),
                service("apps", "db", "10.43.0.20", &[5432]),
            ],
        );
        let expected = build(&s, &settings(&["gw"]));
        assert_eq!(expected.routes.len(), 3);
        let mut r = s.clone();
        r.tcp_routes.reverse();
        r.services.reverse();
        r.namespaces.reverse();
        r.gateways.reverse();
        assert_eq!(build(&r, &settings(&["gw"])), expected);
        // Routes are sorted by key; backends keep backendRef order.
        let keys: Vec<_> = expected.routes.iter().map(|r| r.key.to_string()).collect();
        assert_eq!(keys, ["apps/b", "gw/a", "gw/c"]);
        assert_eq!(
            listener(&expected, "public", "pg").backends,
            [
                backend("gw", "db", "10.43.0.12", 5432, 2),
                backend("gw", "db2", "10.43.0.13", 5432, 1),
            ]
        );
        assert_eq!(
            listener(&expected, "public", "alt").backends,
            [backend("gw", "db2", "10.43.0.13", 5432, 1)]
        );
        assert_eq!(accepted(&expected, "apps", "b"), "UnsupportedValue");
    }
}
