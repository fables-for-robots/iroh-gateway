//! Writes the desired status to the cluster, only where it differs from what is there.
//!
//! Every write is a JSON merge patch of the status subresource that carries the complete status
//! this operator owns for that object: condition lists and the other lists are always sent
//! whole, never in part. Whether an object needs a write is decided against the object in the
//! snapshot, with `lastTransitionTime` values ignored.

use std::time::Duration;

use gateway_api::gatewayclasses::v1::GatewayClass;
use gateway_api::gateways::v1::{
    Gateway, GatewayStatusAddresses, GatewayStatusListeners, GatewayStatusListenersSupportedKinds,
};
use gateway_api::httproutes::v1::HttpRoute;
use gateway_api::tcproutes::v1::TcpRoute;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::jiff::Timestamp;
use kube::api::{Patch, PatchParams};
use kube::{Api, Client, ResourceExt};
use serde::Serialize;
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::crd::{Edge, EdgeStatus};
use crate::model::{
    AddressKind, ObjRef, ParentKey, ParentRef, ParentStatus, RouteKind, RouteResource, Snapshot,
    parent_key,
};
use crate::status::conditions::merge;
use crate::status::{
    ClassStatus, DesiredStatus, EdgeStatusOut, GatewayStatusOut, ListenerStatusOut, RouteStatusOut,
};

/// The group of the route kinds a listener reports as supported.
const ROUTE_GROUP: &str = "gateway.networking.k8s.io";

/// How long one status request may take; a request that takes longer counts as failed.
pub const STATUS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the reconcile loop sends the status it computed.
pub trait StatusSink: Send {
    /// True when every write of this pass succeeded or was not needed; false when at least one
    /// failed, so that the loop tries again later.
    fn write(
        &mut self,
        desired: &DesiredStatus,
        snapshot: &Snapshot,
    ) -> impl Future<Output = bool> + Send;
}

/// Patches status in the cluster. A failed patch is logged; the loop retries the pass.
pub struct StatusWriter {
    client: Client,
    controller_name: String,
    /// [`STATUS_REQUEST_TIMEOUT`]; shorter in tests.
    request_timeout: Duration,
}

impl StatusWriter {
    pub fn new(client: Client, controller_name: String) -> Self {
        Self {
            client,
            controller_name,
            request_timeout: STATUS_REQUEST_TIMEOUT,
        }
    }

    /// Sends one patch; true when it counts as written (see [`written`]). A patch without an
    /// answer within the request timeout counts as failed.
    async fn send(&self, patch: StatusPatch) -> bool {
        let params = PatchParams::default();
        let body = Patch::Merge(&patch.body);
        let request = async {
            match &patch.target {
                Target::GatewayClass(name) => Api::<GatewayClass>::all(self.client.clone())
                    .patch_status(name, &params, &body)
                    .await
                    .map(drop),
                Target::Gateway(key) => {
                    Api::<Gateway>::namespaced(self.client.clone(), &key.namespace)
                        .patch_status(&key.name, &params, &body)
                        .await
                        .map(drop)
                }
                Target::Route(RouteKind::Tcp, key) => {
                    Api::<TcpRoute>::namespaced(self.client.clone(), &key.namespace)
                        .patch_status(&key.name, &params, &body)
                        .await
                        .map(drop)
                }
                Target::Route(RouteKind::Http, key) => {
                    Api::<HttpRoute>::namespaced(self.client.clone(), &key.namespace)
                        .patch_status(&key.name, &params, &body)
                        .await
                        .map(drop)
                }
                Target::Edge(key) => Api::<Edge>::namespaced(self.client.clone(), &key.namespace)
                    .patch_status(&key.name, &params, &body)
                    .await
                    .map(drop),
            }
        };
        let Ok(result) = tokio::time::timeout(self.request_timeout, request).await else {
            warn!(
                object = %patch.target,
                "writing status failed: no answer within {:?}", self.request_timeout
            );
            return false;
        };
        match &result {
            Ok(()) => debug!(object = %patch.target, "wrote status"),
            Err(e) if written(&result) => {
                debug!(object = %patch.target, "not writing status, the object is gone: {e}")
            }
            Err(e) => warn!(object = %patch.target, "writing status failed: {e}"),
        }
        written(&result)
    }
}

/// Whether a patch's outcome counts as written: it succeeded, or the object was deleted since
/// the snapshot (404), so there is nothing left to write. A conflict (409) and every other error
/// count as failed; the retry works from a newer snapshot.
fn written(result: &kube::Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(kube::Error::Api(status)) => status.code == 404,
        Err(_) => false,
    }
}

impl StatusSink for StatusWriter {
    async fn write(&mut self, desired: &DesiredStatus, snapshot: &Snapshot) -> bool {
        let now = Time(Timestamp::now());
        let mut all_written = true;
        for patch in patches(desired, snapshot, &self.controller_name, &now) {
            all_written &= self.send(patch).await;
        }
        all_written
    }
}

/// The object a patch is for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    GatewayClass(String),
    Gateway(ObjRef),
    Route(RouteKind, ObjRef),
    Edge(ObjRef),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::GatewayClass(name) => write!(f, "GatewayClass {name}"),
            Target::Gateway(key) => write!(f, "Gateway {key}"),
            Target::Route(kind, key) => write!(f, "{} {key}", kind.as_str()),
            Target::Edge(key) => write!(f, "Edge {key}"),
        }
    }
}

#[derive(Debug)]
struct StatusPatch {
    target: Target,
    body: Value,
}

/// Every patch needed to bring the snapshot's objects to `desired`.
///
/// GatewayClasses, Gateways and Edges are written only when they are in the model. One that
/// left the model but still carries status from this operator (for example a Gateway whose
/// class now names another controller) is left alone here. Routes of every kind are the
/// exception, since other controllers write the same list: every route in the snapshot loses the
/// entries of ours that are no longer desired.
fn patches(
    desired: &DesiredStatus,
    snapshot: &Snapshot,
    controller: &str,
    now: &Time,
) -> Vec<StatusPatch> {
    let mut out = Vec::new();
    for want in &desired.classes {
        if let Some(class) = snapshot
            .gateway_classes
            .iter()
            .find(|c| c.name_any() == want.name)
            && let Some(body) = class_patch(class, want, now)
        {
            out.push(StatusPatch {
                target: Target::GatewayClass(want.name.clone()),
                body,
            });
        }
    }
    for want in &desired.gateways {
        if let Some(gateway) = snapshot
            .gateways
            .iter()
            .find(|g| ObjRef::of(*g) == want.key)
            && let Some(body) = gateway_patch(gateway, want, now)
        {
            out.push(StatusPatch {
                target: Target::Gateway(want.key.clone()),
                body,
            });
        }
    }
    route_patches(&snapshot.tcp_routes, desired, controller, now, &mut out);
    route_patches(&snapshot.http_routes, desired, controller, now, &mut out);
    for want in &desired.edges {
        if let Some(edge) = snapshot.edges.iter().find(|e| ObjRef::of(*e) == want.key)
            && let Some(body) = edge_patch(edge, want, now)
        {
            out.push(StatusPatch {
                target: Target::Edge(want.key.clone()),
                body,
            });
        }
    }
    out
}

/// The patches for `routes`, each matched with the desired status of its own kind and key.
fn route_patches<R: RouteResource>(
    routes: &[R],
    desired: &DesiredStatus,
    controller: &str,
    now: &Time,
    out: &mut Vec<StatusPatch>,
) {
    for route in routes {
        let key = ObjRef::of(route);
        let want = desired
            .routes
            .iter()
            .find(|r| r.kind == R::KIND && r.key == key);
        if let Some(body) = route_patch(route, want, controller, now) {
            out.push(StatusPatch {
                target: Target::Route(R::KIND, key),
                body,
            });
        }
    }
}

/// `value` as JSON with every `lastTransitionTime` removed.
fn without_times(value: &impl Serialize) -> Value {
    fn strip(value: &mut Value) {
        match value {
            Value::Object(map) => {
                map.remove("lastTransitionTime");
                map.values_mut().for_each(strip);
            }
            Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    let mut value = serde_json::to_value(value).expect("status serializes");
    strip(&mut value);
    value
}

fn same(a: &impl Serialize, b: &impl Serialize) -> bool {
    without_times(a) == without_times(b)
}

fn class_patch(class: &GatewayClass, want: &ClassStatus, now: &Time) -> Option<Value> {
    let existing = class
        .status
        .as_ref()
        .and_then(|s| s.conditions.clone())
        .unwrap_or_default();
    let conditions = merge(&existing, &want.conditions, want.generation, now.clone());
    (!same(&existing, &conditions)).then(|| json!({ "status": { "conditions": conditions } }))
}

fn gateway_patch(gateway: &Gateway, want: &GatewayStatusOut, now: &Time) -> Option<Value> {
    let status = gateway.status.clone().unwrap_or_default();
    let existing_conditions = status.conditions.unwrap_or_default();
    let existing_listeners = status.listeners.unwrap_or_default();
    let conditions = merge(
        &existing_conditions,
        &want.conditions,
        want.generation,
        now.clone(),
    );
    let addresses: Vec<GatewayStatusAddresses> = want
        .addresses
        .iter()
        .map(|a| GatewayStatusAddresses {
            r#type: Some(
                match a.kind {
                    AddressKind::IpAddress => "IPAddress",
                    AddressKind::Hostname => "Hostname",
                }
                .to_owned(),
            ),
            value: a.value.clone(),
        })
        .collect();
    let listeners: Vec<GatewayStatusListeners> = want
        .listeners
        .iter()
        .map(|l| listener_status(l, &existing_listeners, want.generation, now))
        .collect();
    let existing = json!({
        "conditions": existing_conditions,
        "addresses": status.addresses.unwrap_or_default(),
        "listeners": existing_listeners,
    });
    let desired = json!({
        "conditions": conditions,
        "addresses": addresses,
        "listeners": listeners,
    });
    (!same(&existing, &desired)).then(|| json!({ "status": desired }))
}

fn listener_status(
    want: &ListenerStatusOut,
    existing: &[GatewayStatusListeners],
    generation: i64,
    now: &Time,
) -> GatewayStatusListeners {
    let old: &[Condition] = existing
        .iter()
        .find(|l| l.name == want.name)
        .map_or(&[], |l| &l.conditions);
    GatewayStatusListeners {
        name: want.name.clone(),
        supported_kinds: Some(
            want.supported_kinds
                .iter()
                .map(|kind| GatewayStatusListenersSupportedKinds {
                    group: Some(ROUTE_GROUP.to_owned()),
                    kind: kind.clone(),
                })
                .collect(),
        ),
        attached_routes: want.attached_routes,
        conditions: merge(old, &want.conditions, generation, now.clone()),
    }
}

/// The route's own `parentRef` that `key` was made from, as the user wrote it. A status entry's
/// `parentRef` gets its key the same way, with [`parent_key`], so the API server filling in
/// `group` and `kind` does not make an entry of ours look like another.
fn echo(route: &impl RouteResource, route_ns: &str, key: &ParentKey) -> ParentRef {
    let written = route
        .parent_refs()
        .into_iter()
        .find(|p| parent_key(p, route_ns).as_ref() == Some(key));
    // The model takes its keys from the route itself, so the fallback is not expected.
    written.unwrap_or_else(|| ParentRef {
        group: Some(key.group.clone()),
        kind: Some(key.kind.clone()),
        namespace: Some(key.namespace.clone()),
        name: key.name.clone(),
        section_name: key.section_name.clone(),
        port: key.port.map(i32::from),
    })
}

/// `status.parents` rebuilt: entries of other controllers unchanged and in place, ours updated
/// in place, ours that are no longer desired removed, and new ones of ours appended.
fn route_patch<R: RouteResource>(
    route: &R,
    want: Option<&RouteStatusOut>,
    controller: &str,
    now: &Time,
) -> Option<Value> {
    let ns = route.namespace().unwrap_or_default();
    let existing = route.status_parents();
    let is_ours = |entry: &ParentStatus, key: &ParentKey| {
        entry.controller_name == controller
            && parent_key(&entry.parent_ref, &ns).as_ref() == Some(key)
    };
    let mut ours: Vec<(&ParentKey, ParentStatus)> = want
        .map(|w| {
            w.parents
                .iter()
                .map(|(key, conditions)| {
                    let old: &[Condition] = existing
                        .iter()
                        .find(|e| is_ours(e, key))
                        .map_or(&[], |e| &e.conditions);
                    let entry = ParentStatus {
                        parent_ref: echo(route, &ns, key),
                        controller_name: controller.to_owned(),
                        conditions: merge(old, conditions, w.generation, now.clone()),
                    };
                    (key, entry)
                })
                .collect()
        })
        .unwrap_or_default();

    let mut parents = Vec::with_capacity(existing.len() + ours.len());
    for entry in &existing {
        if entry.controller_name != controller {
            parents.push(entry.clone());
        } else if let Some(i) = ours.iter().position(|(key, _)| is_ours(entry, key)) {
            parents.push(ours.remove(i).1);
        }
    }
    parents.extend(ours.into_iter().map(|(_, entry)| entry));

    (!same(&existing, &parents)).then(|| {
        json!({
            // Others write this list too: refuse the write if the route changed since the
            // snapshot, and redo it from the newer route on the next pass.
            "metadata": { "resourceVersion": route.resource_version() },
            "status": { "parents": parents },
        })
    })
}

fn edge_patch(edge: &Edge, want: &EdgeStatusOut, now: &Time) -> Option<Value> {
    let existing = edge.status.clone().unwrap_or_default();
    let desired = EdgeStatus {
        gateway_endpoint_id: Some(want.gateway_endpoint_id.clone()),
        conditions: merge(
            &existing.conditions,
            &want.conditions,
            want.generation,
            now.clone(),
        ),
        listeners: want.listeners.clone(),
    };
    (!same(&existing, &desired)).then(|| json!({ "status": desired }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use gateway_api::gateways::v1::GatewayStatus;
    use gateway_api::httproutes::v1::{HttpRouteStatus, HttpRouteStatusParents};
    use gateway_api::tcproutes::v1::{
        TcpRouteStatus, TcpRouteStatusParents, TcpRouteStatusParentsParentRef,
    };

    use super::*;
    use crate::crd::EdgeListenerStatus;
    use crate::model::fixtures::{
        CONTROLLER, HttpRouteExt, RouteExt, class, edge, gateway, http_route, tcp_route,
    };
    use crate::model::{GatewayAddress, build};
    use crate::status::{Cond, Facts, compute};

    const OTHER: &str = "example.com/other-controller";

    fn at(secs: i64) -> Time {
        Time(Timestamp::from_second(secs).unwrap())
    }

    fn cond(type_: &str, status: bool, reason: &str) -> Cond {
        Cond {
            type_: type_.into(),
            status,
            reason: reason.into(),
            message: String::new(),
        }
    }

    fn key(ns: &str, name: &str) -> ParentKey {
        ParentKey {
            group: ROUTE_GROUP.into(),
            kind: "Gateway".into(),
            namespace: ns.into(),
            name: name.into(),
            section_name: None,
            port: None,
        }
    }

    fn entry(controller: &str, gateway: &str, reason: &str) -> TcpRouteStatusParents {
        TcpRouteStatusParents {
            conditions: merge(&[], &[cond("Accepted", true, reason)], 1, at(10)),
            controller_name: controller.into(),
            parent_ref: TcpRouteStatusParentsParentRef {
                name: gateway.into(),
                ..Default::default()
            },
        }
    }

    fn want_route(gen_: i64, parents: &[(&str, &str)]) -> RouteStatusOut {
        RouteStatusOut {
            kind: RouteKind::Tcp,
            key: ObjRef::new("apps", "r"),
            generation: gen_,
            parents: parents
                .iter()
                .map(|(gw, reason)| (key("apps", gw), vec![cond("Accepted", true, reason)]))
                .collect(),
        }
    }

    fn parents_of(patch: &Value) -> Vec<(String, String, String)> {
        patch["status"]["parents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["controllerName"].as_str().unwrap().to_owned(),
                    p["parentRef"]["name"].as_str().unwrap().to_owned(),
                    p["conditions"][0]["reason"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    fn triple(c: &str, gw: &str, reason: &str) -> (String, String, String) {
        (c.into(), gw.into(), reason.into())
    }

    fn with_status(mut route: TcpRoute, parents: Vec<TcpRouteStatusParents>) -> TcpRoute {
        route.status = Some(TcpRouteStatus { parents });
        route.metadata.resource_version = Some("42".into());
        route
    }

    #[test]
    fn route_entries_of_other_controllers_stay_in_place() {
        let route = with_status(
            tcp_route("apps", "r").parent("a").parent("b").parent("c"),
            vec![
                entry(OTHER, "x", "Theirs"),
                entry(CONTROLLER, "a", "Old"),
                entry(OTHER, "y", "Theirs"),
                entry(CONTROLLER, "stale", "Old"),
            ],
        );
        let want = want_route(2, &[("a", "New"), ("b", "New")]);
        let patch = route_patch(&route, Some(&want), CONTROLLER, &at(100)).unwrap();
        assert_eq!(
            parents_of(&patch),
            [
                triple(OTHER, "x", "Theirs"),
                triple(CONTROLLER, "a", "New"),
                triple(OTHER, "y", "Theirs"),
                triple(CONTROLLER, "b", "New"),
            ]
        );
        assert_eq!(patch["metadata"]["resourceVersion"], "42");
        // Foreign entries are copied unchanged, transition times and all.
        let theirs: TcpRouteStatusParents =
            serde_json::from_value(patch["status"]["parents"][0].clone()).unwrap();
        assert_eq!(theirs, entry(OTHER, "x", "Theirs"));
    }

    #[test]
    fn route_parent_ref_echoes_what_the_user_wrote() {
        let route = tcp_route("apps", "r").parent("a").section("db");
        let mut want = want_route(1, &[]);
        want.parents = vec![(
            ParentKey {
                section_name: Some("db".into()),
                ..key("apps", "a")
            },
            vec![cond("Accepted", true, "Accepted")],
        )];
        let patch = route_patch(&route, Some(&want), CONTROLLER, &at(100)).unwrap();
        assert_eq!(
            patch["status"]["parents"][0]["parentRef"],
            json!({ "name": "a", "sectionName": "db" })
        );
    }

    #[test]
    fn route_left_by_us_loses_only_our_entries() {
        let route = with_status(
            tcp_route("apps", "r").parent("a"),
            vec![entry(CONTROLLER, "a", "Old"), entry(OTHER, "x", "Theirs")],
        );
        let patch = route_patch(&route, None, CONTROLLER, &at(100)).unwrap();
        assert_eq!(parents_of(&patch), [triple(OTHER, "x", "Theirs")]);

        let foreign_only = with_status(tcp_route("apps", "r"), vec![entry(OTHER, "x", "T")]);
        assert!(route_patch(&foreign_only, None, CONTROLLER, &at(100)).is_none());
        assert!(route_patch(&tcp_route("apps", "r"), None, CONTROLLER, &at(100)).is_none());
    }

    #[test]
    fn route_is_not_patched_when_only_times_would_change() {
        let route = with_status(
            tcp_route("apps", "r").parent("a"),
            vec![entry(CONTROLLER, "a", "Same")],
        );
        let want = want_route(1, &[("a", "Same")]);
        assert!(route_patch(&route, Some(&want), CONTROLLER, &at(100)).is_none());
    }

    fn want_http(gen_: i64, parents: &[(&str, &str)]) -> RouteStatusOut {
        RouteStatusOut {
            kind: RouteKind::Http,
            ..want_route(gen_, parents)
        }
    }

    /// `entry`, as an HTTPRoute's status entry.
    fn http_entry(controller: &str, gateway: &str, reason: &str) -> HttpRouteStatusParents {
        let tcp = serde_json::to_value(entry(controller, gateway, reason)).unwrap();
        serde_json::from_value(tcp).unwrap()
    }

    fn with_http_status(mut route: HttpRoute, parents: Vec<HttpRouteStatusParents>) -> HttpRoute {
        route.status = Some(HttpRouteStatus { parents });
        route.metadata.resource_version = Some("42".into());
        route
    }

    /// The desired status of `routes` alone, nothing else in it.
    fn desired_routes(routes: Vec<RouteStatusOut>) -> DesiredStatus {
        DesiredStatus {
            classes: vec![],
            gateways: vec![],
            routes,
            edges: vec![],
        }
    }

    fn http_snapshot(routes: Vec<HttpRoute>) -> Snapshot {
        Snapshot {
            http_routes: routes,
            ..Snapshot::default()
        }
    }

    #[test]
    fn http_route_gets_our_parent_entry() {
        let route = with_http_status(http_route("apps", "r").parent("a").section("db"), vec![]);
        let mut want = want_http(1, &[]);
        want.parents = vec![(
            ParentKey {
                section_name: Some("db".into()),
                ..key("apps", "a")
            },
            vec![cond("Accepted", true, "Accepted")],
        )];
        let mut out = patches(
            &desired_routes(vec![want]),
            &http_snapshot(vec![route]),
            CONTROLLER,
            &at(100),
        );
        assert_eq!(out.len(), 1, "{out:?}");
        let patch = out.remove(0);
        assert_eq!(
            patch.target,
            Target::Route(RouteKind::Http, ObjRef::new("apps", "r"))
        );
        assert_eq!(patch.target.to_string(), "HTTPRoute apps/r");
        assert_eq!(
            parents_of(&patch.body),
            [triple(CONTROLLER, "a", "Accepted")]
        );
        assert_eq!(
            patch.body["status"]["parents"][0]["parentRef"],
            json!({ "name": "a", "sectionName": "db" })
        );
        assert_eq!(patch.body["metadata"]["resourceVersion"], "42");
    }

    #[test]
    fn stale_entry_of_ours_is_removed_from_an_http_route() {
        let route = with_http_status(
            http_route("apps", "r").parent("a"),
            vec![
                http_entry(CONTROLLER, "a", "Old"),
                http_entry(OTHER, "x", "Theirs"),
            ],
        );
        let out = patches(
            &desired_routes(vec![]),
            &http_snapshot(vec![route]),
            CONTROLLER,
            &at(100),
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(
            out[0].target,
            Target::Route(RouteKind::Http, ObjRef::new("apps", "r"))
        );
        assert_eq!(parents_of(&out[0].body), [triple(OTHER, "x", "Theirs")]);
        assert_eq!(out[0].body["metadata"]["resourceVersion"], "42");
    }

    #[test]
    fn foreign_entries_on_an_http_route_stay_in_place() {
        let route = with_http_status(
            http_route("apps", "r").parent("a").parent("b").parent("c"),
            vec![
                http_entry(OTHER, "x", "Theirs"),
                http_entry(CONTROLLER, "a", "Old"),
                http_entry(OTHER, "y", "Theirs"),
                http_entry(CONTROLLER, "stale", "Old"),
            ],
        );
        let want = want_http(2, &[("a", "New"), ("b", "New")]);
        let patch = route_patch(&route, Some(&want), CONTROLLER, &at(100)).unwrap();
        assert_eq!(
            parents_of(&patch),
            [
                triple(OTHER, "x", "Theirs"),
                triple(CONTROLLER, "a", "New"),
                triple(OTHER, "y", "Theirs"),
                triple(CONTROLLER, "b", "New"),
            ]
        );
        assert_eq!(patch["metadata"]["resourceVersion"], "42");
        let theirs: HttpRouteStatusParents =
            serde_json::from_value(patch["status"]["parents"][0].clone()).unwrap();
        assert_eq!(theirs, http_entry(OTHER, "x", "Theirs"));
    }

    #[test]
    fn unchanged_http_route_needs_no_patch() {
        let route = with_http_status(
            http_route("apps", "r").parent("a"),
            vec![
                http_entry(CONTROLLER, "a", "Same"),
                http_entry(OTHER, "x", "Theirs"),
            ],
        );
        let want = want_http(1, &[("a", "Same")]);
        assert!(route_patch(&route, Some(&want), CONTROLLER, &at(100)).is_none());
        let out = patches(
            &desired_routes(vec![want]),
            &http_snapshot(vec![route]),
            CONTROLLER,
            &at(100),
        );
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn tcp_and_http_routes_with_the_same_name_are_told_apart() {
        let mut want = want_route(1, &[("a", "Accepted")]);
        want.key = ObjRef::new("apps", "web");
        let snapshot = Snapshot {
            tcp_routes: vec![with_status(tcp_route("apps", "web").parent("a"), vec![])],
            http_routes: vec![with_http_status(
                http_route("apps", "web").parent("a"),
                vec![],
            )],
            ..Snapshot::default()
        };
        let out = patches(&desired_routes(vec![want]), &snapshot, CONTROLLER, &at(100));
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(
            out[0].target,
            Target::Route(RouteKind::Tcp, ObjRef::new("apps", "web"))
        );
        assert_eq!(out[0].target.to_string(), "TCPRoute apps/web");
        assert_eq!(
            parents_of(&out[0].body),
            [triple(CONTROLLER, "a", "Accepted")]
        );
    }

    fn gateway_want() -> GatewayStatusOut {
        GatewayStatusOut {
            key: ObjRef::new("gw", "public"),
            generation: 3,
            conditions: vec![cond("Accepted", true, "Accepted")],
            addresses: vec![
                GatewayAddress::parse("203.0.113.7").unwrap(),
                GatewayAddress::parse("edge.example.com").unwrap(),
            ],
            listeners: vec![ListenerStatusOut {
                name: "db".into(),
                supported_kinds: vec!["TCPRoute".into()],
                attached_routes: 1,
                conditions: vec![cond("Programmed", true, "Programmed")],
            }],
        }
    }

    #[test]
    fn gateway_status_is_written_whole() {
        let gw = gateway("gw", "public");
        let patch = gateway_patch(&gw, &gateway_want(), &at(100)).unwrap();
        let status = &patch["status"];
        assert_eq!(status["conditions"][0]["type"], "Accepted");
        assert_eq!(status["conditions"][0]["observedGeneration"], 3);
        assert_eq!(
            status["addresses"],
            json!([
                { "type": "IPAddress", "value": "203.0.113.7" },
                { "type": "Hostname", "value": "edge.example.com" },
            ])
        );
        let listener = &status["listeners"][0];
        assert_eq!(listener["name"], "db");
        assert_eq!(
            listener["supportedKinds"],
            json!([{ "group": "gateway.networking.k8s.io", "kind": "TCPRoute" }])
        );
        assert_eq!(listener["attachedRoutes"], 1);
        assert_eq!(listener["conditions"][0]["type"], "Programmed");
    }

    #[test]
    fn gateway_is_not_patched_when_only_times_would_change() {
        let mut gw = gateway("gw", "public");
        let first = gateway_patch(&gw, &gateway_want(), &at(100)).unwrap();
        gw.status = Some(serde_json::from_value::<GatewayStatus>(first["status"].clone()).unwrap());
        assert!(gateway_patch(&gw, &gateway_want(), &at(200)).is_none());

        let mut changed = gateway_want();
        changed.listeners[0].attached_routes = 0;
        assert!(gateway_patch(&gw, &changed, &at(200)).is_some());
    }

    #[test]
    fn class_and_edge_patches_appear_only_on_change() {
        let mut c = class("ours");
        let want = ClassStatus {
            name: "ours".into(),
            generation: 1,
            conditions: vec![cond("Accepted", true, "Accepted")],
        };
        let patch = class_patch(&c, &want, &at(100)).unwrap();
        c.status = Some(serde_json::from_value(patch["status"].clone()).unwrap());
        assert!(class_patch(&c, &want, &at(200)).is_none());

        let mut e = edge("gw", "e1", 1);
        let want = EdgeStatusOut {
            key: ObjRef::new("gw", "e1"),
            generation: 1,
            gateway_endpoint_id: "op".into(),
            conditions: vec![cond("Accepted", true, "Accepted")],
            listeners: vec![EdgeListenerStatus {
                protocol: "TCP".into(),
                port: 5432,
                bound: true,
                message: None,
            }],
        };
        let patch = edge_patch(&e, &want, &at(100)).unwrap();
        assert_eq!(patch["status"]["gatewayEndpointId"], "op");
        assert_eq!(patch["status"]["listeners"][0]["port"], 5432);
        e.status = Some(serde_json::from_value(patch["status"].clone()).unwrap());
        assert!(edge_patch(&e, &want, &at(200)).is_none());
    }

    #[test]
    fn objects_outside_the_model_are_left_alone() {
        use crate::model::fixtures::{GatewayExt, foreign_class, settings};
        let mut theirs = gateway("gw", "public").class("theirs");
        theirs.status = Some(GatewayStatus {
            conditions: Some(merge(&[], &[cond("Accepted", true, "Mine")], 1, at(1))),
            ..Default::default()
        });
        let snapshot = Snapshot {
            gateway_classes: vec![class("ours"), foreign_class("theirs")],
            gateways: vec![theirs],
            ..Snapshot::default()
        };
        let model = build(&snapshot, &settings(&["gw"]));
        let facts = Facts {
            operator_id: iroh::SecretKey::from_bytes(&[1; 32]).public(),
            haproxy: Ok(()),
            edges: BTreeMap::new(),
        };
        let desired = compute(&model, &facts);
        let targets: Vec<Target> = patches(&desired, &snapshot, CONTROLLER, &at(100))
            .into_iter()
            .map(|p| p.target)
            .collect();
        assert_eq!(targets, [Target::GatewayClass("ours".into())]);
    }

    fn api_error(code: u16) -> kube::Result<()> {
        Err(kube::Error::Api(Box::new(kube::core::Status {
            code,
            ..Default::default()
        })))
    }

    #[test]
    fn deleted_objects_count_as_written_and_conflicts_do_not() {
        assert!(written(&Ok(())));
        assert!(written(&api_error(404)));
        assert!(!written(&api_error(409)));
        assert!(!written(&api_error(429)));
        assert!(!written(&api_error(500)));
    }

    /// A writer whose API server refuses every connection.
    fn unreachable_writer() -> StatusWriter {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let url = format!("http://127.0.0.1:{port}").parse().unwrap();
        let client = Client::try_from(kube::Config::new(url)).unwrap();
        StatusWriter::new(client, CONTROLLER.into())
    }

    fn class_world(status_from: Option<&Value>) -> (Snapshot, DesiredStatus) {
        use crate::model::fixtures::settings;
        let mut c = class("ours");
        if let Some(patch) = status_from {
            c.status = Some(serde_json::from_value(patch["status"].clone()).unwrap());
        }
        let snapshot = Snapshot {
            gateway_classes: vec![c],
            ..Snapshot::default()
        };
        let facts = Facts {
            operator_id: iroh::SecretKey::from_bytes(&[1; 32]).public(),
            haproxy: Ok(()),
            edges: BTreeMap::new(),
        };
        let desired = compute(&build(&snapshot, &settings(&["gw"])), &facts);
        (snapshot, desired)
    }

    /// A request to an API server that takes the connection and never answers counts as failed
    /// once the request timeout has passed (shortened here from `STATUS_REQUEST_TIMEOUT`).
    #[tokio::test]
    async fn a_request_without_an_answer_times_out_and_fails() {
        // The kernel completes the handshake; nothing ever reads the request.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", silent.local_addr().unwrap())
            .parse()
            .unwrap();
        let client = Client::try_from(kube::Config::new(url)).unwrap();
        let mut writer = StatusWriter::new(client, CONTROLLER.into());
        assert_eq!(writer.request_timeout, STATUS_REQUEST_TIMEOUT);
        let limit = Duration::from_millis(300);
        writer.request_timeout = limit;
        let (snapshot, desired) = class_world(None);
        let started = tokio::time::Instant::now();
        let written =
            tokio::time::timeout(Duration::from_secs(5), writer.write(&desired, &snapshot))
                .await
                .expect("the write did not end");
        assert!(!written);
        let waited = started.elapsed();
        assert!(
            waited >= limit && waited < Duration::from_secs(3),
            "{waited:?}"
        );
        drop(silent);
    }

    #[tokio::test]
    async fn write_is_false_when_a_patch_fails_and_true_when_none_is_needed() {
        let mut writer = unreachable_writer();
        let (snapshot, desired) = class_world(None);
        assert!(!writer.write(&desired, &snapshot).await);

        let patch = class_patch(&snapshot.gateway_classes[0], &desired.classes[0], &at(1)).unwrap();
        let (snapshot, desired) = class_world(Some(&patch));
        assert!(writer.write(&desired, &snapshot).await);
    }
}
