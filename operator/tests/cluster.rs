//! The operator against a real API server (see `common::envtest`), a real HAProxy and a real
//! in-process edge. Each test has an API server of its own.
//!
//! Run with `KUBEBUILDER_ASSETS=$(scripts/envtest-assets) cargo test -p iroh-gateway-operator
//! --test cluster -- --ignored`.
#![cfg(unix)]

#[allow(dead_code)]
mod common;

use std::fmt::Debug;
use std::time::Duration;

use common::envtest::Envtest;
use common::{edge_options, free_tcp_port, refused, short_dir};
use gateway_api::gatewayclasses::v1::GatewayClass;
use gateway_api::gateways::v1::{Gateway, GatewayStatusListeners};
use gateway_api::httproutes::v1::HttpRoute;
use gateway_api::tcproutes::v1::TcpRoute;
use iroh::SecretKey;
use iroh_gateway_edge::{Edge as EdgeProcess, EdgeHandle};
use iroh_gateway_operator::cluster::{StatusSink, StatusWriter, Stores, identity};
use iroh_gateway_operator::controller::{ControllerOptions, run_loop};
use iroh_gateway_operator::crd::Edge;
use iroh_gateway_operator::engine::{Engine, EngineOptions};
use iroh_gateway_operator::haproxy::SupervisorOptions;
use iroh_gateway_operator::haproxy::render::render;
use iroh_gateway_operator::model::{Settings, Snapshot, build};
use iroh_gateway_operator::status::{Facts, compute};
use iroh_gateway_operator::tunnel::bind_endpoint;
use iroh_gateway_proto::transport::Relay;
use k8s_openapi::ByteString;
use k8s_openapi::NamespaceResourceScope;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::{DeleteParams, DynamicObject, GroupVersionKind, Patch, PatchParams, PostParams};
use kube::discovery::{Scope, pinned_kind};
use kube::{Api, Client, Resource, ResourceExt};
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};

const CONTROLLER: &str = "gateway.fables-for-robots.ch/iroh-gateway";
const OTHER_CONTROLLER: &str = "example.com/other-controller";
/// Where the operator keeps its key in these tests.
const IDENTITY_NS: &str = "default";
const IDENTITY: &str = "iroh-gateway-identity";
const NS: &str = "gw";
/// How long the operator gets to converge.
const CONVERGE: Duration = Duration::from_secs(20);

/// The operator as `run` wires it: identity, engine started with an empty render, stores, loop.
struct Operator {
    key: SecretKey,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<anyhow::Result<()>>>,
    _dir: TempDir,
}

impl Operator {
    async fn start(client: &Client, namespaces: &[&str]) -> Self {
        let key = identity::load_or_create(client, IDENTITY_NS, IDENTITY)
            .await
            .unwrap();
        let dir = short_dir();
        let settings = Settings {
            controller_name: CONTROLLER.into(),
            gateway_namespaces: namespaces.iter().map(|n| (*n).to_owned()).collect(),
            relay: Relay::Disabled,
        };
        let endpoint = bind_endpoint(key.clone(), &Relay::Disabled).await.unwrap();
        let mut supervisor = SupervisorOptions::new(dir.path());
        supervisor.inherit_output = false;
        let initial = render(&build(&Snapshot::default(), &settings), dir.path());
        let mut engine = Engine::start(
            endpoint.clone(),
            EngineOptions::new(supervisor, Relay::Disabled),
            initial,
        )
        .await
        .unwrap();
        let stores = Stores::start(client.clone(), &settings.gateway_namespaces);
        let writer = StatusWriter::new(client.clone(), CONTROLLER.into());
        let opts = ControllerOptions::new(settings, dir.path());
        let (shutdown, shutdown_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let ended = run_loop(stores, &mut engine, writer, opts, async {
                let _ = shutdown_rx.await;
            })
            .await;
            engine.shutdown().await;
            endpoint.close().await;
            ended
        });
        Self {
            key,
            shutdown: Some(shutdown),
            task: Some(task),
            _dir: dir,
        }
    }

    /// An in-process edge that trusts this operator, on 127.0.0.1.
    async fn edge(&self) -> EdgeHandle {
        let opts = edge_options(
            self.key.public(),
            SecretKey::generate(),
            "127.0.0.1:0".parse().unwrap(),
        );
        EdgeProcess::spawn(opts).await.unwrap()
    }

    async fn stop(mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        let ended = tokio::time::timeout(Duration::from_secs(10), self.task.take().unwrap())
            .await
            .expect("the operator did not stop")
            .unwrap();
        ended.unwrap();
    }
}

impl Drop for Operator {
    fn drop(&mut self) {
        // After a failed test: the engine's drop kills HAProxy.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn create<K>(api: &Api<K>, object: Value) -> K
where
    K: Resource + Clone + DeserializeOwned + Serialize + Debug,
{
    let object: K = serde_json::from_value(object).unwrap();
    match api.create(&PostParams::default(), &object).await {
        Ok(created) => created,
        Err(e) => panic!("creating {object:?}: {e}"),
    }
}

fn api<K>(client: &Client, ns: &str) -> Api<K>
where
    K: Resource<Scope = NamespaceResourceScope, DynamicType = ()>,
{
    Api::namespaced(client.clone(), ns)
}

async fn get<K>(client: &Client, ns: &str, name: &str) -> K
where
    K: Resource<Scope = NamespaceResourceScope, DynamicType = ()>
        + Clone
        + DeserializeOwned
        + Debug,
{
    api::<K>(client, ns).get(name).await.unwrap()
}

/// Polls `check` until it returns `Ok`, for up to [`CONVERGE`]; panics with its last `Err`.
async fn eventually<T, F>(what: &str, mut check: impl FnMut() -> F) -> T
where
    F: Future<Output = Result<T, String>>,
{
    let deadline = Instant::now() + CONVERGE;
    loop {
        match check().await {
            Ok(value) => return value,
            Err(last) if Instant::now() >= deadline => {
                panic!("{what} not reached within {CONVERGE:?}; last: {last}")
            }
            Err(_) => sleep(Duration::from_millis(100)).await,
        }
    }
}

fn condition<'a>(conditions: &'a [Condition], type_: &str) -> Option<&'a Condition> {
    conditions.iter().find(|c| c.type_ == type_)
}

/// Ok when every `(type, status)` is present with that status.
fn has(conditions: &[Condition], wanted: &[(&str, &str)]) -> Result<(), String> {
    for (type_, status) in wanted {
        match condition(conditions, type_) {
            Some(c) if c.status == *status => {}
            _ => return Err(format!("wanted {type_}={status} in {conditions:?}")),
        }
    }
    Ok(())
}

async fn class(client: &Client) {
    create::<GatewayClass>(
        &Api::all(client.clone()),
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GatewayClass",
            "metadata": { "name": "iroh" },
            "spec": { "controllerName": CONTROLLER },
        }),
    )
    .await;
}

async fn gateway(client: &Client, ns: &str, port: u16) {
    create::<Gateway>(
        &api(client, ns),
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "public", "namespace": ns },
            "spec": {
                "gatewayClassName": "iroh",
                "listeners": [{ "name": "db", "port": port, "protocol": "TCP" }],
            },
        }),
    )
    .await;
}

async fn service(client: &Client) {
    create::<Service>(
        &api(client, NS),
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "db", "namespace": NS },
            "spec": { "ports": [{ "port": 5432 }] },
        }),
    )
    .await;
}

async fn route(client: &Client) {
    create::<TcpRoute>(
        &api(client, NS),
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "TCPRoute",
            "metadata": { "name": "db", "namespace": NS },
            "spec": {
                "parentRefs": [{ "name": "public" }],
                "rules": [{ "backendRefs": [{ "name": "db", "port": 5432 }] }],
            },
        }),
    )
    .await;
}

async fn edge_object(client: &Client, ns: &str, edge: &EdgeHandle) {
    create::<Edge>(
        &api(client, ns),
        json!({
            "apiVersion": "gateway.fables-for-robots.ch/v1alpha1",
            "kind": "Edge",
            "metadata": { "name": "e1", "namespace": ns },
            "spec": {
                "endpointId": edge.endpoint_id().to_string(),
                "address": edge.iroh_addr().to_string(),
                "gatewayRef": { "name": "public" },
            },
        }),
    )
    .await;
}

/// GatewayClass, namespace `gw`, Gateway `public` listening on `port`, Service `db`, TCPRoute
/// `db` and an Edge for `edge`.
async fn world(env: &Envtest, edge: &EdgeHandle, port: u16) {
    let client = &env.client;
    env.namespace(NS).await;
    class(client).await;
    gateway(client, NS, port).await;
    service(client).await;
    route(client).await;
    edge_object(client, NS, edge).await;
}

async fn connects(port: u16) -> Result<(), String> {
    TcpStream::connect(("127.0.0.1", port))
        .await
        .map(drop)
        .map_err(|e| format!("connect to port {port}: {e}"))
}

/// Waits until everything `world` created is accepted and programmed, and the port serves.
async fn programmed(client: &Client, operator: &Operator, port: u16) {
    eventually("GatewayClass Accepted", || async {
        let class: GatewayClass = Api::all(client.clone()).get("iroh").await.unwrap();
        let conditions = class.status.and_then(|s| s.conditions).unwrap_or_default();
        has(&conditions, &[("Accepted", "True")])
    })
    .await;
    eventually("Gateway programmed", || async {
        let gw: Gateway = get(client, NS, "public").await;
        let status = gw.status.unwrap_or_default();
        has(
            &status.conditions.clone().unwrap_or_default(),
            &[("Accepted", "True"), ("Programmed", "True")],
        )?;
        let addresses: Vec<(Option<String>, String)> = status
            .addresses
            .unwrap_or_default()
            .into_iter()
            .map(|a| (a.r#type, a.value))
            .collect();
        if addresses != [(Some("IPAddress".to_owned()), "127.0.0.1".to_owned())] {
            return Err(format!("addresses {addresses:?}"));
        }
        let listeners = status.listeners.unwrap_or_default();
        let [listener] = listeners.as_slice() else {
            return Err(format!("listeners {listeners:?}"));
        };
        if listener.attached_routes != 1 {
            return Err(format!("attachedRoutes {}", listener.attached_routes));
        }
        has(&listener.conditions, &[("Programmed", "True")])
    })
    .await;
    eventually("route parent accepted", || async {
        let route: TcpRoute = get(client, NS, "db").await;
        let parents = route.status.map(|s| s.parents).unwrap_or_default();
        let [parent] = parents.as_slice() else {
            return Err(format!("parents {parents:?}"));
        };
        if parent.controller_name != CONTROLLER {
            return Err(format!("controllerName {}", parent.controller_name));
        }
        has(
            &parent.conditions,
            &[("Accepted", "True"), ("ResolvedRefs", "True")],
        )
    })
    .await;
    eventually("Edge programmed", || async {
        let edge: Edge = get(client, NS, "e1").await;
        let status = edge.status.unwrap_or_default();
        has(
            &status.conditions,
            &[
                ("Accepted", "True"),
                ("Connected", "True"),
                ("Programmed", "True"),
            ],
        )?;
        match status.gateway_endpoint_id {
            Some(id) if id == operator.key.public().to_string() => Ok(()),
            other => Err(format!("gatewayEndpointId {other:?}")),
        }
    })
    .await;
    eventually("the public port accepts", || connects(port)).await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn crds_install_and_an_edge_roundtrips() {
    let env = Envtest::start().await;
    let edges = api::<Edge>(&env.client, "default");
    let created: Edge = create(
        &edges,
        json!({
            "apiVersion": "gateway.fables-for-robots.ch/v1alpha1",
            "kind": "Edge",
            "metadata": { "name": "fsn1", "namespace": "default" },
            "spec": {
                "endpointId": "some-key",
                "address": "203.0.113.7:7842",
                "gatewayRef": { "name": "public" },
                "publicAddresses": ["203.0.113.7", "edge.example.com"],
            },
        }),
    )
    .await;
    let read = edges.get("fsn1").await.unwrap();
    assert_eq!(read.spec, created.spec);
    assert_eq!(
        read.spec.public_addresses,
        ["203.0.113.7", "edge.example.com"]
    );

    let status = json!({ "status": {
        "gatewayEndpointId": "op",
        "conditions": [{
            "type": "Accepted", "status": "True", "reason": "Accepted", "message": "",
            "observedGeneration": 1, "lastTransitionTime": "2026-01-01T00:00:00Z",
        }],
        "listeners": [{ "protocol": "TCP", "port": 65535, "bound": false, "message": "busy" }],
    }});
    edges
        .patch_status("fsn1", &PatchParams::default(), &Patch::Merge(&status))
        .await
        .unwrap();
    let read = edges.get("fsn1").await.unwrap();
    let status = read.status.unwrap();
    assert_eq!(status.gateway_endpoint_id.as_deref(), Some("op"));
    assert_eq!(status.conditions[0].type_, "Accepted");
    assert_eq!(status.listeners[0].port, 65535);
    assert_eq!(status.listeners[0].message.as_deref(), Some("busy"));

    // Lists left out come back empty.
    let bare: Edge = create(
        &edges,
        json!({
            "apiVersion": "gateway.fables-for-robots.ch/v1alpha1",
            "kind": "Edge",
            "metadata": { "name": "bare", "namespace": "default" },
            "spec": { "endpointId": "k", "gatewayRef": { "name": "public" } },
        }),
    )
    .await;
    assert!(bare.spec.public_addresses.is_empty());
    assert_eq!(bare.spec.address, None);
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn identity_secret_is_created_once_and_reused() {
    let env = Envtest::start().await;
    let a = identity::load_or_create(&env.client, IDENTITY_NS, IDENTITY)
        .await
        .unwrap();
    let secret: Secret = get(&env.client, IDENTITY_NS, IDENTITY).await;
    let b = identity::load_or_create(&env.client, IDENTITY_NS, IDENTITY)
        .await
        .unwrap();
    assert_eq!(a.public(), b.public());
    assert_eq!(secret.type_.as_deref(), Some("Opaque"));
    let data = secret.data.clone().unwrap();
    assert_eq!(data.keys().collect::<Vec<_>>(), ["secret-key"]);
    let value = std::str::from_utf8(&data["secret-key"].0).unwrap();
    assert_eq!(value.len(), 64);
    assert!(
        value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(value, hex::encode(a.to_bytes()));
    let again: Secret = get(&env.client, IDENTITY_NS, IDENTITY).await;
    assert_eq!(again.resource_version(), secret.resource_version());
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn malformed_identity_secret_is_an_error() {
    let env = Envtest::start().await;
    let mut secret = Secret::default();
    secret.metadata.name = Some(IDENTITY.into());
    secret.data = Some([("secret-key".to_owned(), ByteString(b"abcd".to_vec()))].into());
    let secrets = api::<Secret>(&env.client, IDENTITY_NS);
    let before = secrets
        .create(&PostParams::default(), &secret)
        .await
        .unwrap();
    let error = identity::load_or_create(&env.client, IDENTITY_NS, IDENTITY)
        .await
        .unwrap_err();
    assert!(!format!("{error:#}").contains("abcd"), "{error:#}");
    let after: Secret = get(&env.client, IDENTITY_NS, IDENTITY).await;
    assert_eq!(after.resource_version(), before.resource_version());
    assert_eq!(after.data, before.data);
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn gateway_route_and_edge_become_programmed() {
    let env = Envtest::start().await;
    let operator = Operator::start(&env.client, &[NS]).await;
    let edge = operator.edge().await;
    let port = free_tcp_port();
    world(&env, &edge, port).await;
    let svc: Service = get(&env.client, NS, "db").await;
    assert!(
        svc.spec
            .and_then(|s| s.cluster_ip)
            .is_some_and(|ip| ip.starts_with("10.0.0.")),
        "the API server assigns a cluster IP"
    );
    programmed(&env.client, &operator, port).await;
    operator.stop().await;
    edge.shutdown().await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn deleting_the_route_closes_the_port() {
    let env = Envtest::start().await;
    let operator = Operator::start(&env.client, &[NS]).await;
    let edge = operator.edge().await;
    let port = free_tcp_port();
    world(&env, &edge, port).await;
    programmed(&env.client, &operator, port).await;

    api::<TcpRoute>(&env.client, NS)
        .delete("db", &DeleteParams::default())
        .await
        .unwrap();
    eventually("listener without routes", || async {
        let gw: Gateway = get(&env.client, NS, "public").await;
        let status = gw.status.unwrap_or_default();
        has(
            &status.conditions.unwrap_or_default(),
            &[("Accepted", "True")],
        )?;
        let listeners = status.listeners.unwrap_or_default();
        match listeners.as_slice() {
            [l] if l.attached_routes == 0 => Ok(()),
            other => Err(format!("listeners {other:?}")),
        }
    })
    .await;
    refused(port).await;
    operator.stop().await;
    edge.shutdown().await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn gateway_outside_the_allowed_namespaces_is_refused() {
    let env = Envtest::start().await;
    let operator = Operator::start(&env.client, &[NS]).await;
    let edge = operator.edge().await;
    let port = free_tcp_port();
    env.namespace("other").await;
    class(&env.client).await;
    gateway(&env.client, "other", port).await;
    edge_object(&env.client, "other", &edge).await;

    eventually("Gateway refused", || async {
        let gw: Gateway = get(&env.client, "other", "public").await;
        let conditions = gw.status.and_then(|s| s.conditions).unwrap_or_default();
        match condition(&conditions, "Accepted") {
            Some(c) if c.status == "False" && c.reason == "NamespaceNotAllowed" => Ok(()),
            _ => Err(format!("conditions {conditions:?}")),
        }
    })
    .await;
    // The edge was told nothing: give it time to open the port if it were going to.
    sleep(Duration::from_secs(1)).await;
    assert!(connects(port).await.is_err(), "port {port} opened");
    let e: Edge = get(&env.client, "other", "e1").await;
    let conditions = e.status.unwrap_or_default().conditions;
    has(
        &conditions,
        &[
            ("Accepted", "False"),
            ("Connected", "False"),
            ("Programmed", "False"),
        ],
    )
    .unwrap();
    operator.stop().await;
    edge.shutdown().await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn foreign_route_parent_status_is_left_alone() {
    let env = Envtest::start().await;
    let operator = Operator::start(&env.client, &[NS]).await;
    let edge = operator.edge().await;
    let port = free_tcp_port();
    world(&env, &edge, port).await;
    programmed(&env.client, &operator, port).await;

    // Another controller adds its entry beside ours.
    let routes = api::<TcpRoute>(&env.client, NS);
    let foreign = json!({
        "controllerName": OTHER_CONTROLLER,
        // As the API server stores it: the upstream schema fills in group and kind.
        "parentRef": {
            "group": "gateway.networking.k8s.io",
            "kind": "Gateway",
            "name": "elsewhere",
        },
        "conditions": [{
            "type": "Accepted", "status": "False", "reason": "NotMine", "message": "theirs",
            "observedGeneration": 1, "lastTransitionTime": "2026-01-01T00:00:00Z",
        }],
    });
    eventually("foreign entry written", || async {
        let route = routes.get("db").await.unwrap();
        let mut parents =
            serde_json::to_value(route.status.map(|s| s.parents).unwrap_or_default()).unwrap();
        parents.as_array_mut().unwrap().push(foreign.clone());
        let patch = json!({
            "metadata": { "resourceVersion": route.metadata.resource_version },
            "status": { "parents": parents },
        });
        routes
            .patch_status("db", &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map(drop)
            .map_err(|e| e.to_string())
    })
    .await;

    // A spec change makes us rewrite our entry with the new generation.
    let spec = json!({ "spec": {
        "rules": [{ "backendRefs": [{ "name": "db", "port": 5432, "weight": 2 }] }],
    }});
    let changed = routes
        .patch("db", &PatchParams::default(), &Patch::Merge(&spec))
        .await
        .unwrap();
    let generation = changed.metadata.generation.unwrap();
    assert!(generation > 1);
    eventually("our entry rewritten beside theirs", || async {
        let route = routes.get("db").await.unwrap();
        let parents = route.status.map(|s| s.parents).unwrap_or_default();
        let [ours, theirs] = parents.as_slice() else {
            return Err(format!("parents {parents:?}"));
        };
        if ours.controller_name != CONTROLLER
            || ours
                .conditions
                .iter()
                .any(|c| c.observed_generation != Some(generation))
        {
            return Err(format!("our entry {ours:?}"));
        }
        let theirs = serde_json::to_value(theirs).unwrap();
        if theirs != foreign {
            return Err(format!("their entry {theirs}"));
        }
        Ok(())
    })
    .await;
    operator.stop().await;
    edge.shutdown().await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn status_is_not_rewritten_when_nothing_changed() {
    let env = Envtest::start().await;
    let operator = Operator::start(&env.client, &[NS]).await;
    let edge = operator.edge().await;
    let port = free_tcp_port();
    world(&env, &edge, port).await;
    programmed(&env.client, &operator, port).await;
    // Let writes that were already under way land.
    sleep(Duration::from_secs(1)).await;

    let versions = || async {
        let gw: Gateway = get(&env.client, NS, "public").await;
        let route: TcpRoute = get(&env.client, NS, "db").await;
        let edge: Edge = get(&env.client, NS, "e1").await;
        let class: GatewayClass = Api::all(env.client.clone()).get("iroh").await.unwrap();
        [
            gw.resource_version(),
            route.resource_version(),
            edge.resource_version(),
            class.resource_version(),
        ]
    };
    let before = versions().await;
    sleep(Duration::from_secs(2)).await;
    assert_eq!(versions().await, before);
    operator.stop().await;
    edge.shutdown().await;
}

/// An Edge object `name` in `NS` with a fresh endpoint id; `spec` is merged into its spec.
async fn edge_with(client: &Client, name: &str, spec: Value) {
    let mut object = json!({
        "apiVersion": "gateway.fables-for-robots.ch/v1alpha1",
        "kind": "Edge",
        "metadata": { "name": name, "namespace": NS },
        "spec": {
            "endpointId": SecretKey::generate().public().to_string(),
            "gatewayRef": { "name": "public" },
        },
    });
    for (k, v) in spec.as_object().unwrap() {
        object["spec"][k] = v.clone();
    }
    create::<Edge>(&api(client, NS), object).await;
}

/// The Gateway's addresses as (type, value), once it has status from us.
async fn gateway_addresses(client: &Client) -> Result<Vec<(String, String)>, String> {
    let gw: Gateway = get(client, NS, "public").await;
    let status = gw.status.unwrap_or_default();
    has(
        &status.conditions.unwrap_or_default(),
        &[("Accepted", "True")],
    )?;
    Ok(status
        .addresses
        .unwrap_or_default()
        .into_iter()
        .map(|a| (a.r#type.unwrap_or_default(), a.value))
        .collect())
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn mixed_case_and_trailing_dot_addresses_do_not_break_status() {
    let env = Envtest::start().await;
    let operator = Operator::start(&env.client, &[NS]).await;
    env.namespace(NS).await;
    class(&env.client).await;
    gateway(&env.client, NS, free_tcp_port()).await;
    // Nothing listens there: the link only fails to connect, on loopback.
    let nowhere = free_tcp_port();
    edge_with(
        &env.client,
        "e1",
        json!({ "address": format!("Edge.Example.COM.:{nowhere}") }),
    )
    .await;
    let addresses = eventually("the Gateway's addresses", || async {
        match gateway_addresses(&env.client).await? {
            a if a.is_empty() => Err("no addresses yet".to_owned()),
            a => Ok(a),
        }
    })
    .await;
    assert_eq!(
        addresses,
        [("Hostname".to_owned(), "edge.example.com".to_owned())]
    );
    operator.stop().await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn seventeen_edges_give_sixteen_addresses() {
    let env = Envtest::start().await;
    let operator = Operator::start(&env.client, &[NS]).await;
    env.namespace(NS).await;
    class(&env.client).await;
    gateway(&env.client, NS, free_tcp_port()).await;
    let nowhere = free_tcp_port();
    for n in 1..=17 {
        // Published only, never dialled; the links dial loopback, where nothing answers.
        edge_with(
            &env.client,
            &format!("e{n:02}"),
            json!({
                "address": format!("127.0.0.1:{nowhere}"),
                "publicAddresses": [format!("198.51.100.{n}")],
            }),
        )
        .await;
    }
    let addresses = eventually("16 addresses", || async {
        match gateway_addresses(&env.client).await? {
            a if a.len() == 16 => Ok(a),
            a => Err(format!("{} addresses", a.len())),
        }
    })
    .await;
    assert!(addresses.iter().all(|(t, _)| t == "IPAddress"));
    // The first 16 after sorting: "198.51.100.9" sorts last.
    assert!(!addresses.iter().any(|(_, v)| v == "198.51.100.9"));
    let gw: Gateway = get(&env.client, NS, "public").await;
    let conditions = gw.status.unwrap().conditions.unwrap();
    let accepted = condition(&conditions, "Accepted").unwrap();
    assert!(
        accepted
            .message
            .contains("1 of the edges' addresses is not listed"),
        "{accepted:?}"
    );
    operator.stop().await;
}

/// Gateway `public` in `NS` of class `iroh` with `listeners`.
async fn gateway_with(client: &Client, listeners: Value) {
    create::<Gateway>(
        &api(client, NS),
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "public", "namespace": NS },
            "spec": { "gatewayClassName": "iroh", "listeners": listeners },
        }),
    )
    .await;
}

/// Service `web` in `NS`, on port 80.
async fn web_service(client: &Client) {
    create::<Service>(
        &api(client, NS),
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "web", "namespace": NS },
            "spec": { "ports": [{ "port": 80 }] },
        }),
    )
    .await;
}

/// Rules that send everything to Service `web`.
fn web_rules() -> Value {
    json!([{ "backendRefs": [{ "name": "web", "port": 80 }] }])
}

/// HTTPRoute `web` in `NS`, attached to Gateway `public`, with `rules`.
async fn http_route(client: &Client, rules: Value) {
    create::<HttpRoute>(
        &api(client, NS),
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "web", "namespace": NS },
            "spec": { "parentRefs": [{ "name": "public" }], "rules": rules },
        }),
    )
    .await;
}

/// GatewayClass, namespace `gw`, Gateway `public` with one HTTP listener `web` on `port`,
/// Service `web`, HTTPRoute `web` with `rules` and an Edge for `edge`.
async fn http_world(env: &Envtest, edge: &EdgeHandle, port: u16, rules: Value) {
    let client = &env.client;
    env.namespace(NS).await;
    class(client).await;
    gateway_with(
        client,
        json!([{ "name": "web", "port": port, "protocol": "HTTP" }]),
    )
    .await;
    web_service(client).await;
    http_route(client, rules).await;
    edge_object(client, NS, edge).await;
}

/// Ok when condition `type_` has `status` and `reason`.
fn has_reason(
    conditions: &[Condition],
    type_: &str,
    status: &str,
    reason: &str,
) -> Result<(), String> {
    match condition(conditions, type_) {
        Some(c) if c.status == status && c.reason == reason => Ok(()),
        _ => Err(format!(
            "wanted {type_}={status} {reason} in {conditions:?}"
        )),
    }
}

/// Listener `name` of Gateway `public`, once the Gateway is accepted.
async fn listener(client: &Client, name: &str) -> Result<GatewayStatusListeners, String> {
    let gw: Gateway = get(client, NS, "public").await;
    let status = gw.status.unwrap_or_default();
    has(
        &status.conditions.unwrap_or_default(),
        &[("Accepted", "True")],
    )?;
    let listeners = status.listeners.unwrap_or_default();
    listeners
        .iter()
        .find(|l| l.name == name)
        .cloned()
        .ok_or_else(|| format!("no listener {name} in {listeners:?}"))
}

/// Ok when listener `name` has `attached` routes, supports exactly the route `kind` and has the
/// `wanted` conditions.
async fn listener_is(
    client: &Client,
    name: &str,
    attached: i32,
    kind: &str,
    wanted: &[(&str, &str)],
) -> Result<(), String> {
    let l = listener(client, name).await?;
    if l.attached_routes != attached {
        return Err(format!("attachedRoutes {} of {name}", l.attached_routes));
    }
    let kinds: Vec<(Option<String>, String)> = l
        .supported_kinds
        .unwrap_or_default()
        .into_iter()
        .map(|k| (k.group, k.kind))
        .collect();
    if kinds
        != [(
            Some("gateway.networking.k8s.io".to_owned()),
            kind.to_owned(),
        )]
    {
        return Err(format!("supportedKinds {kinds:?} of {name}"));
    }
    has(&l.conditions, wanted)
}

/// The conditions of our only parent entry of HTTPRoute `web`.
async fn http_route_parent(client: &Client) -> Result<Vec<Condition>, String> {
    let route: HttpRoute = get(client, NS, "web").await;
    let parents = route.status.map(|s| s.parents).unwrap_or_default();
    let [parent] = parents.as_slice() else {
        return Err(format!("parents {parents:?}"));
    };
    if parent.controller_name != CONTROLLER {
        return Err(format!("controllerName {}", parent.controller_name));
    }
    if parent.parent_ref.name != "public" {
        return Err(format!("parentRef {:?}", parent.parent_ref));
    }
    Ok(parent.conditions.clone())
}

/// Ok once `port` refuses connections.
async fn closed(port: u16) -> Result<(), String> {
    match connects(port).await {
        Ok(()) => Err(format!("port {port} accepts")),
        Err(_) => Ok(()),
    }
}

/// Waits until the HTTP listener `web` on `port` and HTTPRoute `web` are accepted and
/// programmed, and the port serves.
async fn http_programmed(client: &Client, port: u16) {
    eventually("HTTP listener programmed", || async {
        let gw: Gateway = get(client, NS, "public").await;
        has(
            &gw.status.and_then(|s| s.conditions).unwrap_or_default(),
            &[("Accepted", "True"), ("Programmed", "True")],
        )?;
        listener_is(
            client,
            "web",
            1,
            "HTTPRoute",
            &[
                ("Accepted", "True"),
                ("ResolvedRefs", "True"),
                ("Programmed", "True"),
            ],
        )
        .await
    })
    .await;
    eventually("HTTPRoute parent accepted", || async {
        has(
            &http_route_parent(client).await?,
            &[("Accepted", "True"), ("ResolvedRefs", "True")],
        )
    })
    .await;
    eventually("the HTTP port accepts", || connects(port)).await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn http_route_and_gateway_become_programmed() {
    let env = Envtest::start().await;
    let operator = Operator::start(&env.client, &[NS]).await;
    let edge = operator.edge().await;
    let port = free_tcp_port();
    http_world(&env, &edge, port, web_rules()).await;
    http_programmed(&env.client, port).await;
    eventually("Edge programmed", || async {
        let e: Edge = get(&env.client, NS, "e1").await;
        has(
            &e.status.unwrap_or_default().conditions,
            &[("Connected", "True"), ("Programmed", "True")],
        )
    })
    .await;
    operator.stop().await;
    edge.shutdown().await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn deleting_the_http_route_closes_the_port() {
    let env = Envtest::start().await;
    let operator = Operator::start(&env.client, &[NS]).await;
    let edge = operator.edge().await;
    let port = free_tcp_port();
    http_world(&env, &edge, port, web_rules()).await;
    http_programmed(&env.client, port).await;

    api::<HttpRoute>(&env.client, NS)
        .delete("web", &DeleteParams::default())
        .await
        .unwrap();
    eventually("HTTP listener without routes", || async {
        listener_is(&env.client, "web", 0, "HTTPRoute", &[("Accepted", "True")]).await
    })
    .await;
    eventually("the HTTP port closed", || closed(port)).await;
    operator.stop().await;
    edge.shutdown().await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn unsupported_http_route_is_refused_with_a_reason() {
    let env = Envtest::start().await;
    let operator = Operator::start(&env.client, &[NS]).await;
    let edge = operator.edge().await;
    let port = free_tcp_port();
    let rules = json!([{
        "filters": [{
            "type": "URLRewrite",
            "urlRewrite": { "hostname": "elsewhere.example.com" },
        }],
        "backendRefs": [{ "name": "web", "port": 80 }],
    }]);
    http_world(&env, &edge, port, rules).await;

    eventually("HTTPRoute refused", || async {
        let conditions = http_route_parent(&env.client).await?;
        has_reason(&conditions, "Accepted", "False", "UnsupportedValue")
    })
    .await;
    eventually("HTTP listener without routes", || async {
        listener_is(&env.client, "web", 0, "HTTPRoute", &[("Accepted", "True")]).await
    })
    .await;
    // The edge was told nothing: give it time to open the port if it were going to.
    sleep(Duration::from_secs(1)).await;
    assert!(connects(port).await.is_err(), "port {port} opened");
    operator.stop().await;
    edge.shutdown().await;
}

/// Two different free ports, in no particular order.
fn two_free_ports() -> (u16, u16) {
    let a = free_tcp_port();
    loop {
        let b = free_tcp_port();
        if b != a {
            return (a, b);
        }
    }
}

/// A fresh self-signed certificate for `app.example.com` and its private key, as PEM.
fn tls_pair() -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["app.example.com".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert.pem(), key.serialize_pem())
}

/// Secret `name` in `NS` of `type_` with `tls.crt` and `tls.key`.
async fn tls_secret(client: &Client, name: &str, type_: &str, crt: &str, key: &str) {
    create::<Secret>(
        &api(client, NS),
        json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": name, "namespace": NS },
            "type": type_,
            "stringData": { "tls.crt": crt, "tls.key": key },
        }),
    )
    .await;
}

/// Replaces `tls.crt` and `tls.key` of Secret `name` in `NS`.
async fn replace_tls(client: &Client, name: &str, crt: &str, key: &str) {
    let patch = json!({ "stringData": { "tls.crt": crt, "tls.key": key } });
    api::<Secret>(client, NS)
        .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .unwrap();
}

/// An HTTPS listener `name` on `port` with the certificate of Secret `secret`.
fn https_listener(name: &str, port: u16, secret: &str) -> Value {
    json!({
        "name": name,
        "port": port,
        "protocol": "HTTPS",
        "tls": { "mode": "Terminate", "certificateRefs": [{ "name": secret }] },
    })
}

/// Every condition message of Gateway gw/public and of its listeners.
async fn gateway_messages(client: &Client) -> Vec<String> {
    let gw: Gateway = get(client, NS, "public").await;
    let status = gw.status.unwrap_or_default();
    let listeners = status.listeners.unwrap_or_default();
    status
        .conditions
        .unwrap_or_default()
        .iter()
        .chain(listeners.iter().flat_map(|l| &l.conditions))
        .map(|c| c.message.clone())
        .collect()
}

/// Asserts that no condition message of gw/public or its listeners contains any of `secrets`
/// or a PEM marker.
async fn no_secret_in_gateway_status(client: &Client, secrets: &[&str]) {
    let messages = gateway_messages(client).await;
    assert!(!messages.is_empty());
    for m in &messages {
        assert!(!m.contains("-----") && !m.contains("PRIVATE KEY"), "{m}");
        for s in secrets {
            assert!(!m.contains(s), "{m}");
        }
    }
}

/// The base64 lines of a PEM text: every line that is not a marker.
fn pem_lines(pem: &str) -> Vec<&str> {
    pem.lines()
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect()
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn https_listener_follows_its_secret() {
    let env = Envtest::start().await;
    let client = &env.client;
    let operator = Operator::start(client, &[NS]).await;
    let edge = operator.edge().await;
    let port = free_tcp_port();
    env.namespace(NS).await;
    class(client).await;
    let (crt, key) = tls_pair();
    tls_secret(client, "site-tls", "kubernetes.io/tls", &crt, &key).await;
    gateway_with(client, json!([https_listener("web", port, "site-tls")])).await;
    web_service(client).await;
    http_route(client, web_rules()).await;
    edge_object(client, NS, &edge).await;

    let valid = &[
        ("Accepted", "True"),
        ("ResolvedRefs", "True"),
        ("Programmed", "True"),
    ];
    eventually("HTTPS listener programmed", || {
        listener_is(client, "web", 1, "HTTPRoute", valid)
    })
    .await;
    eventually("the HTTPS port accepts", || connects(port)).await;
    no_secret_in_gateway_status(client, &pem_lines(&key)).await;

    let (garbage_crt, garbage_key) = ("garbage-crt-q8x2v7", "garbage-key-q8x2v7");
    replace_tls(client, "site-tls", garbage_crt, garbage_key).await;
    eventually("HTTPS listener refused", || async {
        let l = listener(client, "web").await?;
        has_reason(
            &l.conditions,
            "ResolvedRefs",
            "False",
            "InvalidCertificateRef",
        )?;
        has(&l.conditions, &[("Programmed", "False")])
    })
    .await;
    eventually("the HTTPS port closed", || closed(port)).await;
    no_secret_in_gateway_status(client, &[garbage_crt, garbage_key, "q8x2v7"]).await;

    let (crt, key) = tls_pair();
    replace_tls(client, "site-tls", &crt, &key).await;
    eventually("HTTPS listener programmed again", || {
        listener_is(client, "web", 1, "HTTPRoute", valid)
    })
    .await;
    eventually("the HTTPS port accepts again", || connects(port)).await;
    no_secret_in_gateway_status(client, &pem_lines(&key)).await;
    operator.stop().await;
    edge.shutdown().await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn secret_of_another_type_is_not_read() {
    let env = Envtest::start().await;
    let client = &env.client;
    let operator = Operator::start(client, &[NS]).await;
    env.namespace(NS).await;
    class(client).await;
    let (crt, key) = tls_pair();
    tls_secret(client, "site-tls", "Opaque", &crt, &key).await;
    let (opaque_port, marker_port) = two_free_ports();
    gateway_with(
        client,
        json!([
            https_listener("opaque", opaque_port, "site-tls"),
            https_listener("marker", marker_port, "marker-tls"),
        ]),
    )
    .await;
    let not_found = |l: GatewayStatusListeners| {
        has_reason(
            &l.conditions,
            "ResolvedRefs",
            "False",
            "InvalidCertificateRef",
        )?;
        let c = condition(&l.conditions, "ResolvedRefs").unwrap();
        if c.message != "secret gw/site-tls not found" {
            return Err(format!("message {:?}", c.message));
        }
        Ok(())
    };
    eventually("the Opaque Secret not found", || async {
        not_found(listener(client, "opaque").await?)
    })
    .await;

    // A TLS Secret created after the Opaque one is seen, and the Opaque one still is not.
    tls_secret(client, "marker-tls", "kubernetes.io/tls", &crt, &key).await;
    eventually("the TLS Secret found", || async {
        let l = listener(client, "marker").await?;
        has(&l.conditions, &[("ResolvedRefs", "True")])
    })
    .await;
    not_found(listener(client, "opaque").await.unwrap()).unwrap();
    operator.stop().await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn http_route_status_is_not_rewritten_when_nothing_changed() {
    let env = Envtest::start().await;
    let client = &env.client;
    let operator = Operator::start(client, &[NS]).await;
    let edge = operator.edge().await;
    let port = free_tcp_port();
    http_world(&env, &edge, port, web_rules()).await;
    http_programmed(client, port).await;
    // Let writes that were already under way land.
    sleep(Duration::from_secs(1)).await;

    let versions = || async {
        let gw: Gateway = get(client, NS, "public").await;
        let route: HttpRoute = get(client, NS, "web").await;
        let edge: Edge = get(client, NS, "e1").await;
        [
            gw.resource_version(),
            route.resource_version(),
            edge.resource_version(),
        ]
    };
    let before = versions().await;
    // Two changes the model does not depend on, so two passes that find nothing to write.
    for touched in ["1", "2"] {
        let annotate = json!({ "metadata": { "annotations": { "touched": touched } } });
        api::<Service>(client, NS)
            .patch("web", &PatchParams::default(), &Patch::Merge(&annotate))
            .await
            .unwrap();
        sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(versions().await, before);
    operator.stop().await;
    edge.shutdown().await;
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn tcp_and_http_listeners_work_side_by_side() {
    let env = Envtest::start().await;
    let client = &env.client;
    let operator = Operator::start(client, &[NS]).await;
    let edge = operator.edge().await;
    let (tcp_port, http_port) = two_free_ports();
    env.namespace(NS).await;
    class(client).await;
    gateway_with(
        client,
        json!([
            { "name": "db", "port": tcp_port, "protocol": "TCP" },
            { "name": "web", "port": http_port, "protocol": "HTTP" },
        ]),
    )
    .await;
    service(client).await;
    route(client).await;
    web_service(client).await;
    http_route(client, web_rules()).await;
    edge_object(client, NS, &edge).await;

    let programmed = &[
        ("Accepted", "True"),
        ("ResolvedRefs", "True"),
        ("Programmed", "True"),
    ];
    eventually("both listeners programmed", || async {
        listener_is(client, "db", 1, "TCPRoute", programmed).await?;
        listener_is(client, "web", 1, "HTTPRoute", programmed).await
    })
    .await;
    eventually("both routes accepted", || async {
        has(
            &http_route_parent(client).await?,
            &[("Accepted", "True"), ("ResolvedRefs", "True")],
        )?;
        let route: TcpRoute = get(client, NS, "db").await;
        let parents = route.status.map(|s| s.parents).unwrap_or_default();
        let [parent] = parents.as_slice() else {
            return Err(format!("TCPRoute parents {parents:?}"));
        };
        has(
            &parent.conditions,
            &[("Accepted", "True"), ("ResolvedRefs", "True")],
        )
    })
    .await;
    eventually("the TCP port accepts", || connects(tcp_port)).await;
    eventually("the HTTP port accepts", || connects(http_port)).await;
    operator.stop().await;
    edge.shutdown().await;
}

/// Kills the child when dropped, so a failed test leaves no process behind.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn run_serves_the_cluster_and_stops_on_sigterm() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let env = Envtest::start().await;
    let dir = short_dir();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_iroh-gateway-operator"));
    for (name, _) in std::env::vars_os() {
        let name_text = name.to_string_lossy();
        if name_text.starts_with("IROH_GATEWAY_") || name_text.starts_with("KUBERNETES_") {
            cmd.env_remove(&name);
        }
    }
    let mut child = cmd
        .env("KUBECONFIG", env.kubeconfig())
        .env("RUST_LOG", "info")
        .args([
            "run",
            "--namespace",
            IDENTITY_NS,
            "--gateway-namespaces",
            NS,
        ])
        .arg("--runtime-dir")
        .arg(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut child = Child(child);
    let (lines_tx, mut lines) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { return };
            if lines_tx.send(line).is_err() {
                return;
            }
        }
    });

    let started = tokio::time::timeout(CONVERGE, async {
        while let Some(line) = lines.recv().await {
            if line.contains("operator started") {
                return line;
            }
        }
        panic!("the operator ended before it started");
    })
    .await
    .expect("no \"operator started\" line");
    let secret: Secret = get(&env.client, IDENTITY_NS, IDENTITY).await;
    let hex_key = std::str::from_utf8(&secret.data.unwrap()["secret-key"].0)
        .unwrap()
        .to_owned();
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(&hex_key, &mut bytes).unwrap();
    let id = SecretKey::from_bytes(&bytes).public().to_string();
    assert!(started.contains(&id), "{started}");
    assert!(!started.contains(&hex_key), "the secret key was logged");

    class(&env.client).await;
    eventually("GatewayClass Accepted", || async {
        let class: GatewayClass = Api::all(env.client.clone()).get("iroh").await.unwrap();
        let conditions = class.status.and_then(|s| s.conditions).unwrap_or_default();
        has(&conditions, &[("Accepted", "True")])
    })
    .await;

    // HAProxy runs in a private directory the operator created inside --runtime-dir, and
    // nothing else is written there.
    let private = dir.path().join("haproxy");
    let mode = std::fs::metadata(&private)
        .unwrap_or_else(|e| panic!("{}: {e}", private.display()))
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "{mode:o}");
    assert!(private.join("haproxy.cfg").is_file());
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, ["haproxy"]);

    kill(Pid::from_raw(child.0.id() as i32), Signal::SIGTERM).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "no exit after SIGTERM");
        sleep(Duration::from_millis(20)).await;
    };
    assert!(status.success(), "{status}");
}

/// GatewayClass `iroh`, Gateway `public` and TCPRoute `db` as the API server has them now.
async fn read_snapshot(client: &Client) -> Snapshot {
    Snapshot {
        gateway_classes: vec![Api::all(client.clone()).get("iroh").await.unwrap()],
        gateways: vec![get(client, NS, "public").await],
        tcp_routes: vec![get(client, NS, "db").await],
        ..Snapshot::default()
    }
}

fn settings() -> Settings {
    Settings {
        controller_name: CONTROLLER.into(),
        gateway_namespaces: [NS.to_owned()].into(),
        relay: Relay::Disabled,
    }
}

/// `writer`'s answer for the status `snapshot` asks for.
async fn write(writer: &mut StatusWriter, snapshot: &Snapshot) -> bool {
    let facts = Facts {
        operator_id: SecretKey::from_bytes(&[1; 32]).public(),
        haproxy: Ok(()),
        edges: Default::default(),
    };
    let desired = compute(&build(snapshot, &settings()), &facts);
    writer.write(&desired, snapshot).await
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn status_writer_reports_what_it_could_not_write() {
    let env = Envtest::start().await;
    let client = &env.client;
    env.namespace(NS).await;
    class(client).await;
    gateway(client, NS, 5432).await;
    route(client).await;
    let mut writer = StatusWriter::new(client.clone(), CONTROLLER.into());

    // Written, then unchanged: both count as written.
    let first = read_snapshot(client).await;
    assert!(write(&mut writer, &first).await);
    let written = read_snapshot(client).await;
    assert!(written.tcp_routes[0].status.is_some());
    assert!(write(&mut writer, &written).await);
    let again = read_snapshot(client).await;
    assert_eq!(
        again.gateways[0].resource_version(),
        written.gateways[0].resource_version()
    );

    // The route changed since `first`, whose route patch is now refused (409): a failure.
    let annotate = json!({ "metadata": { "annotations": { "touched": "yes" } } });
    api::<TcpRoute>(client, NS)
        .patch("db", &PatchParams::default(), &Patch::Merge(&annotate))
        .await
        .unwrap();
    assert!(!write(&mut writer, &first).await);

    // The Gateway was deleted since the snapshot (404): nothing left to write.
    let mut stale = read_snapshot(client).await;
    stale.gateways[0].status = None;
    api::<Gateway>(client, NS)
        .delete("public", &DeleteParams::default())
        .await
        .unwrap();
    assert!(write(&mut writer, &stale).await);
}

/// Every object in every `deploy/*.yaml`, in file name order, with the file it came from.
fn deploy_objects() -> Vec<(String, Value)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../deploy");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no manifests in {}", dir.display());
    let mut objects = Vec::new();
    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&file).unwrap();
        for document in serde_yaml::Deserializer::from_str(&text) {
            let value = Value::deserialize(document).unwrap_or_else(|e| panic!("{name}: {e}"));
            if !value.is_null() {
                objects.push((name.clone(), value));
            }
        }
    }
    objects
}

/// Applies one object with server-side apply; `dry_run` only validates and admits it.
async fn apply_object(client: &Client, file: &str, object: &Value, dry_run: bool) {
    let what = format!(
        "{file}: {} {}",
        object["kind"].as_str().unwrap_or("?"),
        object["metadata"]["name"].as_str().unwrap_or("?")
    );
    let obj: DynamicObject =
        serde_json::from_value(object.clone()).unwrap_or_else(|e| panic!("{what}: {e}"));
    let types = obj
        .types
        .clone()
        .unwrap_or_else(|| panic!("{what}: no kind"));
    let gvk = GroupVersionKind::try_from(&types).unwrap_or_else(|e| panic!("{what}: {e}"));
    let (resource, capabilities) = pinned_kind(client, &gvk)
        .await
        .unwrap_or_else(|e| panic!("{what}: the API server does not know the kind: {e}"));
    let api: Api<DynamicObject> = match (capabilities.scope, obj.metadata.namespace.as_deref()) {
        (Scope::Namespaced, Some(ns)) => Api::namespaced_with(client.clone(), ns, &resource),
        (Scope::Namespaced, None) => panic!("{what}: a namespaced kind without a namespace"),
        (Scope::Cluster, _) => Api::all_with(client.clone(), &resource),
    };
    let mut params = PatchParams::apply("deploy-manifest-test");
    if dry_run {
        params = params.dry_run();
    }
    let name = obj
        .metadata
        .name
        .clone()
        .unwrap_or_else(|| panic!("{what}: no name"));
    api.patch(&name, &params, &Patch::Apply(&obj))
        .await
        .unwrap_or_else(|e| panic!("{what}: rejected: {e}"));
}

#[tokio::test]
#[ignore = "needs KUBEBUILDER_ASSETS"]
async fn deploy_manifests_apply_cleanly() {
    let objects = deploy_objects();
    let env = Envtest::start().await;
    // The namespaces for real, so the namespaced objects have somewhere to go.
    let mut dry_run_count = 0;
    for (file, object) in objects.iter().filter(|(_, o)| o["kind"] == "Namespace") {
        apply_object(&env.client, file, object, false).await;
    }
    for (file, object) in objects.iter().filter(|(_, o)| o["kind"] != "Namespace") {
        apply_object(&env.client, file, object, true).await;
        dry_run_count += 1;
    }
    // The Deployment and the RBAC objects are among what was checked, not skipped.
    assert!(dry_run_count >= 6, "only {dry_run_count} objects checked");
    for kind in ["Deployment", "ClusterRole", "Role", "GatewayClass"] {
        assert!(
            objects.iter().any(|(_, o)| o["kind"] == kind),
            "no {kind} in deploy/"
        );
    }

    // Secrets: only the namespaced Role in iroh-gateway may grant them, the ClusterRole not at
    // all; `get` only for the identity Secret, `create` (which cannot name one), `list` and
    // `watch` of the namespace's Secrets for TLS certificates (which cannot be limited to a type)
    // and nothing else.
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    let mut secret_verbs = Vec::new();
    for (file, object) in objects.iter().filter(|(f, _)| f == "rbac.yaml") {
        let kind = object["kind"].as_str().unwrap();
        for rule in object["rules"].as_array().into_iter().flatten() {
            let resources = strings(&rule["resources"]);
            let verbs = strings(&rule["verbs"]);
            let reaches_secrets = resources
                .iter()
                .any(|r| matches!(r.as_str(), "*" | "secrets") || r.starts_with("secrets/"));
            if reaches_secrets {
                assert_eq!(kind, "Role", "{file}: a {kind} rule reaches Secrets");
                assert_eq!(object["metadata"]["namespace"], "iroh-gateway", "{object}");
                assert_eq!(resources, ["secrets"], "{rule}");
                match verbs.as_slice() {
                    [v] if v == "get" => assert_eq!(
                        strings(&rule["resourceNames"]),
                        ["iroh-gateway-identity"],
                        "{rule}"
                    ),
                    [v] if v == "create" => assert!(rule.get("resourceNames").is_none(), "{rule}"),
                    [a, b] if a == "list" && b == "watch" => {
                        assert!(rule.get("resourceNames").is_none(), "{rule}")
                    }
                    other => panic!("{file}: Secret verbs {other:?} in {rule}"),
                }
                secret_verbs.extend(verbs.clone());
            }
            // Status is only ever patched.
            if resources.iter().any(|r| r.ends_with("/status")) {
                assert_eq!(verbs, ["patch"], "{file}: {rule}");
            }
        }
    }
    secret_verbs.sort();
    assert_eq!(secret_verbs, ["create", "get", "list", "watch"]);

    // The Gateway API: exactly the kinds the operator watches, and the status of those it writes.
    let cluster_role = objects
        .iter()
        .find(|(f, o)| f == "rbac.yaml" && o["kind"] == "ClusterRole")
        .map(|(_, o)| o)
        .unwrap();
    let gateway_rules: Vec<(Vec<String>, Vec<String>)> = cluster_role["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| strings(&r["apiGroups"]) == ["gateway.networking.k8s.io"])
        .map(|r| (strings(&r["resources"]), strings(&r["verbs"])))
        .collect();
    let owned = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        gateway_rules,
        [
            (
                owned(&["gatewayclasses", "gateways", "tcproutes", "httproutes"]),
                owned(&["get", "list", "watch"]),
            ),
            (
                owned(&[
                    "gatewayclasses/status",
                    "gateways/status",
                    "tcproutes/status",
                    "httproutes/status",
                ]),
                owned(&["patch"]),
            ),
        ]
    );
}
