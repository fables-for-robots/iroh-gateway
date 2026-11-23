//! The engine against a real HAProxy, real in-process edges and an echo backend on loopback.
#![cfg(unix)]

#[allow(dead_code)]
mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::*;
use iroh::{EndpointId, SecretKey};
use iroh_gateway_edge::{Edge, EdgeHandle};
use iroh_gateway_operator::engine::{Engine, EngineEvent, EngineOptions};
use iroh_gateway_operator::haproxy::SupervisorOptions;
use iroh_gateway_operator::haproxy::render::{Rendered, port_id, render};
use iroh_gateway_operator::model::{
    Backend, EdgeModel, GatewayModel, ListenerModel, Model, ObjRef,
};
use iroh_gateway_operator::status::Facts;
use iroh_gateway_operator::tunnel::{ListenerState, bind_endpoint};
use iroh_gateway_proto::transport::Relay;
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep, timeout, timeout_at};

const NS: &str = "ns";
/// What the HAProxy runtime directory gets instead of a valid configuration.
const INVALID_CFG: &str = "this is not an haproxy configuration\n";
/// The retry interval the engines in these tests use.
const RETRY: Duration = Duration::from_millis(300);

fn key(name: &str) -> ObjRef {
    ObjRef::new(NS, name)
}

/// The test world: one runtime directory, one echo backend, one operator key.
struct World {
    dir: TempDir,
    echo: SocketAddr,
    /// Gateways whose listeners go to a backend of their own instead of `echo`.
    backends: HashMap<&'static str, SocketAddr>,
    operator_key: SecretKey,
}

/// An edge in a render: its name, its gateway's name, and where it is.
struct EdgeSpec<'a> {
    name: &'a str,
    gateway: &'a str,
    endpoint_id: EndpointId,
    address: Option<String>,
}

fn at<'a>(name: &'a str, gateway: &'a str, edge: &EdgeHandle) -> EdgeSpec<'a> {
    EdgeSpec {
        name,
        gateway,
        endpoint_id: edge.endpoint_id(),
        address: Some(edge.iroh_addr().to_string()),
    }
}

impl World {
    async fn new() -> Self {
        Self {
            dir: short_dir(),
            echo: echo_server().await,
            backends: HashMap::new(),
            operator_key: SecretKey::generate(),
        }
    }

    /// A world in which each named gateway has a backend that writes the given tag first.
    async fn with_tagged(tags: &[(&'static str, &'static [u8])]) -> Self {
        let mut w = Self::new().await;
        for &(gateway, tag) in tags {
            w.backends.insert(gateway, tagged_echo(tag).await);
        }
        w
    }

    fn listener(&self, gateway: &str, port: u16) -> ListenerModel {
        let backend = self.backends.get(gateway).copied().unwrap_or(self.echo);
        ListenerModel {
            name: format!("l{port}"),
            port,
            protocol: "TCP".into(),
            accepted: Ok(()),
            conflicted: None,
            resolved_refs: Ok(()),
            supported_kinds: vec!["TCPRoute".into()],
            allowed_namespaces: Default::default(),
            attached_routes: 1,
            backends: vec![Backend {
                service: key("echo"),
                ip: "127.0.0.1".parse().unwrap(),
                port: backend.port(),
                weight: 1,
            }],
        }
    }

    /// A model of the given gateways (name, ports) and edges.
    fn model(&self, gateways: &[(&str, &[u16])], edges: &[EdgeSpec<'_>]) -> Model {
        Model {
            classes: vec![],
            gateways: gateways
                .iter()
                .map(|&(name, ports)| GatewayModel {
                    key: key(name),
                    generation: 1,
                    accepted: Ok(()),
                    listeners: ports.iter().map(|&p| self.listener(name, p)).collect(),
                    edges: edges
                        .iter()
                        .filter(|e| e.gateway == name)
                        .map(|e| key(e.name))
                        .collect(),
                    addresses: vec![],
                    addresses_dropped: 0,
                })
                .collect(),
            edges: edges
                .iter()
                .map(|e| EdgeModel {
                    key: key(e.name),
                    generation: 1,
                    accepted: Ok(()),
                    endpoint_id: Some(e.endpoint_id),
                    address: e.address.clone(),
                    gateway: Some(key(e.gateway)),
                    public_addresses: vec![],
                })
                .collect(),
            routes: vec![],
        }
    }

    fn plan(&self, gateways: &[(&str, &[u16])], edges: &[EdgeSpec<'_>]) -> Rendered {
        render(&self.model(gateways, edges), self.dir.path())
    }

    /// An edge on 127.0.0.1 with a tunnel grace of 300 ms, for this world's operator.
    async fn edge(&self) -> EdgeHandle {
        self.edge_with_key(SecretKey::generate()).await
    }

    async fn edge_with_key(&self, key: SecretKey) -> EdgeHandle {
        let opts = edge_options(
            self.operator_key.public(),
            key,
            "127.0.0.1:0".parse().unwrap(),
        );
        Edge::spawn(opts).await.unwrap()
    }

    fn options(&self) -> EngineOptions {
        let mut supervisor = SupervisorOptions::new(self.dir.path());
        supervisor.inherit_output = false;
        let mut opts = EngineOptions::new(supervisor, Relay::Disabled);
        opts.retry = RETRY;
        opts
    }

    async fn start(&self, initial: Rendered) -> Engine {
        let endpoint = bind_endpoint(self.operator_key.clone(), &Relay::Disabled)
            .await
            .unwrap();
        Engine::start(endpoint, self.options(), initial)
            .await
            .unwrap()
    }

    /// HAProxy's socket for `port` of gateway `gateway`.
    fn socket(&self, gateway: &str, port: u16) -> PathBuf {
        self.dir
            .path()
            .join("s")
            .join(format!("{}.sock", port_id(&key(gateway), port)))
    }
}

/// Writes `tag` on each connection, then echoes it until EOF.
async fn tagged_echo(tag: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                if stream.write_all(tag).await.is_err() {
                    return;
                }
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
                let _ = wr.shutdown().await;
            });
        }
    });
    addr
}

/// Connects to `port` and returns the tag the backend behind it writes first.
async fn tag_on(port: u16) -> Vec<u8> {
    let mut v = visitor(port).await;
    let mut tag = [0u8; 1];
    timeout(STEP, v.read_exact(&mut tag))
        .await
        .expect("no tag in time")
        .unwrap();
    tag.to_vec()
}

/// Waits for the next event and checks that it is `Changed`.
async fn changed(engine: &mut Engine) {
    match engine.next_event().await {
        EngineEvent::Changed => {}
        EngineEvent::HaproxyExited(status) => panic!("haproxy exited: {status}"),
    }
}

/// The Unix sockets left in `dir` and `dir/s`.
fn sockets_in(dir: &Path) -> Vec<PathBuf> {
    [dir.to_path_buf(), dir.join("s")]
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flat_map(|entries| entries.flatten())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
        .map(|e| e.path())
        .collect()
}

/// Whether `edge` is connected with exactly `ports` bound.
fn serving(f: &Facts, edge: &str, ports: &[u16]) -> bool {
    let want: Vec<ListenerState> = ports
        .iter()
        .map(|&p| ListenerState {
            key: tcp(p),
            bound: Ok(()),
        })
        .collect();
    f.edges
        .get(&key(edge))
        .is_some_and(|s| s.connected && s.listeners == want)
}

/// Waits, through `next_event()`, until the facts satisfy `pred`; panics after [`STEP`].
async fn wait_facts(engine: &mut Engine, pred: impl Fn(&Facts) -> bool) -> Facts {
    let deadline = Instant::now() + STEP;
    loop {
        let facts = engine.facts();
        if pred(&facts) {
            return facts;
        }
        if timeout_at(deadline, changed(engine)).await.is_err() {
            panic!("facts not reached within {STEP:?}; last: {facts:?}");
        }
    }
}

/// Connects to `port` and checks that a message echoes.
async fn echoes_on(port: u16, msg: &[u8]) {
    let mut v = visitor(port).await;
    echoes(&mut v, msg).await;
}

/// Asserts that connecting to `port` is refused for all of `period`.
async fn stays_refused(port: u16, period: Duration) {
    let end = Instant::now() + period;
    while Instant::now() < end {
        assert!(
            TcpStream::connect(("127.0.0.1", port)).await.is_err(),
            "port {port} accepts"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn bytes_flow_from_visitor_to_backend() {
    let w = World::new().await;
    let edge = w.edge().await;
    let p = free_tcp_port();
    let mut engine = w
        .start(w.plan(&[("gw", &[p])], &[at("e", "gw", &edge)]))
        .await;
    let facts = wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    assert_eq!(facts.haproxy, Ok(()));
    assert_eq!(facts.operator_id, w.operator_key.public());
    assert_eq!(facts.edges.len(), 1);

    echoes_on(p, b"hello").await;
    engine.shutdown().await;
    edge.shutdown().await;
}

#[tokio::test]
async fn adding_a_port_opens_it_after_haproxy_has_it() {
    let w = World::new().await;
    let edge = w.edge().await;
    let (p, q) = (free_tcp_port(), free_tcp_port());
    let mut engine = w
        .start(w.plan(&[("gw", &[p])], &[at("e", "gw", &edge)]))
        .await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;

    let q_socket = w.socket("gw", q);
    assert!(!q_socket.exists(), "q's socket exists before q is added");
    // Connects to q as fast as it can. At the first connect that succeeds, HAProxy's socket for
    // q must already exist, and a byte sent must come back through HAProxy.
    let watcher = tokio::spawn({
        let q_socket = q_socket.clone();
        async move {
            let deadline = Instant::now() + STEP;
            loop {
                if let Ok(v) = TcpStream::connect(("127.0.0.1", q)).await {
                    return (q_socket.exists(), v);
                }
                assert!(Instant::now() < deadline, "q never opened");
                tokio::task::yield_now().await;
            }
        }
    });
    engine
        .apply(w.plan(&[("gw", &[p, q])], &[at("e", "gw", &edge)]))
        .await;
    let (existed, mut first) = watcher.await.unwrap();
    assert!(
        existed,
        "the edge accepted on q before HAProxy's socket for q existed"
    );
    echoes(&mut first, b"q").await;
    let facts = wait_facts(&mut engine, |f| serving(f, "e", &[p, q])).await;
    assert_eq!(facts.haproxy, Ok(()));
    echoes_on(p, b"p").await;
    engine.shutdown().await;
    edge.shutdown().await;
}

#[tokio::test]
async fn removing_a_port_closes_it() {
    let w = World::new().await;
    let edge = w.edge().await;
    let (p, q) = (free_tcp_port(), free_tcp_port());
    let mut engine = w
        .start(w.plan(&[("gw", &[p, q])], &[at("e", "gw", &edge)]))
        .await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p, q])).await;
    echoes_on(q, b"q").await;

    engine
        .apply(w.plan(&[("gw", &[p])], &[at("e", "gw", &edge)]))
        .await;
    refused(q).await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    echoes_on(p, b"p").await;
    engine.shutdown().await;
    edge.shutdown().await;
}

#[tokio::test]
async fn removed_edge_loses_its_link() {
    let w = World::new().await;
    let edge = w.edge().await;
    let p = free_tcp_port();
    let mut engine = w
        .start(w.plan(&[("gw", &[p])], &[at("e", "gw", &edge)]))
        .await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    echoes_on(p, b"p").await;

    engine.apply(w.plan(&[("gw", &[p])], &[])).await;
    let facts = engine.facts();
    assert!(facts.edges.is_empty(), "{facts:?}");
    assert_eq!(facts.haproxy, Ok(()));
    // The edge keeps its listeners for its 300 ms grace once the tunnel is gone.
    sleep(Duration::from_millis(300)).await;
    refused(p).await;
    engine.shutdown().await;
    edge.shutdown().await;
}

#[tokio::test]
async fn changed_address_restarts_the_link() {
    let w = World::new().await;
    let edge_key = SecretKey::generate();
    let first = w.edge_with_key(edge_key.clone()).await;
    let p = free_tcp_port();
    let mut engine = w
        .start(w.plan(&[("gw", &[p])], &[at("e", "gw", &first)]))
        .await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    let (id, old_addr) = (first.endpoint_id(), first.iroh_addr());
    first.shutdown().await;
    wait_facts(&mut engine, |f| {
        f.edges.get(&key("e")).is_some_and(|s| !s.connected)
    })
    .await;

    // The same edge, moved to another iroh port. The old link only knows the old address.
    let second = w.edge_with_key(edge_key).await;
    assert_eq!(second.endpoint_id(), id);
    assert_ne!(second.iroh_addr(), old_addr);
    engine
        .apply(w.plan(&[("gw", &[p])], &[at("e", "gw", &second)]))
        .await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    echoes_on(p, b"moved").await;
    engine.shutdown().await;
    second.shutdown().await;
}

#[tokio::test]
async fn failed_haproxy_apply_adds_nothing_but_still_removes() {
    let w = World::new().await;
    let edge = w.edge().await;
    let (p, q, r) = (free_tcp_port(), free_tcp_port(), free_tcp_port());
    let mut engine = w
        .start(w.plan(&[("gw", &[p, q])], &[at("e", "gw", &edge)]))
        .await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p, q])).await;

    let mut bad = w.plan(&[("gw", &[p, r])], &[at("e", "gw", &edge)]);
    bad.haproxy_cfg = INVALID_CFG.into();
    engine.apply(bad).await;
    let facts = engine.facts();
    let err = facts.haproxy.clone().unwrap_err();
    assert!(err.contains("haproxy refused the configuration"), "{err}");
    refused(q).await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    stays_refused(r, Duration::from_millis(500)).await;
    assert!(!w.socket("gw", r).exists());
    echoes_on(p, b"p").await;
    engine.shutdown().await;
    edge.shutdown().await;
}

#[tokio::test]
async fn failed_haproxy_apply_still_drops_a_removed_edge() {
    let w = World::new().await;
    let (kept, dropped) = (w.edge().await, w.edge().await);
    let (p1, p2) = (free_tcp_port(), free_tcp_port());
    let gateways: &[(&str, &[u16])] = &[("gw1", &[p1]), ("gw2", &[p2])];
    let mut engine = w
        .start(w.plan(
            gateways,
            &[at("kept", "gw1", &kept), at("dropped", "gw2", &dropped)],
        ))
        .await;
    wait_facts(&mut engine, |f| {
        serving(f, "kept", &[p1]) && serving(f, "dropped", &[p2])
    })
    .await;
    echoes_on(p2, b"p2").await;

    let mut bad = w.plan(gateways, &[at("kept", "gw1", &kept)]);
    bad.haproxy_cfg = INVALID_CFG.into();
    engine.apply(bad).await;
    let facts = engine.facts();
    assert!(facts.haproxy.is_err());
    assert_eq!(
        facts.edges.keys().cloned().collect::<Vec<_>>(),
        vec![key("kept")]
    );
    sleep(Duration::from_millis(300)).await;
    refused(p2).await;
    echoes_on(p1, b"p1").await;
    engine.shutdown().await;
    kept.shutdown().await;
    dropped.shutdown().await;
}

#[tokio::test]
async fn changed_resolves_on_link_state_change() {
    let w = World::new().await;
    let edge = w.edge().await;
    let p = free_tcp_port();
    let mut engine = w
        .start(w.plan(&[("gw", &[p])], &[at("e", "gw", &edge)]))
        .await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    // Nothing changes while the link is up and nothing is applied.
    assert!(
        timeout(Duration::from_millis(500), changed(&mut engine))
            .await
            .is_err(),
        "next_event() resolved without a change: {:?}",
        engine.facts()
    );

    edge.shutdown().await;
    timeout(STEP, changed(&mut engine))
        .await
        .expect("next_event() did not resolve after the edge stopped");
    wait_facts(&mut engine, |f| {
        f.edges
            .get(&key("e"))
            .is_some_and(|s| !s.connected && s.last_error.is_some())
    })
    .await;
    engine.shutdown().await;
}

#[tokio::test]
async fn changed_is_cancel_safe() {
    let w = World::new().await;
    let edge = w.edge().await;
    let p = free_tcp_port();
    let mut engine = w
        .start(w.plan(&[("gw", &[p])], &[at("e", "gw", &edge)]))
        .await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    // A change that happens while no `next_event()` is being awaited, after one was dropped.
    assert!(
        timeout(Duration::from_millis(100), changed(&mut engine))
            .await
            .is_err()
    );
    edge.shutdown().await;
    sleep(Duration::from_millis(300)).await;
    timeout(Duration::from_millis(100), changed(&mut engine))
        .await
        .expect("a change made while no next_event() was awaited was lost");
    engine.shutdown().await;
}

#[tokio::test]
async fn shutdown_leaves_nothing_behind() {
    let w = World::new().await;
    let edge = w.edge().await;
    let p = free_tcp_port();
    let mut engine = w
        .start(w.plan(&[("gw", &[p])], &[at("e", "gw", &edge)]))
        .await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    let pid = Pid::from_raw(engine.haproxy_pid() as i32);
    assert_eq!(kill(pid, None), Ok(()));
    assert!(w.socket("gw", p).exists());

    engine.shutdown().await;
    assert_eq!(kill(pid, None), Err(Errno::ESRCH), "haproxy still runs");
    assert_eq!(sockets_in(w.dir.path()), Vec::<PathBuf>::new());
    // The link is gone: the edge closes its port after its grace.
    sleep(Duration::from_millis(300)).await;
    refused(p).await;
    edge.shutdown().await;
}

#[tokio::test]
async fn start_fails_and_leaves_nothing_when_haproxy_cannot_start() {
    let w = World::new().await;
    let edge = w.edge().await;
    let p = free_tcp_port();
    let mut initial = w.plan(&[("gw", &[p])], &[at("e", "gw", &edge)]);
    initial.haproxy_cfg = INVALID_CFG.into();
    let endpoint = bind_endpoint(w.operator_key.clone(), &Relay::Disabled)
        .await
        .unwrap();
    let err = Engine::start(endpoint, w.options(), initial)
        .await
        .err()
        .expect("start succeeded with an invalid configuration");
    assert!(
        format!("{err:#}").contains("invalid configuration"),
        "{err:#}"
    );
    assert_eq!(sockets_in(w.dir.path()), Vec::<PathBuf>::new());
    // No link was started: the edge never opens p.
    stays_refused(p, Duration::from_millis(500)).await;
    edge.shutdown().await;
}

#[tokio::test]
async fn failed_reload_is_retried() {
    let w = World::new().await;
    let p = free_tcp_port();
    let mut engine = w.start(w.plan(&[("gw", &[p])], &[])).await;
    // Without the master socket the reload cannot be sent: an I/O error.
    let master = w.dir.path().join("master.sock");
    let away = w.dir.path().join("master.away");
    std::fs::rename(&master, &away).unwrap();
    let q = free_tcp_port();
    engine.apply(w.plan(&[("gw", &[p, q])], &[])).await;
    assert!(engine.facts().haproxy.is_err());

    let failed_at = Instant::now();
    timeout(STEP, changed(&mut engine))
        .await
        .expect("no retry after a failed reload");
    let waited = failed_at.elapsed();
    assert!(waited >= RETRY - Duration::from_millis(50), "{waited:?}");

    std::fs::rename(&away, &master).unwrap();
    engine.apply(w.plan(&[("gw", &[p, q])], &[])).await;
    assert_eq!(engine.facts().haproxy, Ok(()));
    assert!(w.socket("gw", q).exists());
    // Succeeded: no retry is pending any more.
    assert!(timeout(RETRY * 3, changed(&mut engine)).await.is_err());
    engine.shutdown().await;
}

#[tokio::test]
async fn invalid_configuration_is_not_retried() {
    let w = World::new().await;
    let p = free_tcp_port();
    let mut engine = w.start(w.plan(&[("gw", &[p])], &[])).await;
    let mut bad = w.plan(&[("gw", &[p])], &[]);
    bad.haproxy_cfg = INVALID_CFG.into();
    engine.apply(bad).await;
    assert!(engine.facts().haproxy.is_err());
    assert!(timeout(RETRY * 3, changed(&mut engine)).await.is_err());
    // The last good configuration still serves.
    assert!(w.socket("gw", p).exists());
    engine.shutdown().await;
}

#[tokio::test]
async fn unreachable_edge_is_reported_not_linked() {
    let w = World::new().await;
    let edge = w.edge().await;
    let (p1, p2) = (free_tcp_port(), free_tcp_port());
    let nowhere = EdgeSpec {
        name: "nowhere",
        gateway: "gw2",
        endpoint_id: SecretKey::generate().public(),
        address: None,
    };
    let mut engine = w
        .start(w.plan(
            &[("gw1", &[p1]), ("gw2", &[p2])],
            &[at("e", "gw1", &edge), nowhere],
        ))
        .await;
    let facts = wait_facts(&mut engine, |f| serving(f, "e", &[p1])).await;
    assert_eq!(facts.haproxy, Ok(()));
    let state = &facts.edges[&key("nowhere")];
    assert!(!state.connected);
    let why = state.last_error.as_deref().unwrap();
    assert!(why.contains("cannot be reached"), "{why}");
    echoes_on(p1, b"p1").await;
    engine.shutdown().await;
    edge.shutdown().await;
}

#[tokio::test]
async fn haproxy_exit_is_an_event_while_links_are_watched() {
    let w = World::new().await;
    let edge = w.edge().await;
    let p = free_tcp_port();
    let mut engine = w
        .start(w.plan(&[("gw", &[p])], &[at("e", "gw", &edge)]))
        .await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;

    // Killed while `next_event()` waits, with a link to watch as well.
    let pid = Pid::from_raw(engine.haproxy_pid() as i32);
    let killer = tokio::spawn(async move {
        sleep(Duration::from_millis(200)).await;
        kill(pid, Signal::SIGKILL).unwrap();
    });
    let status = match timeout(STEP, engine.next_event()).await {
        Ok(EngineEvent::HaproxyExited(status)) => status,
        Ok(EngineEvent::Changed) => {
            panic!("Changed instead of HaproxyExited: {:?}", engine.facts())
        }
        Err(_) => panic!("next_event() did not resolve after haproxy was killed"),
    };
    killer.await.unwrap();
    assert!(!status.success());
    // And again at once, with the same status.
    match timeout(Duration::from_millis(100), engine.next_event()).await {
        Ok(EngineEvent::HaproxyExited(again)) => assert_eq!(again, status),
        other => panic!("not HaproxyExited again: {other:?}"),
    }
    engine.shutdown().await;
    assert_eq!(sockets_in(w.dir.path()), Vec::<PathBuf>::new());
    edge.shutdown().await;
}

#[tokio::test]
async fn moving_an_edge_to_another_gateway_reaches_its_backend() {
    let w = World::with_tagged(&[("gw1", b"A"), ("gw2", b"B")]).await;
    let edge = w.edge().await;
    let p = free_tcp_port();
    let gateways: &[(&str, &[u16])] = &[("gw1", &[p]), ("gw2", &[p])];
    let mut engine = w.start(w.plan(gateways, &[at("e", "gw1", &edge)])).await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    assert_eq!(tag_on(p).await, b"A");

    engine
        .apply(w.plan(gateways, &[at("e", "gw2", &edge)]))
        .await;
    assert_eq!(engine.facts().haproxy, Ok(()));
    assert_eq!(tag_on(p).await, b"B");
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    engine.shutdown().await;
    edge.shutdown().await;
}

#[tokio::test]
async fn failed_apply_that_changes_a_kept_ports_backend_closes_it() {
    let w = World::with_tagged(&[("gw", b"A")]).await;
    let other = tagged_echo(b"B").await;
    let edge = w.edge().await;
    let p = free_tcp_port();
    let mut engine = w
        .start(w.plan(&[("gw", &[p])], &[at("e", "gw", &edge)]))
        .await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    assert_eq!(tag_on(p).await, b"A");

    // The same gateway, port and socket, but another backend behind the socket.
    let mut model = w.model(&[("gw", &[p])], &[at("e", "gw", &edge)]);
    model.gateways[0].listeners[0].backends[0].port = other.port();
    let moved = render(&model, w.dir.path());
    let before = w.plan(&[("gw", &[p])], &[at("e", "gw", &edge)]);
    assert_eq!(
        moved.edges[0].sockets[&tcp(p)].socket,
        before.edges[0].sockets[&tcp(p)].socket
    );

    let mut bad = moved.clone();
    bad.haproxy_cfg = INVALID_CFG.into();
    engine.apply(bad).await;
    assert!(engine.facts().haproxy.is_err());
    refused(p).await;
    wait_facts(&mut engine, |f| serving(f, "e", &[])).await;

    engine.apply(moved).await;
    assert_eq!(engine.facts().haproxy, Ok(()));
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    assert_eq!(tag_on(p).await, b"B");
    engine.shutdown().await;
    edge.shutdown().await;
}

/// A stand-in for `haproxy` in `dir` that runs the real one, but makes `haproxy -c` take a
/// second while the file `<dir>/slow` exists.
fn slow_check_haproxy(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("slow-haproxy");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\n[ \"$1\" = \"-c\" ] && [ -e {} ] && sleep 1\nexec haproxy \"$@\"\n",
            dir.join("slow").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Whether a visitor on `port` is cut off instead of reaching a backend.
async fn cut_off(port: u16) -> bool {
    let Ok(mut v) = TcpStream::connect(("127.0.0.1", port)).await else {
        return true;
    };
    let mut tag = [0u8; 1];
    matches!(
        timeout(STEP, v.read(&mut tag))
            .await
            .expect("no answer in time"),
        Err(_) | Ok(0)
    )
}

#[tokio::test]
async fn ports_that_change_are_cut_while_haproxy_reloads() {
    let w = World::with_tagged(&[("gw", b"A")]).await;
    let other = tagged_echo(b"B").await;
    let tools = short_dir();
    let edge = w.edge().await;
    let (p, q) = (free_tcp_port(), free_tcp_port());
    let endpoint = bind_endpoint(w.operator_key.clone(), &Relay::Disabled)
        .await
        .unwrap();
    let mut opts = w.options();
    opts.supervisor.haproxy_bin = slow_check_haproxy(tools.path());
    let edges = [at("e", "gw", &edge)];
    let mut engine = Engine::start(endpoint, opts, w.plan(&[("gw", &[p, q])], &edges))
        .await
        .unwrap();
    wait_facts(&mut engine, |f| serving(f, "e", &[p, q])).await;
    assert_eq!(tag_on(q).await, b"A");

    // q gets another backend; p stays as it is.
    let mut model = w.model(&[("gw", &[p, q])], &edges);
    model.gateways[0].listeners[1].backends[0].port = other.port();
    std::fs::write(tools.path().join("slow"), "").unwrap();
    let during = async {
        // Well inside the second `haproxy -c` takes: the old configuration still runs.
        sleep(Duration::from_millis(400)).await;
        let q_cut = cut_off(q).await;
        let p_tag = tag_on(p).await;
        (q_cut, p_tag)
    };
    let ((), (q_cut, p_tag)) = tokio::join!(engine.apply(render(&model, w.dir.path())), during);
    assert!(
        q_cut,
        "a visitor on q reached the old backend during the reload"
    );
    assert_eq!(p_tag, b"A", "p stopped serving during the reload");
    assert_eq!(engine.facts().haproxy, Ok(()));
    assert_eq!(tag_on(q).await, b"B");
    assert_eq!(tag_on(p).await, b"A");
    engine.shutdown().await;
    edge.shutdown().await;
}

#[tokio::test]
async fn failed_apply_that_moves_an_edge_closes_its_port() {
    let w = World::with_tagged(&[("gw1", b"A"), ("gw2", b"B")]).await;
    let edge = w.edge().await;
    let p = free_tcp_port();
    let gateways: &[(&str, &[u16])] = &[("gw1", &[p]), ("gw2", &[p])];
    let mut engine = w.start(w.plan(gateways, &[at("e", "gw1", &edge)])).await;
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    assert_eq!(tag_on(p).await, b"A");

    // The same port, but of another gateway: not a port the old and the new plan share.
    let mut bad = w.plan(gateways, &[at("e", "gw2", &edge)]);
    bad.haproxy_cfg = INVALID_CFG.into();
    engine.apply(bad).await;
    assert!(engine.facts().haproxy.is_err());
    refused(p).await;
    wait_facts(&mut engine, |f| serving(f, "e", &[])).await;

    engine
        .apply(w.plan(gateways, &[at("e", "gw2", &edge)]))
        .await;
    assert_eq!(engine.facts().haproxy, Ok(()));
    wait_facts(&mut engine, |f| serving(f, "e", &[p])).await;
    assert_eq!(tag_on(p).await, b"B");
    engine.shutdown().await;
    edge.shutdown().await;
}
