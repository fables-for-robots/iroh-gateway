//! The operator's tunnel metrics, read from the `Metrics` its links report to while they run.

#[allow(dead_code)]
mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bytes::Bytes;
use common::*;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId, SecretKey};
use iroh_gateway_operator::metrics::Metrics;
use iroh_gateway_operator::tunnel::{
    LinkHandle, LinkOptions, UdpTarget, UdpTargets, bind_endpoint,
};
use iroh_gateway_proto::control::{Config, ListenerKey};
use iroh_gateway_proto::datagram::MAX_PACKET;
use iroh_gateway_proto::transport::Relay;
use iroh_gateway_proto::{RESET_BAD_HEADER, RESET_UNKNOWN_LISTENER};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::time::{Instant, sleep, timeout};

/// How often a waiting test reads the metrics again.
const POLL: Duration = Duration::from_millis(20);
/// How long a test waits for a packet before it sends again.
const RESEND: Duration = Duration::from_millis(500);

/// `name` labelled with `edge` and `labels`, in the order the text format has them: by name.
fn series(name: &str, edge: &str, labels: &[(&str, &str)]) -> String {
    let mut all = labels.to_vec();
    all.push(("edge", edge));
    all.sort();
    let all: Vec<String> = all.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
    format!("{name}{{{}}}", all.join(","))
}

fn value(m: &Metrics, series: &str) -> f64 {
    metric(&m.render(), series)
}

/// Waits until `series` satisfies `ok`; panics with the last text after `STEP`.
async fn wait_until(m: &Metrics, series: &str, ok: impl Fn(f64) -> bool) {
    let deadline = Instant::now() + STEP;
    loop {
        let text = m.render();
        if ok(metric(&text, series)) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{series} never got there:\n{text}"
        );
        sleep(POLL).await;
    }
}

async fn wait_for(m: &Metrics, series: &str, want: f64) {
    wait_until(m, series, |v| v == want).await;
}

/// Calls `send` until `series` is at least 1, again every [`RESEND`]; panics after `STEP`.
async fn until_counted(m: &Metrics, series: &str, send: impl Fn()) {
    let deadline = Instant::now() + STEP;
    loop {
        send();
        let attempt = Instant::now() + RESEND;
        while Instant::now() < attempt {
            if value(m, series) >= 1.0 {
                return;
            }
            sleep(POLL).await;
        }
        assert!(
            Instant::now() < deadline,
            "{series} never counted:\n{}",
            m.render()
        );
    }
}

fn next_packet_id() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// A rig whose link reports to a `Metrics` of its own, and that `Metrics`.
async fn metered_rig(
    targets: &[(u16, SocketAddr)],
    desired: &[u16],
    customize: impl FnOnce(&mut LinkOptions),
) -> (Rig, Metrics, String) {
    let m = Metrics::new();
    let rig = rig_with(targets, desired, |_, opts| {
        opts.metrics = m.clone();
        customize(opts);
    })
    .await;
    let e = rig.edge.endpoint_id().to_string();
    (rig, m, e)
}

/// A link to a hand-driven edge that has answered the link's first config.
struct Hand {
    link: LinkHandle,
    udp: watch::Sender<UdpTargets>,
    s: FakeSession,
    cfg: Config,
    m: Metrics,
    e: String,
    /// Held so the connections live.
    _endpoint: Endpoint,
    _fake: FakeEdge,
}

impl Hand {
    /// The id the first config gave `key`.
    fn id(&self, key: ListenerKey) -> u32 {
        listener_id(&self.cfg, key)
    }

    fn conn(&self) -> &Connection {
        &self.s.conn
    }
}

fn listener_id(cfg: &Config, key: ListenerKey) -> u32 {
    cfg.listeners
        .iter()
        .find(|l| l.key() == key)
        .unwrap_or_else(|| panic!("{key:?} is not in {cfg:?}"))
        .id
}

/// `tcp_ports` and then `udp_ports` desired, `targets` as the UDP table (weight 1 each).
async fn hand(
    tcp_ports: &[u16],
    udp_ports: &[u16],
    targets: &[(u16, SocketAddr)],
    customize: impl FnOnce(&mut LinkOptions),
) -> Hand {
    let m = Metrics::new();
    let fake = FakeEdge::bind().await;
    let e = fake.endpoint.id().to_string();
    let (link, _desired, udp, endpoint) = fake
        .link_with(&[], tcp_ports, targets, udp_ports, |opts| {
            opts.metrics = m.clone();
            customize(opts);
        })
        .await;
    let mut s = fake.accept().await;
    let cfg = s.read_config().await;
    s.reply(&cfg).await;
    wait_state(&link, |st| st.connected).await;
    Hand {
        link,
        udp,
        s,
        cfg,
        m,
        e,
        _endpoint: endpoint,
        _fake: fake,
    }
}

fn addr(socket: &UdpSocket) -> SocketAddr {
    socket.local_addr().unwrap()
}

/// Sends `payload` under `listener_id` and `flow_id` until `backend` receives it, and returns
/// where it came from.
async fn deliver(
    conn: &Connection,
    listener_id: u32,
    flow_id: u64,
    payload: &[u8],
    backend: &UdpSocket,
) -> SocketAddr {
    let mut buf = vec![0u8; MAX_PACKET];
    timeout(STEP, async {
        loop {
            send_packet(conn, listener_id, flow_id, next_packet_id(), payload);
            let arrived = timeout(RESEND, async {
                loop {
                    if let Ok((n, from)) = backend.recv_from(&mut buf).await
                        && &buf[..n] == payload
                    {
                        return from;
                    }
                }
            })
            .await;
            if let Ok(from) = arrived {
                return from;
            }
        }
    })
    .await
    .expect("the packet did not reach the backend")
}

#[tokio::test]
async fn a_link_reports_its_edge_up_and_its_listeners() {
    let echo = echo_server().await;
    let (p, q) = (free_tcp_port(), free_tcp_port());
    let (rig, m, e) = metered_rig(&[(p, echo), (q, echo)], &[p, q], |_| {}).await;
    wait_state(&rig.link, |s| s.connected && s.listeners.len() == 2).await;
    let text = m.render();
    assert_eq!(metric(&text, &series("tunnel_up", &e, &[])), 1.0);
    assert_eq!(
        metric(&text, &series("tunnel_sessions_total", &e, &[])),
        1.0
    );
    let bound = series("tunnel_listeners", &e, &[("state", "bound")]);
    let failed = series("tunnel_listeners", &e, &[("state", "failed")]);
    assert_eq!(metric(&text, &bound), 2.0);
    assert_eq!(metric(&text, &failed), 0.0);

    // A third port the edge cannot bind: something holds it.
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let r = held.local_addr().unwrap().port();
    rig.desired.send(vec![tcp(p), tcp(q), tcp(r)]).unwrap();
    wait_state(&rig.link, |s| {
        s.listeners.len() == 3 && s.listeners.iter().any(|l| l.bound.is_err())
    })
    .await;
    let text = m.render();
    assert_eq!(metric(&text, &bound), 2.0);
    assert_eq!(metric(&text, &failed), 1.0);
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
    drop(held);
}

#[tokio::test]
async fn a_lost_edge_reads_down() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let (rig, m, e) = metered_rig(&[(p, echo)], &[p], |opts| {
        opts.dial_timeout = Duration::from_millis(500);
    })
    .await;
    wait_state(&rig.link, |s| s.connected && s.listeners.len() == 1).await;
    assert_eq!(value(&m, &series("tunnel_up", &e, &[])), 1.0);

    rig.edge.shutdown().await;
    wait_for(&m, &series("tunnel_up", &e, &[]), 0.0).await;
    let text = m.render();
    for state in ["bound", "failed"] {
        let listeners = series("tunnel_listeners", &e, &[("state", state)]);
        assert_eq!(metric(&text, &listeners), 0.0, "{text}");
    }
    wait_until(&m, &series("tunnel_dial_failures_total", &e, &[]), |n| {
        n >= 1.0
    })
    .await;
    assert_eq!(value(&m, &series("tunnel_sessions_total", &e, &[])), 1.0);
    rig.link.shutdown().await;
}

#[tokio::test]
async fn streams_and_bytes_are_counted_as_they_move() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let (rig, m, e) = metered_rig(&[(p, echo)], &[p], |_| {}).await;
    wait_state(&rig.link, |s| s.connected && s.listeners.len() == 1).await;
    let mut v = visitor(p).await;
    echoes(&mut v, &[7; 5_000]).await;

    // The visitor is still connected.
    let bytes_in = series("tunnel_tcp_bytes_total", &e, &[("direction", "in")]);
    let bytes_out = series("tunnel_tcp_bytes_total", &e, &[("direction", "out")]);
    let open = series("tunnel_streams_open", &e, &[]);
    wait_for(&m, &bytes_in, 5_000.0).await;
    wait_for(&m, &bytes_out, 5_000.0).await;
    let text = m.render();
    assert_eq!(metric(&text, &open), 1.0);
    assert_eq!(metric(&text, &series("tunnel_streams_total", &e, &[])), 1.0);

    drop(v);
    wait_for(&m, &open, 0.0).await;
    assert_eq!(value(&m, &series("tunnel_streams_total", &e, &[])), 1.0);
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn bytes_of_a_stream_cut_off_by_tunnel_loss_stay_counted() {
    // Reads what comes and answers nothing.
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent = sink.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = sink.accept().await.unwrap();
        let mut buf = vec![0u8; 65_536];
        while let Ok(n) = stream.read(&mut buf).await
            && n > 0
        {}
    });
    let p = free_tcp_port();
    let (rig, m, e) = metered_rig(&[(p, silent)], &[p], |_| {}).await;
    wait_state(&rig.link, |s| s.connected && s.listeners.len() == 1).await;
    let mut v = visitor(p).await;
    v.write_all(&[3; 5_000]).await.unwrap();
    let bytes_in = series("tunnel_tcp_bytes_total", &e, &[("direction", "in")]);
    let open = series("tunnel_streams_open", &e, &[]);
    wait_for(&m, &bytes_in, 5_000.0).await;
    assert_eq!(value(&m, &open), 1.0);

    rig.edge.shutdown().await;
    wait_for(&m, &open, 0.0).await;
    assert_eq!(value(&m, &bytes_in), 5_000.0);
    rig.link.shutdown().await;
}

#[tokio::test]
async fn a_refused_stream_is_counted_by_reason() {
    let refused =
        |e: &str, reason| series("tunnel_streams_refused_total", e, &[("reason", reason)]);

    // Nothing listens on the target.
    let dead = SocketAddr::from(([127, 0, 0, 1], free_tcp_port()));
    let p = free_tcp_port();
    let (rig, m, e) = metered_rig(&[(p, dead)], &[p], |_| {}).await;
    wait_state(&rig.link, |s| s.connected && s.listeners.len() == 1).await;
    let mut v = visitor(p).await;
    v.write_all(b"anyone there?").await.unwrap();
    wait_for(&m, &refused(&e, "backend_unavailable"), 1.0).await;
    let text = m.render();
    assert_eq!(metric(&text, &refused(&e, "unknown_listener")), 0.0);
    assert_eq!(metric(&text, &refused(&e, "bad_header")), 0.0);
    rig.link.shutdown().await;
    rig.edge.shutdown().await;

    // A hand-driven edge names a listener id the link never issued, then sends no header.
    let t = hand(&[5300], &[], &[], |_| {}).await;
    let (_send, mut recv) = t.s.open(9999, 5300).await;
    assert_eq!(
        reset_code(&mut recv).await,
        u64::from(RESET_UNKNOWN_LISTENER)
    );
    wait_for(&t.m, &refused(&t.e, "unknown_listener"), 1.0).await;
    let (mut send, mut recv) = t.conn().open_bi().await.unwrap();
    send.write_all(&[0xff; 16]).await.unwrap();
    assert_eq!(reset_code(&mut recv).await, u64::from(RESET_BAD_HEADER));
    wait_for(&t.m, &refused(&t.e, "bad_header"), 1.0).await;
    let text = t.m.render();
    assert_eq!(metric(&text, &refused(&t.e, "unknown_listener")), 1.0);
    assert_eq!(metric(&text, &refused(&t.e, "backend_unavailable")), 0.0);
    assert_eq!(
        metric(&text, &series("tunnel_streams_total", &t.e, &[])),
        2.0
    );
    wait_for(&t.m, &series("tunnel_streams_open", &t.e, &[]), 0.0).await;
    t.link.shutdown().await;
}

#[tokio::test]
async fn udp_packets_flows_and_fragments_are_counted() {
    let echo = udp_echo_server().await;
    let p = free_udp_port();
    let m = Metrics::new();
    let rig = rig_full(
        &[],
        &[],
        &[(p, echo)],
        &[p],
        |_| {},
        |_, opts| {
            opts.metrics = m.clone();
        },
    )
    .await;
    let e = rig.edge.endpoint_id().to_string();
    wait_state(&rig.link, |s| s.connected && s.listeners.len() == 1).await;
    let v = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let edge_port = SocketAddr::from(([127, 0, 0, 1], p));
    let small = vec![1u8; 100];
    let large = vec![2u8; 9_000];
    assert_eq!(udp_roundtrip_from(&v, edge_port, &small).await, small);
    assert_eq!(udp_roundtrip_from(&v, edge_port, &large).await, large);

    // A packet the visitor sent again counts again: at least what arrived.
    let text = m.render();
    for (name, at_least) in [
        ("tunnel_udp_packets_total", 2.0),
        ("tunnel_udp_fragmented_packets_total", 1.0),
        ("tunnel_udp_bytes_total", 9_100.0),
    ] {
        for direction in ["in", "out"] {
            let s = series(name, &e, &[("direction", direction)]);
            assert!(metric(&text, &s) >= at_least, "{s} in\n{text}");
        }
    }
    assert_eq!(metric(&text, &series("tunnel_udp_flows", &e, &[])), 1.0);
    assert_eq!(
        metric(&text, &series("tunnel_udp_flows_total", &e, &[])),
        1.0
    );
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn the_flow_cap_counts_an_eviction_and_idle_flows_leave_the_gauge() {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let t = hand(&[], &[5300], &[(5300, addr(&a))], |opts| {
        opts.udp_max_flows = 2;
        opts.udp_flow_idle = Duration::from_millis(300);
    })
    .await;
    let id = t.id(udp(5300));
    for flow in 1..=3 {
        deliver(t.conn(), id, flow, format!("flow {flow}").as_bytes(), &a).await;
    }
    let text = t.m.render();
    let flows = series("tunnel_udp_flows", &t.e, &[]);
    assert_eq!(
        metric(&text, &series("tunnel_udp_flows_evicted_total", &t.e, &[])),
        1.0
    );
    assert_eq!(metric(&text, &flows), 2.0);
    assert_eq!(
        metric(&text, &series("tunnel_udp_flows_total", &t.e, &[])),
        3.0
    );
    wait_for(&t.m, &flows, 0.0).await;
    t.link.shutdown().await;
}

#[tokio::test]
async fn each_udp_drop_reason_is_counted() {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let t = hand(&[5300], &[5301, 5302], &[(5301, addr(&a))], |_| {}).await;
    let (tcp_id, empty_id) = (t.id(tcp(5300)), t.id(udp(5302)));
    let mut table = udp_targets(&[(5301, addr(&a))]);
    table.insert(udp(5302), Vec::<UdpTarget>::new());
    t.udp.send(table).unwrap();
    let dropped = |reason| series("tunnel_udp_dropped_total", &t.e, &[("reason", reason)]);
    let conn = t.conn();

    until_counted(&t.m, &dropped("bad_datagram"), || {
        conn.send_datagram(Bytes::from_static(b"short")).unwrap();
    })
    .await;
    until_counted(&t.m, &dropped("unknown_listener"), || {
        send_packet(conn, 9999, 1, next_packet_id(), b"never issued");
    })
    .await;
    until_counted(&t.m, &dropped("not_udp"), || {
        send_packet(conn, tcp_id, 2, next_packet_id(), b"tcp");
    })
    .await;
    until_counted(&t.m, &dropped("no_target"), || {
        send_packet(conn, empty_id, 3, next_packet_id(), b"nowhere");
    })
    .await;
    t.link.shutdown().await;
}

/// A hand-driven edge that answers the link's first config and sends a packet under the UDP
/// listener of port `p` on flow 1 until `arrived` fires; then its endpoint stops: it runs on a
/// runtime of its own, whose only thread blocks until the returned sender is dropped, so from
/// then on it reads and acknowledges nothing.
struct StalledEdge {
    id: EndpointId,
    addr: SocketAddr,
    arrived: tokio::sync::oneshot::Sender<()>,
    stalled: tokio::sync::oneshot::Receiver<()>,
    release: std::sync::mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

async fn stalled_edge(p: u16) -> StalledEdge {
    let (bound, at) = tokio::sync::oneshot::channel();
    let (arrived, arrival) = tokio::sync::oneshot::channel::<()>();
    let (stall, stalled) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let fake = FakeEdge::bind().await;
            let _ = bound.send((fake.endpoint.id(), fake.endpoint.bound_sockets()[0]));
            let mut s = fake.accept().await;
            let cfg = s.read_config().await;
            s.reply(&cfg).await;
            let id = listener_id(&cfg, udp(p));
            let mut arrival = std::pin::pin!(arrival);
            loop {
                send_packet(&s.conn, id, 1, next_packet_id(), b"start");
                tokio::select! {
                    _ = &mut arrival => break,
                    () = sleep(RESEND) => {}
                }
            }
            let _ = stall.send(());
            // Blocks the thread, and with it every task of the fake's endpoint.
            let _ = released.recv();
        });
    });
    let (id, addr) = timeout(STEP, at).await.unwrap().unwrap();
    StalledEdge {
        id,
        addr,
        arrived,
        stalled,
        release,
        thread,
    }
}

#[tokio::test]
async fn a_full_tunnel_drops_whole_replies_and_counts_them() {
    const REPLIES: usize = 400;
    let p = 5300;
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let edge = stalled_edge(p).await;
    let m = Metrics::new();
    let e = edge.id.to_string();
    let endpoint = bind_endpoint(SecretKey::generate(), &Relay::Disabled)
        .await
        .unwrap();
    let mut opts = LinkOptions::new(edge.id, Some(edge.addr.to_string()), Relay::Disabled).unwrap();
    opts.metrics = m.clone();
    let (_desired, _udp, link) =
        spawn_link(endpoint.clone(), opts, &[], &[], &[(p, addr(&b))], &[p]);
    let mut buf = vec![0u8; MAX_PACKET];
    let (n, flow) = timeout(STEP, b.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"start");
    edge.arrived.send(()).unwrap();
    timeout(STEP, edge.stalled).await.unwrap().unwrap();

    // The edge acknowledges nothing, so the connection soon sends nothing more and its
    // 256 KiB datagram send buffer fills. The forwarder takes each reply in turn, so that none
    // is lost in its socket's buffer instead.
    let payload = [5u8; 1_000];
    for _ in 0..REPLIES {
        b.send_to(&payload, flow).await.unwrap();
        tokio::task::yield_now().await;
    }

    let packets_out = series("tunnel_udp_packets_total", &e, &[("direction", "out")]);
    let tunnel_full = series("tunnel_udp_dropped_total", &e, &[("reason", "tunnel_full")]);
    let send_error = series("tunnel_udp_dropped_total", &e, &[("reason", "send_error")]);
    let handled = |m: &Metrics| {
        let text = m.render();
        metric(&text, &packets_out) + metric(&text, &tunnel_full)
    };
    let deadline = Instant::now() + STEP;
    let mut last = handled(&m);
    loop {
        sleep(Duration::from_millis(200)).await;
        let now = handled(&m);
        if now == last {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the forwarder is still handling replies"
        );
        last = now;
    }

    let text = m.render();
    assert!(metric(&text, &tunnel_full) > 0.0, "{text}");
    assert_eq!(metric(&text, &send_error), 0.0, "{text}");
    link.shutdown().await;
    drop(edge.release);
    edge.thread.join().unwrap();
}

#[tokio::test]
async fn a_stopped_link_takes_its_series_with_it() {
    let echo = echo_server().await;
    let m = Metrics::new();
    let (p, q) = (free_tcp_port(), free_tcp_port());
    let one = rig_with(&[(p, echo)], &[p], |_, opts| opts.metrics = m.clone()).await;
    let two = rig_with(&[(q, echo)], &[q], |_, opts| opts.metrics = m.clone()).await;
    let (e1, e2) = (
        one.edge.endpoint_id().to_string(),
        two.edge.endpoint_id().to_string(),
    );
    assert_eq!(e1.len(), 64, "{e1}");
    assert!(e1.chars().all(|c| c.is_ascii_hexdigit()), "{e1}");
    wait_state(&one.link, |s| s.connected).await;
    wait_state(&two.link, |s| s.connected).await;
    assert!(m.render().contains(&format!("edge=\"{e1}\"")));

    one.link.shutdown().await;
    let text = m.render();
    assert!(
        !text.lines().any(|l| l.contains(&format!("edge=\"{e1}\""))),
        "{text}"
    );
    assert_eq!(metric(&text, &series("tunnel_up", &e2, &[])), 1.0);
    two.link.shutdown().await;
    one.edge.shutdown().await;
    two.edge.shutdown().await;
}
