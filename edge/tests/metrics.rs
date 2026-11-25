//! The edge's Prometheus metrics, read from its `Metrics` while it runs.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use iroh::SecretKey;
use iroh_gateway_edge::{Edge, EdgeHandle, EdgeOptions, Metrics};
use iroh_gateway_proto::control::{BindState, Config, Protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, sleep, timeout};

const GRACE: Duration = Duration::from_secs(5);
/// How often a waiting test reads the metrics again.
const POLL: Duration = Duration::from_millis(20);

/// The value of `series`, a metric name without the `iroh_gateway_edge_` prefix and with its
/// labels as rendered, in `text`; panics with the whole text if it is absent.
fn metric(text: &str, series: &str) -> f64 {
    let wanted = format!("iroh_gateway_edge_{series} ");
    let line = text
        .lines()
        .find(|line| line.starts_with(&wanted))
        .unwrap_or_else(|| panic!("no {series} in\n{text}"));
    line[wanted.len()..]
        .parse()
        .unwrap_or_else(|e| panic!("{line}: {e}"))
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

/// An edge with `customize` applied to its options, and the metrics it reports to.
async fn spawn(customize: impl FnOnce(&mut EdgeOptions)) -> (EdgeHandle, Metrics, SecretKey) {
    let key = SecretKey::generate();
    let mut opts = edge_options(key.public(), GRACE, 100);
    customize(&mut opts);
    let metrics = opts.metrics.clone();
    let edge = Edge::spawn(opts).await.unwrap();
    (edge, metrics, key)
}

/// [`spawn`] with a fake operator connected to the edge.
async fn start(customize: impl FnOnce(&mut EdgeOptions)) -> (EdgeHandle, FakeOperator, Metrics) {
    let (edge, metrics, key) = spawn(customize).await;
    let fake = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    (edge, fake, metrics)
}

/// A TCP listener with id 1 on a free port, configured on `fake`.
async fn tcp_port(fake: &mut FakeOperator) -> u16 {
    let p = free_tcp_port();
    assert!(bound(&fake.push(tcp_cfg(1, &[p])).await));
    p
}

/// Sends `payload` under `flow_id` once and waits for `v` to receive it.
async fn reply_once(
    fake: &FakeOperator,
    flow_id: u64,
    packet_id: u32,
    payload: &[u8],
    v: &UdpSocket,
) {
    send_packet(&fake.conn, 1, flow_id, packet_id, payload);
    let mut buf = vec![0u8; 65_535];
    let (n, _) = timeout(STEP, v.recv_from(&mut buf))
        .await
        .expect("the reply did not reach the visitor")
        .unwrap();
    assert_eq!(&buf[..n], payload);
}

#[tokio::test]
async fn a_fresh_edge_reports_its_build_and_no_session() {
    let (edge, m, _) = spawn(|_| {}).await;
    let text = m.render();
    let build = format!("build_info{{version=\"{}\"}}", env!("CARGO_PKG_VERSION"));
    assert_eq!(metric(&text, &build), 1.0);
    assert_eq!(metric(&text, "session_up"), 0.0);
    assert_eq!(metric(&text, "sessions_total"), 0.0);
    edge.shutdown().await;
}

#[tokio::test]
async fn a_configured_session_shows_up_and_goes_away() {
    let (edge, mut fake, m) = start(|o| o.tunnel_grace = Duration::from_millis(300)).await;
    let p = free_tcp_and_udp_port();
    let st = fake
        .push(cfg(1, &[(1, Protocol::Tcp, p), (2, Protocol::Udp, p)]))
        .await;
    assert!(bound(&st), "{st:?}");
    let text = m.render();
    assert_eq!(metric(&text, "session_up"), 1.0);
    assert_eq!(metric(&text, "sessions_total"), 1.0);
    assert_eq!(metric(&text, r#"listeners{protocol="tcp"}"#), 1.0);
    assert_eq!(metric(&text, r#"listeners{protocol="udp"}"#), 1.0);

    fake.conn.close(0u32.into(), b"");
    wait_for(&m, "session_up", 0.0).await;
    wait_for(&m, r#"listeners{protocol="tcp"}"#, 0.0).await;
    wait_for(&m, r#"listeners{protocol="udp"}"#, 0.0).await;
    assert_eq!(value(&m, "sessions_total"), 1.0);
    edge.shutdown().await;
}

#[tokio::test]
async fn a_bind_error_is_counted() {
    let (edge, mut fake, m) = start(|_| {}).await;
    let held = std::net::TcpListener::bind(("127.0.0.1", free_tcp_port())).unwrap();
    let p = held.local_addr().unwrap().port();
    let st = fake.push(tcp_cfg(1, &[p])).await;
    assert!(
        matches!(st.listeners[0].state, BindState::Error(_)),
        "{st:?}"
    );
    let text = m.render();
    assert_eq!(metric(&text, r#"bind_failures_total{protocol="tcp"}"#), 1.0);
    assert_eq!(metric(&text, r#"bind_failures_total{protocol="udp"}"#), 0.0);
    assert_eq!(metric(&text, r#"listeners{protocol="tcp"}"#), 0.0);
    drop(held);
    edge.shutdown().await;
}

#[tokio::test]
async fn tcp_bytes_are_counted_as_they_move() {
    let (edge, mut fake, m) = start(|_| {}).await;
    let p = tcp_port(&mut fake).await;
    let mut visitor = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    visitor.write_all(&[1; 5_000]).await.unwrap();
    let (_, mut send, mut recv) = fake.accept_from(visitor.local_addr().unwrap()).await;
    let mut up = vec![0; 5_000];
    timeout(STEP, recv.read_exact(&mut up))
        .await
        .unwrap()
        .unwrap();
    send.write_all(&[2; 3_000]).await.unwrap();
    let mut down = vec![0; 3_000];
    timeout(STEP, visitor.read_exact(&mut down))
        .await
        .unwrap()
        .unwrap();

    // Both directions are still open.
    wait_for(&m, r#"tcp_bytes_total{direction="in"}"#, 5_000.0).await;
    wait_for(&m, r#"tcp_bytes_total{direction="out"}"#, 3_000.0).await;
    let text = m.render();
    assert_eq!(metric(&text, "connections_open"), 1.0);
    assert_eq!(metric(&text, "connections_total"), 1.0);

    // The visitor closes, and the operator side closes in turn once it has seen the end.
    drop(visitor);
    let rest = timeout(STEP, recv.read_to_end(16)).await.unwrap().unwrap();
    assert!(rest.is_empty());
    send.finish().unwrap();
    wait_for(&m, "connections_open", 0.0).await;
    assert_eq!(value(&m, "connections_total"), 1.0);
    edge.shutdown().await;
}

#[tokio::test]
async fn bytes_of_a_visitor_cut_off_by_tunnel_loss_stay_counted() {
    let (edge, mut fake, m) = start(|_| {}).await;
    let p = tcp_port(&mut fake).await;
    let mut visitor = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    visitor.write_all(&[1; 5_000]).await.unwrap();
    let (_, _send, mut recv) = fake.accept_from(visitor.local_addr().unwrap()).await;
    let mut up = vec![0; 5_000];
    timeout(STEP, recv.read_exact(&mut up))
        .await
        .unwrap()
        .unwrap();

    fake.conn.close(0u32.into(), b"");
    wait_for(&m, "connections_open", 0.0).await;
    assert_eq!(value(&m, r#"tcp_bytes_total{direction="in"}"#), 5_000.0);
    edge.shutdown().await;
}

#[tokio::test]
async fn a_visitor_past_the_cap_is_refused_and_counted() {
    let (edge, mut fake, m) = start(|o| o.max_connections = 1).await;
    let p = tcp_port(&mut fake).await;
    let mut first = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    first.write_all(b"first").await.unwrap();
    let _stream = fake.accept_from(first.local_addr().unwrap()).await;

    let _second = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    wait_for(&m, r#"connections_refused_total{reason="cap"}"#, 1.0).await;
    let text = m.render();
    assert_eq!(metric(&text, "connections_open"), 1.0);
    assert_eq!(metric(&text, "connections_total"), 1.0);
    edge.shutdown().await;
}

#[tokio::test]
async fn a_visitor_without_a_session_is_refused_and_counted() {
    let (edge, mut fake, m) = start(|_| {}).await;
    let p = tcp_port(&mut fake).await;
    fake.conn.close(0u32.into(), b"");
    wait_for(&m, "session_up", 0.0).await;

    // Inside the grace the port is still open, but there is no session to forward over.
    let _visitor = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    wait_for(&m, r#"connections_refused_total{reason="no_session"}"#, 1.0).await;
    wait_for(&m, "connections_open", 0.0).await;
    edge.shutdown().await;
}

#[tokio::test]
async fn udp_packets_flows_and_fragments_are_counted() {
    let (edge, mut fake, m) = start(|_| {}).await;
    let p = udp_port(&mut fake).await;
    let v = udp_visitor().await;
    let small = vec![1u8; 100];
    let large = vec![2u8; 9_000];

    let (packet, fragments) = send_until_packet(&v, p, &small, &fake.conn).await;
    assert_eq!(fragments, 1);
    reply_once(&fake, packet.flow_id, 0, &small, &v).await;
    let (packet, fragments) = send_until_packet(&v, p, &large, &fake.conn).await;
    assert!(fragments > 1, "9,000 bytes went in one datagram");
    reply_once(&fake, packet.flow_id, 1, &large, &v).await;

    // The visitor resends a packet until it arrives, so `in` counts at least what arrived.
    // Each reply is sent once, so `out` counts exactly two packets, one of them fragmented.
    let text = m.render();
    assert!(
        metric(&text, r#"udp_packets_total{direction="in"}"#) >= 2.0,
        "{text}"
    );
    assert!(
        metric(&text, r#"udp_bytes_total{direction="in"}"#) >= 9_100.0,
        "{text}"
    );
    assert!(
        metric(&text, r#"udp_fragmented_packets_total{direction="in"}"#) >= 1.0,
        "{text}"
    );
    wait_for(&m, r#"udp_packets_total{direction="out"}"#, 2.0).await;
    wait_for(&m, r#"udp_bytes_total{direction="out"}"#, 9_100.0).await;
    wait_for(&m, r#"udp_fragmented_packets_total{direction="out"}"#, 1.0).await;
    let text = m.render();
    assert_eq!(metric(&text, "udp_flows"), 1.0);
    assert_eq!(metric(&text, "udp_flows_total"), 1.0);
    edge.shutdown().await;
}

#[tokio::test]
async fn the_flow_cap_counts_an_eviction() {
    let (edge, mut fake, m) = start(|o| o.max_udp_flows = 2).await;
    let p = udp_port(&mut fake).await;
    for name in [b"a", b"b", b"c"] {
        let v = udp_visitor().await;
        send_until_packet(&v, p, name, &fake.conn).await;
    }
    let text = m.render();
    assert_eq!(metric(&text, "udp_flows"), 2.0);
    assert_eq!(metric(&text, "udp_flows_total"), 3.0);
    assert_eq!(metric(&text, "udp_flows_evicted_total"), 1.0);
    edge.shutdown().await;
}

#[tokio::test]
async fn each_drop_reason_is_counted() {
    let (edge, mut fake, m) = start(|o| o.udp_rate_limit = Some(1)).await;
    let p = udp_port(&mut fake).await;
    let v = udp_visitor().await;

    // At one byte per second the bucket holds about one largest packet and refills nothing
    // worth counting: 9,000-byte packets drain it within eight.
    let payload = vec![3u8; 9_000];
    let deadline = Instant::now() + STEP;
    while value(&m, r#"udp_dropped_total{reason="rate_limit"}"#) < 1.0 {
        assert!(
            Instant::now() < deadline,
            "no packet was over the rate limit"
        );
        v.send_to(&payload, ("127.0.0.1", p)).await.unwrap();
        sleep(POLL).await;
    }

    send_packet(&fake.conn, 1, 1 << 40, 0, b"never issued");
    wait_until(&m, r#"udp_dropped_total{reason="unknown_flow"}"#, |n| {
        n >= 1.0
    })
    .await;
    fake.conn
        .send_datagram(Bytes::from_static(b"short"))
        .unwrap();
    wait_until(&m, r#"udp_dropped_total{reason="bad_datagram"}"#, |n| {
        n >= 1.0
    })
    .await;

    fake.conn.close(0u32.into(), b"");
    wait_for(&m, "session_up", 0.0).await;
    v.send_to(b"inside the grace", ("127.0.0.1", p))
        .await
        .unwrap();
    wait_until(&m, r#"udp_dropped_total{reason="no_session"}"#, |n| {
        n >= 1.0
    })
    .await;
    edge.shutdown().await;
}

/// A fake operator that configures `config` and then stops: its endpoint runs on a runtime of
/// its own, whose only thread blocks until the sender is dropped, so from then on it reads and
/// acknowledges nothing.
async fn stalled_operator(
    edge: &EdgeHandle,
    key: SecretKey,
    config: Config,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (edge_id, edge_addr) = (edge.endpoint_id(), edge.iroh_addr());
    let (configured, status) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let mut fake = FakeOperator::connect(key, edge_id, edge_addr)
                .await
                .unwrap();
            let _ = configured.send(fake.push(config).await);
            // Blocks the thread, and with it every task of the fake's endpoint.
            let _ = released.recv();
        });
    });
    let st = timeout(STEP, status).await.unwrap().unwrap();
    assert!(bound(&st), "{st:?}");
    (release, thread)
}

#[tokio::test]
async fn a_full_tunnel_drops_whole_packets_and_counts_them() {
    const PACKETS: usize = 400;
    let (edge, m, key) = spawn(|_| {}).await;
    let p = free_udp_port();
    let (release, stalled) = stalled_operator(&edge, key, cfg(1, &[(1, Protocol::Udp, p)])).await;
    let v = udp_visitor().await;
    let target = SocketAddr::from(([127, 0, 0, 1], p));
    let payload = [5u8; 1_000];
    // The operator acknowledges nothing, so the connection soon sends nothing more and its
    // 256 KiB datagram send buffer fills. The edge takes each packet in turn, so that none is
    // lost in its socket's buffer instead.
    for _ in 0..PACKETS {
        v.send_to(&payload, target).await.unwrap();
        tokio::task::yield_now().await;
    }

    let handled = |m: &Metrics| {
        let text = m.render();
        metric(&text, r#"udp_packets_total{direction="in"}"#)
            + metric(&text, r#"udp_dropped_total{reason="tunnel_full"}"#)
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
            "the edge is still handling packets"
        );
        last = now;
    }

    let text = m.render();
    assert!(
        metric(&text, r#"udp_dropped_total{reason="tunnel_full"}"#) > 0.0,
        "{text}"
    );
    assert_eq!(
        metric(&text, r#"udp_dropped_total{reason="send_error"}"#),
        0.0,
        "{text}"
    );
    edge.shutdown().await;
    drop(release);
    stalled.join().unwrap();
}
