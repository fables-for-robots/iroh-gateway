mod common;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::*;
use iroh::endpoint::{ConnectError, ConnectingError, ConnectionError, TransportErrorCode};
use iroh::{EndpointAddr, EndpointId, SecretKey};
use iroh_gateway_proto::control::{BindState, ListenerStatus};
use iroh_gateway_proto::transport::{Relay, Role, endpoint_builder};
use iroh_gateway_proto::{ALPN, CLOSE_REPLACED, CLOSE_UNAUTHORIZED};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, sleep, timeout};

const GRACE: Duration = Duration::from_secs(5);

async fn visitor(p: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", p)).await.unwrap()
}

/// Connects until the port refuses: a closed port can accept for a moment after it is closed.
async fn refused(p: u16) -> ErrorKind {
    for _ in 0..50 {
        match TcpStream::connect(("127.0.0.1", p)).await {
            Err(e) => return e.kind(),
            Ok(_) => sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("port {p} still accepts");
}

/// What the visitor's next read returns, within 1 s.
async fn next_read(v: &mut TcpStream) -> std::io::Result<usize> {
    let mut buf = [0u8; 16];
    timeout(Duration::from_secs(1), v.read(&mut buf))
        .await
        .expect("visitor read did not end within 1 s")
}

fn bound(st: &iroh_gateway_proto::control::Status) -> bool {
    st.listeners.iter().all(|l| l.state == BindState::Bound)
}

/// Asserts that a fake operator with an unpinned key is turned away with `CLOSE_UNAUTHORIZED`.
async fn assert_unauthorized(dial: anyhow::Result<FakeOperator>, p: u16) {
    match dial {
        Err(e) => {
            let code = e.downcast_ref::<ConnectionError>().and_then(app_close_code);
            assert_eq!(code, Some(CLOSE_UNAUTHORIZED.into()), "{e:#}");
        }
        Ok(mut fake) => {
            assert!(fake.try_push(tcp_cfg(1, &[p])).await.is_err());
            let closed = timeout(STEP, fake.conn.closed()).await.unwrap();
            assert_eq!(
                app_close_code(&closed),
                Some(CLOSE_UNAUTHORIZED.into()),
                "{closed}"
            );
        }
    }
    assert_eq!(refused(p).await, ErrorKind::ConnectionRefused);
}

#[tokio::test]
async fn forwards_a_visitor_connection() {
    let key = SecretKey::generate();
    let edge = spawn_edge(key.public(), GRACE, 100).await;
    let mut fake = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    let p = free_tcp_port();
    let st = fake.push(tcp_cfg(1, &[p])).await;
    assert_eq!(st.generation, 1);
    assert_eq!(
        st.listeners,
        vec![ListenerStatus {
            id: 1,
            state: BindState::Bound
        }]
    );

    let mut v = visitor(p).await;
    v.write_all(b"hi").await.unwrap();
    let (header, mut send, mut recv) = fake.accept_stream().await;
    assert_eq!(header.listener_id, 1);
    assert_eq!(header.visitor, v.local_addr().unwrap());
    assert_eq!(header.local.port(), p);
    let mut buf = [0u8; 2];
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hi");
    send.write_all(b"yo").await.unwrap();
    v.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"yo");

    edge.shutdown().await;
}

#[tokio::test]
async fn unlisted_operator_key_is_rejected() {
    let edge = spawn_edge(SecretKey::generate().public(), GRACE, 100).await;
    let p = free_tcp_port();
    let dial = FakeOperator::connect(SecretKey::generate(), edge.endpoint_id(), edge.iroh_addr());
    assert_unauthorized(dial.await, p).await;
    edge.shutdown().await;
}

#[tokio::test]
async fn listeners_close_after_grace() {
    let key = SecretKey::generate();
    let edge = spawn_edge(key.public(), Duration::from_millis(200), 100).await;
    let mut fake = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    let p = free_tcp_port();
    assert!(bound(&fake.push(tcp_cfg(1, &[p])).await));
    drop(visitor(p).await);

    fake.conn.close(0u32.into(), b"");
    sleep(Duration::from_secs(1)).await;
    assert_eq!(refused(p).await, ErrorKind::ConnectionRefused);
    edge.shutdown().await;
}

#[tokio::test]
async fn reconnect_within_grace_keeps_listeners() {
    let key = SecretKey::generate();
    let edge = spawn_edge(key.public(), Duration::from_secs(2), 100).await;
    let mut fake1 = FakeOperator::connect(key.clone(), edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    let p = free_tcp_port();
    assert!(bound(&fake1.push(tcp_cfg(1, &[p])).await));
    let _v1 = visitor(p).await;

    fake1.conn.close(0u32.into(), b"");
    let mut fake2 = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    assert!(bound(&fake2.push(tcp_cfg(2, &[p])).await));

    sleep(Duration::from_millis(2500)).await;
    let mut v = visitor(p).await;
    v.write_all(b"ok").await.unwrap();
    let (header, _send, mut recv) = fake2.accept_from(v.local_addr().unwrap()).await;
    assert_eq!(header.local.port(), p);
    let mut buf = [0u8; 2];
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok");
    edge.shutdown().await;
}

#[tokio::test]
async fn new_operator_connection_replaces_old() {
    let key = SecretKey::generate();
    let edge = spawn_edge(key.public(), GRACE, 1000).await;
    let mut fake1 = FakeOperator::connect(key.clone(), edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    let p = free_tcp_port();
    assert!(bound(&fake1.push(tcp_cfg(1, &[p])).await));

    let stop = Arc::new(AtomicBool::new(false));
    let prober = tokio::spawn({
        let stop = stop.clone();
        async move {
            let (mut ok, mut refused) = (0u32, 0u32);
            while !stop.load(Ordering::Relaxed) {
                match TcpStream::connect(("127.0.0.1", p)).await {
                    Ok(_) => ok += 1,
                    Err(_) => refused += 1,
                }
                sleep(Duration::from_millis(20)).await;
            }
            (ok, refused)
        }
    });
    sleep(Duration::from_millis(100)).await;

    let mut fake2 = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    assert!(bound(&fake2.push(tcp_cfg(2, &[p])).await));
    let closed = timeout(STEP, fake1.conn.closed()).await.unwrap();
    assert_eq!(
        app_close_code(&closed),
        Some(CLOSE_REPLACED.into()),
        "{closed}"
    );

    sleep(Duration::from_millis(200)).await;
    stop.store(true, Ordering::Relaxed);
    let (ok, refused) = prober.await.unwrap();
    assert_eq!(refused, 0, "port refused during the switch ({ok} accepted)");
    assert!(ok > 0);

    let mut v = visitor(p).await;
    v.write_all(b"new").await.unwrap();
    let (header, _send, mut recv) = fake2.accept_from(v.local_addr().unwrap()).await;
    assert_eq!(header.listener_id, 1);
    let mut buf = [0u8; 3];
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"new");
    edge.shutdown().await;
}

#[tokio::test]
async fn visitor_before_first_config_is_dropped() {
    let key = SecretKey::generate();
    let edge = spawn_edge(key.public(), GRACE, 100).await;
    let mut fake1 = FakeOperator::connect(key.clone(), edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    let p = free_tcp_port();
    assert!(bound(&fake1.push(tcp_cfg(1, &[p])).await));

    // Same key, as after an operator restart; it pushes no config yet.
    let mut fake2 = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    timeout(STEP, fake1.conn.closed()).await.unwrap();
    let mut v = visitor(p).await;
    assert!(matches!(next_read(&mut v).await, Ok(0) | Err(_)));
    assert!(
        timeout(Duration::from_millis(500), fake2.accept_stream())
            .await
            .is_err(),
        "a visitor reached a session that has applied no config"
    );

    assert!(bound(&fake2.push(tcp_cfg(2, &[p])).await));
    let mut v = visitor(p).await;
    v.write_all(b"now").await.unwrap();
    let (header, _send, mut recv) = fake2.accept_from(v.local_addr().unwrap()).await;
    assert_eq!(header.listener_id, 1);
    let mut buf = [0u8; 3];
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"now");
    edge.shutdown().await;
}

#[tokio::test]
async fn visitors_without_session_are_dropped() {
    let key = SecretKey::generate();
    let edge = spawn_edge(key.public(), GRACE, 100).await;
    let mut fake = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    let p = free_tcp_port();
    assert!(bound(&fake.push(tcp_cfg(1, &[p])).await));

    fake.conn.close(0u32.into(), b"");
    sleep(Duration::from_millis(300)).await;
    let mut v = visitor(p).await;
    assert!(matches!(next_read(&mut v).await, Ok(0) | Err(_)));
    edge.shutdown().await;
}

#[tokio::test]
async fn early_disconnect_releases_slot() {
    let key = SecretKey::generate();
    let edge = spawn_edge(key.public(), GRACE, 1).await;
    let mut fake = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    let p = free_tcp_port();
    assert!(bound(&fake.push(tcp_cfg(1, &[p])).await));

    for _ in 0..20 {
        drop(visitor(p).await);
    }

    // A visitor's FIN is only a half-close, so its slot is freed once the operator side of its
    // stream ends too: `accept_from` drops the streams it skips, which ends them.
    let deadline = Instant::now() + Duration::from_secs(2);
    let (mut v, mut send, mut recv) = loop {
        assert!(Instant::now() < deadline, "no visitor delivered within 2 s");
        let v = visitor(p).await;
        let addr: SocketAddr = v.local_addr().unwrap();
        if let Ok((_, send, recv)) =
            timeout(Duration::from_millis(200), fake.accept_from(addr)).await
        {
            break (v, send, recv);
        }
    };
    v.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    recv.read_exact(&mut buf).await.unwrap();
    send.write_all(&buf).await.unwrap();
    let mut echo = [0u8; 4];
    v.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
    edge.shutdown().await;
}

#[tokio::test]
async fn tunnel_loss_aborts_visitors() {
    let key = SecretKey::generate();
    let edge = spawn_edge(key.public(), GRACE, 100).await;
    let mut fake = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    let p = free_tcp_port();
    assert!(bound(&fake.push(tcp_cfg(1, &[p])).await));

    let mut v = visitor(p).await;
    v.write_all(b"up").await.unwrap();
    let (_, mut send, mut recv) = fake.accept_stream().await;
    let mut buf = [0u8; 2];
    recv.read_exact(&mut buf).await.unwrap();
    send.write_all(b"ok").await.unwrap();
    v.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok");

    fake.conn.close(0u32.into(), b"");
    assert!(next_read(&mut v).await.is_err());
    edge.shutdown().await;
}

#[tokio::test]
async fn reachable_through_relay_without_direct_address() {
    let (_map, relay_url, _server) = iroh::test_utils::run_relay_server().await.unwrap();
    let key = SecretKey::generate();
    let edge = spawn_edge_via_relay(key.public(), relay_url.clone()).await;
    let mut fake = FakeOperator::connect_via_relay(key, edge.endpoint_id(), relay_url)
        .await
        .unwrap();
    let p = free_tcp_port();
    assert!(bound(&fake.push(tcp_cfg(1, &[p])).await));

    let mut v = visitor(p).await;
    v.write_all(b"relayed").await.unwrap();
    let (header, _send, mut recv) = fake.accept_stream().await;
    assert_eq!(header.visitor, v.local_addr().unwrap());
    let mut buf = [0u8; 7];
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"relayed");
    edge.shutdown().await;
}

#[tokio::test]
async fn relay_does_not_weaken_pinning() {
    let (_map, relay_url, _server) = iroh::test_utils::run_relay_server().await.unwrap();
    let edge = spawn_edge_via_relay(SecretKey::generate().public(), relay_url.clone()).await;
    let p = free_tcp_port();
    let dial =
        FakeOperator::connect_via_relay(SecretKey::generate(), edge.endpoint_id(), relay_url);
    assert_unauthorized(dial.await, p).await;
    edge.shutdown().await;
}

#[tokio::test]
async fn bad_control_frame_ends_session_only() {
    let key = SecretKey::generate();
    let edge = spawn_edge(key.public(), GRACE, 100).await;
    let mut fake1 = FakeOperator::connect(key.clone(), edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    let p = free_tcp_port();
    assert!(bound(&fake1.push(tcp_cfg(1, &[p])).await));

    fake1.control_send.write_all(&[0xff; 4]).await.unwrap();
    timeout(STEP, fake1.conn.closed())
        .await
        .expect("connection not closed after a bad control frame");

    let mut fake2 = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    assert!(bound(&fake2.push(tcp_cfg(2, &[p])).await));
    edge.shutdown().await;
}

#[tokio::test]
async fn iroh_listen_is_the_bound_address() {
    let port = free_udp_port();
    let opts = iroh_gateway_edge::EdgeOptions {
        iroh_listen: SocketAddr::from(([127, 0, 0, 1], port)),
        ..edge_options(SecretKey::generate().public(), GRACE, 100)
    };
    let edge = iroh_gateway_edge::Edge::spawn(opts).await.unwrap();
    assert_eq!(edge.iroh_addr(), SocketAddr::from(([127, 0, 0, 1], port)));
    edge.shutdown().await;
}

/// The edge's cap on handshakes in progress, and how long each may take.
const MAX_PENDING_HANDSHAKES: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A UDP relay from one dialer to the edge that forwards the dialer's datagrams only until the
/// edge answers with anything but a Retry. The edge's handshake then waits for a client
/// `Finished` that never arrives, and holds its handshake slot.
async fn stalling_proxy(edge: SocketAddr) -> (SocketAddr, JoinHandle<()>) {
    let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    up.connect(edge).await.unwrap();
    let addr = front.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut from_dialer, mut from_edge) = ([0u8; 2048], [0u8; 2048]);
        let mut dialer = None;
        let mut stalled = false;
        loop {
            tokio::select! {
                r = front.recv_from(&mut from_dialer) => {
                    let Ok((n, from)) = r else { return };
                    dialer = Some(from);
                    if !stalled {
                        let _ = up.send(&from_dialer[..n]).await;
                    }
                }
                r = up.recv(&mut from_edge) => {
                    let Ok(n) = r else { return };
                    // A QUIC v1 long header with packet type Retry.
                    let retry = n > 0 && from_edge[0] & 0xf0 == 0xf0;
                    stalled |= !retry;
                    if let Some(dialer) = dialer {
                        let _ = front.send_to(&from_edge[..n], dialer).await;
                    }
                }
            }
        }
    });
    (addr, task)
}

/// Dials the edge through `proxy` with a fresh unpinned key; true if the edge refused the
/// connection attempt outright.
async fn flood_once(edge_id: EndpointId, proxy: SocketAddr) -> (bool, iroh::Endpoint) {
    let endpoint = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Operator)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();
    let addr = EndpointAddr::new(edge_id).with_ip_addr(proxy);
    let dialed = timeout(Duration::from_secs(5), endpoint.connect(addr, ALPN)).await;
    let refused = matches!(
        dialed,
        Ok(Err(ConnectError::Connecting {
            source: ConnectingError::ConnectionError {
                source: ConnectionError::ConnectionClosed(close),
                ..
            },
            ..
        })) if close.error_code == TransportErrorCode::CONNECTION_REFUSED
    );
    (refused, endpoint)
}

#[tokio::test]
async fn handshake_flood_is_capped() {
    const FLOODERS: usize = MAX_PENDING_HANDSHAKES + 16;
    let key = SecretKey::generate();
    let edge = spawn_edge(key.public(), GRACE, 100).await;

    let mut proxies = Vec::new();
    let mut flood = JoinSet::new();
    for _ in 0..FLOODERS {
        let (addr, proxy) = stalling_proxy(edge.iroh_addr()).await;
        proxies.push(proxy);
        flood.spawn(flood_once(edge.endpoint_id(), addr));
    }
    let flood_started = Instant::now();
    let mut refused = 0;
    let mut flooders = Vec::new();
    while let Some(done) = flood.join_next().await {
        let (was_refused, endpoint) = done.unwrap();
        refused += usize::from(was_refused);
        flooders.push(endpoint);
    }
    // Every handshake past the cap was refused; the others hold their slots until they time out.
    assert_eq!(refused, FLOODERS - MAX_PENDING_HANDSHAKES);

    // The stalled handshakes time out, and then the pinned operator gets in.
    let mut fake = loop {
        match FakeOperator::connect(key.clone(), edge.endpoint_id(), edge.iroh_addr()).await {
            Ok(fake) => break fake,
            Err(e) => {
                assert!(
                    flood_started.elapsed() < HANDSHAKE_TIMEOUT + Duration::from_secs(5),
                    "operator still locked out: {e:#}"
                );
                sleep(Duration::from_millis(200)).await;
            }
        }
    };
    let p = free_tcp_port();
    assert!(bound(&fake.push(tcp_cfg(1, &[p])).await));

    for proxy in proxies {
        proxy.abort();
    }
    drop(flooders);
    edge.shutdown().await;
}
