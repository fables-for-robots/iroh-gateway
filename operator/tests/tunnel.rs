mod common;

use std::io::ErrorKind;
use std::time::Duration;

use common::*;
use iroh::SecretKey;
use iroh::endpoint::ConnectionError;
use iroh_gateway_edge::Edge;
use iroh_gateway_operator::tunnel::{Connector, LinkOptions, ListenerState, StaticConnector};
use iroh_gateway_proto::control::StreamHeader;
use iroh_gateway_proto::transport::Relay;
use iroh_gateway_proto::{CLOSE_SHUTDOWN, RESET_BAD_HEADER, RESET_UNKNOWN_LISTENER};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Instant, timeout};

fn bound(keys: &[u16]) -> Vec<ListenerState> {
    keys.iter()
        .map(|&p| ListenerState {
            key: tcp(p),
            bound: Ok(()),
        })
        .collect()
}

#[tokio::test]
async fn tcp_echo_roundtrip() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let rig = rig(&[(p, echo)]).await;
    let st = wait_state(&rig.link, |s| s.connected && s.listeners == bound(&[p])).await;
    assert_eq!(st.generation, 1);
    assert!(st.edge_version.is_some());

    let mut v = visitor(p).await;
    echoes(&mut v, b"hello").await;
    rig.link.shutdown().await;
    assert!(!rig.endpoint.is_closed());
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn half_close_is_propagated() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = target.accept().await.unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        s.write_all(b"done").await.unwrap();
        s.shutdown().await.unwrap();
        got
    });
    let p = free_tcp_port();
    let rig = rig(&[(p, target_addr)]).await;
    wait_state(&rig.link, |s| s.listeners == bound(&[p])).await;

    let mut v = visitor(p).await;
    v.write_all(b"abc").await.unwrap();
    v.shutdown().await.unwrap();
    let mut back = Vec::new();
    timeout(STEP, v.read_to_end(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back, b"done");
    assert_eq!(server.await.unwrap(), b"abc");
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn backend_abort_resets_visitor() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = target.accept().await.unwrap();
        s.set_zero_linger().unwrap();
        drop(s);
    });
    let p = free_tcp_port();
    let rig = rig(&[(p, target_addr)]).await;
    wait_state(&rig.link, |s| s.listeners == bound(&[p])).await;

    let mut v = visitor(p).await;
    let mut buf = [0u8; 16];
    let read = timeout(STEP, v.read(&mut buf)).await.unwrap();
    assert_eq!(read.unwrap_err().kind(), ErrorKind::ConnectionReset);
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn backend_down_resets_visitor() {
    let dead = format!("127.0.0.1:{}", free_tcp_port()).parse().unwrap();
    let echo = echo_server().await;
    let (p, q) = (free_tcp_port(), free_tcp_port());
    let rig = rig(&[(p, dead), (q, echo)]).await;
    wait_state(&rig.link, |s| s.listeners == bound(&[p, q])).await;

    let mut v = visitor(p).await;
    let mut buf = [0u8; 16];
    let read = timeout(Duration::from_secs(6), v.read(&mut buf))
        .await
        .expect("visitor to a dead backend was not ended within 6 s");
    assert!(matches!(read, Err(_) | Ok(0)), "{read:?}");

    assert!(rig.link.state().borrow().connected);
    let mut w = visitor(q).await;
    echoes(&mut w, b"still up").await;
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn desired_change_adds_and_removes() {
    let echo = echo_server().await;
    let (p, q) = (free_tcp_port(), free_tcp_port());
    let rig = rig_with(&[(p, echo), (q, echo)], &[p], |_, _| {}).await;
    wait_state(&rig.link, |s| s.listeners == bound(&[p])).await;
    let mut v1 = visitor(p).await;
    echoes(&mut v1, b"one").await;

    rig.desired.send(vec![tcp(q)]).unwrap();
    wait_state(&rig.link, |s| {
        s.generation == 2 && s.listeners == bound(&[q])
    })
    .await;
    assert_eq!(refused(p).await, ErrorKind::ConnectionRefused);
    let mut v2 = visitor(q).await;
    echoes(&mut v2, b"two").await;
    echoes(&mut v1, b"one again").await;
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn bind_error_reaches_state() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = held.local_addr().unwrap().port();
    let echo = echo_server().await;
    let rig = rig(&[(p, echo)]).await;
    let st = wait_state(&rig.link, |s| {
        s.listeners.len() == 1 && s.listeners[0].bound.is_err()
    })
    .await;
    assert!(st.connected);
    assert_eq!(st.listeners[0].key, tcp(p));
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
    drop(held);
}

#[tokio::test]
async fn edge_restart_reconnects() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let mut rig = rig(&[(p, echo)]).await;
    let before = wait_state(&rig.link, |s| s.listeners == bound(&[p])).await;
    echoes(&mut visitor(p).await, b"before").await;

    let iroh_addr = rig.edge.iroh_addr();
    rig.edge.shutdown().await;
    wait_state(&rig.link, |s| !s.connected && s.listeners.is_empty()).await;

    rig.edge = Edge::spawn(edge_options(
        rig.operator_key.public(),
        rig.edge_key.clone(),
        iroh_addr,
    ))
    .await
    .unwrap();
    let after = wait_state(&rig.link, |s| s.connected).await;
    assert!(after.generation > before.generation, "{after:?}");
    echoes(&mut visitor(p).await, b"after").await;
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn wrong_edge_key_never_connects() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let rig = rig_with(&[(p, echo)], &[p], |_, opts| {
        opts.edge_id = SecretKey::generate().public();
    })
    .await;
    stays_disconnected(&rig.link, Duration::from_secs(1)).await;
    assert_eq!(refused(p).await, ErrorKind::ConnectionRefused);
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn address_is_resolved_as_a_name() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let rig = rig_with(&[(p, echo)], &[p], |edge, opts| {
        opts.address = Some(format!("localhost:{}", edge.iroh_addr().port()));
    })
    .await;
    wait_state(&rig.link, |s| s.connected && s.listeners == bound(&[p])).await;
    echoes(&mut visitor(p).await, b"by name").await;
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn unresolvable_address_keeps_retrying() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let rig = rig_with(&[(p, echo)], &[p], |_, opts| {
        opts.address = Some("no-such-host.invalid:7842".into());
    })
    .await;
    stays_disconnected(&rig.link, Duration::from_secs(1)).await;
    // `shutdown` re-raises a panic of the link task.
    let started = Instant::now();
    timeout(Duration::from_secs(1), rig.link.shutdown())
        .await
        .expect("shutdown took longer than 1 s");
    assert!(started.elapsed() < Duration::from_secs(1));
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn connects_through_relay_without_address() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let (rig, _relay) = relay_rig(&[(p, echo)], None).await;
    wait_state(&rig.link, |s| s.connected && s.listeners == bound(&[p])).await;
    echoes(&mut visitor(p).await, b"via relay").await;
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn relay_covers_for_a_wrong_direct_address() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let nothing = format!("127.0.0.1:{}", free_udp_port()).parse().unwrap();
    let (rig, _relay) = relay_rig(&[(p, echo)], Some(nothing)).await;
    wait_state(&rig.link, |s| s.connected && s.listeners == bound(&[p])).await;
    echoes(&mut visitor(p).await, b"via relay").await;
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[test]
fn no_address_and_no_relay_is_rejected() {
    let id = SecretKey::generate().public();
    assert!(LinkOptions::new(id, None, Relay::Disabled).is_err());
    assert!(LinkOptions::new(id, None, Relay::N0).is_ok());
    let opts = LinkOptions::new(id, Some("192.0.2.1:7842".into()), Relay::Disabled).unwrap();
    assert_eq!(opts.dial_timeout, Duration::from_secs(10));
    assert_eq!(opts.connect_timeout, Duration::from_secs(5));
    assert_eq!(opts.backoff_min, Duration::from_millis(500));
    assert_eq!(opts.backoff_max, Duration::from_secs(30));
}

#[tokio::test]
async fn static_connector_rejects_an_unknown_key() {
    let connector = StaticConnector::new(Default::default());
    let header = StreamHeader {
        listener_id: 1,
        visitor: "198.51.100.9:50000".parse().unwrap(),
        local: "203.0.113.7:443".parse().unwrap(),
    };
    let err = connector.connect(tcp(80), &header).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn unknown_listener_resets_stream_only() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let fake = FakeEdge::bind().await;
    let (link, _desired, _endpoint) = fake.link(&[(p, echo)], &[p]).await;
    let mut s = fake.accept().await;
    let cfg = s.read_config().await;
    assert_eq!(cfg.generation, 1);
    assert_eq!(cfg.listeners.len(), 1);
    let id = cfg.listeners[0].id;
    assert_ne!(id, 9999);
    s.reply(&cfg).await;
    wait_state(&link, |st| st.connected).await;

    let (_send, mut recv) = s.open(9999).await;
    assert_eq!(
        reset_code(&mut recv).await,
        u64::from(RESET_UNKNOWN_LISTENER)
    );

    let (send, recv) = s.open(id).await;
    assert_eq!(stream_roundtrip(send, recv, b"ping").await, b"ping");
    assert!(s.conn.close_reason().is_none());
    link.shutdown().await;
}

#[tokio::test]
async fn garbage_header_resets_stream_only() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let fake = FakeEdge::bind().await;
    let (link, _desired, _endpoint) = fake.link(&[(p, echo)], &[p]).await;
    let mut s = fake.accept().await;
    let cfg = s.read_config().await;
    s.reply(&cfg).await;

    let (mut send, mut recv) = s.conn.open_bi().await.unwrap();
    send.write_all(&[0xff; 16]).await.unwrap();
    assert_eq!(reset_code(&mut recv).await, u64::from(RESET_BAD_HEADER));
    let stopped = timeout(STEP, send.stopped()).await.unwrap().unwrap();
    assert_eq!(
        stopped.map(|c| c.into_inner()),
        Some(u64::from(RESET_BAD_HEADER))
    );

    let (send, recv) = s.open(cfg.listeners[0].id).await;
    assert_eq!(stream_roundtrip(send, recv, b"ping").await, b"ping");
    assert!(s.conn.close_reason().is_none());
    assert!(link.state().borrow().connected);
    link.shutdown().await;
}

#[tokio::test]
async fn oversized_header_prefix_resets_stream_only() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let fake = FakeEdge::bind().await;
    let (link, _desired, _endpoint) = fake.link(&[(p, echo)], &[p]).await;
    let mut s = fake.accept().await;
    let cfg = s.read_config().await;
    s.reply(&cfg).await;

    // A 64 KiB length prefix and nothing after it.
    let (mut send, mut recv) = s.conn.open_bi().await.unwrap();
    send.write_all(&[0, 1, 0, 0]).await.unwrap();
    let opened = Instant::now();
    assert_eq!(reset_code(&mut recv).await, u64::from(RESET_BAD_HEADER));
    // Well under the 5 s header limit: refused on the prefix, not waited on.
    let waited = opened.elapsed();
    assert!(waited < Duration::from_secs(2), "{waited:?}");
    let stopped = timeout(STEP, send.stopped()).await.unwrap().unwrap();
    assert_eq!(
        stopped.map(|c| c.into_inner()),
        Some(u64::from(RESET_BAD_HEADER))
    );

    let (send, recv) = s.open(cfg.listeners[0].id).await;
    assert_eq!(stream_roundtrip(send, recv, b"ping").await, b"ping");
    assert!(s.conn.close_reason().is_none());
    link.shutdown().await;
}

#[tokio::test]
async fn missing_header_resets_stream_after_timeout() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let fake = FakeEdge::bind().await;
    let (link, _desired, _endpoint) = fake.link(&[(p, echo)], &[p]).await;
    let mut s = fake.accept().await;
    let cfg = s.read_config().await;
    s.reply(&cfg).await;

    // Half a length prefix makes the stream visible but never completes a header.
    let (mut slow_send, mut slow_recv) = s.conn.open_bi().await.unwrap();
    slow_send.write_all(&[0, 0]).await.unwrap();
    let opened = Instant::now();

    // The waiting stream does not hold up the next one.
    let (send, recv) = s.open(cfg.listeners[0].id).await;
    assert_eq!(stream_roundtrip(send, recv, b"ping").await, b"ping");

    assert_eq!(
        reset_code(&mut slow_recv).await,
        u64::from(RESET_BAD_HEADER)
    );
    let waited = opened.elapsed();
    assert!(
        waited >= Duration::from_millis(4500) && waited < Duration::from_secs(7),
        "{waited:?}"
    );
    assert!(s.conn.close_reason().is_none());
    link.shutdown().await;
}

#[tokio::test]
async fn stale_id_still_routes_after_config_change() {
    let echo = echo_server().await;
    let (p, q) = (free_tcp_port(), free_tcp_port());
    let fake = FakeEdge::bind().await;
    let (link, desired, _endpoint) = fake.link(&[(p, echo), (q, echo)], &[p]).await;
    let mut s = fake.accept().await;
    let cfg1 = s.read_config().await;
    assert_eq!(cfg1.listeners.len(), 1);
    let a = cfg1.listeners[0].id;
    s.reply(&cfg1).await;
    wait_state(&link, |st| st.generation == cfg1.generation).await;

    desired.send(vec![tcp(p), tcp(q)]).unwrap();
    // Read, so the link has certainly moved on, but neither applied nor acknowledged.
    let cfg2 = s.read_config().await;
    assert_eq!(cfg2.generation, cfg1.generation + 1);
    let ids: Vec<(u16, u32)> = cfg2.listeners.iter().map(|l| (l.port, l.id)).collect();
    assert_eq!(ids[0], (p, a));
    assert_eq!(ids[1].0, q);
    assert_ne!(ids[1].1, a);

    let (send, recv) = s.open(a).await;
    assert_eq!(stream_roundtrip(send, recv, b"stale").await, b"stale");
    link.shutdown().await;
}

#[tokio::test]
async fn shutdown_closes_with_shutdown_code() {
    let echo = echo_server().await;
    let p = free_tcp_port();
    let fake = FakeEdge::bind().await;
    let (link, _desired, endpoint) = fake.link(&[(p, echo)], &[p]).await;
    let mut s = fake.accept().await;
    let cfg = s.read_config().await;
    s.reply(&cfg).await;
    wait_state(&link, |st| st.connected).await;

    timeout(STEP, link.shutdown()).await.unwrap();
    let closed = timeout(STEP, s.conn.closed()).await.unwrap();
    match closed {
        ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code.into_inner(), u64::from(CLOSE_SHUTDOWN))
        }
        other => panic!("closed with {other}"),
    }
    assert!(!endpoint.is_closed());
    // No redial follows.
    assert!(
        timeout(Duration::from_millis(500), fake.endpoint.accept())
            .await
            .is_err()
    );
}
