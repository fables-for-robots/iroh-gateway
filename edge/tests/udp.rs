mod common;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use iroh::SecretKey;
use iroh::endpoint::Connection;
use iroh_gateway_edge::{Edge, EdgeHandle, EdgeOptions};
use iroh_gateway_proto::control::{BindState, ListenerStatus, Protocol, Status};
use iroh_gateway_proto::datagram::{
    Header, Packet, REASSEMBLY_BYTES, REASSEMBLY_WINDOW, Reassembler,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, sleep, timeout, timeout_at};

const GRACE: Duration = Duration::from_secs(5);
/// How long one attempt waits for its answer before sending again.
const ATTEMPT: Duration = Duration::from_millis(300);
/// How long a test waits before concluding that nothing arrives.
const QUIET: Duration = Duration::from_millis(300);

/// An edge with `customize` applied to its options and a fake operator connected to it.
async fn start(customize: impl FnOnce(&mut EdgeOptions)) -> (EdgeHandle, FakeOperator, SecretKey) {
    let key = SecretKey::generate();
    let mut opts = edge_options(key.public(), GRACE, 100);
    customize(&mut opts);
    let edge = Edge::spawn(opts).await.unwrap();
    let fake = FakeOperator::connect(key.clone(), edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    (edge, fake, key)
}

fn bound(st: &Status) -> bool {
    !st.listeners.is_empty() && st.listeners.iter().all(|l| l.state == BindState::Bound)
}

/// A port free for both TCP and UDP on loopback.
fn free_tcp_and_udp_port() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// Sends `payload` from `v` to port `p` until a datagram carrying it arrives on `conn`;
/// datagrams carrying anything else are skipped.
async fn send_until_datagram(
    v: &UdpSocket,
    p: u16,
    payload: &[u8],
    conn: &Connection,
) -> (Header, Bytes) {
    timeout(STEP, async {
        loop {
            v.send_to(payload, ("127.0.0.1", p)).await.unwrap();
            let deadline = Instant::now() + ATTEMPT;
            while let Ok((header, got)) = timeout_at(deadline, recv_datagram(conn)).await {
                if got == payload {
                    return (header, got);
                }
            }
        }
    })
    .await
    .expect("the visitor's packet did not arrive")
}

/// Sends packets from `v` to port `p`, each carrying the next value of `tag`, until one
/// arrives on `conn`; returns its header and its tag.
async fn send_tagged_until_datagram(
    v: &UdpSocket,
    p: u16,
    tag: &mut u32,
    conn: &Connection,
) -> (Header, u32) {
    let first = *tag;
    timeout(STEP, async {
        loop {
            v.send_to(&tag.to_be_bytes(), ("127.0.0.1", p))
                .await
                .unwrap();
            *tag += 1;
            let deadline = Instant::now() + ATTEMPT;
            while let Ok((header, got)) = timeout_at(deadline, recv_datagram(conn)).await {
                if let Ok(bytes) = <[u8; 4]>::try_from(got.as_ref()) {
                    let got = u32::from_be_bytes(bytes);
                    if got >= first {
                        return (header, got);
                    }
                }
            }
        }
    })
    .await
    .expect("the visitor's packet did not arrive")
}

/// Sends `payload` from `v` to port `p` until the whole packet arrives on `conn`; returns it
/// with the number of datagrams it came in.
async fn send_until_packet(
    v: &UdpSocket,
    p: u16,
    payload: &[u8],
    conn: &Connection,
) -> (Packet, u8) {
    let mut reassembler = Reassembler::new(REASSEMBLY_BYTES, REASSEMBLY_WINDOW);
    timeout(STEP, async {
        loop {
            v.send_to(payload, ("127.0.0.1", p)).await.unwrap();
            let deadline = Instant::now() + ATTEMPT;
            while let Ok((header, got)) = timeout_at(deadline, recv_datagram(conn)).await {
                let now = Instant::now().into_std();
                if let Some(packet) = reassembler.push(header, got, now)
                    && packet.payload == payload
                {
                    return (packet, header.count);
                }
            }
        }
    })
    .await
    .expect("the visitor's packet did not arrive")
}

/// Sends `payload` under `flow_id` on `conn` until `v` receives it; returns where it came from.
async fn reply_until_received(
    conn: &Connection,
    listener_id: u32,
    flow_id: u64,
    payload: &[u8],
    v: &UdpSocket,
) -> SocketAddr {
    let mut buf = vec![0u8; 65_535];
    timeout(STEP, async {
        let mut packet_id = 0u32;
        loop {
            send_packet(conn, listener_id, flow_id, packet_id, payload);
            packet_id += 1;
            let deadline = Instant::now() + ATTEMPT;
            while let Ok(r) = timeout_at(deadline, v.recv_from(&mut buf)).await {
                let (n, from) = r.unwrap();
                if buf[..n] == *payload {
                    return from;
                }
            }
        }
    })
    .await
    .expect("the reply did not reach the visitor")
}

/// Panics if `v` receives a packet carrying any of `unwanted` within `QUIET`.
async fn assert_not_received(v: &UdpSocket, unwanted: &[&[u8]]) {
    let mut buf = vec![0u8; 65_535];
    let deadline = Instant::now() + QUIET;
    while let Ok(r) = timeout_at(deadline, v.recv_from(&mut buf)).await {
        let (n, from) = r.unwrap();
        assert!(
            !unwanted.contains(&&buf[..n]),
            "{:?} from {from} reached the visitor",
            String::from_utf8_lossy(&buf[..n])
        );
    }
}

/// A UDP listener with id 1 on a free port, configured on `fake`.
async fn udp_port(fake: &mut FakeOperator) -> u16 {
    let p = free_udp_port();
    assert!(bound(&fake.push(cfg(1, &[(1, Protocol::Udp, p)])).await));
    p
}

#[tokio::test]
async fn udp_listener_binds_and_reports_bound() {
    let (edge, mut fake, _) = start(|_| {}).await;
    let p = free_udp_port();
    let st = fake.push(cfg(1, &[(3, Protocol::Udp, p)])).await;
    assert_eq!(st.generation, 1);
    assert_eq!(
        st.listeners,
        vec![ListenerStatus {
            id: 3,
            state: BindState::Bound
        }]
    );
    assert!(
        std::net::UdpSocket::bind(("127.0.0.1", p)).is_err(),
        "the edge does not hold port {p}"
    );
    edge.shutdown().await;
}

#[tokio::test]
async fn bind_error_of_a_udp_port_is_reported() {
    let (edge, mut fake, _) = start(|_| {}).await;
    let held = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let p = held.local_addr().unwrap().port();
    let q = free_udp_port();
    let st = fake
        .push(cfg(1, &[(1, Protocol::Udp, p), (2, Protocol::Udp, q)]))
        .await;
    assert!(
        matches!(st.listeners[0].state, BindState::Error(_)),
        "{:?}",
        st.listeners[0]
    );
    assert_eq!(st.listeners[1].state, BindState::Bound);
    drop(held);
    edge.shutdown().await;
}

#[tokio::test]
async fn visitor_packet_arrives_with_the_listener_id_and_a_flow_id() {
    let (edge, mut fake, _) = start(|_| {}).await;
    let p = free_udp_port();
    assert!(bound(&fake.push(cfg(1, &[(7, Protocol::Udp, p)])).await));
    let v = udp_visitor().await;
    let (header, payload) = send_until_datagram(&v, p, b"hello", &fake.conn).await;
    assert_eq!(header.listener_id, 7);
    assert_eq!((header.index, header.count), (0, 1));
    assert!(
        header.flow_id >= 1,
        "flow ids count from 1: {}",
        header.flow_id
    );
    assert_eq!(payload.as_ref(), b"hello");
    edge.shutdown().await;
}

#[tokio::test]
async fn one_visitor_is_one_flow_and_another_visitor_is_another() {
    let (edge, mut fake, _) = start(|_| {}).await;
    let p = udp_port(&mut fake).await;
    let a = udp_visitor().await;
    let b = udp_visitor().await;

    let mut tag = 0;
    let (first, first_tag) = send_tagged_until_datagram(&a, p, &mut tag, &fake.conn).await;
    let (second, second_tag) = send_tagged_until_datagram(&a, p, &mut tag, &fake.conn).await;
    assert_eq!(second.flow_id, first.flow_id);
    // One packet id per packet the visitor sent: n, n + 1 when nothing was resent.
    assert_eq!(
        second.packet_id.wrapping_sub(first.packet_id),
        second_tag - first_tag
    );

    let (other, _) = send_until_datagram(&b, p, b"from b", &fake.conn).await;
    assert_ne!(other.flow_id, first.flow_id);
    edge.shutdown().await;
}

#[tokio::test]
async fn reply_reaches_the_visitor_from_the_listener_port() {
    let (edge, mut fake, _) = start(|_| {}).await;
    let p = udp_port(&mut fake).await;
    let v = udp_visitor().await;
    let (header, _) = send_until_datagram(&v, p, b"ping", &fake.conn).await;
    let from = reply_until_received(&fake.conn, 1, header.flow_id, b"pong", &v).await;
    assert_eq!(from, SocketAddr::from(([127, 0, 0, 1], p)));
    edge.shutdown().await;
}

#[tokio::test]
async fn large_packet_is_fragmented_and_a_fragmented_reply_is_reassembled() {
    let (edge, mut fake, _) = start(|_| {}).await;
    let p = udp_port(&mut fake).await;
    let v = udp_visitor().await;

    let up: Vec<u8> = (0..9_000).map(|_| fastrand::u8(..)).collect();
    let (packet, fragments) = send_until_packet(&v, p, &up, &fake.conn).await;
    assert!(fragments > 1, "9,000 bytes came in one datagram");
    assert_eq!(packet.listener_id, 1);
    assert_eq!(packet.payload.as_ref(), up.as_slice());

    let down: Vec<u8> = (0..9_000).map(|_| fastrand::u8(..)).collect();
    let from = reply_until_received(&fake.conn, 1, packet.flow_id, &down, &v).await;
    assert_eq!(from.port(), p);
    edge.shutdown().await;
}

#[tokio::test]
async fn empty_packet_is_forwarded_both_ways() {
    let (edge, mut fake, _) = start(|_| {}).await;
    let p = udp_port(&mut fake).await;
    let v = udp_visitor().await;
    let (header, payload) = send_until_datagram(&v, p, b"", &fake.conn).await;
    assert_eq!((header.index, header.count), (0, 1));
    assert!(payload.is_empty());
    let from = reply_until_received(&fake.conn, 1, header.flow_id, b"", &v).await;
    assert_eq!(from.port(), p);
    edge.shutdown().await;
}

#[tokio::test]
async fn nothing_is_forwarded_before_the_first_config_of_a_session() {
    let (edge, mut fake1, key) = start(|_| {}).await;
    let p = udp_port(&mut fake1).await;
    let v = udp_visitor().await;
    send_until_datagram(&v, p, b"session 1", &fake1.conn).await;

    // Same key, as after an operator restart; it pushes no config yet.
    let mut fake2 = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    timeout(STEP, fake1.conn.closed()).await.unwrap();
    v.send_to(b"too early", ("127.0.0.1", p)).await.unwrap();
    let (old, new) = tokio::join!(
        timeout(QUIET, fake1.conn.read_datagram()),
        timeout(QUIET, fake2.conn.read_datagram()),
    );
    assert!(
        !matches!(old, Ok(Ok(_))),
        "a datagram reached the old session"
    );
    assert!(
        new.is_err(),
        "a datagram reached a session that has applied no config"
    );

    assert!(bound(&fake2.push(cfg(2, &[(1, Protocol::Udp, p)])).await));
    let (header, _) = send_until_datagram(&v, p, b"session 2", &fake2.conn).await;
    assert_eq!(header.listener_id, 1);
    edge.shutdown().await;
}

#[tokio::test]
async fn flows_restart_with_a_new_session() {
    let (edge, mut fake1, key) = start(|_| {}).await;
    let p = udp_port(&mut fake1).await;
    let v = udp_visitor().await;
    let (header, _) = send_until_datagram(&v, p, b"session 1", &fake1.conn).await;
    let flow = header.flow_id;

    let mut fake2 = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    timeout(STEP, fake1.conn.closed()).await.unwrap();
    assert!(bound(&fake2.push(cfg(2, &[(1, Protocol::Udp, p)])).await));

    // The new session's operator never issued this flow id.
    send_packet(&fake2.conn, 1, flow, 0, b"stale flow");
    assert_not_received(&v, &[b"stale flow"]).await;

    let (header, _) = send_until_datagram(&v, p, b"session 2", &fake2.conn).await;
    assert_ne!(header.flow_id, flow);
    reply_until_received(&fake2.conn, 1, header.flow_id, b"new flow", &v).await;
    edge.shutdown().await;
}

#[tokio::test]
async fn closed_udp_port_is_free_at_once_and_its_flows_are_gone() {
    let (edge, mut fake, _) = start(|_| {}).await;
    let p = udp_port(&mut fake).await;
    let v = udp_visitor().await;
    let (header, _) = send_until_datagram(&v, p, b"hello", &fake.conn).await;
    let flow = header.flow_id;

    let st = fake.push(cfg(2, &[])).await;
    assert!(st.listeners.is_empty());
    let held = std::net::UdpSocket::bind(("127.0.0.1", p))
        .expect("the port is still held after the Status");
    drop(held);

    // Open again, the port starts without flows: the same visitor gets a new one, and the
    // old flow id reaches nobody although the visitor is reachable again.
    assert!(bound(&fake.push(cfg(3, &[(1, Protocol::Udp, p)])).await));
    let (header, _) = send_until_datagram(&v, p, b"again", &fake.conn).await;
    assert_ne!(header.flow_id, flow);
    send_packet(&fake.conn, 1, flow, 0, b"old flow");
    assert_not_received(&v, &[b"old flow"]).await;
    reply_until_received(&fake.conn, 1, header.flow_id, b"back", &v).await;
    edge.shutdown().await;
}

#[tokio::test]
async fn readded_port_gets_the_new_listener_id() {
    let (edge, mut fake, _) = start(|_| {}).await;
    let p = udp_port(&mut fake).await;
    assert!(fake.push(cfg(2, &[])).await.listeners.is_empty());
    assert!(bound(&fake.push(cfg(3, &[(2, Protocol::Udp, p)])).await));
    let v = udp_visitor().await;
    let (header, _) = send_until_datagram(&v, p, b"hello", &fake.conn).await;
    assert_eq!(header.listener_id, 2);
    reply_until_received(&fake.conn, 2, header.flow_id, b"reply", &v).await;
    edge.shutdown().await;
}

#[tokio::test]
async fn tcp_and_udp_listeners_share_a_port_number() {
    let (edge, mut fake, _) = start(|_| {}).await;
    let p = free_tcp_and_udp_port();
    let st = fake
        .push(cfg(1, &[(1, Protocol::Tcp, p), (2, Protocol::Udp, p)]))
        .await;
    assert!(bound(&st), "{st:?}");
    assert_eq!(st.listeners.len(), 2);

    let mut tcp = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    tcp.write_all(b"tcp").await.unwrap();
    let (header, _send, _recv) = fake.accept_from(tcp.local_addr().unwrap()).await;
    assert_eq!(header.listener_id, 1);
    assert_eq!(header.local.port(), p);

    let v = udp_visitor().await;
    let (header, _) = send_until_datagram(&v, p, b"udp", &fake.conn).await;
    assert_eq!(header.listener_id, 2);
    edge.shutdown().await;
}

#[tokio::test]
async fn at_the_flow_cap_the_least_recently_used_flow_is_replaced() {
    let (edge, mut fake, _) = start(|o| o.max_udp_flows = 2).await;
    let p = udp_port(&mut fake).await;
    let (a, b, c) = (
        udp_visitor().await,
        udp_visitor().await,
        udp_visitor().await,
    );

    let fa = send_until_datagram(&a, p, b"a1", &fake.conn)
        .await
        .0
        .flow_id;
    let fb = send_until_datagram(&b, p, b"b1", &fake.conn)
        .await
        .0
        .flow_id;
    let again = send_until_datagram(&a, p, b"a2", &fake.conn)
        .await
        .0
        .flow_id;
    assert_eq!(again, fa);
    // B is now the least recently used flow; C takes its place.
    let fc = send_until_datagram(&c, p, b"c1", &fake.conn)
        .await
        .0
        .flow_id;
    assert!(fa != fb && fb != fc && fa != fc, "{fa} {fb} {fc}");

    send_packet(&fake.conn, 1, fb, 0, b"to b");
    tokio::join!(
        assert_not_received(&a, &[b"to b"]),
        assert_not_received(&b, &[b"to b"]),
        assert_not_received(&c, &[b"to b"]),
    );
    reply_until_received(&fake.conn, 1, fa, b"to a", &a).await;
    reply_until_received(&fake.conn, 1, fc, b"to c", &c).await;
    edge.shutdown().await;
}

#[tokio::test]
async fn idle_flow_is_forgotten_and_a_reply_keeps_it_alive() {
    let (edge, mut fake, _) = start(|o| o.udp_flow_idle = Duration::from_millis(300)).await;
    let p = udp_port(&mut fake).await;
    let v = udp_visitor().await;
    let (header, _) = send_until_datagram(&v, p, b"start", &fake.conn).await;
    let flow = header.flow_id;

    // Replies alone, every 100 ms, keep the flow well past its idle time and the edge's
    // expiry pass, which runs at least once a second.
    let mut buf = vec![0u8; 65_535];
    let until = Instant::now() + Duration::from_secs(2);
    let mut packet_id = 0;
    while Instant::now() < until {
        send_packet(&fake.conn, 1, flow, packet_id, b"keep");
        packet_id += 1;
        let _ = timeout(Duration::from_millis(100), v.recv_from(&mut buf)).await;
    }
    reply_until_received(&fake.conn, 1, flow, b"still there", &v).await;

    // Silence: past the idle time and the next expiry pass the flow is gone.
    sleep(Duration::from_millis(1_600)).await;
    send_packet(&fake.conn, 1, flow, packet_id, b"after idle");
    assert_not_received(&v, &[b"after idle"]).await;
    let (header, _) = send_until_datagram(&v, p, b"new flow", &fake.conn).await;
    assert_ne!(header.flow_id, flow);
    edge.shutdown().await;
}

#[tokio::test]
async fn rate_limit_drops_what_exceeds_it() {
    let (edge, mut fake, _) = start(|o| o.udp_rate_limit = Some(70_000)).await;
    let p = udp_port(&mut fake).await;
    let v = udp_visitor().await;
    let payload = vec![7u8; 9_000];
    for _ in 0..40 {
        v.send_to(&payload, ("127.0.0.1", p)).await.unwrap();
    }
    let mut reassembler = Reassembler::new(REASSEMBLY_BYTES, REASSEMBLY_WINDOW);
    let mut arrived = 0;
    while let Ok((header, got)) = timeout(Duration::from_secs(1), recv_datagram(&fake.conn)).await {
        if reassembler
            .push(header, got, Instant::now().into_std())
            .is_some()
        {
            arrived += 1;
        }
    }
    assert!((1..=20).contains(&arrived), "{arrived} packets arrived");
    edge.shutdown().await;
}

#[tokio::test]
async fn garbage_and_unknown_flows_are_ignored() {
    let (edge, mut fake, _) = start(|_| {}).await;
    let p = udp_port(&mut fake).await;
    let v = udp_visitor().await;
    let (header, _) = send_until_datagram(&v, p, b"hello", &fake.conn).await;
    let flow = header.flow_id;

    fake.conn
        .send_datagram(Bytes::from_static(b"short"))
        .unwrap();
    let mut no_fragments = Header {
        listener_id: 1,
        flow_id: flow,
        packet_id: 100,
        index: 0,
        count: 0,
    }
    .encode()
    .to_vec();
    no_fragments.extend_from_slice(b"count 0");
    fake.conn.send_datagram(Bytes::from(no_fragments)).unwrap();
    send_packet(&fake.conn, 1, flow + 1_000, 0, b"unknown flow");
    send_packet(&fake.conn, 2, flow, 1, b"other listener");
    assert_not_received(
        &v,
        &[b"short", b"count 0", b"unknown flow", b"other listener"],
    )
    .await;

    reply_until_received(&fake.conn, 1, flow, b"still served", &v).await;
    edge.shutdown().await;
}

#[tokio::test]
async fn grace_expiry_closes_udp_ports() {
    let key = SecretKey::generate();
    let edge = spawn_edge(key.public(), Duration::from_millis(200), 100).await;
    let mut fake = FakeOperator::connect(key, edge.endpoint_id(), edge.iroh_addr())
        .await
        .unwrap();
    let p = udp_port(&mut fake).await;
    assert!(std::net::UdpSocket::bind(("127.0.0.1", p)).is_err());

    fake.conn.close(0u32.into(), b"");
    sleep(Duration::from_secs(1)).await;
    std::net::UdpSocket::bind(("127.0.0.1", p)).expect("the port is still held after grace");
    edge.shutdown().await;
}
