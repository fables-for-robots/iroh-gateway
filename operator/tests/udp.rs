//! The link's UDP forwarder against a hand-driven edge; every backend is a socket the test owns.

#[allow(dead_code)]
mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bytes::Bytes;
use common::*;
use iroh::Endpoint;
use iroh::endpoint::Connection;
use iroh_gateway_operator::tunnel::{LinkHandle, LinkOptions, UdpTarget, UdpTargets};
use iroh_gateway_proto::control::{Config, ListenerKey};
use iroh_gateway_proto::datagram::{
    HEADER_LEN, Header, MAX_PACKET, Packet, REASSEMBLY_BYTES, REASSEMBLY_WINDOW, Reassembler, split,
};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Instant, sleep, timeout};

/// How long a test waits to conclude that nothing arrives.
const QUIET: Duration = Duration::from_millis(300);
/// How long a test waits for a packet before it sends again.
const RESEND: Duration = Duration::from_millis(500);

/// A link to a fake edge that has answered the link's first config.
struct Setup {
    link: LinkHandle,
    desired: watch::Sender<Vec<ListenerKey>>,
    udp: watch::Sender<UdpTargets>,
    s: FakeSession,
    cfg: Config,
    /// Held so the connections live.
    _endpoint: Endpoint,
    _fake: FakeEdge,
}

impl Setup {
    /// The id the first config gave `key`.
    fn id(&self, key: ListenerKey) -> u32 {
        self.cfg
            .listeners
            .iter()
            .find(|l| l.key() == key)
            .unwrap_or_else(|| panic!("{key:?} is not in {:?}", self.cfg))
            .id
    }

    fn conn(&self) -> &Connection {
        &self.s.conn
    }

    /// Drops the sender of the link's UDP table, which closes the channel.
    fn close_udp(&mut self) {
        self.udp = watch::Sender::new(UdpTargets::new());
    }

    /// The link is still connected and the edge's connection still open.
    fn assert_up(&self) {
        assert!(self.link.state().borrow().connected);
        assert!(self.s.conn.close_reason().is_none());
    }

    async fn shutdown(self) {
        self.link.shutdown().await;
    }
}

/// `tcp_ports` and then `udp_ports` desired, `targets` as the UDP table (weight 1 each).
async fn setup(
    tcp_ports: &[u16],
    udp_ports: &[u16],
    targets: &[(u16, SocketAddr)],
    customize: impl FnOnce(&mut LinkOptions),
) -> Setup {
    let fake = FakeEdge::bind().await;
    let (link, desired, udp, endpoint) = fake
        .link_with(&[], tcp_ports, targets, udp_ports, customize)
        .await;
    let mut s = fake.accept().await;
    let cfg = s.read_config().await;
    s.reply(&cfg).await;
    wait_state(&link, |st| st.connected).await;
    Setup {
        link,
        desired,
        udp,
        s,
        cfg,
        _endpoint: endpoint,
        _fake: fake,
    }
}

async fn backend() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

fn addr(socket: &UdpSocket) -> SocketAddr {
    socket.local_addr().unwrap()
}

fn target(socket: &UdpSocket, weight: u32) -> UdpTarget {
    UdpTarget {
        addr: addr(socket),
        weight,
    }
}

fn next_packet_id() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Waits up to `wait` for `payload` at `backend` and returns where it came from. Skips other
/// packets, but panics on one in `forbidden`.
async fn arrival(
    backend: &UdpSocket,
    payload: &[u8],
    forbidden: &[&[u8]],
    wait: Duration,
) -> Option<SocketAddr> {
    let mut buf = vec![0u8; MAX_PACKET];
    timeout(wait, async {
        loop {
            let Ok((n, from)) = backend.recv_from(&mut buf).await else {
                continue;
            };
            let got = &buf[..n];
            assert!(
                !forbidden.contains(&got),
                "{:?} reached {}",
                String::from_utf8_lossy(got),
                addr(backend)
            );
            if got == payload {
                return from;
            }
        }
    })
    .await
    .ok()
}

/// Asserts that none of `payloads` reaches `backend` within [`QUIET`].
async fn nothing_arrives(backend: &UdpSocket, payloads: &[&[u8]]) {
    // A payload no one sends: the wait runs to its end unless a forbidden one comes.
    assert!(
        arrival(backend, b"\0never", payloads, QUIET)
            .await
            .is_none()
    );
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
    deliver_after(conn, &[], listener_id, flow_id, payload, backend).await
}

/// [`deliver`], sending every packet of `bad` (listener id, flow id, payload) before each
/// attempt; panics if one of them reaches `backend`. Once `payload` arrives, the forwarder has
/// had the bad packets sent before it.
async fn deliver_after(
    conn: &Connection,
    bad: &[(u32, u64, &[u8])],
    listener_id: u32,
    flow_id: u64,
    payload: &[u8],
    backend: &UdpSocket,
) -> SocketAddr {
    let forbidden: Vec<&[u8]> = bad.iter().map(|&(_, _, p)| p).collect();
    timeout(STEP, async {
        loop {
            for &(id, flow, p) in bad {
                send_packet(conn, id, flow, next_packet_id(), p);
            }
            send_packet(conn, listener_id, flow_id, next_packet_id(), payload);
            if let Some(from) = arrival(backend, payload, &forbidden, RESEND).await {
                return from;
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{:?} did not reach {}",
            String::from_utf8_lossy(payload),
            addr(backend)
        )
    })
}

/// Waits up to `wait` for a whole packet with `payload` on `conn`, skipping others.
async fn packet_with(conn: &Connection, payload: &[u8], wait: Duration) -> Option<Packet> {
    let mut reassembler = Reassembler::new(REASSEMBLY_BYTES, REASSEMBLY_WINDOW);
    timeout(wait, async {
        loop {
            let datagram = conn.read_datagram().await.unwrap();
            let Ok((header, part)) = Header::decode(datagram) else {
                continue;
            };
            let now = Instant::now().into_std();
            if let Some(packet) = reassembler.push(header, part, now)
                && packet.payload == payload
            {
                return packet;
            }
        }
    })
    .await
    .ok()
}

/// `backend` sends `payload` to `to` until it arrives on `conn`; the packet it arrived as.
async fn reply(conn: &Connection, backend: &UdpSocket, to: SocketAddr, payload: &[u8]) -> Packet {
    timeout(STEP, async {
        loop {
            backend.send_to(payload, to).await.unwrap();
            if let Some(packet) = packet_with(conn, payload, RESEND).await {
                return packet;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{:?} did not come back", String::from_utf8_lossy(payload)))
}

/// Asserts that no packet with `payload` arrives on `conn` within [`QUIET`].
async fn no_packet(conn: &Connection, payload: &[u8]) {
    let got = packet_with(conn, payload, QUIET).await;
    assert!(got.is_none(), "{got:?} came back");
}

/// Waits until UDP port `from.port()` is free: the flow's socket there is closed.
async fn closed(from: SocketAddr) {
    timeout(STEP, async {
        while std::net::UdpSocket::bind(("0.0.0.0", from.port())).is_err() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the flow's socket {from} stayed open"));
}

#[tokio::test]
async fn packet_reaches_the_backend_and_the_reply_returns_under_the_flow() {
    let a = backend().await;
    let mut t = setup(&[], &[5300], &[(5300, addr(&a))], |_| {}).await;
    let id = t.id(udp(5300));
    let from = deliver(t.conn(), id, 7, b"ping", &a).await;
    assert!(from.ip().is_loopback(), "{from}");
    let back = reply(t.conn(), &a, from, b"pong").await;
    assert_eq!((back.listener_id, back.flow_id), (id, 7));
    // The flow keeps its socket, and a closed table keeps its last value.
    t.close_udp();
    assert_eq!(deliver(t.conn(), id, 7, b"again", &a).await, from);
    deliver(t.conn(), id, 8, b"new flow", &a).await;
    t.assert_up();
    t.shutdown().await;
}

#[tokio::test]
async fn two_flows_reach_the_backend_from_two_ports() {
    let a = backend().await;
    let t = setup(&[], &[5300], &[(5300, addr(&a))], |_| {}).await;
    let id = t.id(udp(5300));
    let one = deliver(t.conn(), id, 1, b"one", &a).await;
    let two = deliver(t.conn(), id, 2, b"two", &a).await;
    assert_ne!(one, two);
    assert_eq!(reply(t.conn(), &a, two, b"to two").await.flow_id, 2);
    assert_eq!(reply(t.conn(), &a, one, b"to one").await.flow_id, 1);
    t.shutdown().await;
}

#[tokio::test]
async fn fragmented_packet_is_reassembled_and_a_large_reply_is_fragmented() {
    let a = backend().await;
    let t = setup(&[], &[5300], &[(5300, addr(&a))], |_| {}).await;
    let id = t.id(udp(5300));
    let max = t.conn().max_datagram_size().unwrap();
    assert!(
        max < 9_000 + HEADER_LEN,
        "{max}: 9,000 bytes would fit one datagram"
    );
    let mut out = vec![0u8; 9_000];
    fastrand::fill(&mut out);
    let from = deliver(t.conn(), id, 1, &out, &a).await;
    let mut back = vec![0u8; 9_000];
    fastrand::fill(&mut back);
    let packet = reply(t.conn(), &a, from, &back).await;
    assert_eq!((packet.listener_id, packet.flow_id), (id, 1));
    assert_eq!(packet.payload.len(), 9_000);
    t.shutdown().await;
}

#[tokio::test]
async fn datagram_for_an_unknown_or_a_tcp_listener_id_is_dropped() {
    let a = backend().await;
    let t = setup(&[5300], &[5301], &[(5301, addr(&a))], |_| {}).await;
    let (tcp_id, udp_id) = (t.id(tcp(5300)), t.id(udp(5301)));
    assert_ne!(tcp_id, 9999);
    assert_ne!(udp_id, 9999);
    // The TCP listener's key gets a UDP target too: only the protocol check keeps packets
    // under its id from it.
    let mut table = udp_targets(&[(5301, addr(&a))]);
    table.insert(tcp(5300), vec![target(&a, 1)]);
    t.udp.send(table).unwrap();
    let bad: [(u32, u64, &[u8]); 2] = [(9999, 1, b"unknown"), (tcp_id, 2, b"tcp")];
    deliver_after(t.conn(), &bad, udp_id, 3, b"canary", &a).await;
    nothing_arrives(&a, &[b"unknown", b"tcp"]).await;
    t.assert_up();
    t.shutdown().await;
}

#[tokio::test]
async fn known_flow_under_another_listener_id_is_dropped() {
    let (a, b) = (backend().await, backend().await);
    let t = setup(
        &[],
        &[5300, 5301],
        &[(5300, addr(&a)), (5301, addr(&b))],
        |_| {},
    )
    .await;
    let (p, q) = (t.id(udp(5300)), t.id(udp(5301)));
    let from = deliver(t.conn(), p, 5, b"first", &a).await;
    // Flow 5 belongs to the first listener: under the second one's id it goes nowhere.
    let again = deliver_after(t.conn(), &[(q, 5, b"other")], p, 5, b"second", &a).await;
    assert_eq!(again, from);
    nothing_arrives(&b, &[b"other"]).await;
    nothing_arrives(&a, &[b"other"]).await;
    t.assert_up();
    t.shutdown().await;
}

#[tokio::test]
async fn flow_keeps_its_backend_while_other_targets_change() {
    let (a, b) = (backend().await, backend().await);
    let t = setup(&[], &[5300], &[(5300, addr(&a))], |_| {}).await;
    let id = t.id(udp(5300));
    let from = deliver(t.conn(), id, 1, b"zero", &a).await;
    t.udp
        .send(udp_targets(&[(5300, addr(&a)), (5300, addr(&b))]))
        .unwrap();
    let payloads: Vec<Vec<u8>> = (1..=10)
        .map(|i| format!("packet {i}").into_bytes())
        .collect();
    for payload in &payloads {
        assert_eq!(deliver(t.conn(), id, 1, payload, &a).await, from);
    }
    let payloads: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
    nothing_arrives(&b, &payloads).await;
    t.shutdown().await;
}

#[tokio::test]
async fn flow_ends_when_its_backend_leaves_the_targets() {
    let (a, b) = (backend().await, backend().await);
    let t = setup(&[], &[5300], &[(5300, addr(&a))], |_| {}).await;
    let id = t.id(udp(5300));
    let from = deliver(t.conn(), id, 1, b"to a", &a).await;
    t.udp.send(udp_targets(&[(5300, addr(&b))])).unwrap();
    closed(from).await;
    a.send_to(b"late from a", from).await.unwrap();
    no_packet(t.conn(), b"late from a").await;
    let to_b = deliver(t.conn(), id, 1, b"to b", &b).await;
    nothing_arrives(&a, &[b"to b"]).await;
    assert_eq!(reply(t.conn(), &b, to_b, b"from b").await.flow_id, 1);
    t.shutdown().await;
}

#[tokio::test]
async fn flow_ends_when_its_listener_leaves_the_desired_set() {
    let (a, b) = (backend().await, backend().await);
    let mut t = setup(
        &[],
        &[5300, 5301],
        &[(5300, addr(&a)), (5301, addr(&b))],
        |_| {},
    )
    .await;
    let (p, q) = (t.id(udp(5300)), t.id(udp(5301)));
    let from = deliver(t.conn(), p, 1, b"one", &a).await;
    t.desired.send(vec![udp(5301)]).unwrap();
    let cfg = t.s.read_config().await;
    assert_eq!(cfg.listeners.len(), 1);
    assert_eq!(cfg.listeners[0].id, q);
    t.s.reply(&cfg).await;
    // The table still lists the first listener's backend; only its id is gone.
    closed(from).await;
    deliver_after(t.conn(), &[(p, 1, b"gone")], q, 2, b"canary", &b).await;
    nothing_arrives(&a, &[b"gone"]).await;
    a.send_to(b"late", from).await.unwrap();
    no_packet(t.conn(), b"late").await;
    t.assert_up();
    t.shutdown().await;
}

#[tokio::test]
async fn target_of_weight_zero_gets_nothing_and_no_target_drops() {
    let (a, b, c) = (backend().await, backend().await, backend().await);
    let t = setup(&[], &[5300, 5301], &[], |_| {}).await;
    let (p, q) = (t.id(udp(5300)), t.id(udp(5301)));
    let table = |first: Vec<UdpTarget>| -> UdpTargets {
        let mut table = udp_targets(&[(5301, addr(&c))]);
        if !first.is_empty() {
            table.insert(udp(5300), first);
        }
        table
    };
    t.udp
        .send(table(vec![target(&a, 0), target(&b, 1)]))
        .unwrap();
    let payloads: Vec<Vec<u8>> = (1..=20).map(|i| format!("flow {i}").into_bytes()).collect();
    for (flow, payload) in (1..).zip(&payloads) {
        deliver(t.conn(), p, flow, payload, &b).await;
    }
    let payloads: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
    nothing_arrives(&a, &payloads).await;

    // Only a target of weight 0: a new flow goes nowhere.
    t.udp.send(table(vec![target(&a, 0)])).unwrap();
    deliver_after(t.conn(), &[(p, 100, b"zero")], q, 1, b"canary 1", &c).await;
    nothing_arrives(&a, &[b"zero"]).await;
    nothing_arrives(&b, &[b"zero"]).await;

    // No target at all.
    t.udp.send(table(Vec::new())).unwrap();
    deliver_after(t.conn(), &[(p, 101, b"none")], q, 1, b"canary 2", &c).await;
    nothing_arrives(&a, &[b"none"]).await;
    nothing_arrives(&b, &[b"none"]).await;
    t.assert_up();
    t.shutdown().await;
}

#[tokio::test]
async fn idle_flow_is_closed_and_a_reply_keeps_it_open() {
    let idle = Duration::from_millis(300);
    let a = backend().await;
    let t = setup(&[], &[5300], &[(5300, addr(&a))], |opts| {
        opts.udp_flow_idle = idle
    })
    .await;
    let id = t.id(udp(5300));
    let from = deliver(t.conn(), id, 1, b"one", &a).await;
    // Replies alone keep the flow, past idle and the one-second sweep: the visitor is silent.
    for i in 0..15 {
        a.send_to(format!("reply {i}").as_bytes(), from)
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(deliver(t.conn(), id, 1, b"two", &a).await, from);
    // Silent both ways: the flow is closed within idle and one sweep.
    let quiet = Instant::now();
    closed(from).await;
    let took = quiet.elapsed();
    assert!(took < idle + Duration::from_millis(1_800), "{took:?}");
    let again = deliver(t.conn(), id, 1, b"three", &a).await;
    assert_ne!(again, from);
    t.shutdown().await;
}

#[tokio::test]
async fn flow_cap_replaces_the_least_recently_used() {
    let a = backend().await;
    let t = setup(&[], &[5300], &[(5300, addr(&a))], |opts| {
        opts.udp_max_flows = 2
    })
    .await;
    let id = t.id(udp(5300));
    let one = deliver(t.conn(), id, 1, b"one", &a).await;
    let two = deliver(t.conn(), id, 2, b"two", &a).await;
    // Flow 1 is used again, so flow 2 is the least recently used.
    assert_eq!(deliver(t.conn(), id, 1, b"one again", &a).await, one);
    let three = deliver(t.conn(), id, 3, b"three", &a).await;
    closed(two).await;
    assert_eq!(deliver(t.conn(), id, 1, b"one still", &a).await, one);
    a.send_to(b"to two", two).await.unwrap();
    no_packet(t.conn(), b"to two").await;
    assert_eq!(reply(t.conn(), &a, three, b"to three").await.flow_id, 3);
    t.shutdown().await;
}

#[tokio::test]
async fn malformed_datagrams_do_not_end_the_session() {
    let a = backend().await;
    let t = setup(&[], &[5300], &[(5300, addr(&a))], |_| {}).await;
    let id = t.id(udp(5300));
    let conn = t.conn();
    let header = |index, count| {
        let h = Header {
            listener_id: id,
            flow_id: 1,
            packet_id: next_packet_id(),
            index,
            count,
        };
        let mut d = h.encode().to_vec();
        d.extend_from_slice(b"bad");
        Bytes::from(d)
    };
    conn.send_datagram(Bytes::from_static(&[1, 2, 3, 4, 5]))
        .unwrap();
    for (index, count) in [(0, 0), (0, 65), (3, 2)] {
        conn.send_datagram(header(index, count)).unwrap();
    }
    // Incomplete packets of 60,000 bytes, each missing its last fragment: far more than the
    // reassembly budget holds.
    let max = conn.max_datagram_size().unwrap();
    for i in 0..200u32 {
        let datagrams = split(id, 1, next_packet_id(), &vec![i as u8; 60_000], max).unwrap();
        for datagram in &datagrams[..datagrams.len() - 1] {
            // A full send buffer drops the oldest; what arrives is enough.
            let _ = conn.send_datagram(datagram.clone());
        }
    }
    deliver(conn, id, 2, b"after", &a).await;
    t.assert_up();
    t.shutdown().await;
}

#[tokio::test]
async fn a_backend_that_is_not_listening_disturbs_no_other_flow() {
    let a = backend().await;
    let dead: SocketAddr = format!("127.0.0.1:{}", free_udp_port()).parse().unwrap();
    let t = setup(
        &[],
        &[5300, 5301],
        &[(5300, dead), (5301, addr(&a))],
        |_| {},
    )
    .await;
    let (p, q) = (t.id(udp(5300)), t.id(udp(5301)));
    // Each packet of flow 1 draws an ICMP error from the port nothing listens on.
    for _ in 0..5 {
        send_packet(t.conn(), p, 1, next_packet_id(), b"void");
        sleep(Duration::from_millis(20)).await;
    }
    let from = deliver(t.conn(), q, 2, b"alive", &a).await;
    assert_eq!(reply(t.conn(), &a, from, b"back").await.flow_id, 2);
    // Flow 1's task went on: once something listens there, its packets and replies pass.
    let late = UdpSocket::bind(dead).await.unwrap();
    let one = deliver(t.conn(), p, 1, b"now", &late).await;
    assert_eq!(reply(t.conn(), &late, one, b"hi").await.flow_id, 1);
    t.assert_up();
    t.shutdown().await;
}

#[tokio::test]
async fn ipv6_target_is_reached() {
    let Ok(a) = UdpSocket::bind("[::1]:0").await else {
        eprintln!("skipped: this host has no IPv6 loopback");
        return;
    };
    let t = setup(&[], &[5300], &[(5300, addr(&a))], |_| {}).await;
    let id = t.id(udp(5300));
    let from = deliver(t.conn(), id, 1, b"over ipv6", &a).await;
    assert!(from.is_ipv6(), "{from}");
    assert_eq!(reply(t.conn(), &a, from, b"back").await.flow_id, 1);
    t.shutdown().await;
}
