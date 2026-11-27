//! Harness for operator link tests: a real edge on loopback, a link to it, and a fake edge.

pub mod envtest;

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use iroh::endpoint::{Connection, ReadError, RecvStream, SendStream};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, EndpointId, SecretKey};
use iroh_gateway_edge::{Edge, EdgeHandle, EdgeOptions, Metrics};
use iroh_gateway_operator::tunnel::{
    EdgeLink, EdgeState, LinkHandle, LinkOptions, StaticConnector, UdpTarget, UdpTargets,
    bind_endpoint,
};
use iroh_gateway_proto::ALPN;
use iroh_gateway_proto::control::{
    BindState, Config, ListenerKey, ListenerStatus, Protocol, Status, StreamHeader,
};
use iroh_gateway_proto::datagram::{
    Header, MAX_PACKET, MAX_UDP_FLOWS, Packet, REASSEMBLY_BYTES, REASSEMBLY_WINDOW, Reassembler,
    UDP_FLOW_IDLE, split,
};
use iroh_gateway_proto::frame::{read_frame, write_frame};
use iroh_gateway_proto::transport::{MAX_TUNNEL_STREAMS, Relay, Role, endpoint_builder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

/// Upper bound for any single step that should complete promptly on loopback.
pub const STEP: Duration = Duration::from_secs(10);

/// The value of `series`, a metric name without the `iroh_gateway_operator_` prefix and with its
/// labels as rendered, in `text`; panics with the whole text if it is absent.
pub fn metric(text: &str, series: &str) -> f64 {
    let wanted = format!("iroh_gateway_operator_{series} ");
    let line = text
        .lines()
        .find(|line| line.starts_with(&wanted))
        .unwrap_or_else(|| panic!("no {series} in\n{text}"));
    line[wanted.len()..]
        .parse()
        .unwrap_or_else(|e| panic!("{line}: {e}"))
}

/// A runtime directory short enough for Unix socket paths on macOS.
pub fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("igw")
        .tempdir_in("/tmp")
        .unwrap()
}

/// A fresh self-signed certificate for `app.example.com` followed by its private key, as PEM:
/// what HAProxy's `crt` reads.
pub fn certificate_with_key() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["app.example.com".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    format!("{}{}", cert.pem(), key.serialize_pem())
}

/// The next port of this process's walk through 20000..30000. That range lies below every
/// ephemeral range (Linux 32768.., macOS 49152..), so neither a socket bound to port 0 nor the
/// source port of an outgoing connection, such as another test's, can take a port between the
/// moment a test picks it and the moment the test binds it. The walk starts at a random port and
/// hands out each port once, so two tests of one process never get the same one.
fn next_port() -> u16 {
    static NEXT: LazyLock<AtomicU16> = LazyLock::new(|| AtomicU16::new(fastrand::u16(0..10_000)));
    20_000 + NEXT.fetch_add(1, Ordering::Relaxed) % 10_000
}

/// A TCP port on loopback that nothing listens on and nothing takes by chance; see [`next_port`].
pub fn free_tcp_port() -> u16 {
    loop {
        let port = next_port();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// A UDP port on loopback that nothing is bound to and nothing takes by chance; see
/// [`next_port`].
pub fn free_udp_port() -> u16 {
    loop {
        let port = next_port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// A UDP port for a test that leaves it unbound for a while: no socket bound to port 0 meanwhile,
/// such as another test's flow socket, can take it. Every port of [`free_udp_port`] is one.
pub fn unassigned_udp_port() -> u16 {
    free_udp_port()
}

/// A port free for both TCP and UDP on 127.0.0.1.
pub fn free_tcp_and_udp_port() -> u16 {
    loop {
        let port = next_port();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
            && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok()
        {
            return port;
        }
    }
}

/// Echoes each connection until EOF, then closes it.
pub async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
                let _ = wr.shutdown().await;
            });
        }
    });
    addr
}

pub fn tcp(port: u16) -> ListenerKey {
    ListenerKey {
        protocol: Protocol::Tcp,
        port,
    }
}

pub fn udp(port: u16) -> ListenerKey {
    ListenerKey {
        protocol: Protocol::Udp,
        port,
    }
}

/// Answers every UDP packet with the same bytes to its sender, until the test ends.
pub async fn udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET];
        loop {
            // An ICMP error from an earlier answer surfaces here; it ends nothing.
            if let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..n], from).await;
            }
        }
    });
    addr
}

/// Sends `payload` to `to` from a fresh socket and returns the first answer from `to`; sends
/// again every 500 ms until one arrives, and panics after `STEP`.
pub async fn udp_roundtrip(to: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let local: SocketAddr = if to.is_ipv4() {
        "127.0.0.1:0".parse().unwrap()
    } else {
        "[::1]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(local).await.unwrap();
    udp_roundtrip_from(&socket, to, payload).await
}

/// [`udp_roundtrip`] from `socket`, so that every attempt is one flow of the same visitor.
///
/// The answer is the first from `to` whatever its payload, so that a misdelivered answer shows;
/// a test must therefore leave no answer queued on `socket` from an earlier exchange.
pub async fn udp_roundtrip_from(socket: &UdpSocket, to: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; MAX_PACKET];
    timeout(STEP, async {
        loop {
            let _ = socket.send_to(payload, to).await;
            let answer = timeout(Duration::from_millis(500), async {
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((n, from)) if from == to => return buf[..n].to_vec(),
                        _ => continue,
                    }
                }
            })
            .await;
            if let Ok(answer) = answer {
                return answer;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no answer from {to} within {STEP:?}"))
}

/// The next whole packet on `conn`, decoded and reassembled; panics after `STEP`.
pub async fn recv_packet(conn: &Connection) -> Packet {
    let mut reassembler = Reassembler::new(REASSEMBLY_BYTES, REASSEMBLY_WINDOW);
    timeout(STEP, async {
        loop {
            let datagram = conn.read_datagram().await.unwrap();
            let Ok((header, payload)) = Header::decode(datagram) else {
                continue;
            };
            let now = tokio::time::Instant::now().into_std();
            if let Some(packet) = reassembler.push(header, payload, now) {
                return packet;
            }
        }
    })
    .await
    .expect("no packet")
}

/// Sends `payload` as one packet, split by the connection's current datagram size.
pub fn send_packet(
    conn: &Connection,
    listener_id: u32,
    flow_id: u64,
    packet_id: u32,
    payload: &[u8],
) {
    let max = conn.max_datagram_size().expect("datagrams unsupported");
    for datagram in split(listener_id, flow_id, packet_id, payload, max).unwrap() {
        conn.send_datagram(datagram).unwrap();
    }
}

/// A UDP targets table: each `(port, target)` adds `target` with weight 1 to `udp(port)`.
pub fn udp_targets(targets: &[(u16, SocketAddr)]) -> UdpTargets {
    let mut table: UdpTargets = HashMap::new();
    for &(port, addr) in targets {
        table
            .entry(udp(port))
            .or_default()
            .push(UdpTarget { addr, weight: 1 });
    }
    table
}

pub fn edge_options(operator: EndpointId, key: SecretKey, iroh_listen: SocketAddr) -> EdgeOptions {
    EdgeOptions {
        secret_key: key,
        operator,
        iroh_listen,
        public_bind: "127.0.0.1".parse().unwrap(),
        max_connections: 100,
        tunnel_grace: Duration::from_millis(300),
        relay: Relay::Disabled,
        max_udp_flows: MAX_UDP_FLOWS,
        udp_flow_idle: UDP_FLOW_IDLE,
        udp_rate_limit: None,
        metrics: Metrics::new(),
    }
}

pub struct Rig {
    pub edge: EdgeHandle,
    pub link: LinkHandle,
    pub desired: watch::Sender<Vec<ListenerKey>>,
    pub udp: watch::Sender<UdpTargets>,
    pub operator_key: SecretKey,
    pub edge_key: SecretKey,
    /// Held so the link's connections live: dropping an endpoint aborts its connections.
    pub endpoint: Endpoint,
}

/// Edge on 127.0.0.1 (grace 300 ms), link with backoff 50 ms..200 ms, StaticConnector from
/// `targets`, Relay::Disabled; every target is desired from the start.
pub async fn rig(targets: &[(u16, SocketAddr)]) -> Rig {
    let ports: Vec<u16> = targets.iter().map(|&(p, _)| p).collect();
    rig_with(targets, &ports, |_, _| {}).await
}

/// [`rig`] with only `desired` desired at first, and a hook to change the link's options.
pub async fn rig_with(
    targets: &[(u16, SocketAddr)],
    desired: &[u16],
    customize: impl FnOnce(&EdgeHandle, &mut LinkOptions),
) -> Rig {
    rig_full(targets, desired, &[], &[], |_| {}, customize).await
}

/// [`rig_with`] with UDP targets and desired UDP ports (see [`udp_targets`]) and a hook to change
/// the edge's options as well.
pub async fn rig_full(
    targets: &[(u16, SocketAddr)],
    desired: &[u16],
    udp_targets: &[(u16, SocketAddr)],
    udp_desired: &[u16],
    customize_edge: impl FnOnce(&mut EdgeOptions),
    customize: impl FnOnce(&EdgeHandle, &mut LinkOptions),
) -> Rig {
    let operator_key = SecretKey::generate();
    let edge_key = SecretKey::generate();
    let mut edge_opts = edge_options(
        operator_key.public(),
        edge_key.clone(),
        "127.0.0.1:0".parse().unwrap(),
    );
    customize_edge(&mut edge_opts);
    let edge = Edge::spawn(edge_opts).await.unwrap();
    let endpoint = bind_endpoint(operator_key.clone(), &Relay::Disabled)
        .await
        .unwrap();
    let mut opts = LinkOptions::new(
        edge.endpoint_id(),
        Some(edge.iroh_addr().to_string()),
        Relay::Disabled,
    )
    .unwrap();
    opts.backoff_min = Duration::from_millis(50);
    opts.backoff_max = Duration::from_millis(200);
    customize(&edge, &mut opts);
    let (desired, udp, link) = spawn_link(
        endpoint.clone(),
        opts,
        targets,
        desired,
        udp_targets,
        udp_desired,
    );
    Rig {
        edge,
        link,
        desired,
        udp,
        operator_key,
        edge_key,
        endpoint,
    }
}

/// An edge and a link that reach each other only through an in-process relay, plus the relay
/// server, which must be held for as long as the rig is used.
pub async fn relay_rig(
    targets: &[(u16, SocketAddr)],
    direct: Option<SocketAddr>,
) -> (Rig, impl Sized + use<>) {
    relay_rig_with(targets, direct, |_| {}).await
}

/// [`relay_rig`] with the link's options changed by `customize`.
pub async fn relay_rig_with<F: FnOnce(&mut LinkOptions)>(
    targets: &[(u16, SocketAddr)],
    direct: Option<SocketAddr>,
    customize: F,
) -> (Rig, impl Sized + use<F>) {
    let (_map, relay_url, server) = iroh::test_utils::run_relay_server().await.unwrap();
    let relay = Relay::Custom(relay_url);
    let operator_key = SecretKey::generate();
    let edge_key = SecretKey::generate();
    let opts = EdgeOptions {
        relay: relay.clone(),
        ..edge_options(
            operator_key.public(),
            edge_key.clone(),
            "127.0.0.1:0".parse().unwrap(),
        )
    };
    let edge = Edge::spawn_with(opts, |b| {
        b.ca_tls_config(CaTlsConfig::insecure_skip_verify())
    })
    .await
    .unwrap();
    let endpoint = endpoint_builder(
        operator_key.clone(),
        MAX_TUNNEL_STREAMS,
        &relay,
        Role::Operator,
    )
    .ca_tls_config(CaTlsConfig::insecure_skip_verify())
    .bind_addr("127.0.0.1:0")
    .unwrap()
    .bind()
    .await
    .unwrap();
    let mut opts =
        LinkOptions::new(edge.endpoint_id(), direct.map(|a| a.to_string()), relay).unwrap();
    opts.backoff_min = Duration::from_millis(50);
    opts.backoff_max = Duration::from_millis(200);
    customize(&mut opts);
    let ports: Vec<u16> = targets.iter().map(|&(p, _)| p).collect();
    let (desired, udp, link) = spawn_link(endpoint.clone(), opts, targets, &ports, &[], &[]);
    let rig = Rig {
        edge,
        link,
        desired,
        udp,
        operator_key,
        edge_key,
        endpoint,
    };
    (rig, server)
}

/// A link with `desired` as TCP ports and then `udp_desired` as UDP ports desired, TCP
/// `targets` behind a `StaticConnector` and `udp_targets` as its UDP table.
pub fn spawn_link(
    endpoint: Endpoint,
    opts: LinkOptions,
    targets: &[(u16, SocketAddr)],
    desired: &[u16],
    udp_targets: &[(u16, SocketAddr)],
    udp_desired: &[u16],
) -> (
    watch::Sender<Vec<ListenerKey>>,
    watch::Sender<UdpTargets>,
    LinkHandle,
) {
    let keys = desired
        .iter()
        .map(|&p| tcp(p))
        .chain(udp_desired.iter().map(|&p| udp(p)))
        .collect();
    let (tx, rx) = watch::channel(keys);
    let (udp_tx, udp_rx) = watch::channel(self::udp_targets(udp_targets));
    let connector = StaticConnector::new(targets.iter().map(|&(p, a)| (tcp(p), a)).collect());
    let link = EdgeLink::spawn(endpoint, opts, rx, Arc::new(connector), udp_rx);
    (tx, udp_tx, link)
}

/// Waits up to 5 s for the link's state to satisfy `pred`; panics on timeout.
pub async fn wait_state(link: &LinkHandle, pred: impl Fn(&EdgeState) -> bool) -> EdgeState {
    let mut rx = link.state();
    let reached = timeout(Duration::from_secs(5), async {
        rx.wait_for(|s| pred(s)).await.map(|s| s.clone())
    })
    .await;
    match reached {
        Ok(Ok(state)) => state,
        Ok(Err(_)) => panic!("link task ended"),
        Err(_) => panic!(
            "state not reached within 5 s; last: {:?}",
            *link.state().borrow()
        ),
    }
}

/// Asserts that the link's state never becomes connected within `period`.
pub async fn stays_disconnected(link: &LinkHandle, period: Duration) {
    let mut rx = link.state();
    let connected = timeout(period, rx.wait_for(|s| s.connected)).await.is_ok();
    assert!(!connected, "link connected: {:?}", *rx.borrow());
}

pub async fn visitor(p: u16) -> TcpStream {
    timeout(STEP, TcpStream::connect(("127.0.0.1", p)))
        .await
        .expect("visitor connect timed out")
        .unwrap()
}

/// Writes `msg` and reads it back.
pub async fn echoes(v: &mut TcpStream, msg: &[u8]) {
    v.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    timeout(STEP, v.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(buf, msg);
}

/// Connects until the port refuses: a closed port can accept for a moment after it is closed.
pub async fn refused(p: u16) -> ErrorKind {
    for _ in 0..50 {
        match TcpStream::connect(("127.0.0.1", p)).await {
            Err(e) => return e.kind(),
            Ok(_) => sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("port {p} still accepts");
}

/// The reset code that ends `recv`; panics if it ends any other way.
pub async fn reset_code(recv: &mut RecvStream) -> u64 {
    let mut buf = [0u8; 64];
    timeout(STEP, async {
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!("stream finished instead of being reset"),
                Err(ReadError::Reset(code)) => return code.into_inner(),
                Err(e) => panic!("stream failed instead of being reset: {e}"),
            }
        }
    })
    .await
    .expect("stream was not reset")
}

/// A bare iroh endpoint speaking the edge side of the protocol by hand.
pub struct FakeEdge {
    pub endpoint: Endpoint,
}

impl FakeEdge {
    pub async fn bind() -> Self {
        let endpoint = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Edge)
            .alpns(vec![ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        Self { endpoint }
    }

    /// Binds an operator endpoint and spawns a link to this fake edge with `desired` desired.
    pub async fn link(
        &self,
        targets: &[(u16, SocketAddr)],
        desired: &[u16],
    ) -> (LinkHandle, watch::Sender<Vec<ListenerKey>>, Endpoint) {
        let (link, desired, _udp, endpoint) =
            self.link_with(targets, desired, &[], &[], |_| {}).await;
        (link, desired, endpoint)
    }

    /// [`FakeEdge::link`] with UDP targets and desired UDP ports (see [`spawn_link`]) and a hook
    /// to change the link's options; also returns the sender of the link's UDP table.
    pub async fn link_with(
        &self,
        targets: &[(u16, SocketAddr)],
        desired: &[u16],
        udp_targets: &[(u16, SocketAddr)],
        udp_desired: &[u16],
        customize: impl FnOnce(&mut LinkOptions),
    ) -> (
        LinkHandle,
        watch::Sender<Vec<ListenerKey>>,
        watch::Sender<UdpTargets>,
        Endpoint,
    ) {
        let endpoint = bind_endpoint(SecretKey::generate(), &Relay::Disabled)
            .await
            .unwrap();
        let addr = self.endpoint.bound_sockets()[0];
        let mut opts =
            LinkOptions::new(self.endpoint.id(), Some(addr.to_string()), Relay::Disabled).unwrap();
        opts.backoff_min = Duration::from_millis(50);
        opts.backoff_max = Duration::from_millis(200);
        customize(&mut opts);
        let (desired, udp, link) = spawn_link(
            endpoint.clone(),
            opts,
            targets,
            desired,
            udp_targets,
            udp_desired,
        );
        (link, desired, udp, endpoint)
    }

    /// Accepts the link's connection and its control stream.
    pub async fn accept(&self) -> FakeSession {
        timeout(STEP, async {
            let conn = self.endpoint.accept().await.unwrap().await.unwrap();
            let (control_send, control_recv) = conn.accept_bi().await.unwrap();
            FakeSession {
                conn,
                control_send,
                control_recv,
            }
        })
        .await
        .expect("link did not connect")
    }
}

pub struct FakeSession {
    pub conn: Connection,
    pub control_send: SendStream,
    pub control_recv: RecvStream,
}

impl FakeSession {
    pub async fn read_config(&mut self) -> Config {
        timeout(STEP, read_frame(&mut self.control_recv))
            .await
            .expect("no config")
            .unwrap()
            .expect("control stream ended")
    }

    /// Replies to `cfg` with every listener bound.
    pub async fn reply(&mut self, cfg: &Config) {
        let status = Status {
            generation: cfg.generation,
            listeners: cfg
                .listeners
                .iter()
                .map(|l| ListenerStatus {
                    id: l.id,
                    state: BindState::Bound,
                })
                .collect(),
            version: "fake".into(),
        };
        write_frame(&mut self.control_send, &status).await.unwrap();
    }

    /// Opens a visitor stream naming `listener_id`, for a visitor on public port `local_port`.
    pub async fn open(&self, listener_id: u32, local_port: u16) -> (SendStream, RecvStream) {
        let (mut send, recv) = self.conn.open_bi().await.unwrap();
        let header = StreamHeader {
            listener_id,
            visitor: "198.51.100.9:50000".parse().unwrap(),
            local: SocketAddr::from(([203, 0, 113, 7], local_port)),
        };
        write_frame(&mut send, &header).await.unwrap();
        (send, recv)
    }
}

/// Sends `msg` on a fake visitor stream, finishes it, and returns everything read back.
pub async fn stream_roundtrip(mut send: SendStream, mut recv: RecvStream, msg: &[u8]) -> Vec<u8> {
    send.write_all(msg).await.unwrap();
    send.finish().unwrap();
    timeout(STEP, recv.read_to_end(1024))
        .await
        .expect("stream roundtrip timed out")
        .unwrap()
}
