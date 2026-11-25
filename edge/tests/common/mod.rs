//! Harness for edge tests: an edge on loopback and a small fake operator that dials it.
// Each test binary uses its own share of the helpers.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use iroh::endpoint::{
    ConnectError, ConnectingError, Connection, ConnectionError, RecvStream, SendStream,
};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey};
use iroh_gateway_edge::{Edge, EdgeHandle, EdgeOptions, Metrics};
use iroh_gateway_proto::ALPN;
use iroh_gateway_proto::control::{BindState, Config, Listener, Protocol, Status, StreamHeader};
use iroh_gateway_proto::datagram::{
    Header, MAX_UDP_FLOWS, Packet, REASSEMBLY_BYTES, REASSEMBLY_WINDOW, Reassembler, UDP_FLOW_IDLE,
    split,
};
use iroh_gateway_proto::frame::{read_frame, write_frame};
use iroh_gateway_proto::transport::{MAX_TUNNEL_STREAMS, Relay, Role, endpoint_builder};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout, timeout_at};

/// Upper bound for any single step that should complete promptly on loopback.
pub const STEP: Duration = Duration::from_secs(10);
/// How long one attempt waits for its answer before sending again.
pub const ATTEMPT: Duration = Duration::from_millis(300);

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

pub fn edge_options(operator: EndpointId, grace: Duration, max_connections: usize) -> EdgeOptions {
    EdgeOptions {
        secret_key: SecretKey::generate(),
        operator,
        iroh_listen: "127.0.0.1:0".parse().unwrap(),
        public_bind: "127.0.0.1".parse().unwrap(),
        max_connections,
        tunnel_grace: grace,
        relay: Relay::Disabled,
        max_udp_flows: MAX_UDP_FLOWS,
        udp_flow_idle: UDP_FLOW_IDLE,
        udp_rate_limit: None,
        metrics: Metrics::new(),
    }
}

/// An edge on loopback with a fresh key and no relay.
pub async fn spawn_edge(
    operator: EndpointId,
    grace: Duration,
    max_connections: usize,
) -> EdgeHandle {
    Edge::spawn(edge_options(operator, grace, max_connections))
        .await
        .unwrap()
}

/// An edge whose only relay is `relay`, trusting the test relay's self-signed certificate.
pub async fn spawn_edge_via_relay(operator: EndpointId, relay: RelayUrl) -> EdgeHandle {
    let opts = EdgeOptions {
        relay: Relay::Custom(relay),
        ..edge_options(operator, Duration::from_secs(5), 100)
    };
    Edge::spawn_with(opts, |b| {
        b.ca_tls_config(CaTlsConfig::insecure_skip_verify())
    })
    .await
    .unwrap()
}

pub fn tcp_cfg(generation: u64, ports: &[u16]) -> Config {
    Config {
        generation,
        listeners: ports
            .iter()
            .zip(1..)
            .map(|(&port, id)| Listener {
                id,
                protocol: Protocol::Tcp,
                port,
            })
            .collect(),
    }
}

pub fn cfg(generation: u64, listeners: &[(u32, Protocol, u16)]) -> Config {
    Config {
        generation,
        listeners: listeners
            .iter()
            .map(|&(id, protocol, port)| Listener { id, protocol, port })
            .collect(),
    }
}

/// Whether every listener of `st` is bound, and there is at least one.
pub fn bound(st: &Status) -> bool {
    !st.listeners.is_empty() && st.listeners.iter().all(|l| l.state == BindState::Bound)
}

/// A UDP listener with id 1 on a free port, configured on `fake`.
pub async fn udp_port(fake: &mut FakeOperator) -> u16 {
    let p = free_udp_port();
    assert!(bound(&fake.push(cfg(1, &[(1, Protocol::Udp, p)])).await));
    p
}

/// A UDP visitor on loopback.
pub async fn udp_visitor() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

/// The next datagram on `conn`, decoded; panics after `STEP`.
pub async fn recv_datagram(conn: &Connection) -> (Header, Bytes) {
    let datagram = tokio::time::timeout(STEP, conn.read_datagram())
        .await
        .expect("no datagram")
        .unwrap();
    Header::decode(datagram).unwrap()
}

/// The next whole packet on `conn`; panics after `STEP`.
pub async fn recv_packet(conn: &Connection) -> Packet {
    let mut reassembler = Reassembler::new(REASSEMBLY_BYTES, REASSEMBLY_WINDOW);
    tokio::time::timeout(STEP, async {
        loop {
            let (header, payload) = recv_datagram(conn).await;
            let now = tokio::time::Instant::now().into_std();
            if let Some(packet) = reassembler.push(header, payload, now) {
                return packet;
            }
        }
    })
    .await
    .expect("no packet")
}

/// Sends `payload` from `v` to port `p` until the whole packet arrives on `conn`; returns it
/// with the number of datagrams it came in.
pub async fn send_until_packet(
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

/// The application close code of a closed connection, if the peer closed it.
pub fn app_close_code(err: &ConnectionError) -> Option<u64> {
    match err {
        ConnectionError::ApplicationClosed(close) => Some(close.error_code.into_inner()),
        _ => None,
    }
}

pub struct FakeOperator {
    /// Held so the connection lives: dropping an endpoint aborts its connections.
    #[allow(dead_code)]
    pub endpoint: Endpoint,
    pub conn: Connection,
    pub control_send: SendStream,
    pub control_recv: RecvStream,
}

impl FakeOperator {
    pub async fn connect(
        key: SecretKey,
        edge_id: EndpointId,
        edge_addr: SocketAddr,
    ) -> anyhow::Result<Self> {
        let endpoint = endpoint_builder(key, MAX_TUNNEL_STREAMS, &Relay::Disabled, Role::Operator)
            .bind_addr("127.0.0.1:0")?
            .bind()
            .await?;
        Self::dial(endpoint, EndpointAddr::new(edge_id).with_ip_addr(edge_addr)).await
    }

    pub async fn connect_via_relay(
        key: SecretKey,
        edge_id: EndpointId,
        relay: RelayUrl,
    ) -> anyhow::Result<Self> {
        let endpoint = endpoint_builder(
            key,
            MAX_TUNNEL_STREAMS,
            &Relay::Custom(relay.clone()),
            Role::Operator,
        )
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind_addr("127.0.0.1:0")?
        .bind()
        .await?;
        Self::dial(endpoint, EndpointAddr::new(edge_id).with_relay_url(relay)).await
    }

    /// A connection closed by the edge comes back as the bare `ConnectionError`, so tests can
    /// read its close code with `downcast_ref`.
    async fn dial(endpoint: Endpoint, addr: EndpointAddr) -> anyhow::Result<Self> {
        let connect = tokio::time::timeout(STEP, endpoint.connect(addr, ALPN))
            .await
            .context("connect timed out")?;
        let conn = match connect {
            Ok(conn) => conn,
            Err(ConnectError::Connecting {
                source: ConnectingError::ConnectionError { source, .. },
                ..
            })
            | Err(ConnectError::Connection { source, .. }) => return Err(source.into()),
            Err(e) => return Err(e.into()),
        };
        let (control_send, control_recv) = conn.open_bi().await?;
        Ok(Self {
            endpoint,
            conn,
            control_send,
            control_recv,
        })
    }

    pub async fn try_push(&mut self, cfg: Config) -> anyhow::Result<Status> {
        tokio::time::timeout(STEP, async {
            write_frame(&mut self.control_send, &cfg).await?;
            read_frame(&mut self.control_recv)
                .await?
                .context("control stream ended")
        })
        .await
        .context("push timed out")?
    }

    pub async fn push(&mut self, cfg: Config) -> Status {
        self.try_push(cfg).await.unwrap()
    }

    /// The next forwarded stream whose header arrives; streams reset before their header can
    /// be read (an aborted visitor) are skipped.
    pub async fn accept_stream(&self) -> (StreamHeader, SendStream, RecvStream) {
        tokio::time::timeout(STEP, async {
            loop {
                let (send, mut recv) = self.conn.accept_bi().await.unwrap();
                if let Ok(Some(header)) = read_frame::<_, StreamHeader>(&mut recv).await {
                    return (header, send, recv);
                }
            }
        })
        .await
        .expect("no forwarded stream")
    }

    /// The forwarded stream of the visitor at `visitor`, skipping streams of other visitors.
    pub async fn accept_from(&self, visitor: SocketAddr) -> (StreamHeader, SendStream, RecvStream) {
        loop {
            let (header, send, recv) = self.accept_stream().await;
            if header.visitor == visitor {
                return (header, send, recv);
            }
        }
    }
}
