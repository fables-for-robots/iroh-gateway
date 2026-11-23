//! Harness for edge tests: an edge on loopback and a small fake operator that dials it.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use iroh::endpoint::{
    ConnectError, ConnectingError, Connection, ConnectionError, RecvStream, SendStream,
};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey};
use iroh_gateway_edge::{Edge, EdgeHandle, EdgeOptions};
use iroh_gateway_proto::ALPN;
use iroh_gateway_proto::control::{Config, Listener, Protocol, Status, StreamHeader};
use iroh_gateway_proto::frame::{read_frame, write_frame};
use iroh_gateway_proto::transport::{MAX_TUNNEL_STREAMS, Relay, Role, endpoint_builder};

/// Upper bound for any single step that should complete promptly on loopback.
pub const STEP: Duration = Duration::from_secs(10);

pub fn free_tcp_port() -> u16 {
    let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

pub fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
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
