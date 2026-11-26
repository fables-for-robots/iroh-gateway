//! The set of public ports an edge has open, driven by `Config` messages.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use iroh_gateway_proto::control::{
    BindState, Config, ListenerKey, ListenerStatus, Protocol, Status,
};
use iroh_gateway_proto::datagram::MAX_PACKET;
use iroh_gateway_proto::tcp::set_keepalive_and_nodelay;
use iroh_gateway_proto::throttle::{LOG_EVERY, LogThrottle};
use prometheus::IntGauge;
use socket2::SockRef;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use crate::metrics::Metrics;
use crate::udp::{REPLY_QUEUE, Reply, UdpHub};

const ACCEPTED_QUEUE: usize = 1024;

/// A visitor connection accepted on a public port.
pub struct Accepted {
    /// The listener's id when the visitor was accepted.
    pub listener_id: u32,
    /// The listener the visitor connected to.
    pub key: ListenerKey,
    pub stream: TcpStream,
    /// Canonical: an IPv4-mapped IPv6 address is turned into IPv4.
    pub visitor: SocketAddr,
    /// Canonical local address.
    pub local: SocketAddr,
    /// Held for the connection's life.
    pub slot: Slot,
}

/// A visitor's slot in the connection cap, counted in `connections_open` until it is dropped,
/// which releases it.
pub struct Slot {
    _permit: OwnedSemaphorePermit,
    open: IntGauge,
}

impl Slot {
    fn new(permit: OwnedSemaphorePermit, metrics: &Metrics) -> Self {
        metrics.connections_total.inc();
        metrics.connections_open.inc();
        Self {
            _permit: permit,
            open: metrics.connections_open.clone(),
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.open.dec();
    }
}

/// Turns an IPv4-mapped IPv6 address into plain IPv4.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// An open port, counted in `listeners` until it is dropped.
struct Bound {
    id: Arc<AtomicU32>,
    task: JoinHandle<()>,
    open: IntGauge,
}

impl Bound {
    fn new(id: Arc<AtomicU32>, task: JoinHandle<()>, open: &IntGauge) -> Self {
        open.inc();
        Self {
            id,
            task,
            open: open.clone(),
        }
    }

    /// Aborts the port's task and returns once it is gone, and with it the port.
    async fn close(mut self) {
        self.task.abort();
        if let Err(e) = (&mut self.task).await
            && e.is_panic()
        {
            error!("listener task panicked: {e}");
        }
    }
}

impl Drop for Bound {
    fn drop(&mut self) {
        // Aborting drops the socket, which closes the port, once the runtime gets to it.
        self.task.abort();
        self.open.dec();
    }
}

pub struct ListenerSet {
    bind_ip: IpAddr,
    permits: Arc<Semaphore>,
    tx: mpsc::Sender<Accepted>,
    udp: Arc<UdpHub>,
    bound: HashMap<ListenerKey, Bound>,
    metrics: Metrics,
}

impl ListenerSet {
    pub fn new(
        bind_ip: IpAddr,
        max_connections: usize,
        udp: Arc<UdpHub>,
        metrics: Metrics,
    ) -> (Self, mpsc::Receiver<Accepted>) {
        let (tx, rx) = mpsc::channel(ACCEPTED_QUEUE);
        let set = Self {
            bind_ip,
            permits: Arc::new(Semaphore::new(max_connections)),
            tx,
            udp,
            bound: HashMap::new(),
            metrics,
        };
        (set, rx)
    }

    /// Makes the open ports match `cfg` and reports the result. Ports no longer wanted are
    /// closed before any new one is bound and before this returns.
    pub async fn apply(&mut self, cfg: &Config) -> Status {
        // Close ports that are no longer wanted. Established connections are untouched.
        let removed: Vec<(ListenerKey, Bound)> = self
            .bound
            .extract_if(|key, _| !cfg.listeners.iter().any(|l| l.key() == *key))
            .collect();
        for (key, b) in removed {
            self.close(key, b).await;
        }

        let mut listeners = Vec::with_capacity(cfg.listeners.len());
        for l in &cfg.listeners {
            let key = l.key();
            let state = if let Some(b) = self.bound.get(&key) {
                b.id.store(l.id, Ordering::Relaxed);
                BindState::Bound
            } else {
                let id = Arc::new(AtomicU32::new(l.id));
                let addr = SocketAddr::new(self.bind_ip, l.port);
                let task = match l.protocol {
                    Protocol::Tcp => TcpListener::bind(addr).await.map(|listener| {
                        tokio::spawn(accept_loop(
                            listener,
                            key,
                            id.clone(),
                            self.permits.clone(),
                            self.tx.clone(),
                            self.metrics.clone(),
                        ))
                    }),
                    Protocol::Udp => UdpSocket::bind(addr).await.map(|socket| {
                        self.udp.port_opened();
                        tokio::spawn(udp_loop(
                            socket,
                            l.port,
                            id.clone(),
                            self.udp.clone(),
                            self.metrics.clone(),
                        ))
                    }),
                };
                match task {
                    Ok(task) => {
                        let open = self.metrics.listeners.get(l.protocol);
                        self.bound.insert(key, Bound::new(id, task, open));
                        BindState::Bound
                    }
                    Err(e) => {
                        self.metrics.bind_failures.get(l.protocol).inc();
                        BindState::Error(e.to_string())
                    }
                }
            };
            listeners.push(ListenerStatus { id: l.id, state });
        }

        Status {
            generation: cfg.generation,
            listeners,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Closes every port; they are closed when this returns.
    pub async fn close_all(&mut self) {
        let all: Vec<(ListenerKey, Bound)> = self.bound.drain().collect();
        for (key, b) in all {
            self.close(key, b).await;
        }
    }

    /// Closes one port; a UDP port's flows go with it, once its task can make no new one.
    async fn close(&self, key: ListenerKey, b: Bound) {
        b.close().await;
        if key.protocol == Protocol::Udp {
            self.udp.forget_port(key.port);
        }
    }

    /// The id the last applied `Config` gave the listener on `key`, if it is still open.
    pub fn id_of(&self, key: ListenerKey) -> Option<u32> {
        self.bound.get(&key).map(|b| b.id.load(Ordering::Relaxed))
    }

    pub fn bound(&self) -> Vec<ListenerKey> {
        let mut keys: Vec<_> = self.bound.keys().copied().collect();
        keys.sort_by_key(|k| (k.port, k.protocol == Protocol::Udp));
        keys
    }
}

async fn accept_loop(
    listener: TcpListener,
    key: ListenerKey,
    id: Arc<AtomicU32>,
    permits: Arc<Semaphore>,
    tx: mpsc::Sender<Accepted>,
    metrics: Metrics,
) {
    let mut accept_errors = LogThrottle::new(LOG_EVERY);
    loop {
        let (stream, visitor) = match listener.accept().await {
            Ok(x) => x,
            // Transient accept errors (fd exhaustion, aborted handshakes): back off briefly.
            Err(e) => {
                if let Some(suppressed) = accept_errors.hit() {
                    warn!(
                        port = key.port,
                        suppressed, "accepting a visitor failed: {e}"
                    );
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            // Cap reached: dropping the stream closes the visitor.
            metrics.refused.cap.inc();
            continue;
        };
        let slot = Slot::new(permit, &metrics);
        set_keepalive_and_nodelay(&stream);
        let Ok(local) = stream.local_addr() else {
            continue;
        };
        let accepted = Accepted {
            listener_id: id.load(Ordering::Relaxed),
            key,
            stream,
            visitor: canonical(visitor),
            local: canonical(local),
            slot,
        };
        match tx.try_send(accepted) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Dropped: the visitor is closed and its slot freed.
                metrics.refused.queue_full.inc();
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return,
        }
    }
}

/// Owns one UDP port's socket: hands each visitor packet to the hub under the listener's
/// current id, and sends the replies the hub queues for the port. A reply the kernel does not
/// take at once is dropped and counted as a `send_error`.
async fn udp_loop(
    socket: UdpSocket,
    port: u16,
    id: Arc<AtomicU32>,
    hub: Arc<UdpHub>,
    metrics: Metrics,
) {
    let (replies_tx, mut replies) = mpsc::channel::<Reply>(REPLY_QUEUE);
    let mut buf = vec![0u8; MAX_PACKET];
    let mut recv_errors = LogThrottle::new(LOG_EVERY);
    let mut send_errors = LogThrottle::new(LOG_EVERY);
    let send_failures = &metrics.udp_dropped.send_error;
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => match received {
                Ok((n, visitor)) => hub.forward(port, &id, visitor, &buf[..n], &replies_tx),
                Err(e) => {
                    if let Some(suppressed) = recv_errors.hit() {
                        debug!(port, suppressed, "receiving a udp packet failed: {e}");
                    }
                }
            },
            // Never None: this task holds a sender.
            Some((visitor, payload)) = replies.recv() => {
                // Straight to the kernel, as a non-blocking send: awaiting `send_to` would stop
                // the port receiving while a send waits, and tokio's `try_send_to` refuses until
                // the reactor has reported the socket writable, which would drop its first
                // replies.
                match SockRef::from(&socket).send_to(&payload, &visitor.into()) {
                    Ok(_) => {
                        metrics.udp_packets.outbound.inc();
                        metrics.udp_bytes.outbound.inc_by(payload.len() as u64);
                    }
                    Err(e) => {
                        send_failures.inc();
                        if let Some(suppressed) = send_errors.hit() {
                            debug!(
                                port,
                                %visitor,
                                total = send_failures.get(),
                                suppressed,
                                "sending a udp reply failed: {e}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_gateway_proto::control::Listener;
    use iroh_gateway_proto::datagram::{MAX_UDP_FLOWS, UDP_FLOW_IDLE};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn free_port() -> u16 {
        let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    }

    fn cfg(generation: u64, ls: &[(u32, Protocol, u16)]) -> Config {
        Config {
            generation,
            listeners: ls
                .iter()
                .map(|&(id, protocol, port)| Listener { id, protocol, port })
                .collect(),
        }
    }

    fn hub() -> Arc<UdpHub> {
        UdpHub::new(MAX_UDP_FLOWS, UDP_FLOW_IDLE, None, Metrics::new())
    }

    fn new_set(max: usize) -> (ListenerSet, mpsc::Receiver<Accepted>) {
        ListenerSet::new("127.0.0.1".parse().unwrap(), max, hub(), Metrics::new())
    }

    /// A port free for both TCP and UDP on loopback, other than `not`.
    fn free_tcp_and_udp_port(not: u16) -> u16 {
        loop {
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = tcp.local_addr().unwrap().port();
            if port != not && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
                return port;
            }
        }
    }

    /// What one connection attempt to `p` fails with; panics if it succeeds.
    async fn refused_now(p: u16) -> std::io::ErrorKind {
        match TcpStream::connect(("127.0.0.1", p)).await {
            Err(e) => e.kind(),
            Ok(_) => panic!("port {p} still accepts"),
        }
    }

    /// Connects until the port refuses: a dropped set aborts its accept tasks without waiting.
    /// An attempt that races the close can be accepted, or reset while half open.
    async fn refused(p: u16) -> std::io::ErrorKind {
        for _ in 0..50 {
            match TcpStream::connect(("127.0.0.1", p)).await {
                Err(e) if e.kind() != std::io::ErrorKind::ConnectionReset => return e.kind(),
                _ => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        panic!("port {p} still accepts");
    }

    #[tokio::test]
    async fn binds_and_accepts() {
        let p = free_port();
        let (mut set, mut rx) = new_set(10);
        let st = set.apply(&cfg(1, &[(5, Protocol::Tcp, p)])).await;
        assert_eq!(st.generation, 1);
        assert_eq!(st.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            st.listeners,
            vec![ListenerStatus {
                id: 5,
                state: BindState::Bound
            }]
        );
        let c = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        let a = rx.recv().await.unwrap();
        assert_eq!(
            (a.listener_id, a.visitor, a.local.port()),
            (5, c.local_addr().unwrap(), p)
        );
    }

    #[tokio::test]
    async fn removed_listener_is_closed_and_refuses() {
        let p = free_port();
        let (mut set, _rx) = new_set(10);
        set.apply(&cfg(1, &[(1, Protocol::Tcp, p)])).await;
        assert_eq!(set.bound().len(), 1);
        let st = set.apply(&cfg(2, &[])).await;
        assert!(st.listeners.is_empty());
        assert!(set.bound().is_empty());
        assert_eq!(refused_now(p).await, std::io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn remove_then_add_same_port_rebinds() {
        let p = free_port();
        let (mut set, mut rx) = new_set(10);
        assert_eq!(
            set.apply(&cfg(1, &[(1, Protocol::Tcp, p)])).await.listeners[0].state,
            BindState::Bound
        );
        set.apply(&cfg(2, &[])).await;
        let st = set.apply(&cfg(3, &[(2, Protocol::Tcp, p)])).await;
        assert_eq!(st.listeners[0].state, BindState::Bound);
        let _c = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().listener_id, 2);
    }

    #[tokio::test]
    async fn kept_listener_survives_and_takes_new_id() {
        let p = free_port();
        let q = free_port();
        let (mut set, mut rx) = new_set(10);
        set.apply(&cfg(1, &[(1, Protocol::Tcp, p)])).await;
        let mut c1 = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        let mut a1 = rx.recv().await.unwrap();
        assert_eq!(a1.listener_id, 1);

        let st = set
            .apply(&cfg(2, &[(8, Protocol::Tcp, p), (9, Protocol::Tcp, q)]))
            .await;
        assert!(st.listeners.iter().all(|l| l.state == BindState::Bound));

        c1.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        a1.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        a1.stream.write_all(b"pong").await.unwrap();
        c1.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        let _c2 = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().listener_id, 8);
        let _c3 = TcpStream::connect(("127.0.0.1", q)).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().listener_id, 9);
    }

    #[tokio::test]
    async fn id_of_follows_the_last_config() {
        let p = free_port();
        let key = ListenerKey {
            protocol: Protocol::Tcp,
            port: p,
        };
        let (mut set, mut rx) = new_set(10);
        set.apply(&cfg(1, &[(1, Protocol::Tcp, p)])).await;
        let _c = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        let a = rx.recv().await.unwrap();
        assert_eq!((a.key, a.listener_id), (key, 1));
        assert_eq!(set.id_of(key), Some(1));
        set.apply(&cfg(2, &[(7, Protocol::Tcp, p)])).await;
        assert_eq!(set.id_of(key), Some(7));
        set.apply(&cfg(3, &[])).await;
        assert_eq!(set.id_of(key), None);
    }

    #[tokio::test]
    async fn removed_listener_keeps_established_connections() {
        let p = free_port();
        let (mut set, mut rx) = new_set(10);
        set.apply(&cfg(1, &[(1, Protocol::Tcp, p)])).await;
        let mut c = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        let mut a = rx.recv().await.unwrap();
        set.apply(&cfg(2, &[])).await;
        c.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        a.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
    }

    #[tokio::test]
    async fn bind_error_is_reported() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = held.local_addr().unwrap().port();
        let q = free_port();
        let (mut set, _rx) = new_set(10);
        let st = set
            .apply(&cfg(1, &[(1, Protocol::Tcp, p), (2, Protocol::Tcp, q)]))
            .await;
        assert!(matches!(st.listeners[0].state, BindState::Error(_)));
        assert_eq!(st.listeners[1].state, BindState::Bound);
        assert_eq!(set.bound().len(), 1);
    }

    #[tokio::test]
    async fn udp_and_tcp_ports_are_listed_in_port_then_protocol_order() {
        let p = free_tcp_and_udp_port(0);
        let q = free_tcp_and_udp_port(p);
        let (mut set, _rx) = new_set(10);
        let st = set
            .apply(&cfg(
                1,
                &[
                    (1, Protocol::Udp, q),
                    (2, Protocol::Tcp, p),
                    (3, Protocol::Udp, p),
                    (4, Protocol::Tcp, q),
                ],
            ))
            .await;
        assert!(st.listeners.iter().all(|l| l.state == BindState::Bound));
        let key = |protocol, port| ListenerKey { protocol, port };
        let (lo, hi) = (p.min(q), p.max(q));
        assert_eq!(
            set.bound(),
            vec![
                key(Protocol::Tcp, lo),
                key(Protocol::Udp, lo),
                key(Protocol::Tcp, hi),
                key(Protocol::Udp, hi),
            ]
        );
    }

    #[tokio::test]
    async fn the_first_udp_port_without_a_rate_limit_warns_once() {
        let p = free_tcp_and_udp_port(0);
        let q = free_tcp_and_udp_port(p);
        let udp = hub();
        let (mut set, _rx) = ListenerSet::new(
            "127.0.0.1".parse().unwrap(),
            10,
            udp.clone(),
            Metrics::new(),
        );
        set.apply(&cfg(1, &[(1, Protocol::Tcp, p)])).await;
        assert!(udp.unlimited_warning_due());
        let st = set
            .apply(&cfg(2, &[(1, Protocol::Tcp, p), (2, Protocol::Udp, p)]))
            .await;
        assert!(st.listeners.iter().all(|l| l.state == BindState::Bound));
        assert!(!udp.unlimited_warning_due());
        // With a rate limit, there is nothing to warn about.
        let limited = UdpHub::new(MAX_UDP_FLOWS, UDP_FLOW_IDLE, Some(1_000), Metrics::new());
        assert!(!limited.unlimited_warning_due());
        let (mut set, _rx) = ListenerSet::new(
            "127.0.0.1".parse().unwrap(),
            10,
            limited.clone(),
            Metrics::new(),
        );
        set.apply(&cfg(1, &[(1, Protocol::Udp, q)])).await;
        assert!(!limited.unlimited_warning_due());
    }

    #[tokio::test]
    async fn cap_closes_extra_visitors() {
        let p = free_port();
        let (mut set, mut rx) = new_set(2);
        set.apply(&cfg(1, &[(1, Protocol::Tcp, p)])).await;
        let _c1 = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        let _c2 = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        let a1 = rx.recv().await.unwrap();
        let _a2 = rx.recv().await.unwrap();

        let mut c3 = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_secs(1), c3.read(&mut buf))
            .await
            .expect("third visitor was not closed");
        assert!(matches!(r, Ok(0) | Err(_)));
        assert!(rx.try_recv().is_err());

        drop(a1);
        let _c4 = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        let a4 = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("fourth visitor not accepted")
            .unwrap();
        assert_eq!(a4.listener_id, 1);
    }

    #[tokio::test]
    async fn gone_receiver_closes_visitors() {
        let p = free_port();
        let (mut set, rx) = new_set(2);
        set.apply(&cfg(1, &[(1, Protocol::Tcp, p)])).await;
        drop(rx);
        let mut c = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_secs(1), c.read(&mut buf))
            .await
            .expect("visitor was not closed");
        assert!(matches!(r, Ok(0) | Err(_)));
    }

    #[tokio::test]
    async fn close_all_refuses_everything() {
        let p = free_port();
        let q = free_port();
        let (mut set, _rx) = new_set(10);
        set.apply(&cfg(1, &[(1, Protocol::Tcp, p), (2, Protocol::Tcp, q)]))
            .await;
        assert_eq!(set.bound().len(), 2);
        set.close_all().await;
        assert!(set.bound().is_empty());
        assert_eq!(refused_now(p).await, std::io::ErrorKind::ConnectionRefused);
        assert_eq!(refused_now(q).await, std::io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn dropping_the_set_closes_ports() {
        let p = free_port();
        let (mut set, _rx) = new_set(10);
        set.apply(&cfg(1, &[(1, Protocol::Tcp, p)])).await;
        drop(set);
        assert_eq!(refused(p).await, std::io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn accepted_socket_has_keepalive_and_nodelay() {
        use iroh_gateway_proto::tcp::{KEEPALIVE_IDLE, KEEPALIVE_INTERVAL, KEEPALIVE_PROBES};
        let p = free_port();
        let (mut set, mut rx) = new_set(10);
        set.apply(&cfg(1, &[(1, Protocol::Tcp, p)])).await;
        let _c = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        let a = rx.recv().await.unwrap();
        let sock = socket2::SockRef::from(&a.stream);
        assert!(sock.keepalive().unwrap());
        assert!(sock.tcp_nodelay().unwrap());
        assert_eq!(sock.tcp_keepalive_time().unwrap(), KEEPALIVE_IDLE);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert_eq!(sock.tcp_keepalive_interval().unwrap(), KEEPALIVE_INTERVAL);
            assert_eq!(sock.tcp_keepalive_retries().unwrap(), KEEPALIVE_PROBES);
        }
    }

    #[tokio::test]
    async fn ipv4_visitor_on_dual_stack_listener_is_ipv4() {
        let p = free_port();
        let (mut set, mut rx) = ListenerSet::new("::".parse().unwrap(), 10, hub(), Metrics::new());
        let st = set.apply(&cfg(1, &[(1, Protocol::Tcp, p)])).await;
        assert_eq!(st.listeners[0].state, BindState::Bound);
        let c = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
        let a = rx.recv().await.unwrap();
        assert_eq!(a.visitor, c.local_addr().unwrap());
        assert!(a.visitor.is_ipv4(), "{}", a.visitor);
        assert_eq!(a.local, SocketAddr::from(([127, 0, 0, 1], p)));
    }

    #[test]
    fn visitor_address_is_canonical() {
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:4000".parse().unwrap();
        assert_eq!(canonical(mapped), "192.0.2.7:4000".parse().unwrap());
        let v6: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
        assert_eq!(canonical(v6), v6);
    }
}
