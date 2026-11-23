//! The set of public ports an edge has open, driven by `Config` messages.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use iroh_gateway_proto::control::{
    BindState, Config, ListenerKey, ListenerStatus, Protocol, Status,
};
use iroh_gateway_proto::tcp::set_keepalive_and_nodelay;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

const ACCEPTED_QUEUE: usize = 1024;

/// A visitor connection accepted on a public port.
pub struct Accepted {
    pub listener_id: u32,
    pub stream: TcpStream,
    /// Canonical: an IPv4-mapped IPv6 address is turned into IPv4.
    pub visitor: SocketAddr,
    /// Canonical local address.
    pub local: SocketAddr,
    /// Held for the connection's life; releases its slot in the connection cap on drop.
    pub permit: OwnedSemaphorePermit,
}

/// Turns an IPv4-mapped IPv6 address into plain IPv4.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

struct Bound {
    id: Arc<AtomicU32>,
    task: JoinHandle<()>,
}

impl Drop for Bound {
    fn drop(&mut self) {
        // Aborting drops the TcpListener, which closes the port.
        self.task.abort();
    }
}

pub struct ListenerSet {
    bind_ip: IpAddr,
    permits: Arc<Semaphore>,
    tx: mpsc::Sender<Accepted>,
    bound: HashMap<ListenerKey, Bound>,
}

impl ListenerSet {
    pub fn new(bind_ip: IpAddr, max_connections: usize) -> (Self, mpsc::Receiver<Accepted>) {
        let (tx, rx) = mpsc::channel(ACCEPTED_QUEUE);
        let set = Self {
            bind_ip,
            permits: Arc::new(Semaphore::new(max_connections)),
            tx,
            bound: HashMap::new(),
        };
        (set, rx)
    }

    /// Makes the open ports match `cfg` and reports the result.
    pub async fn apply(&mut self, cfg: &Config) -> Status {
        // Close ports that are no longer wanted. Established connections are untouched.
        self.bound
            .retain(|key, _| cfg.listeners.iter().any(|l| l.key() == *key));

        let mut listeners = Vec::with_capacity(cfg.listeners.len());
        for l in &cfg.listeners {
            let key = l.key();
            let state = if let Some(b) = self.bound.get(&key) {
                b.id.store(l.id, Ordering::Relaxed);
                BindState::Bound
            } else if l.protocol == Protocol::Udp {
                BindState::Error("udp is not supported by this edge version".to_string())
            } else {
                match TcpListener::bind(SocketAddr::new(self.bind_ip, l.port)).await {
                    Ok(listener) => {
                        let id = Arc::new(AtomicU32::new(l.id));
                        let task = tokio::spawn(accept_loop(
                            listener,
                            id.clone(),
                            self.permits.clone(),
                            self.tx.clone(),
                        ));
                        self.bound.insert(key, Bound { id, task });
                        BindState::Bound
                    }
                    Err(e) => BindState::Error(e.to_string()),
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

    pub fn close_all(&mut self) {
        self.bound.clear();
    }

    pub fn bound(&self) -> Vec<ListenerKey> {
        let mut keys: Vec<_> = self.bound.keys().copied().collect();
        keys.sort_by_key(|k| k.port);
        keys
    }
}

async fn accept_loop(
    listener: TcpListener,
    id: Arc<AtomicU32>,
    permits: Arc<Semaphore>,
    tx: mpsc::Sender<Accepted>,
) {
    loop {
        let (stream, visitor) = match listener.accept().await {
            Ok(x) => x,
            // Transient accept errors (fd exhaustion, aborted handshakes): back off briefly.
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue; // cap reached: dropping the stream closes the visitor
        };
        set_keepalive_and_nodelay(&stream);
        let Ok(local) = stream.local_addr() else {
            continue;
        };
        let accepted = Accepted {
            listener_id: id.load(Ordering::Relaxed),
            stream,
            visitor: canonical(visitor),
            local: canonical(local),
            permit,
        };
        match tx.try_send(accepted) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {} // dropped: visitor closed, permit freed
            Err(mpsc::error::TrySendError::Closed(_)) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_gateway_proto::control::Listener;
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

    fn new_set(max: usize) -> (ListenerSet, mpsc::Receiver<Accepted>) {
        ListenerSet::new("127.0.0.1".parse().unwrap(), max)
    }

    /// Connects until the port refuses (an aborted accept task may need a moment to drop).
    async fn refused(p: u16) -> std::io::ErrorKind {
        for _ in 0..50 {
            match TcpStream::connect(("127.0.0.1", p)).await {
                Err(e) => return e.kind(),
                Ok(_) => tokio::time::sleep(Duration::from_millis(20)).await,
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
        assert_eq!(refused(p).await, std::io::ErrorKind::ConnectionRefused);
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
    async fn udp_listener_reports_unsupported() {
        let (mut set, _rx) = new_set(10);
        let st = set.apply(&cfg(1, &[(1, Protocol::Udp, 5353)])).await;
        assert_eq!(
            st.listeners[0].state,
            BindState::Error("udp is not supported by this edge version".to_string())
        );
        assert!(set.bound().is_empty());
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
        set.close_all();
        assert!(set.bound().is_empty());
        assert_eq!(refused(p).await, std::io::ErrorKind::ConnectionRefused);
        assert_eq!(refused(q).await, std::io::ErrorKind::ConnectionRefused);
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

    #[test]
    fn visitor_address_is_canonical() {
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:4000".parse().unwrap();
        assert_eq!(canonical(mapped), "192.0.2.7:4000".parse().unwrap());
        let v6: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
        assert_eq!(canonical(v6), v6);
    }
}
