//! The public side of iroh-gateway: listeners that forward visitors into the tunnel.

pub mod listeners;
mod pending;
mod session;

use std::future::pending;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use anyhow::Context;
use iroh::endpoint::{Builder, Connection, Incoming, IncomingAddr, VarInt};
use iroh::{Endpoint, EndpointId, SecretKey};
use iroh_gateway_proto::transport::{Relay, Role, endpoint_builder};
use iroh_gateway_proto::{ALPN, CLOSE_REPLACED, CLOSE_SHUTDOWN, CLOSE_UNAUTHORIZED};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{AbortHandle, JoinError, JoinHandle, JoinSet};
use tokio::time::Sleep;
use tracing::{debug, error, info, warn};

pub use listeners::{Accepted, ListenerSet, canonical};

use pending::PendingHandshakes;
use session::{ApplyRequest, Session};

/// Streams the operator may have open towards the edge: it needs only the control stream.
const OPERATOR_STREAMS: u32 = 4;
const APPLY_QUEUE: usize = 16;
/// Handshakes in progress beyond which one is aborted to admit a new one.
const MAX_PENDING_HANDSHAKES: usize = 64;
/// How long one handshake may take before it is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The source key of handshakes that arrive over a relay or custom transport, which carry no
/// IP address; it cannot be the source address of a direct path.
const NO_IP: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

pub struct EdgeOptions {
    pub secret_key: SecretKey,
    /// The only operator served.
    pub operator: EndpointId,
    pub iroh_listen: SocketAddr,
    pub public_bind: IpAddr,
    pub max_connections: usize,
    /// How long listeners stay open without a configured session.
    pub tunnel_grace: Duration,
    pub relay: Relay,
}

pub struct Edge;

impl Edge {
    /// Binds the iroh endpoint and starts serving the configured operator.
    pub async fn spawn(opts: EdgeOptions) -> anyhow::Result<EdgeHandle> {
        Self::spawn_with(opts, |b| b).await
    }

    /// [`Edge::spawn`] with a hook applied to the endpoint builder before binding.
    ///
    /// For tests only (to trust a test relay's certificate); not for any other use.
    #[doc(hidden)]
    pub async fn spawn_with(
        opts: EdgeOptions,
        customize: impl FnOnce(Builder) -> Builder,
    ) -> anyhow::Result<EdgeHandle> {
        let builder = endpoint_builder(opts.secret_key, OPERATOR_STREAMS, &opts.relay, Role::Edge)
            .alpns(vec![ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr(opts.iroh_listen)
            .with_context(|| format!("invalid iroh listen address {}", opts.iroh_listen))?;
        let endpoint = customize(builder)
            .bind()
            .await
            .with_context(|| format!("binding iroh endpoint on {}", opts.iroh_listen))?;
        let iroh_addr = *endpoint
            .bound_sockets()
            .first()
            .context("iroh endpoint has no bound socket")?;
        let endpoint_id = endpoint.id();

        let (listeners, accepted) = ListenerSet::new(opts.public_bind, opts.max_connections);
        let (apply_tx, apply_rx) = mpsc::channel(APPLY_QUEUE);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (running, running_rx) = watch::channel(());
        let supervisor = Supervisor {
            _running: running,
            endpoint,
            operator: opts.operator,
            grace: opts.tunnel_grace,
            listeners,
            accepted,
            apply_tx,
            apply_rx,
            handshakes: JoinSet::new(),
            pending: PendingHandshakes::new(MAX_PENDING_HANDSHAKES),
            current: None,
            next_id: 0,
            grace_timer: None,
        };
        info!(id = %endpoint_id, addr = %iroh_addr, operator = %opts.operator, "edge started");
        let task = tokio::spawn(supervisor.run(shutdown_rx));
        Ok(EdgeHandle {
            endpoint_id,
            iroh_addr,
            shutdown: shutdown_tx,
            running: running_rx,
            task,
        })
    }
}

/// A running edge. Dropping it shuts the edge down without waiting.
pub struct EdgeHandle {
    endpoint_id: EndpointId,
    iroh_addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    /// Closed once the supervisor is gone, however it ended.
    running: watch::Receiver<()>,
    task: JoinHandle<()>,
}

impl EdgeHandle {
    /// Resolves once the edge has stopped. Before [`EdgeHandle::shutdown`] that happens only
    /// when it stops on its own: its endpoint closed or its task panicked.
    pub async fn stopped(&self) {
        let mut running = self.running.clone();
        while running.changed().await.is_ok() {}
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    pub fn iroh_addr(&self) -> SocketAddr {
        self.iroh_addr
    }

    /// Closes the session with `CLOSE_SHUTDOWN`, the listeners and the endpoint.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        log_panic(self.task.await, "edge supervisor");
    }
}

/// Owns the listeners, the visitor queue and the current session.
struct Supervisor {
    /// Dropped with the supervisor, which tells [`EdgeHandle::stopped`].
    _running: watch::Sender<()>,
    endpoint: Endpoint,
    operator: EndpointId,
    grace: Duration,
    listeners: ListenerSet,
    accepted: mpsc::Receiver<Accepted>,
    apply_tx: mpsc::Sender<ApplyRequest>,
    apply_rx: mpsc::Receiver<ApplyRequest>,
    /// Incoming connections until their handshake is done and their key checked.
    handshakes: JoinSet<Option<Connection>>,
    /// The handshakes in `handshakes` not yet done or aborted.
    pending: PendingHandshakes<PendingHandshake>,
    current: Option<Session>,
    next_id: u64,
    /// Runs while no session has been configured since the last one ended.
    grace_timer: Option<Pin<Box<Sleep>>>,
}

impl Supervisor {
    async fn run(mut self, mut shutdown: oneshot::Receiver<()>) {
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                incoming = self.endpoint.accept() => match incoming {
                    Some(incoming) => self.incoming(incoming),
                    None => {
                        warn!("iroh endpoint closed");
                        break;
                    }
                },
                Some(done) = self.handshakes.join_next_with_id() => {
                    let id = match &done {
                        Ok((id, _)) => *id,
                        Err(e) => e.id(),
                    };
                    // Already gone if it was evicted.
                    self.pending.remove(|p| p.task.id() == id);
                    if let Some((_, Some(conn))) = log_panic(done, "handshake task") {
                        self.install(conn);
                    }
                }
                () = session_ended(&mut self.current) => {
                    if let Some(session) = self.current.take() {
                        session.close_ended();
                    }
                    self.start_grace();
                }
                Some(req) = self.apply_rx.recv() => self.apply(req).await,
                Some(accepted) = self.accepted.recv() => self.visitor(accepted),
                () = grace_fired(&mut self.grace_timer) => {
                    self.grace_timer = None;
                    info!("tunnel grace expired: closing all listeners");
                    self.listeners.close_all().await;
                }
            }
        }
        self.shutdown().await;
    }

    /// Starts the handshake of a connection attempt once its address is validated. With
    /// `MAX_PENDING_HANDSHAKES` in progress, one is aborted to make room: the oldest of the
    /// source IP holding the most of them (see [`PendingHandshakes`]). A host with a single
    /// handshake in progress is evicted only when no IP holds more than one, so a flood from
    /// fewer IPs evicts its own handshakes, not that host's. A flood from 63 or more other
    /// distinct, validated source IPs can still evict that host's handshake. Handshakes over a
    /// relay or custom transport carry no IP and all share one key, `NO_IP`, so a flood
    /// through a relay evicts relayed handshakes, a relayed operator's among them.
    fn incoming(&mut self, incoming: Incoming) {
        if !incoming.remote_addr_validated() {
            // Stateless: the sender must prove it receives at its address before any state is
            // kept for it, so a spoofed source cannot take a handshake slot.
            if let Err(e) = incoming.retry() {
                debug!("retry failed: {e}");
            }
            return;
        }
        let remote = incoming.remote_addr();
        let ip = match &remote {
            IncomingAddr::Ip(addr) => addr.ip(),
            _ => NO_IP,
        };
        let task = self.handshakes.spawn(handshake(incoming, self.operator));
        if let Some(evicted) = self.pending.admit(ip, PendingHandshake { remote, task }) {
            // Cancelling the task drops its connection attempt, which closes it; `run` reaps
            // the task from `handshakes`.
            debug!(remote = ?evicted.remote, "too many handshakes in progress: aborted one");
            evicted.task.abort();
        }
    }

    /// Makes `conn` the current session, replacing any running one.
    fn install(&mut self, conn: Connection) {
        if let Some(old) = self.current.take() {
            old.close(CLOSE_REPLACED, b"replaced");
            self.start_grace();
        }
        let id = self.next_id;
        self.next_id += 1;
        self.current = Some(Session::start(id, conn, self.apply_tx.clone()));
    }

    /// Forwards `accepted` under the id the current session's last `Config` gave its listener;
    /// drops it (closing the visitor) when there is no such id.
    fn visitor(&mut self, mut accepted: Accepted) {
        let Some(session) = self.current.as_mut() else {
            debug!(visitor = %accepted.visitor, "visitor dropped: no session");
            return;
        };
        if !session.configured {
            debug!(visitor = %accepted.visitor, "visitor dropped: session not configured yet");
            return;
        }
        // The id is read now, not when the visitor was accepted: a `Config` applied since then
        // may have changed or removed it.
        let Some(id) = self.listeners.id_of(accepted.key) else {
            debug!(visitor = %accepted.visitor, "visitor dropped: listener closed");
            return;
        };
        accepted.listener_id = id;
        session.forward(accepted);
    }

    async fn apply(&mut self, req: ApplyRequest) {
        let Some(session) = self.current.as_mut().filter(|s| s.id == req.session) else {
            // From a session that has since been replaced or ended.
            return;
        };
        let status = self.listeners.apply(&req.cfg).await;
        session.configured = true;
        self.grace_timer = None;
        info!(
            session = session.id,
            generation = req.cfg.generation,
            listeners = ?self.listeners.bound(),
            "config applied"
        );
        let _ = req.reply.send(status);
    }

    /// Starts the grace timer unless it is already running.
    fn start_grace(&mut self) {
        if self.grace_timer.is_none() {
            self.grace_timer = Some(Box::pin(tokio::time::sleep(self.grace)));
        }
    }

    async fn shutdown(mut self) {
        if let Some(session) = self.current.take() {
            session.close(CLOSE_SHUTDOWN, b"shutdown");
        }
        self.handshakes.abort_all();
        while let Some(done) = self.handshakes.join_next().await {
            log_panic(done, "handshake task");
        }
        self.listeners.close_all().await;
        self.endpoint.close().await;
        info!("edge stopped");
    }
}

/// A handshake in progress, for [`PendingHandshakes`].
struct PendingHandshake {
    remote: IncomingAddr,
    task: AbortHandle,
}

/// Completes the handshake within `HANDSHAKE_TIMEOUT` and keeps the connection only if it is
/// from the pinned operator.
async fn handshake(incoming: Incoming, operator: EndpointId) -> Option<Connection> {
    let accepting = match incoming.accept() {
        Ok(accepting) => accepting,
        Err(e) => {
            debug!("incoming connection failed: {e}");
            return None;
        }
    };
    let conn = match tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            debug!("handshake failed: {e}");
            return None;
        }
        Err(_) => {
            debug!("handshake timed out after {HANDSHAKE_TIMEOUT:?}");
            return None;
        }
    };
    if conn.remote_id() != operator {
        debug!(remote = %conn.remote_id(), "rejected connection from an unpinned key");
        conn.close(VarInt::from_u32(CLOSE_UNAUTHORIZED), b"");
        return None;
    }
    Some(conn)
}

/// The task's output; a panic is logged at error, a cancellation dropped quietly.
pub(crate) fn log_panic<T>(joined: Result<T, JoinError>, task: &str) -> Option<T> {
    match joined {
        Ok(out) => Some(out),
        Err(e) => {
            if e.is_panic() {
                error!("{task} panicked: {e}");
            }
            None
        }
    }
}

async fn session_ended(current: &mut Option<Session>) {
    match current {
        Some(session) => session.ended().await,
        None => pending().await,
    }
}

async fn grace_fired(timer: &mut Option<Pin<Box<Sleep>>>) {
    match timer {
        Some(sleep) => sleep.as_mut().await,
        None => pending().await,
    }
}
