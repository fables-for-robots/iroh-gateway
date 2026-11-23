//! The public side of iroh-gateway: listeners that forward visitors into the tunnel.

pub mod listeners;
mod session;

use std::future::pending;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use anyhow::Context;
use iroh::endpoint::{Builder, Connection, Incoming, VarInt};
use iroh::{Endpoint, EndpointId, SecretKey};
use iroh_gateway_proto::transport::{Relay, Role, endpoint_builder};
use iroh_gateway_proto::{ALPN, CLOSE_REPLACED, CLOSE_SHUTDOWN, CLOSE_UNAUTHORIZED};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::time::Sleep;
use tracing::{debug, error, info, warn};

pub use listeners::{Accepted, ListenerSet, canonical};

use session::{ApplyRequest, Session};

/// Streams the operator may have open towards the edge: it needs only the control stream.
const OPERATOR_STREAMS: u32 = 4;
const APPLY_QUEUE: usize = 16;
/// Handshakes in progress beyond which new connection attempts are refused unanswered.
const MAX_PENDING_HANDSHAKES: usize = 64;
/// How long one handshake may take before it is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
        let supervisor = Supervisor {
            endpoint,
            operator: opts.operator,
            grace: opts.tunnel_grace,
            listeners,
            accepted,
            apply_tx,
            apply_rx,
            handshakes: JoinSet::new(),
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
            task,
        })
    }
}

/// A running edge. Dropping it shuts the edge down without waiting.
pub struct EdgeHandle {
    endpoint_id: EndpointId,
    iroh_addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl EdgeHandle {
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
    endpoint: Endpoint,
    operator: EndpointId,
    grace: Duration,
    listeners: ListenerSet,
    accepted: mpsc::Receiver<Accepted>,
    apply_tx: mpsc::Sender<ApplyRequest>,
    apply_rx: mpsc::Receiver<ApplyRequest>,
    /// Incoming connections until their handshake is done and their key checked.
    handshakes: JoinSet<Option<Connection>>,
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
                Some(done) = self.handshakes.join_next() => {
                    if let Some(Some(conn)) = log_panic(done, "handshake task") {
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

    /// Starts the handshake of a connection attempt, unless its address is not yet validated or
    /// too many handshakes are in progress.
    fn incoming(&mut self, incoming: Incoming) {
        if !incoming.remote_addr_validated() {
            // Stateless: the sender must prove it receives at its address before any state is
            // kept for it, so a spoofed source cannot take a handshake slot.
            if let Err(e) = incoming.retry() {
                debug!("retry failed: {e}");
            }
            return;
        }
        if self.handshakes.len() >= MAX_PENDING_HANDSHAKES {
            debug!(remote = ?incoming.remote_addr(), "refused: too many handshakes in progress");
            incoming.refuse();
            return;
        }
        self.handshakes.spawn(handshake(incoming, self.operator));
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
        self.handshakes.shutdown().await;
        self.listeners.close_all().await;
        self.endpoint.close().await;
        info!("edge stopped");
    }
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
