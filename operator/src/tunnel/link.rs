//! The link to one edge: dials it, redials with backoff, pushes the desired listeners, tracks the
//! state the edge reports, hands every visitor stream to a [`Connector`] and every session's UDP
//! datagrams to its forwarder.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Display;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use futures::StreamExt;
use iroh::endpoint::{
    ConnectError, ConnectingError, Connection, ConnectionError, RecvStream, SendStream, VarInt,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use iroh_gateway_proto::control::{
    BindState, Config, Listener, ListenerKey, MAX_STREAM_HEADER_LEN, Status, StreamHeader,
};
use iroh_gateway_proto::datagram::{MAX_UDP_FLOWS, UDP_FLOW_IDLE};
use iroh_gateway_proto::frame::{FrameError, read_frame, read_frame_max, write_frame};
use iroh_gateway_proto::splice::{SpliceOptions, splice_with};
use iroh_gateway_proto::throttle::{LOG_EVERY, LogThrottle};
use iroh_gateway_proto::transport::{MAX_TUNNEL_STREAMS, Relay, Role, endpoint_builder};
use iroh_gateway_proto::{
    ALPN, CLOSE_CONTROL_ENDED, CLOSE_REPLACED, CLOSE_SHUTDOWN, CLOSE_UNAUTHORIZED,
    RESET_BACKEND_UNAVAILABLE, RESET_BAD_HEADER, RESET_UNKNOWN_LISTENER,
};
use prometheus::IntGauge;
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};
use tracing::{Instrument, debug, error, info, info_span, warn};

use super::connector::Connector;
use super::udp::{self, IssuedIds, UdpTargets};
use crate::metrics::{LinkMetrics, LinkSeries, Metrics};

/// How long an incoming stream may take to deliver its `StreamHeader`.
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// How many sent but unacknowledged configs are kept to read a `Status` against.
const MAX_UNACKED_CONFIGS: usize = 32;
/// `last_error` while a session is up but the edge has not answered its first `Config` yet.
const WAITING_FOR_STATUS: &str = "connected; waiting for the edge to answer the config";
/// `last_error` after a session ended because the edge did not answer within
/// [`LinkOptions::first_status_timeout`].
const NO_STATUS: &str = "the edge accepted the connection but did not answer the config";

/// How the tunnel's traffic reaches the edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathKind {
    /// Straight to the edge's address.
    Direct,
    /// Through a relay server.
    Relay,
}

impl PathKind {
    /// `direct` or `relay`, as the `Edge` status and the metrics spell it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EdgeState {
    /// A connection is up and the edge has answered a `Config` on it.
    pub connected: bool,
    /// The path the connection sends on at the moment; None without a connection, and for the
    /// moment in which a connection has no selected path.
    pub path: Option<PathKind>,
    pub edge_version: Option<String>,
    /// The last generation the edge acknowledged.
    pub generation: u64,
    pub listeners: Vec<ListenerState>,
    /// Why the link is not connected, in plain words; None while connected.
    ///
    /// Set when a dial attempt fails, when a session starts ("connected; waiting for the edge to
    /// answer the config") and when a session ends, so it is also None until the first attempt;
    /// a shutdown leaves it as it was. At most [`MAX_STATUS_TEXT`] characters.
    pub last_error: Option<String>,
}

/// The most characters of text the state passes on from the edge: a listener's bind error, the
/// edge's version and `last_error`, which may quote the edge's close reason. Control characters
/// in them become spaces.
pub const MAX_STATUS_TEXT: usize = 256;

/// `text` with every control character replaced by a space, then cut to at most
/// [`MAX_STATUS_TEXT`] characters. Cuts at a character boundary and appends "…" when it cut.
pub fn truncate_status_text(text: &str) -> String {
    let text: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    match text.char_indices().nth(MAX_STATUS_TEXT - 1) {
        Some((end, _)) if text[end..].chars().nth(1).is_some() => format!("{}…", &text[..end]),
        _ => text,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerState {
    pub key: ListenerKey,
    /// The edge's bind error, cut by [`truncate_status_text`].
    pub bound: Result<(), String>,
}

#[derive(Debug, Clone)]
pub struct LinkOptions {
    pub edge_id: EndpointId,
    /// "host:port"; resolved on every dial attempt.
    pub address: Option<String>,
    /// The operator's relay mode.
    pub relay: Relay,
    pub dial_timeout: Duration,
    /// Limit for `Connector::connect`.
    pub connect_timeout: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// While the last `Status` the edge sent reports a listener it could not bind, the current
    /// listener list is sent again as a new `Config` this often.
    pub bind_retry: Duration,
    /// How long a new session waits for the edge's first `Status`; without one it ends and the
    /// link redials.
    pub first_status_timeout: Duration,
    /// How many UDP flows a session keeps; at the cap a new flow replaces the least recently
    /// used one.
    pub udp_max_flows: usize,
    /// A UDP flow is closed after this long without a packet in either direction.
    pub udp_flow_idle: Duration,
    /// Where the link reports its edge's `tunnel_*` series; it removes them when it ends.
    pub metrics: Metrics,
}

impl LinkOptions {
    /// Err when `address` is None and `relay` is Disabled: there would be no way to reach the edge.
    pub fn new(edge_id: EndpointId, address: Option<String>, relay: Relay) -> anyhow::Result<Self> {
        if address.is_none() && relay == Relay::Disabled {
            bail!("edge {edge_id} has no address and the relay is disabled: it cannot be reached");
        }
        Ok(Self {
            edge_id,
            address,
            relay,
            dial_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            backoff_min: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
            bind_retry: Duration::from_secs(30),
            first_status_timeout: Duration::from_secs(10),
            udp_max_flows: MAX_UDP_FLOWS,
            udp_flow_idle: UDP_FLOW_IDLE,
            metrics: Metrics::new(),
        })
    }
}

/// The operator's endpoint: `endpoint_builder(key, MAX_TUNNEL_STREAMS, relay, Role::Operator)` on
/// iroh's default sockets (IPv4 and IPv6, ephemeral ports). It sets no ALPN, so it accepts no
/// connections; it only dials.
pub async fn bind_endpoint(key: SecretKey, relay: &Relay) -> anyhow::Result<Endpoint> {
    endpoint_builder(key, MAX_TUNNEL_STREAMS, relay, Role::Operator)
        .bind()
        .await
        .context("binding the operator's iroh endpoint")
}

pub struct EdgeLink;

impl EdgeLink {
    /// Starts dialing the edge in the background and keeps a session with it until shutdown.
    /// The packets of each UDP listener go to its targets in `udp`.
    pub fn spawn<C: Connector>(
        endpoint: Endpoint,
        opts: LinkOptions,
        desired: watch::Receiver<Vec<ListenerKey>>,
        connector: Arc<C>,
        udp: watch::Receiver<UdpTargets>,
    ) -> LinkHandle {
        let (state_tx, state) = watch::channel(EdgeState::default());
        let (shutdown, shutdown_rx) = oneshot::channel();
        let span = info_span!("link", edge = %opts.edge_id.fmt_short());
        let metrics = opts.metrics.link(opts.edge_id);
        let serving = Arc::new(Serving {
            connector,
            connect_timeout: opts.connect_timeout,
            backend_errors: Mutex::default(),
            splice: SpliceOptions {
                meter: Some(Arc::new(metrics.tcp_bytes.clone())),
                ..SpliceOptions::default()
            },
            metrics: metrics.clone(),
        });
        let link = Link {
            endpoint,
            opts,
            desired,
            desired_open: true,
            serving,
            udp,
            state: state_tx,
            generation: 0,
            ids: HashMap::new(),
            next_id: 1,
            issued: Arc::new(AtomicU32::new(1)),
            metrics,
        };
        let task = tokio::spawn(link.run(shutdown_rx).instrument(span));
        LinkHandle {
            state,
            shutdown,
            task,
        }
    }
}

/// A running link. Dropping it stops the link as `shutdown` does, without waiting.
pub struct LinkHandle {
    state: watch::Receiver<EdgeState>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl LinkHandle {
    pub fn state(&self) -> watch::Receiver<EdgeState> {
        self.state.clone()
    }

    /// Closes the connection with `CLOSE_SHUTDOWN` and stops redialing; the endpoint stays open.
    /// Returns once the link and all its stream tasks have stopped. A panic of the link task is
    /// raised again here.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        if let Err(e) = self.task.await
            && e.is_panic()
        {
            std::panic::resume_unwind(e.into_panic());
        }
    }
}

struct Link<C> {
    endpoint: Endpoint,
    opts: LinkOptions,
    desired: watch::Receiver<Vec<ListenerKey>>,
    /// False once the sender of `desired` is gone; its last value stays desired.
    desired_open: bool,
    serving: Arc<Serving<C>>,
    /// Each session's UDP forwarder follows it; a closed channel keeps its last value.
    udp: watch::Receiver<UdpTargets>,
    state: watch::Sender<EdgeState>,
    /// The generation of the last `Config` sent, counted over all connections.
    generation: u64,
    /// The id of each key in the last `Config`. Ids come from `next_id` and are not reused for
    /// as long as the link runs, so on no connection does one id ever stand for two keys.
    ids: HashMap<ListenerKey, u32>,
    next_id: u32,
    /// The highest `next_id` so far, for the UDP forwarders to tell an id of an earlier config
    /// from one the link never issued.
    issued: IssuedIds,
    /// The edge's series, removed when the link ends and drops them.
    metrics: LinkSeries,
}

/// What every visitor stream of a link is served with.
struct Serving<C> {
    connector: Arc<C>,
    /// Limit for `Connector::connect`.
    connect_timeout: Duration,
    /// Per listener key, how often a failed backend connection is logged at warn.
    backend_errors: Mutex<HashMap<ListenerKey, LogThrottle>>,
    /// Counts the bytes in `tunnel_tcp_bytes_total`.
    splice: SpliceOptions,
    metrics: LinkMetrics,
}

/// Why a visitor stream is reset before forwarding.
#[derive(Debug, Clone, Copy)]
enum Refusal {
    BadHeader,
    UnknownListener,
    BackendUnavailable,
}

impl Refusal {
    fn code(self) -> u32 {
        match self {
            Refusal::BadHeader => RESET_BAD_HEADER,
            Refusal::UnknownListener => RESET_UNKNOWN_LISTENER,
            Refusal::BackendUnavailable => RESET_BACKEND_UNAVAILABLE,
        }
    }
}

/// A visitor stream, counted in `tunnel_streams_open` until it is dropped.
struct Served(IntGauge);

impl Served {
    fn new(metrics: &LinkMetrics) -> Self {
        metrics.streams.inc();
        metrics.streams_open.inc();
        Self(metrics.streams_open.clone())
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.0.dec();
    }
}

/// Sets `tunnel_up`, `tunnel_path` and `tunnel_listeners` to what `state` says.
fn show(metrics: &LinkMetrics, state: &EdgeState) {
    metrics
        .path
        .direct
        .set(i64::from(state.path == Some(PathKind::Direct)));
    metrics
        .path
        .relay
        .set(i64::from(state.path == Some(PathKind::Relay)));
    let failed = state.listeners.iter().filter(|l| l.bound.is_err()).count();
    let bound = state.listeners.len() - failed;
    metrics.up.set(i64::from(state.connected));
    metrics.listeners.bound.set(bound as i64);
    metrics.listeners.failed.set(failed as i64);
}

/// Per-connection state.
struct Session {
    conn: Connection,
    /// Listener id → key for the ids in the last `Config` sent; stream tasks route by it.
    routes: watch::Sender<HashMap<u32, ListenerKey>>,
    /// Configs sent and not yet acknowledged, oldest first.
    unacked: VecDeque<Config>,
    streams: JoinSet<()>,
    /// The session's UDP forwarder.
    udp: JoinHandle<()>,
    got_status: bool,
    /// The path the connection sends on, as last seen; in the state once the edge has answered.
    path: Option<PathKind>,
}

/// The kind of the path `conn` sends on at the moment, if it has selected one.
fn selected_path(conn: &Connection) -> Option<PathKind> {
    let paths = conn.paths();
    let selected = paths.iter().find(|p| p.is_selected())?;
    if selected.is_relay() {
        Some(PathKind::Relay)
    } else if selected.is_ip() {
        Some(PathKind::Direct)
    } else {
        None
    }
}

enum SessionError {
    /// The connection is closed.
    Lost(ConnectionError),
    /// The control stream failed; the connection is still open.
    Control(anyhow::Error),
    /// The edge sent no `Status` within `first_status_timeout`; the connection is still open.
    NoStatus,
}

enum Ended {
    Shutdown,
    Lost { got_status: bool },
}

impl<C: Connector> Link<C> {
    async fn run(mut self, mut shutdown: oneshot::Receiver<()>) {
        info!("link started");
        let mut backoff = Backoff::new(self.opts.backoff_min, self.opts.backoff_max);
        loop {
            // A dropped handle ends `shutdown` as well.
            let dialed = tokio::select! {
                _ = &mut shutdown => break,
                conn = self.dial() => conn,
            };
            match dialed {
                Ok(conn) => {
                    self.metrics.sessions.inc();
                    match self.session(conn, &mut shutdown).await {
                        Ended::Shutdown => break,
                        Ended::Lost { got_status } => {
                            if got_status {
                                backoff.reset();
                            }
                        }
                    }
                }
                Err(why) => {
                    self.metrics.dial_failures.inc();
                    let why = Some(truncate_status_text(&why));
                    self.state.send_if_modified(|st| {
                        let changed = st.last_error != why;
                        st.last_error = why;
                        changed
                    });
                }
            }
            let wait = backoff.next();
            debug!(?wait, "redialing after a pause");
            tokio::select! {
                _ = &mut shutdown => break,
                () = sleep(wait) => {}
            }
        }
        info!("link stopped");
    }

    /// For a close by the edge that redialing cannot get past, logs at warn what the operator
    /// must do and returns the reason in plain words; None, logging nothing, for any other close.
    fn explain_close(&self, closed: &ConnectionError) -> Option<String> {
        let ConnectionError::ApplicationClosed(close) = closed else {
            return None;
        };
        if close.error_code == VarInt::from_u32(CLOSE_UNAUTHORIZED) {
            let id = self.endpoint.id();
            warn!(
                "the edge does not accept this operator's key: start the edge with \
                 --operator {id}"
            );
            Some(format!(
                "the edge does not accept this operator's key ({id})"
            ))
        } else if close.error_code == VarInt::from_u32(CLOSE_REPLACED) {
            let why =
                "another operator with the same key connected to the edge and replaced this one";
            warn!("{why}");
            Some(why.to_string())
        } else {
            None
        }
    }

    /// One dial attempt; Err says why it failed.
    async fn dial(&self) -> Result<Connection, String> {
        let target = self.target().await?;
        match timeout(self.opts.dial_timeout, self.endpoint.connect(target, ALPN)).await {
            Ok(Ok(conn)) => {
                info!("connected");
                Ok(conn)
            }
            Ok(Err(e)) => {
                let closed = match &e {
                    ConnectError::Connecting {
                        source: ConnectingError::ConnectionError { source, .. },
                        ..
                    }
                    | ConnectError::Connection { source, .. } => Some(source),
                    _ => None,
                };
                Err(closed
                    .and_then(|c| self.explain_close(c))
                    .unwrap_or_else(|| {
                        let why = format!("dial failed: {e:#}");
                        info!("{why}");
                        why
                    }))
            }
            Err(_) => {
                let why = format!("dial timed out after {:?}", self.opts.dial_timeout);
                info!("{why}");
                Err(why)
            }
        }
    }

    /// The edge's id with the addressing this attempt has; Err says why it has none.
    async fn target(&self) -> Result<EndpointAddr, String> {
        let mut target = EndpointAddr::new(self.opts.edge_id);
        if let Relay::Custom(url) = &self.opts.relay {
            target = target.with_relay_url(url.clone());
        }
        let Some(address) = &self.opts.address else {
            return Ok(target);
        };
        match resolve(address, self.opts.dial_timeout).await {
            Ok(addrs) => Ok(addrs.into_iter().fold(target, EndpointAddr::with_ip_addr)),
            Err(e) if self.opts.relay == Relay::Disabled => {
                let why = format!("dial failed: {e:#}");
                info!("{why}");
                Err(why)
            }
            Err(e) => {
                info!("{e:#}; dialing through the relay only");
                Ok(target)
            }
        }
    }

    async fn session(&mut self, conn: Connection, shutdown: &mut oneshot::Receiver<()>) -> Ended {
        let routes = watch::Sender::new(HashMap::new());
        let udp = tokio::spawn(
            udp::forward(
                conn.clone(),
                routes.subscribe(),
                self.issued.clone(),
                self.udp.clone(),
                self.opts.udp_max_flows,
                self.opts.udp_flow_idle,
                self.metrics.udp.clone(),
            )
            .in_current_span(),
        );
        let mut s = Session {
            conn: conn.clone(),
            routes,
            unacked: VecDeque::new(),
            streams: JoinSet::new(),
            udp,
            got_status: false,
            path: selected_path(&conn),
        };
        self.count_path(s.path);
        if let Some(path) = s.path {
            info!(path = path.as_str(), "the tunnel's first path");
        }
        let waiting = Some(WAITING_FOR_STATUS.to_owned());
        self.state.send_if_modified(|st| {
            let changed = st.last_error != waiting;
            st.last_error = waiting;
            changed
        });
        let end = tokio::select! {
            _ = &mut *shutdown => None,
            e = self.drive(&mut s) => Some(e),
        };
        let why = match &end {
            None => {
                conn.close(VarInt::from_u32(CLOSE_SHUTDOWN), b"shutdown");
                None
            }
            Some(e) => Some(truncate_status_text(&self.session_ended(&conn, e))),
        };
        s.streams.abort_all();
        s.udp.abort();
        while let Some(done) = s.streams.join_next().await {
            if let Err(e) = done
                && e.is_panic()
            {
                error!("stream task panicked: {e}");
            }
        }
        if let Err(e) = (&mut s.udp).await
            && e.is_panic()
        {
            error!("udp forwarder panicked: {e}");
        }
        show(&self.metrics, &EdgeState::default());
        self.state.send_if_modified(|st| {
            let mut changed = st.connected || !st.listeners.is_empty() || st.path.is_some();
            st.connected = false;
            st.listeners.clear();
            st.path = None;
            if why.is_some() && st.last_error != why {
                st.last_error = why;
                changed = true;
            }
            changed
        });
        match end {
            None => Ended::Shutdown,
            Some(_) => Ended::Lost {
                got_status: s.got_status,
            },
        }
    }

    /// Counts a path the connection selected.
    fn count_path(&self, path: Option<PathKind>) {
        match path {
            Some(PathKind::Direct) => self.metrics.path_selected.direct.inc(),
            Some(PathKind::Relay) => self.metrics.path_selected.relay.inc(),
            None => {}
        }
    }

    /// Takes the connection's selected path: logs a change, and once the edge has answered a
    /// config puts it into the state and the metrics.
    fn on_path(&mut self, s: &mut Session) {
        let path = selected_path(&s.conn);
        if path == s.path {
            return;
        }
        s.path = path;
        self.count_path(path);
        match path {
            Some(path) => info!(path = path.as_str(), "the tunnel's path changed"),
            None => debug!("the tunnel has no selected path"),
        }
        if s.got_status {
            self.state.send_if_modified(|st| {
                let changed = st.path != path;
                st.path = path;
                changed
            });
            show(&self.metrics, &self.state.borrow());
        }
    }

    /// Logs why the session ended, closes the connection with `CLOSE_CONTROL_ENDED` when the
    /// control stream failed on an open one, and returns the reason in plain words.
    fn session_ended(&self, conn: &Connection, e: &SessionError) -> String {
        // Seen as a lost connection or as a failed control stream, whichever came first.
        if let Some(why) = conn.close_reason().and_then(|c| self.explain_close(&c)) {
            return why;
        }
        match e {
            SessionError::Lost(e) => {
                let why = format!("connection lost: {e}");
                info!("{why}");
                why
            }
            SessionError::Control(e) => {
                let why = format!("control stream failed: {e:#}");
                warn!("{why}");
                conn.close(
                    VarInt::from_u32(CLOSE_CONTROL_ENDED),
                    b"control stream ended",
                );
                why
            }
            SessionError::NoStatus => {
                warn!(
                    timeout = ?self.opts.first_status_timeout,
                    "{NO_STATUS}; dialing again"
                );
                conn.close(VarInt::from_u32(CLOSE_CONTROL_ENDED), b"no status");
                NO_STATUS.to_owned()
            }
        }
    }

    /// Runs the control stream and serves visitor streams until the session fails.
    async fn drive(&mut self, s: &mut Session) -> SessionError {
        let conn = s.conn.clone();
        let (send, recv) = match conn.open_bi().await {
            Ok(streams) => streams,
            Err(e) => return SessionError::Lost(e),
        };
        let first = match self.next_config(s) {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };
        // The edge sees the control stream only once this first frame is written.
        let mut writing = pin!(write_config(send, first));
        // The control stream while no write is in flight.
        let mut idle_send: Option<SendStream> = None;
        // A new `Config` is due: `desired` changed, or binds are retried.
        let mut dirty = false;
        let mut reading = pin!(read_status(recv));
        // Fires `bind_retry` after a `Status` that reports a bind error, unless one without
        // such an error is acknowledged first.
        let mut retry = pin!(sleep(self.opts.bind_retry));
        let mut retry_armed = false;
        // Ends the session unless the edge answers a config in time.
        let mut first_status = pin!(sleep(self.opts.first_status_timeout));
        // Ends when the connection closes, which `conn.closed()` reports.
        let mut path_events = conn.path_events();
        let mut path_events_open = true;
        // A change between the session's first look at the paths and this subscription sent
        // its event to nobody: look again now that later ones will be seen.
        self.on_path(s);
        loop {
            tokio::select! {
                e = conn.closed() => return SessionError::Lost(e),
                event = path_events.next(), if path_events_open => {
                    // Whatever the event, the connection has the answer; a missed event too.
                    path_events_open = event.is_some();
                    self.on_path(s);
                }
                () = &mut first_status, if !s.got_status => return SessionError::NoStatus,
                (send, written) = &mut writing, if idle_send.is_none() => {
                    if let Err(e) = written {
                        return SessionError::Control(e.into());
                    }
                    idle_send = Some(send);
                }
                changed = self.desired.changed(), if self.desired_open => {
                    if changed.is_err() {
                        self.desired_open = false;
                        continue;
                    }
                    dirty = true;
                }
                () = &mut retry, if retry_armed => {
                    retry_armed = false;
                    // A config still unacknowledged retries the binds by itself, and its status
                    // arms the retry again if they still fail.
                    if s.unacked.is_empty() {
                        debug!("retrying the listeners the edge could not bind");
                        dirty = true;
                    }
                }
                (recv, read) = &mut reading => {
                    match read {
                        Ok(Some(status)) => {
                            if let Some(failed) = self.on_status(s, status) {
                                retry_armed = failed;
                                if failed {
                                    retry.set(sleep(self.opts.bind_retry));
                                }
                            }
                        }
                        Ok(None) => {
                            return SessionError::Control(anyhow!("the edge finished the control stream"));
                        }
                        Err(e) => return SessionError::Control(e.into()),
                    }
                    reading.set(read_status(recv));
                }
                accepted = conn.accept_bi() => match accepted {
                    Ok((send, recv)) => {
                        let stream = serve_stream(
                            conn.clone(),
                            send,
                            recv,
                            s.routes.subscribe(),
                            self.serving.clone(),
                            Served::new(&self.metrics),
                        );
                        s.streams.spawn(stream.in_current_span());
                    }
                    Err(e) => return SessionError::Lost(e),
                },
                // Reaps finished stream tasks.
                Some(done) = s.streams.join_next() => {
                    if let Err(e) = done
                        && e.is_panic()
                    {
                        error!("stream task panicked: {e}");
                    }
                }
            }
            if dirty && let Some(send) = idle_send.take() {
                dirty = false;
                match self.next_config(s) {
                    Ok(cfg) => writing.set(write_config(send, cfg)),
                    Err(e) => return e,
                }
            }
        }
    }

    /// Assigns ids to newly desired keys and builds the next `Config`, which the session routes
    /// by from now on.
    fn next_config(&mut self, s: &mut Session) -> Result<Config, SessionError> {
        let mut seen = HashSet::new();
        let mut desired = self.desired.borrow_and_update().clone();
        desired.retain(|key| seen.insert(*key));
        self.ids.retain(|key, _| seen.contains(key));
        let mut listeners = Vec::with_capacity(desired.len());
        for key in desired {
            let id = match self.ids.get(&key) {
                Some(&id) => id,
                None => {
                    let Some(after) = self.next_id.checked_add(1) else {
                        // Unreachable in practice (2^32 keys added). Ids start over on the next
                        // connection, as they do after an operator restart. The edge keeps its
                        // listeners' previous ids until the new session's first `Config` is
                        // applied, but forwards no visitor on a session before that, and
                        // `serve_stream` refuses a stream whose public port is not its
                        // listener's, so an old id cannot reach another listener's backend.
                        self.ids.clear();
                        self.next_id = 1;
                        return Err(SessionError::Control(anyhow!("listener ids exhausted")));
                    };
                    let id = self.next_id;
                    self.next_id = after;
                    self.ids.insert(key, id);
                    id
                }
            };
            listeners.push(Listener {
                id,
                protocol: key.protocol,
                port: key.port,
            });
        }
        // Before the routes: a forwarder that misses an id there knows it was issued.
        self.issued.fetch_max(self.next_id, Ordering::Release);
        self.generation += 1;
        let cfg = Config {
            generation: self.generation,
            listeners,
        };
        debug!(generation = cfg.generation, listeners = ?cfg.listeners, "sending config");
        s.routes
            .send_replace(cfg.listeners.iter().map(|l| (l.id, l.key())).collect());
        s.unacked.push_back(cfg.clone());
        if s.unacked.len() > MAX_UNACKED_CONFIGS {
            s.unacked.pop_front();
        }
        Ok(cfg)
    }

    /// Makes the state follow `status`, read against the config it acknowledges. Returns whether
    /// it reports a listener the edge could not bind; None when it acknowledges no pending config.
    fn on_status(&mut self, s: &mut Session, status: Status) -> Option<bool> {
        let Some(pos) = s
            .unacked
            .iter()
            .position(|c| c.generation == status.generation)
        else {
            debug!(
                generation = status.generation,
                "ignoring a status for no pending config"
            );
            return None;
        };
        let cfg = s
            .unacked
            .drain(..=pos)
            .next_back()
            .expect("drains at least one");
        // One entry per listener of the acknowledged config, in its order: the edge's first
        // entry for that id. Extra and repeated entries are ignored.
        let mut first: HashMap<u32, &BindState> = HashMap::with_capacity(cfg.listeners.len());
        for ls in &status.listeners {
            first.entry(ls.id).or_insert(&ls.state);
        }
        let listeners: Vec<ListenerState> = cfg
            .listeners
            .iter()
            .filter_map(|l| {
                let bound = match first.get(&l.id)? {
                    BindState::Bound => Ok(()),
                    BindState::Error(e) => Err(truncate_status_text(e)),
                };
                Some(ListenerState {
                    key: l.key(),
                    bound,
                })
            })
            .collect();
        s.got_status = true;
        let failed = listeners.iter().any(|l| l.bound.is_err());
        let next = EdgeState {
            connected: true,
            path: s.path,
            edge_version: Some(truncate_status_text(&status.version)),
            generation: status.generation,
            listeners,
            last_error: None,
        };
        debug!(?next, "status received");
        show(&self.metrics, &next);
        self.state.send_if_modified(|st| {
            let changed = *st != next;
            *st = next;
            changed
        });
        Some(failed)
    }
}

async fn resolve(address: &str, limit: Duration) -> anyhow::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = timeout(limit, tokio::net::lookup_host(address))
        .await
        .map_err(|_| anyhow!("resolving {address:?} timed out"))?
        .with_context(|| format!("resolving {address:?}"))?
        .collect();
    if addrs.is_empty() {
        bail!("{address:?} resolved to no address");
    }
    Ok(addrs)
}

/// Owns the stream so the write can live across `select!` rounds without being cancelled.
async fn write_config(mut send: SendStream, cfg: Config) -> (SendStream, Result<(), FrameError>) {
    let written = write_frame(&mut send, &cfg).await;
    (send, written)
}

/// Owns the stream so the read can live across `select!` rounds without being cancelled.
async fn read_status(mut recv: RecvStream) -> (RecvStream, Result<Option<Status>, FrameError>) {
    let read = read_frame(&mut recv).await;
    (recv, read)
}

/// Reads the header of one visitor stream, opens the local side and splices until either side
/// ends or the connection is lost. Every failure ends this stream only. `_served` counts the
/// stream for as long as this runs, however it ends.
async fn serve_stream<C: Connector>(
    conn: Connection,
    send: SendStream,
    mut recv: RecvStream,
    routes: watch::Receiver<HashMap<u32, ListenerKey>>,
    serving: Arc<Serving<C>>,
    _served: Served,
) {
    let header = match timeout(
        HEADER_TIMEOUT,
        read_frame_max::<_, StreamHeader>(&mut recv, MAX_STREAM_HEADER_LEN),
    )
    .await
    {
        Ok(Ok(Some(header))) => header,
        Ok(Ok(None)) => {
            return serving.refuse(
                send,
                recv,
                Refusal::BadHeader,
                &"stream ended before a header",
            );
        }
        Ok(Err(e)) => {
            return serving.refuse(
                send,
                recv,
                Refusal::BadHeader,
                &format_args!("bad header: {e}"),
            );
        }
        Err(_) => return serving.refuse(send, recv, Refusal::BadHeader, &"no header in time"),
    };
    let key = routes.borrow().get(&header.listener_id).copied();
    let Some(key) = key else {
        let why = format!("unknown listener id {}", header.listener_id);
        return serving.refuse(send, recv, Refusal::UnknownListener, &why);
    };
    if header.local.port() != key.port {
        let why = format!(
            "listener id {} is port {}, but the visitor came in on port {}",
            header.listener_id,
            key.port,
            header.local.port()
        );
        return serving.refuse(send, recv, Refusal::UnknownListener, &why);
    }
    let visitor = header.visitor;
    let connecting = serving.connector.connect(key, &header);
    let failed = match timeout(serving.connect_timeout, connecting).await {
        Ok(Ok(local)) => Ok(local),
        Ok(Err(e)) => Err(format!("backend for {key:?} unavailable: {e}")),
        Err(_) => Err(format!("backend for {key:?} did not connect in time")),
    };
    let local = match failed {
        Ok(local) => local,
        Err(why) => {
            let suppressed = serving
                .backend_errors
                .lock()
                .expect("not poisoned")
                .entry(key)
                .or_insert_with(|| LogThrottle::new(LOG_EVERY))
                .hit();
            if let Some(suppressed) = suppressed {
                warn!(suppressed, "{why}");
            }
            return serving.refuse(send, recv, Refusal::BackendUnavailable, &why);
        }
    };
    tokio::select! {
        stats = splice_with(local, send, recv, serving.splice.clone()) => debug!(
            %visitor, ?key, end = ?stats.end,
            to_remote = stats.to_remote, to_local = stats.to_local,
            "visitor done"
        ),
        // Dropping the splice resets the stream and aborts the local side.
        _ = conn.closed() => debug!(%visitor, ?key, "visitor aborted: tunnel lost"),
    }
}

impl<C> Serving<C> {
    /// Counts the refusal, then resets and stops the stream with its code.
    fn refuse(
        &self,
        mut send: SendStream,
        mut recv: RecvStream,
        refusal: Refusal,
        why: &dyn Display,
    ) {
        let refused = &self.metrics.refused;
        match refusal {
            Refusal::BadHeader => refused.bad_header.inc(),
            Refusal::UnknownListener => refused.unknown_listener.inc(),
            Refusal::BackendUnavailable => refused.backend_unavailable.inc(),
        }
        let code = refusal.code();
        debug!(code, "stream refused: {why}");
        let code = VarInt::from_u32(code);
        // Either fails only when that half is already closed.
        let _ = send.reset(code);
        let _ = recv.stop(code);
    }
}

/// Redial pauses: doubling from `min` up to `max`, each with ±20 % jitter.
struct Backoff {
    min: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    fn new(min: Duration, max: Duration) -> Self {
        Self {
            min,
            max: max.max(min),
            next: min,
        }
    }

    fn reset(&mut self) {
        self.next = self.min;
    }

    fn next(&mut self) -> Duration {
        let base = self.next;
        self.next = base.saturating_mul(2).min(self.max);
        let jittered = base.as_secs_f64() * (0.8 + 0.4 * fastrand::f64());
        Duration::try_from_secs_f64(jittered).unwrap_or(base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn within_20_percent(wait: Duration, base_ms: u64) -> bool {
        let ms = wait.as_secs_f64() * 1000.0;
        let base = base_ms as f64;
        ms >= base * 0.8 && ms <= base * 1.2
    }

    #[test]
    fn backoff_doubles_up_to_max_with_jitter_and_resets() {
        let mut b = Backoff::new(Duration::from_millis(500), Duration::from_secs(30));
        for base in [500, 1000, 2000, 4000, 8000, 16000, 30000, 30000] {
            let wait = b.next();
            assert!(within_20_percent(wait, base), "{wait:?} for {base} ms");
        }
        b.reset();
        let wait = b.next();
        assert!(within_20_percent(wait, 500), "{wait:?} after reset");
    }

    #[test]
    fn truncate_status_text_replaces_control_characters() {
        assert_eq!(
            truncate_status_text("a\nb\rc\x1b[31md\0e\tf\u{7f}g\u{85}h"),
            "a b c [31md e f g h"
        );
        // Replaced before the cut, so a cut string is clean too.
        let long = "\n".repeat(1000);
        let cut = truncate_status_text(&long);
        assert_eq!(cut.chars().count(), MAX_STATUS_TEXT);
        assert!(!cut.chars().any(char::is_control), "{cut:?}");
    }

    #[test]
    fn truncate_status_text_respects_char_boundaries() {
        assert_eq!(truncate_status_text("short"), "short");
        let long = "é".repeat(300);
        let cut = truncate_status_text(&long);
        assert_eq!(cut.chars().count(), 256);
        assert!(cut.ends_with('…'));
        assert!(cut.starts_with("éé"));
        let exact = "é".repeat(MAX_STATUS_TEXT);
        assert_eq!(truncate_status_text(&exact), exact);
        let over = "é".repeat(MAX_STATUS_TEXT + 1);
        assert_eq!(
            truncate_status_text(&over),
            format!("{}…", "é".repeat(MAX_STATUS_TEXT - 1))
        );
    }
}
