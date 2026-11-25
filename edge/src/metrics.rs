//! The edge's Prometheus metrics, and the HTTP endpoint that serves them.
//!
//! Every metric is named `iroh_gateway_edge_…` and lives in the [`Metrics`]' own registry,
//! never in the process-wide default one. Each label value the edge uses is set up front, so
//! that every series is there, at 0, before anything has happened.

use axum::Router;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use iroh_gateway_proto::control::Protocol;
use iroh_gateway_proto::splice::SpliceMeter;
use prometheus::{
    IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TEXT_FORMAT, TextEncoder,
};
use tokio::net::TcpListener;
use tracing::error;

const NAMESPACE: &str = "iroh_gateway_edge";

/// The edge's metrics. Clones share the same series.
#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    /// 1 from a session's first applied `Config` until that session ends.
    pub(crate) session_up: IntGauge,
    pub(crate) sessions_total: IntCounter,
    /// Public ports open now.
    pub(crate) listeners: PerProtocol<IntGauge>,
    pub(crate) bind_failures: PerProtocol<IntCounter>,
    /// TCP visitors holding a slot of the connection cap.
    pub(crate) connections_open: IntGauge,
    pub(crate) connections_total: IntCounter,
    pub(crate) refused: Refusals,
    /// Bytes written to the tunnel stream (`in`) and to the visitor (`out`).
    pub(crate) tcp_bytes: PerDirection,
    pub(crate) udp_flows: IntGauge,
    pub(crate) udp_flows_total: IntCounter,
    pub(crate) udp_flows_evicted: IntCounter,
    pub(crate) udp_packets: PerDirection,
    pub(crate) udp_bytes: PerDirection,
    pub(crate) udp_fragmented: PerDirection,
    pub(crate) udp_dropped: UdpDrops,
}

/// One child per `protocol`.
#[derive(Clone)]
pub(crate) struct PerProtocol<M> {
    pub tcp: M,
    pub udp: M,
}

impl<M> PerProtocol<M> {
    pub fn get(&self, protocol: Protocol) -> &M {
        match protocol {
            Protocol::Tcp => &self.tcp,
            Protocol::Udp => &self.udp,
        }
    }
}

/// One child per `direction`: `in` from visitors towards backends, `out` the way back.
#[derive(Clone)]
pub(crate) struct PerDirection {
    pub inbound: IntCounter,
    pub outbound: IntCounter,
}

/// Counts a visitor's stream: what goes to the tunnel is `in`, what goes to the visitor `out`.
impl SpliceMeter for PerDirection {
    fn to_remote(&self, bytes: u64) {
        self.inbound.inc_by(bytes);
    }

    fn to_local(&self, bytes: u64) {
        self.outbound.inc_by(bytes);
    }
}

/// TCP visitors dropped before a tunnel stream, per `reason`.
#[derive(Clone)]
pub(crate) struct Refusals {
    /// The connection cap was reached.
    pub cap: IntCounter,
    /// No session, a session not configured yet, or the visitor's listener closed since.
    pub no_session: IntCounter,
    /// The queue from the ports to the supervisor was full.
    pub queue_full: IntCounter,
}

/// Dropped UDP packets or datagrams, per `reason`.
#[derive(Clone)]
pub(crate) struct UdpDrops {
    pub no_session: IntCounter,
    pub rate_limit: IntCounter,
    pub send_error: IntCounter,
    pub tunnel_full: IntCounter,
    pub unknown_flow: IntCounter,
    pub bad_datagram: IntCounter,
}

impl Metrics {
    pub fn new() -> Self {
        let r = Registry::new();
        gauge_vec(&r, "build_info", "The edge's version; always 1.", "version")
            .with_label_values(&[env!("CARGO_PKG_VERSION")])
            .set(1);
        let listeners = gauge_vec(&r, "listeners", "Public ports open now.", "protocol");
        let bind_failures = counter_vec(
            &r,
            "bind_failures_total",
            "Binds of a public port the OS refused.",
            "protocol",
        );
        let refused = counter_vec(
            &r,
            "connections_refused_total",
            "TCP visitors dropped before a tunnel stream.",
            "reason",
        );
        let dropped = counter_vec(
            &r,
            "udp_dropped_total",
            "Dropped UDP packets or datagrams.",
            "reason",
        );
        Self {
            session_up: gauge(
                &r,
                "session_up",
                "1 from a session's first applied config until that session ends.",
            ),
            sessions_total: counter(&r, "sessions_total", "Sessions installed."),
            listeners: PerProtocol {
                tcp: listeners.with_label_values(&["tcp"]),
                udp: listeners.with_label_values(&["udp"]),
            },
            bind_failures: PerProtocol {
                tcp: bind_failures.with_label_values(&["tcp"]),
                udp: bind_failures.with_label_values(&["udp"]),
            },
            connections_open: gauge(
                &r,
                "connections_open",
                "TCP visitors holding a slot of --max-connections.",
            ),
            connections_total: counter(
                &r,
                "connections_total",
                "TCP visitors accepted into a slot.",
            ),
            refused: Refusals {
                cap: refused.with_label_values(&["cap"]),
                no_session: refused.with_label_values(&["no_session"]),
                queue_full: refused.with_label_values(&["queue_full"]),
            },
            tcp_bytes: per_direction(
                &r,
                "tcp_bytes_total",
                "Bytes written to the tunnel stream (in) and to the visitor (out).",
            ),
            udp_flows: gauge(&r, "udp_flows", "UDP flows held."),
            udp_flows_total: counter(&r, "udp_flows_total", "UDP flows created."),
            udp_flows_evicted: counter(
                &r,
                "udp_flows_evicted_total",
                "UDP flows pushed out at the flow cap.",
            ),
            udp_packets: per_direction(
                &r,
                "udp_packets_total",
                "UDP packets handed to the tunnel in full (in) and sent to a visitor (out).",
            ),
            udp_bytes: per_direction(
                &r,
                "udp_bytes_total",
                "Payload bytes of the packets in udp_packets_total.",
            ),
            udp_fragmented: per_direction(
                &r,
                "udp_fragmented_packets_total",
                "UDP packets split into more than one datagram (in) or reassembled from more \
                 than one (out).",
            ),
            udp_dropped: UdpDrops {
                no_session: dropped.with_label_values(&["no_session"]),
                rate_limit: dropped.with_label_values(&["rate_limit"]),
                send_error: dropped.with_label_values(&["send_error"]),
                tunnel_full: dropped.with_label_values(&["tunnel_full"]),
                unknown_flow: dropped.with_label_values(&["unknown_flow"]),
                bad_datagram: dropped.with_label_values(&["bad_datagram"]),
            },
            registry: r,
        }
    }

    /// Every metric in the Prometheus text format, version 0.0.4.
    pub fn render(&self) -> String {
        TextEncoder::new()
            .encode_to_string(&self.registry.gather())
            .unwrap_or_else(|e| {
                error!("encoding the metrics failed: {e}");
                String::new()
            })
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Serves `GET /metrics` (200, `text/plain; version=0.0.4`); every other path is 404.
pub async fn serve(listener: TcpListener, metrics: Metrics) -> std::io::Result<()> {
    let app = Router::new()
        .route("/metrics", get(page))
        .with_state(metrics);
    axum::serve(listener, app).await
}

async fn page(State(metrics): State<Metrics>) -> impl IntoResponse {
    ([(CONTENT_TYPE, TEXT_FORMAT)], metrics.render())
}

/// The names and labels are fixed and each is registered once, so neither can fail.
const VALID: &str = "a valid metric registered once";

fn opts(name: &str, help: &str) -> Opts {
    Opts::new(name, help).namespace(NAMESPACE)
}

fn counter(r: &Registry, name: &str, help: &str) -> IntCounter {
    let counter = IntCounter::with_opts(opts(name, help)).expect(VALID);
    r.register(Box::new(counter.clone())).expect(VALID);
    counter
}

fn gauge(r: &Registry, name: &str, help: &str) -> IntGauge {
    let gauge = IntGauge::with_opts(opts(name, help)).expect(VALID);
    r.register(Box::new(gauge.clone())).expect(VALID);
    gauge
}

fn counter_vec(r: &Registry, name: &str, help: &str, label: &str) -> IntCounterVec {
    let vec = IntCounterVec::new(opts(name, help), &[label]).expect(VALID);
    r.register(Box::new(vec.clone())).expect(VALID);
    vec
}

fn gauge_vec(r: &Registry, name: &str, help: &str, label: &str) -> IntGaugeVec {
    let vec = IntGaugeVec::new(opts(name, help), &[label]).expect(VALID);
    r.register(Box::new(vec.clone())).expect(VALID);
    vec
}

fn per_direction(r: &Registry, name: &str, help: &str) -> PerDirection {
    let vec = counter_vec(r, name, help, "direction");
    PerDirection {
        inbound: vec.with_label_values(&["in"]),
        outbound: vec.with_label_values(&["out"]),
    }
}
