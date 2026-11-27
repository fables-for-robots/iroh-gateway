//! The operator's Prometheus metrics.
//!
//! Every metric is named `iroh_gateway_operator_…` and lives in the [`Metrics`]' own registry,
//! never in the process-wide default one. Every `tunnel_*` metric carries the label `edge`, the
//! edge's EndpointId as 64 hex characters: a link sets up all of its edge's series, at 0, when it
//! starts, and removes them all when it ends.

use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::sync::{Arc, Mutex, PoisonError};

use iroh::EndpointId;
use iroh_gateway_proto::splice::SpliceMeter;
use prometheus::core::{MetricVec, MetricVecBuilder};
use prometheus::{
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use tracing::error;

const NAMESPACE: &str = "iroh_gateway_operator";

/// The values of `state` in `tunnel_listeners`.
const STATES: [&str; 2] = ["bound", "failed"];
/// The values of `reason` in `tunnel_streams_refused_total`.
const REFUSALS: [&str; 3] = ["bad_header", "unknown_listener", "backend_unavailable"];
/// The values of `direction`.
const DIRECTIONS: [&str; 2] = ["in", "out"];
/// The values of `path` in `tunnel_path` and `tunnel_path_selected_total`.
const PATHS: [&str; 2] = ["direct", "relay"];
/// The values of `reason` in `tunnel_udp_dropped_total`.
const UDP_DROPS: [&str; 9] = [
    "bad_datagram",
    "retired_listener",
    "unknown_listener",
    "not_udp",
    "wrong_listener",
    "no_target",
    "socket_error",
    "send_error",
    "tunnel_full",
];

/// The operator's metrics. Clones share the same series.
#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    tunnel: Tunnel,
    /// How many running links report on each edge; its series go when the last one ends.
    links: Arc<Mutex<HashMap<String, usize>>>,
    control: Control,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metrics").finish_non_exhaustive()
    }
}

/// The `tunnel_*` collectors; `edge` is the first label of each.
#[derive(Clone)]
struct Tunnel {
    up: IntGaugeVec,
    path: IntGaugeVec,
    path_selected: IntCounterVec,
    sessions: IntCounterVec,
    dial_failures: IntCounterVec,
    listeners: IntGaugeVec,
    streams_open: IntGaugeVec,
    streams: IntCounterVec,
    streams_refused: IntCounterVec,
    tcp_bytes: IntCounterVec,
    udp_flows: IntGaugeVec,
    udp_flows_total: IntCounterVec,
    udp_flows_evicted: IntCounterVec,
    udp_packets: IntCounterVec,
    udp_bytes: IntCounterVec,
    udp_fragmented: IntCounterVec,
    udp_dropped: IntCounterVec,
}

/// The series of HAProxy, which the engine updates, and of the controller loop.
#[derive(Clone)]
pub(crate) struct Control {
    /// `haproxy_reloads_total` per `result`: `ok` for a reload HAProxy took, `refused` for a
    /// configuration it refused as invalid, `failed` for a reload that failed.
    pub haproxy_reloads_ok: IntCounter,
    pub haproxy_reloads_refused: IntCounter,
    pub haproxy_reloads_failed: IntCounter,
    /// 1 when HAProxy took the last configuration applied, else 0.
    pub haproxy_config_ok: IntGauge,
    /// Passes of the controller loop.
    pub reconciles: IntCounter,
    /// A pass, from taking the snapshot to the end of its status write.
    pub reconcile_duration: Histogram,
    /// Status writes that failed.
    pub status_write_failures: IntCounter,
}

/// The series of one edge, for its link.
#[derive(Clone)]
pub(crate) struct LinkMetrics {
    /// `EdgeState.connected`.
    pub up: IntGauge,
    /// `EdgeState.path`.
    pub path: Paths,
    /// Times a connection selected a path of each kind, its first path included.
    pub path_selected: PathsSelected,
    /// Dials that connected.
    pub sessions: IntCounter,
    pub dial_failures: IntCounter,
    /// From the edge's last status; both 0 while not connected.
    pub listeners: Listeners,
    /// Visitor streams being served.
    pub streams_open: IntGauge,
    /// Visitor streams accepted.
    pub streams: IntCounter,
    pub refused: Refusals,
    /// Bytes written to the backend (`in`) and to the tunnel stream (`out`).
    pub tcp_bytes: PerDirection,
    pub udp: UdpMetrics,
}

/// `tunnel_path` per `path`: 1 for the path the tunnel sends on, 0 for the other; both 0 while
/// not connected.
#[derive(Clone)]
pub(crate) struct Paths {
    pub direct: IntGauge,
    pub relay: IntGauge,
}

/// `tunnel_path_selected_total` per `path`.
#[derive(Clone)]
pub(crate) struct PathsSelected {
    pub direct: IntCounter,
    pub relay: IntCounter,
}

/// `tunnel_listeners` per `state`.
#[derive(Clone)]
pub(crate) struct Listeners {
    pub bound: IntGauge,
    pub failed: IntGauge,
}

/// Visitor streams reset before forwarding, per `reason`.
#[derive(Clone)]
pub(crate) struct Refusals {
    pub bad_header: IntCounter,
    pub unknown_listener: IntCounter,
    pub backend_unavailable: IntCounter,
}

/// The UDP forwarder's series of one edge.
#[derive(Clone)]
pub(crate) struct UdpMetrics {
    /// Flows the forwarder holds; 0 after a session.
    pub flows: IntGauge,
    pub flows_total: IntCounter,
    /// Flows pushed out at the cap.
    pub flows_evicted: IntCounter,
    /// Packets sent to a backend (`in`); replies handed to the tunnel in full (`out`).
    pub packets: PerDirection,
    /// Payload bytes of those packets.
    pub bytes: PerDirection,
    /// `in`: reassembled from more than one datagram; `out`: split into more than one.
    pub fragmented: PerDirection,
    pub dropped: UdpDrops,
}

/// Dropped UDP packets or datagrams, per `reason`.
#[derive(Clone)]
pub(crate) struct UdpDrops {
    pub bad_datagram: IntCounter,
    pub retired_listener: IntCounter,
    pub unknown_listener: IntCounter,
    pub not_udp: IntCounter,
    pub wrong_listener: IntCounter,
    pub no_target: IntCounter,
    pub socket_error: IntCounter,
    pub send_error: IntCounter,
    pub tunnel_full: IntCounter,
}

/// One child per `direction`: `in` from visitors towards backends, `out` the way back.
#[derive(Clone)]
pub(crate) struct PerDirection {
    pub inbound: IntCounter,
    pub outbound: IntCounter,
}

/// Counts a visitor's stream: what goes to the backend is `in`, what goes to the tunnel `out`.
impl SpliceMeter for PerDirection {
    fn to_remote(&self, bytes: u64) {
        self.outbound.inc_by(bytes);
    }

    fn to_local(&self, bytes: u64) {
        self.inbound.inc_by(bytes);
    }
}

/// A link's hold on its edge's series: dereferences to them, and removes every series labelled
/// with the edge when it is dropped, unless another link of the same edge still holds them.
pub(crate) struct LinkSeries {
    metrics: LinkMetrics,
    edge: String,
    tunnel: Tunnel,
    links: Arc<Mutex<HashMap<String, usize>>>,
}

impl Deref for LinkSeries {
    type Target = LinkMetrics;

    fn deref(&self) -> &LinkMetrics {
        &self.metrics
    }
}

impl Drop for LinkSeries {
    fn drop(&mut self) {
        let mut links = self.links.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(count) = links.get_mut(&self.edge) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            links.remove(&self.edge);
            // Under the lock, so that a link of the same edge starting now sets them up again
            // only after they are gone.
            self.tunnel.remove(&self.edge);
        }
    }
}

impl Metrics {
    pub fn new() -> Self {
        let r = Registry::new();
        let build_info = IntGaugeVec::new(
            opts("build_info", "The operator's version; always 1."),
            &["version"],
        )
        .expect(VALID);
        register(&r, &build_info);
        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION")])
            .set(1);
        let reloads = counter_vec(
            &r,
            "haproxy_reloads_total",
            "HAProxy configurations applied (ok), refused as invalid (refused), or whose reload \
             failed (failed).",
            &["result"],
        );
        let reconcile_duration = Histogram::with_opts(
            HistogramOpts::new(
                "reconcile_duration_seconds",
                "A pass of the controller loop, from taking the snapshot to the end of its \
                 status write.",
            )
            .namespace(NAMESPACE),
        )
        .expect(VALID);
        register(&r, &reconcile_duration);
        let control = Control {
            haproxy_reloads_ok: reloads.with_label_values(&["ok"]),
            haproxy_reloads_refused: reloads.with_label_values(&["refused"]),
            haproxy_reloads_failed: reloads.with_label_values(&["failed"]),
            haproxy_config_ok: gauge(
                &r,
                "haproxy_config_ok",
                "1 when HAProxy took the last configuration applied, else 0.",
            ),
            reconciles: counter(&r, "reconciles_total", "Passes of the controller loop."),
            reconcile_duration,
            status_write_failures: counter(
                &r,
                "status_write_failures_total",
                "Status writes that failed.",
            ),
        };
        let edge = &["edge"];
        let tunnel = Tunnel {
            up: gauge_vec(&r, "tunnel_up", "1 while the edge is connected.", edge),
            path: gauge_vec(
                &r,
                "tunnel_path",
                "1 for the path the tunnel to the edge sends on, direct or relay, 0 for the \
                 other; both 0 while not connected.",
                &["edge", "path"],
            ),
            path_selected: counter_vec(
                &r,
                "tunnel_path_selected_total",
                "Times a connection to the edge selected a direct or a relay path to send on, \
                 its first path included.",
                &["edge", "path"],
            ),
            sessions: counter_vec(
                &r,
                "tunnel_sessions_total",
                "Dials of the edge that connected.",
                edge,
            ),
            dial_failures: counter_vec(
                &r,
                "tunnel_dial_failures_total",
                "Dials of the edge that failed.",
                edge,
            ),
            listeners: gauge_vec(
                &r,
                "tunnel_listeners",
                "The edge's listeners, bound or failed, from its last status; 0 while not \
                 connected.",
                &["edge", "state"],
            ),
            streams_open: gauge_vec(
                &r,
                "tunnel_streams_open",
                "Visitor streams being served.",
                edge,
            ),
            streams: counter_vec(
                &r,
                "tunnel_streams_total",
                "Visitor streams accepted.",
                edge,
            ),
            streams_refused: counter_vec(
                &r,
                "tunnel_streams_refused_total",
                "Visitor streams reset before forwarding.",
                &["edge", "reason"],
            ),
            tcp_bytes: counter_vec(
                &r,
                "tunnel_tcp_bytes_total",
                "Bytes written to the backend (in) and to the tunnel stream (out).",
                &["edge", "direction"],
            ),
            udp_flows: gauge_vec(&r, "tunnel_udp_flows", "UDP flows held.", edge),
            udp_flows_total: counter_vec(&r, "tunnel_udp_flows_total", "UDP flows created.", edge),
            udp_flows_evicted: counter_vec(
                &r,
                "tunnel_udp_flows_evicted_total",
                "UDP flows pushed out at the flow cap.",
                edge,
            ),
            udp_packets: counter_vec(
                &r,
                "tunnel_udp_packets_total",
                "UDP packets sent to a backend (in) and replies handed to the tunnel in full \
                 (out).",
                &["edge", "direction"],
            ),
            udp_bytes: counter_vec(
                &r,
                "tunnel_udp_bytes_total",
                "Payload bytes of the packets in tunnel_udp_packets_total.",
                &["edge", "direction"],
            ),
            udp_fragmented: counter_vec(
                &r,
                "tunnel_udp_fragmented_packets_total",
                "UDP packets reassembled from more than one datagram (in) or replies split \
                 into more than one (out).",
                &["edge", "direction"],
            ),
            udp_dropped: counter_vec(
                &r,
                "tunnel_udp_dropped_total",
                "Dropped UDP packets or datagrams.",
                &["edge", "reason"],
            ),
        };
        Self {
            registry: r,
            tunnel,
            links: Arc::default(),
            control,
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

    /// The series of HAProxy and of the controller loop.
    pub(crate) fn control(&self) -> &Control {
        &self.control
    }

    /// Sets up every series of `edge`, for a link that starts; they go when it drops the hold.
    pub(crate) fn link(&self, edge: EndpointId) -> LinkSeries {
        let edge = edge.to_string();
        let mut links = self.links.lock().unwrap_or_else(PoisonError::into_inner);
        *links.entry(edge.clone()).or_default() += 1;
        let t = &self.tunnel;
        let e = edge.as_str();
        let per_direction = |vec: &IntCounterVec| PerDirection {
            inbound: vec.with_label_values(&[e, "in"]),
            outbound: vec.with_label_values(&[e, "out"]),
        };
        let dropped = |reason| t.udp_dropped.with_label_values(&[e, reason]);
        let refused = |reason| t.streams_refused.with_label_values(&[e, reason]);
        let metrics = LinkMetrics {
            up: t.up.with_label_values(&[e]),
            path: Paths {
                direct: t.path.with_label_values(&[e, "direct"]),
                relay: t.path.with_label_values(&[e, "relay"]),
            },
            path_selected: PathsSelected {
                direct: t.path_selected.with_label_values(&[e, "direct"]),
                relay: t.path_selected.with_label_values(&[e, "relay"]),
            },
            sessions: t.sessions.with_label_values(&[e]),
            dial_failures: t.dial_failures.with_label_values(&[e]),
            listeners: Listeners {
                bound: t.listeners.with_label_values(&[e, "bound"]),
                failed: t.listeners.with_label_values(&[e, "failed"]),
            },
            streams_open: t.streams_open.with_label_values(&[e]),
            streams: t.streams.with_label_values(&[e]),
            refused: Refusals {
                bad_header: refused("bad_header"),
                unknown_listener: refused("unknown_listener"),
                backend_unavailable: refused("backend_unavailable"),
            },
            tcp_bytes: per_direction(&t.tcp_bytes),
            udp: UdpMetrics {
                flows: t.udp_flows.with_label_values(&[e]),
                flows_total: t.udp_flows_total.with_label_values(&[e]),
                flows_evicted: t.udp_flows_evicted.with_label_values(&[e]),
                packets: per_direction(&t.udp_packets),
                bytes: per_direction(&t.udp_bytes),
                fragmented: per_direction(&t.udp_fragmented),
                dropped: UdpDrops {
                    bad_datagram: dropped("bad_datagram"),
                    retired_listener: dropped("retired_listener"),
                    unknown_listener: dropped("unknown_listener"),
                    not_udp: dropped("not_udp"),
                    wrong_listener: dropped("wrong_listener"),
                    no_target: dropped("no_target"),
                    socket_error: dropped("socket_error"),
                    send_error: dropped("send_error"),
                    tunnel_full: dropped("tunnel_full"),
                },
            },
        };
        drop(links);
        LinkSeries {
            metrics,
            edge,
            tunnel: self.tunnel.clone(),
            links: self.links.clone(),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Tunnel {
    /// Removes every series labelled with `edge`.
    fn remove(&self, edge: &str) {
        forget(&self.up, edge, &[]);
        forget(&self.path, edge, &PATHS);
        forget(&self.path_selected, edge, &PATHS);
        forget(&self.sessions, edge, &[]);
        forget(&self.dial_failures, edge, &[]);
        forget(&self.listeners, edge, &STATES);
        forget(&self.streams_open, edge, &[]);
        forget(&self.streams, edge, &[]);
        forget(&self.streams_refused, edge, &REFUSALS);
        forget(&self.tcp_bytes, edge, &DIRECTIONS);
        forget(&self.udp_flows, edge, &[]);
        forget(&self.udp_flows_total, edge, &[]);
        forget(&self.udp_flows_evicted, edge, &[]);
        forget(&self.udp_packets, edge, &DIRECTIONS);
        forget(&self.udp_bytes, edge, &DIRECTIONS);
        forget(&self.udp_fragmented, edge, &DIRECTIONS);
        forget(&self.udp_dropped, edge, &UDP_DROPS);
    }
}

/// Removes the series of `vec` labelled `edge` alone, or `edge` and each of `seconds`.
fn forget<T: MetricVecBuilder>(vec: &MetricVec<T>, edge: &str, seconds: &[&str]) {
    // Err only for a series that is not there.
    if seconds.is_empty() {
        let _ = vec.remove_label_values(&[edge]);
    }
    for second in seconds {
        let _ = vec.remove_label_values(&[edge, second]);
    }
}

/// The names and labels are fixed and each is registered once, so neither can fail.
const VALID: &str = "a valid metric registered once";

fn opts(name: &str, help: &str) -> Opts {
    Opts::new(name, help).namespace(NAMESPACE)
}

fn register<C: prometheus::core::Collector + Clone + 'static>(r: &Registry, collector: &C) {
    r.register(Box::new(collector.clone())).expect(VALID);
}

fn counter(r: &Registry, name: &str, help: &str) -> IntCounter {
    let counter = IntCounter::with_opts(opts(name, help)).expect(VALID);
    register(r, &counter);
    counter
}

fn gauge(r: &Registry, name: &str, help: &str) -> IntGauge {
    let gauge = IntGauge::with_opts(opts(name, help)).expect(VALID);
    register(r, &gauge);
    gauge
}

fn counter_vec(r: &Registry, name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let vec = IntCounterVec::new(opts(name, help), labels).expect(VALID);
    register(r, &vec);
    vec
}

fn gauge_vec(r: &Registry, name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    let vec = IntGaugeVec::new(opts(name, help), labels).expect(VALID);
    register(r, &vec);
    vec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_sets_up_and_removes_every_series_of_its_edge() {
        let m = Metrics::new();
        let id = iroh::SecretKey::generate().public();
        let edge = format!("edge=\"{id}\"");
        let before = m.render();
        assert!(before.contains(&format!(
            "iroh_gateway_operator_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(before.contains("iroh_gateway_operator_haproxy_reloads_total{result=\"ok\"} 0"));
        assert!(before.contains("iroh_gateway_operator_reconcile_duration_seconds_count 0"));
        assert!(!before.contains("edge="));

        let one = m.link(id);
        let two = m.link(id);
        let lines = |text: &str| text.lines().filter(|l| l.contains(&edge)).count();
        // 8 series with `edge` alone, 2 + 2 + 2 + 3 + 4 × 2 + 9 with a second label.
        assert_eq!(lines(&m.render()), 34, "{}", m.render());
        assert_eq!(id.to_string().len(), 64);
        drop(one);
        assert_eq!(
            lines(&m.render()),
            34,
            "another link still reports on the edge"
        );
        drop(two);
        assert_eq!(lines(&m.render()), 0, "{}", m.render());
        assert!(prometheus::gather().is_empty());
    }
}
