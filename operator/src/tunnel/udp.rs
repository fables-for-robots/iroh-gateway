//! UDP flows of one session: the edge numbers each visitor flow, and the operator gives every
//! flow a connected socket towards a target its listener's table picks by weight. Replies go back
//! under the flow's listener id and flow id.
//!
//! A flow lasts while its listener id is in the session's routes, its target is listed with a
//! weight above 0 for that listener and packets pass in either direction; whatever ends it closes its socket, so no
//! reply of an old backend reaches a visitor afterwards.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh_gateway_proto::control::{ListenerKey, Protocol};
use iroh_gateway_proto::datagram::{
    Header, MAX_PACKET, Packet, REASSEMBLY_BYTES, REASSEMBLY_WINDOW, Reassembler, split,
};
use iroh_gateway_proto::idle::IdleMap;
use iroh_gateway_proto::throttle::{LOG_EVERY, LogThrottle};
use socket2::SockRef;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::field::display;
use tracing::{Instrument, debug, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpTarget {
    pub addr: SocketAddr,
    pub weight: u32,
}

/// Where the packets of each UDP listener go. Keys have `Protocol::Udp`.
///
/// A new flow goes to a target picked by weight; a flow ends as soon as its target is no longer
/// listed with a weight above 0 for its listener (a weight-0 target gets no traffic, and UDP has
/// nothing to drain).
pub type UdpTargets = HashMap<ListenerKey, Vec<UdpTarget>>;

/// The target `roll` falls on when the weights are laid end to end; `roll` is taken modulo the
/// sum of the weights. None when no target has a weight above 0.
pub fn pick(targets: &[UdpTarget], roll: u64) -> Option<SocketAddr> {
    let total: u128 = targets.iter().map(|t| u128::from(t.weight)).sum();
    if total == 0 {
        return None;
    }
    let mut at = u128::from(roll) % total;
    for target in targets {
        let weight = u128::from(target.weight);
        if at < weight {
            return Some(target.addr);
        }
        at -= weight;
    }
    None
}

/// Listener id → key, as the session's last `Config` sent has them.
pub(crate) type Routes = HashMap<u32, ListenerKey>;

/// One above the highest listener id the link has issued. A link never reuses an id, so every
/// id from 1 up to below it was in some `Config` of the link.
pub(crate) type IssuedIds = Arc<AtomicU32>;

/// Why a datagram's listener id leads to no UDP listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    /// An id of an earlier config: the edge had not applied the new one yet.
    Retired,
    /// An id the link never issued: the edge is broken.
    NeverIssued,
    /// A TCP listener's id: the edge is broken.
    NotUdp,
}

/// The UDP listener a datagram under `listener_id` is for; `issued` as [`IssuedIds`] holds.
fn udp_listener(routes: &Routes, issued: u32, listener_id: u32) -> Result<ListenerKey, Refused> {
    match routes.get(&listener_id) {
        Some(key) if key.protocol == Protocol::Udp => Ok(*key),
        Some(_) => Err(Refused::NotUdp),
        None if (1..issued).contains(&listener_id) => Err(Refused::Retired),
        None => Err(Refused::NeverIssued),
    }
}

/// How often idle flows are looked for.
const EXPIRE_EVERY: Duration = Duration::from_secs(1);

/// Forwards the UDP datagrams of one session until its connection closes. Dropping the future
/// closes every flow. A closed `routes` or `targets` channel keeps its last value.
///
/// `max_flows` of 0 is taken as 1.
pub(crate) async fn forward(
    conn: Connection,
    mut routes: watch::Receiver<Routes>,
    issued: IssuedIds,
    mut targets: watch::Receiver<UdpTargets>,
    max_flows: usize,
    idle: Duration,
) {
    let shared = Arc::new(Shared {
        conn,
        issued,
        flows: Mutex::new(IdleMap::new(max_flows.max(1), idle)),
        buffer: Mutex::new(vec![0; MAX_PACKET].into_boxed_slice()),
        drops: Drops::default(),
    });
    let _close = CloseFlows(shared.clone());
    let mut forwarder = Forwarder {
        shared,
        reassembler: Reassembler::new(REASSEMBLY_BYTES, REASSEMBLY_WINDOW),
        next_seq: 0,
    };
    let mut expiry = tokio::time::interval(EXPIRE_EVERY);
    expiry.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let (mut routes_open, mut targets_open) = (true, true);
    loop {
        // A datagram that is already queued is read without waiting, which takes no part in
        // tokio's budget: without this, a flood would keep the task on its thread.
        tokio::task::coop::consume_budget().await;
        // Changes first: a datagram sent after a change is forwarded under it.
        tokio::select! {
            biased;
            changed = routes.changed(), if routes_open => {
                routes_open = changed.is_ok();
                let routes = routes.borrow_and_update();
                forwarder.close_where(|flow| routes.get(&flow.listener_id) != Some(&flow.key));
            }
            changed = targets.changed(), if targets_open => {
                targets_open = changed.is_ok();
                let targets = targets.borrow_and_update();
                forwarder.close_where(|flow| {
                    !targets
                        .get(&flow.key)
                        .is_some_and(|ts| ts.iter().any(|t| t.addr == flow.target && t.weight > 0))
                });
            }
            _ = expiry.tick() => forwarder.expire(),
            datagram = forwarder.shared.conn.read_datagram() => match datagram {
                Ok(datagram) => {
                    let routes = routes.borrow();
                    let targets = targets.borrow();
                    forwarder.on_datagram(datagram, &routes, &targets);
                }
                Err(e) => {
                    debug!("udp datagrams ended: {e}");
                    return;
                }
            },
        }
    }
}

/// What the forwarder and its flows' tasks share.
struct Shared {
    conn: Connection,
    issued: IssuedIds,
    flows: Mutex<IdleMap<u64, Flow>>,
    /// Receives the replies of every flow; held only for one `try_recv` and its split.
    buffer: Mutex<Box<[u8]>>,
    drops: Drops,
}

impl Shared {
    /// The listener id and the next packet id of a reply of flow `flow_id`, marking the flow
    /// used; None once the flow is not the one with `seq`.
    fn reply_ids(&self, flow_id: u64, seq: u64) -> Option<(u32, u32)> {
        let mut flows = lock(&self.flows);
        if flows.get(&flow_id)?.seq != seq {
            return None;
        }
        let flow = flows.touch(&flow_id, now())?;
        let packet_id = flow.next_packet;
        flow.next_packet = packet_id.wrapping_add(1);
        Some((flow.listener_id, packet_id))
    }
}

/// Closes every flow of a forwarder that stops, however it stops.
struct CloseFlows(Arc<Shared>);

impl Drop for CloseFlows {
    fn drop(&mut self) {
        lock(&self.0.flows).clear();
    }
}

struct Flow {
    key: ListenerKey,
    /// The listener id the flow was made under; packets under another are dropped.
    listener_id: u32,
    target: SocketAddr,
    /// Connected to `target`.
    socket: Arc<UdpSocket>,
    next_packet: u32,
    /// Tells this flow from a later one with the same id.
    seq: u64,
    /// Reads the replies.
    task: JoinHandle<()>,
}

impl Drop for Flow {
    /// The socket closes once the aborted task has let go of it.
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Forwarder {
    shared: Arc<Shared>,
    reassembler: Reassembler,
    next_seq: u64,
}

impl Forwarder {
    fn on_datagram(&mut self, datagram: Bytes, routes: &Routes, targets: &UdpTargets) {
        let drops = &self.shared.drops;
        let Ok((header, payload)) = Header::decode(datagram) else {
            drops.bad_datagram.hit();
            return;
        };
        let issued = self.shared.issued.load(Ordering::Acquire);
        let key = match udp_listener(routes, issued, header.listener_id) {
            Ok(key) => key,
            Err(refused) => {
                let counter = match refused {
                    Refused::Retired => &drops.retired_listener,
                    Refused::NeverIssued => &drops.unknown_listener,
                    Refused::NotUdp => &drops.not_udp,
                };
                counter.hit();
                return;
            }
        };
        if let Some(packet) = self.reassembler.push(header, payload, now()) {
            self.send(key, packet, targets);
        }
    }

    /// Sends a visitor packet on its flow's socket, making the flow if it is new.
    fn send(&mut self, key: ListenerKey, packet: Packet, targets: &UdpTargets) {
        let shared = &self.shared;
        let now = now();
        let known = {
            let mut flows = lock(&shared.flows);
            match flows.get(&packet.flow_id) {
                Some(flow) if flow.listener_id != packet.listener_id => Err(()),
                Some(_) => Ok(flows
                    .touch(&packet.flow_id, now)
                    .map(|flow| flow.socket.clone())),
                None => Ok(None),
            }
        };
        let socket = match known {
            Err(()) => {
                shared.drops.wrong_listener.hit();
                return;
            }
            Ok(Some(socket)) => socket,
            Ok(None) => {
                let Some(target) = targets.get(&key).and_then(|ts| pick(ts, fastrand::u64(..)))
                else {
                    shared.drops.no_target.hit();
                    return;
                };
                let socket = match connect(target) {
                    Ok(socket) => Arc::new(socket),
                    Err(e) => {
                        shared
                            .drops
                            .socket_error
                            .hit_with(&format_args!("opening a socket to {target} failed: {e}"));
                        return;
                    }
                };
                self.next_seq += 1;
                let seq = self.next_seq;
                let task = tokio::spawn(
                    replies(shared.clone(), socket.clone(), packet.flow_id, seq).in_current_span(),
                );
                let flow = Flow {
                    key,
                    listener_id: packet.listener_id,
                    target,
                    socket: socket.clone(),
                    // Not 0: a reply of an earlier flow with this id must not share packet
                    // ids with this flow's, or the edge could join fragments of the two.
                    next_packet: fastrand::u32(..),
                    seq,
                    task,
                };
                let pushed_out = lock(&shared.flows).insert(packet.flow_id, flow, now);
                drop(pushed_out);
                socket
            }
        };
        // Straight to the kernel, as a non-blocking send: tokio's `try_send` refuses until the
        // reactor has reported a new socket writable, which would drop a flow's first packets.
        if SockRef::from(socket.as_ref())
            .send(&packet.payload)
            .is_err()
        {
            shared.drops.socket_error.hit();
        }
    }

    /// Closes the flows `close` picks.
    fn close_where(&self, mut close: impl FnMut(&Flow) -> bool) {
        let closed = lock(&self.shared.flows).retain(|_, flow| !close(flow));
        drop(closed);
    }

    fn expire(&self) {
        let expired = lock(&self.shared.flows).expire(now());
        drop(expired);
    }
}

/// Sends the replies that arrive on a flow's socket into the tunnel, until the flow closes and
/// aborts it. A receive error (such as `ConnectionRefused` after an ICMP error) is ignored.
async fn replies(shared: Arc<Shared>, socket: Arc<UdpSocket>, flow_id: u64, seq: u64) {
    loop {
        // Cached readiness, `try_recv` and the sends never wait or take from tokio's budget:
        // without this, a backend sending faster than the loop drains would keep the task on
        // its thread.
        tokio::task::coop::consume_budget().await;
        if socket.readable().await.is_err() {
            return;
        }
        let datagrams = {
            let mut buffer = lock(&shared.buffer);
            let len = match socket.try_recv(&mut buffer) {
                Ok(len) => len,
                // Spurious readiness, or an error the next packet does not care about.
                Err(_) => continue,
            };
            // A flow that is not inserted yet or already closed sends nothing.
            let Some((listener_id, packet_id)) = shared.reply_ids(flow_id, seq) else {
                continue;
            };
            // The size changes with the path, so it is read for every packet.
            let max = shared.conn.max_datagram_size().unwrap_or(0);
            split(listener_id, flow_id, packet_id, &buffer[..len], max)
        };
        let Ok(datagrams) = datagrams else {
            shared.drops.send_error.hit();
            continue;
        };
        for datagram in datagrams {
            if shared.conn.send_datagram(datagram).is_err() {
                shared.drops.send_error.hit();
                break;
            }
        }
    }
}

/// A non-blocking UDP socket on the unspecified address of `target`'s family, connected to it.
fn connect(target: SocketAddr) -> io::Result<UdpSocket> {
    let local = match target {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let socket = std::net::UdpSocket::bind(local)?;
    socket.connect(target)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// Dropped packets, per reason.
struct Drops {
    bad_datagram: Counter,
    /// A listener id of an earlier config, during the round trip before the edge applies a new
    /// one.
    retired_listener: Counter,
    /// A listener id the link never issued: the edge is broken.
    unknown_listener: Counter,
    /// A TCP listener's id: the edge is broken.
    not_udp: Counter,
    /// A known flow id under another listener id.
    wrong_listener: Counter,
    no_target: Counter,
    /// Opening a flow's socket failed, or it refused a packet.
    socket_error: Counter,
    /// A reply that could not be split at the session's datagram size (none known, no room
    /// past the header, or more than `MAX_FRAGMENTS` pieces), or a datagram `send_datagram`
    /// refused (too large for the path, datagrams unsupported, or the connection lost). Not
    /// counted: on a full send buffer the QUIC layer discards the oldest queued datagram, one
    /// piece of some earlier packet, silently.
    send_error: Counter,
}

impl Default for Drops {
    fn default() -> Self {
        Self {
            bad_datagram: Counter::new("bad datagram"),
            retired_listener: Counter::new("listener id of an earlier config"),
            unknown_listener: Counter::warning(
                "listener id the operator never issued; the edge is broken",
            ),
            not_udp: Counter::warning("datagram for a tcp listener; the edge is broken"),
            wrong_listener: Counter::new("known flow under another listener id"),
            no_target: Counter::new("no target"),
            socket_error: Counter::new("backend socket error"),
            send_error: Counter::new("could not be sent into the tunnel"),
        }
    }
}

struct Counter {
    reason: &'static str,
    /// Logged at warn rather than debug.
    warn: bool,
    count: AtomicU64,
    log: Mutex<LogThrottle>,
}

impl Counter {
    fn new(reason: &'static str) -> Self {
        Self {
            reason,
            warn: false,
            count: AtomicU64::new(0),
            log: Mutex::new(LogThrottle::new(LOG_EVERY)),
        }
    }

    fn warning(reason: &'static str) -> Self {
        Self {
            warn: true,
            ..Self::new(reason)
        }
    }

    fn hit(&self) {
        self.count_and_log(None);
    }

    /// [`Counter::hit`], logging `detail` with the drop when the throttle lets it through.
    fn hit_with(&self, detail: &dyn fmt::Display) {
        self.count_and_log(Some(detail));
    }

    fn count_and_log(&self, detail: Option<&dyn fmt::Display>) {
        let total = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        let Some(suppressed) = lock(&self.log).hit() else {
            return;
        };
        let detail = detail.map(display);
        if self.warn {
            warn!(
                total,
                suppressed, detail, "udp packet dropped: {}", self.reason
            );
        } else {
            debug!(
                total,
                suppressed, detail, "udp packet dropped: {}", self.reason
            );
        }
    }
}

/// The time on tokio's clock, as the proto types take it.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Nothing holding these locks can panic halfway through a change, so a poisoned lock is
/// taken as it is.
fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(addr: &str, weight: u32) -> UdpTarget {
        UdpTarget {
            addr: addr.parse().unwrap(),
            weight,
        }
    }

    #[test]
    fn listener_ids_are_told_apart() {
        let key = |protocol, port| ListenerKey { protocol, port };
        let routes: Routes = [(3, key(Protocol::Udp, 53)), (4, key(Protocol::Tcp, 53))]
            .into_iter()
            .collect();
        // Ids 1 to 5 were issued; 1, 2 and 5 are retired.
        let issued = 6;
        let got = |id| udp_listener(&routes, issued, id);
        assert_eq!(got(3), Ok(key(Protocol::Udp, 53)));
        assert_eq!(got(4), Err(Refused::NotUdp));
        for id in [1, 2, 5] {
            assert_eq!(got(id), Err(Refused::Retired), "id {id}");
        }
        for id in [0, 6, 7, u32::MAX] {
            assert_eq!(got(id), Err(Refused::NeverIssued), "id {id}");
        }
        // Before any config, no id was issued.
        assert_eq!(
            udp_listener(&Routes::new(), 1, 1),
            Err(Refused::NeverIssued)
        );
    }

    #[test]
    fn pick_follows_the_weights() {
        let ts = [
            t("10.0.0.1:53", 1),
            t("10.0.0.2:53", 0),
            t("10.0.0.3:53", 3),
        ];
        let got: Vec<_> = (0..8)
            .map(|r| pick(&ts, r).unwrap().ip().to_string())
            .collect();
        assert_eq!(
            got,
            [
                "10.0.0.1", "10.0.0.3", "10.0.0.3", "10.0.0.3", "10.0.0.1", "10.0.0.3", "10.0.0.3",
                "10.0.0.3"
            ]
        );
        assert_eq!(
            pick(&ts, u64::MAX).map(|a| a.to_string()).as_deref(),
            Some("10.0.0.3:53")
        );
    }

    #[test]
    fn pick_is_none_without_a_positive_weight() {
        assert_eq!(pick(&[], 0), None);
        assert_eq!(pick(&[], u64::MAX), None);
        let zero = [t("10.0.0.1:53", 0), t("10.0.0.2:53", 0)];
        for roll in [0, 1, 7, u64::MAX] {
            assert_eq!(pick(&zero, roll), None);
        }
    }

    #[test]
    fn pick_does_not_overflow_with_large_weights() {
        let ts = [
            t("10.0.0.1:53", u32::MAX),
            t("10.0.0.2:53", u32::MAX),
            t("10.0.0.3:53", u32::MAX),
        ];
        let max = u64::from(u32::MAX);
        let at = |roll| pick(&ts, roll).unwrap().ip().to_string();
        assert_eq!(at(0), "10.0.0.1");
        assert_eq!(at(max - 1), "10.0.0.1");
        assert_eq!(at(max), "10.0.0.2");
        assert_eq!(at(2 * max), "10.0.0.3");
        assert_eq!(at(3 * max - 1), "10.0.0.3");
        // The sum, 3 × (2^32 - 1), is past the end and starts over.
        assert_eq!(at(3 * max), "10.0.0.1");
        // u64::MAX mod 3 × (2^32 - 1) is 2 × (2^32 - 1): the first roll of the third target.
        assert_eq!(u64::MAX % (3 * max), 2 * max);
        assert_eq!(at(u64::MAX), "10.0.0.3");
    }
}
