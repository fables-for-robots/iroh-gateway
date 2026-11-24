//! UDP flows: visitor packets go into the tunnel as datagrams, replies come back under the
//! flow's id.
//!
//! A flow is one visitor address on one UDP port. The hub numbers flows for its whole life and
//! forgets them all when the session changes, so a reply can only reach a visitor of the
//! session whose operator saw that visitor's packets.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh_gateway_proto::datagram::{
    Header, MAX_PACKET, REASSEMBLY_BYTES, REASSEMBLY_WINDOW, Reassembler, split,
};
use iroh_gateway_proto::idle::IdleMap;
use iroh_gateway_proto::throttle::{LOG_EVERY, LogThrottle};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::debug;

/// Packets queued for one UDP port to send to its visitors.
pub(crate) const REPLY_QUEUE: usize = 256;
/// How often idle flows are looked for.
const EXPIRE_EVERY: Duration = Duration::from_secs(1);

/// A reply for a UDP port's task to send: the visitor's address and the payload.
pub(crate) type Reply = (SocketAddr, Bytes);

/// The UDP flows of an edge and the session they are forwarded over.
pub struct UdpHub {
    shared: Arc<Shared>,
    /// Reads the current session's datagrams.
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl UdpHub {
    /// Panics if `max_flows` is 0.
    pub fn new(max_flows: usize, idle: Duration, rate_limit: Option<u64>) -> Arc<Self> {
        let now = now();
        Arc::new(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    conn: None,
                    session: 0,
                    bucket: rate_limit.map(|rate| TokenBucket::new(rate, now)),
                    flows: Flows::new(max_flows, idle),
                }),
                drops: Drops::default(),
            }),
            reader: Mutex::new(None),
        })
    }

    /// Forwards UDP over `conn` from now on and forgets every flow; None stops forwarding.
    pub fn set_session(&self, conn: Option<Connection>) {
        let mut reader = lock(&self.reader);
        if let Some(old) = reader.take() {
            old.abort();
        }
        let session = {
            let mut state = self.shared.lock();
            state.session += 1;
            state.conn = conn.clone();
            state.flows.clear();
            state.session
        };
        if let Some(conn) = conn {
            *reader = Some(tokio::spawn(read_datagrams(
                self.shared.clone(),
                conn,
                session,
            )));
        }
    }

    /// Forgets the flows of a port that closed.
    pub fn forget_port(&self, port: u16) {
        self.shared.lock().flows.forget_port(port);
    }

    pub fn flows(&self) -> usize {
        self.shared.lock().flows.len()
    }

    /// Forwards one visitor packet received on `port`, whose listener has `listener_id`;
    /// replies to it go to `replies`. Drops it when it cannot be sent at once.
    pub(crate) fn forward(
        &self,
        port: u16,
        listener_id: u32,
        visitor: SocketAddr,
        payload: &[u8],
        replies: &mpsc::Sender<Reply>,
    ) {
        let drops = &self.shared.drops;
        let now = now();
        let (conn, flow_id, packet_id) = {
            let mut state = self.shared.lock();
            let state = &mut *state;
            let Some(conn) = state.conn.clone() else {
                drops.no_session.hit();
                return;
            };
            if let Some(bucket) = &mut state.bucket
                && !bucket.take(payload.len(), now)
            {
                drops.rate_limit.hit();
                return;
            }
            let (flow_id, packet_id) =
                state
                    .flows
                    .outgoing(port, visitor, listener_id, replies, now);
            (conn, flow_id, packet_id)
        };
        // The size changes with the path, so it is read for every packet.
        let Some(max) = conn.max_datagram_size() else {
            drops.send_error.hit();
            return;
        };
        let Ok(datagrams) = split(listener_id, flow_id, packet_id, payload, max) else {
            drops.send_error.hit();
            return;
        };
        for datagram in datagrams {
            if conn.send_datagram(datagram).is_err() {
                drops.send_error.hit();
                return;
            }
        }
    }
}

impl Drop for UdpHub {
    fn drop(&mut self) {
        if let Some(reader) = lock(&self.reader).take() {
            reader.abort();
        }
    }
}

/// What the port tasks and the session's reader share.
struct Shared {
    state: Mutex<State>,
    drops: Drops,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// Hands one datagram from the tunnel to its flow's port. False once `session` is no
    /// longer the current session.
    fn reply(&self, datagram: Bytes, reassembler: &mut Reassembler, session: u64) -> bool {
        let now = now();
        let Ok((header, payload)) = Header::decode(datagram) else {
            self.drops.bad_datagram.hit();
            return true;
        };
        let Some(packet) = reassembler.push(header, payload, now) else {
            return true;
        };
        let mut state = self.lock();
        if state.session != session {
            return false;
        }
        let Some(flow) = state
            .flows
            .incoming(packet.flow_id, packet.listener_id, now)
        else {
            self.drops.unknown_flow.hit();
            return true;
        };
        match flow.replies.try_send((flow.visitor, packet.payload)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => self.drops.send_error.hit(),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The port's task is gone.
                state.flows.remove(packet.flow_id);
                self.drops.send_error.hit();
            }
        }
        true
    }

    /// Forgets idle flows. False once `session` is no longer the current session.
    fn expire(&self, session: u64) -> bool {
        let mut state = self.lock();
        if state.session != session {
            return false;
        }
        state.flows.expire(now());
        true
    }
}

/// Reads the datagrams of one session until its connection closes or another session takes
/// its place, and expires idle flows meanwhile.
async fn read_datagrams(shared: Arc<Shared>, conn: Connection, session: u64) {
    let mut reassembler = Reassembler::new(REASSEMBLY_BYTES, REASSEMBLY_WINDOW);
    let mut expiry = tokio::time::interval(EXPIRE_EVERY);
    expiry.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        let current = tokio::select! {
            datagram = conn.read_datagram() => match datagram {
                Ok(datagram) => shared.reply(datagram, &mut reassembler, session),
                Err(e) => {
                    debug!(session, "udp datagrams ended: {e}");
                    return;
                }
            },
            _ = expiry.tick() => shared.expire(session),
        };
        if !current {
            return;
        }
    }
}

struct State {
    /// The session UDP is forwarded over, once it has been configured.
    conn: Option<Connection>,
    /// Counts `set_session` calls, so that a reader of an earlier session touches nothing.
    session: u64,
    bucket: Option<TokenBucket>,
    flows: Flows,
}

struct Flow {
    port: u16,
    /// As received: replies are sent to it from the same socket.
    visitor: SocketAddr,
    /// The listener id the flow's last visitor packet was sent under.
    listener_id: u32,
    next_packet: u32,
    replies: mpsc::Sender<Reply>,
}

/// The flows, by id and by `(port, visitor)`.
struct Flows {
    /// The id of the next new flow; ids are never reused.
    next_id: u64,
    by_id: IdleMap<u64, Flow>,
    by_visitor: HashMap<(u16, SocketAddr), u64>,
}

impl Flows {
    fn new(max_flows: usize, idle: Duration) -> Self {
        Self {
            next_id: 1,
            by_id: IdleMap::new(max_flows, idle),
            by_visitor: HashMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.by_id.len()
    }

    /// The flow of a visitor packet, made if it is new (replacing the least recently used one
    /// at the cap), marked used: its id and the packet's id.
    fn outgoing(
        &mut self,
        port: u16,
        visitor: SocketAddr,
        listener_id: u32,
        replies: &mpsc::Sender<Reply>,
        now: Instant,
    ) -> (u64, u32) {
        if let Some(&id) = self.by_visitor.get(&(port, visitor))
            && let Some(flow) = self.by_id.touch(&id, now)
        {
            flow.listener_id = listener_id;
            let packet_id = flow.next_packet;
            flow.next_packet = packet_id.wrapping_add(1);
            return (id, packet_id);
        }
        let id = self.next_id;
        self.next_id += 1;
        let flow = Flow {
            port,
            visitor,
            listener_id,
            next_packet: 1,
            replies: replies.clone(),
        };
        if let Some((_, old)) = self.by_id.insert(id, flow, now) {
            self.by_visitor.remove(&(old.port, old.visitor));
        }
        self.by_visitor.insert((port, visitor), id);
        (id, 0)
    }

    /// The flow a reply under `flow_id` and `listener_id` goes to, marked used; None for an
    /// unknown flow or a listener id other than its last visitor packet's.
    fn incoming(&mut self, flow_id: u64, listener_id: u32, now: Instant) -> Option<&Flow> {
        if self.by_id.get(&flow_id)?.listener_id != listener_id {
            return None;
        }
        self.by_id.touch(&flow_id, now).map(|flow| &*flow)
    }

    fn remove(&mut self, flow_id: u64) {
        if let Some(flow) = self.by_id.remove(&flow_id) {
            self.by_visitor.remove(&(flow.port, flow.visitor));
        }
    }

    fn forget_port(&mut self, port: u16) {
        for (_, flow) in self.by_id.retain(|_, flow| flow.port != port) {
            self.by_visitor.remove(&(flow.port, flow.visitor));
        }
    }

    fn expire(&mut self, now: Instant) {
        for (_, flow) in self.by_id.expire(now) {
            self.by_visitor.remove(&(flow.port, flow.visitor));
        }
    }

    /// Forgets every flow; ids go on counting.
    fn clear(&mut self) {
        self.by_id.clear();
        self.by_visitor.clear();
    }
}

/// `rate` bytes per second, holding at most `max(rate, MAX_PACKET)` bytes; starts full.
struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u64, now: Instant) -> Self {
        let capacity = rate.max(MAX_PACKET as u64) as f64;
        Self {
            rate: rate as f64,
            capacity,
            tokens: capacity,
            last: now,
        }
    }

    /// Takes `bytes` if they are there; a packet that does not fit takes nothing.
    fn take(&mut self, bytes: usize, now: Instant) -> bool {
        if now > self.last {
            let earned = now.duration_since(self.last).as_secs_f64() * self.rate;
            self.tokens = (self.tokens + earned).min(self.capacity);
            self.last = now;
        }
        let bytes = bytes as f64;
        if bytes > self.tokens {
            return false;
        }
        self.tokens -= bytes;
        true
    }
}

/// Dropped packets, per reason.
struct Drops {
    no_session: Counter,
    rate_limit: Counter,
    /// The tunnel refused a datagram, or a port's reply queue was full or gone.
    send_error: Counter,
    unknown_flow: Counter,
    bad_datagram: Counter,
}

impl Default for Drops {
    fn default() -> Self {
        Self {
            no_session: Counter::new("no session"),
            rate_limit: Counter::new("over the rate limit"),
            send_error: Counter::new("could not be sent"),
            unknown_flow: Counter::new("unknown flow"),
            bad_datagram: Counter::new("bad datagram"),
        }
    }
}

struct Counter {
    reason: &'static str,
    count: AtomicU64,
    log: Mutex<LogThrottle>,
}

impl Counter {
    fn new(reason: &'static str) -> Self {
        Self {
            reason,
            count: AtomicU64::new(0),
            log: Mutex::new(LogThrottle::new(LOG_EVERY)),
        }
    }

    fn hit(&self) {
        let total = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(suppressed) = lock(&self.log).hit() {
            debug!(total, suppressed, "udp packet dropped: {}", self.reason);
        }
    }

    #[cfg(test)]
    fn get(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

/// The time on tokio's clock, as the proto types take it.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Nothing holding these locks can panic halfway through a change, so a poisoned lock is
/// taken as it is.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: fn(u64) -> Duration = Duration::from_millis;

    fn visitor(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    fn replies() -> (mpsc::Sender<Reply>, mpsc::Receiver<Reply>) {
        mpsc::channel(REPLY_QUEUE)
    }

    #[test]
    fn bucket_starts_full_refills_at_the_rate_and_drops_what_does_not_fit() {
        let t = Instant::now();
        let mut b = TokenBucket::new(70_000, t);
        for _ in 0..7 {
            assert!(b.take(9_000, t));
        }
        // 7,000 left: a packet that does not fit is dropped whole and costs nothing.
        assert!(!b.take(9_000, t));
        assert!(b.take(7_000, t));
        assert!(!b.take(1, t));
        assert!(b.take(0, t));
        // 100 ms earn 7,000 bytes.
        assert!(!b.take(7_001, t + MS(100)));
        assert!(b.take(7_000, t + MS(100)));
        // A long pause fills it only up to its size.
        assert!(b.take(70_000, t + MS(60_000)));
        assert!(!b.take(1, t + MS(60_000)));
    }

    #[test]
    fn bucket_holds_at_least_the_largest_packet() {
        let t = Instant::now();
        let mut b = TokenBucket::new(1_000, t);
        assert!(b.take(MAX_PACKET, t));
        assert!(!b.take(1, t));
        assert!(b.take(1_000, t + MS(1_000)));
        assert!(!b.take(1, t + MS(1_000)));
    }

    #[test]
    fn one_visitor_is_one_flow_and_ids_are_never_reused() {
        let t = Instant::now();
        let (tx, _rx) = replies();
        let mut f = Flows::new(8, Duration::from_secs(60));
        assert_eq!(f.outgoing(53, visitor(1), 7, &tx, t), (1, 0));
        assert_eq!(f.outgoing(53, visitor(1), 7, &tx, t), (1, 1));
        assert_eq!(f.outgoing(53, visitor(2), 7, &tx, t), (2, 0));
        // The same visitor on another port is another flow.
        assert_eq!(f.outgoing(54, visitor(1), 7, &tx, t), (3, 0));
        assert_eq!(f.len(), 3);
        f.clear();
        assert_eq!(f.len(), 0);
        assert_eq!(f.outgoing(53, visitor(1), 7, &tx, t), (4, 0));
    }

    #[test]
    fn packet_ids_wrap() {
        let t = Instant::now();
        let (tx, _rx) = replies();
        let mut f = Flows::new(8, Duration::from_secs(60));
        f.outgoing(53, visitor(1), 7, &tx, t);
        f.by_id.touch(&1, t).unwrap().next_packet = u32::MAX;
        assert_eq!(f.outgoing(53, visitor(1), 7, &tx, t), (1, u32::MAX));
        assert_eq!(f.outgoing(53, visitor(1), 7, &tx, t), (1, 0));
    }

    #[test]
    fn a_reply_needs_the_listener_id_of_the_last_visitor_packet() {
        let t = Instant::now();
        let (tx, _rx) = replies();
        let mut f = Flows::new(8, Duration::from_secs(60));
        let (id, _) = f.outgoing(53, visitor(1), 7, &tx, t);
        assert_eq!(f.incoming(id, 7, t).unwrap().visitor, visitor(1));
        assert!(f.incoming(id, 8, t).is_none());
        assert!(f.incoming(id + 1, 7, t).is_none());
        // The listener was given a new id, and the visitor sent under it.
        f.outgoing(53, visitor(1), 8, &tx, t);
        assert!(f.incoming(id, 7, t).is_none());
        assert!(f.incoming(id, 8, t).is_some());
    }

    #[test]
    fn at_the_cap_the_least_recently_used_flow_is_replaced() {
        let t = Instant::now();
        let (tx, _rx) = replies();
        let mut f = Flows::new(2, Duration::from_secs(60));
        let (a, _) = f.outgoing(53, visitor(1), 7, &tx, t);
        let (b, _) = f.outgoing(53, visitor(2), 7, &tx, t + MS(1));
        f.outgoing(53, visitor(1), 7, &tx, t + MS(2));
        let (c, _) = f.outgoing(53, visitor(3), 7, &tx, t + MS(3));
        assert_eq!(f.len(), 2);
        assert!(f.incoming(b, 7, t).is_none());
        assert!(f.incoming(a, 7, t).is_some());
        assert!(f.incoming(c, 7, t).is_some());
        // B comes back as a new flow; the index followed the eviction.
        assert_eq!(f.outgoing(53, visitor(2), 7, &tx, t + MS(4)), (c + 1, 0));
        assert_eq!(f.by_visitor.len(), 2);
    }

    #[test]
    fn idle_flows_expire_and_a_reply_keeps_one_alive() {
        let t = Instant::now();
        let (tx, _rx) = replies();
        let mut f = Flows::new(8, MS(300));
        let (a, _) = f.outgoing(53, visitor(1), 7, &tx, t);
        let (b, _) = f.outgoing(53, visitor(2), 7, &tx, t);
        assert!(f.incoming(a, 7, t + MS(200)).is_some());
        f.expire(t + MS(300));
        assert!(f.incoming(b, 7, t + MS(300)).is_none());
        assert!(f.incoming(a, 7, t + MS(300)).is_some());
        assert_eq!(f.by_visitor.len(), 1);
        f.expire(t + MS(600));
        assert_eq!(f.len(), 0);
        assert!(f.by_visitor.is_empty());
    }

    #[test]
    fn forget_port_forgets_only_that_port() {
        let t = Instant::now();
        let (tx, _rx) = replies();
        let mut f = Flows::new(8, Duration::from_secs(60));
        let (a, _) = f.outgoing(53, visitor(1), 7, &tx, t);
        let (b, _) = f.outgoing(54, visitor(1), 8, &tx, t);
        f.forget_port(53);
        assert!(f.incoming(a, 7, t).is_none());
        assert!(f.incoming(b, 8, t).is_some());
        assert_eq!(f.outgoing(53, visitor(1), 7, &tx, t), (3, 0));
    }

    #[tokio::test]
    async fn without_a_session_packets_are_dropped_and_counted() {
        let hub = UdpHub::new(8, Duration::from_secs(60), None);
        let (tx, _rx) = replies();
        hub.forward(53, 7, visitor(1), b"hello", &tx);
        assert_eq!(hub.shared.drops.no_session.get(), 1);
        assert_eq!(hub.flows(), 0);
        hub.set_session(None);
        hub.forward(53, 7, visitor(1), b"hello", &tx);
        assert_eq!(hub.shared.drops.no_session.get(), 2);
    }

    #[tokio::test]
    async fn a_closed_reply_queue_removes_the_flow() {
        let hub = UdpHub::new(8, Duration::from_secs(60), None);
        let (tx, rx) = replies();
        let (id, _) = hub
            .shared
            .lock()
            .flows
            .outgoing(53, visitor(1), 7, &tx, now());
        let session = hub.shared.lock().session;
        let reply = |payload: &'static [u8]| {
            let header = Header {
                listener_id: 7,
                flow_id: id,
                packet_id: 0,
                index: 0,
                count: 1,
            };
            let mut d = header.encode().to_vec();
            d.extend_from_slice(payload);
            Bytes::from(d)
        };
        let mut r = Reassembler::new(REASSEMBLY_BYTES, REASSEMBLY_WINDOW);
        assert!(hub.shared.reply(reply(b"one"), &mut r, session));
        drop(rx);
        assert!(hub.shared.reply(reply(b"two"), &mut r, session));
        assert_eq!(hub.flows(), 0);
        assert_eq!(hub.shared.drops.send_error.get(), 1);
        assert!(hub.shared.reply(reply(b"three"), &mut r, session));
        assert_eq!(hub.shared.drops.unknown_flow.get(), 1);
        assert!(
            hub.shared
                .reply(Bytes::from_static(b"short"), &mut r, session)
        );
        assert_eq!(hub.shared.drops.bad_datagram.get(), 1);
        // A reader of an earlier session stops.
        assert!(!hub.shared.reply(reply(b"four"), &mut r, session + 1));
    }
}
