//! `splice` between a loopback TCP socket and one QUIC stream between two loopback endpoints.

use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use iroh::{
    Endpoint, EndpointAddr, SecretKey,
    endpoint::{Connection, ReadError, RecvStream, SendStream, VarInt, WriteError},
};
use iroh_gateway_proto::{
    ALPN, RESET_ABORTED,
    splice::{
        LocalStream, SpliceEnd, SpliceMeter, SpliceOptions, SpliceStats, splice, splice_with,
    },
    transport::{Relay, Role, endpoint_builder},
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::{Instant, Interval, MissedTickBehavior, interval},
};

const TIMEOUT: Duration = Duration::from_secs(30);

async fn within<F: Future>(fut: F) -> F::Output {
    tokio::time::timeout(TIMEOUT, fut).await.expect("timed out")
}

/// Both ends of one connection. The endpoints are kept because dropping one kills its connections.
struct QuicPair {
    near: Connection,
    far: Connection,
    _endpoints: (Endpoint, Endpoint),
}

async fn quic_pair() -> QuicPair {
    let far_ep = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Edge)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();
    let near_ep = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Operator)
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();
    let addr = EndpointAddr::new(far_ep.id()).with_ip_addr(far_ep.bound_sockets()[0]);
    let accept = async { far_ep.accept().await.unwrap().await.unwrap() };
    let (near, far) = within(async { tokio::join!(near_ep.connect(addr, ALPN), accept) }).await;
    QuicPair {
        near: near.unwrap(),
        far,
        _endpoints: (near_ep, far_ep),
    }
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (a, b) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (a.unwrap(), b.unwrap().0)
}

/// `tcp_b` spliced with the near ends of one stream; the test drives `tcp_a` and the far ends.
struct Rig {
    tcp_a: TcpStream,
    far_send: SendStream,
    far_recv: RecvStream,
    quic: QuicPair,
    splice: JoinHandle<SpliceStats>,
}

/// tcp_b as splice's local side, taking `room` more bytes and then none, as if tcp_a had
/// stopped reading and every buffer on the way were full. Signals `stalled` when it gets
/// there. Reads, shutdown and `abort` go to the real socket.
struct StallingLocal {
    tcp: TcpStream,
    room: usize,
    stalled: Option<oneshot::Sender<()>>,
}

impl AsyncRead for StallingLocal {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_read(cx, buf)
    }
}

impl AsyncWrite for StallingLocal {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.room == 0 {
            if let Some(stalled) = this.stalled.take() {
                let _ = stalled.send(());
            }
            // Never woken: only an abort can end a splice stuck here.
            return Poll::Pending;
        }
        let n = buf.len().min(this.room);
        let written = ready!(Pin::new(&mut this.tcp).poll_write(cx, &buf[..n]));
        if let Ok(written) = written {
            this.room -= written;
        }
        Poll::Ready(written)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

impl LocalStream for StallingLocal {
    fn abort(self) {
        self.tcp.abort();
    }
}

/// tcp_b as splice's local side, taking at most `per_tick` bytes per `period`: slow, but never
/// stalled for longer than one period. The ticks start at the first write, once the rig is set
/// up, and a late tick delays the next instead of letting a burst through.
struct TricklingLocal {
    tcp: TcpStream,
    period: Duration,
    tick: Option<Interval>,
    per_tick: usize,
    allowance: usize,
}

impl AsyncRead for TricklingLocal {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_read(cx, buf)
    }
}

impl AsyncWrite for TricklingLocal {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.allowance == 0 {
            let period = this.period;
            let tick = this.tick.get_or_insert_with(|| {
                let mut tick = interval(period);
                tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
                tick
            });
            ready!(tick.poll_tick(cx));
            this.allowance = this.per_tick;
        }
        let n = buf.len().min(this.allowance);
        let written = ready!(Pin::new(&mut this.tcp).poll_write(cx, &buf[..n]));
        if let Ok(written) = written {
            this.allowance -= written;
        }
        Poll::Ready(written)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

impl LocalStream for TricklingLocal {
    fn abort(self) {
        self.tcp.abort();
    }
}

/// Spawns `splice(local, ..)`, or `splice_with` when given options, on the near ends of one
/// stream; returns the far ends.
async fn spliced<L: LocalStream>(
    local: L,
    opts: Option<SpliceOptions>,
) -> (SendStream, RecvStream, QuicPair, JoinHandle<SpliceStats>) {
    let quic = quic_pair().await;
    // A stream reaches the peer only once it carries something, so the near side sends a
    // one-byte stand-in for a stream header before splicing.
    let (mut send, recv) = within(quic.near.open_bi()).await.unwrap();
    send.write_all(b"h").await.unwrap();
    let (far_send, mut far_recv) = within(quic.far.accept_bi()).await.unwrap();
    let mut header = [0; 1];
    within(far_recv.read_exact(&mut header)).await.unwrap();
    assert_eq!(&header, b"h");
    let splice = match opts {
        None => tokio::spawn(splice(local, send, recv)),
        Some(opts) => tokio::spawn(splice_with(local, send, recv, opts)),
    };
    (far_send, far_recv, quic, splice)
}

async fn rig_from<L: LocalStream>(
    tcp_a: TcpStream,
    local_b: L,
    opts: Option<SpliceOptions>,
) -> Rig {
    let (far_send, far_recv, quic, splice) = spliced(local_b, opts).await;
    Rig {
        tcp_a,
        far_send,
        far_recv,
        quic,
        splice,
    }
}

async fn rig() -> Rig {
    let (tcp_a, tcp_b) = tcp_pair().await;
    rig_from(tcp_a, tcp_b, None).await
}

/// Reads until `tcp_a` fails, skipping data that arrived before the reset; EOF fails the test.
async fn read_until_reset(tcp_a: &mut TcpStream) -> io::Error {
    let mut buf = vec![0; 64 << 10];
    loop {
        match within(tcp_a.read(&mut buf)).await {
            Ok(0) => panic!("clean EOF where an abort was expected"),
            Ok(_) => continue,
            Err(err) => return err,
        }
    }
}

fn aborted() -> VarInt {
    VarInt::from_u32(RESET_ABORTED)
}

#[tokio::test]
async fn copies_both_directions() {
    let mut r = rig().await;
    let mut buf = [0; 4];

    r.tcp_a.write_all(b"ping").await.unwrap();
    within(r.far_recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"ping");

    r.far_send.write_all(b"pong").await.unwrap();
    within(r.tcp_a.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"pong");

    r.tcp_a.shutdown().await.unwrap();
    r.far_send.finish().unwrap();
    assert_eq!(within(r.far_recv.read_to_end(16)).await.unwrap(), b"");
    assert_eq!(within(r.tcp_a.read(&mut buf)).await.unwrap(), 0);
    let stats = within(r.splice).await.unwrap();
    assert_eq!(stats.end, SpliceEnd::Clean);
    assert_eq!((stats.to_remote, stats.to_local), (4, 4));
}

#[tokio::test]
async fn local_eof_finishes_stream_and_keeps_reading() {
    let mut r = rig().await;

    r.tcp_a.shutdown().await.unwrap();
    assert_eq!(within(r.far_recv.read_to_end(16)).await.unwrap(), b"");

    r.far_send.write_all(b"late").await.unwrap();
    r.far_send.finish().unwrap();
    let mut got = Vec::new();
    within(r.tcp_a.read_to_end(&mut got)).await.unwrap();
    assert_eq!(got, b"late");

    let stats = within(r.splice).await.unwrap();
    assert_eq!(stats.end, SpliceEnd::Clean);
    assert_eq!((stats.to_remote, stats.to_local), (0, 4));
}

#[tokio::test]
async fn remote_finish_shuts_local_write_and_keeps_reading() {
    let mut r = rig().await;
    let mut buf = [0; 8];

    r.far_send.finish().unwrap();
    assert_eq!(within(r.tcp_a.read(&mut buf)).await.unwrap(), 0);

    r.tcp_a.write_all(b"still").await.unwrap();
    r.tcp_a.shutdown().await.unwrap();
    assert_eq!(within(r.far_recv.read_to_end(16)).await.unwrap(), b"still");

    let stats = within(r.splice).await.unwrap();
    assert_eq!(stats.end, SpliceEnd::Clean);
    assert_eq!((stats.to_remote, stats.to_local), (5, 0));
}

#[tokio::test]
async fn local_abort_resets_stream() {
    let mut r = rig().await;
    let mut buf = [0; 8];

    r.tcp_a.set_zero_linger().unwrap();
    drop(r.tcp_a);

    let err = within(r.far_recv.read(&mut buf)).await.unwrap_err();
    assert_eq!(err, ReadError::Reset(aborted()));
    assert_eq!(within(r.far_send.stopped()).await.unwrap(), Some(aborted()));
    assert_eq!(within(r.splice).await.unwrap().end, SpliceEnd::LocalAborted);
}

#[tokio::test]
async fn remote_reset_aborts_local() {
    let mut r = rig().await;
    let mut buf = [0; 8];

    r.far_send.reset(VarInt::from_u32(9)).unwrap();

    let err = within(r.tcp_a.read(&mut buf)).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
    // The near send must be reset too: dropping it would have finished it cleanly.
    let err = within(r.far_recv.read(&mut buf)).await.unwrap_err();
    assert_eq!(err, ReadError::Reset(aborted()));
    assert_eq!(within(r.splice).await.unwrap().end, SpliceEnd::RemoteReset);
}

#[tokio::test]
async fn remote_stop_aborts_local() {
    let mut r = rig().await;
    let mut buf = [0; 8];

    r.far_recv.stop(VarInt::from_u32(9)).unwrap();

    let err = within(r.tcp_a.read(&mut buf)).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
    assert_eq!(within(r.far_send.stopped()).await.unwrap(), Some(aborted()));
    assert_eq!(within(r.splice).await.unwrap().end, SpliceEnd::RemoteReset);
}

#[tokio::test]
async fn connection_loss_aborts_local() {
    let mut r = rig().await;
    let mut buf = [0; 8];

    r.quic.far.close(0u32.into(), b"bye");

    let err = within(r.tcp_a.read(&mut buf)).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
    assert_eq!(
        within(r.splice).await.unwrap().end,
        SpliceEnd::ConnectionLost
    );
}

#[tokio::test]
async fn large_transfer_is_intact() {
    const LEN: usize = 8 << 20;
    let data: Vec<u8> = (0..(LEN / 4) as u32).flat_map(u32::to_le_bytes).collect();
    let expected = Sha256::digest(&data);

    let Rig {
        tcp_a,
        mut far_send,
        mut far_recv,
        quic: _quic,
        splice,
    } = rig().await;

    let echo = tokio::spawn(async move {
        let mut buf = vec![0; 64 << 10];
        while let Some(n) = far_recv.read(&mut buf).await.unwrap() {
            far_send.write_all(&buf[..n]).await.unwrap();
        }
        far_send.finish().unwrap();
    });
    let (mut rd, mut wr) = tcp_a.into_split();
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        wr.shutdown().await.unwrap();
    });

    let mut got = Vec::with_capacity(LEN);
    within(rd.read_to_end(&mut got)).await.unwrap();
    within(writer).await.unwrap();
    within(echo).await.unwrap();
    assert_eq!(got.len(), LEN);
    assert_eq!(Sha256::digest(&got), expected);

    let stats = within(splice).await.unwrap();
    assert_eq!(stats.end, SpliceEnd::Clean);
    assert_eq!((stats.to_remote, stats.to_local), (LEN as u64, LEN as u64));
}

/// What the stalled local side takes before it stops, and what far sends: more than that, and
/// less than splice reads ahead.
const ROOM: usize = 4 << 10;
const BLOCKING_LEN: usize = 64 << 10;

/// tcp_a half-closes, so local → remote is finished, then far sends `BLOCKING_LEN` bytes and
/// the splice is left blocked writing to a local side that takes no more.
async fn blocked_on_local_write() -> Rig {
    let (tcp_a, tcp_b) = tcp_pair().await;
    let (stalled_tx, stalled) = oneshot::channel();
    let local_b = StallingLocal {
        tcp: tcp_b,
        room: ROOM,
        stalled: Some(stalled_tx),
    };
    let mut r = rig_from(tcp_a, local_b, None).await;
    r.tcp_a.shutdown().await.unwrap();
    assert_eq!(within(r.far_recv.read_to_end(16)).await.unwrap(), b"");
    within(r.far_send.write_all(&[7; BLOCKING_LEN]))
        .await
        .unwrap();
    within(stalled).await.unwrap();
    assert!(!r.splice.is_finished());
    r
}

#[tokio::test]
async fn remote_reset_reaches_local_blocked_on_write() {
    let mut r = blocked_on_local_write().await;

    r.far_send.reset(VarInt::from_u32(9)).unwrap();

    assert_eq!(within(r.splice).await.unwrap().end, SpliceEnd::RemoteReset);
    let err = read_until_reset(&mut r.tcp_a).await;
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn connection_loss_reaches_local_blocked_on_write() {
    let mut r = blocked_on_local_write().await;

    r.quic.far.close(0u32.into(), b"bye");

    assert_eq!(
        within(r.splice).await.unwrap().end,
        SpliceEnd::ConnectionLost
    );
    let err = read_until_reset(&mut r.tcp_a).await;
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn cancelled_splice_aborts_both_sides() {
    let mut r = rig().await;
    let mut buf = [0; 4];
    r.tcp_a.write_all(b"ping").await.unwrap();
    within(r.far_recv.read_exact(&mut buf)).await.unwrap();

    r.splice.abort();
    assert!(within(r.splice).await.unwrap_err().is_cancelled());

    let err = within(r.far_recv.read(&mut buf)).await.unwrap_err();
    assert_eq!(err, ReadError::Reset(aborted()));
    assert_eq!(within(r.far_send.stopped()).await.unwrap(), Some(aborted()));
    let err = read_until_reset(&mut r.tcp_a).await;
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
}

/// A `SpliceMeter` that adds up what it is told.
#[derive(Default)]
struct Recorder {
    to_remote: AtomicU64,
    to_local: AtomicU64,
}

impl SpliceMeter for Recorder {
    fn to_remote(&self, bytes: u64) {
        self.to_remote.fetch_add(bytes, Ordering::Relaxed);
    }

    fn to_local(&self, bytes: u64) {
        self.to_local.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// A rig whose splice reports to the returned recorder.
async fn metered_rig() -> (Rig, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let opts = SpliceOptions {
        meter: Some(recorder.clone()),
        ..SpliceOptions::default()
    };
    let (tcp_a, tcp_b) = tcp_pair().await;
    (rig_from(tcp_a, tcp_b, Some(opts)).await, recorder)
}

#[tokio::test]
async fn the_meter_sees_every_byte_in_both_directions() {
    // Larger than one read buffer each way, so the meter is told of several chunks.
    const UP: usize = 300 << 10;
    const DOWN: usize = 200 << 10;
    let (r, recorder) = metered_rig().await;
    let Rig {
        tcp_a,
        mut far_send,
        mut far_recv,
        quic: _quic,
        splice,
    } = r;
    let (mut rd, mut wr) = tcp_a.into_split();
    let up = tokio::spawn(async move {
        wr.write_all(&[1; UP]).await.unwrap();
        wr.shutdown().await.unwrap();
    });
    let down = tokio::spawn(async move {
        far_send.write_all(&[2; DOWN]).await.unwrap();
        far_send.finish().unwrap();
    });
    let got_up = within(far_recv.read_to_end(UP + 1)).await.unwrap();
    let mut got_down = Vec::new();
    within(rd.read_to_end(&mut got_down)).await.unwrap();
    within(up).await.unwrap();
    within(down).await.unwrap();
    assert_eq!((got_up.len(), got_down.len()), (UP, DOWN));

    let stats = within(splice).await.unwrap();
    assert_eq!(stats.end, SpliceEnd::Clean);
    assert_eq!((stats.to_remote, stats.to_local), (UP as u64, DOWN as u64));
    assert_eq!(
        (
            recorder.to_remote.load(Ordering::Relaxed),
            recorder.to_local.load(Ordering::Relaxed)
        ),
        (stats.to_remote, stats.to_local)
    );
}

#[tokio::test]
async fn the_meter_has_the_bytes_of_a_dropped_splice() {
    const LEN: usize = 10_000;
    let (mut r, recorder) = metered_rig().await;
    r.tcp_a.write_all(&[3; LEN]).await.unwrap();
    let mut buf = vec![0; LEN];
    within(r.far_recv.read_exact(&mut buf)).await.unwrap();

    r.splice.abort();
    assert!(within(r.splice).await.unwrap_err().is_cancelled());
    assert_eq!(recorder.to_remote.load(Ordering::Relaxed), LEN as u64);
}

#[cfg(unix)]
#[tokio::test]
async fn unix_stream_splices_and_sees_remote_reset_as_eof() {
    let (mut unix_a, unix_b) = tokio::net::UnixStream::pair().unwrap();
    let (mut far_send, mut far_recv, _quic, splice) = spliced(unix_b, None).await;
    let mut buf = [0; 4];

    unix_a.write_all(b"ping").await.unwrap();
    within(far_recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"ping");
    far_send.write_all(b"pong").await.unwrap();
    within(unix_a.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"pong");

    far_send.reset(VarInt::from_u32(9)).unwrap();

    // AF_UNIX has no reset, so the abort reaches the Unix peer as a clean end of stream.
    assert_eq!(within(unix_a.read(&mut buf)).await.unwrap(), 0);
    assert_eq!(within(splice).await.unwrap().end, SpliceEnd::RemoteReset);
}

/// Short enough for tests, long against loopback round trips.
const STALL: Duration = Duration::from_millis(300);

fn short_stall() -> Option<SpliceOptions> {
    Some(SpliceOptions {
        local_write_stall: STALL,
        ..SpliceOptions::default()
    })
}

#[tokio::test]
async fn stalled_local_write_aborts_after_timeout() {
    let (tcp_a, tcp_b) = tcp_pair().await;
    let (stalled_tx, stalled) = oneshot::channel();
    let local_b = StallingLocal {
        tcp: tcp_b,
        room: ROOM,
        stalled: Some(stalled_tx),
    };
    let Rig {
        tcp_a: _tcp_a,
        mut far_send,
        mut far_recv,
        quic: _quic,
        splice,
    } = rig_from(tcp_a, local_b, short_stall()).await;
    let start = Instant::now();

    // Far keeps sending, well past what splice reads ahead, until its writes fail.
    let flood = tokio::spawn(async move {
        let chunk = vec![7; 16 << 10];
        loop {
            if let Err(err) = far_send.write_all(&chunk).await {
                return err;
            }
        }
    });
    within(stalled).await.unwrap();

    let stats = within(splice).await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(stats.end, SpliceEnd::LocalAborted);
    assert!(
        elapsed >= STALL,
        "aborted after {elapsed:?}, before the stall timeout"
    );
    assert!(elapsed < STALL * 10, "aborted only after {elapsed:?}");
    assert_eq!(within(flood).await.unwrap(), WriteError::Stopped(aborted()));
    let mut buf = [0; 8];
    let err = within(far_recv.read(&mut buf)).await.unwrap_err();
    assert_eq!(err, ReadError::Reset(aborted()));
}

#[tokio::test]
async fn slow_but_progressing_local_is_not_cut() {
    // 1 KiB per 100 ms: 16 KiB take about 1.6 s, more than five stall periods.
    const LEN: usize = 16 << 10;
    let (tcp_a, tcp_b) = tcp_pair().await;
    let local_b = TricklingLocal {
        tcp: tcp_b,
        period: Duration::from_millis(100),
        tick: None,
        per_tick: 1 << 10,
        allowance: 0,
    };
    let mut r = rig_from(tcp_a, local_b, short_stall()).await;
    let data: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let start = Instant::now();

    r.tcp_a.shutdown().await.unwrap();
    r.far_send.write_all(&data).await.unwrap();
    r.far_send.finish().unwrap();
    let mut got = Vec::new();
    within(r.tcp_a.read_to_end(&mut got)).await.unwrap();

    assert!(
        start.elapsed() > STALL * 4,
        "too fast to test the stall timer"
    );
    assert_eq!(got, data);
    let stats = within(r.splice).await.unwrap();
    assert_eq!(stats.end, SpliceEnd::Clean);
    assert_eq!(stats.to_local, LEN as u64);
}

#[tokio::test]
async fn idle_connection_is_not_cut_by_stall_timeout() {
    let (tcp_a, tcp_b) = tcp_pair().await;
    let mut r = rig_from(tcp_a, tcp_b, short_stall()).await;
    let mut buf = [0; 4];

    tokio::time::sleep(STALL * 3).await;
    assert!(!r.splice.is_finished());

    r.tcp_a.write_all(b"ping").await.unwrap();
    within(r.far_recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"ping");
    r.far_send.write_all(b"pong").await.unwrap();
    within(r.tcp_a.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"pong");

    r.tcp_a.shutdown().await.unwrap();
    r.far_send.finish().unwrap();
    assert_eq!(within(r.far_recv.read_to_end(16)).await.unwrap(), b"");
    assert_eq!(within(r.tcp_a.read(&mut buf)).await.unwrap(), 0);
    assert_eq!(within(r.splice).await.unwrap().end, SpliceEnd::Clean);
}

/// Short enough for tests, long against loopback round trips.
const IDLE: Duration = Duration::from_millis(300);

fn short_half_closed_idle() -> Option<SpliceOptions> {
    Some(SpliceOptions {
        half_closed_idle: IDLE,
        ..SpliceOptions::default()
    })
}

/// Writes to `tcp_a` until the write fails, as it does once a reset has arrived. Reading cannot
/// show the reset portably once the peer's FIN has been read: Linux keeps reporting EOF. A
/// write fails with `BrokenPipe` (seen on macOS) or `ConnectionReset`, by platform and timing.
async fn write_until_reset(tcp_a: &mut TcpStream) -> io::Error {
    within(async {
        loop {
            match tcp_a.write(b"x").await {
                Ok(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                Err(err) => return err,
            }
        }
    })
    .await
}

#[tokio::test]
async fn half_closed_idle_aborts_after_local_eof() {
    let (tcp_a, tcp_b) = tcp_pair().await;
    let mut r = rig_from(tcp_a, tcp_b, short_half_closed_idle()).await;
    let start = Instant::now();

    r.tcp_a.shutdown().await.unwrap();
    assert_eq!(within(r.far_recv.read_to_end(16)).await.unwrap(), b"");

    let stats = within(r.splice).await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(stats.end, SpliceEnd::HalfClosedIdle);
    assert!(
        elapsed >= IDLE,
        "aborted after {elapsed:?}, before the idle timeout"
    );
    assert!(elapsed < IDLE * 10, "aborted only after {elapsed:?}");
    // Far's own direction is the one that was still open: it is stopped as an abort.
    assert_eq!(within(r.far_send.stopped()).await.unwrap(), Some(aborted()));
    let err = read_until_reset(&mut r.tcp_a).await;
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn half_closed_idle_aborts_after_remote_finish() {
    let (tcp_a, tcp_b) = tcp_pair().await;
    let mut r = rig_from(tcp_a, tcp_b, short_half_closed_idle()).await;
    let mut buf = [0; 8];
    let start = Instant::now();

    r.far_send.finish().unwrap();
    assert_eq!(within(r.tcp_a.read(&mut buf)).await.unwrap(), 0);

    let stats = within(r.splice).await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(stats.end, SpliceEnd::HalfClosedIdle);
    assert!(
        elapsed >= IDLE,
        "aborted after {elapsed:?}, before the idle timeout"
    );
    assert!(elapsed < IDLE * 10, "aborted only after {elapsed:?}");
    let err = within(r.far_recv.read(&mut buf)).await.unwrap_err();
    assert_eq!(err, ReadError::Reset(aborted()));
    let err = write_until_reset(&mut r.tcp_a).await;
    assert!(
        matches!(
            err.kind(),
            ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
        ),
        "{err}"
    );
}

#[tokio::test]
async fn half_closed_with_traffic_is_not_cut() {
    const TICKS: u32 = 13;
    let (tcp_a, tcp_b) = tcp_pair().await;
    let mut r = rig_from(tcp_a, tcp_b, short_half_closed_idle()).await;
    r.tcp_a.shutdown().await.unwrap();
    assert_eq!(within(r.far_recv.read_to_end(16)).await.unwrap(), b"");
    let start = Instant::now();

    // One byte per 100 ms, for more than four idle periods in all.
    let mut far_send = r.far_send;
    let trickle = tokio::spawn(async move {
        for i in 0..TICKS {
            tokio::time::sleep(Duration::from_millis(100)).await;
            far_send.write_all(&[i as u8]).await.unwrap();
        }
        far_send.finish().unwrap();
    });
    let mut got = Vec::new();
    within(r.tcp_a.read_to_end(&mut got)).await.unwrap();
    within(trickle).await.unwrap();

    assert!(
        start.elapsed() > IDLE * 4,
        "too fast to test the idle timer"
    );
    assert_eq!(got, (0..TICKS as u8).collect::<Vec<_>>());
    let stats = within(r.splice).await.unwrap();
    assert_eq!(stats.end, SpliceEnd::Clean);
    assert_eq!(stats.to_local, u64::from(TICKS));
}

#[tokio::test]
async fn fully_open_idle_is_not_cut_by_half_closed_timer() {
    let (tcp_a, tcp_b) = tcp_pair().await;
    let mut r = rig_from(tcp_a, tcp_b, short_half_closed_idle()).await;
    let mut buf = [0; 4];

    tokio::time::sleep(IDLE * 3).await;
    assert!(!r.splice.is_finished());

    r.tcp_a.write_all(b"ping").await.unwrap();
    within(r.far_recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"ping");
    r.far_send.write_all(b"pong").await.unwrap();
    within(r.tcp_a.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"pong");

    r.tcp_a.shutdown().await.unwrap();
    r.far_send.finish().unwrap();
    assert_eq!(within(r.far_recv.read_to_end(16)).await.unwrap(), b"");
    assert_eq!(within(r.tcp_a.read(&mut buf)).await.unwrap(), 0);
    assert_eq!(within(r.splice).await.unwrap().end, SpliceEnd::Clean);
}
