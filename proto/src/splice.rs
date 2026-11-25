//! Byte copy between a local socket and a QUIC stream, mapping half-close to stream finish and
//! abort to stream reset in both directions.

use std::{
    future::{Future, pending},
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use iroh::endpoint::{ReadError, RecvStream, SendStream, StoppedError, VarInt, WriteError};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    time::{Instant, sleep_until},
};

use crate::RESET_ABORTED;

const BUF_LEN: usize = 64 * 1024;

/// How long the local side may accept no bytes while data is waiting for it before the splice
/// gives up on it.
pub const LOCAL_WRITE_STALL: Duration = Duration::from_secs(300);

/// How long the direction still open may move nothing once the other has ended.
pub const HALF_CLOSED_IDLE: Duration = Duration::from_secs(300);

/// A local socket that can be torn down abruptly.
pub trait LocalStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// Close so the peer sees an abort, not a clean end. TCP: SO_LINGER 0 then drop.
    ///
    /// Unix sockets have no reset, so for a `UnixStream` the peer sees a clean end of stream.
    fn abort(self);
}

impl LocalStream for tokio::net::TcpStream {
    fn abort(self) {
        // Should this fail, the drop still closes the socket, only without the reset.
        let _ = self.set_zero_linger();
    }
}

/// Only drops: AF_UNIX has no reset, so the peer sees a clean end of stream, not an abort.
#[cfg(unix)]
impl LocalStream for tokio::net::UnixStream {
    fn abort(self) {
        drop(self);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceEnd {
    /// Both directions ended with a half-close.
    Clean,
    /// A local read or write failed.
    LocalAborted,
    /// The peer reset or stopped the stream.
    RemoteReset,
    /// The QUIC connection went away.
    ConnectionLost,
    /// One direction had ended and the other moved no byte for `half_closed_idle`.
    HalfClosedIdle,
}

/// Told of every chunk a splice writes, as it is written.
pub trait SpliceMeter: Send + Sync + 'static {
    /// Bytes written to the tunnel stream.
    fn to_remote(&self, bytes: u64);
    /// Bytes written to the local stream.
    fn to_local(&self, bytes: u64);
}

#[derive(Clone)]
pub struct SpliceOptions {
    /// Abort, as `LocalAborted`, once the local side has accepted no bytes for this long while
    /// data is waiting for it. Never applies while nothing is waiting.
    pub local_write_stall: Duration,
    /// Abort, as `HalfClosedIdle`, once one direction has ended cleanly and the other has moved
    /// no byte for this long. Never applies while both directions are open.
    pub half_closed_idle: Duration,
    /// Told of the bytes as they are written, so that what a splice moved is known while it
    /// runs and after it is dropped.
    pub meter: Option<Arc<dyn SpliceMeter>>,
}

impl std::fmt::Debug for SpliceOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpliceOptions")
            .field("local_write_stall", &self.local_write_stall)
            .field("half_closed_idle", &self.half_closed_idle)
            .field("meter", &self.meter.as_ref().map(|_| "SpliceMeter"))
            .finish()
    }
}

impl Default for SpliceOptions {
    fn default() -> Self {
        Self {
            local_write_stall: LOCAL_WRITE_STALL,
            half_closed_idle: HALF_CLOSED_IDLE,
            meter: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SpliceStats {
    pub to_remote: u64,
    pub to_local: u64,
    pub end: SpliceEnd,
}

/// [`splice_with`] with the default [`SpliceOptions`].
pub async fn splice<L: LocalStream>(local: L, send: SendStream, recv: RecvStream) -> SpliceStats {
    splice_with(local, send, recv, SpliceOptions::default()).await
}

/// Copies `local` ↔ (`send`, `recv`) until both directions have ended or either aborts.
///
/// On any abort, and when the future is dropped before it completes, the stream is reset and
/// stopped with `RESET_ABORTED` and `local` is aborted, so neither side mistakes the abort for a
/// clean end.
///
/// A lost connection is not always visible from the stream alone (for example while the local
/// side is not reading), so callers are expected to race this future against the connection's
/// `closed()` and drop it when that wins; dropping it aborts both sides as above.
pub async fn splice_with<L: LocalStream>(
    local: L,
    send: SendStream,
    recv: RecvStream,
    opts: SpliceOptions,
) -> SpliceStats {
    let mut ends = Ends {
        send,
        recv,
        local: Some(tokio::io::split(local)),
        armed: true,
    };
    let mut to_remote = 0;
    let mut to_local = 0;
    let moved = Moved::new();
    let meter = opts.meter.as_deref();
    let ended = {
        let Ends {
            send, recv, local, ..
        } = &mut ends;
        let (local_rd, local_wr) = local.as_mut().expect("present until drop");
        both_directions(
            local_to_remote(local_rd, send, &mut to_remote, &moved, meter),
            remote_to_local(
                recv,
                local_wr,
                opts.local_write_stall,
                &mut to_local,
                &moved,
                meter,
            ),
            opts.half_closed_idle,
            &moved,
        )
        .await
    };
    let end = match ended {
        Ok(()) => {
            ends.armed = false;
            SpliceEnd::Clean
        }
        Err(end) => end,
    };
    drop(ends);
    SpliceStats {
        to_remote,
        to_local,
        end,
    }
}

/// Everything `splice` owns. Dropped while armed, which is every way out but `Clean`, it aborts
/// all of it: a dropped `SendStream` would finish cleanly, and a dropped socket close cleanly.
struct Ends<L: LocalStream> {
    send: SendStream,
    recv: RecvStream,
    local: Option<(ReadHalf<L>, WriteHalf<L>)>,
    armed: bool,
}

impl<L: LocalStream> Drop for Ends<L> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Either call fails only when that half is already closed, which is the state we want.
        let code = VarInt::from_u32(RESET_ABORTED);
        let _ = self.send.reset(code);
        let _ = self.recv.stop(code);
        if let Some((local_rd, local_wr)) = self.local.take() {
            local_rd.unsplit(local_wr).abort();
        }
    }
}

/// When a byte last moved in either direction.
struct Moved {
    base: Instant,
    /// Nanoseconds after `base`.
    at: AtomicU64,
}

impl Moved {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            at: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let nanos = u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.at.store(nanos, Ordering::Relaxed);
    }

    fn last(&self) -> Instant {
        self.base + Duration::from_nanos(self.at.load(Ordering::Relaxed))
    }
}

/// Runs both directions until both have ended cleanly or either aborts; an abort drops the
/// other. Once one has ended cleanly, the other alone is given `idle` without a byte moving
/// before it is cut as `HalfClosedIdle`.
async fn both_directions(
    to_remote: impl Future<Output = Result<(), SpliceEnd>>,
    to_local: impl Future<Output = Result<(), SpliceEnd>>,
    idle: Duration,
    moved: &Moved,
) -> Result<(), SpliceEnd> {
    let mut to_remote = pin!(to_remote);
    let mut to_local = pin!(to_local);
    tokio::select! {
        ended = &mut to_remote => {
            ended?;
            alone(to_local, idle, moved).await
        }
        ended = &mut to_local => {
            ended?;
            alone(to_remote, idle, moved).await
        }
    }
}

/// The direction left open after the other ended, cut once no byte has moved for `idle`.
async fn alone(
    mut rest: Pin<&mut impl Future<Output = Result<(), SpliceEnd>>>,
    idle: Duration,
    moved: &Moved,
) -> Result<(), SpliceEnd> {
    let since = Instant::now();
    loop {
        let deadline = deadline_from(moved.last().max(since), idle);
        tokio::select! {
            ended = &mut rest => return ended,
            () = sleep_until(deadline) => {
                if deadline_from(moved.last().max(since), idle) <= Instant::now() {
                    return Err(SpliceEnd::HalfClosedIdle);
                }
            }
        }
    }
}

async fn local_to_remote<R: AsyncRead + Unpin>(
    local: &mut R,
    send: &mut SendStream,
    copied: &mut u64,
    moved: &Moved,
    meter: Option<&dyn SpliceMeter>,
) -> Result<(), SpliceEnd> {
    let mut buf = vec![0; BUF_LEN];
    // A write sees a stop as an error; this catches one while the local side is idle.
    let mut stopped = std::pin::pin!(stop_or_loss(send.stopped()));
    loop {
        let n = tokio::select! {
            read = local.read(&mut buf) => read.map_err(|_| SpliceEnd::LocalAborted)?,
            end = &mut stopped => return Err(end),
        };
        if n == 0 {
            // Fails only if the stream is already finished or reset.
            let _ = send.finish();
            return Ok(());
        }
        moved.touch();
        send.write_all(&buf[..n]).await.map_err(write_end)?;
        moved.touch();
        *copied += n as u64;
        if let Some(meter) = meter {
            meter.to_remote(n as u64);
        }
    }
}

/// While `out` is written to local, the stream is read into `ahead`, so a reset or a lost
/// connection is seen even when local stops taking data. That holds until `ahead` is full.
/// Beyond that the only watcher that does not consume data is `received_reset()`, and
/// cancelling it while data is buffered leaves a reader waker registered, which noq's
/// `RecvStream` drop asserts against once the stream has been read to the end. What covers
/// that state is `stall`: local accepting nothing for that long while `out` waits is an abort.
async fn remote_to_local<W: AsyncWrite + Unpin>(
    recv: &mut RecvStream,
    local: &mut W,
    stall: Duration,
    copied: &mut u64,
    moved: &Moved,
    meter: Option<&dyn SpliceMeter>,
) -> Result<(), SpliceEnd> {
    let mut out = Vec::with_capacity(BUF_LEN);
    let mut ahead = Vec::with_capacity(BUF_LEN);
    let mut finished = false;
    loop {
        if out.is_empty() {
            if finished {
                return local.shutdown().await.map_err(|_| SpliceEnd::LocalAborted);
            }
            finished = !read_more(recv, &mut out, moved).await?;
            continue;
        }
        // Both `write` and `read_chunk` are cancel-safe: whichever loses a round has done
        // nothing, so the other branches can complete first without losing data.
        let mut written = 0;
        let mut deadline = deadline_after(stall);
        while written < out.len() {
            tokio::select! {
                n = local.write(&out[written..]) => match n {
                    Ok(n) if n > 0 => {
                        written += n;
                        moved.touch();
                        deadline = deadline_after(stall);
                        *copied += n as u64;
                        if let Some(meter) = meter {
                            meter.to_local(n as u64);
                        }
                    }
                    _ => return Err(SpliceEnd::LocalAborted),
                },
                more = read_more(recv, &mut ahead, moved), if !finished && ahead.len() < BUF_LEN => {
                    finished = !more?;
                }
                () = sleep_until(deadline) => return Err(SpliceEnd::LocalAborted),
            }
        }
        out.clear();
        std::mem::swap(&mut out, &mut ahead);
    }
}

/// `now + after`, saturating far in the future for durations too large to add.
fn deadline_after(after: Duration) -> Instant {
    deadline_from(Instant::now(), after)
}

/// `from + after`, saturating far in the future for durations too large to add.
fn deadline_from(from: Instant, after: Duration) -> Instant {
    from.checked_add(after)
        .unwrap_or_else(|| from + Duration::from_secs(100 * 365 * 24 * 3600))
}

/// Appends the next chunk to `buf`, up to `BUF_LEN` in all; `false` once the stream is finished.
async fn read_more(
    recv: &mut RecvStream,
    buf: &mut Vec<u8>,
    moved: &Moved,
) -> Result<bool, SpliceEnd> {
    match recv
        .read_chunk(BUF_LEN - buf.len())
        .await
        .map_err(read_end)?
    {
        Some(chunk) => {
            moved.touch();
            buf.extend_from_slice(&chunk);
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Resolves only when the peer stops the stream or the connection is lost.
async fn stop_or_loss(
    stopped: impl Future<Output = Result<Option<VarInt>, StoppedError>>,
) -> SpliceEnd {
    match stopped.await {
        Ok(Some(_)) | Err(StoppedError::ZeroRttRejected) => SpliceEnd::RemoteReset,
        Err(StoppedError::ConnectionLost(_)) => SpliceEnd::ConnectionLost,
        // Finished and acknowledged, or reset by us: nothing left to watch for.
        Ok(None) => pending().await,
    }
}

fn read_end(err: ReadError) -> SpliceEnd {
    match err {
        ReadError::ConnectionLost(_) => SpliceEnd::ConnectionLost,
        ReadError::Reset(_) | ReadError::ClosedStream | ReadError::ZeroRttRejected => {
            SpliceEnd::RemoteReset
        }
    }
}

fn write_end(err: WriteError) -> SpliceEnd {
    match err {
        WriteError::ConnectionLost(_) => SpliceEnd::ConnectionLost,
        WriteError::Stopped(_) | WriteError::ClosedStream | WriteError::ZeroRttRejected => {
            SpliceEnd::RemoteReset
        }
    }
}
