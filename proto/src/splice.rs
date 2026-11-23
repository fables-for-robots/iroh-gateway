//! Byte copy between a local socket and a QUIC stream, mapping half-close to stream finish and
//! abort to stream reset in both directions.

use std::future::{Future, pending};

use iroh::endpoint::{ReadError, RecvStream, SendStream, StoppedError, VarInt, WriteError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::RESET_ABORTED;

const BUF_LEN: usize = 64 * 1024;

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
}

#[derive(Debug, Clone, Copy)]
pub struct SpliceStats {
    pub to_remote: u64,
    pub to_local: u64,
    pub end: SpliceEnd,
}

/// Copies `local` ↔ (`send`, `recv`) until both directions have ended or either aborts.
///
/// On any abort, and when the future is dropped before it completes, the stream is reset and
/// stopped with `RESET_ABORTED` and `local` is aborted, so neither side mistakes the abort for a
/// clean end.
pub async fn splice<L: LocalStream>(local: L, send: SendStream, recv: RecvStream) -> SpliceStats {
    let mut ends = Ends {
        send,
        recv,
        local: Some(tokio::io::split(local)),
        armed: true,
    };
    let mut to_remote = 0;
    let mut to_local = 0;
    let ended = {
        let Ends {
            send, recv, local, ..
        } = &mut ends;
        let (local_rd, local_wr) = local.as_mut().expect("present until drop");
        // `try_join!` drops the other direction as soon as one returns an abort.
        tokio::try_join!(
            local_to_remote(local_rd, send, &mut to_remote),
            remote_to_local(recv, local_wr, &mut to_local),
        )
    };
    let end = match ended {
        Ok(((), ())) => {
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

async fn local_to_remote<R: AsyncRead + Unpin>(
    local: &mut R,
    send: &mut SendStream,
    copied: &mut u64,
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
        send.write_all(&buf[..n]).await.map_err(write_end)?;
        *copied += n as u64;
    }
}

/// While `out` is written to local, the stream is read into `ahead`, so a reset or a lost
/// connection is seen even when local stops taking data. That holds until `ahead` is full.
/// Beyond that the only watcher that does not consume data is `received_reset()`, and
/// cancelling it while data is buffered leaves a reader waker registered, which noq's
/// `RecvStream` drop asserts against once the stream has been read to the end.
async fn remote_to_local<W: AsyncWrite + Unpin>(
    recv: &mut RecvStream,
    local: &mut W,
    copied: &mut u64,
) -> Result<(), SpliceEnd> {
    let mut out = Vec::with_capacity(BUF_LEN);
    let mut ahead = Vec::with_capacity(BUF_LEN);
    let mut finished = false;
    loop {
        if out.is_empty() {
            if finished {
                return local.shutdown().await.map_err(|_| SpliceEnd::LocalAborted);
            }
            finished = !read_more(recv, &mut out).await?;
            continue;
        }
        {
            // The write is never cancelled except by an abort; a pending read is, when the
            // write completes first, which `read_chunk` allows without losing data.
            let mut write = std::pin::pin!(local.write_all(&out));
            loop {
                tokio::select! {
                    written = &mut write => {
                        written.map_err(|_| SpliceEnd::LocalAborted)?;
                        break;
                    }
                    more = read_more(recv, &mut ahead), if !finished && ahead.len() < BUF_LEN => {
                        finished = !more?;
                    }
                }
            }
        }
        *copied += out.len() as u64;
        out.clear();
        std::mem::swap(&mut out, &mut ahead);
    }
}

/// Appends the next chunk to `buf`, up to `BUF_LEN` in all; `false` once the stream is finished.
async fn read_more(recv: &mut RecvStream, buf: &mut Vec<u8>) -> Result<bool, SpliceEnd> {
    match recv
        .read_chunk(BUF_LEN - buf.len())
        .await
        .map_err(read_end)?
    {
        Some(chunk) => {
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
