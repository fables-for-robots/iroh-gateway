//! Byte copy between a local socket and a QUIC stream, mapping half-close to stream finish and
//! abort to stream reset in both directions.

use std::future::{Future, pending};

use iroh::endpoint::{ReadError, RecvStream, SendStream, StoppedError, VarInt, WriteError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::RESET_ABORTED;

const BUF_LEN: usize = 64 * 1024;

/// A local socket that can be torn down abruptly.
pub trait LocalStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// Close so the peer sees an abort, not a clean end. TCP: SO_LINGER 0 then drop.
    fn abort(self);
}

impl LocalStream for tokio::net::TcpStream {
    fn abort(self) {
        // Should this fail, the drop still closes the socket, only without the reset.
        let _ = self.set_zero_linger();
    }
}

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
/// On any abort the stream is reset and stopped with `RESET_ABORTED` and `local` is aborted, so
/// neither side mistakes the abort for a clean end.
pub async fn splice<L: LocalStream>(
    local: L,
    mut send: SendStream,
    mut recv: RecvStream,
) -> SpliceStats {
    let (mut local_rd, mut local_wr) = tokio::io::split(local);
    let mut to_remote = 0;
    let mut to_local = 0;
    // `try_join!` drops the other direction as soon as one returns an abort.
    let ended = tokio::try_join!(
        local_to_remote(&mut local_rd, &mut send, &mut to_remote),
        remote_to_local(&mut recv, &mut local_wr, &mut to_local),
    );
    let end = match ended {
        Ok(((), ())) => SpliceEnd::Clean,
        Err(end) => {
            // A dropped SendStream finishes cleanly, so the reset must be explicit. Either call
            // fails only when that half is already closed, which is the state we want.
            let code = VarInt::from_u32(RESET_ABORTED);
            let _ = send.reset(code);
            let _ = recv.stop(code);
            local_rd.unsplit(local_wr).abort();
            end
        }
    };
    SpliceStats {
        to_remote,
        to_local,
        end,
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

async fn remote_to_local<W: AsyncWrite + Unpin>(
    recv: &mut RecvStream,
    local: &mut W,
    copied: &mut u64,
) -> Result<(), SpliceEnd> {
    let mut buf = vec![0; BUF_LEN];
    loop {
        let Some(n) = recv.read(&mut buf).await.map_err(read_end)? else {
            return local.shutdown().await.map_err(|_| SpliceEnd::LocalAborted);
        };
        local
            .write_all(&buf[..n])
            .await
            .map_err(|_| SpliceEnd::LocalAborted)?;
        *copied += n as u64;
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
