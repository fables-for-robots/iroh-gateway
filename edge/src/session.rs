//! One tunnel session over one authorized operator connection.

use std::sync::Arc;

use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use iroh_gateway_proto::control::{Config, Status, StreamHeader};
use iroh_gateway_proto::frame::{read_frame, write_frame};
use iroh_gateway_proto::splice::{LocalStream, SpliceOptions, splice_with};
use iroh_gateway_proto::{CLOSE_CONTROL_ENDED, RESET_ABORTED};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info};

use crate::listeners::Accepted;
use crate::log_panic;
use crate::metrics::Metrics;

/// A `Config` read on a session's control stream, for the supervisor to apply.
pub(crate) struct ApplyRequest {
    pub session: u64,
    pub cfg: Config,
    pub reply: oneshot::Sender<Status>,
}

/// One session: the control stream task and the visitors forwarded over this connection.
///
/// Dropping it aborts the control task and every visitor task; an aborted splice resets its
/// stream and aborts its local socket. A configured session counts in `session_up` until then.
pub(crate) struct Session {
    pub id: u64,
    /// Whether a `Config` from this session has been applied. Until then the listeners carry
    /// ids from an earlier session, which this one's operator may not have issued.
    configured: bool,
    conn: Connection,
    control: JoinHandle<()>,
    visitors: JoinSet<()>,
    /// Counts the bytes of every visitor stream in `tcp_bytes_total`.
    splice: SpliceOptions,
    metrics: Metrics,
}

impl Session {
    pub fn start(
        id: u64,
        conn: Connection,
        apply: mpsc::Sender<ApplyRequest>,
        metrics: Metrics,
    ) -> Self {
        info!(session = id, operator = %conn.remote_id().fmt_short(), "session started");
        let control = tokio::spawn(control(id, conn.clone(), apply));
        Self {
            id,
            configured: false,
            conn,
            control,
            visitors: JoinSet::new(),
            splice: SpliceOptions {
                meter: Some(Arc::new(metrics.tcp_bytes.clone())),
                ..SpliceOptions::default()
            },
            metrics,
        }
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn configured(&self) -> bool {
        self.configured
    }

    /// Marks that a `Config` from this session has been applied.
    pub fn set_configured(&mut self) {
        self.configured = true;
        self.metrics.session_up.set(1);
    }

    /// Forwards a visitor over this session's connection as one stream.
    pub fn forward(&mut self, accepted: Accepted) {
        self.visitors
            .spawn(forward(self.conn.clone(), accepted, self.splice.clone()));
    }

    /// Resolves once the control stream has ended; finished visitor tasks are reaped meanwhile.
    ///
    /// Once this has resolved the session must be closed, not awaited again.
    pub async fn ended(&mut self) {
        loop {
            tokio::select! {
                ended = &mut self.control => {
                    log_panic(ended, "control task");
                    return;
                }
                Some(done) = self.visitors.join_next() => {
                    log_panic(done, "visitor task");
                }
            }
        }
    }

    /// Closes the connection and drops the session with everything it runs.
    pub fn close(self, code: u32, reason: &[u8]) {
        info!(session = self.id, code, "session closed");
        self.conn.close(VarInt::from_u32(code), reason);
    }

    /// Closes the connection after its control stream ended.
    pub fn close_ended(self) {
        self.close(CLOSE_CONTROL_ENDED, b"control stream ended");
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.control.abort();
        if self.configured {
            self.metrics.session_up.set(0);
        }
    }
}

/// Accepts the control stream, then hands each `Config` to the supervisor and writes back the
/// `Status`. Returns on clean end, any frame error, or a lost connection.
async fn control(id: u64, conn: Connection, apply: mpsc::Sender<ApplyRequest>) {
    let run = async {
        let (mut send, mut recv) = conn.accept_bi().await?;
        while let Some(cfg) = read_frame::<_, Config>(&mut recv).await? {
            let (reply, status) = oneshot::channel();
            apply
                .send(ApplyRequest {
                    session: id,
                    cfg,
                    reply,
                })
                .await?;
            write_frame(&mut send, &status.await?).await?;
        }
        anyhow::Ok(())
    };
    let end = tokio::select! {
        r = run => r,
        e = conn.closed() => Err(e.into()),
    };
    match end {
        Ok(()) => info!(session = id, "control stream finished"),
        Err(e) => info!(session = id, "control stream ended: {e:#}"),
    }
}

/// Opens a stream for the visitor, writes its header and splices until either side ends or the
/// connection is lost. The slot is held until this returns, or until the task is dropped.
async fn forward(conn: Connection, accepted: Accepted, opts: SpliceOptions) {
    let Accepted {
        listener_id,
        stream,
        visitor,
        local,
        slot,
        ..
    } = accepted;
    let header = StreamHeader {
        listener_id,
        visitor,
        local,
    };
    let opened = tokio::select! {
        r = open(&conn, &header) => r,
        e = conn.closed() => Err(e.into()),
    };
    match opened {
        Ok((send, recv)) => {
            tokio::select! {
                stats = splice_with(stream, send, recv, opts) => debug!(
                    %visitor, listener_id, end = ?stats.end,
                    to_remote = stats.to_remote, to_local = stats.to_local,
                    "visitor done"
                ),
                // Dropping the splice resets the stream and aborts the visitor.
                _ = conn.closed() => debug!(%visitor, listener_id, "visitor aborted: tunnel lost"),
            }
        }
        Err(e) => {
            debug!(%visitor, listener_id, "visitor dropped: {e:#}");
            stream.abort();
        }
    }
    drop(slot);
}

async fn open(
    conn: &Connection,
    header: &StreamHeader,
) -> anyhow::Result<(SendStream, RecvStream)> {
    let (mut send, recv) = conn.open_bi().await?;
    if let Err(e) = write_frame(&mut send, header).await {
        // A dropped `SendStream` would finish cleanly.
        let _ = send.reset(VarInt::from_u32(RESET_ABORTED));
        return Err(e.into());
    }
    Ok((send, recv))
}
