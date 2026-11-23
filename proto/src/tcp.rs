//! Socket options for the TCP connections at either end of a tunnelled stream.

use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tracing::debug;

/// Idle time before the first keepalive probe.
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
/// Time between keepalive probes, where the platform lets it be set.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// Unanswered probes before the connection is dropped, where the platform lets it be set.
pub const KEEPALIVE_PROBES: u32 = 4;

/// Enables TCP keepalive (so a peer that vanished from an idle connection is noticed) and
/// `TCP_NODELAY`. A failure is logged at debug and the connection is used as it is.
pub fn set_keepalive_and_nodelay(stream: &TcpStream) {
    let sock = SockRef::from(stream);
    let keepalive = TcpKeepalive::new().with_time(KEEPALIVE_IDLE);
    #[cfg(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
    ))]
    let keepalive = keepalive
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_PROBES);
    if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
        debug!("setting TCP keepalive failed: {e}");
    }
    if let Err(e) = sock.set_tcp_nodelay(true) {
        debug!("setting TCP_NODELAY failed: {e}");
    }
}
