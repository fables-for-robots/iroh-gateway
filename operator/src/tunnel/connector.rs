//! Opening the local side of a visitor connection.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;

use iroh_gateway_proto::control::{ListenerKey, StreamHeader};
use iroh_gateway_proto::splice::LocalStream;
use iroh_gateway_proto::tcp::set_keepalive_and_nodelay;
use tokio::net::TcpStream;

pub trait Connector: Send + Sync + 'static {
    type Stream: LocalStream;

    /// Opens the local side for one visitor connection on `key`.
    fn connect(
        &self,
        key: ListenerKey,
        header: &StreamHeader,
    ) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// Dials a fixed TCP address per listener, with TCP keepalive and `TCP_NODELAY` on. Unknown key →
/// io::ErrorKind::NotFound.
#[derive(Debug, Clone)]
pub struct StaticConnector {
    targets: HashMap<ListenerKey, SocketAddr>,
}

impl StaticConnector {
    pub fn new(targets: HashMap<ListenerKey, SocketAddr>) -> Self {
        Self { targets }
    }
}

impl Connector for StaticConnector {
    type Stream = TcpStream;

    fn connect(
        &self,
        key: ListenerKey,
        _header: &StreamHeader,
    ) -> impl Future<Output = io::Result<TcpStream>> + Send {
        let target = self.targets.get(&key).copied();
        async move {
            match target {
                Some(addr) => {
                    let stream = TcpStream::connect(addr).await?;
                    set_keepalive_and_nodelay(&stream);
                    Ok(stream)
                }
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no target for {key:?}"),
                )),
            }
        }
    }
}
