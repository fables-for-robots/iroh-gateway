//! Connector for HAProxy: one Unix socket per public port, `accept-proxy` on the HAProxy side.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use iroh_gateway_proto::control::{ListenerKey, StreamHeader};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use super::connector::Connector;
use super::proxyv2;

/// Connects to the Unix socket HAProxy listens on for a listener and sends a PROXY v2 header
/// carrying the visitor's address before any payload. Clones share one table.
#[derive(Clone, Default)]
pub struct HaproxyConnector {
    sockets: Arc<RwLock<HashMap<ListenerKey, PathBuf>>>,
}

impl HaproxyConnector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the whole table.
    pub fn set(&self, sockets: HashMap<ListenerKey, PathBuf>) {
        *self.sockets.write().unwrap_or_else(|e| e.into_inner()) = sockets;
    }
}

impl Connector for HaproxyConnector {
    type Stream = UnixStream;

    fn connect(
        &self,
        key: ListenerKey,
        header: &StreamHeader,
    ) -> impl Future<Output = io::Result<UnixStream>> + Send {
        let path = self
            .sockets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .cloned();
        let bytes = proxyv2::header(header.visitor, header.local);
        async move {
            let path = path.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("no socket for {key:?}"))
            })?;
            let mut stream = UnixStream::connect(path).await?;
            stream.write_all(&bytes).await?;
            Ok(stream)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_gateway_proto::control::Protocol;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixListener;

    fn tcp(port: u16) -> ListenerKey {
        ListenerKey {
            protocol: Protocol::Tcp,
            port,
        }
    }

    fn stream_header() -> StreamHeader {
        StreamHeader {
            listener_id: 1,
            visitor: "198.51.100.9:50000".parse().unwrap(),
            local: "203.0.113.7:443".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn connector_writes_header_then_hands_over_the_stream() {
        let dir = tempfile::Builder::new()
            .prefix("igw")
            .tempdir_in("/tmp")
            .unwrap();
        let path = dir.path().join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let connector = HaproxyConnector::new();
        connector.set(HashMap::from([(tcp(443), path)]));

        let h = stream_header();
        let (client, accepted) = tokio::join!(connector.connect(tcp(443), &h), listener.accept());
        let mut client = client.unwrap();
        let (mut server, _) = accepted.unwrap();

        client.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 29];
        server.read_exact(&mut buf).await.unwrap();
        let want = proxyv2::header(h.visitor, h.local);
        assert_eq!(want.len(), 28);
        assert_eq!(&buf[..28], &want[..]);
        assert_eq!(buf[28], b'x');
    }

    #[tokio::test]
    async fn unknown_listener_is_not_found() {
        let err = HaproxyConnector::new()
            .connect(tcp(1), &stream_header())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn set_replaces_the_table() {
        let connector = HaproxyConnector::new();
        connector.set(HashMap::from([(
            tcp(443),
            PathBuf::from("/nonexistent/igw"),
        )]));
        // Known key: fails on connect, not with NotFound-by-table (path is missing so also NotFound
        // kind from the OS); distinguish by the message.
        let err = connector
            .connect(tcp(443), &stream_header())
            .await
            .unwrap_err();
        assert!(!err.to_string().contains("no socket for"));
        connector.set(HashMap::new());
        let err = connector
            .connect(tcp(443), &stream_header())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("no socket for"));
    }
}
