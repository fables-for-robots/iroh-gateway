//! The operator's HTTP endpoint: `/healthz`, `/readyz` and `/metrics`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iroh_gateway_operator::http::{HttpState, serve};
use iroh_gateway_operator::metrics::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(10);

/// Serves `state` on a loopback port of its own.
async fn server(state: HttpState) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, state));
    addr
}

fn state() -> HttpState {
    HttpState {
        metrics: Metrics::new(),
        ready: Arc::new(AtomicBool::new(false)),
    }
}

/// The status code, the headers in lower case, and the body of `GET <path>` over HTTP/1.0.
async fn get(addr: SocketAddr, path: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(STEP, stream.read_to_end(&mut response))
        .await
        .expect("no response in time")
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no end of headers in {response:?}"));
    let code = head
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status in {head:?}"));
    (code, head.to_lowercase(), body.to_owned())
}

#[tokio::test]
async fn healthz_is_ok() {
    let addr = server(state()).await;
    let (code, _, body) = get(addr, "/healthz").await;
    assert_eq!((code, body.as_str()), (200, "ok"));
}

#[tokio::test]
async fn readyz_follows_the_flag() {
    let state = state();
    let ready = state.ready.clone();
    let addr = server(state).await;
    let (code, _, body) = get(addr, "/readyz").await;
    assert_eq!((code, body.as_str()), (503, "not ready"));
    ready.store(true, Ordering::SeqCst);
    let (code, _, body) = get(addr, "/readyz").await;
    assert_eq!((code, body.as_str()), (200, "ready"));
}

#[tokio::test]
async fn metrics_are_the_registry_as_text() {
    let addr = server(state()).await;
    let (code, head, body) = get(addr, "/metrics").await;
    assert_eq!(code, 200);
    assert!(head.contains("\r\ncontent-type: text/plain"), "{head}");
    assert!(
        body.contains("iroh_gateway_operator_build_info{version=\""),
        "{body}"
    );
}

#[tokio::test]
async fn another_path_is_not_found() {
    let addr = server(state()).await;
    for path in ["/", "/other", "/metrics/x"] {
        let (code, _, _) = get(addr, path).await;
        assert_eq!(code, 404, "{path}");
    }
}
