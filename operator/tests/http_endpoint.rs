//! The operator's HTTP endpoint: `/healthz`, `/readyz` and `/metrics`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iroh_gateway_operator::http::{HttpState, serve};
use iroh_gateway_operator::metrics::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
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
        haproxy_exporter: None,
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

/// A state whose exporter is at `socket`.
fn state_with_exporter(socket: &std::path::Path) -> HttpState {
    HttpState {
        haproxy_exporter: Some(socket.to_path_buf()),
        ..state()
    }
}

fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("igw")
        .tempdir_in("/tmp")
        .unwrap()
}

#[tokio::test]
async fn metrics_append_haproxys() {
    let dir = short_dir();
    let model = iroh_gateway_operator::model::Model {
        classes: Vec::new(),
        gateways: Vec::new(),
        edges: Vec::new(),
        routes: Vec::new(),
    };
    let rendered = iroh_gateway_operator::haproxy::render::render(&model, dir.path());
    let sup = iroh_gateway_operator::haproxy::Supervisor::start(
        iroh_gateway_operator::haproxy::SupervisorOptions::new(dir.path()),
        &rendered.haproxy_cfg,
    )
    .await
    .unwrap();
    let addr = server(state_with_exporter(
        &dir.path()
            .join(iroh_gateway_operator::haproxy::METRICS_SOCKET),
    ))
    .await;
    let (code, _, body) = get(addr, "/metrics").await;
    assert_eq!(code, 200);
    assert!(body.contains("iroh_gateway_operator_build_info"), "{body}");
    assert!(
        body.contains("haproxy_process_start_time_seconds"),
        "{body}"
    );
    assert!(
        body.lines()
            .any(|l| l == "iroh_gateway_operator_haproxy_exporter_up 1"),
        "{body}"
    );
    for line in body.lines() {
        assert!(!line.starts_with("HTTP/"), "{line}");
        let lower = line.to_lowercase();
        assert!(
            !lower.starts_with("content-type:") && !lower.starts_with("connection:"),
            "{line}"
        );
    }
    sup.shutdown().await;
}

#[tokio::test]
async fn a_missing_exporter_socket_leaves_the_operators_metrics() {
    let dir = short_dir();
    let addr = server(state_with_exporter(&dir.path().join("none.sock"))).await;
    let started = std::time::Instant::now();
    let (code, _, body) = get(addr, "/metrics").await;
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(code, 200);
    assert!(body.contains("iroh_gateway_operator_build_info"), "{body}");
    assert!(
        body.lines()
            .any(|l| l == "iroh_gateway_operator_haproxy_exporter_up 0"),
        "{body}"
    );
    assert!(!body.contains("haproxy_process_"), "{body}");
}

#[tokio::test]
async fn an_exporter_that_never_answers_is_given_up_on() {
    let dir = short_dir();
    let path = dir.path().join("silent.sock");
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
        }
    });
    let addr = server(state_with_exporter(&path)).await;
    let started = std::time::Instant::now();
    let (code, _, body) = get(addr, "/metrics").await;
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(code, 200);
    assert!(
        body.lines()
            .any(|l| l == "iroh_gateway_operator_haproxy_exporter_up 0"),
        "{body}"
    );
}

#[tokio::test]
async fn an_exporter_answering_an_error_is_left_out() {
    let dir = short_dir();
    let path = dir.path().join("broken.sock");
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(b"HTTP/1.0 503 Service Unavailable\r\n\r\nhaproxy_broken 1\n")
                .await;
        }
    });
    let addr = server(state_with_exporter(&path)).await;
    let (code, _, body) = get(addr, "/metrics").await;
    assert_eq!(code, 200);
    assert!(
        body.lines()
            .any(|l| l == "iroh_gateway_operator_haproxy_exporter_up 0"),
        "{body}"
    );
    assert!(!body.contains("haproxy_broken"), "{body}");
}

#[tokio::test]
async fn without_an_exporter_the_gauge_is_absent() {
    let addr = server(state()).await;
    let (code, _, body) = get(addr, "/metrics").await;
    assert_eq!(code, 200);
    assert!(!body.contains("haproxy_exporter_up"), "{body}");
}

#[tokio::test]
async fn a_chunked_answer_cut_short_is_left_out() {
    let dir = short_dir();
    let path = dir.path().join("cut.sock");
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nhaproxy_cut_off 1\n\r\n",
                )
                .await;
        }
    });
    let addr = server(state_with_exporter(&path)).await;
    let (code, _, body) = get(addr, "/metrics").await;
    assert_eq!(code, 200);
    assert!(
        body.lines()
            .any(|l| l == "iroh_gateway_operator_haproxy_exporter_up 0"),
        "{body}"
    );
    assert!(!body.contains("haproxy_cut_off"), "{body}");
}
