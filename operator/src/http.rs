//! The operator's HTTP endpoint: liveness, readiness and the Prometheus metrics.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus::TEXT_FORMAT;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::time::timeout;

use crate::metrics::Metrics;

/// What the endpoint serves from.
#[derive(Clone)]
pub struct HttpState {
    pub metrics: Metrics,
    /// Whether `/readyz` answers that the operator is ready.
    pub ready: Arc<AtomicBool>,
    /// The unix socket of HAProxy's Prometheus exporter, whose answer `/metrics` appends.
    /// `None` leaves the exporter, and the gauge about it, out.
    pub haproxy_exporter: Option<PathBuf>,
}

/// Bound for connecting to the exporter, asking it and reading its whole answer, together.
const EXPORTER_TIMEOUT: Duration = Duration::from_secs(2);
/// The most of the exporter's answer that is read; a longer one is not accepted.
const EXPORTER_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// `/healthz`: 200 `ok`. `/readyz`: 200 `ready`, or 503 `not ready`. `/metrics`: 200,
/// `text/plain; version=0.0.4`. Anything else: 404.
pub async fn serve(listener: TcpListener, state: HttpState) -> std::io::Result<()> {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state);
    axum::serve(listener, app).await
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<HttpState>) -> (StatusCode, &'static str) {
    if state.ready.load(Ordering::Acquire) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

async fn metrics(State(state): State<HttpState>) -> impl IntoResponse {
    let mut text = state.metrics.render();
    if let Some(socket) = &state.haproxy_exporter {
        let body = fetch_exporter(socket).await;
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(
            "# HELP iroh_gateway_operator_haproxy_exporter_up Whether the last scrape of \
             HAProxy's exporter was answered.\n\
             # TYPE iroh_gateway_operator_haproxy_exporter_up gauge\n",
        );
        text.push_str(&format!(
            "iroh_gateway_operator_haproxy_exporter_up {}\n",
            u8::from(body.is_some())
        ));
        if let Some(body) = body {
            text.push_str(&body);
        }
    }
    ([(CONTENT_TYPE, TEXT_FORMAT)], text)
}

/// The body of HAProxy's `GET /metrics` on `socket`, or `None` when it did not answer a `200`
/// with a complete body (a chunked one decoded) within [`EXPORTER_TIMEOUT`] and [`EXPORTER_MAX_BYTES`].
async fn fetch_exporter(socket: &Path) -> Option<String> {
    let exchange = async {
        let mut stream = UnixStream::connect(socket).await.ok()?;
        stream
            .write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
            .await
            .ok()?;
        let mut answer = Vec::new();
        // One byte over the cap tells a body that is too long from one that just fits.
        (&mut stream)
            .take(EXPORTER_MAX_BYTES + 1)
            .read_to_end(&mut answer)
            .await
            .ok()?;
        Some(answer)
    };
    let answer = timeout(EXPORTER_TIMEOUT, exchange).await.ok()??;
    if answer.len() as u64 > EXPORTER_MAX_BYTES {
        return None;
    }
    parse_response(&answer)
}

/// The body of an HTTP response that is a `200`, with a chunked body decoded; `None` for
/// anything else, including a chunked body that is cut short or malformed.
fn parse_response(answer: &[u8]) -> Option<String> {
    let end = answer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&answer[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?;
    if status.split(' ').nth(1) != Some("200") {
        return None;
    }
    let chunked = lines.any(|l| {
        l.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    let body = &answer[end + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    if body.len() as u64 > EXPORTER_MAX_BYTES {
        return None;
    }
    String::from_utf8(body).ok()
}

/// Decodes a chunked body up to its zero-size chunk; trailers after it are ignored.
fn decode_chunked(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = rest.windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&rest[..eol]).ok()?;
        let size = line.split(';').next()?.trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        rest = &rest[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        if rest.len() < 2 || rest.len() - 2 < size || &rest[size..size + 2] != b"\r\n" {
            return None;
        }
        out.extend_from_slice(&rest[..size]);
        if out.len() as u64 > EXPORTER_MAX_BYTES {
            return None;
        }
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_chunks_with_an_extension_decode_to_their_concatenation() {
        let body = b"5;name=value\r\nhello\r\n7\r\n, world\r\n0\r\nTrailer: x\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), b"hello, world");
    }

    #[test]
    fn a_size_that_overflows_is_refused_without_a_panic() {
        for size in ["ffffffffffffffff", "fffffffffffffffe", "7ffffffffffffffe"] {
            let body = format!("{size}\r\nhello\r\n0\r\n\r\n");
            assert!(decode_chunked(body.as_bytes()).is_none(), "{size}");
        }
    }

    #[test]
    fn a_truncated_body_is_refused() {
        assert!(decode_chunked(b"5\r\nhel").is_none());
    }

    #[test]
    fn a_bad_hex_size_is_refused() {
        assert!(decode_chunked(b"zz\r\nhello\r\n0\r\n\r\n").is_none());
    }

    #[test]
    fn a_missing_final_zero_chunk_is_refused() {
        assert!(decode_chunked(b"5\r\nhello\r\n").is_none());
    }

    #[test]
    fn the_header_name_and_value_are_matched_without_case() {
        let r = b"HTTP/1.1 200 OK\r\nTRANSFER-ENCODING: Chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n";
        assert_eq!(parse_response(r).unwrap(), "hi");
    }
}
