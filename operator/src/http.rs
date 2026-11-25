//! The operator's HTTP endpoint: liveness, readiness and the Prometheus metrics.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus::TEXT_FORMAT;
use tokio::net::TcpListener;

use crate::metrics::Metrics;

/// What the endpoint serves from.
#[derive(Clone)]
pub struct HttpState {
    pub metrics: Metrics,
    /// Whether `/readyz` answers that the operator is ready.
    pub ready: Arc<AtomicBool>,
}

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
    ([(CONTENT_TYPE, TEXT_FORMAT)], state.metrics.render())
}
