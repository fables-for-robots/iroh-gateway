//! What the link logs when the edge closes the connection for a reason the operator must act on.
//!
//! The log is captured by a global subscriber, so these tests have a process of their own: a
//! thread-local one misses events whose callsites another test thread registered first.

#[allow(dead_code)]
mod common;

use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use common::*;
use iroh::SecretKey;
use iroh_gateway_operator::tunnel::{EdgeLink, LinkOptions, StaticConnector, bind_endpoint};
use iroh_gateway_proto::transport::Relay;
use tokio::sync::watch;
use tokio::time::Instant;

/// Everything logged at info and above by any test in this binary.
fn logs() -> &'static Mutex<Vec<u8>> {
    static LOGS: OnceLock<&'static Mutex<Vec<u8>>> = OnceLock::new();
    LOGS.get_or_init(|| {
        let buf: &'static Mutex<Vec<u8>> = Box::leak(Box::new(Mutex::new(Vec::new())));
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || Shared(buf))
            .init();
        buf
    })
}

struct Shared(&'static Mutex<Vec<u8>>);

impl Write for Shared {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The first logged line containing all of `needles` within 5 s; panics with the log otherwise.
async fn line_with(needles: &[&str]) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = String::from_utf8_lossy(&logs().lock().unwrap()).into_owned();
        if let Some(line) = text.lines().find(|l| needles.iter().all(|n| l.contains(n))) {
            return line.to_string();
        }
        assert!(
            Instant::now() < deadline,
            "no line with {needles:?} in:\n{text}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn unauthorized_close_names_the_operator_key() {
    logs();
    let echo = echo_server().await;
    let p = free_tcp_port();
    let rig = rig_full(
        &[(p, echo)],
        &[p],
        &[],
        &[],
        |e| e.operator = SecretKey::generate().public(),
        |_, _| {},
    )
    .await;
    let id = rig.operator_key.public().to_string();
    let line = line_with(&["does not accept this operator's key", &id]).await;
    assert!(line.contains("WARN"), "{line}");
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}

#[tokio::test]
async fn replaced_close_says_another_operator_connected() {
    logs();
    let echo = echo_server().await;
    let p = free_tcp_port();
    let rig = rig(&[(p, echo)]).await;
    wait_state(&rig.link, |s| s.connected).await;

    // A second operator process with the same key takes the edge over.
    let endpoint = bind_endpoint(rig.operator_key.clone(), &Relay::Disabled)
        .await
        .unwrap();
    let opts = LinkOptions::new(
        rig.edge.endpoint_id(),
        Some(rig.edge.iroh_addr().to_string()),
        Relay::Disabled,
    )
    .unwrap();
    let (_desired, rx) = watch::channel(vec![tcp(p)]);
    let connector = StaticConnector::new([(tcp(p), echo)].into_iter().collect());
    let (_udp, udp_rx) = watch::channel(Default::default());
    let second = EdgeLink::spawn(endpoint.clone(), opts, rx, Arc::new(connector), udp_rx);

    let edge = rig.edge.endpoint_id().fmt_short().to_string();
    let line = line_with(&["another operator with the same key", &edge]).await;
    assert!(line.contains("WARN"), "{line}");
    second.shutdown().await;
    endpoint.close().await;
    rig.link.shutdown().await;
    rig.edge.shutdown().await;
}
