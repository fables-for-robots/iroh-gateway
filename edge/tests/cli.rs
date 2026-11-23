//! The `iroh-gateway-edge` binary, run as a child process.
#![cfg(unix)]

#[allow(dead_code)]
mod common;

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use iroh::{EndpointId, SecretKey};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use common::{FakeOperator, STEP, free_tcp_port, free_udp_port, tcp_cfg};

const BIN: &str = env!("CARGO_BIN_EXE_iroh-gateway-edge");

fn edge(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .unwrap()
}

fn id_of(key_file: &Path) -> String {
    let out = edge(&["id", "--key-file", key_file.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// Kills the child when dropped, so a failed test leaves no process behind.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Running {
    fn terminate(&mut self) -> std::process::ExitStatus {
        kill(Pid::from_raw(self.0.id() as i32), Signal::SIGTERM).unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "no exit after SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
fn id_prints_a_stable_endpoint_id() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("e.key");
    let first = id_of(&key);
    let second = id_of(&key);
    assert_eq!(first, second);
    assert!(first.ends_with('\n'));
    assert_eq!(first.trim().lines().count(), 1);
    first.trim().parse::<EndpointId>().unwrap();
}

#[test]
fn run_requires_operator() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("e.key");
    let out = edge(&["run", "--key-file", key.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--operator"));
}

#[test]
fn run_rejects_malformed_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("e.key");
    std::fs::write(&key, "abcd").unwrap();
    let operator = SecretKey::generate().public().to_string();
    for args in [vec!["run", "--operator", operator.as_str()], vec!["id"]] {
        let mut full = args.clone();
        full.extend(["--key-file", key.to_str().unwrap()]);
        let out = edge(&full);
        assert!(!out.status.success(), "{args:?}");
    }
    assert_eq!(std::fs::read_to_string(&key).unwrap(), "abcd");
}

#[test]
fn run_rejects_bad_relay() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("e.key");
    let operator = SecretKey::generate().public().to_string();
    let out = edge(&[
        "run",
        "--key-file",
        key.to_str().unwrap(),
        "--operator",
        &operator,
        "--relay",
        "nonsense",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("relay"));
}

#[test]
fn run_rejects_out_of_range_max_connections() {
    let operator = SecretKey::generate().public().to_string();
    for n in ["0", "65537"] {
        let out = edge(&["run", "--operator", &operator, "--max-connections", n]);
        assert!(!out.status.success(), "{n}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("max-connections"));
    }
}

#[tokio::test]
async fn run_serves_the_pinned_operator() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("e.key");
    let edge_id: EndpointId = id_of(&key).trim().parse().unwrap();
    let operator_key = SecretKey::generate();
    let iroh_port = free_udp_port();
    let mut child = Running(
        Command::new(BIN)
            .args(["run", "--key-file", key.to_str().unwrap()])
            .args(["--operator", &operator_key.public().to_string()])
            .args(["--iroh-listen", &format!("127.0.0.1:{iroh_port}")])
            .args(["--public-bind", "127.0.0.1"])
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let addr = format!("127.0.0.1:{iroh_port}").parse().unwrap();
    let start = Instant::now();
    let mut op = loop {
        match FakeOperator::connect(operator_key.clone(), edge_id, addr).await {
            Ok(op) => break op,
            Err(e) => {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "edge never came up: {e}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    let port = free_tcp_port();
    op.push(tcp_cfg(1, &[port])).await;

    let mut visitor = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    visitor.write_all(b"ping").await.unwrap();
    let (_header, _send, mut recv) = op.accept_stream().await;
    let mut buf = [0u8; 4];
    tokio::time::timeout(STEP, recv.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"ping");

    let status = child.terminate();
    assert!(status.success(), "{status:?}");
}
