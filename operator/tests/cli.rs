//! The `iroh-gateway-operator` binary, run as a child process.
#![cfg(unix)]

#[allow(dead_code)]
mod common;

use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use iroh::{EndpointId, SecretKey};
use iroh_gateway_edge::Edge;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use common::{echo_server, edge_options, free_tcp_port};

const BIN: &str = env!("CARGO_BIN_EXE_iroh-gateway-operator");

fn operator(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .unwrap()
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
    let key = dir.path().join("o.key");
    let args = ["id", "--key-file", key.to_str().unwrap()];
    let first = operator(&args);
    let second = operator(&args);
    assert!(first.status.success(), "{first:?}");
    assert_eq!(first.stdout, second.stdout);
    let text = String::from_utf8(first.stdout).unwrap();
    assert!(text.ends_with('\n'));
    assert_eq!(text.trim().lines().count(), 1);
    text.trim().parse::<EndpointId>().unwrap();
}

#[test]
fn id_and_static_reject_malformed_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("o.key");
    std::fs::write(&key, "abcd").unwrap();
    let out = operator(&["id", "--key-file", key.to_str().unwrap()]);
    assert!(!out.status.success());

    let cfg = dir.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            "key_file = {:?}\n[[edge]]\nendpoint_id = \"{}\"\naddress = \"127.0.0.1:1\"\n\
             [[edge.listener]]\nprotocol = \"tcp\"\nport = 8080\ntarget = \"127.0.0.1:3000\"\n",
            key.to_str().unwrap(),
            SecretKey::generate().public()
        ),
    )
    .unwrap();
    let out = operator(&["static", "--config", cfg.to_str().unwrap()]);
    assert!(!out.status.success());
    assert_eq!(std::fs::read_to_string(&key).unwrap(), "abcd");
}

#[test]
fn static_rejects_a_bad_config() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("c.toml");
    std::fs::write(&cfg, "key_file = \"o.key\"\ncolour = \"red\"\n").unwrap();
    let out = operator(&["static", "--config", cfg.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("colour"));
}

#[tokio::test]
async fn static_forwards_to_target() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("o.key");
    let id = operator(&["id", "--key-file", key.to_str().unwrap()]);
    assert!(id.status.success());
    let operator_id: EndpointId = String::from_utf8(id.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    let edge = Edge::spawn(edge_options(
        operator_id,
        SecretKey::generate(),
        "127.0.0.1:0".parse().unwrap(),
    ))
    .await
    .unwrap();
    let target = echo_server().await;
    let port = free_tcp_port();
    let cfg = dir.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            "key_file = {:?}\n[[edge]]\nendpoint_id = \"{}\"\naddress = \"{}\"\n\
             [[edge.listener]]\nprotocol = \"tcp\"\nport = {port}\ntarget = \"{target}\"\n",
            key.to_str().unwrap(),
            edge.endpoint_id(),
            edge.iroh_addr()
        ),
    )
    .unwrap();
    let mut child = Running(
        Command::new(BIN)
            .args(["static", "--config", cfg.to_str().unwrap()])
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let start = Instant::now();
    loop {
        let attempt = async {
            let mut v = TcpStream::connect(("127.0.0.1", port)).await?;
            v.write_all(b"hello").await?;
            let mut buf = [0u8; 5];
            tokio::time::timeout(Duration::from_secs(2), v.read_exact(&mut buf))
                .await
                .map_err(|_| std::io::Error::other("timeout"))??;
            Ok::<_, std::io::Error>(buf)
        };
        match attempt.await {
            Ok(buf) => {
                assert_eq!(&buf, b"hello");
                break;
            }
            Err(e) => {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "no echo through the edge: {e}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    let status = child.terminate();
    assert!(status.success(), "{status:?}");
    edge.shutdown().await;
}
