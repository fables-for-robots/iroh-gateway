//! The `iroh-gateway-operator` binary, run as a child process.
#![cfg(unix)]

#[allow(dead_code)]
mod common;

use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use iroh::{EndpointId, SecretKey};
use iroh_gateway_edge::Edge;
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use common::{echo_server, edge_options, free_tcp_port};

const BIN: &str = env!("CARGO_BIN_EXE_iroh-gateway-operator");

/// The binary with a clean environment for it: no `RUST_LOG` and no `IROH_GATEWAY_*` variable
/// of the shell running the tests, which would act as flags.
fn bin() -> Command {
    let mut cmd = Command::new(BIN);
    cmd.env_remove("RUST_LOG");
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("IROH_GATEWAY_") {
            cmd.env_remove(name);
        }
    }
    cmd
}

fn operator(args: &[&str]) -> Output {
    bin().args(args).output().unwrap()
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

/// The parent's hard open-file limit, capped at `cap`: a child may lower it, not raise it.
fn hard_nofile_at_most(cap: u64) -> u64 {
    let (_, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
    hard.min(cap)
}

/// Spawns `cmd` with open-file limits `soft` and `hard` and its stderr lines sent to the
/// receiver.
fn spawn_with_nofile(mut cmd: Command, soft: u64, hard: u64) -> (Running, mpsc::Receiver<String>) {
    // SAFETY: setrlimit is async-signal-safe and the closure touches nothing else.
    unsafe {
        cmd.pre_exec(move || Ok(setrlimit(Resource::RLIMIT_NOFILE, soft, hard)?));
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { return };
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    (Running(child), rx)
}

/// The first stderr line containing `needle` within 10 s; panics with what came instead.
fn line_with(lines: &mpsc::Receiver<String>, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match lines.recv_timeout(left) {
            Ok(line) if line.contains(needle) => return line,
            Ok(line) => seen.push(line),
            Err(_) => break,
        }
    }
    panic!("no line with {needle:?} in {seen:#?}");
}

#[test]
fn static_raises_the_open_file_limit() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            "key_file = {:?}\n[[edge]]\nendpoint_id = \"{}\"\naddress = \"127.0.0.1:1\"\n\
             [[edge.listener]]\nprotocol = \"tcp\"\nport = 8080\ntarget = \"127.0.0.1:3000\"\n",
            dir.path().join("o.key").to_str().unwrap(),
            SecretKey::generate().public()
        ),
    )
    .unwrap();
    let mut cmd = bin();
    cmd.args(["static", "--config", cfg.to_str().unwrap()]);
    let hard = hard_nofile_at_most(4096);
    let (_child, lines) = spawn_with_nofile(cmd, 256, hard);
    line_with(&lines, &format!("open file limit is {hard}"));
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
        bin()
            .args(["static", "--config", cfg.to_str().unwrap()])
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

/// `run` with no in-cluster configuration and a kubeconfig path that does not exist.
fn run_without_cluster(args: &[&str]) -> Output {
    let home = tempfile::tempdir().unwrap();
    let mut cmd = bin();
    cmd.env_remove("POD_NAMESPACE")
        .env_remove("KUBERNETES_SERVICE_HOST")
        .env_remove("KUBERNETES_SERVICE_PORT")
        .env("HOME", home.path())
        .env("KUBECONFIG", home.path().join("missing"))
        .arg("run")
        .args(args);
    cmd.output().unwrap()
}

#[test]
fn run_without_a_cluster_configuration_fails() {
    let out = run_without_cluster(&["--namespace", "iroh-gateway"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no Kubernetes configuration"),
        "stderr: {stderr}"
    );
}

#[test]
fn run_refuses_an_empty_gateway_namespace_list() {
    for list in ["", "a,,b"] {
        let out = run_without_cluster(&["--namespace", "ns", "--gateway-namespaces", list]);
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("--gateway-namespaces"), "stderr: {stderr}");
        assert!(
            !stderr.contains("Kubernetes configuration"),
            "stderr: {stderr}"
        );
    }
}

#[test]
fn run_needs_a_namespace() {
    let out = run_without_cluster(&[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--namespace"), "stderr: {stderr}");
}
