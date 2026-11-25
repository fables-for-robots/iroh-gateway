//! The `iroh-gateway-edge` binary, run as a child process.
#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use iroh::{EndpointId, SecretKey};
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use common::{FakeOperator, STEP, free_tcp_port, free_udp_port, tcp_cfg};

const BIN: &str = env!("CARGO_BIN_EXE_iroh-gateway-edge");

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

fn edge(args: &[&str]) -> Output {
    bin().args(args).output().unwrap()
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
    spawn_with_lines(cmd)
}

/// Spawns `cmd` with its stderr lines sent to the receiver.
fn spawn_with_lines(mut cmd: Command) -> (Running, mpsc::Receiver<String>) {
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
    lines_through(lines, needle)
        .pop()
        .expect("the line with the needle")
}

/// The stderr lines up to and including the first containing `needle` within 10 s; panics
/// with what came instead.
fn lines_through(lines: &mpsc::Receiver<String>, needle: &str) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match lines.recv_timeout(left) {
            Ok(line) => {
                let found = line.contains(needle);
                seen.push(line);
                if found {
                    return seen;
                }
            }
            Err(_) => break,
        }
    }
    panic!("no line with {needle:?} in {seen:#?}");
}

/// `run` with a fresh key, a random operator and loopback addresses.
fn run_command(dir: &Path, extra: &[&str]) -> Command {
    let mut cmd = bin();
    cmd.args(["run", "--key-file", dir.join("e.key").to_str().unwrap()])
        .args(["--operator", &SecretKey::generate().public().to_string()])
        .args(["--iroh-listen", &format!("127.0.0.1:{}", free_udp_port())])
        .args(["--public-bind", "127.0.0.1"])
        .args(extra);
    cmd
}

#[test]
fn run_raises_the_open_file_limit() {
    let dir = tempfile::tempdir().unwrap();
    let hard = hard_nofile_at_most(4096);
    let (_child, lines) = spawn_with_nofile(run_command(dir.path(), &[]), 256, hard);
    line_with(&lines, &format!("open file limit is {hard}"));
    assert!(!lines.try_iter().any(|l| l.contains("--max-connections")));
}

#[test]
fn run_warns_when_max_connections_exceed_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    let hard = hard_nofile_at_most(1024);
    let cmd = run_command(dir.path(), &["--max-connections", "2048"]);
    let (_child, lines) = spawn_with_nofile(cmd, 256, hard);
    line_with(&lines, &format!("open file limit is {hard}"));
    let warning = line_with(&lines, "--max-connections 2048 needs about 2112 open files");
    assert!(warning.contains("WARN"), "{warning}");
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

/// Runs `cmd` to completion; one still running after 10 s is killed and fails the test.
fn output_within_10s(cmd: &mut Command) -> Output {
    let mut child = Running(
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "still running after 10 s"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    Output {
        status,
        stdout,
        stderr,
    }
}

#[test]
fn run_rejects_bad_relay() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("e.key");
    let operator = SecretKey::generate().public().to_string();
    let out = output_within_10s(
        bin()
            .args(["run", "--key-file", key.to_str().unwrap()])
            .args(["--operator", &operator, "--relay", "nonsense"])
            .args(["--iroh-listen", &format!("127.0.0.1:{}", free_udp_port())])
            .args(["--public-bind", "127.0.0.1"]),
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("nonsense"), "{stderr}");
}

#[test]
fn run_rejects_out_of_range_max_connections() {
    let operator = SecretKey::generate().public().to_string();
    for n in ["0", "4097"] {
        let out = edge(&["run", "--operator", &operator, "--max-connections", n]);
        assert!(!out.status.success(), "{n}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("max-connections"));
    }
}

#[test]
fn run_rejects_out_of_range_udp_flags() {
    let operator = SecretKey::generate().public().to_string();
    for (flag, value) in [
        ("--max-udp-flows", "0"),
        ("--max-udp-flows", "4097"),
        ("--udp-rate-limit", "0"),
    ] {
        let out = edge(&["run", "--operator", &operator, flag, value]);
        assert!(!out.status.success(), "{flag} {value}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(flag), "{flag} {value}: {stderr}");
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
        bin()
            .args(["run", "--key-file", key.to_str().unwrap()])
            .args(["--operator", &operator_key.public().to_string()])
            .args(["--iroh-listen", &format!("127.0.0.1:{iroh_port}")])
            .args(["--public-bind", "127.0.0.1"])
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

/// The whole response to `GET <path>` over HTTP/1.0 from `addr`.
async fn http_get(addr: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(STEP, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn metrics_are_served_when_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let addr = format!("127.0.0.1:{}", free_tcp_port());
    let cmd = run_command(dir.path(), &["--metrics-listen", &addr]);
    let (_child, lines) = spawn_with_lines(cmd);
    line_with(&lines, &format!("metrics on http://{addr}/metrics"));

    let metrics = http_get(&addr, "/metrics").await;
    assert!(
        metrics.starts_with("HTTP/1.0 200") || metrics.starts_with("HTTP/1.1 200"),
        "{metrics}"
    );
    assert!(
        metrics.contains("\niroh_gateway_edge_session_up 0\n"),
        "{metrics}"
    );
    let other = http_get(&addr, "/other").await;
    assert!(
        other.starts_with("HTTP/1.0 404") || other.starts_with("HTTP/1.1 404"),
        "{other}"
    );
}

#[test]
fn no_metrics_listener_without_the_flag() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, lines) = spawn_with_lines(run_command(dir.path(), &[]));
    let mut seen = lines_through(&lines, "serving");
    // Its exit status is not checked: SIGTERM can arrive before the handler is installed.
    child.terminate();
    // The child has exited, so its stderr ends and the reader thread with it.
    seen.extend(lines.iter());
    assert!(!seen.iter().any(|l| l.contains("metrics on")), "{seen:#?}");
}

#[test]
fn metrics_listen_on_a_taken_address_fails_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let held = std::net::TcpListener::bind(("127.0.0.1", free_tcp_port())).unwrap();
    let addr = held.local_addr().unwrap().to_string();
    let out = output_within_10s(&mut run_command(dir.path(), &["--metrics-listen", &addr]));
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(&addr), "{stderr}");
}
