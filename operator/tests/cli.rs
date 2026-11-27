//! The `iroh-gateway-operator` binary, run as a child process.
#![cfg(unix)]

#[allow(dead_code)]
mod common;

use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
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

use common::{
    STEP, echo_server, edge_options, free_tcp_port, free_udp_port, udp_echo_server, udp_roundtrip,
};

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

#[tokio::test]
async fn static_forwards_udp_to_target() {
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
    let target = udp_echo_server().await;
    let port = free_udp_port();
    let cfg = dir.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            "key_file = {:?}\n[[edge]]\nendpoint_id = \"{}\"\naddress = \"{}\"\n\
             [[edge.listener]]\nprotocol = \"udp\"\nport = {port}\ntarget = \"{target}\"\n",
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

    // Sent again until the operator has connected and the edge has bound the port.
    let to = format!("127.0.0.1:{port}").parse().unwrap();
    assert_eq!(udp_roundtrip(to, b"hello").await, b"hello");

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
fn run_refuses_a_bad_address_grace() {
    for bad in ["soon", "-5s", ""] {
        let grace = format!("--address-grace={bad}");
        let out = run_without_cluster(&["--namespace", "ns", &grace]);
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(&format!("invalid value '{bad}' for '--address-grace")),
            "stderr: {stderr}"
        );
        assert!(
            !stderr.contains("Kubernetes configuration"),
            "stderr: {stderr}"
        );
    }
}

#[test]
fn run_takes_an_address_grace() {
    // Accepted, zero included: the run gets as far as looking for a cluster.
    for grace in ["5s", "0s", "2m"] {
        let out = run_without_cluster(&["--namespace", "ns", "--address-grace", grace]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("no Kubernetes configuration"),
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

/// An API server that takes connections and never answers, so `run` stays in start-up, and a
/// kubeconfig in `home` that points at it. Hold the listener for as long as `run` should hang.
fn silent_cluster(home: &Path) -> (std::net::TcpListener, PathBuf) {
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let kubeconfig = home.join("kubeconfig");
    std::fs::write(
        &kubeconfig,
        format!(
            "apiVersion: v1\n\
             kind: Config\n\
             clusters:\n\
             - name: silent\n  \
               cluster:\n    \
                 server: http://{}\n\
             users:\n\
             - name: nobody\n  \
               user: {{}}\n\
             contexts:\n\
             - name: silent\n  \
               context:\n    \
                 cluster: silent\n    \
                 user: nobody\n\
             current-context: silent\n",
            silent.local_addr().unwrap()
        ),
    )
    .unwrap();
    (silent, kubeconfig)
}

/// `run` against `kubeconfig`, with HAProxy's directory in `runtime` and `args` added.
fn run_against(home: &Path, kubeconfig: &Path, runtime: &Path, args: &[&str]) -> Command {
    let mut cmd = bin();
    cmd.env_remove("KUBERNETES_SERVICE_HOST")
        .env_remove("KUBERNETES_SERVICE_PORT")
        .env("HOME", home)
        .env("KUBECONFIG", kubeconfig)
        .env("RUST_LOG", "info")
        .args(["run", "--namespace", "ns", "--runtime-dir"])
        .arg(runtime)
        .args(args);
    cmd
}

#[test]
fn run_stops_on_sigterm_during_start_up() {
    let home = tempfile::tempdir().unwrap();
    let (silent, kubeconfig) = silent_cluster(home.path());
    let runtime = common::short_dir();
    let cmd = run_against(home.path(), &kubeconfig, runtime.path(), &[]);
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
    let (mut child, lines) = spawn_with_nofile(cmd, soft, hard);
    // Logged just before the client is built.
    line_with(&lines, "open file limit is");
    std::thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    let status = child.terminate();
    assert!(status.success(), "{status:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
    // Nothing was started: no HAProxy directory.
    assert!(!runtime.path().join("haproxy").exists());
    drop(silent);
}

/// The status code and the body of `GET <path>` over HTTP/1.0 from `addr`.
async fn http_get(addr: &str, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(STEP, stream.read_to_end(&mut response))
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
    (code, body.to_owned())
}

/// The output of `cmd`, which must exit within 10 s.
fn output_within_10s(cmd: &mut Command) -> Output {
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = Pid::from_raw(child.id() as i32);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(out) => out.unwrap(),
        Err(_) => {
            let _ = kill(pid, Signal::SIGKILL);
            panic!("still running after 10 s");
        }
    }
}

/// A `static` configuration with one edge at an address nothing answers on, and its key file.
fn unreachable_static_config(dir: &Path) -> PathBuf {
    let cfg = dir.join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            "key_file = {:?}\n[[edge]]\nendpoint_id = \"{}\"\naddress = \"127.0.0.1:1\"\n\
             [[edge.listener]]\nprotocol = \"tcp\"\nport = 8080\ntarget = \"127.0.0.1:3000\"\n",
            dir.join("o.key").to_str().unwrap(),
            SecretKey::generate().public()
        ),
    )
    .unwrap();
    cfg
}

#[tokio::test]
async fn static_serves_metrics_and_is_ready() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = unreachable_static_config(dir.path());
    let addr = format!("127.0.0.1:{}", free_tcp_port());
    let mut cmd = bin();
    cmd.env("RUST_LOG", "info")
        .args(["static", "--config", cfg.to_str().unwrap()])
        .args(["--metrics-listen", &addr]);
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
    let (mut child, lines) = spawn_with_nofile(cmd, soft, hard);
    line_with(&lines, &format!("on http://{addr}"));

    // Ready once every link is spawned, which is just after the listener is bound.
    let deadline = Instant::now() + STEP;
    loop {
        let (code, body) = http_get(&addr, "/readyz").await;
        if code == 200 {
            assert_eq!(body, "ready");
            break;
        }
        assert!(Instant::now() < deadline, "not ready within {STEP:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (code, metrics) = http_get(&addr, "/metrics").await;
    assert_eq!(code, 200);
    assert!(
        metrics.contains("iroh_gateway_operator_tunnel_up{edge=\""),
        "{metrics}"
    );
    assert_eq!(http_get(&addr, "/healthz").await, (200, "ok".to_owned()));
    let status = child.terminate();
    assert!(status.success(), "{status:?}");
}

#[tokio::test]
async fn run_answers_healthz_before_it_has_a_cluster() {
    let home = tempfile::tempdir().unwrap();
    let (silent, kubeconfig) = silent_cluster(home.path());
    let runtime = common::short_dir();
    let addr = format!("127.0.0.1:{}", free_tcp_port());
    let cmd = run_against(
        home.path(),
        &kubeconfig,
        runtime.path(),
        &["--metrics-listen", &addr],
    );
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
    let (mut child, lines) = spawn_with_nofile(cmd, soft, hard);
    line_with(&lines, &format!("on http://{addr}"));

    // The API server never answers, so `run` is still loading its identity.
    assert_eq!(http_get(&addr, "/healthz").await, (200, "ok".to_owned()));
    assert_eq!(
        http_get(&addr, "/readyz").await,
        (503, "not ready".to_owned())
    );
    let (code, metrics) = http_get(&addr, "/metrics").await;
    assert_eq!(code, 200);
    assert!(
        metrics.contains("iroh_gateway_operator_reconciles_total 0"),
        "{metrics}"
    );
    let status = child.terminate();
    assert!(status.success(), "{status:?}");
    assert!(!runtime.path().join("haproxy").exists());
    drop(silent);
}

#[test]
fn logs_on_a_pipe_have_no_colour_codes() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = unreachable_static_config(dir.path());
    let mut cmd = bin();
    // Without it only the destination decides; journald stores a line with ESC as binary.
    cmd.env_remove("NO_COLOR")
        .args(["static", "--config", cfg.to_str().unwrap()]);
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
    let (mut child, lines) = spawn_with_nofile(cmd, soft, hard);
    // Every line through the first with the needle, which `line_with` would drop.
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(left) {
            Ok(line) => {
                let found = line.contains("open file limit is");
                seen.push(line);
                if found {
                    break;
                }
            }
            Err(_) => panic!("no line with the open file limit in {seen:#?}"),
        }
    }
    child.terminate();
    // The child has exited, so its stderr ends and the reader thread with it.
    seen.extend(lines.iter());
    assert!(!seen.iter().any(|l| l.contains('\x1b')), "{seen:#?}");
}

#[test]
fn metrics_listen_on_a_taken_address_fails_at_start() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = held.local_addr().unwrap().to_string();

    let dir = tempfile::tempdir().unwrap();
    let cfg = unreachable_static_config(dir.path());
    let out = output_within_10s(
        bin()
            .args(["static", "--config", cfg.to_str().unwrap()])
            .args(["--metrics-listen", &addr]),
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(&addr), "{stderr}");

    // `run` binds it before it looks for a cluster.
    let out = run_without_cluster(&["--namespace", "ns", "--metrics-listen", &addr]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(&addr), "{stderr}");
    assert!(
        !stderr.contains("Kubernetes configuration"),
        "stderr: {stderr}"
    );
    drop(held);
}
