//! The HAProxy supervisor against a real `haproxy` binary on PATH.
#![cfg(unix)]

#[allow(dead_code)]
mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::short_dir;
use iroh_gateway_operator::haproxy::{
    Applied, ApplyError, MAX_RUNTIME_DIR_LEN, Supervisor, SupervisorOptions,
};
use iroh_gateway_operator::tunnel::proxyv2;
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::time::{Instant, sleep, timeout};

/// Upper bound for any single step that should complete promptly on loopback.
const STEP: Duration = Duration::from_secs(10);
const VISITOR: &str = "198.51.100.9:50000";
const LOCAL: &str = "203.0.113.7:443";

fn opts(dir: &TempDir) -> SupervisorOptions {
    SupervisorOptions {
        haproxy_bin: "haproxy".into(),
        runtime_dir: dir.path().to_path_buf(),
        reload_timeout: Duration::from_secs(30),
        inherit_output: false,
    }
}

/// A TCP-mode configuration with one frontend on `<dir>/s/<name>` per pair, each sending its
/// connections to one server at the paired address.
fn cfg(dir: &TempDir, frontends: &[(&str, SocketAddr)]) -> String {
    cfg_with(dir, frontends, "")
}

/// [`cfg`], with `server_opts` appended to every server line.
fn cfg_with(dir: &TempDir, frontends: &[(&str, SocketAddr)], server_opts: &str) -> String {
    let d = dir.path().display();
    let mut out = format!(
        "global\n\
         \x20   stats socket {d}/stats.sock mode 600 level admin expose-fd listeners\n\
         \x20   hard-stop-after 5s\n\
         \n\
         defaults\n\
         \x20   mode tcp\n\
         \x20   timeout connect 5s\n\
         \x20   timeout client 30s\n\
         \x20   timeout server 30s\n"
    );
    for (i, (name, addr)) in frontends.iter().enumerate() {
        out.push_str(&format!(
            "\nfrontend f{i}\n\
             \x20   bind unix@{d}/s/{name} accept-proxy mode 600\n\
             \x20   default_backend b{i}\n\
             \n\
             backend b{i}\n\
             \x20   server s1 {addr} {server_opts}\n"
        ));
    }
    out
}

/// Echoes each connection until EOF, after first writing `tag` (which may be empty).
async fn echo_backend(tag: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                if stream.write_all(tag).await.is_err() {
                    return;
                }
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
                let _ = wr.shutdown().await;
            });
        }
    });
    addr
}

/// Connects to `<dir>/s/<name>` and sends the PROXY v2 header for [`VISITOR`] and [`LOCAL`].
async fn visit(dir: &TempDir, name: &str) -> UnixStream {
    let mut s = timeout(STEP, UnixStream::connect(dir.path().join("s").join(name)))
        .await
        .unwrap()
        .unwrap();
    let header = proxyv2::header(VISITOR.parse().unwrap(), LOCAL.parse().unwrap());
    s.write_all(&header).await.unwrap();
    s
}

async fn read_exact(s: &mut UnixStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0; n];
    timeout(STEP, s.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    buf
}

async fn echoes(s: &mut UnixStream, msg: &[u8]) {
    s.write_all(msg).await.unwrap();
    assert_eq!(read_exact(s, msg.len()).await, msg);
}

/// Pids of the workers the master lists in `show proc`.
async fn worker_pids(dir: &TempDir) -> Vec<i32> {
    let mut s = UnixStream::connect(dir.path().join("master.sock"))
        .await
        .unwrap();
    s.write_all(b"show proc\n").await.unwrap();
    s.shutdown().await.unwrap();
    let mut reply = String::new();
    timeout(STEP, s.read_to_string(&mut reply))
        .await
        .unwrap()
        .unwrap();
    let pids: Vec<i32> = reply
        .lines()
        .filter(|l| l.split_whitespace().nth(1) == Some("worker"))
        .map(|l| l.split_whitespace().next().unwrap().parse().unwrap())
        .collect();
    assert!(!pids.is_empty(), "no worker in {reply:?}");
    pids
}

/// Waits until no process with any of `pids` exists.
async fn gone(pids: &[i32]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    for &pid in pids {
        while kill(Pid::from_raw(pid), None) != Err(Errno::ESRCH) {
            assert!(Instant::now() < deadline, "process {pid} still exists");
            sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Reads the PROXY v2 header at the start of `stream` and returns its source and destination.
async fn read_proxy_v2(stream: &mut TcpStream) -> (SocketAddr, SocketAddr) {
    let mut fixed = [0u8; 16];
    stream.read_exact(&mut fixed).await.unwrap();
    assert_eq!(&fixed[..12], b"\r\n\r\n\0\r\nQUIT\n");
    assert_eq!(fixed[12], 0x21, "version 2, command PROXY");
    let len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
    let mut block = vec![0u8; len];
    stream.read_exact(&mut block).await.unwrap();
    let port = |at: usize| u16::from_be_bytes([block[at], block[at + 1]]);
    match fixed[13] {
        0x11 => {
            assert!(len >= 12);
            let ip = |at: usize| {
                IpAddr::V4(Ipv4Addr::new(
                    block[at],
                    block[at + 1],
                    block[at + 2],
                    block[at + 3],
                ))
            };
            (
                SocketAddr::new(ip(0), port(8)),
                SocketAddr::new(ip(4), port(10)),
            )
        }
        0x21 => {
            assert!(len >= 36);
            let ip = |at: usize| {
                let octets: [u8; 16] = block[at..at + 16].try_into().unwrap();
                IpAddr::V6(Ipv6Addr::from(octets)).to_canonical()
            };
            (
                SocketAddr::new(ip(0), port(32)),
                SocketAddr::new(ip(16), port(34)),
            )
        }
        other => panic!("unexpected family byte {other:#x}"),
    }
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

#[tokio::test]
async fn serves_through_a_unix_socket_with_proxy_header() {
    let echo = echo_backend(b"").await;
    let dir = short_dir();
    let sup = Supervisor::start(opts(&dir), &cfg(&dir, &[("a.sock", echo)]))
        .await
        .unwrap();
    let mut s = visit(&dir, "a.sock").await;
    echoes(&mut s, b"hi").await;
    drop(s);
    sup.shutdown().await;
}

#[tokio::test]
async fn visitor_address_survives_the_haproxy_hop() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = backend.local_addr().unwrap();
    let dir = short_dir();
    let sup = Supervisor::start(
        opts(&dir),
        &cfg_with(&dir, &[("a.sock", addr)], "send-proxy-v2"),
    )
    .await
    .unwrap();
    let mut s = visit(&dir, "a.sock").await;
    let (mut conn, _) = timeout(STEP, backend.accept()).await.unwrap().unwrap();
    let (src, dst) = timeout(STEP, read_proxy_v2(&mut conn)).await.unwrap();
    assert_eq!(src, VISITOR.parse::<SocketAddr>().unwrap());
    assert_eq!(dst, LOCAL.parse::<SocketAddr>().unwrap());
    // The payload follows the header untouched.
    s.write_all(b"hi").await.unwrap();
    let mut buf = [0u8; 2];
    timeout(STEP, conn.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"hi");
    drop((s, conn));
    sup.shutdown().await;
}

#[tokio::test]
async fn apply_same_text_is_unchanged() {
    let echo = echo_backend(b"").await;
    let dir = short_dir();
    let c = cfg(&dir, &[("a.sock", echo)]);
    let mut sup = Supervisor::start(opts(&dir), &c).await.unwrap();
    let before = worker_pids(&dir).await;
    assert_eq!(sup.apply(&c).await.unwrap(), Applied::Unchanged);
    assert_eq!(worker_pids(&dir).await, before, "no new worker");
    sup.shutdown().await;
}

#[tokio::test]
async fn apply_switches_backend_and_keeps_open_connections() {
    let a = echo_backend(b"A").await;
    let b = echo_backend(b"B").await;
    let dir = short_dir();
    let mut sup = Supervisor::start(opts(&dir), &cfg(&dir, &[("a.sock", a)]))
        .await
        .unwrap();
    let mut conn1 = visit(&dir, "a.sock").await;
    assert_eq!(read_exact(&mut conn1, 1).await, b"A");

    let next = cfg(&dir, &[("a.sock", b)]);
    assert_eq!(sup.apply(&next).await.unwrap(), Applied::Reloaded);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("haproxy.cfg")).unwrap(),
        next
    );

    echoes(&mut conn1, b"still").await;
    let mut conn2 = visit(&dir, "a.sock").await;
    assert_eq!(read_exact(&mut conn2, 1).await, b"B");
    echoes(&mut conn2, b"new").await;
    drop((conn1, conn2));
    sup.shutdown().await;
}

#[tokio::test]
async fn invalid_config_is_refused_and_old_one_keeps_serving() {
    let echo = echo_backend(b"").await;
    let dir = short_dir();
    let good = cfg(&dir, &[("a.sock", echo)]);
    let mut sup = Supervisor::start(opts(&dir), &good).await.unwrap();

    let bad = good.replace("default_backend b0", "default_backend nope");
    assert_ne!(bad, good);
    match sup.apply(&bad).await {
        Err(ApplyError::Invalid(m)) => {
            assert!(m.contains("nope"), "{m}");
            assert!(m.contains("[ALERT]"), "{m}");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(dir.path().join("haproxy.cfg")).unwrap(),
        good
    );
    assert!(!exists(&dir.path().join("haproxy.cfg.new")));
    let mut s = visit(&dir, "a.sock").await;
    echoes(&mut s, b"hi").await;
    drop(s);
    // The refused text did not become the running one.
    assert_eq!(sup.apply(&good).await.unwrap(), Applied::Unchanged);
    sup.shutdown().await;
}

#[tokio::test]
async fn failed_reload_restores_the_previous_config() {
    let echo = echo_backend(b"").await;
    let dir = short_dir();
    let good = cfg(&dir, &[("a.sock", echo)]);
    let mut sup = Supervisor::start(opts(&dir), &good).await.unwrap();

    // `haproxy -c` does not bind, so this passes the check and fails only when the new worker
    // starts.
    match sup.apply(&fails_to_load(&dir, &good)).await {
        Err(ApplyError::ReloadFailed(m)) => assert!(m.contains("Success=0"), "{m}"),
        other => panic!("expected ReloadFailed, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(dir.path().join("haproxy.cfg")).unwrap(),
        good
    );
    let mut s = visit(&dir, "a.sock").await;
    echoes(&mut s, b"hi").await;
    drop(s);
    sup.shutdown().await;
}

/// A configuration that passes `haproxy -c` but fails to load: a socket in a missing directory.
fn fails_to_load(dir: &TempDir, good: &str) -> String {
    format!(
        "{good}\nfrontend broken\n    bind unix@{}/missing/x.sock accept-proxy mode 600\n    default_backend b0\n",
        dir.path().display()
    )
}

#[tokio::test]
async fn definite_reload_failure_keeps_unchanged_working() {
    let echo = echo_backend(b"").await;
    let dir = short_dir();
    let good = cfg(&dir, &[("a.sock", echo)]);
    let mut sup = Supervisor::start(opts(&dir), &good).await.unwrap();
    match sup.apply(&fails_to_load(&dir, &good)).await {
        Err(ApplyError::ReloadFailed(m)) => assert!(m.contains("Success=0"), "{m}"),
        other => panic!("expected ReloadFailed, got {other:?}"),
    }
    let before = worker_pids(&dir).await;
    // `Success=0` says the old worker kept serving, so the old text is known to run.
    assert_eq!(sup.apply(&good).await.unwrap(), Applied::Unchanged);
    assert_eq!(worker_pids(&dir).await, before, "no new worker");
    sup.shutdown().await;
}

#[tokio::test]
async fn apply_after_a_cancelled_apply_reloads_again() {
    let a = echo_backend(b"A").await;
    let b = echo_backend(b"B").await;
    let dir = short_dir();
    let old = cfg(&dir, &[("a.sock", a)]);
    let new = cfg(&dir, &[("a.sock", b)]);
    let mut o = opts(&dir);
    // A reload sent while the master re-executes can go unanswered; keep such attempts short.
    o.reload_timeout = Duration::from_secs(2);
    let mut sup = Supervisor::start(o, &old).await.unwrap();

    // Drive `apply(new)` until the new text is on disk, which happens just before the reload
    // request, then drop it while the reload is in flight.
    let cfg_path = dir.path().join("haproxy.cfg");
    {
        let fut = sup.apply(&new);
        tokio::pin!(fut);
        let deadline = Instant::now() + STEP;
        loop {
            tokio::select! {
                r = &mut fut => panic!("apply finished before it could be cancelled: {r:?}"),
                _ = sleep(Duration::from_millis(1)) => {}
            }
            if std::fs::read_to_string(&cfg_path).unwrap() == new {
                break;
            }
            assert!(Instant::now() < deadline, "new text never reached the disk");
        }
    }

    // The cancelled reload may still be under way: while the master re-executes, its socket
    // refuses connections or leaves a request unanswered. Such attempts fail and are retried,
    // as the engine would; none may claim `Unchanged`.
    let deadline = Instant::now() + 3 * STEP;
    loop {
        match sup.apply(&old).await {
            Ok(Applied::Reloaded) => break,
            Ok(Applied::Unchanged) => panic!("old text claimed to run after a cancelled reload"),
            Err(e) => {
                assert!(Instant::now() < deadline, "apply(old) kept failing: {e}");
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
    let mut conn = visit(&dir, "a.sock").await;
    assert_eq!(read_exact(&mut conn, 1).await, b"A");
    drop(conn);
    assert_eq!(sup.apply(&new).await.unwrap(), Applied::Reloaded);
    let mut conn = visit(&dir, "a.sock").await;
    assert_eq!(read_exact(&mut conn, 1).await, b"B");
    drop(conn);
    sup.shutdown().await;
}

#[tokio::test]
async fn exited_resolves_when_haproxy_is_killed() {
    let echo = echo_backend(b"").await;
    let dir = short_dir();
    let mut sup = Supervisor::start(opts(&dir), &cfg(&dir, &[("a.sock", echo)]))
        .await
        .unwrap();
    let workers = worker_pids(&dir).await;
    kill(Pid::from_raw(sup.pid() as i32), Signal::SIGKILL).unwrap();
    let status = timeout(Duration::from_secs(2), sup.exited())
        .await
        .expect("exited() did not resolve");
    assert!(!status.success());
    // Resolves again, with the same status.
    assert_eq!(sup.exited().await, status);
    gone(&workers).await;
    sup.shutdown().await;
    assert!(!exists(&dir.path().join("master.sock")));
}

#[tokio::test]
async fn shutdown_stops_haproxy_and_removes_sockets() {
    let echo = echo_backend(b"").await;
    let dir = short_dir();
    let sup = Supervisor::start(opts(&dir), &cfg(&dir, &[("a.sock", echo)]))
        .await
        .unwrap();
    let mut pids = worker_pids(&dir).await;
    pids.push(sup.pid() as i32);
    for name in ["master.sock", "stats.sock", "s/a.sock"] {
        assert!(
            exists(&dir.path().join(name)),
            "{name} missing while running"
        );
    }
    let started = Instant::now();
    sup.shutdown().await;
    assert!(started.elapsed() < Duration::from_secs(5));
    gone(&pids).await;
    for name in ["master.sock", "stats.sock", "s/a.sock"] {
        assert!(!exists(&dir.path().join(name)), "{name} left behind");
    }
}

#[tokio::test]
async fn dropping_the_supervisor_stops_haproxy() {
    let echo = echo_backend(b"").await;
    let dir = short_dir();
    let sup = Supervisor::start(opts(&dir), &cfg(&dir, &[("a.sock", echo)]))
        .await
        .unwrap();
    let mut pids = worker_pids(&dir).await;
    pids.push(sup.pid() as i32);
    drop(sup);
    gone(&pids).await;
}

#[tokio::test]
async fn a_panic_while_running_stops_haproxy() {
    let echo = echo_backend(b"").await;
    let dir = short_dir();
    let c = cfg(&dir, &[("a.sock", echo)]);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let path = dir.path().to_path_buf();
    let task = tokio::spawn(async move {
        let mut o = SupervisorOptions::new(path);
        o.inherit_output = false;
        let sup = Supervisor::start(o, &c).await.unwrap();
        tx.send(sup.pid() as i32).unwrap();
        let _ = go_rx.await;
        // `sup` is still held here, so unwinding drops it.
        std::panic::resume_unwind(Box::new("deliberate"));
    });
    let master = rx.await.unwrap();
    let mut pids = worker_pids(&dir).await;
    pids.push(master);
    go_tx.send(()).unwrap();
    assert!(task.await.unwrap_err().is_panic());
    gone(&pids).await;
}

#[tokio::test]
async fn start_makes_the_runtime_directory_private() {
    use std::os::unix::fs::PermissionsExt;
    let echo = echo_backend(b"").await;
    let dir = short_dir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let sup = Supervisor::start(opts(&dir), &cfg(&dir, &[("a.sock", echo)]))
        .await
        .unwrap();
    for d in [dir.path().to_path_buf(), dir.path().join("s")] {
        let mode = std::fs::metadata(&d).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "{}: {mode:o}", d.display());
    }
    sup.shutdown().await;
}

#[tokio::test]
async fn start_refuses_an_invalid_config() {
    let echo = echo_backend(b"").await;
    let dir = short_dir();
    let bad = cfg(&dir, &[("a.sock", echo)]).replace("default_backend b0", "default_backend nope");
    let err = Supervisor::start(opts(&dir), &bad).await.err().unwrap();
    let msg = format!("{err:#}");
    assert!(msg.contains("nope"), "{msg}");
    assert!(!exists(&dir.path().join("master.sock")));
    assert!(!exists(&dir.path().join("haproxy.cfg.new")));
}

#[tokio::test]
async fn start_rejects_a_long_runtime_dir() {
    let dir = short_dir();
    let mut long = dir.path().as_os_str().to_owned();
    long.push("/");
    while long.len() < 80 {
        long.push("x");
    }
    assert_eq!(long.len(), 80);
    let long = std::path::PathBuf::from(long);
    let mut o = opts(&dir);
    o.runtime_dir = long.clone();
    let err = Supervisor::start(o, "").await.err().unwrap();
    let msg = format!("{err:#}");
    assert!(msg.contains(&MAX_RUNTIME_DIR_LEN.to_string()), "{msg}");
    assert!(!exists(&long), "created a directory it refused");
}

#[tokio::test]
async fn start_fails_clearly_without_the_binary() {
    let dir = short_dir();
    let mut o = opts(&dir);
    o.haproxy_bin = "/nonexistent/haproxy".into();
    let err = Supervisor::start(o, "global\n").await.err().unwrap();
    let msg = format!("{err:#}");
    assert!(msg.contains("/nonexistent/haproxy"), "{msg}");
}

/// A stand-in for `haproxy`: `-c` accepts anything; otherwise it records its pid in
/// `<cfg>.pid` and sleeps without ever opening the master socket.
fn fake_haproxy(dir: &TempDir) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.path().join("fake-haproxy");
    std::fs::write(
        &path,
        "#!/bin/sh\n[ \"$1\" = \"-c\" ] && exit 0\necho $$ > \"$5.tmp\"\nmv \"$5.tmp\" \"$5.pid\"\nexec sleep 60\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// The pid the fake recorded, once it has.
async fn fake_pid(dir: &TempDir) -> i32 {
    let path = dir.path().join("haproxy.cfg.pid");
    let deadline = Instant::now() + STEP;
    loop {
        if let Ok(text) = std::fs::read_to_string(&path) {
            return text.trim().parse().unwrap();
        }
        assert!(Instant::now() < deadline, "fake haproxy never started");
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn start_times_out_when_the_master_never_answers() {
    let dir = short_dir();
    let mut o = opts(&dir);
    o.haproxy_bin = fake_haproxy(&dir);
    o.reload_timeout = Duration::from_millis(300);
    let started = Instant::now();
    let err = Supervisor::start(o, "global\n").await.err().unwrap();
    assert!(started.elapsed() < STEP);
    let msg = format!("{err:#}");
    assert!(msg.contains("did not answer"), "{msg}");
    gone(&[fake_pid(&dir).await]).await;
}

/// Plays the master for the fake once it has started: answers the readiness probe, and takes
/// each `reload` without ever replying. The counter is the number of `reload` requests.
fn fake_master(dir: &TempDir) -> (tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
    let master = dir.path().join("master.sock");
    let marker = dir.path().join("haproxy.cfg.pid");
    let reloads = Arc::new(AtomicUsize::new(0));
    let counter = reloads.clone();
    let server = tokio::spawn(async move {
        while !marker.exists() {
            sleep(Duration::from_millis(5)).await;
        }
        let listener = tokio::net::UnixListener::bind(&master).unwrap();
        let mut held = Vec::new();
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut line = Vec::new();
            loop {
                let mut b = [0u8; 1];
                if s.read(&mut b).await.unwrap() == 0 || b[0] == b'\n' {
                    break;
                }
                line.push(b[0]);
            }
            if line == b"reload" {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(s);
            } else {
                s.write_all(b"Name: fake\n").await.unwrap();
            }
        }
    });
    (server, reloads)
}

#[tokio::test]
async fn reload_without_a_reply_times_out_and_restores() {
    let dir = short_dir();
    let mut o = opts(&dir);
    o.haproxy_bin = fake_haproxy(&dir);
    o.reload_timeout = Duration::from_millis(500);
    let (server, reloads) = fake_master(&dir);
    let mut sup = Supervisor::start(o, "global\n").await.unwrap();
    let pid = fake_pid(&dir).await;
    let started = Instant::now();
    match sup.apply("global\n    maxconn 10\n").await {
        Err(ApplyError::ReloadFailed(m)) => assert!(m.contains("timed out"), "{m}"),
        other => panic!("expected ReloadFailed, got {other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(500));
    assert_eq!(reloads.load(Ordering::SeqCst), 1);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("haproxy.cfg")).unwrap(),
        "global\n"
    );
    server.abort();
    sup.shutdown().await;
    gone(&[pid]).await;
}

#[tokio::test]
async fn restore_replaces_the_file_instead_of_rewriting_it() {
    use std::os::unix::fs::MetadataExt;
    let dir = short_dir();
    let mut o = opts(&dir);
    o.haproxy_bin = fake_haproxy(&dir);
    o.reload_timeout = Duration::from_millis(500);
    let (server, _reloads) = fake_master(&dir);
    let old = "global\n";
    let new = "global\n    maxconn 10\n";
    let mut sup = Supervisor::start(o, old).await.unwrap();
    let pid = fake_pid(&dir).await;
    let cfg = dir.path().join("haproxy.cfg");
    let seen = dir.path().join("seen.cfg");
    // While the reload waits for its reply, keep a second name for the file HAProxy was told to
    // load. A restore in place would change what that name shows.
    let watch = async {
        let deadline = Instant::now() + STEP;
        while std::fs::read_to_string(&cfg).ok().as_deref() != Some(new) {
            assert!(
                Instant::now() < deadline,
                "the new configuration was never written"
            );
            sleep(Duration::from_millis(5)).await;
        }
        std::fs::hard_link(&cfg, &seen).unwrap();
    };
    let (applied, ()) = tokio::join!(sup.apply(new), watch);
    assert!(
        matches!(applied, Err(ApplyError::ReloadFailed(_))),
        "{applied:?}"
    );
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), old);
    assert_eq!(std::fs::read_to_string(&seen).unwrap(), new);
    assert_ne!(
        std::fs::metadata(&cfg).unwrap().ino(),
        std::fs::metadata(&seen).unwrap().ino()
    );
    assert!(!exists(&dir.path().join("haproxy.cfg.new")));
    server.abort();
    sup.shutdown().await;
    gone(&[pid]).await;
}

#[tokio::test]
async fn apply_after_a_timed_out_reload_reloads_again() {
    let dir = short_dir();
    let mut o = opts(&dir);
    o.haproxy_bin = fake_haproxy(&dir);
    o.reload_timeout = Duration::from_millis(300);
    let (server, reloads) = fake_master(&dir);
    let old = "global\n";
    let mut sup = Supervisor::start(o, old).await.unwrap();
    let pid = fake_pid(&dir).await;
    match sup.apply("global\n    maxconn 10\n").await {
        Err(ApplyError::ReloadFailed(m)) => assert!(m.contains("timed out"), "{m}"),
        other => panic!("expected ReloadFailed, got {other:?}"),
    }
    // The timed-out reload may still take effect, so the old text is no longer known to run.
    match sup.apply(old).await {
        Err(ApplyError::ReloadFailed(m)) => assert!(m.contains("timed out"), "{m}"),
        other => panic!("expected another reload attempt, got {other:?}"),
    }
    assert_eq!(reloads.load(Ordering::SeqCst), 2);
    server.abort();
    sup.shutdown().await;
    gone(&[pid]).await;
}

#[tokio::test]
async fn rendered_config_passes_haproxy_validation() {
    use iroh_gateway_operator::haproxy::render::render;
    use iroh_gateway_operator::model::{Backend, GatewayModel, ListenerModel, Model, ObjRef};

    fn listener(port: u16, backends: Vec<Backend>) -> ListenerModel {
        ListenerModel {
            name: format!("l{port}"),
            port,
            protocol: "TCP".into(),
            accepted: Ok(()),
            conflicted: None,
            resolved_refs: Ok(()),
            supported_kinds: vec!["TCPRoute".into()],
            allowed_namespaces: Default::default(),
            attached_routes: 1,
            backends,
        }
    }
    fn backend(ip: &str, port: u16, weight: u32) -> Backend {
        Backend {
            service: ObjRef::new("apps", "svc"),
            ip: ip.parse().unwrap(),
            port,
            weight,
        }
    }
    fn gateway(ns: &str, name: &str, listeners: Vec<ListenerModel>) -> GatewayModel {
        GatewayModel {
            key: ObjRef::new(ns, name),
            generation: 1,
            accepted: Ok(()),
            listeners,
            edges: Vec::new(),
            addresses: Vec::new(),
            addresses_dropped: 0,
        }
    }

    let model = Model {
        classes: Vec::new(),
        gateways: vec![
            gateway(
                "a",
                "x",
                vec![
                    listener(
                        80,
                        vec![backend("10.0.0.1", 80, 3), backend("10.0.0.2", 80, 1)],
                    ),
                    listener(443, vec![backend("10.0.0.1", 443, 1)]),
                ],
            ),
            gateway(
                "b",
                "y",
                vec![listener(5432, vec![backend("fd00::12", 5432, 1)])],
            ),
        ],
        edges: Vec::new(),
        routes: Vec::new(),
    };
    // The longest runtime directory the supervisor accepts, so that HAProxy binds the longest
    // socket paths the render can give.
    let dir = short_dir();
    let mut runtime = dir.path().as_os_str().to_owned();
    runtime.push("/");
    while runtime.len() < MAX_RUNTIME_DIR_LEN {
        runtime.push("r");
    }
    assert_eq!(runtime.len(), 60);
    let runtime = std::path::PathBuf::from(runtime);
    let rendered = render(&model, &runtime);
    assert!(rendered.haproxy_cfg.contains("[fd00::12]:5432"));
    let mut o = opts(&dir);
    o.runtime_dir = runtime.clone();
    let sup = Supervisor::start(o, &rendered.haproxy_cfg).await.unwrap();
    assert!(exists(&runtime.join("s").join("idle.sock")));
    sup.shutdown().await;
}
