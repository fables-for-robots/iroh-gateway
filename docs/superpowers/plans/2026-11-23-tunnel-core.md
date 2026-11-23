# Tunnel Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working TCP tunnel between an edge binary on a public machine and an operator-side process, over iroh, with static configuration and no Kubernetes.

**Architecture:** Three crates in one workspace. `proto` holds the wire messages, framing, key files, transport settings and the byte-copy loop shared by both ends. `edge` opens the public ports it is told to and forwards each visitor connection as one QUIC stream. `operator` dials each edge, pushes the listener list, and hands each incoming stream to a `Connector`; in this plan the only connector dials a fixed TCP address.

**Tech Stack:** Rust 2024 (rust-version 1.100), tokio, iroh 1.x, ciborium (CBOR), serde, clap 4, tracing, toml, thiserror 2, anyhow.

**Spec:** `docs/superpowers/specs/2026-11-23-iroh-gateway-design.md`. This plan implements build step 1 of 5 ("Tunnel with static configuration"). Steps 2 to 5 each get their own plan, written when the previous one has landed.

## Global Constraints

- Rust edition 2024, `rust-version = "1.100"`, license `AGPL-3.0-or-later`, repository `https://github.com/fables-for-robots/iroh-gateway`.
- Package names: `iroh-gateway-proto`, `iroh-gateway-edge`, `iroh-gateway-operator`, in directories `proto/`, `edge/`, `operator/`.
- ALPN is exactly `iroh-gateway/0`.
- The toolchain is Rust 1.100.0, pinned in `rust-toolchain.toml` and provided by `oxalica/rust-overlay` in the flake. nixpkgs does not ship 1.100 yet (26.05 has 1.95, unstable 1.99).
- Relay mode is `disabled` by default. In that mode an endpoint has no relay and no address lookup: `presets::Minimal` with `RelayMode::Disabled`.
- Relay mode `n0` or a relay URL is opt-in, and is the same value on the operator and its edges. The operator never publishes its own address anywhere, in any mode.
- The operator dials the edge. The edge never dials.
- Each side pins the other's key. The edge serves only the configured operator EndpointId.
- The edge binds only ports named in the current `Config`, and persists only its own key.
- Default iroh UDP port on the edge: `7842`.
- QUIC keep-alive 5 s, idle timeout 20 s, on both sides.
- Control messages are length-prefixed CBOR.
- UDP forwarding is not in this plan. An edge asked for a UDP listener reports a bind error for it.
- Metrics are not in this plan. Log with `tracing`.
- Pin crate versions that resolve together at the time of building; use `iroh = "1"` as the sibling project does. Check iroh calls against the resolved version's docs before using them.
- All tests pass on macOS and Linux with `cargo test --workspace`, using loopback only.
- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` are clean at every commit.
- Leave no build output outside `target/`. Run `cargo clean` when the last task is done.
- Work on a branch named `tunnel-core`, not on `main`.

## Review Focus

Conditions the spec implies that are most likely to bite a real user. Each has a test in the task named.

1. The operator restarts and dials again while the edge still holds the old connection. The edge must switch to the new connection and keep its ports open. (Task 5, `new_operator_connection_replaces_old`)
2. The key file is empty, truncated or corrupt. The program must stop with an error and must not silently generate a new identity, because that breaks the pinning on the other side. (Task 2, `load_rejects_malformed_key_file`)
3. A visitor connects and disconnects at once, or the tunnel stream fails mid-setup. The connection slot must be released, or the cap fills up for good. (Task 5, `early_disconnect_releases_slot`)
4. The peer sends an oversized length prefix or bytes that are not valid CBOR. The reader must refuse without allocating the claimed size, and a bad stream header must cost one stream, not the tunnel. (Task 1, `read_frame_rejects_oversized_length`; Task 6, `garbage_header_resets_stream_only`)
5. The edge binds `::` and an IPv4 visitor shows up as `::ffff:a.b.c.d`. The address sent to the operator must be the plain IPv4 form. (Task 4, `visitor_address_is_canonical`)

## File Structure

```
Cargo.toml                    workspace manifest, shared dependency versions
flake.nix  .envrc  .gitignore  LICENSE  README.md
.github/workflows/ci.yml
proto/
  Cargo.toml
  src/lib.rs                  ALPN, error codes, re-exports
  src/control.rs              Config, Status, Listener, StreamHeader types
  src/frame.rs                length-prefixed CBOR read/write
  src/key.rs                  key file load/generate
  src/transport.rs            QUIC transport settings, relay mode, endpoint builder
  src/splice.rs               byte copy between a local stream and a QUIC stream
  tests/splice.rs
edge/
  Cargo.toml
  src/lib.rs                  Edge::spawn, EdgeOptions, EdgeHandle
  src/listeners.rs            ListenerSet: public ports, cap, config diff
  src/session.rs              one tunnel session over a Connection
  src/main.rs                 CLI: run, id
  tests/common/mod.rs         FakeOperator, port helpers, echo server
  tests/session.rs
  tests/cli.rs
operator/
  Cargo.toml
  src/lib.rs
  src/tunnel/mod.rs           re-exports
  src/tunnel/link.rs          EdgeLink: dial, backoff, config push, stream dispatch
  src/tunnel/connector.rs     Connector trait, StaticConnector
  src/staticcfg.rs            TOML config for static mode
  src/main.rs                 CLI: static, id
  tests/common/mod.rs
  tests/tunnel.rs
  tests/cli.rs
```

---

### Task 1: Workspace, control messages and framing

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `flake.nix`, `.envrc`, `.gitignore`, `LICENSE`, `.github/workflows/ci.yml`
- Create: `proto/Cargo.toml`, `proto/src/lib.rs`, `proto/src/control.rs`, `proto/src/frame.rs`

**Interfaces:**
- Consumes: nothing.
- Produces (crate `iroh_gateway_proto`):

```rust
// lib.rs
pub const ALPN: &[u8] = b"iroh-gateway/0";
pub const DEFAULT_IROH_PORT: u16 = 7842;
/// Stream reset codes.
pub const RESET_ABORTED: u32 = 1;
pub const RESET_UNKNOWN_LISTENER: u32 = 2;
pub const RESET_BACKEND_UNAVAILABLE: u32 = 3;
pub const RESET_BAD_HEADER: u32 = 4;
/// Connection close codes.
pub const CLOSE_UNAUTHORIZED: u32 = 1;
pub const CLOSE_REPLACED: u32 = 2;
pub const CLOSE_SHUTDOWN: u32 = 3;

// control.rs — all derive Debug, Clone, PartialEq, Eq, Serialize, Deserialize
pub enum Protocol { Tcp, Udp }                       // also Copy, Hash; serde "tcp"/"udp"
pub struct ListenerKey { pub protocol: Protocol, pub port: u16 }   // also Copy, Hash
pub struct Listener { pub id: u32, pub protocol: Protocol, pub port: u16 }
impl Listener { pub fn key(&self) -> ListenerKey }
pub struct Config { pub generation: u64, pub listeners: Vec<Listener> }
pub enum BindState { Bound, Error(String) }
pub struct ListenerStatus { pub id: u32, pub state: BindState }
pub struct Status { pub generation: u64, pub listeners: Vec<ListenerStatus>, pub version: String }
pub struct StreamHeader { pub listener_id: u32, pub visitor: SocketAddr, pub local: SocketAddr }

// frame.rs
pub const MAX_FRAME_LEN: usize = 65_536;
#[derive(Debug, thiserror::Error)]
pub enum FrameError { Io(#[from] std::io::Error), TooLarge(usize), Decode(String), Encode(String) }
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), FrameError>
    where W: AsyncWrite + Unpin, T: Serialize;
/// Ok(None) on clean EOF before the first length byte.
pub async fn read_frame<R, T>(r: &mut R) -> Result<Option<T>, FrameError>
    where R: AsyncRead + Unpin, T: DeserializeOwned;
```

A frame is a 4-byte big-endian length followed by that many bytes of CBOR. Structs encode as CBOR maps, so unknown fields from a newer peer are ignored.

- [ ] **Step 1: Scaffold the workspace**

Root `Cargo.toml`: virtual workspace, `resolver = "3"`, members `proto`, `edge`, `operator`, a `[workspace.package]` with the edition, rust-version, license and repository from Global Constraints, and `[workspace.dependencies]` for the shared crates. Create only `proto` for now; add the other two members in their tasks.

`rust-toolchain.toml`: channel `1.100.0`, components `rustfmt`, `clippy`, `rust-analyzer`. `flake.nix`: same shape as `../secret-bunker-iroh/flake.nix` plus the input `rust-overlay` (`github:oxalica/rust-overlay`, following `nixpkgs`); the dev shell's only package is the toolchain built from `rust-toolchain.toml` (`rust-bin.fromRustupToolchainFile`); no `packages` output yet. Check with `nix develop -c rustc --version`, expected `rustc 1.100.0`. `.envrc`: `use flake`. `.gitignore`: `/target`, `.direnv`, `.DS_Store`, `*.key`. `LICENSE`: copy `../secret-bunker-iroh/LICENSE`. `.github/workflows/ci.yml`: the `test` and `audit` jobs from `../secret-bunker-iroh/.github/workflows/ci.yml`, without the CRD drift step.

- [ ] **Step 2: Write the failing tests** in `proto/src/frame.rs` and `proto/src/control.rs` (`#[cfg(test)]`)

```rust
#[tokio::test]
async fn config_roundtrips() {
    let cfg = Config { generation: 7, listeners: vec![Listener { id: 3, protocol: Protocol::Tcp, port: 443 }] };
    let mut buf = Vec::new();
    write_frame(&mut buf, &cfg).await.unwrap();
    assert_eq!(&buf[..4], &((buf.len() - 4) as u32).to_be_bytes());
    let got: Option<Config> = read_frame(&mut &buf[..]).await.unwrap();
    assert_eq!(got, Some(cfg));
}

#[tokio::test]
async fn status_and_header_roundtrip() {
    // Status with one Bound and one Error("address in use"), version "0.1.0"
    // StreamHeader with visitor 198.51.100.9:50000 and local [2001:db8::1]:443
    // each: write_frame then read_frame, assert_eq
}

#[tokio::test]
async fn read_frame_returns_none_on_clean_eof() {
    let got: Option<Config> = read_frame(&mut &[][..]).await.unwrap();
    assert_eq!(got, None);
}

#[tokio::test]
async fn read_frame_errors_on_truncated_body() {
    let bytes = [0, 0, 0, 10, 1, 2];
    let err = read_frame::<_, Config>(&mut &bytes[..]).await.unwrap_err();
    assert!(matches!(err, FrameError::Io(_)));
}

#[tokio::test]
async fn read_frame_rejects_oversized_length() {
    let bytes = (MAX_FRAME_LEN as u32 + 1).to_be_bytes();
    let err = read_frame::<_, Config>(&mut &bytes[..]).await.unwrap_err();
    assert!(matches!(err, FrameError::TooLarge(n) if n == MAX_FRAME_LEN + 1));
}

#[tokio::test]
async fn read_frame_rejects_garbage_cbor() {
    let bytes = [0, 0, 0, 3, 0xff, 0xff, 0xff];
    assert!(matches!(read_frame::<_, Config>(&mut &bytes[..]).await, Err(FrameError::Decode(_))));
}

#[tokio::test]
async fn unknown_fields_are_ignored() {
    // Encode a CBOR map {generation: 1, listeners: [], future_field: true} by hand with
    // ciborium::Value, frame it, read it as Config, assert generation == 1.
}

#[test]
fn listener_key_drops_id() {
    let l = Listener { id: 9, protocol: Protocol::Udp, port: 53 };
    assert_eq!(l.key(), ListenerKey { protocol: Protocol::Udp, port: 53 });
}
```

- [ ] **Step 3: Run the tests and see them fail**

Run: `cargo test -p iroh-gateway-proto`
Expected: compile errors for the missing items.

- [ ] **Step 4: Implement `control.rs`, `frame.rs` and the constants in `lib.rs`**

`read_frame` checks the length against `MAX_FRAME_LEN` before allocating. `write_frame` returns `FrameError::TooLarge` if the encoded body exceeds it.

- [ ] **Step 5: Run the tests and the lints**

Run: `cargo test -p iroh-gateway-proto && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 8 tests pass, no lint output.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(proto): workspace scaffold, control messages and framing"
```

---

### Task 2: Key files and transport settings

**Files:**
- Create: `proto/src/key.rs`, `proto/src/transport.rs`
- Modify: `proto/src/lib.rs`, `proto/Cargo.toml`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:

```rust
// key.rs
/// Reads the key at `path`; if the file does not exist, generates one and writes it.
/// Any other problem (unreadable, wrong length, not hex) is an error.
pub fn load_or_generate(path: &Path) -> anyhow::Result<iroh::SecretKey>;

// transport.rs
pub const KEEP_ALIVE: Duration = Duration::from_secs(5);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(20);
pub const MAX_TUNNEL_STREAMS: u32 = 65_536;
/// `incoming_bidi_streams` is how many streams the peer may have open towards us.
pub fn transport_config(incoming_bidi_streams: u32) -> iroh::endpoint::QuicTransportConfig;

/// Parses from and displays as "disabled", "n0", or an https relay URL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Relay { #[default] Disabled, N0, Custom(iroh::RelayUrl) }
impl FromStr for Relay { .. }      impl Display for Relay { .. }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role { Edge, Operator }

/// Builder with presets::Minimal, the key, the transport config, and relay settings per the table below.
pub fn endpoint_builder(key: iroh::SecretKey, incoming_bidi_streams: u32, relay: &Relay, role: Role)
    -> iroh::endpoint::Builder;
```

| `relay` | `Role::Edge` | `Role::Operator` |
|---|---|---|
| `Disabled` | `RelayMode::Disabled`, no address lookup | same |
| `N0` | n0 default relays; `PkarrPublisher::n0_dns()` (publishes the relay URL only, its default) | n0 default relays; `PkarrResolver::n0_dns()` and `DnsAddressLookup::n0_dns()`; **no publisher** |
| `Custom(url)` | `RelayMode::Custom(url.into())`, no address lookup | same |

Do not use `presets::N0` for the operator: it adds a publisher.

The key file is 64 lowercase hex characters and a newline. On creation the file has mode `0600` and missing parent directories are created with mode `0700` (on Unix).

- [ ] **Step 1: Write the failing tests** in `proto/src/key.rs`

```rust
#[test]
fn generates_then_reloads_same_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub/edge.key");
    let a = load_or_generate(&path).unwrap();
    let b = load_or_generate(&path).unwrap();
    assert_eq!(a.public(), b.public());
    assert_eq!(std::fs::read_to_string(&path).unwrap().trim().len(), 64);
}

#[cfg(unix)]
#[test]
fn new_key_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    // after load_or_generate on a fresh path:
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn load_rejects_malformed_key_file() {
    for bad in ["", "abcd", &"zz".repeat(32), &"ab".repeat(31)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.key");
        std::fs::write(&path, bad).unwrap();
        assert!(load_or_generate(&path).is_err(), "accepted {bad:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), bad, "file was rewritten");
    }
}
```

And in `proto/src/transport.rs`:

```rust
#[tokio::test]
async fn two_endpoints_connect_directly_by_key() {
    let a = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Edge)
        .alpns(vec![ALPN.to_vec()]).bind_addr("127.0.0.1:0").unwrap().bind().await.unwrap();
    let b = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Operator)
        .bind_addr("127.0.0.1:0").unwrap().bind().await.unwrap();
    let addr = EndpointAddr::new(a.id()).with_ip_addr(a.bound_sockets()[0]);
    let (conn, incoming) = tokio::join!(b.connect(addr, ALPN), a.accept());
    let conn = conn.unwrap();
    assert_eq!(conn.remote_id(), a.id());
    assert!(incoming.is_some());
}

#[test]
fn relay_parses_and_displays() {
    assert_eq!("disabled".parse::<Relay>().unwrap(), Relay::Disabled);
    assert_eq!("n0".parse::<Relay>().unwrap(), Relay::N0);
    let r: Relay = "https://relay.example.com".parse().unwrap();
    assert!(matches!(r, Relay::Custom(_)));
    assert_eq!(r.to_string().trim_end_matches('/'), "https://relay.example.com");
    assert_eq!(Relay::default(), Relay::Disabled);
    for bad in ["", "N0 ", "relay.example.com", "ftp://x"] { assert!(bad.parse::<Relay>().is_err(), "{bad:?}"); }
}

#[tokio::test]
async fn connects_through_a_relay_with_no_direct_address() {
    // iroh::test_utils::run_relay_server() gives (relay_map, relay_url, _server)
    // a: Role::Edge, Relay::Custom(relay_url), ALPN set; b: Role::Operator, same relay
    // both builders also get the test-only setting that accepts the test relay's certificate
    // a.online().await
    // b.connect(EndpointAddr::new(a.id()).with_relay_url(relay_url), ALPN) succeeds; remote_id == a.id()
    // one bi stream carries b"x" each way
}
```

The relay test needs iroh's `test-utils` feature as a dev-dependency. It runs a relay inside the test process and touches no outside network. There is no automated test for `N0`, because that would reach n0's servers; its wiring is covered by review against the table above.

- [ ] **Step 2: Run the tests and see them fail**

Run: `cargo test -p iroh-gateway-proto key:: transport::`
Expected: compile errors.

- [ ] **Step 3: Implement `key.rs` and `transport.rs`**

`transport_config` sets `max_concurrent_bidi_streams`, `max_concurrent_uni_streams(0)`, `keep_alive_interval(KEEP_ALIVE)` and `max_idle_timeout(IDLE_TIMEOUT)`. If the resolved iroh version also has per-path keep-alive and idle settings, set them to the same values.

- [ ] **Step 4: Run the tests and lints**

Run: `cargo test -p iroh-gateway-proto && cargo clippy --workspace --all-targets -- -D warnings`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(proto): key files and QUIC transport settings"
```

---

### Task 3: Splice

Copies bytes both ways between a local socket and a QUIC stream, mapping half-close and abort as the spec requires.

**Files:**
- Create: `proto/src/splice.rs`, `proto/tests/splice.rs`
- Modify: `proto/src/lib.rs`

**Interfaces:**
- Consumes: `endpoint_builder`, `ALPN`, `RESET_ABORTED` (Tasks 1, 2).
- Produces:

```rust
/// A local socket that can be torn down abruptly.
pub trait LocalStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// Close so the peer sees an abort, not a clean end. TCP: SO_LINGER 0 then drop.
    fn abort(self);
}
impl LocalStream for tokio::net::TcpStream { .. }
#[cfg(unix)] impl LocalStream for tokio::net::UnixStream { .. }   // abort = drop

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceEnd { Clean, LocalAborted, RemoteReset, ConnectionLost }
#[derive(Debug, Clone, Copy)]
pub struct SpliceStats { pub to_remote: u64, pub to_local: u64, pub end: SpliceEnd }

pub async fn splice<L: LocalStream>(
    local: L, send: iroh::endpoint::SendStream, recv: iroh::endpoint::RecvStream,
) -> SpliceStats;
```

Behaviour:

| Event | Action |
|---|---|
| Local read returns EOF | `send.finish()`, keep copying remote → local |
| Remote `recv` ends cleanly | shut down the local write half, keep copying local → remote |
| Both directions ended | return `Clean` |
| Local read or write errors | `send.reset(RESET_ABORTED)`, `recv.stop(RESET_ABORTED)`, return `LocalAborted` |
| Remote reset or stop | `local.abort()`, return `RemoteReset` |
| Connection lost | `local.abort()`, return `ConnectionLost` |

A dropped iroh `SendStream` finishes cleanly, so every abort path must call `reset` explicitly.

- [ ] **Step 1: Write the failing tests** in `proto/tests/splice.rs`

Harness (in the test file): `async fn quic_pair() -> (Connection, Connection)` builds two loopback endpoints as in Task 2 and returns both ends of one connection. `async fn tcp_pair() -> (TcpStream, TcpStream)` returns two connected loopback sockets. Each test opens one bi stream, runs `splice(tcp_b, send, recv)` on one side in a task, and drives `tcp_a` and the far stream ends directly.

```rust
#[tokio::test] async fn copies_both_directions() {
    // write b"ping" into tcp_a → read b"ping" from far recv
    // write b"pong" into far send → read b"pong" from tcp_a
}
#[tokio::test] async fn local_eof_finishes_stream_and_keeps_reading() {
    // tcp_a.shutdown() → far recv.read_to_end() returns Ok
    // then far send writes b"late", finish() → tcp_a reads b"late" then EOF
    // splice returns end == SpliceEnd::Clean, to_remote == 0, to_local == 4
}
#[tokio::test] async fn remote_finish_shuts_local_write_and_keeps_reading() {
    // far send.finish() → tcp_a read returns 0
    // tcp_a writes b"still" then shutdown → far recv reads b"still" then end
}
#[tokio::test] async fn local_abort_resets_stream() {
    // tcp_a.set_linger(Some(Duration::ZERO)); drop(tcp_a)
    // far recv.read(..) → Err(ReadError::Reset(code)) with code == RESET_ABORTED
    // splice returns SpliceEnd::LocalAborted
}
#[tokio::test] async fn remote_reset_aborts_local() {
    // far send.reset(VarInt::from_u32(9))
    // tcp_a.read(..) → Err with kind ConnectionReset
    // splice returns SpliceEnd::RemoteReset
}
#[tokio::test] async fn connection_loss_aborts_local() {
    // close the far Connection with code 0
    // tcp_a.read(..) → Err with kind ConnectionReset; splice returns ConnectionLost
}
#[tokio::test] async fn large_transfer_is_intact() {
    // 8 MiB of a repeating counter pattern tcp_a → far, far echoes back, compare sha256
}
```

- [ ] **Step 2: Run the tests and see them fail**

Run: `cargo test -p iroh-gateway-proto --test splice`
Expected: compile errors.

- [ ] **Step 3: Implement `splice.rs`**

Two concurrent copy loops with a 64 KiB buffer each, joined so that either loop's abort cancels the other. Do not use `tokio::io::copy_bidirectional`; it cannot express the reset mapping.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p iroh-gateway-proto --test splice`
Expected: 7 pass. Run it 20 times in a loop to check for flakiness: `for i in $(seq 20); do cargo test -p iroh-gateway-proto --test splice -q || break; done`

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(proto): splice between local sockets and QUIC streams"
```

---

### Task 4: Edge listeners

The set of public ports an edge has open. No iroh in this task.

**Files:**
- Create: `edge/Cargo.toml`, `edge/src/lib.rs`, `edge/src/listeners.rs`
- Modify: `Cargo.toml` (add member)

**Interfaces:**
- Consumes: `Config`, `Status`, `Listener`, `ListenerKey`, `BindState`, `Protocol` (Task 1).
- Produces (crate `iroh_gateway_edge`):

```rust
pub struct Accepted {
    pub listener_id: u32,
    pub stream: tokio::net::TcpStream,
    pub visitor: SocketAddr,     // canonical: IPv4-mapped IPv6 turned into IPv4
    pub local: SocketAddr,       // canonical
    pub permit: tokio::sync::OwnedSemaphorePermit,   // held for the connection's life
}
pub struct ListenerSet { .. }
impl ListenerSet {
    pub fn new(bind_ip: IpAddr, max_connections: usize) -> (Self, tokio::sync::mpsc::Receiver<Accepted>);
    /// Makes the open ports match `cfg` and reports the result.
    pub async fn apply(&mut self, cfg: &Config) -> Status;
    pub fn close_all(&mut self);
    pub fn bound(&self) -> Vec<ListenerKey>;
}
pub fn canonical(addr: SocketAddr) -> SocketAddr;
```

Rules for `apply`:

- A port already bound whose `ListenerKey` is still in `cfg` stays bound and keeps its established connections; only its id is updated. The accept loop reads the current id at accept time.
- A bound port not in `cfg` is closed. Established connections on it are not touched.
- A new key is bound on `bind_ip`. Failure gives `BindState::Error` with the OS error text.
- `Protocol::Udp` gives `BindState::Error("udp is not supported by this edge version")`.
- `Status.generation` echoes `cfg.generation`; `Status.version` is `env!("CARGO_PKG_VERSION")`; one `ListenerStatus` per listener in `cfg`, same order.
- When no connection permit is free, an accepted visitor is closed at once.
- When the `Accepted` receiver is full or gone, an accepted visitor is closed at once.

- [ ] **Step 1: Write the failing tests** in `edge/src/listeners.rs`

Helper in the test module: `fn free_port() -> u16` binds `127.0.0.1:0`, reads the port, drops the socket. `fn cfg(generation, &[(id, Protocol, port)]) -> Config`.

```rust
#[tokio::test] async fn binds_and_accepts() {
    let p = free_port();
    let (mut set, mut rx) = ListenerSet::new("127.0.0.1".parse().unwrap(), 10);
    let st = set.apply(&cfg(1, &[(5, Protocol::Tcp, p)])).await;
    assert_eq!(st.generation, 1);
    assert_eq!(st.listeners, vec![ListenerStatus { id: 5, state: BindState::Bound }]);
    let c = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    let a = rx.recv().await.unwrap();
    assert_eq!((a.listener_id, a.visitor, a.local.port()), (5, c.local_addr().unwrap(), p));
}
#[tokio::test] async fn removed_listener_is_closed_and_refuses() {
    // apply [p], then apply [] → connect to p fails with ConnectionRefused; set.bound() is empty
}
#[tokio::test] async fn kept_listener_survives_and_takes_new_id() {
    // apply gen1 [(1,Tcp,p)], connect c1, recv a1; apply gen2 [(8,Tcp,p),(9,Tcp,q)]
    // c1/a1 still pass bytes both ways; a new connection to p arrives with listener_id 8
}
#[tokio::test] async fn bind_error_is_reported() {
    // hold p with a std::net::TcpListener; apply [(1,Tcp,p),(2,Tcp,q)]
    // → listeners[0].state is Error(_), listeners[1].state is Bound
}
#[tokio::test] async fn udp_listener_reports_unsupported() {
    // apply [(1,Udp,5353)] → Error("udp is not supported by this edge version")
}
#[tokio::test] async fn cap_closes_extra_visitors() {
    // max_connections 2; connect three, recv two Accepted and keep them
    // third socket: read returns Ok(0) or Err within 1 s; rx has no third item
    // drop one Accepted → a fourth connection is accepted
}
#[tokio::test] async fn close_all_refuses_everything() { .. }
#[test] fn visitor_address_is_canonical() {
    let mapped: SocketAddr = "[::ffff:192.0.2.7]:4000".parse().unwrap();
    assert_eq!(canonical(mapped), "192.0.2.7:4000".parse().unwrap());
    let v6: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
    assert_eq!(canonical(v6), v6);
}
```

- [ ] **Step 2: Run the tests and see them fail**

Run: `cargo test -p iroh-gateway-edge listeners::`
Expected: compile errors.

- [ ] **Step 3: Implement `listeners.rs`**

One accept task per bound port, aborted on removal. The `Accepted` channel has capacity 1024.

- [ ] **Step 4: Run the tests and lints**

Run: `cargo test -p iroh-gateway-edge && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 8 pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(edge): public listener set with config diff and connection cap"
```

---

### Task 5: Edge tunnel

**Files:**
- Create: `edge/src/session.rs`, `edge/tests/common/mod.rs`, `edge/tests/session.rs`
- Modify: `edge/src/lib.rs`

**Interfaces:**
- Consumes: `ListenerSet`, `Accepted` (Task 4); `splice`, `endpoint_builder`, `read_frame`, `write_frame`, `StreamHeader`, `Config`, `Status`, close and reset codes (Tasks 1 to 3).
- Produces:

```rust
pub struct EdgeOptions {
    pub secret_key: iroh::SecretKey,
    pub operator: iroh::EndpointId,
    pub iroh_listen: SocketAddr,          // default 0.0.0.0:7842 in the CLI
    pub public_bind: IpAddr,              // default :: in the CLI
    pub max_connections: usize,           // default 10_000 in the CLI
    pub tunnel_grace: Duration,           // default 5 s in the CLI
    pub relay: iroh_gateway_proto::Relay, // default Disabled in the CLI
}
pub struct Edge;
impl Edge { pub async fn spawn(opts: EdgeOptions) -> anyhow::Result<EdgeHandle>; }
pub struct EdgeHandle { .. }
impl EdgeHandle {
    pub fn endpoint_id(&self) -> iroh::EndpointId;
    pub fn iroh_addr(&self) -> SocketAddr;
    pub async fn shutdown(self);          // closes listeners and the endpoint
}
```

Behaviour:

- The endpoint is `endpoint_builder(key, 4, &opts.relay, Role::Edge)` with ALPN `iroh-gateway/0`; the operator needs one stream towards the edge.
- Key pinning is the same in every relay mode.
- A connection whose `remote_id()` is not `opts.operator` is closed with `CLOSE_UNAUTHORIZED` and an empty reason. Nothing else happens.
- A session accepts one bi stream as the control stream. For each `Config` read it calls `ListenerSet::apply` and writes the `Status`. A frame error on the control stream ends the session.
- For each `Accepted` during a session: open a bi stream, write the `StreamHeader`, run `splice`. The permit is dropped when the splice returns or when opening the stream fails.
- With no session, an `Accepted` is dropped at once.
- When a session ends, a timer of `tunnel_grace` starts. If no new session has received its first `Config` by then, `close_all()` runs. Established visitor connections die with the lost connection, through `splice`.
- A new connection from the operator while a session is running replaces it: the old connection is closed with `CLOSE_REPLACED`, listeners stay open, and the new session's first `Config` is applied as a diff.
- `shutdown` closes the connection with `CLOSE_SHUTDOWN`.

Test harness in `edge/tests/common/mod.rs`:

```rust
pub fn free_tcp_port() -> u16;
pub fn free_udp_port() -> u16;
pub async fn spawn_edge(operator: EndpointId, grace: Duration, max_connections: usize) -> EdgeHandle;
    // iroh_listen 127.0.0.1:0, public_bind 127.0.0.1, fresh key, Relay::Disabled
pub struct FakeOperator { pub endpoint: Endpoint, pub conn: Connection, /* control stream halves */ }
impl FakeOperator {
    pub async fn connect(key: SecretKey, edge_id: EndpointId, edge_addr: SocketAddr) -> anyhow::Result<Self>;
    pub async fn connect_via_relay(key: SecretKey, edge_id: EndpointId, relay: RelayUrl) -> anyhow::Result<Self>;
    pub async fn push(&mut self, cfg: Config) -> Status;                // write Config, read Status
    pub async fn accept_stream(&self) -> (StreamHeader, SendStream, RecvStream);
}
pub fn tcp_cfg(generation: u64, ports: &[u16]) -> Config;               // ids 1..=n
```

- [ ] **Step 1: Write the harness and the failing tests** in `edge/tests/session.rs`

```rust
#[tokio::test] async fn forwards_a_visitor_connection() {
    // push [p] → Bound. Visitor connects to p and writes b"hi".
    // accept_stream(): header.listener_id == 1, header.visitor == visitor.local_addr(),
    //   header.local.port() == p; recv reads b"hi"; send b"yo" → visitor reads b"yo"
}
#[tokio::test] async fn unlisted_operator_key_is_rejected() {
    // edge pinned to key A; FakeOperator with key B:
    //   connect() fails, or its first push() fails, with the close code CLOSE_UNAUTHORIZED
    // a port asked for by B is not open
}
#[tokio::test] async fn listeners_close_after_grace() {
    // grace 200 ms; push [p]; fake.conn.close(0, b""); sleep 1 s → connect to p is ConnectionRefused
}
#[tokio::test] async fn reconnect_within_grace_keeps_listeners() {
    // grace 2 s; push [p]; hold a std listener's worth of proof: connect v1 succeeds;
    // close connection; a second FakeOperator (same key) connects and pushes [p] within 500 ms;
    // sleep 2.5 s → connect to p still succeeds and is forwarded
}
#[tokio::test] async fn new_operator_connection_replaces_old() {
    // fake1 pushes [p]; fake2 (same key) connects and pushes [p]
    // fake1.conn.closed() resolves with application code CLOSE_REPLACED
    // p was never refused in between (connect in a loop every 20 ms during the switch)
    // a new visitor is delivered on fake2
}
#[tokio::test] async fn visitors_without_session_are_dropped() {
    // grace 5 s; push [p]; close the connection; connect to p succeeds; read returns Ok(0) or Err within 1 s
}
#[tokio::test] async fn early_disconnect_releases_slot() {
    // max_connections 1; push [p]; connect and drop a visitor 20 times in a row;
    // then a final visitor, retried for up to 2 s, is delivered by accept_stream and echoes
}
#[tokio::test] async fn tunnel_loss_aborts_visitors() {
    // visitor established and spliced; close the connection → visitor read errors within 1 s
}
#[tokio::test] async fn reachable_through_relay_without_direct_address() {
    // local relay from iroh::test_utils; edge with Relay::Custom(url);
    // FakeOperator dials EndpointAddr::new(edge_id).with_relay_url(url), no IP
    // push [p] → Bound; a visitor's bytes arrive on accept_stream
}
#[tokio::test] async fn relay_does_not_weaken_pinning() {
    // same setup; a FakeOperator with a different key is closed with CLOSE_UNAUTHORIZED
}
#[tokio::test] async fn bad_control_frame_ends_session_only() {
    // write 4 garbage bytes [0xff; 4] on the control stream → connection closes;
    // a fresh FakeOperator can connect and push
}
```

- [ ] **Step 2: Run the tests and see them fail**

Run: `cargo test -p iroh-gateway-edge --test session`
Expected: compile errors.

- [ ] **Step 3: Implement `session.rs` and `Edge::spawn`**

One supervising task owns the `ListenerSet`, the `Accepted` receiver and the current session, and selects over: endpoint accept, session end, the grace timer, the next `Accepted`, and shutdown.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p iroh-gateway-edge`
Expected: all pass. Loop the session tests 10 times to check for flakiness.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(edge): tunnel session with key pinning, grace period and replacement"
```

---

### Task 6: Operator link

**Files:**
- Create: `operator/Cargo.toml`, `operator/src/lib.rs`, `operator/src/tunnel/mod.rs`, `operator/src/tunnel/link.rs`, `operator/src/tunnel/connector.rs`, `operator/tests/common/mod.rs`, `operator/tests/tunnel.rs`
- Modify: `Cargo.toml` (add member)

**Interfaces:**
- Consumes: everything in `proto`; `Edge`, `EdgeOptions`, `EdgeHandle` as a dev-dependency for tests (Task 5).
- Produces (crate `iroh_gateway_operator`, module `tunnel`):

```rust
pub trait Connector: Send + Sync + 'static {
    type Stream: LocalStream;
    /// Opens the local side for one visitor connection on `key`.
    fn connect(&self, key: ListenerKey, header: &StreamHeader)
        -> impl Future<Output = std::io::Result<Self::Stream>> + Send;
}
/// Dials a fixed TCP address per listener. Unknown key → io::ErrorKind::NotFound.
pub struct StaticConnector { .. }
impl StaticConnector { pub fn new(targets: HashMap<ListenerKey, SocketAddr>) -> Self; }
impl Connector for StaticConnector { type Stream = TcpStream; .. }

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EdgeState {
    pub connected: bool,
    pub edge_version: Option<String>,
    pub generation: u64,                      // last generation the edge acknowledged
    pub listeners: Vec<ListenerState>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerState { pub key: ListenerKey, pub bound: Result<(), String> }

pub struct LinkOptions {
    pub edge_id: iroh::EndpointId,
    pub address: Option<String>,              // "host:port"; resolved on every dial attempt
    pub relay: Relay,                         // the operator's relay mode
    pub dial_timeout: Duration,               // default 10 s
    pub connect_timeout: Duration,            // Connector::connect limit, default 5 s
    pub backoff_min: Duration,                // default 500 ms
    pub backoff_max: Duration,                // default 30 s
}
impl LinkOptions {
    /// Err when `address` is None and `relay` is Disabled: there would be no way to reach the edge.
    pub fn new(edge_id: iroh::EndpointId, address: Option<String>, relay: Relay) -> anyhow::Result<Self>;
}

pub struct EdgeLink;
impl EdgeLink {
    pub fn spawn<C: Connector>(
        endpoint: iroh::Endpoint,
        opts: LinkOptions,
        desired: tokio::sync::watch::Receiver<Vec<ListenerKey>>,
        connector: Arc<C>,
    ) -> LinkHandle;
}
pub struct LinkHandle { .. }
impl LinkHandle {
    pub fn state(&self) -> tokio::sync::watch::Receiver<EdgeState>;
    pub async fn shutdown(self);
}
/// The operator's endpoint: endpoint_builder(key, MAX_TUNNEL_STREAMS, relay, Role::Operator), bound on 0.0.0.0:0.
pub async fn bind_endpoint(key: iroh::SecretKey, relay: &Relay) -> anyhow::Result<iroh::Endpoint>;
```

Behaviour:

- The dial target is an `EndpointAddr` for `edge_id` carrying: the resolved `address` if there is one; the relay URL if `relay` is `Custom`; nothing more for `N0`, where the endpoint's lookup finds the edge.
- Dial loop, forever: build the dial target, connect with ALPN, run a session, wait, repeat. The wait doubles from `backoff_min` to `backoff_max` with ±20 % jitter and returns to `backoff_min` once a session has received a `Status`. A resolve failure counts as a failed attempt when there is no relay; with a relay the attempt goes ahead without the direct address.
- At session start the link opens the control stream and sends a `Config` for the current `desired`. It sends a new `Config` with the next generation on every change of `desired`. Generations start at 1 per link and never repeat across reconnects.
- Listener ids are assigned per `ListenerKey`, are stable for as long as the key stays in `desired`, and are never reused within one connection. A stream that names an id from an older `Config` whose key is still desired is therefore still routed correctly.
- `EdgeState` follows the last `Status`. On disconnect `connected` becomes `false` and `listeners` becomes empty.
- For each incoming bi stream: read the `StreamHeader` within 5 s, then
  - undecodable or late header → reset and stop with `RESET_BAD_HEADER`;
  - id not currently assigned → `RESET_UNKNOWN_LISTENER`;
  - `Connector::connect` fails or exceeds `connect_timeout` → `RESET_BACKEND_UNAVAILABLE`;
  - otherwise `splice`.
  None of these end the session.
- `shutdown` closes the connection with `CLOSE_SHUTDOWN` and stops redialing. It does not close the shared endpoint.

Test harness in `operator/tests/common/mod.rs`:

```rust
pub fn free_tcp_port() -> u16;
pub fn free_udp_port() -> u16;
pub async fn echo_server() -> SocketAddr;                       // echoes until EOF, then closes
pub struct Rig { pub edge: EdgeHandle, pub link: LinkHandle, pub desired: watch::Sender<Vec<ListenerKey>>,
                 pub operator_key: SecretKey, pub edge_key: SecretKey, pub endpoint: Endpoint }
/// Edge on 127.0.0.1 (grace 300 ms), link with backoff 50 ms..200 ms, StaticConnector from `targets`, Relay::Disabled.
pub async fn rig(targets: &[(u16, SocketAddr)]) -> Rig;
pub async fn wait_state(link: &LinkHandle, pred: impl Fn(&EdgeState) -> bool) -> EdgeState;  // 5 s limit, panics on timeout
pub fn tcp(port: u16) -> ListenerKey;
```

- [ ] **Step 1: Write the harness and the failing tests** in `operator/tests/tunnel.rs`

```rust
#[tokio::test] async fn tcp_echo_roundtrip() {
    // rig [(p, echo)]; wait_state(connected && listeners == [ListenerState{key: tcp(p), bound: Ok(())}])
    // connect 127.0.0.1:p, write b"hello", read b"hello"
}
#[tokio::test] async fn half_close_is_propagated() {
    // target: reads to EOF, then writes b"done" and closes
    // visitor writes b"abc", shutdown(), read_to_end == b"done"
}
#[tokio::test] async fn backend_abort_resets_visitor() {
    // target accepts, sets linger 0, drops → visitor read is Err(kind ConnectionReset)
}
#[tokio::test] async fn backend_down_resets_visitor() {
    // target is a free port with nothing listening → visitor read is Err or Ok(0) within 6 s;
    // the link stays connected and a second listener with a live echo still works
}
#[tokio::test] async fn desired_change_adds_and_removes() {
    // start [p]; open visitor v1 on p; desired → [q]
    // wait_state(generation == 2 && listeners == [tcp(q) Ok]); p is ConnectionRefused; q echoes;
    // v1 still echoes
}
#[tokio::test] async fn bind_error_reaches_state() {
    // hold p with a std listener → wait_state(listeners[0].bound.is_err())
}
#[tokio::test] async fn edge_restart_reconnects() {
    // edge on a fixed iroh port (free_udp_port) with a fixed key; echo works;
    // edge.shutdown() → wait_state(!connected && listeners.is_empty());
    // spawn the edge again, same key and port → wait_state(connected); echo works
}
#[tokio::test] async fn wrong_edge_key_never_connects() {
    // link edge_id is a random key but address points at the real edge
    // state stays !connected for 1 s; the real edge has no public port open
}
#[tokio::test] async fn address_is_resolved_as_a_name() {
    // address "localhost:<port>" with the edge on 127.0.0.1 → connects
}
#[tokio::test] async fn unresolvable_address_keeps_retrying() {
    // address "no-such-host.invalid:7842" → state stays !connected for 1 s, task has not panicked,
    // shutdown() returns within 1 s
}
#[tokio::test] async fn connects_through_relay_without_address() {
    // local relay; edge with Relay::Custom(url); link with address None, relay Custom(url)
    // wait_state(connected); echo works
}
#[tokio::test] async fn relay_covers_for_a_wrong_direct_address() {
    // same, but address Some("127.0.0.1:<free udp port with nothing on it>") → still connects and echoes
}
#[test] fn no_address_and_no_relay_is_rejected() {
    assert!(LinkOptions::new(id, None, Relay::Disabled).is_err());
    assert!(LinkOptions::new(id, None, Relay::N0).is_ok());
    assert!(LinkOptions::new(id, Some("192.0.2.1:7842".into()), Relay::Disabled).is_ok());
}
#[tokio::test] async fn unknown_listener_resets_stream_only() {
    // fake edge: a raw endpoint that accepts the link, reads the Config, replies Status,
    // opens a bi stream with listener_id 9999 → reading it yields Reset(RESET_UNKNOWN_LISTENER)
    // then opens one with the real id → echo works
}
#[tokio::test] async fn garbage_header_resets_stream_only() {
    // fake edge opens a bi stream and writes [0xff; 16] → Reset/Stopped with RESET_BAD_HEADER;
    // a following good stream works; the connection is still open
}
#[tokio::test] async fn stale_id_still_routes_after_config_change() {
    // fake edge: Config gen 1 has [p → id A]. desired → [p, q]; fake edge does NOT read gen 2
    // and opens a stream with id A → echo works
}
#[tokio::test] async fn shutdown_closes_with_shutdown_code() {
    // fake edge: link.shutdown() → conn.closed() gives application code CLOSE_SHUTDOWN
}
```

- [ ] **Step 2: Run the tests and see them fail**

Run: `cargo test -p iroh-gateway-operator --test tunnel`
Expected: compile errors.

- [ ] **Step 3: Implement `connector.rs` and `link.rs`**

- [ ] **Step 4: Run the tests and lints**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: all pass. Loop `--test tunnel` 10 times to check for flakiness.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(operator): edge link with redial, config push and stream dispatch"
```

---

### Task 7: Binaries and quickstart

**Files:**
- Create: `edge/src/main.rs`, `edge/tests/cli.rs`, `operator/src/main.rs`, `operator/src/staticcfg.rs`, `operator/tests/cli.rs`, `README.md`
- Modify: `edge/Cargo.toml`, `operator/Cargo.toml`

**Interfaces:**
- Consumes: `Edge::spawn` (Task 5); `EdgeLink`, `StaticConnector`, `bind_endpoint` (Task 6); `load_or_generate` (Task 2).
- Produces: two binaries.

`iroh-gateway-edge`:

| Command | Flags (env) | Default |
|---|---|---|
| `id` | `--key-file` (`IROH_GATEWAY_EDGE_KEY_FILE`) | `/var/lib/iroh-gateway-edge/edge.key` |
| `run` | `--key-file` as above | |
| | `--operator <EndpointId>` (`IROH_GATEWAY_EDGE_OPERATOR`) | required |
| | `--iroh-listen <addr>` (`IROH_GATEWAY_EDGE_IROH_LISTEN`) | `0.0.0.0:7842` |
| | `--public-bind <ip>` (`IROH_GATEWAY_EDGE_PUBLIC_BIND`) | `::` |
| | `--max-connections <n>` (`IROH_GATEWAY_EDGE_MAX_CONNECTIONS`), 1 to 65536 | `10000` |
| | `--tunnel-grace <duration>` (`IROH_GATEWAY_EDGE_TUNNEL_GRACE`), humantime | `5s` |
| | `--relay <disabled\|n0\|URL>` (`IROH_GATEWAY_EDGE_RELAY`) | `disabled` |

`--public-bind ::` also accepts IPv4 on a dual-stack host. On a host with IPv6 disabled the bind fails and shows up as a listener bind error; the README tells the user to set `0.0.0.0` there.

`iroh-gateway-operator`:

| Command | Flags | Default |
|---|---|---|
| `id` | `--key-file` | `operator.key` |
| `static` | `--config <file>` | required |

`id` prints the EndpointId and a newline to stdout, nothing else, and creates the key if it is missing. `run` and `static` log the own EndpointId at start, log every `EdgeState` change, and exit 0 on SIGINT or SIGTERM after a clean shutdown. Logging goes to stderr; level from `RUST_LOG`, default `info`.

Static config file:

```toml
key_file = "operator.key"
relay = "disabled"             # optional; "disabled" (default), "n0", or a relay URL

[[edge]]
endpoint_id = "<edge EndpointId>"
address = "203.0.113.7:7842"   # optional when relay is not "disabled"

[[edge.listener]]
protocol = "tcp"
port = 8080
target = "127.0.0.1:3000"
```

```rust
// staticcfg.rs
pub struct StaticConfig { pub key_file: PathBuf, pub relay: Relay, pub edges: Vec<StaticEdge> }
pub struct StaticEdge { pub endpoint_id: EndpointId, pub address: Option<String>, pub listeners: Vec<StaticListener> }
pub struct StaticListener { pub protocol: Protocol, pub port: u16, pub target: SocketAddr }
pub fn parse(text: &str) -> anyhow::Result<StaticConfig>;
```

`parse` rejects: unknown fields, an invalid `relay`, an edge without `address` while `relay` is `disabled`, an edge with no listeners, two edges with the same `endpoint_id`, and two listeners with the same protocol and port inside one edge.

- [ ] **Step 1: Write the failing tests**

`operator/src/staticcfg.rs`:

```rust
#[test] fn parses_the_documented_example() { /* the TOML above → 1 edge, 1 listener, port 8080, target 127.0.0.1:3000 */ }
#[test] fn rejects_unknown_fields() { /* add `colour = "red"` → Err */ }
#[test] fn rejects_duplicate_listener() { /* two tcp 8080 in one edge → Err mentioning "8080" */ }
#[test] fn rejects_duplicate_edge() { .. }
#[test] fn rejects_edge_without_listeners() { .. }
#[test] fn relay_defaults_to_disabled() { /* the documented example minus the relay line → Relay::Disabled */ }
#[test] fn address_is_optional_only_with_relay() {
    // no address + relay "disabled" → Err mentioning "address"
    // no address + relay "n0" → Ok, edges[0].address == None
    // relay "nonsense" → Err
}
```

`edge/tests/cli.rs` (binary via `env!("CARGO_BIN_EXE_iroh-gateway-edge")`):

```rust
#[test] fn id_prints_a_stable_endpoint_id() {
    // run `id --key-file <tmp>/e.key` twice → exit 0, same stdout, stdout parses as EndpointId
}
#[test] fn run_requires_operator() { /* `run --key-file ..` → non-zero exit, stderr mentions "--operator" */ }
#[test] fn run_rejects_malformed_key_file() { /* key file "abcd" → non-zero exit, file unchanged */ }
#[test] fn run_rejects_bad_relay() { /* `--relay nonsense` → non-zero exit, stderr mentions "relay" */ }
#[tokio::test] async fn run_serves_the_pinned_operator() {
    // start `run` on --iroh-listen 127.0.0.1:<free udp> --public-bind 127.0.0.1;
    // FakeOperator (from tests/common) connects, pushes [p], a visitor's bytes arrive on accept_stream;
    // SIGTERM → exit status 0 within 5 s
}
```

`operator/tests/cli.rs` (binary via `env!("CARGO_BIN_EXE_iroh-gateway-operator")`):

```rust
#[test] fn id_prints_a_stable_endpoint_id() { .. }
#[test] fn static_rejects_a_bad_config() { /* unknown field → non-zero exit, stderr names the field */ }
#[tokio::test] async fn static_forwards_to_target() {
    // key via `id`; in-process Edge pinned to that id; echo server; write the config file;
    // start `static --config ..`; retry connecting to the edge port for up to 5 s; echo b"hello";
    // SIGTERM → exit status 0 within 5 s
}
```

- [ ] **Step 2: Run the tests and see them fail**

Run: `cargo test --workspace`
Expected: compile errors in the new tests.

- [ ] **Step 3: Implement `staticcfg.rs` and both `main.rs` files**

Static mode: one shared endpoint from `bind_endpoint`, one `EdgeLink` and one `StaticConnector` per edge, `desired` set once.

- [ ] **Step 4: Write `README.md`**

Sections: what the project is (three sentences, link to the spec); status (tunnel core only, no Kubernetes yet); build (`direnv allow`, `cargo build`, `cargo test`); a quickstart with exact commands for one edge and one operator on one machine, using `python3 -m http.server 3000` as the target and `curl` through the edge port; the two flag tables above; the trust note from the spec ("the visitor address is only as trustworthy as the edge"); a "Relay mode" section that says it is off by default, when to turn it on, that both sides need the same value, and, in plain words, what a relay learns (the home IP, the edge's IP, size and timing of relayed traffic; with `n0` also lookups from home) and what it cannot do (read or alter traffic).

- [ ] **Step 5: Run everything**

Run: `cargo test --workspace && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: all pass, no output from the lints.

Then follow the README quickstart by hand, once, and confirm `curl` returns the directory listing through the edge port.

- [ ] **Step 6: Commit and clean**

```bash
git add -A
git commit -m "feat: edge and operator binaries with static mode, quickstart"
cargo clean
```
