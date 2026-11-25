# Packaging and Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Step 5 of the design: Prometheus metrics and health endpoints in both binaries, a Helm chart that replaces `deploy/`, a release workflow (images, chart, static edge binaries, systemd unit), nix packages with a NixOS module for the edge, and a README rebuilt around them.

**Architecture:** Each binary owns a `Metrics` value (its own `prometheus::Registry`) that is passed down through the existing options structs, and serves it with a small `axum` server that only exists when `--metrics-listen` is given. The operator's `/metrics` appends HAProxy's exporter output, read over a unix socket that a new frontend in `haproxy.cfg` binds. Everything else is packaging around the two binaries that already exist.

**Tech Stack:** Rust 1.100, `prometheus` 0.14, `axum` 0.8, HAProxy 3.2+, Helm 3, GitHub Actions, nix flakes (nixpkgs 26.05, rust-overlay).

**Spec:** `docs/superpowers/specs/2026-11-23-iroh-gateway-design.md` (sections "Packaging", "Observability", "Testing", "Build order").

## Global Constraints

- Every cargo command runs as `nix develop -c cargo …`. Before each commit: `nix develop -c cargo fmt --all --check`, `nix develop -c cargo clippy --workspace --all-targets -- -D warnings`, `nix develop -c cargo test --workspace`. Shell scripts pass `nix develop -c shellcheck scripts/*.sh`.
- The API-server suite, when a task touches `operator/src/cluster/`, `operator/src/controller.rs`, `operator/src/engine.rs` or `operator/tests/cluster.rs`: `KUBEBUILDER_ASSETS=$(nix develop -c scripts/envtest-assets) nix develop -c cargo test -p iroh-gateway-operator --test cluster -- --ignored`.
- Docker is not available on the development machine. Never try to run `kind`, `docker` or `scripts/e2e-kind.sh` locally; they run in CI.
- New Rust dependencies, in `[workspace.dependencies]`, and no others: `prometheus = { version = "0.14", default-features = false }`, `axum = { version = "0.8", default-features = false, features = ["http1", "tokio"] }`.
- Tests fetch HTTP with a plain `tokio::net::TcpStream` (or `UnixStream`): `GET <path> HTTP/1.0\r\n\r\n`, read to EOF. No HTTP client crate.
- Test ports come from `free_tcp_port()`, `free_udp_port()`, `free_tcp_and_udp_port()` in the test `common` modules. A test waits for an event (a watch, a retry loop bounded by `STEP`), never for a fixed sleep alone.
- Metric names start with `iroh_gateway_edge_` or `iroh_gateway_operator_`. Counters end in `_total`. Units are bytes and seconds. The only label names are `edge`, `direction`, `protocol`, `reason`, `result`, `state`, `version`. `direction` is `in` for traffic from visitors towards backends and `out` for the way back, on both binaries. No label value is a visitor address, a port, a hostname or a route name.
- A `Metrics::new()` owns its own `prometheus::Registry`. Nothing registers in the global default registry.
- The metrics listener exists only when `--metrics-listen` is given. An address that cannot be bound ends the process at start with a non-zero exit and an error that names the address.
- Datagram send rule, edge and operator: a packet's datagrams go to the tunnel only through `iroh_gateway_proto::transport::send_whole(conn: &Connection, datagrams: Vec<Bytes>) -> Result<(), SendPacketError>` (Task 1), with `pub enum SendPacketError { TunnelFull, Refused(SendDatagramError) }`. It returns `TunnelFull` without sending anything when `conn.datagram_send_buffer_space()` is less than the sum of the lengths, and otherwise sends each datagram on the path that never displaces a queued one (`send_datagram_wait` polled exactly once with `Waker::noop()`; `Pending` is `TunnelFull` and ends the packet). `conn.send_datagram` is not called for packets anywhere. `TunnelFull` is counted with reason `tunnel_full`, `Refused` with `send_error`. Reason: in noq 1.5.0 `datagram_send_buffer_space()` counts the 32-byte per-datagram overhead once, while the buffer charges it per queued datagram, so the space check alone still lets `send_datagram` discard older datagrams.
- Names fixed by the spec: chart `iroh-gateway` at `charts/iroh-gateway`; images `ghcr.io/fables-for-robots/iroh-gateway-operator` and `ghcr.io/fables-for-robots/iroh-gateway-edge`; chart registry `oci://ghcr.io/fables-for-robots/charts`; NixOS module `nixosModules.edge`; packages `packages.edge`, `packages.operator`.
- Systemd hardening, identical in `dist/iroh-gateway-edge.service` and the NixOS module: `DynamicUser=yes`, `StateDirectory=iroh-gateway-edge`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`, `ProtectHostname=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX`, `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`, `LimitNOFILE=65536`, `Restart=always`, `RestartSec=2`.
- One commit per task (more are fine), message style of the repository (`feat(edge): …`, `test: …`, `docs: …`). Never push. Leave no build output or binaries outside `target/`.
- Documentation states what is true of the code as built, in plain sentences, and says of every walkthrough part whether a test runs it.

## Metric catalogue

Edge (`iroh_gateway_edge_` + name):

| name | type | labels | counts |
|---|---|---|---|
| `build_info` | gauge | `version` | always 1 |
| `session_up` | gauge | | 1 from a session's first applied config until that session ends |
| `sessions_total` | counter | | sessions installed |
| `listeners` | gauge | `protocol` (`tcp`, `udp`) | public ports open now |
| `bind_failures_total` | counter | `protocol` | binds the OS refused |
| `connections_open` | gauge | | TCP visitors holding a slot of `--max-connections` |
| `connections_total` | counter | | TCP visitors accepted into a slot |
| `connections_refused_total` | counter | `reason` (`cap`, `no_session`, `queue_full`) | TCP visitors dropped before a tunnel stream; `no_session` covers no session, not configured, and listener closed |
| `tcp_bytes_total` | counter | `direction` | bytes written to the tunnel stream (`in`) and to the visitor (`out`), counted as they are written |
| `udp_flows` | gauge | | flows the hub holds |
| `udp_flows_total` | counter | | flows created |
| `udp_flows_evicted_total` | counter | | flows pushed out at the cap |
| `udp_packets_total` | counter | `direction` | packets handed to the tunnel in full (`in`); packets sent to a visitor (`out`) |
| `udp_bytes_total` | counter | `direction` | payload bytes of those packets |
| `udp_fragmented_packets_total` | counter | `direction` | `in`: of those, split into more than one datagram; `out`: packets reassembled from more than one |
| `udp_dropped_total` | counter | `reason` (`no_session`, `rate_limit`, `send_error`, `tunnel_full`, `unknown_flow`, `bad_datagram`) | dropped packets or datagrams |

Operator (`iroh_gateway_operator_` + name); every `tunnel_*` metric also has the label `edge`, the edge's EndpointId as 64 hex characters:

| name | type | labels | counts |
|---|---|---|---|
| `build_info` | gauge | `version` | always 1 |
| `tunnel_up` | gauge | `edge` | `EdgeState.connected` |
| `tunnel_sessions_total` | counter | `edge` | dials that connected |
| `tunnel_dial_failures_total` | counter | `edge` | dials that failed |
| `tunnel_listeners` | gauge | `edge`, `state` (`bound`, `failed`) | from the edge's last status; both 0 while not connected |
| `tunnel_streams_open` | gauge | `edge` | visitor streams being served |
| `tunnel_streams_total` | counter | `edge` | visitor streams accepted |
| `tunnel_streams_refused_total` | counter | `edge`, `reason` (`bad_header`, `unknown_listener`, `backend_unavailable`) | streams reset before forwarding |
| `tunnel_tcp_bytes_total` | counter | `edge`, `direction` | bytes written to the backend (`in`) and to the tunnel stream (`out`), as written |
| `tunnel_udp_flows` | gauge | `edge` | flows the forwarder holds; 0 after a session |
| `tunnel_udp_flows_total` | counter | `edge` | flows created |
| `tunnel_udp_flows_evicted_total` | counter | `edge` | flows pushed out at the cap |
| `tunnel_udp_packets_total` | counter | `edge`, `direction` | packets sent to a backend (`in`); replies handed to the tunnel in full (`out`) |
| `tunnel_udp_bytes_total` | counter | `edge`, `direction` | payload bytes of those |
| `tunnel_udp_fragmented_packets_total` | counter | `edge`, `direction` | `in`: reassembled from more than one datagram; `out`: split into more than one |
| `tunnel_udp_dropped_total` | counter | `edge`, `reason` (`bad_datagram`, `retired_listener`, `unknown_listener`, `not_udp`, `wrong_listener`, `no_target`, `socket_error`, `send_error`, `tunnel_full`) | dropped packets or datagrams |
| `haproxy_reloads_total` | counter | `result` (`ok`, `refused`, `failed`) | `Applied::Reloaded`; `ApplyError::Invalid`; `ApplyError::ReloadFailed` or `Io`. `Applied::Unchanged` counts nothing |
| `haproxy_config_ok` | gauge | | 1 when the last `Engine::apply` was taken, else 0 |
| `reconciles_total` | counter | | passes of the controller loop |
| `reconcile_duration_seconds` | histogram | | a pass, from taking the snapshot to the end of its status write |
| `status_write_failures_total` | counter | | status writes that returned false |
| `haproxy_exporter_up` | gauge | | written by the HTTP handler (Task 4), only in `run` mode |

## Review Focus

1. `--metrics-listen` on an address already in use: both binaries exit non-zero at start and name the address (Tasks 1 and 3, CLI tests).
2. A scrape while HAProxy's exporter socket is missing, or accepts and never answers: `/metrics` still answers within 3 s with the operator's own metrics and `haproxy_exporter_up 0` (Task 4).
3. A visitor whose tunnel is lost mid-transfer: the bytes it moved are in `tcp_bytes_total`, because bytes are counted as written, not at the end (Tasks 1 and 2).
4. An edge removed from the cluster: no series with its `edge` label remains (Task 2).
5. A chart installed under a release name that is not `iroh-gateway`, and with the release namespace listed in `gatewayNamespaces`: Service selector and pod labels agree, and no object is rendered twice (Task 5).
6. A release tag that does not equal the crates' version: the release workflow fails before it publishes anything (Task 7).

---

### Task 1: Edge metrics, the edge's endpoint, and the full-tunnel rule on the edge

**Files:**
- Modify: `Cargo.toml` (workspace deps), `proto/src/splice.rs`, `proto/src/transport.rs` (doc of `DATAGRAM_SEND_BUFFER`)
- Create: `edge/src/metrics.rs`, `edge/tests/metrics.rs`
- Modify: `edge/Cargo.toml`, `edge/src/lib.rs`, `edge/src/main.rs`, `edge/src/session.rs`, `edge/src/listeners.rs`, `edge/src/udp.rs`, `edge/tests/common/mod.rs`, `edge/tests/cli.rs`, `operator/tests/common/mod.rs` (its `edge_options` literal)

**Interfaces:**
- Produces, in `iroh_gateway_proto::splice`:
  ```rust
  /// Told of every chunk a splice writes, as it is written.
  pub trait SpliceMeter: Send + Sync + 'static {
      /// Bytes written to the tunnel stream.
      fn to_remote(&self, bytes: u64);
      /// Bytes written to the local stream.
      fn to_local(&self, bytes: u64);
  }
  pub struct SpliceOptions { /* existing fields */ pub meter: Option<Arc<dyn SpliceMeter>> }
  ```
  `SpliceOptions` stays `Clone` and `Debug` (no longer `Copy`); `Default` has `meter: None`. `SpliceStats` and `splice` are unchanged.
- Produces, in `iroh_gateway_edge`:
  ```rust
  pub mod metrics;
  #[derive(Clone)] pub struct Metrics { /* private */ }
  impl Metrics { pub fn new() -> Self; /* Prometheus text format, version 0.0.4 */ pub fn render(&self) -> String; }
  impl Default for Metrics
  /// Serves `GET /metrics` (200, `text/plain; version=0.0.4`); every other path is 404.
  pub async fn serve(listener: tokio::net::TcpListener, metrics: Metrics) -> std::io::Result<()>;
  pub struct EdgeOptions { /* existing fields */ pub metrics: Metrics }
  ```
- CLI: `--metrics-listen <ADDR>`, env `IROH_GATEWAY_EDGE_METRICS_LISTEN`, type `Option<SocketAddr>`, no default.

- [ ] **Step 1: Write the failing tests** in `edge/tests/metrics.rs` (helpers: a `metric(text: &str, series: &str) -> f64` that finds the line starting with `series` followed by a space and parses the value, panicking with the whole text if absent; `start(customize)` like `edge/tests/udp.rs`, keeping a clone of `opts.metrics`):
  - `a_fresh_edge_reports_its_build_and_no_session`: `build_info{version="<CARGO_PKG_VERSION>"} == 1`, `session_up == 0`, `sessions_total == 0`.
  - `a_configured_session_shows_up_and_goes_away`: after the first config with one TCP and one UDP port, `session_up == 1`, `sessions_total == 1`, `listeners{protocol="tcp"} == 1`, `listeners{protocol="udp"} == 1`; after the fake operator closes and the grace passes, `session_up == 0` and both `listeners` are 0.
  - `a_bind_error_is_counted`: a config naming a TCP port the test holds; `bind_failures_total{protocol="tcp"} == 1`.
  - `tcp_bytes_are_counted_as_they_move`: a visitor sends 5,000 bytes and the fake operator answers 3,000 on the stream; while the stream is still open, wait until `tcp_bytes_total{direction="in"} == 5000` and `{direction="out"} == 3000`; `connections_open == 1`, `connections_total == 1`. After the visitor closes, `connections_open == 0`.
  - `bytes_of_a_visitor_cut_off_by_tunnel_loss_stay_counted`: 5,000 bytes in, then the fake operator's connection is closed without finishing the stream; `tcp_bytes_total{direction="in"} == 5000` and `connections_open == 0`.
  - `a_visitor_past_the_cap_is_refused_and_counted`: `max_connections = 1`, a second visitor while the first is open; wait for `connections_refused_total{reason="cap"} == 1`.
  - `a_visitor_without_a_session_is_refused_and_counted`: a visitor after the session ended but inside the grace; `connections_refused_total{reason="no_session"} == 1`.
  - `udp_packets_flows_and_fragments_are_counted`: one 100-byte packet and one 9,000-byte packet from one visitor, each answered by the fake operator with a packet of the same size; `udp_flows == 1`, `udp_flows_total == 1`, `udp_packets_total{direction="in"} == 2`, `udp_bytes_total{direction="in"} == 9100`, `udp_fragmented_packets_total{direction="in"} == 1`, and the same three values for `direction="out"`. The visitor resends until answered, so assert `>=` on `in` and exact values on `out` only where the test controls the count; say which in a comment.
  - `the_flow_cap_counts_an_eviction`: `max_udp_flows = 2`, three visitors; `udp_flows == 2`, `udp_flows_total == 3`, `udp_flows_evicted_total == 1`.
  - `each_drop_reason_is_counted`: `rate_limit` (limit 1, two packets), `unknown_flow` (a datagram for a flow id never issued), `bad_datagram` (five bytes), `no_session` (a packet inside the grace): each `udp_dropped_total{reason=…} >= 1`.
  - `a_full_tunnel_drops_whole_packets_and_counts_them`: on the default current-thread test runtime, with a fake operator that does not read datagrams, one visitor sends 400 packets of 1,000 bytes in a tight loop (`try_send` until the socket refuses, no await between sends beyond what `send` needs); wait until `udp_packets_total{direction="in"} + udp_dropped_total{reason="tunnel_full"}` stops changing; then `tunnel_full > 0` and `udp_dropped_total{reason="send_error"} == 0`.
  - In `edge/tests/cli.rs`: `metrics_are_served_when_asked_for` (run with `--metrics-listen 127.0.0.1:<free_tcp_port()>`; `GET /metrics` answers `HTTP/1.0 200` or `HTTP/1.1 200` with a body containing `iroh_gateway_edge_session_up 0`; `GET /other` answers 404), `no_metrics_listener_without_the_flag` (run without the flag until "serving" is logged, then stop it: stderr has no line containing `metrics on`), `metrics_listen_on_a_taken_address_fails_at_start` (the test holds a `TcpListener`; exit status non-zero within 10 s, stderr contains the address).
  - In `proto/src/splice.rs` tests: `the_meter_sees_every_byte_in_both_directions` (a recording `SpliceMeter`; totals equal `SpliceStats.to_remote` and `.to_local`), `the_meter_has_the_bytes_of_a_dropped_splice` (drop the splice future after 10,000 bytes have moved; the meter's `to_remote` total is 10,000).

- [ ] **Step 2: Run them and see them fail**

  Run: `nix develop -c cargo test -p iroh-gateway-proto splice && nix develop -c cargo test -p iroh-gateway-edge --test metrics --test cli`
  Expected: compile errors (`SpliceMeter`, `metrics` not found).

- [ ] **Step 3: `SpliceMeter` in `proto/src/splice.rs`.** Call the meter at the two places the byte counts are added today (`*copied += …` in `local_to_remote` and `remote_to_local`).

- [ ] **Step 4: `edge/src/metrics.rs`.** `Metrics` holds the registry and every collector of the edge table above, registered once in `new()`; `build_info` is set there. `render()` encodes with `prometheus::TextEncoder`. `serve` is an `axum::Router` with the one route.

- [ ] **Step 5: Wire the edge.** `EdgeOptions.metrics` is handed to the supervisor, `ListenerSet::new`, `UdpHub::new` and each `Session`. Event sites (see the code): `Supervisor::install` and `apply` (session), `ListenerSet::apply`/`close`/`close_all` (ports, bind failures), `accept_loop` and `Supervisor::visitor` (connections, refusals), `session::forward` (a `SpliceMeter` over the two `tcp_bytes_total` children, through `splice_with`), `UdpHub::forward`, `Flows::outgoing`, `Shared::reply` and `udp_loop` (UDP). `connections_open` must equal the slots in use at every moment a test can observe, including when a session is dropped with visitors still running. The existing `Drops`/`Counter` keep their throttled log lines; their counts become the `udp_dropped_total` children, and `udp_loop`'s local `send_failures` becomes `send_error`.

- [ ] **Step 6: The full-tunnel rule.** Add `send_whole` and `SendPacketError` to `proto/src/transport.rs` as Global Constraints give them, and send through it in `UdpHub::forward` after `split`; `tunnel_full` is a new `Drops` entry with the log text "tunnel full". Correct the doc comment of `Drops::send_error` and of `DATAGRAM_SEND_BUFFER` in `proto/src/transport.rs`, which say the oldest queued datagram is discarded silently.

- [ ] **Step 7: `--metrics-listen` in `edge/src/main.rs`.** Bind before `Edge::spawn`, with the error context `binding the metrics listener on {addr}`; log `metrics on http://{addr}/metrics` at info; spawn `metrics::serve`; abort the task at shutdown.

- [ ] **Step 8: Run everything**

  Run: the three commands of Global Constraints.
  Expected: all pass, no warnings.

- [ ] **Step 9: Commit**

  ```bash
  git add -A && git commit -m "feat(edge): Prometheus metrics, --metrics-listen, and whole-packet drops on a full tunnel"
  ```

### Task 2: Operator tunnel metrics and the full-tunnel rule on the operator

**Files:**
- Create: `operator/src/metrics.rs`, `operator/tests/metrics.rs`
- Modify: `operator/Cargo.toml`, `operator/src/lib.rs`, `operator/src/tunnel/link.rs`, `operator/src/tunnel/udp.rs`, `operator/tests/common/mod.rs`

**Interfaces:**
- Consumes: `iroh_gateway_proto::splice::{SpliceMeter, SpliceOptions, splice_with}` from Task 1.
- Produces, in `iroh_gateway_operator`:
  ```rust
  pub mod metrics;
  #[derive(Clone)] pub struct Metrics { /* private */ }
  impl Metrics { pub fn new() -> Self; pub fn render(&self) -> String; }
  impl Default for Metrics
  pub struct LinkOptions { /* existing fields */ pub metrics: Metrics }   // LinkOptions::new sets Metrics::new()
  ```
  `Metrics::new()` registers every collector of the operator table except `haproxy_exporter_up`, including the engine and controller ones that Task 3 uses, and sets `build_info`. Crate-private accessors for the tunnel live next to it (for example `pub(crate) fn link(&self, edge: EndpointId) -> LinkMetrics`); Task 3 adds its own accessors.

- [ ] **Step 1: Write the failing tests** in `operator/tests/metrics.rs` (same `metric` helper as Task 1, in `operator/tests/common/mod.rs`; rigs from `common`: `rig_with` for a real in-process edge, `udp.rs`-style `setup` for a hand-driven edge; each test passes its own `Metrics` through `LinkOptions.metrics` and labels with the edge's id, `e`):
  - `a_link_reports_its_edge_up_and_its_listeners`: after the first status, `tunnel_up{edge=e} == 1`, `tunnel_sessions_total{edge=e} == 1`, `tunnel_listeners{edge=e,state="bound"}` equals the listener count, `state="failed"` is 0. With one port the test holds on the edge side: `state="failed"} == 1`.
  - `a_lost_edge_reads_down`: the edge is shut down; `tunnel_up == 0` and both `tunnel_listeners` are 0; after the link has tried again, `tunnel_dial_failures_total >= 1`.
  - `streams_and_bytes_are_counted_as_they_move`: a visitor sends 5,000 bytes to an echo backend and reads them back; while it is still connected, wait for `tunnel_tcp_bytes_total{edge=e,direction="in"} == 5000` and `direction="out"} == 5000`, `tunnel_streams_open == 1`, `tunnel_streams_total == 1`; after it closes, `tunnel_streams_open == 0`.
  - `bytes_of_a_stream_cut_off_by_tunnel_loss_stay_counted`: 5,000 bytes to a backend that does not answer, then the edge is shut down; `direction="in"} == 5000`, `tunnel_streams_open == 0`.
  - `a_refused_stream_is_counted_by_reason`: a listener whose target nothing listens on gives `tunnel_streams_refused_total{edge=e,reason="backend_unavailable"} == 1`; a hand-driven edge opening a stream with a listener id never issued gives `reason="unknown_listener"} == 1`; one with a garbage header gives `reason="bad_header"} == 1`.
  - `udp_packets_flows_and_fragments_are_counted`: one 100-byte and one 9,000-byte packet on one flow, each echoed; `tunnel_udp_flows == 1`, `tunnel_udp_flows_total == 1`, `tunnel_udp_packets_total{direction="in"} >= 2`, `tunnel_udp_fragmented_packets_total{direction="in"} >= 1`, `tunnel_udp_packets_total{direction="out"} >= 2`, `tunnel_udp_fragmented_packets_total{direction="out"} >= 1`, and `tunnel_udp_bytes_total` at least 9,100 each way.
  - `the_flow_cap_counts_an_eviction_and_idle_flows_leave_the_gauge`: `udp_max_flows = 2`, `udp_flow_idle = 300 ms`, three flows; `tunnel_udp_flows_evicted_total == 1`, `tunnel_udp_flows == 2`; then wait for `tunnel_udp_flows == 0`.
  - `each_udp_drop_reason_is_counted`: `bad_datagram`, `unknown_listener`, `not_udp`, `no_target` (an empty target list), each `>= 1`.
  - `a_full_tunnel_drops_whole_replies_and_counts_them`: a hand-driven edge that does not read datagrams; the backend sends 400 replies of 1,000 bytes to one flow as fast as it can; wait until `tunnel_udp_packets_total{direction="out"} + tunnel_udp_dropped_total{reason="tunnel_full"}` stops changing; `tunnel_full > 0`, `send_error == 0`.
  - `a_stopped_link_takes_its_series_with_it`: two links with ids `e1` and `e2` on one `Metrics`; after `e1`'s `LinkHandle::shutdown()`, `render()` contains no line with `edge="<e1>"` and still has `tunnel_up{edge="<e2>"} 1`.

- [ ] **Step 2: Run them and see them fail**

  Run: `nix develop -c cargo test -p iroh-gateway-operator --test metrics`
  Expected: compile error (`metrics` not found).

- [ ] **Step 3: `operator/src/metrics.rs`** as in Interfaces.

- [ ] **Step 4: Wire the link** (`link.rs`): `Link::run`/`dial`/`session`/`on_status` for `tunnel_up`, sessions, dial failures and `tunnel_listeners`; `drive` and `serve_stream` for streams, refusals (`refuse` gets the reason) and bytes (a `SpliceMeter`: `to_local` is `in`, `to_remote` is `out`). When the link task ends, every series labelled with its edge is removed.

- [ ] **Step 5: Wire the UDP forwarder** (`udp.rs`): flows created, evicted (the value `IdleMap::insert` returns when the cap pushed one out, not a same-id replacement), the gauge after every change to the flow map and 0 when the forwarder ends; packets, bytes and fragmented packets in `on_datagram`/`send` and in `replies`; the existing `Drops` counts become the `tunnel_udp_dropped_total` children, keeping their log lines. In `replies`, send through `send_whole` (Task 1), counting `TunnelFull` under the new reason `tunnel_full`, and correct the `Drops::send_error` doc comment.

- [ ] **Step 6: Run everything** (Global Constraints, plus the UDP and tunnel tests five times: `for i in 1 2 3 4 5; do nix develop -c cargo test -p iroh-gateway-operator --test udp --test tunnel --test metrics || break; done`).

- [ ] **Step 7: Commit**

  ```bash
  git add -A && git commit -m "feat(operator): tunnel metrics per edge, and whole-packet drops on a full tunnel"
  ```

### Task 3: Operator engine and controller metrics, `/healthz`, `/readyz`, `--metrics-listen`

**Files:**
- Create: `operator/src/http.rs`, `operator/tests/http_endpoint.rs`
- Modify: `operator/Cargo.toml` (`axum`, already a workspace dependency since Task 1), `operator/src/lib.rs`, `operator/src/metrics.rs`, `operator/src/engine.rs`, `operator/src/controller.rs`, `operator/src/main.rs`, `operator/tests/engine.rs`, `operator/tests/cli.rs`, `operator/tests/cluster.rs`

**Interfaces:**
- Consumes: `Metrics` from Task 2.
- Produces:
  ```rust
  // operator/src/http.rs
  #[derive(Clone)]
  pub struct HttpState { pub metrics: Metrics, pub ready: Arc<AtomicBool> }
  /// `/healthz`: 200 `ok`. `/readyz`: 200 `ready`, or 503 `not ready`. `/metrics`: 200, `text/plain; version=0.0.4`. Anything else: 404.
  pub async fn serve(listener: tokio::net::TcpListener, state: HttpState) -> std::io::Result<()>;
  // operator/src/engine.rs
  pub struct EngineOptions { /* existing */ pub metrics: Metrics }          // EngineOptions::new sets Metrics::new()
  // operator/src/controller.rs
  pub struct ControllerOptions { /* existing */ pub metrics: Metrics, pub ready: Arc<AtomicBool> }  // ::new sets Metrics::new() and false
  ```
- CLI: `--metrics-listen <ADDR>`, env `IROH_GATEWAY_METRICS_LISTEN`, `Option<SocketAddr>`, on `run` and on `static`.

- [ ] **Step 1: Write the failing tests**
  - `operator/tests/http_endpoint.rs`: `healthz_is_ok`, `readyz_follows_the_flag` (503 with body `not ready`, then after `ready.store(true)` 200 with `ready`), `metrics_are_the_registry_as_text` (content type starts with `text/plain`, body contains `iroh_gateway_operator_build_info{version="`), `another_path_is_not_found`.
  - `operator/tests/engine.rs`: `reloads_are_counted_by_result` (an accepted change: `haproxy_reloads_total{result="ok"} == 1`, `haproxy_config_ok == 1`; the same plan again: still 1; `INVALID_CFG`: `result="refused"} == 1`, `haproxy_config_ok == 0`; a reload that fails through the existing failing-reload helper: `result="failed"} >= 1`), `links_of_the_engine_report_into_its_metrics` (`tunnel_up{edge=…} == 1` in `opts.metrics` after an edge connects, and no such line after a plan without that edge).
  - `operator/src/controller.rs` unit tests (with `Rig`): `a_pass_is_counted_and_timed` (`reconciles_total == 1`, `reconcile_duration_seconds_count == 1`), `a_failed_status_write_is_counted` (`status_write_failures_total == 1`), `ready_after_the_first_pass_even_when_haproxy_refuses` (not ready before the source is synced; ready after the first pass with the applier's facts reporting a HAProxy error).
  - `operator/tests/cli.rs`: `static_serves_metrics_and_is_ready` (`static --config … --metrics-listen 127.0.0.1:<port>`; `/readyz` is 200, `/metrics` contains `iroh_gateway_operator_tunnel_up{edge="`), `run_answers_healthz_before_it_has_a_cluster` (`run` pointed at a kube API address that accepts and never answers, or the existing no-cluster rig if it keeps the process alive long enough: `/healthz` 200 and `/readyz` 503 while it starts; if no existing rig keeps `run` alive without a cluster, put this assertion in `operator/tests/cluster.rs` instead and say so in the report), `metrics_listen_on_a_taken_address_fails_at_start` (both subcommands).
  - `operator/tests/cluster.rs` (ignored suite): `the_operator_becomes_ready_after_its_first_pass` using `Operator::start` with the `ready` flag taken from `ControllerOptions`.

- [ ] **Step 2: Run them and see them fail**

  Run: `nix develop -c cargo test -p iroh-gateway-operator --test http_endpoint --test engine --test cli controller`
  Expected: compile errors.

- [ ] **Step 3: `operator/src/http.rs`** as in Interfaces.

- [ ] **Step 4: Engine.** `Engine::start` gives every `LinkOptions` it builds `opts.metrics.clone()`. `Engine::apply` counts `haproxy_reloads_total` from the `Result<Applied, ApplyError>` it already matches on and sets `haproxy_config_ok`; after `Engine::start`'s first configuration is running, `haproxy_config_ok` is 1.

- [ ] **Step 5: Controller.** In `run_loop`, time each pass from `source.snapshot()` to the end of the status write into `reconcile_duration_seconds`, count it, count a false status write, and store `true` in `opts.ready` when the first pass's `applier.apply` has returned.

- [ ] **Step 6: `main.rs`.** One `Metrics` per process. `run`: bind the listener right after `shutdown_signals()`, before the Kubernetes client, with the error context `binding the metrics listener on {addr}`; give the same `Metrics` to `EngineOptions` and `ControllerOptions`, and the controller's `ready` to `HttpState`. `static`: the same `Metrics` in every `LinkOptions`; `ready` is stored true once every link is spawned. The server task is aborted at shutdown.

- [ ] **Step 7: Run everything** (Global Constraints, including the API-server suite).

- [ ] **Step 8: Commit**

  ```bash
  git add -A && git commit -m "feat(operator): reload and reconcile metrics, /healthz, /readyz and --metrics-listen"
  ```

### Task 4: HAProxy's exporter through the operator's `/metrics`

**Files:**
- Modify: `operator/src/haproxy/mod.rs`, `operator/src/haproxy/render.rs`, `operator/src/haproxy/supervisor.rs`, `operator/src/haproxy/testdata/*.cfg` (all five), `operator/src/http.rs`, `operator/src/main.rs`, `operator/tests/haproxy.rs`, `operator/tests/http_endpoint.rs`

**Interfaces:**
- Consumes: `HttpState`, `serve` from Task 3.
- Produces:
  ```rust
  // operator/src/haproxy/mod.rs
  /// The unix socket, in the runtime directory, on which HAProxy serves its Prometheus exporter.
  pub const METRICS_SOCKET: &str = "metrics.sock";
  // operator/src/http.rs
  pub struct HttpState { pub metrics: Metrics, pub ready: Arc<AtomicBool>, pub haproxy_exporter: Option<PathBuf> }
  ```
- The frontend `render` emits, right after `frontend idle`, exactly:
  ```
  frontend metrics
      mode http
      bind unix@{dir}/metrics.sock mode 600
      http-request use-service prometheus-exporter if { path /metrics }
      no log
  ```

- [ ] **Step 1: Write the failing tests**
  - `render.rs`: the five golden files gain the frontend (update them by hand; the fingerprint tests that hash from `frontend fe_<id>` to the end must still pass unchanged, which shows the new frontend sits before every listener's section).
  - `operator/tests/haproxy.rs`: `the_exporter_answers_on_its_socket` (start the supervisor with a rendered empty configuration; `GET /metrics HTTP/1.0` on `<dir>/metrics.sock` answers 200 and the body contains `haproxy_process_start_time_seconds`), `the_exporter_socket_survives_a_reload_and_goes_at_shutdown`.
  - `operator/tests/http_endpoint.rs`: `metrics_append_haproxys` (a real HAProxy; the body contains `iroh_gateway_operator_build_info`, `haproxy_process_start_time_seconds` and the line `iroh_gateway_operator_haproxy_exporter_up 1`, and the HAProxy text contains no HTTP header line), `a_missing_exporter_socket_leaves_the_operators_metrics` (path to a socket that does not exist: 200 within 3 s, `haproxy_exporter_up 0`, no `haproxy_process_`), `an_exporter_that_never_answers_is_given_up_on` (a `UnixListener` the test owns that accepts and stays silent: 200 within 3 s, `haproxy_exporter_up 0`), `an_exporter_answering_an_error_is_left_out` (the test's listener answers `HTTP/1.0 503 …`: `haproxy_exporter_up 0` and none of its body), `without_an_exporter_the_gauge_is_absent` (`haproxy_exporter: None`: no line containing `haproxy_exporter_up`).

- [ ] **Step 2: Run them and see them fail**

  Run: `nix develop -c cargo test -p iroh-gateway-operator --test haproxy --test http_endpoint && nix develop -c cargo test -p iroh-gateway-operator render`
  Expected: failures (golden mismatch, missing field).

- [ ] **Step 3: Render and supervisor.** Emit the frontend; `remove_sockets` also removes `metrics.sock`.

- [ ] **Step 4: The handler.** With `haproxy_exporter: Some(path)`: connect a `UnixStream`, send `GET /metrics HTTP/1.0\r\n\r\n`, read to EOF, all within 2 s and at most 16 MiB; accept only a `200` status line and a body that is not chunked; the answer is the operator's own text, then `# HELP`/`# TYPE` and the line `iroh_gateway_operator_haproxy_exporter_up <0|1>`, then HAProxy's body when it was accepted. `main.rs` sets `haproxy_exporter: Some(haproxy_dir.join(METRICS_SOCKET))` in `run` and `None` in `static`.

- [ ] **Step 5: Run everything** (Global Constraints).

- [ ] **Step 6: Commit**

  ```bash
  git add -A && git commit -m "feat(operator): HAProxy's Prometheus exporter in the operator's /metrics"
  ```

### Task 5: The Helm chart, and the kind test on it

**Files:**
- Create: `charts/iroh-gateway/{Chart.yaml,values.yaml,.helmignore,README.md}`, `charts/iroh-gateway/crds/edges.yaml` (moved from `deploy/crd.yaml`, byte for byte), `charts/iroh-gateway/templates/{_helpers.tpl,NOTES.txt,serviceaccount.yaml,rbac.yaml,deployment.yaml,gatewayclass.yaml,service.yaml,servicemonitor.yaml,networkpolicy.yaml}`, `scripts/chart-test.sh`
- Delete: `deploy/` (all five files)
- Modify: `scripts/e2e-kind.sh`, `.github/workflows/ci.yml`, `flake.nix`, `README.md` (only the sentences that name `deploy/`, the manifests, "no health endpoint, no metrics, no NetworkPolicy", and the Install section's commands)

**Interfaces:**
- Consumes: `--metrics-listen` and the three paths from Tasks 3 and 4; the edge's `--metrics-listen` from Task 1.
- Produces: the chart, with these values and defaults (the sibling chart `../secret-bunker-iroh/charts/secret-bunker-operator` is the model for layout, helpers and the placeholder versions `0.0.0-dev`):
  ```yaml
  image: { repository: ghcr.io/fables-for-robots/iroh-gateway-operator, tag: "", pullPolicy: IfNotPresent }   # "" → appVersion
  imagePullSecrets: []
  nameOverride: ""
  fullnameOverride: ""
  controllerName: gateway.fables-for-robots.ch/iroh-gateway
  gatewayClass: { create: true, name: iroh-gateway }
  gatewayNamespaces: []          # [] → the release namespace only
  relay: disabled                # disabled | n0 | https://…
  identity: { secretName: iroh-gateway-identity }
  metrics: { port: 8080, service: { enabled: true }, serviceMonitor: { enabled: false } }
  networkPolicy: { enabled: false, metricsFrom: [] }   # metricsFrom: NetworkPolicyPeers; [] → any source
  resources: { requests: { cpu: 50m, memory: 128Mi }, limits: { memory: 1Gi } }
  serviceAccount: { create: true, name: "", annotations: {} }
  rbac: { create: true }
  podAnnotations: {}
  podLabels: {}
  nodeSelector: {}
  tolerations: []
  affinity: {}
  priorityClassName: ""
  ```
- What the templates must render, carried over from `deploy/` unless said otherwise: one replica, `Recreate`, the pod and container security context, the two in-memory volumes, `terminationGracePeriodSeconds: 60`, `POD_NAMESPACE` from the field ref; arguments or env for `--gateway-namespaces` (when the list is not empty), `--controller-name`, `--identity-secret`, `--relay`, `--metrics-listen=0.0.0.0:<metrics.port>`; a container port named `http`; `livenessProbe` on `/healthz` and `readinessProbe` on `/readyz`. RBAC: the ClusterRole and binding of `deploy/rbac.yaml`; in the release namespace a Role with `get` on the identity Secret by name and `create` on Secrets; in every gateway namespace (the release namespace when the list is empty) a Role with `list` and `watch` on Secrets; each with its binding. The NetworkPolicy selects the operator pod, has `policyTypes: [Ingress]` and one ingress rule for the metrics port from `metricsFrom` (no `from` when empty). The ServiceMonitor fails the render unless `metrics.service.enabled`. `NOTES.txt` says how to read the operator's id and points at the README's enrolment section.

- [ ] **Step 1: Write the failing chart test** `scripts/chart-test.sh` (bash, `set -euo pipefail`, uses `helm` and `yq`; prints one line per check and exits non-zero on the first failure). Checks:
  - `helm lint charts/iroh-gateway` passes.
  - Defaults, release `iroh-gateway` in namespace `iroh-gateway`: exactly one each of Deployment, ServiceAccount, ClusterRole, ClusterRoleBinding, GatewayClass, Service; one Role and one RoleBinding (identity and Secret reads in one Role, or two Roles with different names; no two rendered objects share kind, namespace and name); no ServiceMonitor, no NetworkPolicy; the container args contain `--metrics-listen=0.0.0.0:8080`; the image is `ghcr.io/fables-for-robots/iroh-gateway-operator:0.0.0-dev`.
  - `--set 'gatewayNamespaces={iroh-gateway,apps,web}'`: a Secret-reading Role and binding in each of the three namespaces, the identity rule only in `iroh-gateway`, no duplicate object, and the args contain `--gateway-namespaces=iroh-gateway,apps,web`.
  - Release name `gw` (`helm template gw …`): the Service's selector is a subset of the Deployment's pod labels, the ClusterRoleBinding and RoleBindings name the rendered ServiceAccount, and the ServiceAccount's namespace is the release namespace.
  - `--set networkPolicy.enabled=true --set metrics.serviceMonitor.enabled=true`: both render; `--set metrics.service.enabled=false --set metrics.serviceMonitor.enabled=true` fails to render.
  - `--set relay=n0` puts `--relay=n0` (or the env equivalent) on the container; `--set gatewayClass.create=false` renders no GatewayClass.
  - The CRD: `charts/iroh-gateway/crds/edges.yaml` equals the output of `cargo run -q -p iroh-gateway-operator --bin crdgen`.

- [ ] **Step 2: Run it and see it fail**

  Run: `nix develop -c scripts/chart-test.sh` (after adding `pkgs.kubernetes-helm`, `pkgs.kind` and `pkgs.yq-go` to the flake's dev shell)
  Expected: FAIL at `helm lint` (no chart).

- [ ] **Step 3: Write the chart**, move the CRD, delete `deploy/`.

- [ ] **Step 4: Run the chart test**

  Run: `nix develop -c scripts/chart-test.sh && nix develop -c shellcheck scripts/*.sh`
  Expected: every check prints `ok`.

- [ ] **Step 5: `scripts/e2e-kind.sh` on the chart.** Replace the step that applies `deploy/` with `helm install iroh-gateway "$root/charts/iroh-gateway" --namespace "$ns" --create-namespace --set image.repository=iroh-gateway-operator --set image.tag=e2e --set image.pullPolicy=IfNotPresent --set networkPolicy.enabled=true --wait --timeout 180s` (so the readiness probe is what the script waits on), and follow the renamed objects everywhere the script names the Deployment, its container or its label (`diagnostics`, `certificate_files_private`, the final pod deletion). Give the edge pod `--metrics-listen=0.0.0.0:9090` and its Service a TCP port `metrics` 9090. New steps, after the existing "conditions" step, each with the script's `retry` and a failure message that prints what was seen:
  - "metrics: the operator's": from the `probe` pod, `wget -qO- http://iroh-gateway.$ns.svc:8080/metrics` contains `iroh_gateway_operator_tunnel_up{edge="$edge_id"} 1`, `iroh_gateway_operator_haproxy_exporter_up 1` and a line starting with `haproxy_process_`.
  - "metrics: the edge's": `wget -qO- http://edge.$ns.svc:9090/metrics` contains `iroh_gateway_edge_session_up 1`.
  - "probes": the operator pod's `Ready` condition is `True` and its container has both probes (`kubectl get pod -o jsonpath`).
  - After the existing TCP traffic step: the operator's `iroh_gateway_operator_tunnel_streams_total{edge="$edge_id"}` is at least 1.

- [ ] **Step 6: CI.** In `.github/workflows/ci.yml`: a job `chart` that runs `scripts/chart-test.sh` (helm and yq are on the runner; the script needs cargo for the CRD check, so it uses the same toolchain and cache steps as `test`), replacing the "CRD manifest is up to date" step of `test`; `e2e-kind` also needs `chart`.

- [ ] **Step 7: README, only what the chart makes false.** The Install section's commands (build both images, load them, the `helm install` above without the e2e-only settings but with the locally built image), and each sentence that names `deploy/`, a manifest file, or says there is no health endpoint, no metrics or no NetworkPolicy. Task 9 rewrites the section properly; here nothing false may remain.

- [ ] **Step 8: Run everything** (Global Constraints, plus `nix develop -c scripts/chart-test.sh`).

- [ ] **Step 9: Commit**

  ```bash
  git add -A && git commit -m "feat(chart): a Helm chart replaces deploy/, and the kind test installs it"
  ```

### Task 6: cert-manager in the kind test

**Files:**
- Modify: `scripts/e2e-kind.sh`, `operator/src/model/http_routes.rs` (tests only, unless a test fails)

**Interfaces:**
- Consumes: the kind script as Task 5 left it. Facts about cert-manager are in the SDD workspace file `research-cert-manager-external-dns.md`, sections A1 to A5.

- [ ] **Step 1: A model test for the route cert-manager creates.** In `operator/src/model/http_routes.rs` tests (or where the HTTPRoute model tests live): `the_acme_http01_solver_route_is_served`: a Gateway with an `HTTP` listener on port 80 without a hostname and an `HTTPS` listener `example.net` on 443 whose Secret does not exist; an `HTTPRoute` in the Gateway's namespace with `parentRefs: [{kind: Gateway, name, namespace}]` (no `sectionName`, no `port`), `hostnames: [example.net]`, one rule with one `Exact` path `/.well-known/acme-challenge/YadC4gaAzqEPU1Yea0D2MrzvNRWiBCtUizCtpiRQZqI` and one backend `{group: "", kind: Service, name, namespace: <the route's own>, port: 8089, weight: 1}` to a `NodePort` Service. Assert: the route is `Accepted` and `ResolvedRefs` for that parent, the port-80 listener is served with that host and path, and port 443 is not opened.

- [ ] **Step 2: Run it**

  Run: `nix develop -c cargo test -p iroh-gateway-operator the_acme_http01_solver_route_is_served`
  Expected: PASS if the controller already handles the shape. If it fails, the failure is a defect in the controller: fix it in the model, with the test as the proof, and say so in the report.

- [ ] **Step 3: The kind steps**, at the end of `scripts/e2e-kind.sh`, before the final pod deletion:
  - "cert-manager": `helm install cert-manager oci://quay.io/jetstack/charts/cert-manager --version v1.21.3 --namespace cert-manager --create-namespace --set crds.enabled=true --set config.gatewayAPI.enabled=true --wait --timeout 300s`.
  - "cert-manager: an issuer and an annotated Gateway": the self-signed `ClusterIssuer` of section A5; the Gateway `public` re-applied with every listener it has at that point plus an `HTTPS` listener `cm` on port 8443 with hostname `cm.example.test` and `certificateRefs: [{name: cm-tls}]`, the annotation `cert-manager.io/cluster-issuer`, and `cert-manager.io/ignore-tls-listeners` naming the script's existing HTTPS listener so cert-manager leaves the script's own `app-tls` Secret alone; an `HTTPRoute` for `cm.example.test` to the existing `web` Service.
  - "cert-manager: the Secret appears and is served": wait for `certificate/cm-tls` to be `Ready`; then, with the script's `curl` pod and the certificate from the Secret's `tls.crt` as the trust anchor, `https://cm.example.test:8443/` through the edge answers with the `web` backend's body. The listener `cm` is `Programmed`.
  - "cert-manager: app-tls is untouched": no `Certificate` named `app-tls` exists.
  - `diagnostics` also prints `kubectl get certificates,certificaterequests -A` and the cert-manager controller's last 100 log lines.

- [ ] **Step 4: Check the script**

  Run: `nix develop -c shellcheck scripts/*.sh` and the Global Constraints commands.
  Expected: clean. The steps themselves first run in CI; say so in the report.

- [ ] **Step 5: Commit**

  ```bash
  git add -A && git commit -m "test(e2e): a certificate issued by cert-manager for an annotated Gateway is served"
  ```

### Task 7: The release workflow, static edge binaries, the systemd unit

**Files:**
- Create: `.github/workflows/release.yml`, `dist/iroh-gateway-edge.service`, `dist/README.md` (ten lines: what the tarball holds and where the files go), `scripts/check-release-version.sh`
- Modify: `Dockerfile` (labels), `flake.nix` (`pkgs.actionlint`)

**Interfaces:**
- Consumes: `--metrics-listen` (Task 1) is not in the unit; the unit starts `/usr/local/bin/iroh-gateway-edge run` with `EnvironmentFile=/etc/iroh-gateway-edge/env`.
- Produces:
  - `scripts/check-release-version.sh <tag>`: exits 0 when `<tag>` is `v` followed by the version of the `iroh-gateway-edge` and `iroh-gateway-operator` crates (read from `cargo metadata --no-deps --format-version 1` with `jq`, or from the two `Cargo.toml` files), else prints both and exits 1.
  - Release assets on a tag: `iroh-gateway-edge-<tag>-x86_64-unknown-linux-musl.tar.gz` and `…-aarch64-unknown-linux-musl.tar.gz`, each holding `iroh-gateway-edge`, `iroh-gateway-edge.service`, `README.md` (from `dist/`) and `LICENSE`; and `SHA256SUMS`.
  - Image tags: on `main`, `edge` and `sha-<short>`; on a tag `vX.Y.Z`, `X.Y.Z` and `latest`. Chart `iroh-gateway-X.Y.Z.tgz` pushed to `oci://ghcr.io/fables-for-robots/charts`.

- [ ] **Step 1: The unit** `dist/iroh-gateway-edge.service`: `[Unit]` with `After=network-online.target` and `Wants=network-online.target`; `[Service]` with `ExecStart`, `EnvironmentFile`, and every line of the Global Constraints' hardening set; `[Install]` `WantedBy=multi-user.target`. A comment block at the top gives the three commands to install it and the `systemd-run` command that prints the edge's id using the same state directory: `systemd-run --wait --pipe --collect -p DynamicUser=yes -p StateDirectory=iroh-gateway-edge /usr/local/bin/iroh-gateway-edge id`.

- [ ] **Step 2: `scripts/check-release-version.sh`**, and a check of it by hand: `scripts/check-release-version.sh v0.1.0` exits 0, `v9.9.9` exits 1 (put both in the report).

- [ ] **Step 3: `release.yml`**, modelled on `../secret-bunker-iroh/.github/workflows/release.yml`. Triggers: push to `main`, tags `v*`, `workflow_dispatch`, and `pull_request` limited to the paths `.github/workflows/release.yml`, `Dockerfile`, `dist/**`, `scripts/check-release-version.sh`, `charts/**`. Nothing is pushed or published on `pull_request` or `workflow_dispatch`: those runs build only. Jobs:
  - `version` (tags only): `scripts/check-release-version.sh "$GITHUB_REF_NAME"`; every publishing job needs it.
  - `images`: matrix `ubuntu-latest`/`linux/amd64` and `ubuntu-24.04-arm`/`linux/arm64`; in one job per platform, build `--target operator` and `--target edge` with buildx, pushing each by digest (as the sibling does) when publishing; upload the digests.
  - `manifests` (publishing runs only): one multi-arch manifest per image with the tags above (`docker/metadata-action`).
  - `edge-binaries`: the same two runners; `rustup target add <arch>-unknown-linux-musl`, `musl-tools`, `cargo build --release --locked -p iroh-gateway-edge --target …`; assert the binary is static (`file` says `statically linked` or `static-pie linked`) and runs (`--version`); build the tarball; upload it. On the x86_64 runner also: `systemd-analyze verify dist/iroh-gateway-edge.service` with the binary installed at `/usr/local/bin`, then the real thing: install the unit and an env file with `IROH_GATEWAY_EDGE_OPERATOR=5866666666666666666666666666666666666666666666666666666666666666`, read the id with the `systemd-run` command from the unit's comment, `systemctl start iroh-gateway-edge`, and within 30 s the unit is `active`, the journal has the line `edge started` with that same id, and UDP port 7842 is bound; on failure print `journalctl -u iroh-gateway-edge`.
  - `release` (tags only): download the tarballs, write `SHA256SUMS`, `gh release create "$GITHUB_REF_NAME" --generate-notes` with the assets; `permissions: contents: write`.
  - `chart` (tags only): `helm package charts/iroh-gateway --version X.Y.Z --app-version X.Y.Z`, `helm push` to the registry.
  Least permissions per job (`contents: read` and `packages: write` only where pushed).

- [ ] **Step 4: Dockerfile labels** on both final stages: `org.opencontainers.image.source=https://github.com/fables-for-robots/iroh-gateway`, `org.opencontainers.image.licenses=AGPL-3.0-or-later`.

- [ ] **Step 5: Check what can be checked here**

  Run: `nix develop -c actionlint .github/workflows/*.yml && nix develop -c shellcheck scripts/*.sh`
  Expected: clean. The workflow first runs in the pull request (build only); say so in the report.

- [ ] **Step 6: Commit**

  ```bash
  git add -A && git commit -m "feat(release): a release workflow, static edge binaries and a hardened systemd unit"
  ```

### Task 8: Nix packages, the NixOS module, and its VM test

**Files:**
- Create: `nix/edge-module.nix`, `nix/edge-test.nix`, `.github/workflows/nix.yml`
- Modify: `flake.nix`, `flake.lock` (only if an input is added; none should be)

**Interfaces:**
- Consumes: the edge's flags, including `--metrics-listen` (Task 1); the hardening set of Global Constraints.
- Produces, as flake outputs:
  - `packages.<system>.edge` and `.operator` for the four systems of the `systems` input, built with the toolchain of `rust-toolchain.toml` through `pkgs.makeRustPlatform`, `cargoLock.lockFile = ./Cargo.lock`, `doCheck = false` (the tests need sockets the sandbox forbids), each building only its crate; the operator's `haproxy` is on its `PATH` through a wrapper; `packages.<system>.default = edge`.
  - `nixosModules.edge` and `nixosModules.default`: options under `services.iroh-gateway-edge`: `enable`, `package` (default: this flake's `edge` for the host's system), `operator` (string, required when enabled, checked by an assertion against `^[0-9a-f]{64}$`), `keyFile` (default `/var/lib/iroh-gateway-edge/edge.key`), `irohListen` (default `0.0.0.0:7842`), `publicBind` (default `::`), `maxConnections` (2048), `maxUdpFlows` (4096), `udpRateLimit` (null or positive int), `tunnelGrace` (string, `5s`), `relay` (string, `disabled`), `metricsListen` (null or string), `openFirewall` (bool, default false: opens only the iroh UDP port; the public ports are the Gateway's and stay the administrator's to open), `extraArgs` (list of strings). The unit is `iroh-gateway-edge.service` with the hardening set and `ExecStart` built from the options.
  - `checks.x86_64-linux.edge-module`: `pkgs.testers.runNixOSTest` with one machine: the module enabled, `operator = "5866666666666666666666666666666666666666666666666666666666666666"`, `metricsListen = "127.0.0.1:9090"`, `openFirewall = true`. The script: `wait_for_unit("iroh-gateway-edge.service")`, `wait_for_open_port(9090)`, `curl` of `/metrics` contains `iroh_gateway_edge_session_up 0`, UDP 7842 is bound (`ss -lun`), the firewall allows UDP 7842, `systemctl show -p DynamicUser` is `yes`, the key file exists under `/var/lib/private/iroh-gateway-edge/`, and the unit is still active after a restart with the same id in the journal both times.

- [ ] **Step 1: Packages.** Run: `nix build .#edge .#operator -L` (on this machine: the darwin build). Expected: both build; `./result/bin/iroh-gateway-edge --version` prints the version; `result-1/bin/iroh-gateway-operator --version` too. Remove the `result` links afterwards.

- [ ] **Step 2: Module and test.** Run: `nix eval .#checks.x86_64-linux.edge-module.drvPath` and `nix flake check --no-build --all-systems`. Expected: a store path, and no evaluation error. A second evaluation with `operator = "nope"` (a throwaway `nix eval --expr`, not committed) fails with the assertion's message; put the message in the report. The VM test itself cannot run here; it first runs in CI. Say so in the report.

- [ ] **Step 3: `.github/workflows/nix.yml`.** Triggers: push to `main`, `workflow_dispatch`, and `pull_request` limited to `flake.nix`, `flake.lock`, `nix/**`, `rust-toolchain.toml`, `Cargo.lock`, `.github/workflows/nix.yml`. One job on `ubuntu-latest`: the KVM udev rule (the three commands in the workspace file `research-cert-manager-external-dns.md`, section C3), a nix installer action, `nix build .#edge .#operator -L`, `nix build .#checks.x86_64-linux.edge-module -L`.

- [ ] **Step 4: Check**

  Run: `nix develop -c actionlint .github/workflows/*.yml` and `nix flake check --no-build --all-systems`.
  Expected: clean.

- [ ] **Step 5: Commit**

  ```bash
  git add -A && git commit -m "feat(nix): packages for both binaries and a NixOS module for the edge, with a VM test"
  ```

### Task 9: The README, the chart's README, and the design

**Files:**
- Modify: `README.md`, `charts/iroh-gateway/README.md`, `docs/superpowers/specs/2026-11-23-iroh-gateway-design.md`

**Interfaces:**
- Consumes: everything built in Tasks 1 to 8, read from the code and files, not from this plan; the SDD workspace file `research-cert-manager-external-dns.md` for cert-manager v1.21.3 and external-dns v0.24.0.

- [ ] **Step 1: Restructure the README** so a reader installs with the chart and never meets `deploy/`. Required content, each checked against the code or file it describes:
  - **Status:** what exists, that no version has been released yet, and that images tagged `edge` are built from `main`.
  - **Install:** Gateway API v1.7.0 standard CRDs; `helm install` from the OCI registry for a released version and from a checkout with `--set image.tag=edge`; the values that matter (`gatewayNamespaces`, `relay`, `metrics`, `networkPolicy`) with a pointer to the chart's README; what RBAC the chart grants, in the words the current README uses for Secrets.
  - **The edge on a machine of its own:** the release tarball, where its files go, the `systemd-run` command that prints the id, the env file, `systemctl enable --now`; the same with the NixOS module (a complete `configuration.nix` fragment using `nixosModules.edge`); the container image as a third way.
  - **Walkthrough: from an empty VPS to an HTTPS site.** Numbered steps with every command and manifest: chart; edge; `Edge` and `Gateway` (an `HTTP` listener on 80 and an `HTTPS` listener on 443 with a hostname); the operator's id; an `HTTPRoute`; cert-manager v1.21.3 with `config.gatewayAPI.enabled=true`, a Let's Encrypt `ClusterIssuer` with the `gatewayHTTPRoute` solver, the Gateway's annotation, and what cert-manager then creates and removes; DNS-01 as the alternative in two sentences with the link; external-dns v0.24.0 with `--source=gateway-httproute`, the required `--policy`, its RBAC, that targets come from `Gateway.status.addresses` (state where the operator gets those from, as the code does it), the `external-dns.kubernetes.io/` annotation prefix, and that `gateway-udproute` reads `UDPRoute` `v1alpha2`, which the standard channel of Gateway API v1.7.0 does not serve.
  - At the head of the walkthrough, one paragraph: which parts a test runs (chart install, enrolment, routes, a cert-manager certificate from a self-signed issuer, in the kind test) and which none does (Let's Encrypt, external-dns, the VPS itself), and the versions the text was written against, including that cert-manager v1.21.3 is built against Gateway API v1.6.
  - **Metrics and health:** the flags, the three paths, readiness as defined in the design, both metric tables (generated by reading `render()` output of each binary in a throwaway test or by reading `metrics.rs`; every name in the README must exist in the code and every metric in the code must be in the README), three example queries (an edge down, a refused HAProxy configuration, UDP drops by reason), and the full-tunnel rule.
  - **Upgrading from the manifests in `deploy/`:** delete the old objects (the list, with the commands; the identity Secret stays so the operator keeps its id), then `helm install`.
  - **Known limitations:** remove "No metrics yet"; keep what is still true; add that GitHub may create the container packages private until their visibility is changed once, and the two step-4 limits (a UDP-only Gateway shows `Programmed=False` at Gateway level while HAProxy refuses a configuration; an `Edge` added while HAProxy refuses gets no UDP until HAProxy accepts one).
  - The three stale sentences: every place that says a UDP flood "can slow" or "slows" TCP says "can stall", as the UDP section does; the design's sentence that a `UDP` listener on the iroh port ends as a bind error says when (the iroh address and the public bind address overlap, as with the defaults).
  - Every sentence in the README and the design that says a full send buffer discards the oldest datagram is corrected to the full-tunnel rule.

- [ ] **Step 2: `charts/iroh-gateway/README.md`:** install command, the complete values table (every key of `values.yaml`, checked by a one-off script that lists the keys; put its output in the report), the CRD note (Helm does not upgrade CRDs in `crds/`; the `kubectl apply --server-side -f` command for upgrades).

- [ ] **Step 3: The design:** "Build order" step 5 gets "(Built.)" and the sentence above the list says steps 1 to 5; "Testing" names the chart test, the cert-manager step and the VM test; "Left to the builder" loses "Metric names".

- [ ] **Step 4: Check the documents against the tree**

  Run: `grep -n "deploy/" README.md charts docs/superpowers/specs -r` (expected: only the upgrade section and history), and for every command in the README that can run on this machine without a cluster (`helm template` with the documented values, `iroh-gateway-edge run --help`, `iroh-gateway-operator run --help` flag names), run it and compare; list what was run in the report.

- [ ] **Step 5: Commit**

  ```bash
  git add -A && git commit -m "docs: the README around the chart, a walkthrough to an HTTPS site, metrics, and the design after step 5"
  ```
