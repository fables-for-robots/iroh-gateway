# Kubernetes Controller Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raw TCP reaches a Service in a Kubernetes cluster through an edge: the operator watches `GatewayClass`, `Gateway`, `TCPRoute` and a new `Edge` resource, drives HAProxy, tells each edge which ports to open, and reports status.

**Architecture:** The watched resources are reduced to a model by pure functions, and the model is rendered to an HAProxy configuration, a table of Unix sockets and a listener list per edge. An engine applies that: HAProxy first, then the edge links, so a port never opens before something is behind it. Each visitor stream goes to HAProxy over a Unix socket with a PROXY v2 header. Status is computed from the model plus runtime facts and written back.

**Tech Stack:** Rust 2024 (1.100), tokio, iroh 1.5, kube 5.1, k8s-openapi 0.29, gateway-api 0.23 (Gateway API v1.7.0), schemars 1, HAProxy 3.x, sha2.

**Spec:** `docs/superpowers/specs/2026-11-23-iroh-gateway-design.md`. This plan implements build step 2 of 5 ("Controller skeleton"). HTTP and TLS are step 3, UDP is step 4, the Helm chart and release packaging are step 5.

## Global Constraints

- Rust edition 2024, `rust-version = "1.100"`, license `AGPL-3.0-or-later`. Run every cargo command through the flake: `nix develop -c cargo …`.
- Work on a branch named `k8s-controller`, not on `main`. Never push.
- The workspace iroh dependency keeps `default-features = false` (port mapping stays compiled out). The CI guard for it stays.
- Crates: `kube = "5.1"` (features `runtime`, `client`, `derive`), `k8s-openapi = "0.29"` (feature `latest`), `gateway-api = "0.23"`, `schemars = "1"`. These four resolve together; do not let cargo pick a second `kube` or `k8s-openapi`.
- Gateway API types come from `gateway_api::apis::standard`: `gatewayclasses::v1::GatewayClass`, `gateways::v1::Gateway`, `tcproutes::v1::TcpRoute`, and the condition enums in `constants`. `TCPRoute` v1 is in the standard channel as of Gateway API v1.7.0.
- CRD group `gateway.fables-for-robots.ch`, version `v1alpha1`, kind `Edge`, namespaced.
- Controller name: `gateway.fables-for-robots.ch/iroh-gateway`.
- The operator honours `Gateway` and `Edge` only in the namespaces it is configured with. Routes, Services and Namespaces are read cluster-wide.
- All cross-namespace `backendRefs` are refused with `ResolvedRefs=False`, reason `RefNotPermitted`.
- Only listener protocol `TCP` is supported in this step. `HTTP`, `HTTPS`, `TLS` and `UDP` listeners get `Accepted=False`, reason `UnsupportedProtocol`.
- HAProxy is reached over Unix sockets with `accept-proxy`. It binds no TCP port. Do not use the `master-worker` configuration keyword (deprecated in 3.3); pass `-W` on the command line.
- HAProxy is never left running a configuration that failed validation, and the operator never opens an edge port before HAProxy serves it.
- A model must never be built from watch stores that have not finished their first list.
- Edge-supplied text that ends up in Kubernetes status is truncated to 256 characters.
- Tests that need the `haproxy` binary find it on `PATH` (the dev shell provides it) and fail with a clear message if it is missing. Tests that need a Kubernetes API server are marked `#[ignore]` and read `KUBEBUILDER_ASSETS`.
- All non-ignored tests pass on macOS and Linux with `cargo test --workspace`, on loopback only. Test output is pristine. No test leaves a process, port or file behind.
- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` are clean at every commit.
- Leave no build output outside `target/`. Downloaded test binaries go under `target/`. Run `cargo clean` when the last task is done.
- Metrics are not in this plan. Log with `tracing`; only binaries install a subscriber. Never log the secret key.

## Review Focus

Conditions the spec implies that are most likely to bite a real user. Each has a test in the task named.

1. The operator restarts and its watch stores are still filling. Rendering from a partial view would close every port and drop every edge. Nothing may be applied before all stores have synced. (Task 11, `nothing_is_applied_before_stores_sync`)
2. A backend Service is headless (`clusterIP: None`), of type `ExternalName`, or has an IPv6 cluster IP. The first two must be refused cleanly; the third must render as `[addr]:port`. (Task 7, `headless_and_external_name_services_are_refused`; Task 8, `ipv6_backend_is_bracketed`)
3. A Gateway and namespace with 63-character names. Socket paths must stay under the 104-byte Unix limit and HAProxy identifiers must stay valid. (Task 8, `long_names_give_short_socket_paths`)
4. HAProxy dies while the operator runs. The operator must notice and exit non-zero, so the pod restarts, instead of silently dropping every connection. (Task 4, `exited_resolves_when_haproxy_is_killed`; Task 11, `run_ends_with_an_error_when_haproxy_dies`)
5. Two `Edge` resources carry the same `endpointId`, or an `Edge` names a Gateway that is not this controller's. The outcome must be deterministic and visible in status, never two links fighting over one edge. (Task 6, `duplicate_endpoint_id_oldest_wins`, `edge_for_foreign_gateway_is_refused`)

## File Structure

```
flake.nix                               + haproxy, setup-envtest, kubectl in the dev shell
Dockerfile                              targets `operator` and `edge`
deploy/                                 plain manifests: namespace, crd, rbac, operator, gatewayclass
scripts/envtest-assets                  prints the directory with kube-apiserver and etcd
scripts/e2e-kind.sh                     end-to-end test in a kind cluster
.github/workflows/ci.yml                + haproxy, cluster tests, CRD drift check, e2e-kind job
edge/src/lib.rs                         handshake cap: evict the oldest (Task 1)
operator/src/
  tunnel/link.rs                        bind retry, last_error, truncation (Task 2)
  tunnel/proxyv2.rs                     PROXY protocol v2 header
  tunnel/haproxy_connector.rs           Connector that dials HAProxy's Unix sockets
  haproxy/mod.rs
  haproxy/supervisor.rs                 runs, validates and reloads HAProxy
  haproxy/render.rs                     Model → haproxy.cfg, socket table, edge plans
  crd.rs                                the Edge resource
  bin/crdgen.rs                         prints the Edge CRD as YAML
  model/mod.rs                          Snapshot, Settings, Model and its parts; build()
  model/gateways.rs                     classes, gateways, listeners
  model/edges.rs                        edges and their binding to gateways
  model/routes.rs                       TCPRoute attachment and backends
  model/fixtures.rs                     #[cfg(test)] builders for resources
  status/mod.rs                         Model + Facts → desired status
  status/conditions.rs                  merging conditions, keeping transition times
  engine.rs                             applies a render: HAProxy, connectors, links
  cluster/mod.rs
  cluster/stores.rs                     watchers and reflector stores → Snapshot
  cluster/identity.rs                   the operator key in a Secret
  cluster/status_writer.rs              patches status where it differs
  controller.rs                         the reconcile loop
  main.rs                               + `run`
operator/tests/
  haproxy.rs                            supervisor and connector against a real haproxy
  engine.rs                             model in, bytes through a real edge and haproxy
  cluster.rs                            #[ignore] tests against a real API server
  common/envtest.rs                     starts etcd and kube-apiserver
```

---

### Task 1: Handshake cap evicts the oldest

Closes the problem left open by the first plan: with 64 pending handshakes the edge refuses new ones, so a host that holds all 64 slots locks the operator out.

**Files:**
- Modify: `edge/src/lib.rs`, `edge/tests/session.rs`

**Interfaces:**
- Consumes: the existing `MAX_PENDING_HANDSHAKES = 64` and `HANDSHAKE_TIMEOUT = 10 s` in `edge/src/lib.rs`.
- Produces: no API change.

Behaviour: when 64 handshakes are pending and another validated incoming connection arrives, the edge aborts the pending handshake that started first and admits the new one. Address validation by retry and the 10 s timeout stay.

- [ ] **Step 1: Write the failing tests** in `edge/tests/session.rs`

```rust
#[tokio::test] async fn handshake_flood_does_not_lock_out_the_operator() {
    // hold 64 validated handshakes stalled (the technique `handshake_flood_is_capped` uses),
    // keep starting a new stalled one every 50 ms in the background;
    // the pinned operator connects and pushes a config within 3 s
}
#[tokio::test] async fn oldest_pending_handshake_is_evicted() {
    // start 80 stalled handshakes one after another; at least 16 of the first ones fail
    // well before the 10 s handshake timeout (assert within 5 s); the last 64 are still pending
}
```

Replace `handshake_flood_is_capped`, whose "16 refused" assertion no longer holds, with the second test.

- [ ] **Step 2: Run them and see them fail**

Run: `nix develop -c cargo test -p iroh-gateway-edge --test session handshake`
Expected: the lock-out test fails (the operator is refused).

- [ ] **Step 3: Implement eviction in `incoming()`**

Keep pending handshakes in start order; aborting the oldest must release everything it holds.

- [ ] **Step 4: Run the edge tests**

Run: `nix develop -c cargo test -p iroh-gateway-edge`, then loop `--test session` 10 times.
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "fix(edge): evict the oldest pending handshake instead of refusing new ones"
```

---

### Task 2: Link follow-ups for the controller

**Files:**
- Modify: `operator/src/tunnel/link.rs`, `operator/tests/tunnel.rs`

**Interfaces:**
- Produces:

```rust
pub struct EdgeState {
    pub connected: bool,
    pub edge_version: Option<String>,
    pub generation: u64,
    pub listeners: Vec<ListenerState>,
    /// Why the link is not connected, in plain words; None while connected.
    pub last_error: Option<String>,
}
pub struct LinkOptions { /* existing fields */ pub bind_retry: Duration /* default 30 s */ }
pub const MAX_STATUS_TEXT: usize = 256;
/// Cuts at a character boundary and appends "…" when it cut.
pub fn truncate_status_text(text: &str) -> String;
```

Behaviour:

- `last_error` is set when a dial fails, a session ends, or the peer closes with a known code. For `CLOSE_UNAUTHORIZED` the text is `the edge does not accept this operator's key (<operator EndpointId>)`. It is cleared when `connected` becomes true.
- While the last acknowledged `Status` contains a bind error, the link sends the current listener list again as a new `Config` every `bind_retry`.
- `ListenerState.bound` error text and `edge_version` go through `truncate_status_text`.

- [ ] **Step 1: Write the failing tests** in `operator/tests/tunnel.rs` and `link.rs`

```rust
#[tokio::test] async fn bind_error_is_retried_and_recovers() {
    // bind_retry 200 ms; hold port p with a std listener → state.listeners[0].bound is Err;
    // drop the std listener → within 2 s bound is Ok and a visitor echoes
}
#[tokio::test] async fn last_error_explains_a_wrong_key() {
    // edge pinned to another operator key → wait_state(last_error contains "does not accept this operator's key")
    // and contains the link's own EndpointId
}
#[tokio::test] async fn last_error_clears_on_connect() { /* edge down → Some(_); edge up → None and connected */ }
#[tokio::test] async fn long_bind_error_is_truncated() {
    // fake edge answers with a 10 KiB error string → state error text has at most 256 chars and ends with '…'
}
#[test] fn truncate_status_text_respects_char_boundaries() {
    assert_eq!(truncate_status_text("short"), "short");
    let long = "é".repeat(300);
    let cut = truncate_status_text(&long);
    assert_eq!(cut.chars().count(), 256);
    assert!(cut.ends_with('…'));
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `nix develop -c cargo test -p iroh-gateway-operator`
Expected: compile errors for the new field and function.

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run the operator tests**, loop `--test tunnel` 10 times.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(operator): link retries failed binds and reports why it is not connected"
```

---

### Task 3: PROXY v2 and the HAProxy connector

**Files:**
- Create: `operator/src/tunnel/proxyv2.rs`, `operator/src/tunnel/haproxy_connector.rs`
- Modify: `operator/src/tunnel/mod.rs`

**Interfaces:**
- Consumes: `Connector`, `ListenerKey`, `StreamHeader`, `LocalStream for UnixStream`.
- Produces:

```rust
// proxyv2.rs
/// PROXY protocol v2, command PROXY, protocol STREAM. Source is the visitor, destination is `local`.
/// Both IPv4 → family TCP4 (28 bytes). Otherwise both are written as IPv6, an IPv4 address as
/// IPv4-mapped → family TCP6 (52 bytes).
pub fn header(visitor: SocketAddr, local: SocketAddr) -> Vec<u8>;

// haproxy_connector.rs
#[derive(Clone, Default)]
pub struct HaproxyConnector { /* shared map ListenerKey → socket path */ }
impl HaproxyConnector {
    pub fn new() -> Self;
    /// Replaces the whole table.
    pub fn set(&self, sockets: HashMap<ListenerKey, PathBuf>);
}
impl Connector for HaproxyConnector { type Stream = tokio::net::UnixStream; .. }
```

`connect`: unknown key → `io::ErrorKind::NotFound`; otherwise connect to the socket, write the header for `header.visitor` and `header.local`, return the stream.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn v4_header_bytes() {
    let h = header("198.51.100.9:50000".parse().unwrap(), "203.0.113.7:443".parse().unwrap());
    let mut want = b"\r\n\r\n\x00\r\nQUIT\n".to_vec();
    want.extend([0x21, 0x11, 0x00, 0x0c]);
    want.extend([198, 51, 100, 9, 203, 0, 113, 7]);
    want.extend(50000u16.to_be_bytes());
    want.extend(443u16.to_be_bytes());
    assert_eq!(h, want);
}
#[test] fn v6_header_bytes() { /* [2001:db8::1]:1234 → [2001:db8::2]:443: byte 13 is 0x21, length 0x0024, total 52 bytes */ }
#[test] fn mixed_families_become_v6() {
    // visitor 192.0.2.1:1, local [2001:db8::2]:443 → family 0x21, source bytes are ::ffff:192.0.2.1
}
#[tokio::test] async fn connector_writes_header_then_hands_over_the_stream() {
    // a UnixListener in a short temp dir; set({tcp(443) → path}); connect(tcp(443), &header)
    // the listener side reads exactly the 28 header bytes, then b"x" written by the caller arrives
}
#[tokio::test] async fn unknown_listener_is_not_found() { /* connect(tcp(1)) → ErrorKind::NotFound */ }
#[tokio::test] async fn set_replaces_the_table() { /* after set({}) the old key is NotFound */ }
```

- [ ] **Step 2: Run and see them fail** — `nix develop -c cargo test -p iroh-gateway-operator proxyv2 haproxy_connector`

- [ ] **Step 3: Implement both files**

- [ ] **Step 4: Run the tests and lints**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(operator): PROXY v2 header and a connector for HAProxy's Unix sockets"
```

---

### Task 4: HAProxy supervisor

**Files:**
- Create: `operator/src/haproxy/mod.rs`, `operator/src/haproxy/supervisor.rs`, `operator/tests/haproxy.rs`
- Modify: `flake.nix` (add `haproxy` to the dev shell), `.github/workflows/ci.yml` (install HAProxy 3.2 from `ppa:vbernat/haproxy-3.2` before the tests; if that source is not available, any HAProxy 3.0 or newer, and say which in the report)

**Interfaces:**
- Produces:

```rust
pub struct SupervisorOptions {
    pub haproxy_bin: PathBuf,        // default "haproxy"
    pub runtime_dir: PathBuf,        // holds haproxy.cfg, master.sock, stats.sock and s/
    pub reload_timeout: Duration,    // default 30 s
    pub inherit_output: bool,        // true in the binary, false in tests
}
#[derive(Debug, PartialEq, Eq)]
pub enum Applied { Unchanged, Reloaded }
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// `haproxy -c` refused it. Carries the ALERT lines.
    Invalid(String),
    /// The master answered something other than Success=1. Carries its reply.
    ReloadFailed(String),
    Io(#[from] std::io::Error),
}
pub struct Supervisor { .. }
impl Supervisor {
    /// Validates `cfg`, writes it, starts `haproxy -W -S unix@<runtime_dir>/master.sock -f <runtime_dir>/haproxy.cfg`
    /// and returns once the master socket answers.
    pub async fn start(opts: SupervisorOptions, cfg: &str) -> anyhow::Result<Self>;
    pub async fn apply(&mut self, cfg: &str) -> Result<Applied, ApplyError>;
    /// Resolves when the HAProxy master process ends on its own.
    pub async fn exited(&mut self) -> std::process::ExitStatus;
    /// SIGTERM to the master, wait up to 5 s, then kill. Removes the sockets it created.
    pub async fn shutdown(self);
}
/// Longest runtime_dir this module accepts, so that `<runtime_dir>/s/<20 chars>` fits a Unix socket path.
pub const MAX_RUNTIME_DIR_LEN: usize = 70;
```

`apply`, in order:

1. Same text as the running configuration → `Unchanged`.
2. Write `haproxy.cfg.new`; run `haproxy -c -f haproxy.cfg.new`. Non-zero exit → remove the file, return `Invalid` with the lines that contain `[ALERT]`.
3. Rename over `haproxy.cfg`; send `reload\n` on the master socket; read to end of stream within `reload_timeout`.
4. Reply starts with `Success=1` → `Reloaded`. Anything else → write the previous configuration back to `haproxy.cfg` and return `ReloadFailed`.

Facts checked against HAProxy 3.3.17: a reload reply is `Success=1` or `Success=0`, a line `--`, then the startup log, and the master closes the connection; after a failed reload the old worker keeps serving.

`start` creates `runtime_dir` and `runtime_dir/s` with mode `0700` and fails if `runtime_dir` is longer than `MAX_RUNTIME_DIR_LEN` bytes.

Test harness in `operator/tests/haproxy.rs`: `fn short_dir() -> TempDir` under `/tmp`; `fn cfg(dir, frontends: &[(socket_name, backend_addr)]) -> String` producing a TCP-mode configuration with a `global` section (`stats socket <dir>/stats.sock mode 600 level admin expose-fd listeners`, `hard-stop-after 5s`), `defaults` (mode tcp, timeouts), and per pair a frontend `bind unix@<dir>/s/<name> accept-proxy mode 600` with one server.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test] async fn serves_through_a_unix_socket_with_proxy_header() {
    // echo backend; start; UnixStream to s/a.sock, write proxyv2::header(..) then b"hi" → read b"hi"
}
#[tokio::test] async fn visitor_address_survives_the_haproxy_hop() {
    // backend line has `send-proxy-v2`; the test backend parses the PROXY v2 header HAProxy sends
    // and sees source 198.51.100.9:50000 — proves our header is what HAProxy accepts
}
#[tokio::test] async fn apply_same_text_is_unchanged() { .. }
#[tokio::test] async fn apply_switches_backend_and_keeps_open_connections() {
    // conn1 open through backend A; apply cfg pointing at backend B → Reloaded;
    // conn1 still echoes; a new connection reaches B
}
#[tokio::test] async fn invalid_config_is_refused_and_old_one_keeps_serving() {
    // apply text with `default_backend nope` → Err(Invalid(m)) with m containing "nope";
    // haproxy.cfg on disk is still the old text; a new connection still echoes; no haproxy.cfg.new left
}
#[tokio::test] async fn exited_resolves_when_haproxy_is_killed() { /* SIGKILL the master pid → exited() resolves within 2 s */ }
#[tokio::test] async fn shutdown_stops_haproxy_and_removes_sockets() { /* no process left; master.sock, stats.sock gone */ }
#[tokio::test] async fn start_rejects_a_long_runtime_dir() { /* 80-byte path → Err mentioning the limit */ }
#[tokio::test] async fn start_fails_clearly_without_the_binary() { /* haproxy_bin "/nonexistent/haproxy" → Err naming the path */ }
```

- [ ] **Step 2: Run and see them fail** — `nix develop -c cargo test -p iroh-gateway-operator --test haproxy`

- [ ] **Step 3: Implement the supervisor; add `haproxy` to the dev shell and to CI**

Kill the child on drop as well, so a panicking test leaves no HAProxy behind.

- [ ] **Step 4: Run the tests** and loop `--test haproxy` 10 times. Afterwards `pgrep haproxy` shows nothing.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(operator): HAProxy supervisor with validated, reversible reloads"
```

---

### Task 5: The Edge resource

**Files:**
- Create: `operator/src/crd.rs`, `operator/src/bin/crdgen.rs`, `deploy/crd.yaml`
- Modify: `operator/Cargo.toml`, `Cargo.toml`, `.github/workflows/ci.yml` (CRD drift check: `cargo run -p iroh-gateway-operator --bin crdgen | diff - deploy/crd.yaml`)

**Interfaces:**
- Produces:

```rust
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq)]
#[kube(group = "gateway.fables-for-robots.ch", version = "v1alpha1", kind = "Edge", namespaced,
       status = "EdgeStatus", shortname = "edge",
       printcolumn = r#"{"name":"Gateway","type":"string","jsonPath":".spec.gatewayRef.name"}"#,
       printcolumn = r#"{"name":"Connected","type":"string","jsonPath":".status.conditions[?(@.type==\"Connected\")].status"}"#,
       printcolumn = r#"{"name":"Programmed","type":"string","jsonPath":".status.conditions[?(@.type==\"Programmed\")].status"}"#)]
#[serde(rename_all = "camelCase")]
pub struct EdgeSpec {
    pub endpoint_id: String,
    pub address: Option<String>,
    pub gateway_ref: EdgeGatewayRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_addresses: Vec<String>,
}
pub struct EdgeGatewayRef { pub name: String }
#[serde(rename_all = "camelCase")]
pub struct EdgeStatus {
    pub gateway_endpoint_id: Option<String>,
    #[serde(default)] pub conditions: Vec<Condition>,
    #[serde(default)] pub listeners: Vec<EdgeListenerStatus>,
}
pub struct EdgeListenerStatus { pub protocol: String, pub port: u16, pub bound: bool, pub message: Option<String> }
```

- [ ] **Step 1: Write the failing tests** in `crd.rs`

```rust
#[test] fn crd_identity() {
    let crd = Edge::crd();
    assert_eq!(crd.spec.group, "gateway.fables-for-robots.ch");
    assert_eq!(crd.spec.names.kind, "Edge");
    assert_eq!(crd.spec.scope, "Namespaced");
    assert_eq!(crd.spec.versions[0].name, "v1alpha1");
    assert!(crd.spec.versions[0].subresources.as_ref().unwrap().status.is_some());
}
#[test] fn spec_parses_from_the_documented_yaml() {
    // the Edge example from the spec ("### `Edge` (custom resource)") → endpoint_id, address Some("203.0.113.7:7842"),
    // gateway_ref.name "public", public_addresses empty
}
#[test] fn address_is_optional() { .. }
#[test] fn checked_in_crd_matches_generated() {
    // serde_yaml of Edge::crd() equals the contents of ../deploy/crd.yaml
}
```

- [ ] **Step 2: Run and see them fail**

- [ ] **Step 3: Implement `crd.rs` and `crdgen`; generate `deploy/crd.yaml`**

- [ ] **Step 4: Run the tests and the drift command**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(operator): Edge custom resource and CRD generator"
```

---

### Task 6: Model — classes, gateways, listeners, edges

Pure functions. No I/O, no clock.

**Files:**
- Create: `operator/src/model/mod.rs`, `operator/src/model/gateways.rs`, `operator/src/model/edges.rs`, `operator/src/model/fixtures.rs`

**Interfaces:**
- Consumes: `Edge` (Task 5); Gateway API types; `Relay`.
- Produces:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjRef { pub namespace: String, pub name: String }      // Display: "namespace/name"

pub struct Settings {
    pub controller_name: String,
    pub gateway_namespaces: BTreeSet<String>,
    pub relay: Relay,
}
#[derive(Default, Clone)]
pub struct Snapshot {
    pub gateway_classes: Vec<GatewayClass>, pub gateways: Vec<Gateway>, pub tcp_routes: Vec<TcpRoute>,
    pub edges: Vec<Edge>, pub services: Vec<Service>, pub namespaces: Vec<Namespace>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject { pub reason: String, pub message: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    pub classes: Vec<ClassModel>,       // every GatewayClass with our controller name, by name
    pub gateways: Vec<GatewayModel>,    // every Gateway whose class is ours, by key
    pub edges: Vec<EdgeModel>,          // every Edge, by key
    pub routes: Vec<RouteModel>,        // filled by Task 7
}
pub struct ClassModel { pub name: String, pub generation: i64 }
pub struct GatewayModel {
    pub key: ObjRef, pub generation: i64,
    pub accepted: Result<(), Reject>,
    pub listeners: Vec<ListenerModel>,
    pub edges: Vec<ObjRef>,                     // accepted edges bound to this gateway
    pub addresses: Vec<GatewayAddress>,
}
pub enum AddressKind { IpAddress, Hostname }
pub struct GatewayAddress { pub kind: AddressKind, pub value: String }
pub struct ListenerModel {
    pub name: String, pub port: u16, pub protocol: String,
    pub accepted: Result<(), Reject>,
    pub conflicted: Option<Reject>,
    pub resolved_refs: Result<(), Reject>,
    pub supported_kinds: Vec<String>,
    pub attached_routes: i32,                   // Task 7
    pub backends: Vec<Backend>,                 // Task 7
}
impl ListenerModel {
    /// Accepted, not conflicted, and with at least one backend. Only serving listeners get an
    /// HAProxy frontend and an open port on the edges.
    pub fn serving(&self) -> bool;
}
pub struct Backend { pub service: ObjRef, pub ip: IpAddr, pub port: u16, pub weight: u32 }
pub struct EdgeModel {
    pub key: ObjRef, pub generation: i64,
    pub accepted: Result<(), Reject>,
    pub endpoint_id: Option<iroh::EndpointId>,
    pub address: Option<String>,
    pub gateway: Option<ObjRef>,
    pub public_addresses: Vec<GatewayAddress>,
}
pub struct RouteModel { .. }                    // Task 7

pub fn build(snapshot: &Snapshot, settings: &Settings) -> Model;
```

Rules. Reasons are the Gateway API names unless marked (custom).

Gateways:

| Condition | `accepted` |
|---|---|
| Namespace not in `gateway_namespaces` | `NamespaceNotAllowed` (custom) |
| `spec.addresses` not empty | `UnsupportedAddress` |
| No listener is accepted and unconflicted | `ListenersNotValid` |
| Otherwise | Ok |

Listeners:

| Condition | Result |
|---|---|
| Protocol is not `TCP` | `accepted` = `UnsupportedProtocol`, `supported_kinds` empty |
| `allowedRoutes.kinds` given and without `TCPRoute` (group `gateway.networking.k8s.io`) | `resolved_refs` = `InvalidRouteKinds`, `supported_kinds` empty |
| Otherwise | `supported_kinds` = `["TCPRoute"]` |
| Two or more listeners of the Gateway share a port, same protocol | each `conflicted` = `HostnameConflict` |
| Share a port, different protocols | each `conflicted` = `ProtocolConflict` |

Edges, checked in this order:

| Condition | `accepted` |
|---|---|
| Namespace not in `gateway_namespaces` | `NamespaceNotAllowed` |
| `endpointId` does not parse | `InvalidEndpointId` |
| `address` absent and `settings.relay` is `Disabled` | `NoAddress` |
| `address` absent and `publicAddresses` empty | `NoPublicAddress` |
| `address` present but not `host:port` with port 1..=65535 | `InvalidAddress` |
| No Gateway of that name in the Edge's namespace whose class is ours | `GatewayNotFound` |
| That Gateway is not accepted | `GatewayNotAccepted` |
| An older Edge (creationTimestamp, then key) has the same `endpointId` | `DuplicateEndpointId` |
| Otherwise | Ok |

`public_addresses`: `spec.publicAddresses` if not empty, otherwise the host part of `address`. A value that parses as an IP is `IpAddress`, anything else `Hostname`. A Gateway's `addresses` are those of its accepted edges, de-duplicated, sorted.

Output order is always sorted by key, so equal inputs give equal models.

`fixtures.rs` (`#[cfg(test)]`): `class(name)`, `foreign_class(name)`, `gateway(ns, name)` with `.listener(name, port, protocol)`, `.allowed_kinds(..)`, `.allow_all_namespaces()`, `.allow_selector(labels)`, `.requested_address(..)`; `edge(ns, name, key_seed: u8)` with `.address(..)`, `.no_address()`, `.gateway(name)`, `.public(..)`, `.created(seconds)`; `settings(&[namespaces])`; `ns(name, labels)`.

- [ ] **Step 1: Write the failing tests** in `gateways.rs` and `edges.rs`

```rust
#[test] fn class_with_our_controller_name_is_listed() { /* class("a") + foreign_class("b") → classes == ["a"] */ }
#[test] fn gateway_of_foreign_class_is_ignored() { /* not in model.gateways at all */ }
#[test] fn tcp_listener_is_accepted() {
    // gateway("gw","public").listener("pg", 5432, "TCP") → accepted Ok, listener accepted Ok,
    // conflicted None, supported_kinds ["TCPRoute"], serving() false (no backends yet)
}
#[test] fn other_protocols_are_unsupported() { /* HTTP, HTTPS, TLS, UDP → UnsupportedProtocol each */ }
#[test] fn gateway_with_no_valid_listener_is_not_accepted() { /* only an HTTP listener → ListenersNotValid */ }
#[test] fn gateway_outside_allowed_namespaces() { /* NamespaceNotAllowed */ }
#[test] fn requested_addresses_are_unsupported() { /* UnsupportedAddress */ }
#[test] fn same_port_same_protocol_conflicts() { /* both listeners HostnameConflict; a third on another port is fine */ }
#[test] fn same_port_different_protocol_conflicts() { /* TCP 53 + UDP 53 → ProtocolConflict on both */ }
#[test] fn allowed_kinds_without_tcproute() { /* InvalidRouteKinds, supported_kinds empty */ }
#[test] fn edge_binds_to_its_gateway() {
    // edge("gw","fsn1",1).address("203.0.113.7:7842").gateway("public") → accepted Ok,
    // gateway.edges == [gw/fsn1], gateway.addresses == [IpAddress 203.0.113.7]
}
#[test] fn edge_rejections() { /* one case per row of the edge table, asserting the reason */ }
#[test] fn hostname_address_is_published_as_hostname() { /* address "edge.example.com:7842" → Hostname */ }
#[test] fn public_addresses_override_the_address() { .. }
#[test] fn no_address_is_fine_in_relay_mode_with_public_addresses() { .. }
#[test] fn duplicate_endpoint_id_oldest_wins() {
    // two edges, same key seed, created 10 and 20 → first Ok, second DuplicateEndpointId;
    // swap the creation times → the other one wins
}
#[test] fn edge_for_foreign_gateway_is_refused() { /* gateway of a foreign class → GatewayNotFound */ }
#[test] fn edge_cannot_reach_a_gateway_in_another_namespace() { /* same name, other namespace → GatewayNotFound */ }
#[test] fn build_is_deterministic() { /* shuffled snapshot vectors → equal Model */ }
```

- [ ] **Step 2: Run and see them fail** — `nix develop -c cargo test -p iroh-gateway-operator model::`

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run the tests and lints**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(operator): model of classes, gateways, listeners and edges"
```

---

### Task 7: Model — routes and backends

**Files:**
- Create: `operator/src/model/routes.rs`
- Modify: `operator/src/model/mod.rs`, `operator/src/model/fixtures.rs`

**Interfaces:**
- Consumes: Task 6 types.
- Produces:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ParentKey {
    pub group: String, pub kind: String, pub namespace: String, pub name: String,
    pub section_name: Option<String>, pub port: Option<u16>,
}
pub struct RouteModel { pub key: ObjRef, pub generation: i64, pub parents: Vec<RouteParent> }
pub struct RouteParent {
    pub parent: ParentKey,
    pub accepted: Result<(), Reject>,
    pub resolved_refs: Result<(), Reject>,
}
```

`model.routes` holds every `TCPRoute` that has at least one `parentRef` naming a Gateway in the model; only those `parentRef`s appear in `parents`.

Attachment of one `parentRef` to one Gateway:

1. Candidate listeners: all of the Gateway's, narrowed by `sectionName` and `port` when given. None left → `accepted` = `NoMatchingParent`.
2. Keep candidates that are accepted, unconflicted, have `TCPRoute` in `supported_kinds`, and whose `allowedRoutes.namespaces` admits the route's namespace: `Same` (the default) admits the Gateway's own namespace, `All` admits any, `Selector` admits namespaces whose labels match (`matchLabels` and `matchExpressions`). None left → `NotAllowedByListeners`.
3. The route has more than one rule → `UnsupportedValue`, message "a TCPRoute may have one rule".
4. Per listener, the oldest route (creationTimestamp, then key) wins. A route that lost on every kept listener → `UnsupportedValue`, message "another TCPRoute is already bound to this listener".
5. Otherwise `accepted` Ok. `attached_routes` of a listener counts routes accepted on it (0 or 1).

Backends of the winning route's rule, per `backendRef`:

| Condition | Effect |
|---|---|
| `group` not empty/core or `kind` not `Service` | dropped; `resolved_refs` = `InvalidKind` |
| `namespace` set and different from the route's | dropped; `RefNotPermitted` |
| `port` missing | dropped; `UnsupportedValue` |
| Service not in the snapshot | dropped; `BackendNotFound` |
| Service type `ExternalName`, or `clusterIP` empty or `None` | dropped; `BackendNotFound`, message says why |
| `port` not among the Service's ports | dropped; `BackendNotFound` |
| `weight` 0 | dropped silently |
| Otherwise | `Backend { ip: clusterIP, port, weight (default 1) }` |

`resolved_refs` reports the first problem in `backendRef` order. Valid backends are used even when others were dropped; the dropped ones' share goes to the rest. (The Gateway API asks for that share to be refused instead. That is a known deviation in this step.)

- [ ] **Step 1: Write the failing tests** in `routes.rs`

Fixtures to add: `tcp_route(ns, name)` with `.parent(gateway_name)`, `.parent_in(ns, name)`, `.section(name)`, `.port(p)`, `.backend(service, port)`, `.weighted(service, port, w)`, `.backend_in(ns, service, port)`, `.backend_kind(group, kind, name)`, `.second_rule()`, `.created(seconds)`; `service(ns, name, cluster_ip, &[ports])`, `.external_name()`.

```rust
#[test] fn route_binds_and_listener_serves() {
    // gateway gw/public listener pg:5432, service gw/db 10.43.0.12 [5432], route gw/r → parent public, backend db:5432
    // → route.parents[0] accepted Ok, resolved_refs Ok; listener.attached_routes 1,
    //   backends == [Backend{service gw/db, ip 10.43.0.12, port 5432, weight 1}], serving() true
}
#[test] fn section_name_and_port_narrow_the_listeners() { /* two listeners; sectionName picks one; wrong port → NoMatchingParent */ }
#[test] fn default_allows_only_the_gateways_namespace() { /* route in apps → NotAllowedByListeners */ }
#[test] fn all_namespaces_allows_any() { .. }
#[test] fn selector_matches_namespace_labels() { /* ns apps {expose: "yes"} admitted, ns other refused */ }
#[test] fn oldest_route_wins_a_listener() { /* created 10 and 20 → second UnsupportedValue; attached_routes 1 */ }
#[test] fn two_rules_are_unsupported() { .. }
#[test] fn route_to_unknown_gateway_is_not_in_the_model() { .. }
#[test] fn route_to_conflicted_listener_is_not_allowed() { /* NotAllowedByListeners */ }
#[test] fn weights_are_kept_and_zero_is_dropped() { /* weights 3, 1, 0 → two backends with 3 and 1 */ }
#[test] fn cross_namespace_backend_is_refused() { /* RefNotPermitted; listener not serving */ }
#[test] fn missing_service_and_missing_port() { /* BackendNotFound for each */ }
#[test] fn non_service_backend_is_invalid_kind() { .. }
#[test] fn headless_and_external_name_services_are_refused() { /* clusterIP "None", and type ExternalName → BackendNotFound, no backend */ }
#[test] fn valid_backends_survive_an_invalid_sibling() { /* one good, one missing → resolved_refs BackendNotFound, backends has the good one, serving() true */ }
#[test] fn ipv6_cluster_ip_is_parsed() { /* clusterIP fd00::12 → Backend.ip is that IPv6 address */ }
#[test] fn route_in_allowed_namespace_cannot_use_a_gateway_outside_gateway_namespaces() { /* that gateway is not accepted → NotAllowedByListeners */ }
```

- [ ] **Step 2: Run and see them fail**

- [ ] **Step 3: Implement `routes.rs` and call it from `build`**

- [ ] **Step 4: Run all model tests and lints**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(operator): TCPRoute attachment and backend resolution"
```

---

### Task 8: Render

**Files:**
- Create: `operator/src/haproxy/render.rs`, `operator/src/haproxy/testdata/*.cfg`
- Modify: `operator/src/haproxy/mod.rs`

**Interfaces:**
- Consumes: `Model` and its parts (Tasks 6, 7); `ListenerKey`, `Protocol`.
- Produces:

```rust
pub struct Rendered {
    pub haproxy_cfg: String,
    pub edges: Vec<EdgePlan>,                  // one per accepted edge, sorted by key
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgePlan {
    pub key: ObjRef,
    pub endpoint_id: iroh::EndpointId,
    pub address: Option<String>,
    pub gateway: ObjRef,
    /// The Gateway's serving TCP ports and the socket behind each.
    pub sockets: HashMap<ListenerKey, PathBuf>,
}
pub fn render(model: &Model, runtime_dir: &Path) -> Rendered;
/// First 16 hex characters of sha256("<namespace>/<name>:<port>").
pub fn port_id(gateway: &ObjRef, port: u16) -> String;
/// Scales weights so the largest becomes 256 and none that was positive becomes 0.
pub fn scale_weights(weights: &[u32]) -> Vec<u32>;
```

The configuration, in this order, with four-space indentation and one blank line between sections:

```
global
    log stdout format raw local0
    stats socket <runtime_dir>/stats.sock mode 600 level admin expose-fd listeners
    hard-stop-after 5m

defaults
    mode tcp
    log global
    option tcplog
    option dontlognull
    timeout connect 5s
    timeout client 1h
    timeout server 1h

frontend idle
    bind unix@<runtime_dir>/s/idle.sock mode 600
    tcp-request connection reject

# <namespace>/<name> port <port>
frontend fe_<port_id>
    bind unix@<runtime_dir>/s/<port_id>.sock accept-proxy mode 600
    default_backend be_<port_id>

backend be_<port_id>
    server s0 <ip>:<port> weight <scaled>
    server s1 ...
```

- One `frontend`/`backend` pair per serving listener of an accepted Gateway, ordered by Gateway key, then port.
- Servers keep `backendRef` order. IPv6 addresses are written `[addr]:port`.
- The `idle` frontend is always there, so HAProxy has a listener even with nothing to serve.
- A Gateway that is not accepted contributes nothing, and its edges get no plan.

- [ ] **Step 1: Write the failing tests** in `render.rs`

```rust
#[test] fn empty_model_renders_only_the_idle_frontend() { /* equals testdata/empty.cfg with <runtime_dir> = /run/igw */ }
#[test] fn one_gateway_one_port() { /* equals testdata/one.cfg; edges[0].sockets == {tcp(5432) → /run/igw/s/<id>.sock} */ }
#[test] fn two_gateways_are_ordered_by_key_then_port() { /* equals testdata/two.cfg */ }
#[test] fn non_serving_listener_is_left_out() { /* no frontend, not in any EdgePlan.sockets */ }
#[test] fn unaccepted_gateway_contributes_nothing() { .. }
#[test] fn edge_plan_carries_the_edge_identity() { /* endpoint_id, address, gateway from the EdgeModel */ }
#[test] fn ipv6_backend_is_bracketed() { /* "server s0 [fd00::12]:5432 weight 256" */ }
#[test] fn scale_weights_examples() {
    assert_eq!(scale_weights(&[1]), vec![256]);
    assert_eq!(scale_weights(&[3, 1]), vec![256, 85]);
    assert_eq!(scale_weights(&[1_000_000, 1]), vec![256, 1]);
    assert_eq!(scale_weights(&[5, 5, 5]), vec![256, 256, 256]);
}
#[test] fn port_id_is_stable_and_short() {
    let id = port_id(&ObjRef { namespace: "gw".into(), name: "public".into() }, 5432);
    assert_eq!(id.len(), 16);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(id, port_id(&ObjRef { namespace: "gw".into(), name: "public".into() }, 5432));
}
#[test] fn long_names_give_short_socket_paths() {
    // 63-char namespace and name, runtime_dir of 70 bytes → every socket path is at most 103 bytes
}
#[test] fn render_is_deterministic() { .. }
```

And in `operator/tests/haproxy.rs`:

```rust
#[tokio::test] async fn rendered_config_passes_haproxy_validation() {
    // a model with two gateways, three ports, an IPv6 backend → Supervisor::start accepts the render
}
```

- [ ] **Step 2: Run and see them fail**

- [ ] **Step 3: Implement; write the three golden files by hand from the template above**

- [ ] **Step 4: Run the tests and lints**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(operator): render the model to an HAProxy configuration and edge plans"
```

---

### Task 9: Status

Pure functions. The clock is a parameter.

**Files:**
- Create: `operator/src/status/mod.rs`, `operator/src/status/conditions.rs`

**Interfaces:**
- Consumes: `Model` (Tasks 6, 7); `EdgeState`, `ListenerState` (Task 2); `EdgeListenerStatus` (Task 5).
- Produces:

```rust
pub struct Facts {
    pub operator_id: iroh::EndpointId,
    /// Result of the last HAProxy apply.
    pub haproxy: Result<(), String>,
    pub edges: BTreeMap<ObjRef, EdgeState>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cond { pub type_: String, pub status: bool, pub reason: String, pub message: String }

pub struct DesiredStatus {
    pub classes: Vec<ClassStatus>, pub gateways: Vec<GatewayStatusOut>,
    pub routes: Vec<RouteStatusOut>, pub edges: Vec<EdgeStatusOut>,
}
pub struct ClassStatus { pub name: String, pub generation: i64, pub conditions: Vec<Cond> }
pub struct GatewayStatusOut {
    pub key: ObjRef, pub generation: i64, pub conditions: Vec<Cond>,
    pub addresses: Vec<GatewayAddress>, pub listeners: Vec<ListenerStatusOut>,
}
pub struct ListenerStatusOut { pub name: String, pub supported_kinds: Vec<String>, pub attached_routes: i32, pub conditions: Vec<Cond> }
pub struct RouteStatusOut { pub key: ObjRef, pub generation: i64, pub parents: Vec<(ParentKey, Vec<Cond>)> }
pub struct EdgeStatusOut {
    pub key: ObjRef, pub generation: i64, pub gateway_endpoint_id: String,
    pub conditions: Vec<Cond>, pub listeners: Vec<EdgeListenerStatus>,
}
pub fn compute(model: &Model, facts: &Facts) -> DesiredStatus;

// conditions.rs
/// One Condition per desired entry, with `observedGeneration`. `lastTransitionTime` is kept from
/// `existing` when the status (True/False) of that type did not change, otherwise it is `now`.
/// Messages are truncated with `truncate_status_text`.
pub fn merge(existing: &[Condition], desired: &[Cond], generation: i64, now: Time) -> Vec<Condition>;
```

Conditions. "ready edge" means an accepted edge of the Gateway that is connected and reports every serving port of the Gateway as bound.

| Object | Type | True | False |
|---|---|---|---|
| GatewayClass | `Accepted` | `Accepted` | |
| Gateway | `Accepted` | `Accepted`, or `ListenersNotValid` when some listener is invalid | the model's reject reason |
| Gateway | `Programmed` | `Programmed`: accepted, HAProxy ok, at least one ready edge | `Invalid` (not accepted, or HAProxy refused: its message); `AddressNotAssigned` (no accepted edge); `Pending` (edges exist, none ready: say which and why) |
| Listener | `Accepted` | `Accepted` | the model's reason |
| Listener | `Conflicted` | the model's reason | `NoConflicts` |
| Listener | `ResolvedRefs` | `ResolvedRefs` | the model's reason |
| Listener | `Programmed` | `Programmed`: accepted, unconflicted, HAProxy ok, and a ready edge exists | `Invalid`; `Pending` (with an edge's bind error for this port if there is one) |
| Route parent | `Accepted` | `Accepted` | the model's reason |
| Route parent | `ResolvedRefs` | `ResolvedRefs` | the model's reason |
| Edge | `Accepted` | `Accepted` | the model's reason |
| Edge | `Connected` | `Connected` | `NotConnected`, message = `last_error` |
| Edge | `Programmed` | `Programmed`: connected, every requested port bound | `NotConnected`; `BindFailed` (port and error) |

Gateway `addresses` come from the model whether or not the edges are connected. `EdgeStatusOut.listeners` mirrors `EdgeState.listeners`. `gateway_endpoint_id` is `facts.operator_id` for every edge, accepted or not.

- [ ] **Step 1: Write the failing tests**

```rust
// status/mod.rs
#[test] fn healthy_gateway_is_programmed() { /* one gateway, one serving port, one connected edge with the port bound → all True */ }
#[test] fn no_edge_is_address_not_assigned() { /* Gateway Programmed False AddressNotAssigned; addresses empty */ }
#[test] fn disconnected_edge_keeps_addresses_and_is_pending() {
    // edge accepted, state not connected, last_error "dial timed out" → Programmed False Pending,
    // message names the edge and contains "dial timed out"; addresses == [203.0.113.7]
}
#[test] fn bind_error_shows_on_listener_and_edge() { /* Listener Programmed False Pending with the error; Edge Programmed False BindFailed */ }
#[test] fn haproxy_failure_is_invalid_everywhere() { /* facts.haproxy Err("…nope…") → Gateway and listeners Programmed False Invalid with the text */ }
#[test] fn unaccepted_gateway_reports_its_reason() { .. }
#[test] fn some_invalid_listeners_keep_the_gateway_accepted() { /* Accepted True with reason ListenersNotValid */ }
#[test] fn route_parent_conditions_follow_the_model() { .. }
#[test] fn every_edge_gets_the_operator_id() { /* also an edge with Accepted False */ }
#[test] fn one_ready_edge_is_enough() { /* two edges, one down → Gateway Programmed True */ }
#[test] fn non_serving_listener_does_not_block_readiness() { /* a listener with no route is not required to be bound */ }

// status/conditions.rs
#[test] fn new_condition_gets_now() { .. }
#[test] fn unchanged_status_keeps_its_transition_time() { /* True→True with a new message keeps the old time */ }
#[test] fn changed_status_gets_now() { .. }
#[test] fn observed_generation_is_set() { .. }
#[test] fn conditions_not_desired_are_dropped() { .. }
#[test] fn message_is_truncated() { /* 1000 chars in → at most 256 out */ }
```

- [ ] **Step 2: Run and see them fail** — `nix develop -c cargo test -p iroh-gateway-operator status::`

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run the tests and lints**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(operator): status computed from the model and runtime facts"
```

---

### Task 10: Engine

Applies a render to the running system. No Kubernetes.

**Files:**
- Create: `operator/src/engine.rs`, `operator/tests/engine.rs`
- Modify: `operator/src/lib.rs`

**Interfaces:**
- Consumes: `Supervisor`, `SupervisorOptions`, `ApplyError` (Task 4); `Rendered`, `EdgePlan` (Task 8); `HaproxyConnector` (Task 3); `EdgeLink`, `LinkOptions`, `LinkHandle`, `EdgeState` (Task 2); `Facts` (Task 9).
- Produces:

```rust
pub struct EngineOptions { pub supervisor: SupervisorOptions, pub relay: Relay }
pub struct Engine { .. }
impl Engine {
    /// Starts HAProxy with `initial.haproxy_cfg`, then applies `initial` as `apply` does.
    pub async fn start(endpoint: iroh::Endpoint, opts: EngineOptions, initial: Rendered) -> anyhow::Result<Self>;
    pub async fn apply(&mut self, rendered: Rendered);
    pub fn facts(&self) -> Facts;
    /// Resolves when any link's state changed since the last call.
    pub async fn changed(&mut self);
    /// Resolves if HAProxy ends on its own.
    pub async fn haproxy_exited(&mut self) -> std::process::ExitStatus;
    pub async fn shutdown(self);
}
```

`apply`, in order:

1. `Supervisor::apply(haproxy_cfg)`. Record the result for `facts().haproxy`.
2. Links whose edge is no longer in `rendered.edges`, or whose `endpoint_id` or `address` changed, are shut down. This happens whether or not step 1 succeeded.
3. If step 1 succeeded: every plan's connector gets its socket table, missing links are spawned, and each link's desired listeners become the plan's ports.
4. If step 1 failed: no link is spawned. Each remaining link's desired listeners and socket table are cut down to the ports that are in both the old and the new plan. Nothing is added.

One `HaproxyConnector` per link. `facts().edges` has an entry for every running link.

- [ ] **Step 1: Write the failing tests** in `operator/tests/engine.rs`

Harness: a real in-process `Edge` (as in `tests/tunnel.rs`), a real HAProxy in a short temp dir, an echo backend on `127.0.0.1`. `fn plan(..)`/`fn model(..)` helpers build a `Model` by hand with a backend at the echo address and render it with `render()`.

```rust
#[tokio::test] async fn bytes_flow_from_visitor_to_backend() {
    // start with one gateway, port p → echo; wait until facts().edges[edge] is connected with p bound;
    // connect to the edge's port p, b"hello" echoes
}
#[tokio::test] async fn adding_a_port_opens_it_after_haproxy_has_it() {
    // apply a render with a second port q → q echoes; HAProxy's q socket existed before the edge opened q
    // (assert by polling: the socket file exists at the first moment a connect to q succeeds)
}
#[tokio::test] async fn removing_a_port_closes_it() { /* q is refused (retry up to 1 s), p still echoes */ }
#[tokio::test] async fn removed_edge_loses_its_link() { /* facts().edges no longer has it; its ports are refused after the grace */ }
#[tokio::test] async fn changed_address_restarts_the_link() { /* second edge instance at another iroh port, same key → reconnects there */ }
#[tokio::test] async fn failed_haproxy_apply_adds_nothing_but_still_removes() {
    // running: ports p and q. Apply a render whose haproxy_cfg is replaced by invalid text and whose plan
    // has p and a new port r but not q → facts().haproxy is Err; r is not opened; q is closed; p still echoes
}
#[tokio::test] async fn failed_haproxy_apply_still_drops_a_removed_edge() { .. }
#[tokio::test] async fn changed_resolves_on_link_state_change() { /* stop the edge → changed() resolves within the idle timeout */ }
#[tokio::test] async fn shutdown_leaves_nothing_behind() { /* no haproxy process, links stopped, sockets removed */ }
```

- [ ] **Step 2: Run and see them fail** — `nix develop -c cargo test -p iroh-gateway-operator --test engine`

- [ ] **Step 3: Implement `engine.rs`**

- [ ] **Step 4: Run the tests**, loop `--test engine` 10 times, then the whole workspace and the lints.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(operator): engine applies HAProxy first, then the edge links"
```

---

### Task 11: Cluster glue, controller and `run`

**Files:**
- Create: `operator/src/cluster/mod.rs`, `operator/src/cluster/stores.rs`, `operator/src/cluster/identity.rs`, `operator/src/cluster/status_writer.rs`, `operator/src/controller.rs`, `operator/tests/cluster.rs`, `operator/tests/common/envtest.rs`, `scripts/envtest-assets`
- Modify: `operator/src/main.rs`, `operator/src/lib.rs`, `flake.nix` (add `setup-envtest`, `kubectl`), `.github/workflows/ci.yml` (run the ignored cluster tests with `KUBEBUILDER_ASSETS` set)

**Interfaces:**
- Consumes: everything from Tasks 2 to 10.
- Produces:

```rust
// cluster/stores.rs
pub trait SnapshotSource: Send {
    /// Resolves once every store has finished its first list.
    fn synced(&mut self) -> impl Future<Output = ()> + Send;
    fn snapshot(&self) -> Snapshot;
    /// Resolves when any store changed since the last call.
    fn changed(&mut self) -> impl Future<Output = ()> + Send;
}
pub struct Stores { .. }                       // GatewayClass, Gateway, TcpRoute, Edge, Service, Namespace; all cluster-wide
impl Stores { pub fn start(client: kube::Client) -> Self; }
impl SnapshotSource for Stores { .. }

// cluster/identity.rs
/// Reads key `secret-key` (64 hex characters) from the Secret; creates the Secret with a fresh key
/// if it does not exist. A malformed value is an error and is never overwritten.
pub async fn load_or_create(client: &kube::Client, namespace: &str, name: &str) -> anyhow::Result<iroh::SecretKey>;

// cluster/status_writer.rs
pub trait StatusSink: Send {
    fn write(&mut self, desired: &DesiredStatus, snapshot: &Snapshot) -> impl Future<Output = ()> + Send;
}
pub struct StatusWriter { .. }
impl StatusWriter { pub fn new(client: kube::Client, controller_name: String) -> Self; }
impl StatusSink for StatusWriter { .. }

// controller.rs
pub struct ControllerOptions { pub settings: Settings, pub runtime_dir: PathBuf, pub debounce: Duration /* default 200 ms */ }
pub trait Applier: Send {       // implemented by Engine
    fn apply(&mut self, rendered: Rendered) -> impl Future<Output = ()> + Send;
    fn facts(&self) -> Facts;
    fn changed(&mut self) -> impl Future<Output = ()> + Send;
    fn haproxy_exited(&mut self) -> impl Future<Output = std::process::ExitStatus> + Send;
}
/// Runs until `shutdown` resolves (Ok) or HAProxy dies (Err).
pub async fn run_loop(
    source: impl SnapshotSource, applier: impl Applier, sink: impl StatusSink,
    opts: ControllerOptions, shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()>;
```

Loop: await `synced()`. Then, forever: take a snapshot, `build`, `render`, `apply`, `compute`, `write`; wait for `source.changed()` or `applier.changed()`, then wait `debounce` more so that a burst becomes one pass. The caller starts the engine before the loop with the render of an empty model. An empty render serves nothing and has no links, so it is safe before the stores have synced.

`StatusWriter` patches the status subresource only where the desired status differs from what the snapshot's object already has (ignoring `lastTransitionTime`), using `conditions::merge` with the current time. For a `TCPRoute` it owns only the `parents` entries whose `controllerName` is ours and leaves the others in place. A failed patch is logged at warn and retried on the next pass; it never stops the loop.

`iroh-gateway-operator run`:

| Flag (env) | Default |
|---|---|
| `--namespace` (`POD_NAMESPACE`) | required |
| `--gateway-namespaces` (`IROH_GATEWAY_NAMESPACES`), comma-separated | the value of `--namespace` |
| `--controller-name` (`IROH_GATEWAY_CONTROLLER_NAME`) | `gateway.fables-for-robots.ch/iroh-gateway` |
| `--identity-secret` (`IROH_GATEWAY_IDENTITY_SECRET`) | `iroh-gateway-identity` |
| `--relay` (`IROH_GATEWAY_RELAY`) | `disabled` |
| `--runtime-dir` (`IROH_GATEWAY_RUNTIME_DIR`) | `/run/iroh-gateway` |
| `--haproxy-bin` (`IROH_GATEWAY_HAPROXY_BIN`) | `haproxy` |

It builds the client from the in-cluster configuration or the kubeconfig, loads the identity, logs the EndpointId, and exits non-zero when `run_loop` returns an error. SIGINT and SIGTERM shut down cleanly with exit 0.

`scripts/envtest-assets`: runs `setup-envtest use -p path --bin-dir target/envtest` and prints the directory. `operator/tests/common/envtest.rs`: starts `etcd` and `kube-apiserver` from `KUBEBUILDER_ASSETS` on free loopback ports with a throwaway data directory under the test's temp dir, a generated service-account key, a static bearer token and `--authorization-mode=AlwaysAllow`; returns a `kube::Client`; kills both processes on drop. It installs the `Edge` CRD from `Edge::crd()` and the Gateway API CRDs from the crate's types (`GatewayClass::crd()`, `Gateway::crd()`, `TcpRoute::crd()`), and waits until they are established.

- [ ] **Step 1: Write the failing tests**

Unit tests in `controller.rs` with fake `SnapshotSource`, `Applier` and `StatusSink` that record calls:

```rust
#[tokio::test] async fn nothing_is_applied_before_stores_sync() {
    // source.synced() pending for 300 ms while changed() fires → zero apply and zero write calls in that time;
    // after sync exactly one apply
}
#[tokio::test] async fn a_burst_of_changes_is_one_pass() { /* 20 changed() within 50 ms, debounce 200 ms → one more apply */ }
#[tokio::test] async fn link_state_change_triggers_a_status_write() { /* applier.changed() → write called with new facts */ }
#[tokio::test] async fn run_ends_with_an_error_when_haproxy_dies() { /* applier.haproxy_exited() resolves → Err */ }
#[tokio::test] async fn shutdown_ends_the_loop_cleanly() { .. }
```

Ignored tests in `operator/tests/cluster.rs` (`#[ignore = "needs KUBEBUILDER_ASSETS"]`), each with its own API server, a real HAProxy and a real in-process edge:

```rust
async fn crds_install_and_an_edge_roundtrips() { .. }
async fn identity_secret_is_created_once_and_reused() { /* two calls → same public key; the Secret has key `secret-key` */ }
async fn malformed_identity_secret_is_an_error() { /* value "abcd" → Err; the Secret is unchanged */ }
async fn gateway_route_and_edge_become_programmed() {
    // create GatewayClass, namespace gw, Gateway (TCP 5432), Service db (the API server assigns a cluster IP),
    // TCPRoute, Edge pointing at the in-process edge. Within 20 s:
    //   GatewayClass Accepted=True; Gateway Accepted=True and Programmed=True with the edge's address;
    //   listener attachedRoutes 1 and Programmed=True; route parent Accepted=True, ResolvedRefs=True,
    //   controllerName ours; Edge Accepted, Connected, Programmed all True and status.gatewayEndpointId set;
    //   a TCP connect to the edge's public port 5432 succeeds
}
async fn deleting_the_route_closes_the_port() { /* port refused; listener attachedRoutes 0; Gateway still Accepted */ }
async fn gateway_outside_the_allowed_namespaces_is_refused() { /* Accepted=False, NamespaceNotAllowed; no port opens */ }
async fn foreign_route_parent_status_is_left_alone() {
    // a TCPRoute status.parents entry written by another controllerName survives our writes
}
async fn status_is_not_rewritten_when_nothing_changed() {
    // after convergence, the Gateway's resourceVersion is the same 2 s later
}
```

- [ ] **Step 2: Run and see them fail**

Run: `nix develop -c cargo test -p iroh-gateway-operator controller::`
Then: `KUBEBUILDER_ASSETS=$(nix develop -c scripts/envtest-assets) nix develop -c cargo test -p iroh-gateway-operator --test cluster -- --ignored`

- [ ] **Step 3: Implement**

`Stores` uses `kube::runtime::watcher` with its default backoff and `reflector` stores; a watch error is logged and retried, and the stores keep their last contents meanwhile.

- [ ] **Step 4: Run everything**

Run: `nix develop -c cargo test --workspace`, the ignored cluster tests as above (loop them 5 times), fmt and clippy. Afterwards no `etcd`, `kube-apiserver` or `haproxy` process is left.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(operator): watch the cluster, reconcile, and write status"
```

---

### Task 12: Image, manifests, kind test, README

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `deploy/namespace.yaml`, `deploy/rbac.yaml`, `deploy/operator.yaml`, `deploy/gatewayclass.yaml`, `scripts/e2e-kind.sh`
- Modify: `.github/workflows/ci.yml`, `README.md`

**Interfaces:**
- Consumes: both binaries; `deploy/crd.yaml` (Task 5).
- Produces: images `iroh-gateway-operator` and `iroh-gateway-edge`; manifests that run the operator in namespace `iroh-gateway`.

`Dockerfile`: a `rust:1.100-bookworm` build stage running `cargo build --release --locked -p iroh-gateway-operator -p iroh-gateway-edge`; target `operator` from `haproxy:3.2` with the operator binary at `/usr/local/bin/iroh-gateway-operator`, `USER 65532:65532`, entrypoint `["/usr/local/bin/iroh-gateway-operator", "run"]`; target `edge` from `gcr.io/distroless/cc-debian12:nonroot` with entrypoint `["/iroh-gateway-edge"]`.

`deploy/operator.yaml`: a ServiceAccount and a one-replica Deployment, `strategy: Recreate`, `POD_NAMESPACE` from the downward API, an in-memory `emptyDir` at `/run/iroh-gateway`, `runAsNonRoot`, `readOnlyRootFilesystem`, all capabilities dropped, `seccompProfile: RuntimeDefault`.

`deploy/rbac.yaml`: a ClusterRole with `get/list/watch` on `gatewayclasses`, `gateways`, `tcproutes`, `edges`, `services`, `namespaces` and `get/patch/update` on the `/status` of the first four; a Role in `iroh-gateway` with `get/create` on `secrets`. No other Secret access.

`deploy/gatewayclass.yaml`: `GatewayClass` named `iroh-gateway` with our controller name.

`scripts/e2e-kind.sh` (expects a running kind cluster and the two images loaded into it; exits non-zero on any failure, prints operator and edge logs on failure):

1. Apply the Gateway API v1.7.0 standard CRDs from the upstream release, then `deploy/`.
2. Wait for the operator Deployment.
3. Create an edge key with `iroh-gateway-edge id` in a throwaway container, store it in a Secret, create the `Edge` resource with that id and address `edge.iroh-gateway.svc:7842`.
4. Read `.status.gatewayEndpointId` from the `Edge`; deploy the edge (a Deployment and a Service exposing UDP 7842 and TCP 8080) with `--operator <that id>`.
5. Deploy an echo server and Service, a `Gateway` with a TCP listener on 8080, and a `TCPRoute`.
6. Wait for `Gateway` `Programmed=True` and `Edge` `Connected=True`.
7. From a throwaway pod, send a line to `edge.iroh-gateway.svc:8080` and require the echo.
8. Delete the `TCPRoute`; require the connection to be refused.

CI: a job `e2e-kind` after `test`, modelled on the sibling project's job (`helm/kind-action@v1`), that builds both images, loads them and runs the script.

README: a section "Kubernetes" with what works in this step (TCP only), the install commands for `deploy/`, a worked example (the manifests the kind script uses), the `run` flag table, how to enrol an edge (the two-key exchange through `Edge.status.gatewayEndpointId`), and what the `Edge` and `Gateway` conditions mean.

- [ ] **Step 1: Write the manifests, the Dockerfile and the script**

- [ ] **Step 2: Check what can be checked without Docker**

Run: `kubectl apply --dry-run=client -f deploy/` against the API server from Task 11's harness (or `--validate=false` with `kubeconform` if that is simpler), `shellcheck scripts/e2e-kind.sh`, and `bash -n scripts/e2e-kind.sh`.
Expected: no errors. The kind test itself needs Docker; if `docker info` works, run it, otherwise say plainly in the report that it has not been run. It runs for the first time in CI.

- [ ] **Step 3: Write the README section**

- [ ] **Step 4: Run the whole suite and lints**

Run: `nix develop -c cargo test --workspace`, the ignored cluster tests, fmt, clippy.

- [ ] **Step 5: Commit and clean**

```bash
git add -A && git commit -m "feat: operator image, manifests and a kind end-to-end test"
nix develop -c cargo clean
```
