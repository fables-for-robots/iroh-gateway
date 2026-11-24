# HTTP and HTTPS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A website in the cluster is reachable through an edge over HTTP and HTTPS: the operator accepts `HTTP` and `HTTPS` listeners and `HTTPRoute`s, terminates TLS in HAProxy with certificates from Secrets, routes by host, path, method and header, and applies redirects and header filters.

**Architecture:** The pipeline of step 2 stays: cluster state → model → HAProxy configuration and edge plans → status, with the model, render and status steps pure. The model gains certificates, HTTP rules in matching order and one `HttpPort` per shared port; the render turns each into an HTTP-mode frontend with one backend section per route rule. Certificates reach HAProxy as files whose names contain a hash of their content, so a rotated certificate changes the configuration text and the existing "reload when the text changes" rule covers it.

**Tech Stack:** Rust 2024 (1.100), tokio, kube 5.1, k8s-openapi 0.29, gateway-api 0.23 (Gateway API v1.7.0), rustls 0.23 (ring), HAProxy 3.x. Tests add `tokio-rustls` 0.26 as a dev-dependency; `rcgen` 0.14 is already one.

**Spec:** `docs/superpowers/specs/2026-11-23-iroh-gateway-design.md`. This plan implements build step 3 of 5 ("HTTP and HTTPS"). UDP is step 4; the Helm chart, metrics and release packaging are step 5.

## Global Constraints

- Rust edition 2024, `rust-version = "1.100"`. Run every cargo command through the flake: `nix develop -c cargo …`.
- Work on the branch `http-routes`, not on `main`. Never push.
- Gateway API types come from the `gateway_api` crate root re-exports: `gateway_api::httproutes::v1::HttpRoute` beside the existing `gateways::v1::Gateway` and `tcproutes::v1::TcpRoute`. Do not add a second `kube` or `k8s-openapi`.
- Supported, and nothing else:
  - listeners `TCP`, `HTTP`, `HTTPS` (`tls.mode: Terminate`, `certificateRefs` to `kubernetes.io/tls` Secrets);
  - `HTTPRoute` hostnames; matches on path (`Exact`, `PathPrefix`), headers (exact) and method; weighted `backendRefs` to Services; rule filters `RequestRedirect` (scheme, hostname, port, status code), `RequestHeaderModifier`, `ResponseHeaderModifier`.
- An `HTTPRoute` that uses anything the operator cannot honour is refused whole: `Accepted=False`, reason `UnsupportedValue`, with a message naming the first such thing. Nothing is silently ignored, because an ignored match would send requests somewhere the author did not intend.
- Cross-namespace `backendRefs` and `certificateRefs` are refused with `ResolvedRefs=False`, reason `RefNotPermitted`.
- One protocol per port on a Gateway. `HTTP` listeners with different hostnames may share a port; so may `HTTPS` listeners. Any other mix on one port is `Conflicted`.
- No matching route answers 404. A rule with no usable backend answers 500.
- TLS: strict SNI, TLS 1.2 minimum, ALPN `h2,http/1.1`. `X-Forwarded-For` and `X-Forwarded-Proto` are set by HAProxy, replacing whatever the visitor sent.
- **Configuration injection.** Every string that comes from a cluster resource and is written into `haproxy.cfg` goes through the one quoting function of Task 7. Independently of that, the model refuses resource strings that contain control characters.
- **Key material.** A private key is never logged, never part of a `Debug` output, a `Reject` message or a status message. On disk it exists only as a file of mode 0600 in a directory of mode 0700 under the runtime directory, and is removed when HAProxy stops.
- Secrets are read only in the namespaces the operator is configured with, and only those of type `kubernetes.io/tls`.
- One unusable certificate or route must not affect any other listener, Gateway or route.
- Carried over from step 2 and still binding: HAProxy binds no TCP port and is never left running a configuration that failed validation; an edge port never opens before HAProxy serves it; nothing is applied before every watch store has listed once; the render is byte-for-byte stable for equal models.
- Tests that need `haproxy` find it on `PATH`. Tests that need an API server are `#[ignore = "needs KUBEBUILDER_ASSETS"]`.
- All non-ignored tests pass on macOS and Linux, on loopback only, with pristine output, and leave no process, port or file behind. Free ports come in random order on Linux: a test never assumes an order among ports it obtained.
- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` are clean at every commit. No new `unsafe`.
- Build output stays under `target/`. Run `cargo clean` when the last task is done.

## Review Focus

Conditions the spec implies that are most likely to bite a real user. Each has a test in the task named.

1. A route author puts quotes, `%`, `#`, `$` or a line break into a header value, path or hostname. It must reach the backend byte for byte or be refused; it must never become a configuration directive. (Task 4, `control_characters_refuse_the_route`; Task 7, `hostile_strings_cannot_inject_configuration`)
2. One Secret holds a certificate whose key does not match, or garbage. Only the listener that refers to it may stop serving; every other listener and Gateway keeps working and keeps reloading. (Task 3, `mismatched_key_refuses_only_that_listener`; Task 7, `a_listener_without_certificates_does_not_break_its_port`)
3. A private key ends up somewhere readable: a log line through `{:?}`, a status message, a world-readable file, or a file left behind after the operator stops. (Task 3, `debug_output_never_contains_key_material`, `reject_messages_never_contain_key_material`; Task 6, `certificate_files_are_private`, `shutdown_removes_certificate_files`)
4. `PathPrefix: /foo` must match `/foo` and `/foo/bar` and must not match `/foobar`; a `Host` header in upper case or with a port must still match. (Task 7, `prefix_matches_whole_path_elements`, `host_header_with_port_and_upper_case_still_matches`)
5. cert-manager renews a certificate: the Secret changes while everything else stays. The new certificate must be served after one reload and the old file must be gone. (Task 6, `unreferenced_files_are_removed_after_a_successful_apply`; Task 7, `rotated_certificate_is_served_after_apply`; Task 9, the rotation step of the kind test)

## Not in this plan

- `ReferenceGrant`, `TLSRoute`, `GRPCRoute`, URL rewrites, request mirroring, CORS, regular-expression and query-parameter matches, per-route timeouts and retries, redirect path changes, backend TLS, HTTP/3.
- A finalizer on `GatewayClass` (it needs write access beyond status, which step 2 deliberately removed) and killing HAProxy when the operator is SIGKILLed outside a container (inside the pod the operator is PID 1, so the container ends with it). Both stay open from step 2.
- Metrics, the Helm chart, cert-manager and external-dns walkthroughs: step 5.

## File Structure

```
operator/src/
  model/mod.rs            + RouteKind, ParentRef, ParentStatus, RouteResource; Snapshot.http_routes, .secrets
  model/routes.rs         TCPRoute; shared parent and backend handling
  model/gateways.rs       listeners: protocols, hostnames, port sharing
  model/http.rs           NEW  HostMatch, HTTP rule types, HttpPort, matching order
  model/certs.rs          NEW  certificateRefs → Certificate
  model/http_routes.rs    NEW  HTTPRoute: validation, attachment
  model/fixtures.rs       + builders for HTTPRoute and TLS Secrets
  status/mod.rs           route kind in the output; HTTPS listeners without certificates
  cluster/status_writer.rs  one writer for both route kinds
  cluster/stores.rs       + HTTPRoute watch, TLS Secret watch per gateway namespace
  haproxy/mod.rs          + SecretFile
  haproxy/supervisor.rs   apply(cfg, files): certificate directory
  haproxy/render.rs       HTTP and HTTPS frontends, quoting
  haproxy/testdata/       + http.cfg, https.cfg; the three existing files regenerated
  engine.rs               passes files to the supervisor
operator/tests/
  http.rs                 NEW  rendered configuration against a real HAProxy
  haproxy.rs, engine.rs   + file handling
  cluster.rs, common/envtest.rs   + HTTPRoute CRD, HTTP and HTTPS cases
deploy/rbac.yaml          + httproutes, TLS Secret list/watch
scripts/e2e-kind.sh       + HTTP, HTTPS, redirect, rotation
README.md, docs/superpowers/specs/2026-11-23-iroh-gateway-design.md
```

---

### Task 1: Two route kinds through the model types, status and the writer

A refactor plus the plumbing an `HTTPRoute` needs to receive status. No `HTTPRoute` is attached yet.

**Files:**
- Modify: `operator/src/model/mod.rs`, `operator/src/model/routes.rs`, `operator/src/model/fixtures.rs`, `operator/src/status/mod.rs`, `operator/src/cluster/status_writer.rs`, `operator/src/cluster/stores.rs` (construct `Snapshot` with `..Default::default()` for the new fields)

**Interfaces:**
- Consumes: the existing `ParentKey`, `RouteModel`, `RouteStatusOut`, `route_patch`.
- Produces:

```rust
// model/mod.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RouteKind { Tcp, Http }
impl RouteKind { pub fn as_str(self) -> &'static str }        // "TCPRoute", "HTTPRoute"

/// A `parentRef`, in a route's spec or in its status, as written. Absent fields are not serialised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParentRef {
    pub group: Option<String>, pub kind: Option<String>, pub namespace: Option<String>,
    pub name: String, pub section_name: Option<String>, pub port: Option<i32>,
}

/// One entry of a route's `status.parents`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParentStatus { pub parent_ref: ParentRef, pub controller_name: String, pub conditions: Vec<Condition> }

/// What the model and the status writer need from a route resource.
pub trait RouteResource:
    kube::Resource<DynamicType = ()> + Clone + DeserializeOwned + Debug + Send + Sync + 'static
{
    const KIND: RouteKind;
    fn parent_refs(&self) -> Vec<ParentRef>;
    fn status_parents(&self) -> Vec<ParentStatus>;
}
impl RouteResource for TcpRoute { .. }
impl RouteResource for HttpRoute { .. }

pub(crate) fn parent_key(parent: &ParentRef, route_ns: &str) -> Option<ParentKey>;   // was over TcpRouteParentRefs

pub struct Snapshot { .., pub http_routes: Vec<HttpRoute>, pub secrets: Vec<Secret> }
pub struct RouteModel { pub kind: RouteKind, pub key: ObjRef, pub generation: i64, pub parents: Vec<RouteParent> }
// Model.routes is sorted by (kind, key).

// model/routes.rs, for Task 4
pub(super) struct BackendRef<'a> { pub group: Option<&'a str>, pub kind: Option<&'a str>, pub namespace: Option<&'a str>,
                                   pub name: &'a str, pub port: Option<i32>, pub weight: Option<i32> }
pub(super) fn backend(b: &BackendRef<'_>, route_ns: &str, services: &BTreeMap<ObjRef, &Service>) -> Result<Option<Backend>, Reject>;
/// The listeners of `gw` a route of `kind` from `route_ns` may attach to through `parent`:
/// `NoMatchingParent` or `NotAllowedByListeners` otherwise. The checks `attach` makes today, minus the rule count.
pub(super) fn admitted(kind: RouteKind, route_ns: &str, parent: &ParentKey, gw: &GatewayModel,
                       namespaces: &BTreeMap<String, Labels>) -> Result<Vec<usize>, Reject>;

// status/mod.rs
pub struct RouteStatusOut { pub kind: RouteKind, pub key: ObjRef, pub generation: i64, pub parents: Vec<(ParentKey, Vec<Cond>)> }
```

Status writer: `route_patch` becomes generic over `R: RouteResource` and builds `Vec<ParentStatus>`; `patches` runs it over `snapshot.tcp_routes` and `snapshot.http_routes`, looking the desired status up by `(R::KIND, key)`. `Target::TcpRoute(ObjRef)` becomes `Target::Route(RouteKind, ObjRef)`, displayed as `TCPRoute ns/name` or `HTTPRoute ns/name`, and `send` picks the `Api` type from the kind. Everything `route_patch` does today holds for both kinds: entries of other controllers stay in place, ours are updated in place, ours that are no longer desired are removed, the patch carries `resourceVersion`.

- [ ] **Step 1: Write the failing tests**

```rust
// model/mod.rs
#[test] fn parent_ref_serialises_like_the_api() {
    // only `name` set → {"name":"gw"}; all set → keys group, kind, namespace, name, sectionName, port
}
#[test] fn tcp_and_http_routes_expose_their_parent_refs() { /* parent_refs() equals what the spec holds, in order */ }
#[test] fn status_parents_roundtrip() { /* a route with two status entries → two ParentStatus, fields equal */ }

// status/mod.rs
#[test] fn route_status_carries_its_kind() { .. }

// cluster/status_writer.rs — each existing TCPRoute test of route_patch gets an HTTPRoute twin:
#[test] fn http_route_gets_our_parent_entry() { .. }
#[test] fn stale_entry_of_ours_is_removed_from_an_http_route() { /* route in the snapshot, not in desired */ }
#[test] fn foreign_entries_on_an_http_route_stay_in_place() { .. }
#[test] fn unchanged_http_route_needs_no_patch() { .. }
#[test] fn tcp_and_http_routes_with_the_same_name_are_told_apart() {
    // desired holds only (Tcp, apps/web); the snapshot has a TCPRoute and an HTTPRoute apps/web:
    // exactly one patch, for the TCPRoute
}
```

- [ ] **Step 2: Run them.** `nix develop -c cargo test -p iroh-gateway-operator --lib` — expected: compile errors for the missing items.
- [ ] **Step 3: Implement.** The existing tests of `model::routes`, `status` and `status_writer` must pass with only mechanical changes (a `kind` field, the new argument types).
- [ ] **Step 4: Run** `nix develop -c cargo test --workspace` — expected: all pass.
- [ ] **Step 5: Commit** — `refactor(operator): route kinds share parent, backend and status handling`

---

### Task 2: Listeners — HTTP, HTTPS, hostnames, port sharing

**Files:**
- Create: `operator/src/model/http.rs` (only `HostMatch` in this task)
- Modify: `operator/src/model/mod.rs`, `operator/src/model/gateways.rs`, `operator/src/model/fixtures.rs` (`GatewayExt`: a hostname and a `tls` on a listener), every `ListenerModel { .. }` literal in tests (`hostname: HostMatch::Any`)

**Interfaces:**
- Produces:

```rust
// model/http.rs
/// Which request hosts a listener or a route answers for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostMatch {
    Any,
    Exact(String),          // lower case
    /// `*.example.com`, held as the suffix `.example.com`. Matches hosts with at least one more label.
    Wildcard(String),
}
impl HostMatch {
    /// `None` and `""` give `Any`. Lower-cases. `Err` (a message) unless the rest is a DNS name of
    /// labels `[a-z0-9-]` (1 to 63 characters, not starting or ending with `-`, at most 253 in all),
    /// optionally after `*.`. An IP address is an error.
    pub fn parse(hostname: Option<&str>) -> Result<Self, String>;
    /// What both match: the more specific of the two, or `None` when no host matches both.
    pub fn intersect(&self, other: &HostMatch) -> Option<HostMatch>;
}

// model/mod.rs
pub struct ListenerModel { .., pub hostname: HostMatch }      // always Any for TCP
impl ListenerModel {
    pub fn serving(&self) -> bool;   // see below
}
```

Rules for one listener:

| Protocol | `supported_kinds` | Extra checks |
|---|---|---|
| `TCP` | `TCPRoute` | `hostname` is ignored |
| `HTTP` | `HTTPRoute` | `hostname` parsed |
| `HTTPS` | `HTTPRoute` | `hostname` parsed; `tls.mode: Passthrough` → `Accepted=False`, reason `UnsupportedProtocol`, message `tls.mode Passthrough is not supported; only Terminate is` |
| anything else | none | `Accepted=False`, reason `UnsupportedProtocol`, message `protocol "<p>" is not supported; TCP, HTTP and HTTPS are` |

- A hostname `HostMatch::parse` refuses gives `Accepted=False`, reason `UnsupportedValue`, with the parse message.
- `allowedRoutes.kinds`, when not empty: `supported_kinds` keeps the listed kinds that are the protocol's kind in group `gateway.networking.k8s.io`, without repeats. If any listed kind is not that, `ResolvedRefs=False`, reason `InvalidRouteKinds`. The listener still works with the kinds it keeps. (Today a list that contains `TCPRoute` and something else is reported as fine; the Gateway API asks for `False`.)
- An invalid port keeps its own rejection, as today.

Sharing a port (ports stored as 0 share nothing, as today):

- Listeners with different protocols on one port: all `Conflicted`, reason `ProtocolConflict` (unchanged).
- Several `HTTP` listeners, or several `HTTPS` listeners, on one port: those whose `hostname` equals another's are `Conflicted`, reason `HostnameConflict`, message `several listeners use port <port> with hostname <hostname or "(any)">`. The others are not conflicted.
- Several listeners of any other single protocol on one port: all `HostnameConflict` (unchanged).

`serving()`: accepted, not conflicted, and

- `TCP`: at least one backend (unchanged);
- `HTTP`: `attached_routes > 0`. A route can answer without a backend (a redirect), so the port opens once a route is attached;
- `HTTPS`: `false` in this task. Task 3 makes it "`attached_routes > 0` and it has certificates".

- [ ] **Step 1: Write the failing tests**

```rust
// model/http.rs
#[test] fn host_match_parse() {
    assert_eq!(HostMatch::parse(None), Ok(HostMatch::Any));
    assert_eq!(HostMatch::parse(Some("")), Ok(HostMatch::Any));
    assert_eq!(HostMatch::parse(Some("Example.COM")), Ok(HostMatch::Exact("example.com".into())));
    assert_eq!(HostMatch::parse(Some("*.Example.com")), Ok(HostMatch::Wildcard(".example.com".into())));
    for bad in ["*", "*.", "a.*.com", "10.0.0.1", "exa mple.com", "example.com.", "-a.com", "a..com", "ex'ample.com"] {
        assert!(HostMatch::parse(Some(bad)).is_err(), "{bad}");
    }
}
#[test] fn host_match_intersect() {
    let (any, a, wild) = (HostMatch::Any, exact("a.example.com"), wildcard(".example.com"));
    assert_eq!(any.intersect(&a), Some(a.clone()));
    assert_eq!(a.intersect(&wild), Some(a.clone()));
    assert_eq!(wild.intersect(&a), Some(a.clone()));
    assert_eq!(exact("example.com").intersect(&wild), None);          // a wildcard needs one more label
    assert_eq!(wildcard(".a.example.com").intersect(&wild), Some(wildcard(".a.example.com")));
    assert_eq!(wild.intersect(&wildcard(".example.org")), None);
    assert_eq!(a.intersect(&exact("b.example.com")), None);
    assert_eq!(any.intersect(&any), Some(HostMatch::Any));
}

// model/gateways.rs
#[test] fn http_listener_is_accepted_and_supports_http_routes() { .. }
#[test] fn https_listener_is_accepted() { .. }
#[test] fn tls_and_udp_listeners_are_unsupported() { /* message names TCP, HTTP and HTTPS */ }
#[test] fn https_with_passthrough_is_refused() { .. }
#[test] fn hostname_is_lower_cased() { .. }
#[test] fn tcp_listener_ignores_its_hostname() { .. }
#[test] fn invalid_hostname_refuses_the_listener() { /* UnsupportedValue */ }
#[test] fn http_listeners_with_different_hostnames_share_a_port() { /* neither conflicted; the Gateway is accepted */ }
#[test] fn http_listeners_with_the_same_hostname_conflict() { /* a, a, b on one port: both a conflicted, b not */ }
#[test] fn two_http_listeners_without_hostname_conflict() { .. }
#[test] fn http_and_https_on_one_port_conflict() { /* ProtocolConflict, both */ }
#[test] fn tcp_and_http_on_one_port_conflict() { .. }
#[test] fn two_tcp_listeners_on_one_port_still_conflict() { .. }
#[test] fn allowed_kinds_with_an_unsupported_kind_keep_the_supported_one() {
    // TCP listener, kinds [TCPRoute, HTTPRoute]: ResolvedRefs False InvalidRouteKinds, supported_kinds == ["TCPRoute"]
}
#[test] fn allowed_kinds_of_another_group_are_invalid() { .. }
#[test] fn http_listener_serves_once_a_route_is_attached() { /* attached_routes 0 → false, 1 → true */ }
#[test] fn https_listener_does_not_serve_yet() { .. }
```

- [ ] **Step 2: Run them** — `nix develop -c cargo test -p iroh-gateway-operator --lib model::` — expected: fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `nix develop -c cargo test --workspace` — expected: all pass. Existing listener tests that asserted `UnsupportedProtocol` for `HTTP` now use `UDP`.
- [ ] **Step 5: Commit** — `feat(operator): HTTP and HTTPS listeners, hostnames and port sharing`

---

### Task 3: Certificates

**Files:**
- Create: `operator/src/model/certs.rs`
- Modify: `operator/src/model/mod.rs`, `operator/src/model/gateways.rs`, `operator/src/model/fixtures.rs` (`tls_secret(ns, name, crt_pem, key_pem) -> Secret`, and a test helper that makes a certificate and key with `rcgen`), `operator/src/status/mod.rs`

**Interfaces:**
- Consumes: `Snapshot.secrets` (Task 1), `ListenerModel` (Task 2).
- Produces:

```rust
// model/certs.rs
/// A certificate chain with its private key, as HAProxy reads it.
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    pub secret: ObjRef,
    /// See `file_name`.
    pub file_name: String,
    /// `tls.crt`, then `tls.key`, each ending in exactly one newline. Key material.
    pub pem: String,
}
impl fmt::Debug for Certificate { /* prints `secret` and `file_name` only */ }

/// `<the first 80 characters of "<namespace>.<name>", every character outside [a-z0-9.-] replaced by '_'>`
/// `.<the first 16 hex characters of SHA-256 over pem>.pem`
pub(crate) fn file_name(secret: &ObjRef, pem: &str) -> String;

/// The certificates of an HTTPS listener's `certificateRefs`, in order, when every one is usable.
pub(super) fn resolve(tls: Option<&GatewayListenersTls>, gateway_ns: &str,
                      secrets: &BTreeMap<ObjRef, &Secret>) -> Result<Vec<Certificate>, Reject>;

// model/mod.rs
pub struct ListenerModel { .., pub certificates: Vec<Certificate> }   // empty unless HTTPS with every ref usable
```

Reasons, all on the listener's `ResolvedRefs`. A certificate problem replaces an `InvalidRouteKinds` already there, because it is the one that stops the listener.

| Condition | Reason |
|---|---|
| no `tls`, or no `certificateRefs` | `InvalidCertificateRef`: `an HTTPS listener needs at least one certificateRef` |
| a ref whose group is not empty or whose kind is not `Secret` | `InvalidCertificateRef` |
| a ref with a `namespace` other than the Gateway's | `RefNotPermitted` |
| Secret not in the snapshot | `InvalidCertificateRef`: `secret <ns>/<name> not found` |
| Secret type is not `kubernetes.io/tls` | `InvalidCertificateRef` |
| `tls.crt` or `tls.key` missing, not UTF-8, without a certificate, or without exactly one private key | `InvalidCertificateRef` |
| key of a type rustls with ring cannot use | `InvalidCertificateRef`: `secret <ns>/<name>: unsupported private key type` |
| key does not belong to the first certificate | `InvalidCertificateRef`: `secret <ns>/<name>: the private key does not match the certificate` |

Check with rustls, which is already a dependency: `rustls::pki_types::pem::PemObject` to parse (`CertificateDer::pem_slice_iter`, `PrivateKeyDer::from_pem_slice`), `rustls::crypto::ring::sign::any_supported_type` for the key, and `rustls::sign::CertifiedKey::new(chain, key).keys_match()`; any `Err` from `keys_match` refuses the Secret. A message is built from the Secret's name and a fixed text, never from the Secret's data or from an error that could quote it.

`serving()` for `HTTPS` becomes: `attached_routes > 0 && !certificates.is_empty()`.

Status (`status/mod.rs`): an `HTTPS` listener that is accepted and not conflicted but has no certificates is `Programmed=False`, reason `Invalid`, with the `ResolvedRefs` message. This comes before the checks of HAProxy and the edges.

- [ ] **Step 1: Write the failing tests**

```rust
// model/certs.rs
#[test] fn valid_secret_gives_one_certificate() {
    // pem == crt + key; file_name == format!("gw.site-tls.{}.pem", <16 hex>)
}
#[test] fn file_name_is_stable_and_changes_with_the_content() { .. }
#[test] fn long_names_are_cut() { /* a 253-character Secret name: file_name.len() <= 80 + 1 + 16 + 4 */ }
#[test] fn odd_characters_in_names_become_underscores() { /* file_name(&ObjRef::new("a/b", "c d"), "x") has no '/' or ' ' */ }
#[test] fn missing_certificate_refs_are_invalid() { .. }
#[test] fn secret_in_another_namespace_is_not_permitted() { /* even when that Secret is in the snapshot */ }
#[test] fn ref_to_another_kind_is_invalid() { .. }
#[test] fn missing_secret_is_invalid() { .. }
#[test] fn wrong_secret_type_is_invalid() { .. }
#[test] fn missing_tls_key_is_invalid() { .. }
#[test] fn garbage_pem_is_invalid() { .. }
#[test] fn two_private_keys_are_invalid() { .. }
#[test] fn mismatched_key_refuses_only_that_listener() {
    // one Gateway with listeners a (good Secret) and b (key of another certificate), a second Gateway with a good one:
    // b: ResolvedRefs False InvalidCertificateRef, certificates empty; a and the other Gateway: certificates.len() == 1
}
#[test] fn one_bad_ref_among_two_refuses_the_listener() { .. }
#[test] fn two_valid_refs_give_two_certificates_in_ref_order() { .. }
#[test] fn ecdsa_p256_p384_and_ed25519_keys_are_accepted() { .. }
#[test] fn certificate_problem_replaces_invalid_route_kinds() { .. }
#[test] fn reject_messages_never_contain_key_material() { /* for every failing case above: no "PRIVATE KEY", no line of the key */ }
#[test] fn debug_output_never_contains_key_material() {
    // format!("{:?}", build(..)) of a model with a certificate: no "PRIVATE KEY", no line of the key's base64
}
#[test] fn https_listener_with_certificates_serves_once_a_route_is_attached() { .. }

// status/mod.rs
#[test] fn https_listener_without_usable_certificates_is_not_programmed() {
    // with a connected edge and HAProxy fine: Programmed False, reason "Invalid", message == the ResolvedRefs message
}
```

- [ ] **Step 2: Run them** — expected: fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `nix develop -c cargo test --workspace` — expected: all pass.
- [ ] **Step 5: Commit** — `feat(operator): certificates of HTTPS listeners from TLS Secrets`

---

### Task 4: HTTPRoute — validation and attachment

**Files:**
- Create: `operator/src/model/http_routes.rs`
- Modify: `operator/src/model/http.rs` (rule types), `operator/src/model/mod.rs` (`build`), `operator/src/model/fixtures.rs` (`http_route(ns, name)` and an `HttpRouteExt` in the style of the TCPRoute builders)

**Interfaces:**
- Consumes: `admitted`, `backend`, `BackendRef`, `parent_key` (Task 1); `HostMatch`, `ListenerModel.hostname` (Task 2).
- Produces:

```rust
// model/http.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathMatch { Exact(String), /** Never ends in '/', except "/" itself. */ Prefix(String) }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMatch {
    pub path: PathMatch,                      // Prefix("/") when the match names no path
    pub method: Option<String>,               // upper case
    pub headers: Vec<(String, String)>,       // names lower case, sorted by name
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderMods { pub set: Vec<(String, String)>, pub add: Vec<(String, String)>, pub remove: Vec<String> }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect { pub scheme: Option<String>, pub hostname: Option<String>, pub port: Option<u16>, pub status: u16 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpAction { Forward(Vec<Backend>), Redirect(Redirect), /** Answers 500. */ Fail }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRouteRule {
    pub matches: Vec<HttpMatch>,              // never empty: a rule without matches matches Prefix("/")
    pub request_headers: HeaderMods,
    pub response_headers: HeaderMods,
    pub action: HttpAction,
}

// model/http_routes.rs
/// One accepted route on one listener.
pub(super) struct Attached {
    pub slot: (usize, usize),                 // gateway index, listener index
    pub route: ObjRef,
    pub created: Option<Time>,
    /// Listener hostname ∩ each route hostname, without repeats. Never empty.
    pub hosts: Vec<HostMatch>,
    pub rules: Vec<HttpRouteRule>,
}
/// The route's rules, or the first thing in it the operator cannot honour.
pub(super) fn translate(route: &HttpRoute, services: &BTreeMap<ObjRef, &Service>)
    -> (Result<Vec<HttpRouteRule>, Reject>, Result<(), Reject> /* ResolvedRefs */);
/// Every HTTPRoute that names one of our gateways, by key; adds to `attached_routes` of the listeners.
pub(super) fn routes(snapshot: &Snapshot, gateways: &mut [GatewayModel]) -> (Vec<RouteModel>, Vec<Attached>);
```

`build` appends these `RouteModel`s to the TCP ones and sorts by `(kind, key)`. It drops the `Vec<Attached>` in this task; Task 5 uses it.

**Translation.** A route is refused whole (`UnsupportedValue`, message naming the rule index and the thing) on the first of:

- a path match of type `RegularExpression`; a path that does not start with `/`;
- a header match of type `RegularExpression`; any `queryParams` match;
- a filter of a type other than `RequestHeaderModifier`, `ResponseHeaderModifier`, `RequestRedirect`; two filters of the same type in one rule;
- a `RequestRedirect` with a `path`; a `RequestRedirect` in a rule that also has `backendRefs`; a redirect hostname `HostMatch::parse` does not accept as an exact name;
- a `backendRef` with `filters`; a rule with `timeouts` or `retry`;
- a header name, in a match or a filter, outside `[A-Za-z0-9_-]+`;
- a control character (a byte below 0x20, or 0x7f) in any path, header value or hostname;
- a route hostname `HostMatch::parse` refuses.

Otherwise:

- A prefix path loses its trailing `/` (`/foo/` → `/foo`); `/` stays.
- Redirect `status` is the filter's code (301, 302, 303, 307 or 308), 302 when absent.
- Backends are resolved exactly as for `TCPRoute`, through `backend`. The first problem becomes the route's `ResolvedRefs`; a backend with a problem or weight 0 is left out.
- A rule's action: `Redirect` if it has the filter; else `Forward` with its usable backends; else, with none, `Fail`.

**Attachment**, per `parentRef` that names one of our Gateways (repeats ignored), in this order:

1. `admitted(RouteKind::Http, ..)` — `NoMatchingParent` or `NotAllowedByListeners`.
2. Keep the listeners whose `hostname` intersects at least one route hostname (every listener, when the route has none). None left: `Accepted=False`, reason `NoMatchingListenerHostname`.
3. The translation result: `UnsupportedValue`.
4. Accepted. For each kept listener one `Attached`, and its `attached_routes` goes up by one. A route counts once per listener however many of its `parentRef`s reach it.

- [ ] **Step 1: Write the failing tests** in `http_routes.rs`

```rust
// translation
#[test] fn rule_without_matches_matches_every_path() { /* [HttpMatch { path: Prefix("/"), method: None, headers: [] }] */ }
#[test] fn exact_and_prefix_paths_are_kept() { .. }
#[test] fn prefix_loses_its_trailing_slash() { /* "/foo/" → Prefix("/foo"); "/" → Prefix("/") */ }
#[test] fn header_names_are_lower_cased_and_sorted() { .. }
#[test] fn method_is_upper_case() { .. }
#[test] fn weighted_backends_are_resolved() { .. }
#[test] fn rule_with_only_bad_backends_fails() { /* action == Fail; ResolvedRefs False BackendNotFound */ }
#[test] fn rule_without_backends_or_redirect_fails() { .. }
#[test] fn bad_backend_among_good_ones_is_left_out() { /* Forward([good]); ResolvedRefs False */ }
#[test] fn cross_namespace_backend_is_not_permitted() { .. }
#[test] fn redirect_defaults_to_302() { .. }
#[test] fn redirect_keeps_scheme_hostname_port_and_code() { .. }
#[test] fn header_modifiers_are_kept_in_order() { /* set, add, remove of request and response */ }
#[test] fn unsupported_things_refuse_the_route() {
    // one case each: regex path, regex header, query param, URLRewrite, RequestMirror, CORS, ExtensionRef,
    // two RequestHeaderModifier filters, redirect with a path, redirect beside backendRefs,
    // backendRef filters, timeouts, retry, header name "x y", path "foo".
    // Each: Err with reason "UnsupportedValue" and a message containing "rule 0"
}
#[test] fn control_characters_refuse_the_route() {
    // "\n", "\r", "\0", "\x7f" in: a path, a match header value, a set-header value, a redirect hostname
}

// attachment
#[test] fn http_route_attaches_to_an_http_listener() { /* Accepted True, attached_routes == 1, one Attached */ }
#[test] fn two_routes_attach_to_one_listener() { /* attached_routes == 2 */ }
#[test] fn route_reaching_a_listener_through_two_parent_refs_counts_once() { .. }
#[test] fn route_attaches_to_every_listener_of_the_gateway_without_section_name() { .. }
#[test] fn http_route_is_not_allowed_on_a_tcp_listener() { /* NotAllowedByListeners */ }
#[test] fn tcp_route_is_not_allowed_on_an_http_listener() { .. }
#[test] fn route_from_a_namespace_the_listener_does_not_admit_is_refused() { .. }
#[test] fn hostnames_intersect_with_the_listener() {
    // listener *.example.com; route [a.example.com, b.example.org, *.example.com]:
    // hosts == [Exact("a.example.com"), Wildcard(".example.com")]
}
#[test] fn route_without_hostnames_takes_the_listeners() { /* hosts == [listener.hostname] */ }
#[test] fn route_with_no_common_hostname_is_refused() { /* NoMatchingListenerHostname; attached_routes == 0 */ }
#[test] fn route_attaches_only_to_listeners_whose_hostname_matches() { .. }
#[test] fn refused_route_is_not_counted() { /* UnsupportedValue: attached_routes == 0, no Attached */ }
#[test] fn refused_route_still_reports_resolved_refs() { .. }
#[test] fn route_naming_a_foreign_gateway_is_not_in_the_model() { .. }
#[test] fn tcp_and_http_routes_are_sorted_by_kind_then_key() { .. }
```

- [ ] **Step 2: Run them** — expected: fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `nix develop -c cargo test --workspace` — expected: all pass.
- [ ] **Step 5: Commit** — `feat(operator): HTTPRoute validation and attachment`

---

### Task 5: HTTP ports — rules in matching order

**Files:**
- Modify: `operator/src/model/http.rs`, `operator/src/model/mod.rs` (`GatewayModel.http_ports`, `build`), every `GatewayModel { .. }` literal in tests (`http_ports: Vec::new()`)

**Interfaces:**
- Consumes: `Attached` (Task 4), `Certificate` (Task 3), `ListenerModel::serving`.
- Produces:

```rust
// model/http.rs
/// One port of a Gateway that serves HTTP or HTTPS, for all its serving listeners together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPort {
    pub port: u16,
    /// HTTPS: the certificates of the port's serving listeners, without repeats, sorted by file name.
    /// `None` for HTTP.
    pub tls: Option<Vec<Certificate>>,
    /// In the order to try: the first rule that matches a request decides.
    pub rules: Vec<HttpRule>,
    /// What rules point at: one per attached route rule, ordered by (route key, rule index).
    pub backends: Vec<HttpBackend>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRule { pub host: HostMatch, pub path: PathMatch, pub method: Option<String>,
                      pub headers: Vec<(String, String)>, pub backend: usize }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBackend { pub route: ObjRef, pub rule: usize, pub request_headers: HeaderMods,
                         pub response_headers: HeaderMods, pub action: HttpAction }

/// Fills `http_ports` of every gateway: its ports with a serving HTTP or HTTPS listener, ascending.
pub(super) fn ports(gateways: &mut [GatewayModel], attached: Vec<Attached>);

// model/mod.rs
pub struct GatewayModel { .., pub http_ports: Vec<HttpPort> }
```

Only `serving()` listeners contribute. One `HttpRule` per (serving listener of the port, attached route, host in `hosts`, rule, match). Rules are ordered by, in turn:

1. host: `Exact` first, then `Wildcard` with the longer suffix first, then `Any`;
2. path: `Exact` before `Prefix`;
3. among prefixes, the longer first (in characters);
4. a method before none;
5. more header matches first;
6. the older route first (`created`; a route without a creation time last);
7. route key;
8. rule index, then match index.

Of two rules with equal host, path, method and headers, only the first in this order is kept.

- [ ] **Step 1: Write the failing tests** in `http.rs`

```rust
#[test] fn gateway_without_http_listeners_has_no_http_ports() { .. }
#[test] fn listener_without_routes_gives_no_port() { .. }
#[test] fn one_route_gives_one_rule_and_one_backend() { .. }
#[test] fn each_match_and_each_host_gives_a_rule() { /* 2 hosts × 2 matches → 4 rules, all backend 0 */ }
#[test] fn exact_host_comes_before_wildcard_before_any() { .. }
#[test] fn longer_wildcard_comes_first() { .. }
#[test] fn specific_host_beats_specific_path() {
    // route A: a.example.com, Prefix("/"); route B: no hostname on listener *.example.com, Exact("/x"): A's rule first
}
#[test] fn exact_path_comes_before_prefix() { .. }
#[test] fn longer_prefix_comes_first() { .. }
#[test] fn method_comes_before_no_method() { .. }
#[test] fn more_headers_come_first() { .. }
#[test] fn older_route_comes_first_then_key_then_rule_then_match() { .. }
#[test] fn equal_rules_keep_only_the_first() { /* two routes, same host and match: the older one's rule stays */ }
#[test] fn listeners_of_one_port_are_merged() { /* a.example.com and b.example.com on port 80: one HttpPort */ }
#[test] fn https_port_lists_the_certificates_of_its_serving_listeners() { /* without repeats, sorted by file_name */ }
#[test] fn https_listener_without_certificates_contributes_nothing() {
    // its routes give no rules and its (absent) certificates nothing; the other listener of the port is served
}
#[test] fn conflicted_listener_contributes_nothing() { .. }
#[test] fn ports_are_ascending_and_backends_ordered_by_route_then_rule() { .. }
#[test] fn build_is_deterministic() { /* the same snapshot with its lists reversed gives an equal Model */ }
```

- [ ] **Step 2: Run them** — expected: fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `nix develop -c cargo test --workspace` — expected: all pass.
- [ ] **Step 5: Commit** — `feat(operator): HTTP ports with rules in matching order`

---

### Task 6: Supervisor and engine — files beside the configuration

**Files:**
- Modify: `operator/src/haproxy/mod.rs`, `operator/src/haproxy/supervisor.rs`, `operator/src/haproxy/render.rs` (the `files` field only, always empty here), `operator/src/engine.rs`, `operator/src/staticcfg.rs` if it builds a `Rendered`
- Test: `operator/tests/haproxy.rs`, `operator/tests/engine.rs`

**Interfaces:**
- Produces:

```rust
// haproxy/mod.rs
/// A file HAProxy reads besides its configuration: a certificate with its key, or a list of them.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretFile { pub name: String, pub contents: String }
impl fmt::Debug for SecretFile { /* prints `name` only */ }

// haproxy/render.rs
pub struct Rendered { pub haproxy_cfg: String, pub files: Vec<SecretFile>, pub edges: Vec<EdgePlan> }

// haproxy/supervisor.rs
/// The directory under the runtime directory that holds the files, mode 0700.
pub const CERT_DIR: &str = "certs";
pub async fn apply(&mut self, cfg: &str, files: &[SecretFile]) -> Result<Applied, ApplyError>;
```

Contract: the caller names files after their content, so equal `cfg` means equal files.

- `start` creates `<runtime_dir>/certs` with mode 0700 and removes whatever a previous run left in it.
- `apply` with the text it already runs returns `Unchanged` and touches no file.
- Otherwise, before validation, each file that does not exist yet is created with mode 0600 from the start (never widened and narrowed), written under a temporary name and renamed. A name that contains `/`, starts with `.` or is empty fails the apply with `ApplyError::Io` of kind `InvalidInput` before anything is written.
- After the outcome is known, every file in the directory that the configuration HAProxy runs, or may run, does not list is removed: after a success, all but `files`; after a refused validation or a reload that certainly failed, all but the loaded configuration's files; after an outcome that is unknown, nothing.
- `shutdown` and `Drop` remove the files.

`Engine::apply` passes `rendered.files`; its retry after a failed reload passes them again.

- [ ] **Step 1: Write the failing tests**

```rust
// operator/src/haproxy/mod.rs
#[test] fn debug_of_a_secret_file_hides_its_contents() { .. }

// operator/tests/haproxy.rs — `with_cert(dir, name)` returns a configuration whose frontend binds a second
// socket with `ssl crt <dir>/certs/<name>`, and the SecretFile for it (certificate from rcgen)
#[tokio::test] async fn certificate_files_are_private() { /* certs/ is 0700, the file 0600 */ }
#[tokio::test] async fn files_are_written_before_validation() { /* apply → Ok(Reloaded) */ }
#[tokio::test] async fn configuration_naming_a_missing_file_is_invalid() { /* files: [] → Err(Invalid); the old configuration serves */ }
#[tokio::test] async fn unreferenced_files_are_removed_after_a_successful_apply() { /* a.pem, then b.pem: only b.pem is left */ }
#[tokio::test] async fn invalid_configuration_keeps_the_loaded_files_and_removes_the_new() { .. }
#[tokio::test] async fn failed_reload_keeps_the_loaded_files() { /* with the existing `fails_to_load` */ }
#[tokio::test] async fn unknown_outcome_removes_nothing() { /* with the existing fake master that never answers */ }
#[tokio::test] async fn file_names_that_leave_the_directory_are_refused() { /* "../x", "a/b", ".hidden", "": Err(Io), nothing written */ }
#[tokio::test] async fn start_empties_the_certificate_directory() { .. }
#[tokio::test] async fn shutdown_removes_certificate_files() { .. }
#[tokio::test] async fn dropping_the_supervisor_removes_certificate_files() { .. }

// operator/tests/engine.rs
#[tokio::test] async fn engine_passes_files_to_haproxy() { /* a Rendered with such a configuration and file: facts().haproxy == Ok(()) */ }
#[tokio::test] async fn retry_after_a_failed_reload_passes_the_files_again() { .. }
```

- [ ] **Step 2: Run them** — `nix develop -c cargo test -p iroh-gateway-operator --test haproxy --test engine` — expected: fail to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `nix develop -c cargo test --workspace` — expected: all pass; `pgrep -fl haproxy` prints nothing.
- [ ] **Step 5: Commit** — `feat(operator): HAProxy supervisor manages certificate files`

---

### Task 7: Render HTTP and HTTPS

**Files:**
- Modify: `operator/src/haproxy/render.rs`, `operator/src/haproxy/testdata/{empty,one,two}.cfg`, `operator/Cargo.toml` (dev-dependency `tokio-rustls`, added to the workspace as `"0.26"` with `default-features = false, features = ["ring"]`)
- Create: `operator/src/haproxy/testdata/http.cfg`, `operator/src/haproxy/testdata/https.cfg`, `operator/tests/http.rs`

**Interfaces:**
- Consumes: `GatewayModel.http_ports` (Task 5), `SecretFile`, `Rendered.files`, `Supervisor::apply` (Task 6).
- Produces:

```rust
/// `s` as one HAProxy configuration word: in single quotes, each `'` written as `'\''`, control
/// characters dropped. Inside single quotes HAProxy expands nothing.
pub(crate) fn quote(s: &str) -> String;
/// `quote`, for arguments HAProxy reads as a log-format string: each `%` doubled first.
pub(crate) fn quote_format(s: &str) -> String;
```

`defaults` gains three lines after `timeout server 1h`, which changes the three existing golden files:

```
    timeout tunnel 1h
    timeout http-request 10s
    timeout http-keep-alive 60s
```

TCP ports render as today. After a Gateway's TCP ports come its HTTP ports, ascending. One HTTP port:

```
# <namespace>/<name> port <port>
frontend fe_<id>
    mode http
    bind unix@<dir>/s/<id>.sock accept-proxy mode 600
    option httplog
    http-request set-header X-Forwarded-For %[src]
    http-request set-header X-Forwarded-Proto http
    use_backend be_<id>_<n> if <condition> <condition> ...
    default_backend be_<id>_none

backend be_<id>_<n>
    mode http
    http-request set-header <quote(name)> <quote_format(value)>
    http-request add-header <quote(name)> <quote_format(value)>
    http-request del-header <quote(name)>
    http-response set-header <quote(name)> <quote_format(value)>
    http-response add-header <quote(name)> <quote_format(value)>
    http-response del-header <quote(name)>
    server s<i> <ip>:<port> weight <scaled>

backend be_<id>_none
    mode http
    http-request return status 404
```

- `<id>` is `port_id`, `<n>` the index in `HttpPort.backends`. One `backend` section per entry, in order, then `be_<id>_none`.
- An HTTPS port's `bind` line continues with ` ssl crt-list <dir>/certs/<list> strict-sni ssl-min-ver TLSv1.2 alpn h2,http/1.1`, and its `X-Forwarded-Proto` is `https`.
- Conditions of a rule, in this order, each left out when it does not apply:
  - host `Exact(h)`: `{ req.hdr(host),host_only,lower -m str -- <quote(h)> }`; `Wildcard(s)`: the same with `-m end -- <quote(s)>`;
  - path `Exact(p)`: `{ path -m str -- <quote(p)> }`;
  - method: `{ method <quote(METHOD)> }`;
  - each header: `{ req.fhdr(<name>) -m str -- <quote(value)> }`. A name cannot be quoted inside the parentheses. The model only lets `[A-Za-z0-9_-]` through; the render still replaces any other character with `_`, so that it is safe on its own.
- Path `Prefix(p)` other than `/` gives two consecutive lines for the rule: one with `{ path -m str -- <quote(p)> }`, one with `{ path -m beg -- <quote(p + "/")> }`. `Prefix("/")` gives no path condition. A rule with no condition at all is `use_backend be_<id>_<n>` without `if`.
- A backend's last line is its action: the servers for `Forward` (weights through `scale_weights`, weight-0 servers left out, as for TCP); `http-request return status 500` for `Fail`; for `Redirect`:

  `http-request redirect location <quote(scheme + "://" + host + port + "%[pathq]")> code <status>`

  where `scheme` is the redirect's or else the port's own (`https` when it has `tls`); `host` is the redirect's hostname with each `%` doubled, or else `%[req.hdr(host),host_only]`; `port` is `:<n>` for the redirect's port, or, when it has none, nothing if the redirect names a scheme and otherwise the listener's port, and is left out when it is the scheme's default (80 for `http`, 443 for `https`).
- Header operations come before the action: request `set`, `add`, `remove`, then response `set`, `add`, `remove`.

Files (`Rendered.files`, sorted by name, without repeats):

- one per certificate of an HTTPS port: name `Certificate.file_name`, contents `Certificate.pem`;
- one list per HTTPS port: contents one line `<dir>/certs/<file_name>` per certificate, in order; name `<id>.<first 16 hex of SHA-256 over the contents>.list`.

The port's fingerprint covers the text of all its sections, as today. Because the list's name is in the `bind` line and the certificate names are in the list, a rotated certificate changes the fingerprint. `EdgePlan.sockets` gets every HTTP port under `ListenerKey { protocol: Tcp, port }`.

If HAProxy 3.2 or 3.3 refuses a directive written here, use the equivalent it accepts, keep the behaviour the tests pin, and say so in the report. Check every golden file with `haproxy -c`.

- [ ] **Step 1: Write the failing tests**

```rust
// operator/src/haproxy/render.rs
#[test] fn quote_examples() {
    assert_eq!(quote("plain"), "'plain'");
    assert_eq!(quote("it's"), r"'it'\''s'");
    assert_eq!(quote("a b #c $HOME \"d\" \\e"), "'a b #c $HOME \"d\" \\e'");
    assert_eq!(quote("a\nb\r\0c\x7f"), "'abc'");
    assert_eq!(quote_format("100% it's"), r"'100%% it'\''s'");
}
#[test] fn http_port_matches_the_golden_file() { /* testdata/http.cfg: two hosts, exact, prefix, method, header, redirect, Fail, header filters */ }
#[test] fn https_port_matches_the_golden_file() { /* testdata/https.cfg; files == [two certificates, one list] */ }
#[test] fn prefix_gives_two_lines_and_root_prefix_none() { .. }
#[test] fn rule_without_conditions_has_no_if() { .. }
#[test] fn header_name_with_odd_characters_is_made_safe() { /* a model built by hand with name "x)y z": req.fhdr(x_y_z) */ }
#[test] fn redirect_locations() {
    // (port has tls?, listener port, Redirect) → location, e.g.
    // (no, 80, {scheme: https}) → 'https://%[req.hdr(host),host_only]%[pathq]'
    // (no, 8080, {}) → 'http://%[req.hdr(host),host_only]:8080%[pathq]'
    // (yes, 443, {hostname: b.example.com}) → 'https://b.example.com%[pathq]'
    // (no, 80, {scheme: https, port: 8443}) → 'https://%[req.hdr(host),host_only]:8443%[pathq]'
    // (no, 80, {scheme: http, port: 80}) → 'http://%[req.hdr(host),host_only]%[pathq]'
}
#[test] fn certificate_shared_by_two_ports_is_one_file() { .. }
#[test] fn rotated_certificate_changes_list_name_configuration_and_fingerprint() { .. }
#[test] fn http_ports_are_in_the_edge_plan() { .. }
#[test] fn tcp_and_http_ports_of_one_gateway_render_together() { .. }
#[test] fn debug_of_rendered_hides_key_material() { .. }

// operator/tests/http.rs — a Model built by hand, rendered into a temp dir, run by a Supervisor.
// `get(dir, port_id, request) -> (status, headers, body)` connects to the port's socket, writes the
// PROXY v2 header for VISITOR and then the HTTP/1.1 request. Backends are small HTTP servers in the
// test that answer with their tag and the request headers they saw.
#[tokio::test] async fn rendered_http_configuration_is_valid() { .. }
#[tokio::test] async fn routes_by_host_and_path() { .. }
#[tokio::test] async fn prefix_matches_whole_path_elements() { /* /foo and /foo/bar → A; /foobar → 404 */ }
#[tokio::test] async fn exact_path_beats_prefix_and_longer_prefix_wins() { .. }
#[tokio::test] async fn host_header_with_port_and_upper_case_still_matches() { /* "Host: EXAMPLE.com:8080" */ }
#[tokio::test] async fn wildcard_host_matches_subdomains_only() { .. }
#[tokio::test] async fn method_and_header_matches_select_the_backend() { .. }
#[tokio::test] async fn unknown_host_gets_404() { .. }
#[tokio::test] async fn rule_without_usable_backend_gets_500() { .. }
#[tokio::test] async fn redirect_to_https_keeps_host_path_and_query() { /* 301, Location: https://example.com/a?b=c */ }
#[tokio::test] async fn request_and_response_header_filters_apply() { .. }
#[tokio::test] async fn x_forwarded_headers_are_set_and_cannot_be_forged() {
    // the request carries its own X-Forwarded-For and X-Forwarded-Proto: the backend sees VISITOR's address and "http"
}
#[tokio::test] async fn weighted_backends_share_the_traffic() { /* weights 1 and 0: every request reaches the first */ }
#[tokio::test] async fn websocket_upgrade_passes_bytes_both_ways() { .. }
#[tokio::test] async fn hostile_strings_cannot_inject_configuration() {
    // set-header value and a path containing ' " # $HOME % \ and spaces: the configuration validates, the
    // backend receives the header value byte for byte, the path matches only its literal self
}
#[tokio::test] async fn https_terminates_tls_with_the_certificate() { /* tokio-rustls client trusting the test CA; 200; backend sees X-Forwarded-Proto: https */ }
#[tokio::test] async fn https_negotiates_h2_when_offered() { /* ALPN result is h2 */ }
#[tokio::test] async fn two_certificates_on_one_port_are_chosen_by_sni() { .. }
#[tokio::test] async fn unknown_sni_fails_the_handshake() { .. }
#[tokio::test] async fn rotated_certificate_is_served_after_apply() { /* apply a model with a new certificate: the client sees the new one; the old file is gone */ }
#[tokio::test] async fn a_listener_without_certificates_does_not_break_its_port() {
    // an HttpPort built from one good listener while another on the port had no certificates: validates and serves
}
```

- [ ] **Step 2: Run them** — expected: fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `nix develop -c cargo test --workspace`, then `nix develop -c cargo test -p iroh-gateway-operator --test http` ten times in a row — expected: all pass every time; `pgrep -fl haproxy` prints nothing.
- [ ] **Step 5: Commit** — `feat(operator): render HTTP and HTTPS ports`

---

### Task 8: Cluster — watches, permissions, API-server tests

**Files:**
- Modify: `operator/src/cluster/stores.rs`, `operator/src/main.rs`, `deploy/rbac.yaml`, `operator/tests/common/envtest.rs` (install `httproutes.gateway.networking.k8s.io` too), `operator/tests/cluster.rs`

**Interfaces:**
- Consumes: everything above.
- Produces:

```rust
impl Stores {
    /// One watch per resource kind, cluster-wide, and one watch of TLS Secrets per gateway namespace.
    pub fn start(client: Client, gateway_namespaces: &BTreeSet<String>) -> Self;
}
/// Waits for every named future; while some are pending, calls `report` with their names every `every`.
pub(crate) async fn wait_all(waits: Vec<(String, BoxFuture<'_, ()>)>, every: Duration, report: impl FnMut(&[String]));
```

- `HTTPRoute`s are watched cluster-wide, like `TCPRoute`s.
- Secrets are watched with `Api::namespaced` in each gateway namespace, with the field selector `type=kubernetes.io/tls`. No other Secret is requested or held.
- `synced()` uses `wait_all` with `WARN_EVERY` and logs a warning naming what has not listed yet, for example `still waiting for the first list of: HTTPRoute, Secret in apps`. Nothing is applied before every store has listed, as today. A missing permission or CRD therefore shows up by name every 30 s.
- `deploy/rbac.yaml`: the ClusterRole gains `httproutes` (get, list, watch) and `httproutes/status` (patch). The Role in `iroh-gateway` gains a rule for `secrets` with verbs `list`, `watch`. Its comment says what this means: the operator can now read every Secret of a namespace it serves Gateways in; `list` and `watch` cannot be limited to a type. `deploy_manifests_apply_cleanly` asserts the new shape exactly.

- [ ] **Step 1: Write the failing tests**

```rust
// operator/src/cluster/stores.rs
#[tokio::test(start_paused = true)] async fn wait_all_reports_what_is_still_pending() {
    // "a" resolves at once, "b" after 70 s, every = 30 s: reports [["b"], ["b"]], then returns
}
#[tokio::test(start_paused = true)] async fn wait_all_reports_nothing_when_all_are_ready() { .. }

// operator/tests/cluster.rs  (#[ignore = "needs KUBEBUILDER_ASSETS"])
async fn http_route_and_gateway_become_programmed() {
    // HTTP listener, HTTPRoute to a Service: listener Programmed True, attachedRoutes 1, supportedKinds [HTTPRoute];
    // the route's parent status Accepted True and ResolvedRefs True under our controller name; the edge port accepts connections
}
async fn deleting_the_http_route_closes_the_port() { .. }
async fn unsupported_http_route_is_refused_with_a_reason() { /* a URLRewrite filter: Accepted False UnsupportedValue; attachedRoutes 0 */ }
async fn https_listener_follows_its_secret() {
    // valid Secret: ResolvedRefs True, Programmed True, the port accepts connections;
    // Secret replaced by garbage: ResolvedRefs False InvalidCertificateRef, Programmed False, the port closes;
    // valid again: back to True
}
async fn secret_of_another_type_is_not_read() {
    // an Opaque Secret named like the certificateRef: InvalidCertificateRef "not found"
}
async fn http_route_status_is_not_rewritten_when_nothing_changed() { /* resourceVersion stays over two passes */ }
async fn tcp_and_http_listeners_work_side_by_side() { .. }
```

- [ ] **Step 2: Run them** — `KUBEBUILDER_ASSETS=$(nix develop -c scripts/envtest-assets) nix develop -c cargo test -p iroh-gateway-operator --test cluster -- --ignored` — expected: the new ones fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the workspace tests, then the cluster tests five times in a row — expected: all pass every time; no `haproxy`, `etcd` or `kube-apiserver` process is left.
- [ ] **Step 5: Commit** — `feat(operator): watch HTTPRoutes and TLS Secrets`

---

### Task 9: End to end, README, design

**Files:**
- Modify: `scripts/e2e-kind.sh`, `README.md`, `docs/superpowers/specs/2026-11-23-iroh-gateway-design.md`

`scripts/e2e-kind.sh`, after the existing TCP steps and before the shutdown check. The edge's Service gains ports 8081 and 8443. The probe for HTTP is a pod of `curlimages/curl:8.11.1`; the web backend is `busybox:1.37` running `httpd -f -p 8080 -h /www` with one file `index.html` containing `hello from web`.

1. A Gateway listener `http` (HTTP, 8081) and an `HTTPRoute` for `app.example.test` to the web Service. `curl -H 'Host: app.example.test' http://<edge>:8081/` prints `hello from web`. The route's status shows `Accepted=True`.
2. `curl -H 'Host: other.example.test'` gives 404.
3. A second `HTTPRoute` for `secure.example.test` with a `RequestRedirect` to scheme `https`, status 301: the answer is 301 with `Location: https://secure.example.test/x?y=1` for `/x?y=1`.
4. A self-signed certificate for `app.example.test` made with `openssl`, as Secret `app-tls`; a listener `https` (HTTPS, 8443) with it; the route attached to both listeners. `curl --cacert <cert> --connect-to app.example.test:8443:edge.<ns>.svc:8443 https://app.example.test:8443/` prints `hello from web`.
5. Rotation: a new certificate replaces the Secret. Within 30 s the same `curl` with the new certificate as `--cacert` succeeds, and with the old one fails.
6. A file listing in the operator pod (`ls -l` through `kubectl exec`) shows the certificate files with mode `-rw-------`.

The script stays shellcheck-clean and keeps its failure diagnostics.

`README.md`, in the Kubernetes section:

- an HTTPS example: Secret, Gateway with `HTTP` and `HTTPS` listeners, an `HTTPRoute`, and the HTTP→HTTPS redirect route;
- what is supported and that anything else refuses the route with `UnsupportedValue`;
- Secrets: which the operator reads, that the Role now lets it list every Secret in a gateway namespace, and a Role and RoleBinding to copy for each further namespace in `--gateway-namespaces`;
- limits: private keys must be RSA of 2048 bits or more, ECDSA P-256 or P-384, or Ed25519; visitors must send SNI; `X-Forwarded-For` comes from the edge and is only as trustworthy as the edge; a certificate that passes these checks but that HAProxy still refuses fails the whole reload, and the Gateway's `Programmed` condition then carries HAProxy's message naming the file, which starts with the Secret's namespace and name;
- upgrading from the TCP-only version: apply `deploy/rbac.yaml` before the new image, or the operator waits for permissions and applies nothing.

Design document: an HTTP or HTTPS port opens once a route is attached (a redirect needs no backend); an `HTTPRoute` with anything unsupported is refused whole; how certificates are checked and the key types; the Secret permissions; certificate files named by content.

- [ ] **Step 1:** Extend the script; run `nix develop -c shellcheck scripts/e2e-kind.sh` — expected: clean. The script itself runs in CI (no Docker on the development machine); say so in the report.
- [ ] **Step 2:** Write the README and design changes.
- [ ] **Step 3:** Run `nix develop -c cargo test --workspace`, the cluster tests, `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and the `crdgen` drift check — expected: all clean.
- [ ] **Step 4: Commit** — `test(e2e): HTTP, HTTPS, redirect and certificate rotation; docs`
