# Addresses That Follow the Tunnel: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `Gateway.status.addresses` lists only the addresses of connected edges, so DNS follows the tunnels and a second edge gives failover.

**Architecture:** A small stateful tracker in the controller decides, at each pass, which edges are listed: connected ones, and disconnected ones still inside the address grace. `status::compute` stays pure and takes that set. The controller loop wakes when a grace ends. The Gateway's own status is the only remembered state, read once per edge when the tracker first sees it.

**Tech Stack:** Rust 1.100 (`nix develop -c cargo …`), kube 5.2, tokio (paused time in tests), Helm chart, envtest, kind in CI.

**Spec:** `docs/superpowers/specs/2026-11-23-iroh-gateway-design.md`, section "Edge enrolment", the bullet on `Gateway.status.addresses`.

## Global Constraints

- "Connected" is `EdgeState.connected`: a connection is up and the edge has answered a config on it.
- The address grace defaults to 30 s. `0s` withdraws at once. Flag `--address-grace <duration>` on `iroh-gateway-operator run`, env `IROH_GATEWAY_ADDRESS_GRACE`, parsed with `humantime::parse_duration`. Chart value `addressGrace`, default `30s`.
- An edge not connected when first seen is held for one grace from that moment if its Gateway's status already lists one of its public addresses, and is withdrawn otherwise.
- A Gateway with no listed edge lists no address. Conditions are unchanged and do not wait for the grace.
- An address shared by several edges is listed while any of them is listed. At most 16 addresses, the first 16 in sorted order of the listed ones; the "not listed" note counts only listed edges' addresses.
- No change to the edge, the tunnel protocol, the `Edge` CRD or `iroh-gateway-operator static`.
- Checks before every commit: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`; for chart or cluster changes also `scripts/chart-test.sh` and the envtest suite (`KUBEBUILDER_ASSETS=$(nix develop -c scripts/envtest-assets) nix develop -c cargo test -p iroh-gateway-operator --test cluster -- --ignored`).

## Review Focus

1. **Operator restart with every edge healthy.** No address may leave the status between the start and the edges' reconnect. Test: Task 2, `a_restart_withdraws_nothing_within_the_grace`.
2. **A tunnel that reconnects within the grace.** The status is not rewritten with fewer addresses. Test: Task 1, `a_reconnect_within_the_grace_stays_listed`.
3. **A grace that ends while nothing else changes.** The address must leave without another event. Test: Task 2, `a_grace_that_ends_triggers_a_pass`.
4. **A dead edge across an operator restart.** Its address, already withdrawn, must not come back. Test: Task 1, `first_seen_disconnected_and_not_in_status_is_withdrawn`.
5. **A new `Edge` that has never connected.** Not listed until it connects. Same test as 4, and Task 2's cluster test.

---

### Task 1: The listing rule and the status computed from it

**Files:**
- Create: `operator/src/status/listing.rs`
- Modify: `operator/src/status/mod.rs` (`compute`, `gateway_status`), `operator/src/model/edges.rs` and `operator/src/model/mod.rs` (the Gateway model no longer carries `addresses` and `addresses_dropped`), every caller of `status::compute`

**Interfaces:**
- Produces:
  ```rust
  // operator/src/status/listing.rs
  pub struct EdgeView { pub key: ObjRef, pub connected: bool, pub in_status: bool }
  pub struct Listing { /* grace, per-edge state */ }
  impl Listing {
      pub fn new(grace: Duration) -> Self;
      /// The edges listed at `now`. Edges absent from `edges` are forgotten.
      pub fn update(&mut self, now: Instant, edges: &[EdgeView]) -> BTreeSet<ObjRef>;
      /// When the earliest grace of a held edge ends.
      pub fn next_expiry(&self) -> Option<Instant>;
  }
  /// One view per accepted edge bound to a Gateway; `in_status` from the snapshot's Gateway status.
  pub fn views(model: &Model, facts: &Facts, snapshot: &Snapshot) -> Vec<EdgeView>;
  // operator/src/status/mod.rs
  pub fn compute(model: &Model, facts: &Facts, listed: &BTreeSet<ObjRef>) -> DesiredStatus;
  ```
  `Instant` is `tokio::time::Instant`.

- [ ] **Step 1: Failing tests for `Listing`** in `listing.rs`, with `t0 = Instant::now()` and grace 30 s:
  - `a_connected_edge_is_listed`
  - `a_disconnect_is_held_for_the_grace_then_withdrawn`: listed at `t0+29s`, not at `t0+30s`; `next_expiry()` is `Some(t0+30s)` while held and `None` after.
  - `a_reconnect_within_the_grace_stays_listed`: and a later disconnect starts a new grace.
  - `a_withdrawn_edge_is_listed_again_when_it_connects`
  - `first_seen_disconnected_and_in_status_is_held`
  - `first_seen_disconnected_and_not_in_status_is_withdrawn`
  - `a_zero_grace_withdraws_at_once`
  - `an_edge_that_is_gone_is_forgotten`: gone, then back disconnected with `in_status: false`, is withdrawn.
  - `the_earliest_expiry_is_reported` with two held edges.
- [ ] **Step 2:** Run them, see them fail. Implement `Listing`. Log at `info` when an edge's addresses are listed, held (with the grace) and withdrawn.
- [ ] **Step 3: Failing tests for `compute`** in `status/mod.rs`:
  - `only_listed_edges_give_addresses`: two edges, one listed.
  - `no_listed_edge_gives_no_address`
  - `an_address_shared_by_two_edges_stays_while_one_is_listed`
  - the existing cap test, now with 17 listed addresses; and `unlisted_edges_do_not_count_as_dropped`.
  Replace `disconnected_edge_keeps_addresses_and_is_pending` with a test that a disconnected, still listed edge keeps its address and the Gateway is `Pending`.
- [ ] **Step 4:** Implement: `gateway_status` builds the addresses from the listed edges' `public_addresses`. Add `views` with a test of `in_status` (an IP and a hostname in a Gateway's status).
- [ ] **Step 5:** All checks, commit.

### Task 2: The controller, the flag, the chart, the cluster tests

**Files:**
- Modify: `operator/src/controller.rs` (`ControllerOptions.address_grace`, `DEFAULT_ADDRESS_GRACE`, the loop), `operator/src/main.rs` (`--address-grace`), `operator/tests/cli.rs`, `operator/tests/cluster.rs`, `charts/iroh-gateway/{values.yaml,templates/deployment.yaml,README.md}`, `scripts/chart-test.sh`

**Interfaces:**
- Consumes: `Listing`, `views`, `compute` from Task 1.
- Produces: `ControllerOptions.address_grace: Duration` (default `DEFAULT_ADDRESS_GRACE = 30 s`).

- [ ] **Step 1: Failing controller tests** (paused time, the existing `Rig`):
  - `a_grace_that_ends_triggers_a_pass`: an edge of the model goes from connected to disconnected; exactly one more status write happens `address_grace` later with nothing else changing.
  - `no_pass_is_scheduled_without_a_held_edge`
- [ ] **Step 2:** Implement: the loop owns a `Listing`, calls `update` after `apply`, passes the set to `compute`, and adds `sleep_until_some(listing.next_expiry())` to the wait.
- [ ] **Step 3:** `--address-grace` with a CLI test that a bad duration fails at start naming the flag. Chart value, the argument, a row in the chart README's values table, render checks in `scripts/chart-test.sh` for the default and for `--set addressGrace=5s`.
- [ ] **Step 4: Cluster tests** (`operator/tests/cluster.rs`, in-process edges from `Operator::edge()`, a 2 s grace):
  - Rework the two tests that read addresses of edges that never connect, so their edges are connected (`seventeen_edges_give_sixteen_addresses` becomes one connected edge with 17 `publicAddresses`).
  - `an_edge_that_never_connected_gives_no_address`
  - `a_dead_edge_loses_its_address_and_the_other_keeps_serving`: two edges, both listed; one is shut down; its address leaves within the grace plus the convergence time, the other stays, and the Gateway stays `Programmed`.
  - `the_last_edge_gone_leaves_no_address`
  - `a_restart_withdraws_nothing_within_the_grace`: stop the operator and its edge stays down; a new operator with a long grace starts; the address is still listed after its first pass.
- [ ] **Step 5:** All checks, chart test, envtest suite, commit.

### Task 3: Failover in the kind test, and the documentation

**Files:**
- Modify: `scripts/e2e-kind.sh`, `README.md`

- [ ] **Step 1:** In `scripts/e2e-kind.sh`, install the chart with `addressGrace=5s`, add a second edge (Deployment, Service, `Edge` with its own `publicAddresses`), and steps: both addresses are listed; the second edge scaled to 0 loses its address while HTTP through the first still answers; scaled back, its address returns. `diagnostics` prints the Gateway's addresses. `shellcheck` clean.
- [ ] **Step 2:** `README.md`: a section "Several edges and failover" under Kubernetes (the rules, the timing: about 20 s to notice a dead edge, the grace, external-dns's interval, the record's TTL; the single-edge consequence); the walkthrough's step 4 paragraph on the Gateway's address; the flag in the `run` table; the chart value under "Values that matter"; the sentence "only one is tested; there is no failover"; an upgrade note for v0.1.0 users.
- [ ] **Step 3:** Link check of the README, all checks, commit.
