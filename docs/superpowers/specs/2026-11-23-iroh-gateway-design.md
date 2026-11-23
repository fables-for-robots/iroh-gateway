# iroh-gateway — Design

Date: 2026-11-23
Status: approved design, pre-implementation

## Overview

iroh-gateway exposes services in a home Kubernetes cluster to the internet
without revealing the home IP address and without opening any inbound port
at home.

Small **edge** machines run on rented public IPs. An edge only accepts TCP
and UDP from visitors and pipes it over [iroh](https://www.iroh.computer)
(QUIC, peers authenticated by ed25519 key) to the **operator** in the
cluster. The operator is a Kubernetes Gateway API controller: it watches
`Gateway` and route resources, drives an HAProxy process that terminates
TLS and routes HTTP, and forwards everything to cluster Services.

```
visitor ──TCP/UDP──▶ edge (VPS, public IP)
                       ▲
                       │ iroh / QUIC, dialed outbound from home
                       │
        ┌──────────────┴──────────────── operator pod ───────────────┐
        │ tunnel ──unix socket + PROXY v2──▶ HAProxy ──▶ Service     │
        │   └────────────── UDP flows ─────────────────▶ Service     │
        │ controller: Gateway API ──▶ haproxy.cfg, edge port lists   │
        └────────────────────────────────────────────────────────────┘
```

### Why

The owner wants to expose a homelab (k3s, single node, currently reachable
only over a tailnet and LAN ingress) securely, and never expose home IPs.
Multiple edges for availability are required eventually; phase 1 may ship
with one.

### Goals (phase 1)

- Visitors only ever see edge IPs.
- The cluster needs no inbound port; it dials out to the edges.
- By default no third party is involved in the tunnel: no public relays, no
  public address lookup. The home IP is known to the edge machines and
  nobody else.
- An edge can also be reached through an iroh relay with address lookup,
  for networks where a direct connection is not possible. This is opt-in and
  its privacy cost is documented (see "Relay mode").
- The edge holds no TLS keys and no routing knowledge. TLS terminates in
  the cluster.
- Exposure is declared with standard Gateway API resources, so cert-manager
  and external-dns work unmodified.
- HTTP, HTTPS (terminated), raw TCP and UDP all work end to end.
- HTTP and HTTPS backends see the real client address
  (`X-Forwarded-For`).
- The data model allows any number of edges per Gateway, so phase 2 is an
  extension and not a redesign.

### Non-goals (phase 1)

- Creating machines at providers. The owner deploys edges.
- Multi-edge failover behaviour: health-driven DNS, address debouncing,
  draining. Several edges may connect, but only one is tested and promised.
- More than one operator replica.
- HTTP/3, `GRPCRoute`, `TLSRoute` (SNI passthrough), `BackendTLSPolicy`,
  `ReferenceGrant`, backendRef-level filters, `URLRewrite`, request
  mirroring.
- Balancing across individual pods (see "Backends").
- Running a relay. Relay mode uses n0's public relays or one the owner
  already runs.
- Rate limiting, WAF, bot protection.
- Issuing certificates or managing DNS records (cert-manager and
  external-dns do that).
- `Ingress` resources.
- Client address for raw TCP and UDP backends. A `TCPRoute` backend sees
  the operator pod's address. The only mechanism for TCP is sending PROXY
  protocol to the backend, which breaks any backend not expecting it, so it
  needs a per-backend opt-in; that comes later.
- Passing the upstream Gateway API conformance suite. It is the north star
  for behaviour, not a phase 1 gate.

### Anti-goals

These make the project a failure even if it works:

- The home IP becoming visible to visitors, or to any third-party service,
  in the default configuration.
- An edge holding TLS private keys, or seeing plaintext of HTTPS traffic.
- A compromised edge being able to reach anything other than the listeners
  of the Gateway it is attached to.
- A route in one namespace reaching a Secret or Service in another
  namespace.
- The operator serving a broken or stale configuration without saying so in
  resource status.
- Ports open on an edge that no Gateway asked for.

## Context: facts this design relies on

- **Sibling conventions.** `../secret-bunker-iroh` is the house template:
  Rust 2024, `rust-version = "1.91"`, iroh 1.x, `kube` with a `crdgen`
  binary, Helm chart under `charts/`, nix flake dev shell with `kind`,
  `kubectl`, `helm`, distroless-style image, AGPL-3.0-or-later, CRD group
  `bunker.fables-for-robots.ch`, images at `ghcr.io/fables-for-robots/…`.
- **Target cluster.** k3s on one node, Argo CD, `NetworkPolicy` in use,
  `Ingress` with classes `tailscale` and `traefik`. No Gateway API resources
  and no cert-manager are in the GitOps repo today.
- **iroh (checked in the 1.3.0 source).**
  - `Endpoint::builder(preset)` with `presets::Minimal` or `presets::Empty`
    gives an endpoint with no relay and no address lookup; `RelayMode::Disabled`
    exists. `Builder::bind_addr` pins the UDP port.
  - `EndpointAddr::with_ip_addr(SocketAddr)` lets a peer be dialed by key at
    a known IP and port with no lookup.
  - `Connection` offers `open_bi`/`accept_bi`, `send_datagram`,
    `read_datagram`, `max_datagram_size`, `remote_id`.
  - Datagram size follows the path MTU: it starts at 1200 bytes and MTU
    discovery raises it to at most 1452 by default. A full-size internet UDP
    payload (1472 bytes) therefore never fits in one datagram.
- **HAProxy.** The open-source edition has no generic UDP proxying (only
  syslog/DNS via `log-forward`); generic UDP is an Enterprise module. It
  accepts PROXY protocol v2 on any bind, including unix sockets, and in
  master-worker mode reloads without dropping established connections.
- **HAProxy Unified Gateway** (the "HAProxy gateway") is the model for the
  controller side: a controller watches Gateway API resources and runs
  HAProxy for them. Its documented route support is `HTTPRoute`.
- **Crates (current on crates.io at time of writing).** `iroh` 1.5,
  `kube` 5.1, `gateway-api` 0.23 (kube-rs bindings generated from upstream).
  The builder pins a mutually compatible set; `gateway-api` pins specific
  `kube`/`k8s-openapi` versions.

## Approaches

Three ways of building the cluster side were considered.

1. **Load-balancer provider (layer 4 only).** Implement
   `Service type=LoadBalancer` for a `loadBalancerClass`; leave TLS and HTTP
   to an existing ingress or gateway controller behind it. Smallest, no
   certificate handling in our code, but two components to run.
2. **Gateway API controller driving HAProxy.** One integrated product that
   owns routing and TLS. Much larger: it rebuilds what HAProxy's gateway
   controller does, and UDP has to bypass HAProxy.
3. **Custom tunnel resource.** Same as 1 with a bespoke CRD. Dropped:
   nothing in the ecosystem understands it.

**Chosen: 2**, by the owner, with the recommendation for 1 on the table. One
integrated product was preferred over composing two.

## Decided by the owner

- Purpose: expose the homelab securely without exposing home IPs.
- Multiple edges are a must; phase 1 may ship with one.
- Edges terminate TCP and UDP only; TLS terminates in the cluster.
- Approach 2, using HAProxy.
- The owner deploys edges; the operator calls no provider APIs.
- Edges are accepted only if their iroh key is listed in the cluster.
- TCP is built before UDP.
- An edge must also be reachable through a relay with discovery.
- Rust 1.100.

Everything below is the designer's call unless marked otherwise.

## Architecture

### Components

| Component | Runs | Role |
|---|---|---|
| `iroh-gateway-edge` | VPS, one static binary | Opens public ports it is told to, forwards traffic into the tunnel |
| `iroh-gateway-operator` | one pod in the cluster | Gateway API controller, tunnel endpoint, HAProxy supervisor, UDP forwarder |
| HAProxy | child process of the operator | TLS termination, HTTP routing, TCP proxying |

The operator is one binary in one pod with one replica. HAProxy runs as its
child in the same container, because the operator must validate, write and
reload its configuration atomically and talk to it over unix sockets that
nothing else can reach. Controller and data path are separate modules inside
the binary so they can be split into separate pods later.

### Who dials whom

**The operator dials each edge**, directly, at the address in the `Edge`
resource. By default neither side uses relays or address lookup.

This reverses an earlier suggestion that the edge dials in. The reason: an
edge has a stable public address and the cluster does not, so dialing
outbound from home needs no relay and no published address record. That
removes every third party from the path, which is the point of the project.
The home router only needs to allow outbound UDP.

Both sides pin the other's key, WireGuard-style:

- The operator expects the `endpointId` from the `Edge` resource. The iroh
  handshake proves it.
- The edge is configured with the operator's EndpointId and rejects every
  other peer.

The operator's key is generated on first start and kept in a Secret in its
own namespace, so its identity survives restarts. Its EndpointId is logged
at startup and written to `Edge.status.gatewayEndpointId`.

The operator redials a lost edge with capped exponential backoff, forever.

### Relay mode

Relay mode is off by default. It exists for cases where the direct path
fails: a home network that blocks outbound UDP, a provider firewall that
blocks the edge's iroh port, or an edge whose address changes.

One setting, with the same value on the operator and on its edges:

| Value | Edge | Operator |
|---|---|---|
| `disabled` (default) | direct only | direct only; every `Edge` needs an `address` |
| `n0` | uses n0's public relays and publishes its relay URL (no IP addresses) to n0's lookup service | uses n0's relays and looks edges up there; publishes nothing |
| a relay URL | uses that relay | uses that relay; no lookup service |

- The operator still dials. An `Edge` with an `address` is tried directly
  and through the relay; iroh moves to the direct path whenever one works.
  An `Edge` without an `address` is found through the relay alone.
- Key pinning is unchanged, and traffic stays encrypted end to end between
  the two pinned keys. A relay cannot read or alter it.
- What a relay does learn: the home IP (the operator connects to it), the
  edge's IP, and the size and timing of relayed traffic. With `n0`, n0's
  lookup service also sees lookups coming from home. This is the trade the
  owner makes by turning it on, and the README says so next to the setting.
- An edge still needs a public IP for visitors. Relay mode changes how the
  tunnel is established, not how visitors arrive.

### What an edge does

- Listens for iroh on one fixed UDP port (default `7842`).
- Accepts a connection only from the pinned operator key.
- Receives a list of listeners (`tcp`/`udp` + port) and binds exactly those
  on all addresses. It reports per-listener success or the bind error.
- Forwards each accepted TCP connection as one QUIC stream and each UDP
  packet as QUIC datagrams.
- Closes all public listeners a few seconds after the tunnel drops, so
  visitors fail fast and a future health check sees the edge as down.
- Enforces a cap on concurrent connections and UDP flows and refuses new
  ones beyond it.
- Persists only its own key. No certificates, no routes, no hostnames.

### What a compromised edge can and cannot do

Can: read and alter whatever passes through it that is not TLS (plain HTTP
on port 80, raw TCP, UDP); see TLS ciphertext and SNI; open connections to
its Gateway's listeners like any visitor; lie about client addresses; learn
the home IP.

Cannot: obtain TLS keys; reach any Service that is not behind a listener of
its own Gateway; change routing; affect other Gateways.

Consequence for users, to be documented: the client address a backend sees
is only as trustworthy as the edge. It is for logging, not for access
control.

## Resources

### Gateway API

- `GatewayClass` with `controllerName: gateway.fables-for-robots.ch/iroh-gateway`.
- `Gateway` listeners with protocol `HTTP`, `HTTPS` (`tls.mode: Terminate`,
  `certificateRefs` to `kubernetes.io/tls` Secrets), `TCP`, `UDP`.
- `HTTPRoute`: hostnames; matches on path (`Exact`, `PathPrefix`), headers
  (exact) and method; weighted `backendRefs`; rule filters
  `RequestRedirect`, `RequestHeaderModifier`, `ResponseHeaderModifier`.
- `TCPRoute` and `UDPRoute`: weighted `backendRefs`.
- Backends are `Service` references only.

Rules:

- Route precedence follows the Gateway API specification (hostname
  specificity, then exact path, longest prefix, method, header count, then
  oldest route, then name).
- `allowedRoutes` (namespaces `Same`/`All`/`Selector`, kinds) is enforced.
- All cross-namespace `backendRefs` and `certificateRefs` are refused with
  `ResolvedRefs=False`, reason `RefNotPermitted`. `ReferenceGrant` comes
  later; refusing is the safe subset.
- One protocol family per port on a Gateway. `HTTPS` listeners with
  different hostnames may share a port; so may `HTTP` listeners. Any other
  mix on one port is `Conflicted`.
- A listener may not use the edge's iroh port.
- No matching route answers 404; a rule whose backends are all invalid
  answers 500, as the specification requires.

### `Edge` (custom resource)

Group `gateway.fables-for-robots.ch`, version `v1alpha1`, namespaced.

```yaml
apiVersion: gateway.fables-for-robots.ch/v1alpha1
kind: Edge
metadata:
  name: fsn1
  namespace: iroh-gateway
spec:
  endpointId: <edge public key>
  address: 203.0.113.7:7842        # where the operator dials; IP or DNS name.
                                   # Optional in relay mode.
  gatewayRef:
    name: public                   # same namespace only
  publicAddresses: []              # defaults to the IP in `address`;
                                   # required when `address` is absent
status:
  gatewayEndpointId: <operator public key>
  conditions:                      # Connected, Programmed
  listeners:
    - {protocol: TCP, port: 443, bound: true}
```

- An `Edge` without `address` is `Accepted=False` when relay mode is
  `disabled`, and one without both `address` and `publicAddresses` is
  always `Accepted=False`.
- An edge serves exactly one Gateway. A Gateway is served by any number of
  edges, and every edge of a Gateway opens all of that Gateway's ports.
  Edges are never shared, so two Gateways can never fight over a port.
- `Gateway.status.addresses` lists the public addresses of every `Edge`
  attached to the Gateway, taken from the `Edge` spec, whether or not the
  edge is connected right now. An address leaves only when its `Edge` is
  deleted or re-pointed. This is deliberate: with one edge, withdrawing the
  address on a tunnel blip would make external-dns delete the record and
  turn seconds of outage into minutes, with no other edge to send visitors
  to. It also needs no remembered state, since addresses come from spec. An
  IP is published as `IPAddress`, a DNS name as `Hostname`.
- Connectivity shows in conditions, not addresses. A Gateway with no `Edge`
  is `Programmed=False`, reason `AddressNotAssigned`. A Gateway whose edges
  are all disconnected or unbound is `Programmed=False` with a reason
  saying so, and keeps its addresses.
- A listener is `Programmed=True` once HAProxy serves it (or the UDP
  forwarder for UDP) and at least one edge has bound its port. An edge's
  bind error shows on the `Edge` and in the listener's condition message.

### Where Gateways may live

The operator honours `Gateway` and `Edge` resources only in namespaces named
in its configuration (chart value `gatewayNamespaces`, default: its own
namespace). Its Secret read access is granted per namespace by `Role`, only
there. Routes and Services are read cluster-wide. This keeps a
cluster-wide Secret read out of the operator's permissions.

### Status

Every resource the operator handles carries standard conditions with
`observedGeneration`: `GatewayClass` `Accepted`; `Gateway` `Accepted` and
`Programmed`, per-listener `Accepted`, `Programmed`, `ResolvedRefs`,
`Conflicted` and `attachedRoutes`; route parent status `Accepted` and
`ResolvedRefs` under the controller name.

## Tunnel protocol

ALPN `iroh-gateway/0`. A breaking change bumps the number. Control messages
are length-prefixed CBOR (as in `secret-bunker-iroh`).

**Control stream.** The operator opens the first bidirectional stream.

- Operator → edge: `Config { generation, listeners: [{ id, protocol, port }] }`,
  the full desired set, resent on every change. `id` is a small integer.
- Edge → operator: `Status { generation, listeners: [{ id, bound | error }], version }`.

Liveness uses QUIC keep-alive and idle timeout (order of 5 s and 20 s), not
application pings.

**TCP.** For each accepted visitor connection the edge opens a
bidirectional stream and writes a header: listener id, visitor address,
local address. Raw bytes follow in both directions. Half-close maps to
stream finish and an abort maps to stream reset, in both directions. The
operator connects to the HAProxy socket for that port, writes a PROXY v2
header with the visitor's address, and copies.

The default QUIC limit on concurrent streams is far too low for this and
must be raised on both sides to the connection cap.

**UDP.** Each visitor packet travels as one or more QUIC datagrams:

```
listener id | flow id | packet id | fragment index | fragment count | payload
```

- The edge assigns a flow id per (visitor address, listener) and forgets it
  after an idle timeout (default 60 s).
- On an unknown flow id the operator picks a backend from the `UDPRoute` by
  weight, opens a UDP socket to it, and keeps the pairing until idle
  timeout. Replies travel back under the same flow id and the edge sends
  them to the visitor from the listener's socket.
- A packet larger than `max_datagram_size()` minus the header is split into
  fragments. The receiver reassembles within a short window and drops
  incomplete packets. `max_datagram_size()` is read per send because it
  changes with the path.
- Delivery stays unreliable and unordered, which is what UDP promises.
  Reliable streams were rejected because they add head-of-line blocking.

An edge that sends a stream or datagram for a listener id not in its current
`Config` gets that stream reset or datagram dropped, and the event counted.

## Data path in the operator

### HAProxy

- One frontend per (Gateway, port), bound to a unix socket with
  `accept-proxy`. HAProxy binds no TCP port for traffic, so nothing in the
  cluster can bypass the tunnel or forge a PROXY header.
- `HTTPS` ports bind with all certificates of the listeners on that port,
  strict SNI, TLS 1.2 minimum, ALPN `h2,http/1.1`. Certificates are written
  from Secrets to a memory-backed directory, mode 0600.
- `HTTP`/`HTTPS` frontends select a backend by host and match rules, emitted
  in precedence order. Each route rule becomes its own backend section,
  which carries that rule's filters and its weighted servers.
- `TCP` ports are TCP-mode frontends with one backend. The visitor address
  is logged but not passed on to the backend.
- `X-Forwarded-For` and `X-Forwarded-Proto` are set. WebSockets work.
- Access logs go to stdout.

### Backends

Each `backendRef` becomes one HAProxy server pointing at the Service's
ClusterIP and port; kube-proxy balances across pods. This avoids watching
EndpointSlices and reloading on every pod change. The cost is no per-pod
balancing or health checks, and kept-alive connections stick to one pod.
Per-pod balancing is a later improvement.

### Reload

The controller reduces the watched resources to an intermediate model, then
renders it. Both steps are pure functions:

```
resources ──▶ model (gateways, ports, rules, backends, statuses)
model ──▶ haproxy.cfg + certificate files + edge listener lists + UDP table
```

Applying a new render:

1. Changes are coalesced for a short interval.
2. The new configuration is written beside the live one and checked with
   `haproxy -c`.
3. If valid, it is swapped in and HAProxy is reloaded through the master
   socket. Established connections stay on the old worker until they end or
   a hard-stop limit passes.
4. If invalid, the running configuration stays, the affected Gateways go
   `Programmed=False` with the validator's message, and a metric counts it.

Edge listener lists and the UDP table are applied after HAProxy is ready
for them, so an edge never opens a port that has nothing behind it.

## Packaging

- **Workspace.** Three crates: `proto` (messages, framing, fragmentation),
  `edge`, `operator` (with a `crdgen` binary).
- **Operator image.** An official HAProxy LTS image as base with the
  operator binary added, running as non-root. Published to
  `ghcr.io/fables-for-robots/iroh-gateway-operator`.
- **Helm chart** under `charts/iroh-gateway`: Deployment, RBAC, the `Edge`
  CRD, a `GatewayClass`, an optional `NetworkPolicy`, metrics Service.
  Gateway API CRDs are a prerequisite, not bundled.
- **Edge.** Static Linux binaries for x86_64 and aarch64, a hardened systemd
  unit (dynamic user, `CAP_NET_BIND_SERVICE` only), and a NixOS module from
  the flake. Subcommands: `run`, and `id` to print the EndpointId.
  Configuration: key file path, operator EndpointId, iroh listen address,
  connection cap, relay mode.
- **Operator relay mode** is a chart value, default `disabled`.
- **Toolchain.** Rust 1.100 (`rust-version = "1.100"`). nixpkgs 26.05 ships
  1.95 and unstable 1.99, so the flake takes the toolchain from
  `oxalica/rust-overlay`, pinned by a `rust-toolchain.toml`.
- **Flake** dev shell: that toolchain, `haproxy`, `kind`, `kubectl`, `helm`.
- **License** AGPL-3.0-or-later, as the sibling projects.

## Observability

Both binaries log with `tracing` and serve Prometheus metrics: tunnel state
per edge, streams and flows open, bytes each way, dropped and fragmented
datagrams, bind failures, reload count and failures, reconcile durations.
HAProxy's built-in Prometheus exporter is exposed on the pod's metrics port.

## Testing

- **Unit.** Model building (precedence, conflicts, refused references,
  status conditions) and rendering against golden `haproxy.cfg` files.
  Property tests for fragmentation and reassembly.
- **Integration, no cluster.** Edge and operator tunnel endpoints in one
  process over loopback with relays off: TCP echo including half-close and
  reset; UDP echo including packets above the datagram size; reconnect after
  the edge restarts; rejection of an unlisted key; an edge with no direct
  address reached through a relay started inside the test. A real `haproxy` binary
  for HTTP routing, TLS termination and reload-on-change.
- **End to end.** A kind cluster with the chart installed and an edge
  process outside it: HTTP, HTTPS with a test certificate, TCP and UDP
  requests through the edge to in-cluster echo services, and status
  assertions on `Gateway`, routes and `Edge`.

## Build order

Each step ends in something that runs.

1. Tunnel with static configuration: `proto`, edge, operator-side endpoint,
   TCP forwarding to a fixed target. No Kubernetes.
2. Controller skeleton: `Edge` CRD, `GatewayClass`, `Gateway`, `TCPRoute`,
   HAProxy supervision, status. Raw TCP works in a cluster.
3. HTTP and HTTPS: `HTTPRoute`, TLS termination, redirects and header
   filters.
4. UDP: datagram protocol with fragmentation, `UDPRoute`.
5. Packaging and docs: chart, image, edge releases, NixOS module, README
   with a walkthrough including cert-manager and external-dns.

## Phase 2 (not built now, must stay possible)

- Several edges per Gateway with tested failover: addresses leave
  `Gateway.status` when an edge is unhealthy, with debouncing.
- Several operator replicas.
- `ReferenceGrant`, `TLSRoute`, per-pod balancing, opt-in PROXY protocol
  towards TCP backends.

## Left to the builder

- Exact crate versions and the HAProxy LTS release.
- Module layout inside each crate, error types, CLI flag names.
- Header field widths, fragment limits, reassembly window, timeouts, backoff
  values, default caps, coalescing interval.
- How host and path matching is expressed in HAProxy (ACLs or map files).
- Metric names.
- Whether the upstream conformance suite is wired in as a non-gating job.
