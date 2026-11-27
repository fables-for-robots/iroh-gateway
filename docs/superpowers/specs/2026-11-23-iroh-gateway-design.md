# iroh-gateway — Design

Date: 2026-11-23
Status: approved design; build steps 1 to 5 are built (see "Build order")

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
- Draining an edge, and health checks of an edge beyond its tunnel. (Phase
  1 first shipped without failover between edges; addresses that follow the
  tunnel were added after step 5, see "Edge enrolment".)
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
  - Datagram size follows the path MTU: QUIC packets start at 1200 bytes
    and MTU discovery raises them to at most 1452 by default, and what
    `max_datagram_size()` returns is smaller by the per-packet overhead
    (1162 bytes on a fresh loopback connection, measured). A full-size
    internet UDP payload (1472 bytes) therefore never fits in one datagram,
    and with the 18-byte header a visitor packet of more than about 1140
    bytes is split on a new path.
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

Port mapping (UPnP, NAT-PMP, PCP) is switched off on both sides and compiled
out of the build, because on the operator side it would ask the home router
to open an inbound port.

**Known limitation.** iroh 1.5 has no supported way to switch off QUIC NAT
traversal. Even in the default mode each side tells the other its local
interface addresses and probes the addresses it is told: the operator sends
probe packets to the edge's private and bridge addresses, and the edge to
the operator's. Binding the edge's iroh port to its public address instead
of a wildcard stops the edge from advertising its other interfaces. The
operator's side has no mitigation yet; options are a supported switch
upstream or binding the operator to specific addresses.

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
- The operator reports which kind of path it sends to an edge on, `direct`
  or `relay`:
  in `Edge.status.path` (a column of `kubectl get edge`), in the metric
  `tunnel_path` per edge, with `tunnel_path_selected_total` counting the
  changes, and in a log line at each change. It follows iroh's path events,
  so a move from the relay to the direct path shows as it happens. The edge
  reports nothing of its own. (Added after v0.2.0.)
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
- Enforces a cap on concurrent connections and refuses new ones beyond it.
  The default is 2048 connections and the most that can be configured is
  4096; the worst case is about 400 KiB of memory per connection.
- Enforces a cap on UDP flows (default and most 4096) by evicting, not
  refusing: at the cap a new flow replaces the least recently used one.
  Refusing would let anyone who sprays packets from made-up source addresses
  (about 70 a second fill 4096 flows that live for 60 s) keep every real
  visitor out; evicting costs the attacker's flows nothing but lets new
  visitors in. A flow is also forgotten after 60 s without a packet in either
  direction, when the tunnel's session changes, and when its port closes.
- Optionally limits the UDP it sends into the tunnel (`--udp-rate-limit`,
  bytes per second, off by default). The limit counts datagram bytes: each
  packet's payload plus the 18-byte header of every piece it is split into,
  so tiny and empty packets are not free. A token bucket holds at most
  `max(rate, 65 535 + 64 × 18)` bytes, so the largest packet can pass even a
  small limit, and starts full. A packet that does not fit is dropped before
  it makes a flow. The reason: QUIC sends datagrams ahead of stream data, so
  a UDP flood that fills the tunnel can stall every TCP and HTTP stream of the
  same edge, and no share of the tunnel is reserved for TCP. Replies from the
  operator are not limited.
- Does not let a visitor hold a connection slot indefinitely:
  - a connection that accepts no data for 300 s while data is waiting for
    it is aborted;
  - once one side has finished sending, the connection is aborted if the
    other side sends nothing for 300 s;
  - visitor sockets use TCP keepalive, so a visitor that vanishes is
    noticed.
- Limits what an unauthenticated host can cost it: source addresses are
  validated before a handshake is processed, at most 64 handshakes are
  pending at once, and each has 10 s to complete.
- Does not let those hosts lock the operator out. When all 64 slots are
  taken, a new handshake is still admitted and one pending handshake is
  dropped: the oldest one of the source that holds the most slots. A source
  is an IPv4 address or an IPv6 /64 prefix, because one IPv6 host usually
  controls a whole /64. One host can therefore only push out its own
  handshakes. What remains: an attacker who controls at least 63 other
  sources can still push out the operator's handshake, which then retries.
  Handshakes that arrive through a relay have no source address and share
  one group, so in relay mode a flood through the relay pushes out relayed
  handshakes first, the operator's among them.
- Forwards no visitor until the current operator session has sent its first
  `Config`.
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
  `RequestRedirect` (scheme, hostname, port, status code),
  `RequestHeaderModifier`, `ResponseHeaderModifier`.
- `TCPRoute` and `UDPRoute`: weighted `backendRefs`.
- Backends are `Service` references only.

Rules:

- An `HTTPRoute` that uses anything the operator cannot honour is refused
  whole: `Accepted=False`, reason `UnsupportedValue`, with a message naming
  the rule and the first such thing. Nothing is silently ignored, because an
  ignored match would send requests somewhere the author did not intend.
  Besides everything outside the list above (regular expressions,
  `queryParams`, `URLRewrite`, mirroring, CORS, extension filters, redirect
  paths, `backendRef` filters, timeouts, retries), this refuses: two filters
  of one type in a rule; a redirect beside `backendRefs`; a filter that
  carries another filter type's settings; a redirect status code other than
  301, 302, 303, 307 or 308; a header name outside `[A-Za-z0-9_-]`; an empty
  header value, in a match or a header filter; an empty `hostnames` entry
  (for a route it would widen the route to every host of the listener); a
  path with a space, `#` or `?`, which can never match (HAProxy answers 400
  to a request target with a space or `#`, and the query is not part of the
  path); more than 16 header matches in one match; a control character in a
  path, header value or hostname.
- A `RequestHeaderModifier` beside a redirect is accepted and has no effect,
  since no request is forwarded. A `ResponseHeaderModifier` applies to every
  answer of its rule, a redirect and a 500 included.
- Paths are matched as the request sends them, without normalising `..` or
  repeated slashes: `/public/../admin` matches a `/public` prefix. A `Host`
  with a trailing dot matches no listener or route hostname, only rules for
  any host. A listener's `tls.options`, and
  `tls` on an `HTTP` listener, are ignored.
- An `HTTPRoute` with no rules attaches and answers 404.
- Route precedence follows the Gateway API specification (hostname
  specificity, then exact path, longest prefix, method, header count, then
  oldest route, then namespace and name). Of two rules with the same host
  and match, only the first counts.
- `allowedRoutes` (namespaces `Same`/`All`/`Selector`, kinds) is enforced.
  A `kinds` list that names a kind the listener's protocol does not support
  gives `ResolvedRefs=False`, reason `InvalidRouteKinds`, while the listener
  keeps working with the kinds it supports.
- All cross-namespace `backendRefs` and `certificateRefs` are refused with
  `ResolvedRefs=False`, reason `RefNotPermitted`. `ReferenceGrant` comes
  later; refusing is the safe subset.
- One protocol family per port on a Gateway. `HTTPS` listeners with
  different hostnames may share a port; so may `HTTP` listeners. Any other
  mix on one port is `Conflicted`. The exception is `UDP`: it is its own
  family, and a `UDP` listener may use the same port number as a `TCP`,
  `HTTP` or `HTTPS` one (DNS on 53), the two being different sockets on the
  edge, bound and routed separately. Two `UDP` listeners on one port
  conflict.
- Listeners that share a port share one rule list, but a more specific
  listener owns its hostname against the routes of less specific listeners
  on that port: a route host reached through a listener gives no rule when
  another listener of the port, accepted and not conflicted (serving or
  not), has a more specific hostname (in the precedence order of hosts) that
  the host falls under. With listeners `*.example.com` and
  `foo.example.com`, a route of the wildcard listener that names
  `foo.example.com` gets no rule for it, and keeps its rules for
  `*.example.com` and other hosts. The route stays `Accepted`. What remains:
  a request for `foo.example.com` that matches none of that listener's
  rules can still be answered by a rule for `*.example.com` or for any host
  on the same port (closing that needs negated host conditions). Listener
  isolation, an optional feature of the Gateway API, is therefore still not
  provided.
- Listeners are not kept off the edge's iroh port. When the edge's iroh
  address and its public bind address overlap, as they do with the defaults
  (`0.0.0.0:7842` and `::`), a `UDP` listener on that port ends as a bind
  error that the edge reports, as for any port it cannot open.
- A TCP listener carries one `TCPRoute`, and a UDP listener one `UDPRoute`.
  If several attach, the oldest wins and the others are not accepted.
- An edge opens a `TCP` or `UDP` listener's port only once the listener has
  a route with at least one usable backend. An `HTTP` or `HTTPS` port opens once a
  route is attached to one of its listeners, because a route can answer
  without a backend (a redirect, or 500 for a rule whose backends are all
  unusable); an `HTTPS` listener also needs usable certificates. Until then
  visitors get a refused connection.
- A backend that cannot be used is left out and its share of traffic goes
  to the others. (The Gateway API asks for that share to be refused. This
  is a known deviation for now.)
- A backend must be a Service with a cluster IP. Headless and
  `ExternalName` Services are refused.
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
  path: direct                     # or relay; absent while not connected
  conditions:                      # Connected, Programmed
  listeners:
    - {protocol: TCP, port: 443, bound: true}
```

- An `Edge` without `address` is `Accepted=False` when relay mode is
  `disabled`, and one without both `address` and `publicAddresses` is
  always `Accepted=False`.
- If two `Edge` resources carry the same `endpointId`, the older one is
  accepted and the other is not. Only edges that pass every other check
  compete, so a mistyped `Edge` cannot block a correct one for the same
  machine.
- Published addresses are checked before they reach `Gateway.status`. An
  entry must be an IP address or a DNS name; names are lower-cased and a
  trailing dot is dropped. An `Edge` with an entry that is neither (a name
  with a port, for example) is `Accepted=False`, reason
  `InvalidPublicAddress`. A Gateway publishes at most 16 addresses, the
  first 16 in sorted order, which is the Gateway API's limit.
- An edge serves exactly one Gateway. A Gateway is served by any number of
  edges, and every edge of a Gateway opens all of that Gateway's ports.
  Edges are never shared, so two Gateways can never fight over a port.
- `Gateway.status.addresses` lists the public addresses of the edges that
  are connected, so that DNS follows the tunnels and a second edge gives
  failover. An IP is published as `IPAddress`, a DNS name as `Hostname`.
  (Until v0.1.0 the addresses of every accepted `Edge` were listed, connected
  or not.) The rules:
  - An edge's addresses are listed while its link is connected: a
    connection is up and the edge has answered a config on it.
  - An edge that disconnects keeps its addresses for the address grace
    (`--address-grace`, default 30 s; `0s` withdraws at once), so a tunnel
    that reconnects does not make external-dns delete and re-create a
    record. If it has not reconnected by then, its addresses are withdrawn.
  - This holds for the last edge too: a Gateway with no connected edge
    lists no address once the grace has passed. With a single edge an
    outage longer than the grace therefore removes the DNS record, and
    resolvers may cache its absence. This was chosen over keeping the last
    address: an address should mean a working edge.
  - An edge that is not connected when the operator first sees it (at the
    operator's start, or a new `Edge`) is treated as just disconnected if
    its Gateway's status already lists one of its addresses, and as
    withdrawn otherwise. So an operator restart withdraws nothing before the
    edges had the grace to reconnect, a dead edge's address does not come
    back with a restart, and a new `Edge` is listed only once it connects.
    The Gateway's status is the only remembered state.
  - An `Edge` edited to serve another Gateway, to name another
    `endpointId` or to publish other addresses is, for this rule, an edge
    first seen: the address of a machine that has never connected is not
    listed because the `Edge` object was listed before the edit.
  - An address shared by several edges is listed while any of them is
    listed. The limit of 16 applies to the listed addresses.
- A Gateway with no `Edge` is `Programmed=False`, reason
  `AddressNotAssigned`. A Gateway whose edges are all disconnected or
  unbound is `Programmed=False` with a reason saying so; conditions do not
  wait for the grace.
- A listener is `Programmed=True` once HAProxy serves it (or the UDP
  forwarder for UDP) and at least one accepted, connected edge has bound its
  port. This is decided per listener: one port that fails to bind does not
  change the other listeners. An edge's bind error shows on the `Edge` and
  in the listener's condition message.
- An `Edge` that the operator does not accept is never `Connected` or
  `Programmed`, whatever its link last reported. An `Edge` whose ports have
  not been reported yet is `Programmed=False`, reason `Pending`; `BindFailed`
  is used only for a failure the edge reported.
- Text that comes from an edge (its version, its bind errors) is cut to 256
  bytes and stripped of control characters before it is written to status.

### Certificates

An `HTTPS` listener takes its certificates from `kubernetes.io/tls` Secrets
in the Gateway's namespace; a reference to another namespace is
`RefNotPermitted`. Certificates are checked only for accepted `HTTPS`
listeners of Gateways in a served namespace, with rustls, before anything
reaches HAProxy:

- `tls.crt` must hold at least one certificate and no private key (a
  `tls.crt` with a key is refused with a message saying so), and every
  certificate in it must parse (`certificate <n> in tls.crt cannot be
  read`); `tls.key` exactly one private key.
- The key must be one rustls with ring can sign with: RSA of 2048 to 4096
  bits, ECDSA P-256 or P-384, or Ed25519; and it must belong to the first
  certificate.
- Every other problem gives the listener `ResolvedRefs=False`, reason
  `InvalidCertificateRef`; either way the listener is `Programmed=False` and
  serves nothing. A message is built from the Secret's name and fixed text,
  never from its data. One unusable certificate affects only the listener
  that refers to it.

The certificate files are not a copy of the Secret. The operator writes only
the certificates and the one private key it parsed and checked, re-encoded
as PEM, so HAProxy reads exactly what was checked; comments and other blocks
in the Secret are not passed on. An EC key in SEC1 form is written as
PKCS#8, wrapped with the algorithm of the curve ring confirmed, and checked
again in that form: OpenSSL does not read a SEC1 key without its optional
curve parameters, which ring accepts. A file is named after the Secret and the
first 16 hex characters of the SHA-256 of its content
(`<namespace>.<name>.<hash>.pem`), and each `HTTPS` port lists its files in
a crt-list named after its content in turn. A renewed certificate therefore
changes the configuration text, and the existing rule "reload when the text
changes" covers rotation. A certificate that passes these checks but that
HAProxy still refuses fails the whole reload; the `Programmed=False`
message of every accepted Gateway then carries HAProxy's message, which
names the file.

### Where Gateways may live

The operator honours `Gateway` and `Edge` resources only in namespaces named
in its configuration (chart value `gatewayNamespaces`, default: its own
namespace). It watches Secrets only in those namespaces, and requests only
those of type `kubernetes.io/tls`. Its Secret read access is granted per
namespace by `Role`, only there; routes and Services are read cluster-wide.
This keeps a cluster-wide Secret read out of the operator's permissions.
Within a gateway namespace, though, `list` and `watch` cannot be limited to
a Secret type, so the operator can read every Secret of that namespace.

### Status

Every resource the operator handles carries standard conditions with
`observedGeneration`: `GatewayClass` `Accepted`; `Gateway` `Accepted` and
`Programmed`, per-listener `Accepted`, `Programmed`, `ResolvedRefs`,
`Conflicted` and `attachedRoutes`; route parent status `Accepted` and
`ResolvedRefs` under the controller name.

Status writes are not allowed to stall the operator. Each request to the API
server has 10 s. After a pass in which a write failed, the operator writes
again after 5 s, doubling up to 60 s, until a pass succeeds. Shutdown
interrupts a write in progress.

## Tunnel protocol

ALPN `iroh-gateway/0`. A breaking change bumps the number. Control messages
are length-prefixed CBOR (as in `secret-bunker-iroh`).

**Control stream.** The operator opens the first bidirectional stream.

- Operator → edge: `Config { generation, listeners: [{ id, protocol, port }] }`,
  the full desired set, resent on every change. `id` is a small integer.
- Edge → operator: `Status { generation, listeners: [{ id, bound | error }], version }`.

Listener ids belong to the operator's link to one edge. An id stays with its
listener for as long as the listener is wanted, across reconnects, and is
never reused. The edge stamps a visitor with the id that is current when it
forwards the stream.

Liveness uses QUIC keep-alive (5 s) and idle timeout (20 s for the
connection, 15 s per path, which is iroh's maximum), not application pings.

Close codes: 1 unauthorized, 2 replaced by a newer connection from the same
operator, 3 shutdown, 4 control stream ended. Stream reset codes: 1 aborted,
2 unknown listener, 3 backend unavailable, 4 bad header.

**TCP.** For each accepted visitor connection the edge opens a
bidirectional stream and writes a header: listener id, visitor address,
local address. Raw bytes follow in both directions. Half-close maps to
stream finish and an abort maps to stream reset, in both directions. The
operator connects to the HAProxy socket for that port, writes a PROXY v2
header with the visitor's address, and copies.

The default QUIC limit on concurrent streams is far too low for this and
must be raised on both sides to the connection cap, 4096 streams per edge.

Receive memory is bounded explicitly, because the QUIC defaults are not:

- Each stream has a 256 KiB receive window, on both sides.
- The operator also caps each edge connection at 64 MiB of unread data, so
  a compromised edge cannot exhaust the operator's memory. If one edge
  fills it, only that edge's own traffic waits.
- Together with the stream limit this bounds what one edge can make the
  operator hold: about 4096 × 192 KiB + 64 MiB ≈ 830 MiB in the worst case.
  The shipped memory limit of 1 GiB fits one edge and must be raised by
  about that much for each further edge.
- UDP adds per edge on the operator: 4 MiB of reassembly, 1 MiB of received
  datagrams not yet read and 256 KiB of datagrams queued to send, about
  5.3 MiB, small against the figure above, so the worst case is about
  835 MiB and the shipped limit still fits one edge. The kernel's buffers of
  the flow sockets (one per flow, at most 4096 per edge) are not counted.
  The edge holds the same 4 MiB, 1 MiB and 256 KiB for its session, and
  queues at most 256 replies per UDP port.
- The edge has no such connection-wide cap on purpose: with one, a few
  hundred visitors that stop reading could stall every other visitor.
- The stream header is at most 256 bytes and must arrive within 5 s.
- An edge must answer a `Config` with its first `Status` within 10 s, or the
  operator drops the connection and dials again.

The operator also refuses a stream whose header names a local port that
does not match the listener its id belongs to.

**Aborts at the HAProxy hop.** A Unix socket cannot signal an abort:
closing it looks like a clean end of data, so an aborted visitor connection
reaches HAProxy as a clean close. This is accepted, and the Unix sockets
stay. HAProxy itself turns most aborts into ordinary closes towards a TCP
backend, so loopback TCP would gain little, and for HTTP it notices a
truncated request from the message framing. In return nothing outside the
operator's container can reach the sockets, and no ports have to be
allocated.

**UDP.** Each visitor packet travels as one or more QUIC datagrams, in both
directions, behind a header of 18 bytes, big-endian:

```
listener id u32 | flow id u64 | packet id u32 | fragment index u8 | fragment count u8 | payload
```

- The edge assigns a flow id per (visitor address, port) and forgets it
  after 60 s without a packet in either direction. Flow ids are never reused,
  and the edge forgets every flow when the session
  changes, so a reply can only reach a visitor of the session whose operator
  saw that visitor's packets. The operator keeps at most 4096 flows per
  edge too, and evicts the least recently used one at the cap.
- On an unknown flow id the operator picks a backend from the `UDPRoute` by
  weight, opens a UDP socket connected to it, and keeps the pairing until
  the idle timeout. Replies travel back under the same flow id and the edge
  sends them to the visitor from the listener's socket. The backend sees
  the operator pod, not the visitor.
- A flow ends when its listener id leaves the routes or its backend is no
  longer listed for the listener with a weight above 0. A backend set to
  weight 0 therefore loses its flows at once: UDP has nothing to drain. The
  socket closes with the flow, so no reply of the old backend reaches a
  visitor afterwards.
- A packet may carry up to 65 535 bytes (`MAX_PACKET`). One that does not
  fit `max_datagram_size()` minus the header is split into at most 64 pieces
  (`MAX_FRAGMENTS`); one that would need more is dropped.
  `max_datagram_size()` is read for every packet, because it changes with
  the path; `None`, or a size not above the header, drops the packet. The
  receiver reassembles within 1 s of a packet's first piece and drops what
  is incomplete.
- Reassembly is bounded: per edge session, at most 4 MiB, counting each
  stored piece's payload plus a small overhead for the piece and for its
  packet, so many tiny pieces cannot exceed it. When it is full, the oldest
  incomplete packets give way. A datagram that is shorter than the header,
  has a count of 0 or above 64, an index not below its count, or belongs to a
  packet above 65 535 bytes is dropped; none of it ends a session.
- Nothing waits, retries or blocks for a UDP packet. A packet goes into
  the tunnel only by the full-tunnel rule (see "Observability"): when the
  datagram send buffer reports room for all of its pieces, each piece queued
  in the way that never displaces one already queued, polled once so that it
  never waits; otherwise the packet is dropped and counted (`tunnel_full`).
  Sockets send without blocking, and what does not fit is dropped. Delivery
  stays unreliable and unordered, which is what UDP promises. Reliable
  streams were rejected because they add head-of-line blocking.
- QUIC sends datagrams ahead of stream data. A UDP flood that fills the
  tunnel therefore can stall TCP and HTTP through the same edge; the edge's
  optional rate limit (see "What an edge does") bounds it.
- On an edge with several public addresses of one family, replies leave
  from the address the system's routing picks, not necessarily the one the
  visitor sent to. Fixing that needs `IP_PKTINFO`, which is not built.

A stream for a listener id not in the operator's current `Config` is reset
and counted. A datagram for such an id is dropped, and counted: quietly when
the id belonged to an earlier `Config` of the link (the edge had not applied
the newest one yet, which happens at every change), and as a warning when
the operator never issued the id, or issued it to a TCP listener, because
the edge is then broken. A datagram under a known flow id with a different
listener id is dropped. Each reason is counted separately and logged
without flooding.

## Data path in the operator

### HAProxy

- One frontend per (Gateway, port), bound to a unix socket with
  `accept-proxy`. HAProxy binds no TCP port for traffic, so nothing in the
  cluster can bypass the tunnel or forge a PROXY header.
- `HTTPS` ports bind with all certificates of the serving listeners on that
  port, through a crt-list, strict SNI, TLS 1.2 minimum, ALPN
  `h2,http/1.1`. The files (see "Certificates") are written to
  `<runtime-dir>/haproxy/certs`, a directory of mode 0700 in a memory-backed
  volume, each file of mode 0600, before the configuration is validated.
  Files no loaded configuration names are removed after a successful apply,
  and all of them when HAProxy stops.
- `HTTP`/`HTTPS` frontends select a backend by host and match rules, emitted
  in precedence order. Each route rule becomes its own backend section,
  which carries that rule's filters and its weighted servers. A request no
  rule matches gets 404.
- Every string from a route is quoted before it reaches the configuration,
  and each match condition is a named ACL declared on its own line; no
  resource string stands inside an anonymous `{ … }` ACL, where a value of
  `}` would end it. A route cannot change the configuration's structure.
  Header names, which cannot be quoted inside a sample fetch, only ever
  contain `[A-Za-z0-9_-]`.
- `TCP` ports are TCP-mode frontends with one backend. The visitor address
  is logged but not passed on to the backend.
- HAProxy runs in `<runtime-dir>/haproxy`, a directory the operator creates
  for itself with mode 0700. The mount point itself may belong to someone
  else, as an `emptyDir` does. Unix socket paths are short, so the runtime
  directory's path may be at most 60 bytes.
- Global limits: `maxconn 8192`; `timeout client` and `timeout server` of
  1 h, so a connection that is idle for an hour is closed; a TLS handshake
  must complete within 10 s (`timeout client-hs`).
- `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` (the request's
  `Host`) and `X-Forwarded-Port` (the port the visitor connected to) are
  set, replacing whatever the visitor sent; `Forwarded` and `X-Real-IP` from
  the visitor are removed. WebSockets work.
- Response header filters are `http-after-response` rules, so they also
  apply to the answers HAProxy makes itself: redirects and 500s.
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

Nothing is applied before every watch has listed once. While some have not
(a CRD is missing, or the operator may not list Secrets in a gateway
namespace), the operator logs every 30 s which lists are missing. Routes
are watched so that one the operator's types cannot read is left out of the
snapshot and logged by namespace and name, instead of failing the whole
list. `Gateway`s, `GatewayClass`es and `Edge`s are not: an unreadable one
holds up the first list, and afterwards its kind stays as last read, since
a stale but serving state is safer than dropping a Gateway.

Applying a new render:

1. Changes are coalesced for a short interval.
2. The new configuration is written beside the live one and checked with
   `haproxy -c`.
3. If valid, it is swapped in and HAProxy is reloaded through the master
   socket. Established connections stay on the old worker until they end or
   a hard-stop limit passes.
4. If invalid, the running configuration stays, the affected Gateways go
   `Programmed=False` with the validator's message, and a metric counts it.
5. If HAProxy answers that the reload failed, the previous configuration is
   written back and reloaded once: after a failed reload, HAProxy's master
   re-executes without its listening sockets on the next failure, so two
   failures in a row would leave every socket refusing connections. If that
   reload does not succeed either, or the outcome of a reload is lost, the
   operator no longer assumes which configuration is live.
6. After a failed reload the operator tries again after 5 s, then after
   twice as long each time, up to 5 minutes; a successful apply resets the
   delay.

Edge listener lists are applied after HAProxy is ready for them, so an edge
never opens a TCP port that has nothing behind it. Ports that the new render
removes or re-points, and `TCP` ports whose backend changes, stop accepting
streams before HAProxy is reloaded.

UDP does not depend on HAProxy: a UDP listener adds nothing to
`haproxy.cfg`, and the UDP table of a running link follows every render at
once, whether or not HAProxy takes that render's configuration, because UDP
has no HAProxy state to be consistent with. Flows whose backend left the
table end at once (see "Tunnel protocol"). Only the ports asked of the
edge keep the order: the table is set first, then the edge is asked for the
port, so an edge never opens a UDP port that has nothing behind it.

During an apply and after one that failed, an edge keeps a TCP-family port only if it
keeps the same listener and the same socket as the last configuration
HAProxy loaded, and either the same frontend and backend text or, for an
`HTTP` or `HTTPS` port, is such a port in both. A `TCP` port whose backend
changed closes until an apply succeeds: it must never keep serving a backend
the cluster no longer assigns to it. An `HTTP` or `HTTPS` port serves many
routes and hosts, so it keeps forwarding to HAProxy's socket, which serves
the rules HAProxy last loaded: a route that was changed or deleted stays
served by its old rules until a configuration loads, with
`Programmed=False` on the Gateway meanwhile. Closing it instead would take
every host of the port down for one route's change. It closes when it
leaves the plan, changes socket, or becomes a `TCP` port.

**Known limit: long-lived connections.** Any change to a serving listener's
routes, backends or certificates, in any namespace, reloads HAProxy. A connection that is
still open 30 minutes after a reload (`hard-stop-after 30m`), or after 50
further reloads (`mworker-max-reloads 50`), is closed. A refused reload
counts twice, since the previous configuration is reloaded after it; the
retry delay grows so that a failure that persists reloads rarely. SSH and database
sessions notice this. The real fix is to change backends through HAProxy's
runtime API without reloading; that is later work.

## Packaging

- **Workspace.** Three crates: `proto` (messages, framing, fragmentation),
  `edge`, `operator` (with a `crdgen` binary).
- **Images.** The operator image is an official HAProxy LTS image with the
  operator binary added, running as non-root, published to
  `ghcr.io/fables-for-robots/iroh-gateway-operator`. The edge image, a
  distroless image with the edge binary, is published next to it as
  `ghcr.io/fables-for-robots/iroh-gateway-edge`. Both are built for amd64
  and arm64.
- **Helm chart** under `charts/iroh-gateway`: Deployment with liveness and
  readiness probes, RBAC (one `Role` per gateway namespace), the `Edge`
  CRD, a `GatewayClass`, a metrics Service, an optional `ServiceMonitor`
  and an optional `NetworkPolicy` that lets nothing in but the metrics
  port. Gateway API CRDs are a prerequisite, not bundled. The chart is the
  only way to install; the plain manifests of steps 2 to 4 (`deploy/`) are
  gone, and the CRD that `crdgen` writes lives in the chart's `crds/`.
- **Releases.** Every push to `main` publishes both images with the tags
  `edge` and `sha-<commit>`. A `v*` tag, which must equal the crates'
  version, publishes them under that version, pushes the chart to
  `oci://ghcr.io/fables-for-robots/charts`, and creates a GitHub release
  with the static edge binaries, the systemd unit and checksums.
- **Operator permissions.** In its own namespace the operator may `get` its
  identity Secret, by name, and `create` Secrets. In every gateway
  namespace a `Role` lets it `list` and `watch` Secrets, for certificates;
  that cannot be limited to a type, so it can read every Secret there. On
  status subresources it may only `patch`.
- **Operator resources.** Memory request 128 Mi, limit 1 Gi, sized for one
  edge (see the tunnel protocol's memory bound).
- **Edge.** Static Linux binaries (musl) for x86_64 and aarch64, a hardened
  systemd unit (dynamic user, `CAP_NET_BIND_SERVICE` only), and a NixOS
  module from the flake (`nixosModules.edge`) with the same hardening. The
  flake also builds both binaries (`packages.edge`, `packages.operator`).
  Subcommands: `run`, and `id` to print the EndpointId. Configuration: key
  file path, operator EndpointId, iroh listen address, connection cap,
  relay mode, metrics listen address.
- **Operator relay mode** is a chart value, default `disabled`.
- **Toolchain.** Rust 1.100 (`rust-version = "1.100"`). nixpkgs 26.05 ships
  1.95 and unstable 1.99, so the flake takes the toolchain from
  `oxalica/rust-overlay`, pinned by a `rust-toolchain.toml`.
- **Flake** dev shell: that toolchain, `haproxy`, `kind`, `kubectl`, `helm`,
  `yq` and `actionlint` for the chart and workflow checks, and `openssl`,
  which the HTTPS tests use to make RSA and SEC1 keys.
- **License** AGPL-3.0-or-later, as the sibling projects.

## Observability

Both binaries log with `tracing` and serve Prometheus metrics: tunnel state
per edge, streams and flows open, bytes each way, dropped and fragmented
datagrams, bind failures, reload count and failures, reconcile durations.
HAProxy's built-in Prometheus exporter is exposed on the pod's metrics port.

- **Endpoint.** `--metrics-listen <addr>` on `iroh-gateway-edge run` and on
  `iroh-gateway-operator run` and `static`. Without the flag nothing
  listens; the chart always sets it. An address that cannot be bound stops
  the process at start.
- **Paths.** `/metrics` on both. The operator also answers `/healthz` (200
  while the process serves) and `/readyz`: 200 once the first pass over the
  cluster's objects has been applied, whatever HAProxy said to it, and in
  `static` mode once every link is started. An operator that cannot list
  what it watches is therefore never ready.
- **One scrape.** The operator's `/metrics` is its own metrics followed by
  HAProxy's exporter output, fetched over a unix socket in the runtime
  directory within 2 s. If HAProxy does not answer, the operator's own
  metrics are served alone and `iroh_gateway_operator_haproxy_exporter_up`
  is 0.
- **Names.** `iroh_gateway_edge_…` and `iroh_gateway_operator_…`. Counters
  end in `_total`; units are bytes and seconds. Tunnel metrics of the
  operator carry the label `edge` (the EndpointId), and the series of an
  edge go away with its link. `direction` is `in` for traffic from visitors
  towards backends and `out` for the way back. No label carries a visitor
  address, a port, a hostname or a route name.
- **Full tunnel.** A UDP packet is handed to the tunnel only when the
  connection's datagram send buffer reports room for all of its pieces, and
  its pieces are queued in the way that never displaces one already queued;
  otherwise the packet is dropped and counted with the reason
  `tunnel_full`. The QUIC layer would otherwise discard the oldest queued
  piece without a trace. Under overload the newest packet is lost, not the
  oldest. The reported room is slightly generous (the QUIC library counts
  its per-datagram overhead once, not per queued datagram), so on a nearly
  full buffer a packet of several pieces can still have a later piece
  refused after earlier ones were queued; it is then counted once and its
  remaining pieces are not sent.

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
- **Integration, API server only.** The controller against a real
  `kube-apiserver` and `etcd` (envtest) with the upstream Gateway API CRDs
  installed, so the API server's own validation rules apply to every status
  the operator writes. No nodes, no pods.
- **Chart.** `scripts/chart-test.sh`, without a cluster: `helm lint`, and
  `helm template` with several sets of values, the objects read back and
  checked (names, arguments, RBAC per namespace, the CRD against `crdgen`).
- **End to end.** A kind cluster with the chart installed (with its
  `NetworkPolicy`) and the edge as a pod: TCP, HTTP, an HTTP redirect, HTTPS
  with a test certificate and its rotation, UDP (a packet through the edge to a
  backend that answers it, and its end when the `UDPRoute` is deleted),
  requests through the edge to in-cluster services, status assertions on `Gateway`,
  routes and `Edge`, both binaries' metrics and the operator's probes. A
  cert-manager step installs cert-manager v1.21.3 with its Gateway API
  support: a self-signed `ClusterIssuer` issues a certificate for a listener
  of an annotated Gateway, which is then served, and
  `cert-manager.io/ignore-tls-listeners` keeps cert-manager off another
  listener's Secret. A model test checks that a route of the shape of
  cert-manager's HTTP-01 solver is served. Let's Encrypt and external-dns are
  not run.
- **NixOS VM test** (`nix/edge-test.nix`, x86_64-linux): the module starts
  the edge as a dynamic user with its key in the state directory, binds the
  iroh port, opens it in the firewall, serves metrics and keeps its id
  across a restart. The release workflow starts the tarball's systemd unit
  on a GitHub runner and checks that it binds the iroh port and logs the id
  that `systemd-run` printed.

## Build order

Each step ends in something that runs. Steps 1 to 5 are built.

1. Tunnel with static configuration: `proto`, edge, operator-side endpoint,
   TCP forwarding to a fixed target. No Kubernetes. (Built.)
2. Controller skeleton: `Edge` CRD, `GatewayClass`, `Gateway`, `TCPRoute`,
   HAProxy supervision, status. Raw TCP works in a cluster. (Built.)
3. HTTP and HTTPS: `HTTPRoute`, TLS termination, redirects and header
   filters. (Built.)
4. UDP: datagram protocol with fragmentation, `UDPRoute`. (Built.)
5. Packaging and docs: chart, image, edge releases, NixOS module, README
   with a walkthrough including cert-manager and external-dns. (Built.)

## Phase 2 (not built now, must stay possible)

- Draining an edge before it is taken away, and health checks of an edge
  beyond its tunnel (a connected edge whose provider drops visitor traffic
  stays listed).
- Several operator replicas.
- `ReferenceGrant`, `TLSRoute`, per-pod balancing, opt-in PROXY protocol
  towards TCP backends.

## Left to the builder

- Exact crate versions and the HAProxy LTS release.
- Module layout inside each crate, error types, CLI flag names.
- Header field widths, fragment limits, reassembly window, timeouts, backoff
  values, default caps, coalescing interval.
- How host and path matching is expressed in HAProxy (ACLs or map files).
- Whether the upstream conformance suite is wired in as a non-gating job.
