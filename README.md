# iroh-gateway

iroh-gateway is a TCP tunnel between a small public machine (the edge) and a private machine (the operator, for example a home cluster). The operator dials out to the edge over iroh (QUIC, peers identified by ed25519 key), so the private side needs no open port and no public address. Visitors connect to the edge, and their connections are carried through the tunnel to a target next to the operator. The design is in [the spec](docs/superpowers/specs/2026-11-23-iroh-gateway-design.md).

## Status

The edge binary, and the operator binary with a static configuration file or as a Kubernetes Gateway API controller for raw TCP (see [Kubernetes](#kubernetes); the images are not published yet).

## Build

```sh
direnv allow        # or: nix develop
cargo build --release
cargo test
```

The binaries are `target/release/iroh-gateway-edge` and `target/release/iroh-gateway-operator`.

## Quickstart

Everything on one machine, over loopback. Run every command below in the same terminal, from the repository root, one block after another.

1. Build, create both keys and note the two ids:

   ```sh
   cargo build --release
   EDGE=target/release/iroh-gateway-edge
   OPERATOR=target/release/iroh-gateway-operator
   EDGE_ID=$($EDGE id --key-file edge.key)
   OPERATOR_ID=$($OPERATOR id --key-file operator.key)
   echo "edge: $EDGE_ID"; echo "operator: $OPERATOR_ID"
   ```

2. Start something to expose, in the background (the `docs` directory, so the keys are not served):

   ```sh
   python3 -m http.server 3000 --bind 127.0.0.1 --directory docs >/dev/null 2>&1 &
   TARGET_PID=$!
   ```

3. Start the edge in the background, serving only that operator:

   ```sh
   $EDGE run --key-file edge.key --operator "$OPERATOR_ID" \
       --iroh-listen 127.0.0.1:7842 --public-bind 127.0.0.1 2>edge.log &
   EDGE_PID=$!
   ```

4. Write the operator configuration and start the operator in the background:

   ```sh
   cat > operator.toml <<EOF
   key_file = "operator.key"

   [[edge]]
   endpoint_id = "$EDGE_ID"
   address = "127.0.0.1:7842"

   [[edge.listener]]
   protocol = "tcp"
   port = 8080
   target = "127.0.0.1:3000"
   EOF
   $OPERATOR static --config operator.toml 2>operator.log &
   OPERATOR_PID=$!
   ```

5. Visit the target through the edge port (give the operator a moment to connect):

   ```sh
   sleep 2
   curl http://127.0.0.1:8080/
   ```

   You get the directory listing of `python3 -m http.server`. The edge and operator logs are in `edge.log` and `operator.log`.

6. Stop everything and remove what the quickstart created:

   ```sh
   kill $OPERATOR_PID $EDGE_PID $TARGET_PID
   wait
   rm -f edge.key operator.key operator.toml edge.log operator.log
   ```

On a real deployment the edge runs on the public machine with `--iroh-listen <public-ip>:7842` and the default `--public-bind ::`, the operator config names the edge's public address, and `port = 8080` is whatever public port you want. Key files must be backed up: the key is the identity. Both binaries log to stderr; set `RUST_LOG` to change the level (default `info`).

## `iroh-gateway-edge`

| Command | Flags (env) | Default |
|---|---|---|
| `id` | `--key-file` (`IROH_GATEWAY_EDGE_KEY_FILE`) | `/var/lib/iroh-gateway-edge/edge.key` |
| `run` | `--key-file` as above | |
| | `--operator <EndpointId>` (`IROH_GATEWAY_EDGE_OPERATOR`) | required |
| | `--iroh-listen <addr>` (`IROH_GATEWAY_EDGE_IROH_LISTEN`) | `0.0.0.0:7842` |
| | `--public-bind <ip>` (`IROH_GATEWAY_EDGE_PUBLIC_BIND`) | `::` |
| | `--max-connections <n>` (`IROH_GATEWAY_EDGE_MAX_CONNECTIONS`), 1 to 65536; about 400 KiB per connection in the worst case | `2048` |
| | `--tunnel-grace <duration>` (`IROH_GATEWAY_EDGE_TUNNEL_GRACE`), for example `5s` | `5s` |
| | `--relay <disabled\|n0\|URL>` (`IROH_GATEWAY_EDGE_RELAY`) | `disabled` |

`id` prints the EndpointId and a newline, nothing else, and creates the key file if it is missing. A malformed key file is an error and is never overwritten. `--public-bind ::` also accepts IPv4 on a dual-stack host. On a host with IPv6 disabled the bind fails and shows up as a listener bind error; set `--public-bind 0.0.0.0` there.

## `iroh-gateway-operator`

| Command | Flags | Default |
|---|---|---|
| `id` | `--key-file` | `operator.key` |
| `static` | `--config <file>` | required |
| `run` | see [Kubernetes](#kubernetes) | |

The static configuration file:

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

A relative `key_file` is taken relative to the directory of the configuration file. An `address` is `host:port`: an IP address (IPv6 in brackets, as in `[2001:db8::1]:7842`) or a DNS name, and a port from 1 to 65535. Unknown fields, a file without any `[[edge]]`, an edge listed twice, an edge without listeners, a listener on port 0, two listeners with the same protocol and port in one edge, a malformed `address`, and a missing `address` while `relay` is `disabled` are rejected at start.

## Kubernetes

`iroh-gateway-operator run` turns the operator into a Gateway API controller. It watches `GatewayClass`, `Gateway`, `TCPRoute`, `Service` and `Namespace` objects and the `Edge` resource of this project, runs HAProxy as a child process to forward each listener to its backend Service, tells every edge which public ports to open, and writes status back to the objects.

What this step does and does not do:

- Raw TCP only. There is no HTTP, TLS or UDP support yet; a listener with any other protocol is not accepted.
- One operator replica. The manifests use one replica with the `Recreate` strategy; running two would make both dial the edges and write the same status.
- The images are not published yet. `deploy/operator.yaml` names `ghcr.io/fables-for-robots/iroh-gateway-operator:0.1.0`, which does not exist until the packaging step is done. Build the images yourself and load them into your cluster (see below).
- No health endpoint, no metrics, no NetworkPolicy. The operator pod must be able to send UDP to the edges and TCP to the backend Services.
- Everything the manifests create lives in the namespace `iroh-gateway`.

### Prerequisites

The Gateway API v1.7.0 standard CRDs, which include `TCPRoute`:

```sh
kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
```

### Install

Build the two images and make them available to the cluster. For a kind cluster named `kind`:

```sh
docker build --target operator -t iroh-gateway-operator:dev .
docker build --target edge -t iroh-gateway-edge:dev .
kind load docker-image iroh-gateway-operator:dev iroh-gateway-edge:dev
```

Install the CRD, the namespace, the RBAC rules, the `GatewayClass` named `iroh-gateway` and the operator, then point the operator at the image you built:

```sh
kubectl apply -f deploy/
kubectl -n iroh-gateway patch deployment iroh-gateway-operator --type strategic -p \
  '{"spec":{"template":{"spec":{"containers":[{"name":"operator","imagePullPolicy":"IfNotPresent"}]}}}}'
kubectl -n iroh-gateway set image deployment/iroh-gateway-operator operator=iroh-gateway-operator:dev
kubectl -n iroh-gateway rollout status deployment/iroh-gateway-operator
```

The operator creates its own key in the Secret `iroh-gateway-identity` in `iroh-gateway` on first start (it may only `get` and `create` Secrets there, and has no access to Secrets anywhere else). The container runs as user 65532 with a read-only root filesystem; HAProxy's files go to a private directory `haproxy` that the operator creates in the in-memory volume at `/run/iroh-gateway`.

### Enrolling an edge

The two sides pin each other's key, so enrolling an edge is an exchange of two ids:

1. Create the edge's key and read its id. For an edge in the cluster, as in the example below:

   ```sh
   mkdir keys
   docker run --rm -v "$PWD/keys:/keys" --user "$(id -u)" iroh-gateway-edge:dev id --key-file /keys/edge.key
   kubectl -n iroh-gateway create secret generic edge-key --from-file=edge.key=keys/edge.key
   ```

   On a separate machine use `iroh-gateway-edge id --key-file <file>` instead. The command prints the id and creates the file if it is missing.
2. Create the `Edge` resource with that id and the address where the operator can reach the edge's iroh UDP port, and the `Gateway` it serves (see the example).
3. Read the operator's id from the `Edge`:

   ```sh
   kubectl -n iroh-gateway get edge e2e -o jsonpath='{.status.gatewayEndpointId}'
   ```

   It is filled in as soon as the operator has seen the `Edge`, whether or not the `Edge` is accepted.
4. Start the edge with `--operator <that id>`. It then serves only that operator, and the `Edge` turns `Connected`.

### Worked example

This is what `scripts/e2e-kind.sh` does (the script is the tested version of it). The Gateway and the Edge:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: iroh-gateway
spec:
  gatewayClassName: iroh-gateway
  listeners:
    - name: tcp-8080
      protocol: TCP
      port: 8080
---
apiVersion: gateway.fables-for-robots.ch/v1alpha1
kind: Edge
metadata:
  name: e2e
  namespace: iroh-gateway
spec:
  endpointId: <edge id from step 1>
  address: edge.iroh-gateway.svc:7842
  gatewayRef:
    name: public
```

The edge, with the key from step 1 and the operator id from step 3:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: edge
  namespace: iroh-gateway
spec:
  replicas: 1
  selector:
    matchLabels:
      app: edge
  template:
    metadata:
      labels:
        app: edge
    spec:
      containers:
        - name: edge
          image: iroh-gateway-edge:dev
          imagePullPolicy: IfNotPresent
          args:
            - run
            - --key-file=/keys/edge.key
            - --operator=<operator id from step 3>
            - --iroh-listen=0.0.0.0:7842
            - --public-bind=0.0.0.0
          volumeMounts:
            - name: key
              mountPath: /keys
              readOnly: true
      volumes:
        - name: key
          secret:
            secretName: edge-key
---
apiVersion: v1
kind: Service
metadata:
  name: edge
  namespace: iroh-gateway
spec:
  selector:
    app: edge
  ports:
    - name: iroh
      protocol: UDP
      port: 7842
    - name: public
      protocol: TCP
      port: 8080
```

A backend and the route to it:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  namespace: iroh-gateway
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
        - name: echo
          image: busybox:1.37
          command: ["nc", "-ll", "-p", "9000", "-e", "/bin/cat"]
          ports:
            - containerPort: 9000
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: iroh-gateway
spec:
  selector:
    app: echo
  ports:
    - port: 9000
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: echo
  namespace: iroh-gateway
spec:
  parentRefs:
    - name: public
  rules:
    - backendRefs:
        - name: echo
          port: 9000
```

Once `kubectl -n iroh-gateway get gateway public` shows `Programmed` `True` and the `Edge` shows `Connected` `True`, a connection to the edge's port 8080 reaches the echo server. Delete the `TCPRoute` and the edge closes port 8080 again.

### `iroh-gateway-operator run`

| Flag | Environment variable | Default |
|---|---|---|
| `--namespace <name>` | `POD_NAMESPACE` | required; the namespace the operator runs in, which holds its identity Secret |
| `--gateway-namespaces <a,b,...>` | `IROH_GATEWAY_NAMESPACES` | the value of `--namespace` |
| `--controller-name <name>` | `IROH_GATEWAY_CONTROLLER_NAME` | `gateway.fables-for-robots.ch/iroh-gateway` |
| `--identity-secret <name>` | `IROH_GATEWAY_IDENTITY_SECRET` | `iroh-gateway-identity` |
| `--relay <disabled\|n0\|URL>` | `IROH_GATEWAY_RELAY` | `disabled` |
| `--runtime-dir <dir>` | `IROH_GATEWAY_RUNTIME_DIR` | `/run/iroh-gateway`; the operator creates a private directory `haproxy` inside it for HAProxy's configuration and sockets |
| `--haproxy-bin <path>` | `IROH_GATEWAY_HAPROXY_BIN` | `haproxy` (from `PATH`) |

`--gateway-namespaces` lists the namespaces whose `Gateway` and `Edge` objects are served; an empty entry is an error. `--relay` must match the edges' `--relay`. The path of that `haproxy` directory may be at most 60 bytes long, so that HAProxy's socket paths fit the operating system's limit.

### Status conditions

Every condition below is also visible with `kubectl describe`. A False condition carries a reason and a message.

| Object | Condition | Meaning |
|---|---|---|
| `GatewayClass` (ours) | `Accepted` | Always True. |
| `Gateway` | `Accepted` | False with `NamespaceNotAllowed` (the namespace is not in `--gateway-namespaces`), `UnsupportedAddress` (`spec.addresses` is set; addresses come from the edges) or `ListenersNotValid` (no listener is both accepted and free of conflicts). True with reason `ListenersNotValid` when the Gateway works but some listeners do not. |
| | `Programmed` | False with `Invalid` (the Gateway is not accepted, or HAProxy refused the configuration), `AddressNotAssigned` (no accepted `Edge` is bound to the Gateway) or `Pending` (no bound edge is connected with every serving port open). |
| Listener | `Accepted` | False with `UnsupportedProtocol` (only `TCP`) or `PortUnavailable` (not between 1 and 65535). |
| | `Conflicted` | True with `HostnameConflict` (several listeners on one port with the same protocol) or `ProtocolConflict` (listeners on one port with different protocols); both listeners are then unusable. |
| | `ResolvedRefs` | False with `InvalidRouteKinds` (`allowedRoutes.kinds` does not include `TCPRoute`). |
| | `Programmed` | False with `Invalid` (the listener, its Gateway, or HAProxy is at fault) or `Pending` (no edge is ready; the message names edges that cannot bind the port). |
| `TCPRoute`, per parent | `Accepted` | False with `NoMatchingParent` (no listener matches `sectionName` and `port`), `NotAllowedByListeners` (no usable listener admits routes from the route's namespace) or `UnsupportedValue` (more than one rule, or another `TCPRoute` already holds the listener). |
| | `ResolvedRefs` | False with `InvalidKind` (the backend is not a core `Service`), `RefNotPermitted` (the Service is in another namespace), `BackendNotFound` (no such Service, an `ExternalName` Service, no cluster IP, or no TCP port with that number) or `UnsupportedValue` (the backend has no valid port). |
| `Edge` | `Accepted` | False with `NamespaceNotAllowed`, `InvalidEndpointId`, `NoAddress` (`address` is required while the operator uses no relay), `NoPublicAddress` (no `address` and no `publicAddresses`), `InvalidAddress`, `GatewayNotFound` (no `Gateway` of ours with `gatewayRef.name` in the same namespace), `GatewayNotAccepted`, or `DuplicateEndpointId` (an older `Edge` has the same id). |
| | `Connected` | False with `NotConnected`; the message says why, for example that the link has not started yet or the last connection error. An edge that is not accepted is never connected. |
| | `Programmed` | False with `NotConnected` or `BindFailed` (the edge could not open a port; the message names the port and the error). |

`Edge.status.listeners` lists, per port, whether the edge reports it bound. `Edge.status.gatewayEndpointId` is the operator's id.

### Rules you will trip over

- A `Gateway` and an `Edge` are served only in the namespaces of `--gateway-namespaces` (by default only the operator's own). In other namespaces they are not accepted.
- An `Edge` names its `Gateway` by `gatewayRef.name` and must be in the same namespace. A `Gateway` serves through the `Edge` objects that point at it.
- The `Gateway`'s `gatewayClassName` must name a `GatewayClass` whose `controllerName` is this operator's; any other `Gateway` is ignored.
- A backend must be a core `Service` with a cluster IP, in the same namespace as the `TCPRoute`. There is no `ReferenceGrant` support, `ExternalName` and headless Services do not work, and the operator sends to the Service's cluster IP.
- Each listener has at most one `TCPRoute` with at most one rule. If several routes name a listener, the oldest wins and the others are not accepted.
- A port opens on the edges only when a listener is accepted, has no conflict, and has a `TCPRoute` attached whose backend resolved. A `Gateway` with no route opens nothing (it is `Programmed` once an edge is connected); deleting the last route closes the port.
- A `Gateway` cannot ask for addresses; they come from the edges' `publicAddresses`, or from the host in their `address`.

## Running in production

- **File descriptors.** Each visitor uses one file descriptor on the edge and one on the operator (its backend connection). `iroh-gateway-edge run` and `iroh-gateway-operator static` raise their soft open-file limit to the hard limit at start (on macOS to at most 10240) and log the limit in force; the edge warns when `--max-connections` plus 64 exceeds it. If the hard limit is too low, raise it, for example with `LimitNOFILE=` in a systemd unit.
- **Ports below 1024.** On Linux, a public port below 1024 needs `CAP_NET_BIND_SERVICE` or root on the edge.
- **The iroh port.** The edge's iroh UDP port (`--iroh-listen`, default 7842) must be reachable from the operator for a direct connection.

## Trust

The visitor address a backend sees is only as trustworthy as the edge. It is for logging, not for access control. Each side pins the other's key: the edge serves only the operator named by `--operator`, and the operator connects only to the edges it lists.

## Relay mode

Relay mode is off by default (`disabled`): the operator reaches the edge at the `address` you give, and nothing else is contacted, except that a DNS name in `address` is resolved through the operator's normal system resolver. Turn it on when the operator cannot reach the edge directly, for example when the edge has no stable address. Both sides must use the same value (`--relay` on the edge, `relay` in the operator config).

A relay learns the home IP, the edge's IP, and the size and timing of the relayed traffic. With `n0` it also sees address lookups from home. A relay cannot read or alter the traffic: it is encrypted end to end between the two keys.

## Known limitations

- **Addresses exchanged in direct mode.** iroh's QUIC NAT traversal cannot be switched off in iroh 1.5: even with relay mode disabled, each side tells the other its local interface addresses and sends probe packets to the addresses it is told. Port mapping (UPnP/NAT-PMP/PCP) is disabled. Mitigation, for the edge only: start the edge with `--iroh-listen <public-ip>:7842` instead of `0.0.0.0:7842`, since only a wildcard bind advertises every interface. This limits only what the edge advertises: the operator binds wildcard sockets and still advertises its own interface addresses (its LAN addresses, for example) to the edge.
- **Stalled visitors are cut after 5 minutes.** If a visitor accepts no data for 300 seconds while data is waiting for it, the connection is aborted. Idle connections with nothing pending are not affected.
- **Half-closed connections are cut after 5 minutes of silence.** Once one side has finished sending, the connection is aborted if the other side sends nothing for 300 seconds.
- **TCP only.** UDP listeners are reported as a bind error in this version.
- **No metrics yet.** Both binaries log to stderr only.

## License

AGPL-3.0-or-later.
