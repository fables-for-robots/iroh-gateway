# iroh-gateway

iroh-gateway is a TCP and UDP tunnel between a small public machine (the edge) and a private machine (the operator, for example a home cluster). The operator dials out to the edge over iroh (QUIC, peers identified by ed25519 key), so the private side needs no open port and no public address. Visitors connect to the edge, and their connections and packets are carried through the tunnel to a target next to the operator. The design is in [the spec](docs/superpowers/specs/2026-11-23-iroh-gateway-design.md).

## Status

The edge binary, and the operator binary with a static configuration file or as a Kubernetes Gateway API controller for raw TCP, UDP, HTTP and HTTPS (see [Kubernetes](#kubernetes); the images are not published yet).

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
| | `--max-connections <n>` (`IROH_GATEWAY_EDGE_MAX_CONNECTIONS`), 1 to 4096; about 400 KiB per connection in the worst case | `2048` |
| | `--max-udp-flows <n>` (`IROH_GATEWAY_EDGE_MAX_UDP_FLOWS`), 1 to 4096; at the cap a new UDP flow replaces the least recently used one | `4096` |
| | `--udp-rate-limit <BYTES_PER_SECOND>` (`IROH_GATEWAY_EDGE_UDP_RATE_LIMIT`), 1 or more; see [UDP](#udp) | no limit |
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

[[edge.listener]]
protocol = "udp"              # "tcp" or "udp"; both may use one port number
port = 5353
target = "127.0.0.1:5353"
```

A UDP listener forwards each visitor's packets to its `target` as described under [UDP](#udp) (flows, limits, the backend seeing the operator's address); a listener has one target. A relative `key_file` is taken relative to the directory of the configuration file. An `address` is `host:port`: an IP address (IPv6 in brackets, as in `[2001:db8::1]:7842`) or a DNS name, and a port from 1 to 65535. Unknown fields, a file without any `[[edge]]`, an edge listed twice, an edge without listeners, a listener on port 0, two listeners with the same protocol and port in one edge (a `tcp` and a `udp` listener may share a port number), a malformed `address`, and a missing `address` while `relay` is `disabled` are rejected at start.

## Kubernetes

`iroh-gateway-operator run` turns the operator into a Gateway API controller. It watches `GatewayClass`, `Gateway`, `TCPRoute`, `UDPRoute`, `HTTPRoute`, `Service` and `Namespace` objects, the `Edge` resource of this project, and the TLS Secrets of the namespaces it serves Gateways in. It runs HAProxy as a child process, which forwards TCP listeners to their backend Service and routes HTTP and HTTPS requests by host, path, method and header, terminating TLS in the cluster. UDP listeners do not go through HAProxy: the operator forwards their packets itself (see [UDP](#udp)). It tells every edge which public ports to open, and writes status back to the objects.

What this step does and does not do:

- `TCP`, `UDP`, `HTTP` and `HTTPS` listeners, `TCPRoute`, `UDPRoute` and `HTTPRoute` (see [UDP](#udp) and [HTTP and HTTPS](#http-and-https) for what a `UDPRoute` and an `HTTPRoute` may use). There is no TLS passthrough and no `TLSRoute` or `GRPCRoute` yet; a listener with any other protocol is not accepted.
- One operator replica. The manifests use one replica with the `Recreate` strategy; running two would make both dial the edges and write the same status.
- The images are not published yet. `deploy/operator.yaml` names `ghcr.io/fables-for-robots/iroh-gateway-operator:0.1.0`, which does not exist until the packaging step is done. Build the images yourself and load them into your cluster (see below).
- No health endpoint, no metrics, no NetworkPolicy. The operator pod must be able to send UDP to the edges, and TCP and UDP to the backend Services.
- Everything the manifests create lives in the namespace `iroh-gateway`.
- Long-lived connections. A configuration change anywhere (any serving listener's routes, backends or certificates, in any namespace) reloads HAProxy. Connections that are still open 30 minutes after a reload, or after 50 further reloads, are closed, and a connection idle for an hour is closed. This is a known limit of this step for long-lived TCP such as SSH or database sessions.
- Memory. The operator accepts at most 4096 streams from one edge and buffers at most 64 MiB of unread data per edge, so in the worst case one edge can make it hold about 4096 × 192 KiB + 64 MiB ≈ 830 MiB. The manifest's limit of 1 GiB fits one edge; raise it by about that much for each further edge. UDP adds about 5.3 MiB per edge to the worst case (a 4 MiB budget for reassembling large packets, 1 MiB of received datagrams and 256 KiB queued to send), which the 1 GiB limit still covers; the kernel's buffers for the flow sockets (one per UDP flow, up to 4096 per edge) are not counted.

### Prerequisites

The Gateway API v1.7.0 standard CRDs, which include `HTTPRoute`, `TCPRoute` and `UDPRoute`:

```sh
kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
```

The `UDPRoute` CRD must be installed: the operator applies nothing until every kind it watches has been listed once.

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

The operator creates its own key in the Secret `iroh-gateway-identity` in `iroh-gateway` on first start (it may `get` that Secret by name and `create` Secrets there; with another `--identity-secret`, change the Role's `resourceNames` to match). For HTTPS it also lists and watches the Secrets of every namespace it serves Gateways in, which means it can read every Secret there; see [Secrets](#secrets). It writes status only with `patch`. The container runs as user 65532 with a read-only root filesystem; HAProxy's files go to a private directory `haproxy` that the operator creates in the in-memory volume at `/run/iroh-gateway`.

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

### HTTP and HTTPS

An HTTPS site with a redirect from HTTP. The certificate and its key are a Secret of type `kubernetes.io/tls` in the Gateway's namespace, made by cert-manager or by hand:

```sh
kubectl -n iroh-gateway create secret tls site-tls --cert=site.crt --key=site.key
```

The Gateway has an `HTTP` and an `HTTPS` listener. One `HTTPRoute` sends `www.example.com` on the HTTPS listener to the Service `site`, the other answers every HTTP request for that host with a redirect to the same path and query over HTTPS:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: iroh-gateway
spec:
  gatewayClassName: iroh-gateway
  listeners:
    - name: http
      protocol: HTTP
      port: 80
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs:
          - name: site-tls
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: site
  namespace: iroh-gateway
spec:
  parentRefs:
    - name: public
      sectionName: https
  hostnames:
    - www.example.com
  rules:
    - backendRefs:
        - name: site
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: site-redirect
  namespace: iroh-gateway
spec:
  parentRefs:
    - name: public
      sectionName: http
  hostnames:
    - www.example.com
  rules:
    - filters:
        - type: RequestRedirect
          requestRedirect:
            scheme: https
            statusCode: 301
```

`http://www.example.com/a?b=c` then answers 301 with `Location: https://www.example.com/a?b=c`. A route without `sectionName` attaches to every listener of the Gateway that admits it. Ports 80 and 443 need the edge to be allowed to bind them (see [Running in production](#running-in-production)); `scripts/e2e-kind.sh` uses 8081 and 8443 instead and adds them to the edge's Service, which must list every port of the Gateway when the edge runs in the cluster.

What an `HTTPRoute` may use:

- `hostnames`: exact names and `*.` wildcards (a wildcard needs at least one more label: `*.example.com` does not match `example.com`). A request's `Host` is compared in lower case and without its port. The route answers for the hostnames it shares with the listener; without `hostnames`, for the listener's.
- `matches`: `path` of type `Exact` or `PathPrefix` (a prefix matches whole path segments: `/foo` matches `/foo` and `/foo/bar`, not `/foobar`; a trailing `/` makes no difference), `headers` of type `Exact` (the name in any case, the value exactly; of two entries for one name the first counts; at most 16 in one match), and `method`. Every part of a match must hold; a rule applies when any of its matches does, and a rule without matches applies to every request. A path is compared with the request's path as sent, without its query and without normalising it (see [Limits of HTTP and HTTPS](#limits-of-http-and-https)).
- `backendRefs`: Services in the route's namespace, with weights. A backend that cannot be used or has weight 0 is left out; a rule left with no backend answers 500.
- Rule `filters`: `RequestHeaderModifier` and `ResponseHeaderModifier` (`set`, `add`, `remove`), and `RequestRedirect` with `scheme`, `hostname` (an exact name), `port` and `statusCode` (301, 302, 303, 307 or 308; 302 when absent). At most one filter of each type in a rule, and a rule with a redirect has no `backendRefs`. Without `port` the redirect keeps the listener's port, unless it names a `scheme`, whose default port it then uses. A `ResponseHeaderModifier` applies to every answer of its rule: a backend's, a redirect (an HSTS header on an HTTP-to-HTTPS redirect, say) and the 500 of a rule without a usable backend. A `RequestHeaderModifier` beside a redirect is accepted and has no effect, since no request is forwarded.

Anything else refuses the whole route: `Accepted` `False`, reason `UnsupportedValue`, with a message naming the rule and what is not supported. Nothing is silently ignored. In particular: `RegularExpression` paths and headers, `queryParams`, the filters `URLRewrite`, `RequestMirror`, `CORS` and `ExtensionRef`, a redirect `path`, filters on a `backendRef`, `timeouts`, `retry`, a filter that also carries the settings of another filter type, a header name with characters other than letters, digits, `-` and `_`, an empty header value (in a match or a filter), an empty entry in `hostnames`, a path that does not start with `/`, a path with a space, a `#` or a `?` (it can never match: HAProxy answers 400 to a request target with a space or a `#`, and the query is not part of the path), more than 16 header matches in one match, and a control character in a path, a header value or a hostname.

How requests are answered:

- Rules are tried in the order the Gateway API gives: an exact host before a wildcard (the longer first) before none, an `Exact` path before a `PathPrefix`, a longer prefix first, a match with a method first, more header matches first, then the older route, then the route's namespace and name. Of two rules with equal host and match, only the first counts. A request no rule matches gets 404; a route with no rules attaches and answers 404.
- Every string from a route reaches HAProxy quoted, and each match condition is a named ACL on its own line, so a route cannot change the structure of the configuration.
- `X-Forwarded-For` is set to the visitor's address, `X-Forwarded-Proto` to `http` or `https`, `X-Forwarded-Host` to the request's `Host` and `X-Forwarded-Port` to the port the visitor connected to, replacing whatever the visitor sent; a `Forwarded` or `X-Real-IP` header from the visitor is removed. WebSocket upgrades pass through.
- HTTPS listeners terminate TLS 1.2 or later and offer HTTP/2 and HTTP/1.1. The certificate is chosen by SNI among the certificates of the port's serving HTTPS listeners. An HTTPS listener that serves nothing (no attached route, or a certificate that is not usable) adds no certificate, so a handshake with SNI for its hostname fails unless another serving listener's certificate covers that name.
- Listeners that share a port share one rule list, but a more specific listener owns its hostname against the routes of less specific listeners on that port. With listeners for `*.example.com` and `foo.example.com` on one port, a route that reaches the port only through the `*.example.com` listener gets no rule for `foo.example.com`, even if it names that host; its other hosts (`bar.example.com`, or `*.example.com` itself) keep their rules. The owner need not be serving, but it must be accepted and free of conflicts; a listener without a hostname yields to every named one. What remains: a request for `foo.example.com` that matches none of the `foo.example.com` listener's rules can still be answered by a rule for `*.example.com` (or for any host) on the same port. Listener isolation, an optional feature of the Gateway API, is therefore still not provided.
- An HTTP port opens on the edges once an `HTTPRoute` is attached to one of its listeners (a redirect needs no backend); an HTTPS listener also needs every one of its certificates to be usable. Deleting the last route closes the port.
- An HTTP or HTTPS port keeps serving the rules HAProxy last loaded while a change is applied, and while HAProxy refuses a configuration (see [Limits of HTTP and HTTPS](#limits-of-http-and-https)): a route that was changed or deleted stays served by its old rules until a configuration loads, and the Gateway is `Programmed` `False` meanwhile. It closes when it leaves the plan (its last route or listener goes), or when its port number moves to a `TCP` listener.

Certificates:

- `certificateRefs` name core Secrets of type `kubernetes.io/tls` in the Gateway's namespace. A Secret in another namespace is refused with `RefNotPermitted` (there is no `ReferenceGrant` support). If any reference of a listener is unusable, the listener serves nothing: `ResolvedRefs` `False` with `InvalidCertificateRef` and a message naming the Secret and the problem, and `Programmed` `False`. Other listeners and Gateways are not affected. Certificates are checked only for accepted HTTPS listeners of Gateways in a namespace of `--gateway-namespaces`.
- `tls.crt` holds the certificate and its chain, the server's certificate first; every certificate in it must be readable (otherwise `certificate <n> in tls.crt cannot be read`, counted from 1). `tls.key` holds exactly one private key, which must belong to that certificate. A `tls.crt` that also holds a private key is refused with a message saying so.
- The certificate files HAProxy reads are not a copy of the Secret: the operator writes only the certificates and the one private key it parsed and checked, re-encoded. An EC key in SEC1 form (`EC PRIVATE KEY`) is written as PKCS#8, which OpenSSL reads whether or not the key names its curve. Comments and other blocks in the Secret are not passed on. Each file is named after the Secret and a hash of its content, so a renewed certificate (from cert-manager, for example) is a new file and HAProxy reloads with it; the old file is removed. The files are in `/run/iroh-gateway/haproxy/certs`, a directory of mode 0700, each of mode 0600, and are removed when the operator stops.

### Secrets

The operator reads two kinds of Secret:

- Its identity, `iroh-gateway-identity` in its own namespace, which it may `get` by name and creates on first start.
- The certificates of HTTPS listeners. It watches the Secrets of type `kubernetes.io/tls` in each namespace of `--gateway-namespaces`, and requests and holds no other Secret. Kubernetes cannot limit `list` and `watch` to a type, though, so the Role in `deploy/rbac.yaml` lets the operator list and watch every Secret of `iroh-gateway`, and so read every Secret there.

For each further namespace in `--gateway-namespaces` (here `apps`, which must exist), give the operator the same in a Role and RoleBinding of that namespace, and know that it can then read every Secret there:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: iroh-gateway-operator
  namespace: apps
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: iroh-gateway-operator
  namespace: apps
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: iroh-gateway-operator
subjects:
  - kind: ServiceAccount
    name: iroh-gateway-operator
    namespace: iroh-gateway
```

Until the operator has listed every resource it watches once, it applies nothing: no edge is dialed, no port opens and no status is written. While it waits (for a missing CRD, or a namespace where it may not list Secrets) it logs every 30 s which lists are missing, for example `still waiting for the first list of: Secret in apps`. One namespace without the Role therefore holds up every Gateway.

A `TCPRoute` or `HTTPRoute` the operator cannot read (one that uses a field value from the experimental channel, for example) is left out, as if it did not exist, and logged once per change with its namespace and name; every other route is served. A `Gateway`, `GatewayClass` or `Edge` it cannot read is not left out: before the first list the operator applies nothing until that object is fixed, and afterwards it keeps working with the objects of that kind as it last read them, logging the failure at most every 30 s.

### Limits of HTTP and HTTPS

- Private keys must be RSA of 2048 to 4096 bits, ECDSA P-256 or P-384, or Ed25519, as PKCS#8, PKCS#1 (RSA) or SEC1 (EC). Another key type gives `InvalidCertificateRef` with `unsupported private key type`.
- Visitors must send SNI. A TLS client that sends no server name, or one that none of the port's certificates covers, fails the handshake.
- `X-Forwarded-For` comes from the visitor address the edge reports, so it is only as trustworthy as the edge (see [Trust](#trust)).
- A certificate that passes these checks but that HAProxy still refuses fails the whole reload: the running configuration stays, and the `Programmed` condition of every accepted Gateway is `False` with HAProxy's message. That message names the file, whose name starts with the Secret's namespace and name (`<namespace>.<name>.<hash>.pem`). Meanwhile HTTP and HTTPS ports keep serving the rules HAProxy last loaded, even after further changes; a `TCP` port whose backend changed closes until an apply succeeds. After a reload that HAProxy refused, the operator reloads the previous configuration once (two failed reloads in a row would make HAProxy drop its listening sockets), and it tries the new configuration again after 5 s, then after twice as long each time, up to every 5 minutes.
- A TLS handshake must complete within 10 s, a request's headers must arrive within 10 s, and an idle keep-alive connection is closed after 60 s.
- Request paths are matched as sent, without normalising `..` or repeated slashes: a request for `/public/../admin` matches a `/public` prefix, and `//public` does not. A backend that normalises paths can therefore be asked for one that no rule was written for.
- A `Host` with a trailing dot (`www.example.com.`) matches no hostname of a listener or route; only rules for any host apply to it.
- A listener's `tls.options`, and `tls` on an `HTTP` listener, are ignored.

### UDP

A `UDP` listener and a `UDPRoute` forward packets through the tunnel as QUIC datagrams, without HAProxy. The edge opens the UDP port, the operator sends each visitor's packets to the backend Service's cluster IP and port, and the backend's replies go back to the visitor from the same port. The `Gateway` gets a listener, and a route names it and a Service (which needs a `UDP` port with that number):

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: iroh-gateway
spec:
  gatewayClassName: iroh-gateway
  listeners:
    - name: dns
      protocol: UDP
      port: 53
---
apiVersion: gateway.networking.k8s.io/v1
kind: UDPRoute
metadata:
  name: dns
  namespace: iroh-gateway
spec:
  parentRefs:
    - name: public
      sectionName: dns
  rules:
    - backendRefs:
        - name: dns
          port: 53
```

The edge's `Service` (or firewall) must let UDP on that port in. `scripts/e2e-kind.sh` sends packets through such a route to a backend that answers them.

What to know:

- **The backend sees the operator pod,** not the visitor, as with TCP.
- **A flow is a visitor's address and port.** It lasts 60 s after its last packet in either direction. The operator picks the flow's backend by weight when the flow begins, so a visitor who returns after the flow has ended may get another backend. A flow ends at once when its backend is no longer listed in the route with a weight above 0 (a backend set to weight 0 loses its flows immediately; UDP has no draining), and when its route or listener goes away.
- **At most 4,096 flows per edge.** At the limit a new flow replaces the least recently used one, so someone spraying packets from made-up source addresses cannot shut new visitors out, though they can push existing flows out. `--max-udp-flows` lowers the limit on an edge.
- **Packets up to 65,535 bytes work.** A packet larger than one QUIC datagram (1,200 bytes on a new path, up to 1,452 once the path is known to take it) is split into at most 64 pieces inside the tunnel, each with an 18-byte header, and put back together within 1 s on the other side. One lost piece loses the packet, as with IP fragments, and delivery is neither ordered nor retried, as with UDP. Reassembly holds at most 4 MiB of pieces per edge session, counting a small overhead for each piece.
- **A `UDP` and a `TCP`, `HTTP` or `HTTPS` listener may share a port number** on one `Gateway` (DNS on 53, for example). Two `UDP` listeners on one port conflict. A `UDP` listener takes one `UDPRoute` with one rule (the oldest wins), as a `TCP` listener does.
- **A UDP flood slows TCP and HTTP through the same edge.** QUIC sends datagrams ahead of stream data, so UDP that fills the tunnel starves the streams. `--udp-rate-limit <BYTES_PER_SECOND>` on the edge bounds it: it limits the UDP bytes the edge sends into the tunnel, counting each packet's payload plus an 18-byte header for every piece it is split into, and drops packets beyond it. Its burst is at least one largest packet (65,535 bytes plus 64 headers), so a small limit still lets a big packet through now and then. It is off by default and does not limit replies coming back from the operator.
- **On an edge with several public addresses,** replies leave from the address the system's routing picks, which may not be the one the visitor sent to.
- **UDP keeps following the cluster while HAProxy refuses a configuration:** the targets of UDP listeners change with every render, whether or not HAProxy takes it.
- **Packets are dropped quietly when they cannot be delivered:** a full tunnel, a packet no path can carry, a flow whose backend left, a datagram for a listener that an earlier configuration of the edge still named. A datagram for a listener id the operator never issued, or for a TCP listener, is logged as a warning, because the edge is then broken.

### Upgrading from the TCP-only version

The new version watches `HTTPRoute`s, `UDPRoute`s and TLS Secrets, which the old RBAC rules do not allow. Apply `deploy/rbac.yaml` before switching to the new image; otherwise the operator waits for its permissions, logging which lists it cannot get, and applies nothing, so no edge serves any port until the rules are in place. The `UDPRoute` CRD must also be installed, as it is with the standard channel of Gateway API v1.7.0; without it the operator applies nothing either.

Old and new binaries work together: an edge of the previous version answers a `UDP` listener with a bind error, and a previous operator never asks for one. Update the edges to serve UDP.

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
| `Gateway` | `Accepted` | False with `NamespaceNotAllowed` (the namespace is not in `--gateway-namespaces`), `UnsupportedAddress` (`spec.addresses` is set; addresses come from the edges) or `ListenersNotValid` (no listener is both accepted and free of conflicts). True with reason `ListenersNotValid` when the Gateway works but some listeners do not: refused, conflicted, or `HTTPS` without a usable certificate. |
| | `Programmed` | False with `Invalid` (the Gateway is not accepted, or HAProxy refused the configuration), `AddressNotAssigned` (no accepted `Edge` is bound to the Gateway) or `Pending` (no bound edge is connected with every serving port open). |
| Listener | `Accepted` | False with `UnsupportedProtocol` (only `TCP`, `UDP`, `HTTP` and `HTTPS`; `HTTPS` only with `tls.mode` `Terminate`), `UnsupportedValue` (the `hostname` of an `HTTP` or `HTTPS` listener is not a DNS name or a `*.` wildcard) or `PortUnavailable` (not between 1 and 65535). A `TCP` listener's `hostname` is ignored. |
| | `Conflicted` | True with `HostnameConflict` (several `TCP` or several `UDP` listeners on one port, or several `HTTP` or several `HTTPS` listeners on one port with the same `hostname`) or `ProtocolConflict` (listeners on one port with different protocols); the conflicting listeners are then unusable. `HTTP` listeners with different hostnames share a port, and so do `HTTPS` listeners. A `UDP` listener and a `TCP`, `HTTP` or `HTTPS` listener on one port do not conflict. |
| | `ResolvedRefs` | False with `InvalidRouteKinds` (`allowedRoutes.kinds` lists a kind other than the protocol's: `TCPRoute` for `TCP`, `UDPRoute` for `UDP`, `HTTPRoute` for `HTTP` and `HTTPS`; the listener keeps working with its own kind if that is listed too), and for an `HTTPS` listener `InvalidCertificateRef` or `RefNotPermitted` (see [Certificates](#http-and-https)), which replace `InvalidRouteKinds`. |
| | `Programmed` | False with `Invalid` (the listener, its Gateway, or HAProxy is at fault; for an `HTTPS` listener without usable certificates, the `ResolvedRefs` message) or `Pending` (no connected edge reports this listener's port open, or, for a listener without a route, no edge is connected; the message names the edges that cannot bind the port, or those not connected and those that have not reported it). True as soon as one edge has the port open, whatever the Gateway's other ports do. |
| `TCPRoute` and `UDPRoute`, per parent | `Accepted` | False with `NoMatchingParent` (no listener matches `sectionName` and `port`), `NotAllowedByListeners` (no usable listener admits routes of this kind from the route's namespace) or `UnsupportedValue` (more than one rule, or another route of the same kind already holds the listener). |
| `HTTPRoute`, per parent | `Accepted` | False with `NoMatchingParent`, `NotAllowedByListeners`, `NoMatchingListenerHostname` (no listener that admits the route shares a hostname with it) or `UnsupportedValue` (the route uses something the operator does not support; see [HTTP and HTTPS](#http-and-https)). |
| `TCPRoute`, `UDPRoute` and `HTTPRoute`, per parent | `ResolvedRefs` | False with `InvalidKind` (the backend is not a core `Service`), `RefNotPermitted` (the Service is in another namespace), `BackendNotFound` (no such Service, an `ExternalName` Service, no cluster IP, or no port with that number of the route's protocol: `UDP` for a `UDPRoute`, otherwise TCP) or `UnsupportedValue` (the backend has no valid port). |
| `Edge` | `Accepted` | False with `NamespaceNotAllowed`, `InvalidEndpointId`, `NoAddress` (`address` is required while the operator uses no relay), `NoPublicAddress` (no `address` and no `publicAddresses`), `InvalidPublicAddress` (an entry of `publicAddresses` is neither an IP address nor a DNS name; a port is not allowed), `InvalidAddress`, `GatewayNotFound` (no `Gateway` of ours with `gatewayRef.name` in the same namespace), `GatewayNotAccepted`, or `DuplicateEndpointId` (an older `Edge` has the same id). |
| | `Connected` | False with `NotConnected`; the message says why, for example that the link has not started yet or the last connection error. An edge that is not accepted is never connected. |
| | `Programmed` | False with `NotConnected`, `Pending` (connected, but the edge has not reported a port yet) or `BindFailed` (the edge could not open a port; the message names the port and the error). |

`Edge.status.listeners` lists, per port, whether the edge reports it bound. `Edge.status.gatewayEndpointId` is the operator's id.

### Rules you will trip over

- A `Gateway` and an `Edge` are served only in the namespaces of `--gateway-namespaces` (by default only the operator's own). In other namespaces they are not accepted.
- An `Edge` names its `Gateway` by `gatewayRef.name` and must be in the same namespace. A `Gateway` serves through the `Edge` objects that point at it.
- Whoever may create an `Edge` in a served namespace controls the published addresses of that namespace's Gateways and sees their raw TCP and UDP: an `Edge` with the id of an edge they run adds its addresses to the Gateway, and that edge then carries, and sees, the TCP streams and UDP packets of the visitors who use them, and can reach the Gateway's backends. Restrict who may create `Edge` resources there (RBAC on `edges.gateway.fables-for-robots.ch`).
- Pointing an `Edge` at another `Gateway` leaves the streams that are already open running until they end; new visitors reach the new Gateway's backends. Deleting the `Edge` cuts its open streams.
- The `Gateway`'s `gatewayClassName` must name a `GatewayClass` whose `controllerName` is this operator's; any other `Gateway` is ignored.
- A backend must be a core `Service` with a cluster IP, in the same namespace as the route. There is no `ReferenceGrant` support, `ExternalName` and headless Services do not work, and the operator sends to the Service's cluster IP.
- Each `TCP` listener has at most one `TCPRoute`, and each `UDP` listener at most one `UDPRoute`, with at most one rule. If several routes name a listener, the oldest wins and the others are not accepted. An `HTTP` or `HTTPS` listener takes any number of `HTTPRoute`s.
- A port opens on the edges only when a listener is accepted and has no conflict, and: for `TCP` or `UDP`, has a `TCPRoute` or `UDPRoute` attached whose backend resolved; for `HTTP`, has an `HTTPRoute` attached; for `HTTPS`, has an `HTTPRoute` attached and usable certificates. A `Gateway` with no route opens nothing (it is `Programmed` once an edge is connected); deleting the last route closes the port.
- A certificate Secret must be in the Gateway's namespace, and that namespace needs the Secret rules of [Secrets](#secrets).
- A `Gateway` cannot ask for addresses; they come from the edges' `publicAddresses`, or from the host in their `address`. A DNS name is published in lower case without a trailing dot. A `Gateway` lists at most 16 addresses, the first 16 in sorted order; when there are more, its `Programmed` message (when True) or its `Accepted` message says how many are not listed.

## Running in production

- **File descriptors.** Each visitor uses one file descriptor on the edge and one on the operator (its backend connection); each UDP flow uses one on the operator (its socket to the backend), up to 4096 per edge. `iroh-gateway-edge run` and `iroh-gateway-operator static` raise their soft open-file limit to the hard limit at start (on macOS to at most 10240) and log the limit in force; the edge warns when `--max-connections` plus 64 exceeds it. If the hard limit is too low, raise it, for example with `LimitNOFILE=` in a systemd unit.
- **Ports below 1024.** On Linux, a public port below 1024 needs `CAP_NET_BIND_SERVICE` or root on the edge.
- **The iroh port.** The edge's iroh UDP port (`--iroh-listen`, default 7842) must be reachable from the operator for a direct connection.

## Trust

The visitor address a backend sees (in `X-Forwarded-For` for HTTP and HTTPS) is only as trustworthy as the edge. It is for logging, not for access control. A `TCPRoute` or `UDPRoute` backend sees the operator pod's address, not the visitor's. Each side pins the other's key: the edge serves only the operator named by `--operator`, and the operator connects only to the edges it lists.

## Relay mode

Relay mode is off by default (`disabled`): the operator reaches the edge at the `address` you give, and nothing else is contacted, except that a DNS name in `address` is resolved through the operator's normal system resolver. Turn it on when the operator cannot reach the edge directly, for example when the edge has no stable address. Both sides must use the same value (`--relay` on the edge, `relay` in the operator config).

A relay learns the home IP, the edge's IP, and the size and timing of the relayed traffic. With `n0` it also sees address lookups from home. A relay cannot read or alter the traffic: it is encrypted end to end between the two keys.

## Known limitations

- **Addresses exchanged in direct mode.** iroh's QUIC NAT traversal cannot be switched off in iroh 1.5: even with relay mode disabled, each side tells the other its local interface addresses and sends probe packets to the addresses it is told. Port mapping (UPnP/NAT-PMP/PCP) is disabled. Mitigation, for the edge only: start the edge with `--iroh-listen <public-ip>:7842` instead of `0.0.0.0:7842`, since only a wildcard bind advertises every interface. This limits only what the edge advertises: the operator binds wildcard sockets and still advertises its own interface addresses (its LAN addresses, for example) to the edge.
- **Stalled visitors are cut after 5 minutes.** If a visitor accepts no data for 300 seconds while data is waiting for it, the connection is aborted. Idle connections with nothing pending are not affected.
- **Half-closed connections are cut after 5 minutes of silence.** Once one side has finished sending, the connection is aborted if the other side sends nothing for 300 seconds.
- **UDP is best effort.** A packet that does not fit the tunnel, or loses a piece, is lost, and a UDP flood can slow TCP and HTTP through the same edge unless `--udp-rate-limit` is set; see [UDP](#udp).
- **No metrics yet.** Both binaries log to stderr only.

## License

AGPL-3.0-or-later.
