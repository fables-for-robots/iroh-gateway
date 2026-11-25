#!/usr/bin/env bash
# End-to-end test in a kind cluster: the operator installed from the Helm chart, an edge,
# Gateway API objects, real traffic, and both binaries' metrics.
#
# Expects kubectl and helm pointed at a running kind cluster and the images
# iroh-gateway-operator:e2e and iroh-gateway-edge:e2e both built locally (docker build
# --target operator|edge) and loaded into the cluster (kind load docker-image). Takes no arguments. On any failure it
# prints the state and logs of what it created and exits non-zero.
set -euo pipefail

if [ "$#" -ne 0 ]; then
  echo "usage: $0 (no arguments)" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ns=iroh-gateway
# The chart's release; its Deployment and Service are named like it, and its pod has these labels.
release=iroh-gateway
operator_labels="app.kubernetes.io/name=iroh-gateway,app.kubernetes.io/instance=$release"
edge_image=iroh-gateway-edge:e2e
gateway_api_crds=https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
tmp="$(mktemp -d)"

k() { kubectl -n "$ns" "$@"; }

diagnostics() {
  echo "=== e2e failed; cluster state follows ===" >&2
  kubectl get pods -A -o wide >&2 || true
  for resource in gateways.gateway.networking.k8s.io tcproutes.gateway.networking.k8s.io \
    udproutes.gateway.networking.k8s.io httproutes.gateway.networking.k8s.io \
    edges.gateway.fables-for-robots.ch; do
    k get "$resource" -o wide >&2 || true
    k describe "$resource" >&2 || true
  done
  # A pod that is not Ready says why only in its events.
  k describe pods -l "$operator_labels" >&2 || true
  for pod in $(k get pods -o name 2>/dev/null || true); do
    echo "=== logs of $pod ===" >&2
    k logs "$pod" --all-containers --tail=200 >&2 || true
  done
  # Only once the cert-manager steps have started does the cluster have these resources.
  kubectl get certificates,certificaterequests -A >&2 || true
  kubectl -n cert-manager logs deployment/cert-manager --tail=100 >&2 || true
}

finish() {
  status=$?
  if [ "$status" -ne 0 ]; then
    diagnostics
  fi
  rm -rf "$tmp"
  exit "$status"
}
trap finish EXIT

step() { echo "--- $*"; }

# Runs a command in the probe pod: a line sent to host:port, whatever comes back on stdout.
# A refused or closed connection gives no output; this never fails because of that.
send_line() {
  k exec probe -- sh -c \
    "(echo '$1'; sleep 1) | nc -w 3 edge.$ns.svc 8080" 2>/dev/null || true
}

# Calls "$@" every 2 s until it succeeds, for at most $1 seconds; fails if it never does.
retry() {
  local seconds="$1"
  shift
  local deadline=$((SECONDS + seconds))
  until "$@"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      return 1
    fi
    sleep 2
  done
}

# What the last check saw, for the failure message.
got=

# Runs curl in the curl pod with these arguments, each request limited to 5 s. What it prints,
# its errors included, goes to $got; the status is curl's, or kubectl's if the exec fails.
curl_pod() {
  got="$(k exec curl -- curl -sS --max-time 5 "$@" 2>&1)"
}

# True when curl in the curl pod succeeds and prints exactly $1; the rest are curl's arguments.
curl_prints() {
  local want="$1"
  shift
  curl_pod "$@" && [ "$got" = "$want" ]
}

# True when curl in the curl pod fails because the certificate does not verify (curl's exit
# code 60); the arguments are curl's.
curl_rejects_certificate() {
  if curl_pod "$@"; then
    return 1
  fi
  [[ "$got" == *"curl: (60)"* ]]
}

# True when the conditions Accepted of the parent entries of HTTPRoute $1 read $2, for example
# "True" for one parent, "True True" for two.
route_accepted() {
  got="$(k get httproutes.gateway.networking.k8s.io "$1" \
    -o jsonpath='{.status.parents[*].conditions[?(@.type=="Accepted")].status}' 2>&1)" &&
    [ "$got" = "$2" ]
}

# True when the Programmed condition of the listener named udp of Gateway public reads True.
udp_listener_programmed() {
  got="$(k get gateways.gateway.networking.k8s.io public \
    -o jsonpath='{.status.listeners[?(@.name=="udp")].conditions[?(@.type=="Programmed")].status}' 2>&1)" &&
    [ "$got" = True ]
}

# True when the Programmed condition of the listener named $1 of Gateway public reads True.
listener_programmed() {
  got="$(k get gateways.gateway.networking.k8s.io public \
    -o jsonpath="{.status.listeners[?(@.name==\"$1\")].conditions[?(@.type==\"Programmed\")].status}" 2>&1)" &&
    [ "$got" = True ]
}

# True when the Accepted condition of the only parent entry of UDPRoute udp-echo reads True.
udproute_accepted() {
  got="$(k get udproutes.gateway.networking.k8s.io udp-echo \
    -o jsonpath='{.status.parents[*].conditions[?(@.type=="Accepted")].status}' 2>&1)" &&
    [ "$got" = True ]
}

# The cluster IP of the edge's Service, where the UDP probes send to; set by the UDP steps.
udp_edge_ip=
# The last token sent by udp_dial.
token=

# Makes the udp-echo pod send "echo <token>" over UDP to the edge's Service on port 9001
# (agnhost's /dial, asked through its HTTP port from the probe pod; it waits up to 5 s for an
# answer). A fresh lowercase token each time, so an old answer cannot pass for a new one. What
# it printed goes to $got: {"responses":["<token>"]} when the packet was answered by the
# backend, {"errors":[...]} when nothing came back. The status is wget's.
udp_dial() {
  token="t$RANDOM$RANDOM"
  got="$(k exec probe -- wget -qO- -T 15 \
    "http://udp-echo.$ns.svc:8081/dial?request=echo%20$token&protocol=udp&host=$udp_edge_ip&port=9001&tries=1" 2>&1)"
}

# True when the packet of a udp_dial was answered with its token.
udp_answered() {
  udp_dial && [[ "$got" == *"\"responses\":[\"$token\"]"* ]]
}

# True when a udp_dial ran and brought no answer.
udp_silent() {
  udp_dial && [[ "$got" != *'"responses"'* ]]
}

# True when three packets in a row get no answer.
udp_stopped() {
  udp_silent && udp_silent && udp_silent
}

# Writes the Secret app-tls of type kubernetes.io/tls from certificate $1 and key $2, creating
# or replacing it.
app_tls_secret() {
  k create secret tls app-tls --cert="$1" --key="$2" --dry-run=client -o yaml | k apply -f -
}

# A self-signed certificate for app.example.test with an ECDSA P-256 key (PKCS#8): $1.crt, $1.key.
self_signed() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7 \
    -subj "/CN=app.example.test" -addext "subjectAltName = DNS:app.example.test" \
    -keyout "$1.key" -out "$1.crt"
}

# True when the operator's certificate directory holds exactly one certificate file of app-tls
# and every entry in it has mode 0600 (-rw-------).
certificate_files_private() {
  got="$(k exec "deploy/$release" -c operator -- \
    ls -l /run/iroh-gateway/haproxy/certs 2>&1)" || return 1
  local certificates others
  # grep -c prints 0 when nothing matches, and then fails.
  certificates="$(printf '%s\n' "$got" |
    grep -cE '^-rw-------[.+]? .* iroh-gateway\.app-tls\.[0-9a-f]{16}\.pem$' || true)"
  others="$(printf '%s\n' "$got" | grep -v '^total ' | grep -cvE '^-rw-------[.+]? ' || true)"
  [ "$certificates" = 1 ] && [ "$others" = 0 ]
}

# Fetches http://$1/metrics from the probe pod; what it printed, its errors included, goes to
# $got. The status is wget's.
metrics_of() {
  got="$(k exec probe -- wget -qO- -T 5 "http://$1/metrics" 2>&1)"
}

# The lines of $got that match the extended regular expression $1, or, when none does, the
# first 20 lines of $got: what a metrics check saw, for its failure message.
seen() {
  grep -E "$1" <<<"$got" || head -n 20 <<<"$got"
}

# True when the operator's /metrics, through its Service, has the tunnel to the edge up, the
# HAProxy exporter answering, and HAProxy's own metrics.
operator_metrics_complete() {
  metrics_of "$release.$ns.svc:8080" &&
    grep -qxF "iroh_gateway_operator_tunnel_up{edge=\"$edge_id\"} 1" <<<"$got" &&
    grep -qxF 'iroh_gateway_operator_haproxy_exporter_up 1' <<<"$got" &&
    grep -q '^haproxy_process_' <<<"$got"
}

# True when the edge's /metrics has a session with a configuration.
edge_metrics_complete() {
  metrics_of "edge.$ns.svc:9090" &&
    grep -qxF 'iroh_gateway_edge_session_up 1' <<<"$got"
}

# True when the operator's one pod is Ready and its container has the liveness probe on
# /healthz and the readiness probe on /readyz.
operator_pod_probed() {
  got="$(k get pod -l "$operator_labels" -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status} {.spec.containers[?(@.name=="operator")].livenessProbe.httpGet.path} {.spec.containers[?(@.name=="operator")].readinessProbe.httpGet.path}{"\n"}{end}' 2>&1)" &&
    [ "$got" = "True /healthz /readyz" ]
}

# True when the operator's /metrics counts at least one visitor stream from the edge.
operator_streams_counted() {
  metrics_of "$release.$ns.svc:8080" || return 1
  local streams
  streams="$(sed -n "s/^iroh_gateway_operator_tunnel_streams_total{edge=\"$edge_id\"} //p" <<<"$got")"
  [[ "$streams" =~ ^[0-9]+$ ]] && [ "$streams" -ge 1 ]
}

step "Gateway API CRDs"
kubectl apply --server-side -f "$gateway_api_crds"
# The chart creates a GatewayClass, so its CRD must be served before the install.
kubectl wait --for=condition=Established --timeout=60s \
  crd/gatewayclasses.gateway.networking.k8s.io crd/gateways.gateway.networking.k8s.io \
  crd/tcproutes.gateway.networking.k8s.io crd/udproutes.gateway.networking.k8s.io

step "the chart and the operator"
# The locally built image instead of the unpublished one. --wait returns once the operator's
# pod is Ready, which its readiness probe (/readyz) reports after the first pass over the
# cluster's objects.
helm install "$release" "$root/charts/iroh-gateway" --namespace "$ns" --create-namespace \
  --set image.repository=iroh-gateway-operator --set image.tag=e2e \
  --set image.pullPolicy=IfNotPresent --set networkPolicy.enabled=true \
  --wait --timeout 180s
# Helm installs crds/ before the templates.
kubectl wait --for=condition=Established --timeout=60s \
  crd/edges.gateway.fables-for-robots.ch

step "edge key"
docker run --rm -v "$tmp:/keys" --user "$(id -u)" "$edge_image" id --key-file /keys/edge.key \
  >"$tmp/edge.id"
edge_id="$(tr -d '[:space:]' <"$tmp/edge.id")"
echo "edge id: $edge_id"
[[ "$edge_id" =~ ^[0-9a-f]{64}$ ]]
k create secret generic edge-key --from-file=edge.key="$tmp/edge.key"
rm -f "$tmp/edge.key"

step "Gateway and Edge"
kubectl apply -f - <<YAML
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: $ns
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
  namespace: $ns
spec:
  endpointId: $edge_id
  address: edge.$ns.svc:7842
  gatewayRef:
    name: public
YAML

step "operator id"
operator_id=
for _ in $(seq 1 60); do
  operator_id="$(k get edges.gateway.fables-for-robots.ch e2e \
    -o jsonpath='{.status.gatewayEndpointId}' 2>/dev/null || true)"
  [ -n "$operator_id" ] && break
  sleep 2
done
echo "operator id: ${operator_id:-<never appeared>}"
[[ "$operator_id" =~ ^[0-9a-f]{64}$ ]]

step "edge"
kubectl apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: edge
  namespace: $ns
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
          image: $edge_image
          imagePullPolicy: IfNotPresent
          args:
            - run
            - --key-file=/keys/edge.key
            - --operator=$operator_id
            - --iroh-listen=0.0.0.0:7842
            - --public-bind=0.0.0.0
            - --metrics-listen=0.0.0.0:9090
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
  namespace: $ns
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
    - name: http
      protocol: TCP
      port: 8081
    - name: https
      protocol: TCP
      port: 8443
    - name: udp
      protocol: UDP
      port: 9001
    - name: metrics
      protocol: TCP
      port: 9090
YAML
k rollout status deployment/edge --timeout=120s

step "echo backend and TCPRoute"
kubectl apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  namespace: $ns
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
  namespace: $ns
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
  namespace: $ns
spec:
  parentRefs:
    - name: public
  rules:
    - backendRefs:
        - name: echo
          port: 9000
YAML
k rollout status deployment/echo --timeout=120s
k run probe --image=busybox:1.37 --image-pull-policy=IfNotPresent --restart=Never \
  --command -- sleep 3600
k wait --for=condition=Ready pod/probe --timeout=120s

step "conditions"
k wait --for=condition=Programmed gateways.gateway.networking.k8s.io/public --timeout=120s
k wait --for=condition=Connected edges.gateway.fables-for-robots.ch/e2e --timeout=120s

step "metrics: the operator's"
if ! retry 60 operator_metrics_complete; then
  echo "expected iroh_gateway_operator_tunnel_up{edge=\"$edge_id\"} 1, iroh_gateway_operator_haproxy_exporter_up 1 and haproxy_process_ lines at http://$release.$ns.svc:8080/metrics, got:" >&2
  seen '^(iroh_gateway_operator_(tunnel_up|haproxy_exporter_up)|haproxy_process_)' >&2
  exit 1
fi
seen '^iroh_gateway_operator_(tunnel_up|haproxy_exporter_up)'
echo "and $(grep -c '^haproxy_process_' <<<"$got") haproxy_process_ lines"

step "metrics: the edge's"
if ! retry 30 edge_metrics_complete; then
  echo "expected iroh_gateway_edge_session_up 1 at http://edge.$ns.svc:9090/metrics, got:" >&2
  seen '^iroh_gateway_edge_session_up' >&2
  exit 1
fi
seen '^iroh_gateway_edge_session_up'

step "probes"
if ! retry 30 operator_pod_probed; then
  echo "expected the operator pod Ready 'True' with probes on /healthz and /readyz, got '$got'" >&2
  exit 1
fi
echo "ready, liveness and readiness paths: $got"

step "traffic reaches the backend"
line="hello-$RANDOM-$RANDOM"
echoed=
for _ in $(seq 1 30); do
  echoed="$(send_line "$line")"
  [ "$echoed" = "$line" ] && break
  sleep 2
done
if [ "$echoed" != "$line" ]; then
  echo "expected the echo of '$line', got '$echoed'" >&2
  exit 1
fi
echo "echoed: $echoed"

step "metrics: the operator counted the stream"
if ! retry 30 operator_streams_counted; then
  echo "expected iroh_gateway_operator_tunnel_streams_total{edge=\"$edge_id\"} of at least 1, got:" >&2
  seen '^iroh_gateway_operator_tunnel_streams_total' >&2
  exit 1
fi
seen '^iroh_gateway_operator_tunnel_streams_total'

step "deleting the TCPRoute closes the port"
k delete tcproutes.gateway.networking.k8s.io echo
closed=
for _ in $(seq 1 15); do
  echoed="$(send_line "$line")"
  if [ "$echoed" != "$line" ]; then
    closed=yes
    break
  fi
  sleep 2
done
if [ -z "$closed" ]; then
  echo "the port still echoes 30 s after the TCPRoute was deleted" >&2
  exit 1
fi

step "web backend and curl pod"
kubectl apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: $ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: busybox:1.37
          command:
            - sh
            - -c
            - "mkdir -p /www && echo 'hello from web' >/www/index.html && exec httpd -f -p 8080 -h /www"
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: $ns
spec:
  selector:
    app: web
  ports:
    - port: 8080
YAML
k rollout status deployment/web --timeout=120s
k run curl --image=curlimages/curl:8.11.1 --image-pull-policy=IfNotPresent --restart=Never \
  --command -- sleep 3600
k wait --for=condition=Ready pod/curl --timeout=120s

step "HTTP: an HTTPRoute for app.example.test reaches the web backend"
kubectl apply -f - <<YAML
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: $ns
spec:
  gatewayClassName: iroh-gateway
  listeners:
    - name: tcp-8080
      protocol: TCP
      port: 8080
    - name: http
      protocol: HTTP
      port: 8081
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: $ns
spec:
  parentRefs:
    - name: public
      sectionName: http
  hostnames:
    - app.example.test
  rules:
    - backendRefs:
        - name: web
          port: 8080
YAML
if ! retry 60 curl_prints "hello from web" \
  -H 'Host: app.example.test' "http://edge.$ns.svc:8081/"; then
  echo "expected 'hello from web' for http://app.example.test:8081/, got '$got'" >&2
  exit 1
fi
echo "got: $got"
if ! retry 30 route_accepted app True; then
  echo "expected HTTPRoute app Accepted 'True', got '$got'" >&2
  exit 1
fi

step "HTTP: a host no route names gets 404"
if ! retry 10 curl_prints 404 -o /dev/null -w '%{http_code}' \
  -H 'Host: other.example.test' "http://edge.$ns.svc:8081/"; then
  echo "expected status 404 for http://other.example.test:8081/, got '$got'" >&2
  exit 1
fi

step "HTTP: a RequestRedirect to https answers 301 with the same host, path and query"
kubectl apply -f - <<YAML
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: secure
  namespace: $ns
spec:
  parentRefs:
    - name: public
      sectionName: http
  hostnames:
    - secure.example.test
  rules:
    - filters:
        - type: RequestRedirect
          requestRedirect:
            scheme: https
            statusCode: 301
YAML
want="301 https://secure.example.test/x?y=1"
if ! retry 60 curl_prints "$want" -o /dev/null -w '%{http_code} %header{location}' \
  -H 'Host: secure.example.test' "http://edge.$ns.svc:8081/x?y=1"; then
  echo "expected '$want' (status and Location), got '$got'" >&2
  exit 1
fi

step "HTTPS: the route on an HTTPS listener with a certificate from a Secret"
self_signed "$tmp/first"
self_signed "$tmp/second"
# The CA files curl checks the edge's certificate against, inside the curl pod.
k exec -i curl -- sh -c 'cat >/tmp/first.crt' <"$tmp/first.crt"
k exec -i curl -- sh -c 'cat >/tmp/second.crt' <"$tmp/second.crt"
app_tls_secret "$tmp/first.crt" "$tmp/first.key"
kubectl apply -f - <<YAML
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: $ns
spec:
  gatewayClassName: iroh-gateway
  listeners:
    - name: tcp-8080
      protocol: TCP
      port: 8080
    - name: http
      protocol: HTTP
      port: 8081
    - name: https
      protocol: HTTPS
      port: 8443
      tls:
        mode: Terminate
        certificateRefs:
          - name: app-tls
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: $ns
spec:
  parentRefs:
    - name: public
      sectionName: http
    - name: public
      sectionName: https
  hostnames:
    - app.example.test
  rules:
    - backendRefs:
        - name: web
          port: 8080
YAML
# SNI and Host are app.example.test; the connection goes to the edge's Service.
https=(--connect-to "app.example.test:8443:edge.$ns.svc:8443" "https://app.example.test:8443/")
if ! retry 60 curl_prints "hello from web" --cacert /tmp/first.crt "${https[@]}"; then
  echo "expected 'hello from web' for https://app.example.test:8443/, got '$got'" >&2
  exit 1
fi
echo "got: $got"
if ! retry 30 route_accepted app "True True"; then
  echo "expected HTTPRoute app Accepted 'True True' (two listeners), got '$got'" >&2
  exit 1
fi

step "HTTPS: a new certificate in the Secret is served within 30 s"
app_tls_secret "$tmp/second.crt" "$tmp/second.key"
if ! retry 30 curl_prints "hello from web" --cacert /tmp/second.crt "${https[@]}"; then
  echo "expected 'hello from web' with the new certificate within 30 s, got '$got'" >&2
  exit 1
fi
# A connection that reached the old HAProxy worker just before the switch could still pass.
if ! retry 10 curl_rejects_certificate --cacert /tmp/first.crt "${https[@]}"; then
  echo "expected the old certificate to be refused (curl exit code 60), got '$got'" >&2
  exit 1
fi
echo "refused with the old certificate: $got"

step "certificate files in the operator pod are private"
# The old certificate's file goes once the new configuration has loaded.
if ! retry 20 certificate_files_private; then
  echo "expected one iroh-gateway.app-tls.<hash>.pem and only -rw------- entries, got:" >&2
  echo "$got" >&2
  exit 1
fi
echo "$got"

step "UDP: backend, UDP listener and UDPRoute"
kubectl apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: udp-echo
  namespace: $ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: udp-echo
  template:
    metadata:
      labels:
        app: udp-echo
    spec:
      containers:
        - name: udp-echo
          image: registry.k8s.io/e2e-test-images/agnhost:2.47
          imagePullPolicy: IfNotPresent
          args:
            - netexec
            - --http-port=8081
            - --udp-port=9001
          ports:
            - containerPort: 8081
              protocol: TCP
            - containerPort: 9001
              protocol: UDP
---
apiVersion: v1
kind: Service
metadata:
  name: udp-echo
  namespace: $ns
spec:
  selector:
    app: udp-echo
  ports:
    - name: http
      protocol: TCP
      port: 8081
    - name: udp
      protocol: UDP
      port: 9001
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: $ns
spec:
  gatewayClassName: iroh-gateway
  listeners:
    - name: tcp-8080
      protocol: TCP
      port: 8080
    - name: http
      protocol: HTTP
      port: 8081
    - name: https
      protocol: HTTPS
      port: 8443
      tls:
        mode: Terminate
        certificateRefs:
          - name: app-tls
    - name: udp
      protocol: UDP
      port: 9001
---
apiVersion: gateway.networking.k8s.io/v1
kind: UDPRoute
metadata:
  name: udp-echo
  namespace: $ns
spec:
  parentRefs:
    - name: public
      sectionName: udp
  rules:
    - backendRefs:
        - name: udp-echo
          port: 9001
YAML
k rollout status deployment/udp-echo --timeout=120s
udp_edge_ip="$(k get service edge -o jsonpath='{.spec.clusterIP}')"
echo "edge service address: $udp_edge_ip"
[[ "$udp_edge_ip" =~ ^[0-9.]+$ ]]

step "UDP: a packet through the edge is answered by the backend"
# The first attempts may fail while the edge opens the port.
if ! retry 60 udp_answered; then
  echo "expected the answer '$token' from the backend through the edge's UDP port 9001, got '$got'" >&2
  exit 1
fi
echo "answered: $got"

step "UDP: conditions"
if ! retry 30 udp_listener_programmed; then
  echo "expected the listener udp of Gateway public Programmed 'True', got '$got'" >&2
  exit 1
fi
if ! retry 30 udproute_accepted; then
  echo "expected UDPRoute udp-echo Accepted 'True', got '$got'" >&2
  exit 1
fi

step "UDP: deleting the UDPRoute stops the answers"
k delete udproutes.gateway.networking.k8s.io udp-echo
if ! retry 60 udp_stopped; then
  echo "the edge still answers UDP port 9001 60 s after the UDPRoute was deleted, last got '$got'" >&2
  exit 1
fi

step "cert-manager"
# The Gateway API CRDs are installed already; without them cert-manager would need a restart.
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager --version v1.21.3 \
  --namespace cert-manager --create-namespace --set crds.enabled=true \
  --set config.gatewayAPI.enabled=true --wait --timeout 300s

step "cert-manager: an issuer and an annotated Gateway"
# The webhook may need a moment after the install before it accepts an issuer.
apply_issuer() {
  got="$(kubectl apply -f - 2>&1 <<'YAML'
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-cluster-issuer
spec:
  selfSigned: {}
YAML
  )"
}
if ! retry 60 apply_issuer; then
  echo "expected the ClusterIssuer to be applied, got '$got'" >&2
  exit 1
fi
# Every listener Gateway public has by now, plus cm. The annotation names the script's own HTTPS
# listener so that cert-manager leaves app-tls alone.
kubectl apply -f - <<YAML
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: $ns
  annotations:
    cert-manager.io/cluster-issuer: selfsigned-cluster-issuer
    cert-manager.io/ignore-tls-listeners: https
spec:
  gatewayClassName: iroh-gateway
  listeners:
    - name: tcp-8080
      protocol: TCP
      port: 8080
    - name: http
      protocol: HTTP
      port: 8081
    - name: https
      protocol: HTTPS
      port: 8443
      tls:
        mode: Terminate
        certificateRefs:
          - name: app-tls
    - name: cm
      protocol: HTTPS
      port: 8443
      hostname: cm.example.test
      tls:
        mode: Terminate
        certificateRefs:
          - name: cm-tls
    - name: udp
      protocol: UDP
      port: 9001
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: cm
  namespace: $ns
spec:
  parentRefs:
    - name: public
      sectionName: cm
  hostnames:
    - cm.example.test
  rules:
    - backendRefs:
        - name: web
          port: 8080
YAML

step "cert-manager: the Secret appears and is served"
# gateway-shim creates the Certificate some time after the Gateway is applied.
if ! retry 60 k get certificates.cert-manager.io cm-tls; then
  echo "cert-manager did not create the Certificate cm-tls for the annotated Gateway" >&2
  exit 1
fi
k wait --for=condition=Ready certificates.cert-manager.io/cm-tls --timeout=120s
k get secret cm-tls -o jsonpath='{.data.tls\.crt}' | base64 -d >"$tmp/cm.crt"
k exec -i curl -- sh -c 'cat >/tmp/cm.crt' <"$tmp/cm.crt"
cm=(--connect-to "cm.example.test:8443:edge.$ns.svc:8443" "https://cm.example.test:8443/")
if ! retry 60 curl_prints "hello from web" --cacert /tmp/cm.crt "${cm[@]}"; then
  echo "expected 'hello from web' for https://cm.example.test:8443/ with the issued certificate, got '$got'" >&2
  exit 1
fi
echo "got: $got"
if ! retry 30 listener_programmed cm; then
  echo "expected the listener cm of Gateway public Programmed 'True', got '$got'" >&2
  exit 1
fi

step "cert-manager: app-tls is untouched"
if k get certificates.cert-manager.io app-tls >/dev/null 2>&1; then
  echo "cert-manager created a Certificate app-tls for the script's own HTTPS listener:" >&2
  k get certificates.cert-manager.io app-tls -o yaml >&2 || true
  exit 1
fi

step "deleting the operator pod is prompt (the image's stop signal reaches the operator)"
# Well under the 60 s grace period: a pod that is only killed after the grace period fails here.
k delete pod -l "$operator_labels" --wait=true --timeout=30s
k wait --for=condition=Available "deployment/$release" --timeout=120s

echo "e2e passed"
