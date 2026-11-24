#!/usr/bin/env bash
# End-to-end test in a kind cluster: operator, edge, Gateway API objects, real traffic.
#
# Expects kubectl pointed at a running kind cluster and the images iroh-gateway-operator:e2e
# and iroh-gateway-edge:e2e both built locally (docker build --target operator|edge) and
# loaded into the cluster (kind load docker-image). Takes no arguments. On any failure it
# prints the state and logs of what it created and exits non-zero.
set -euo pipefail

if [ "$#" -ne 0 ]; then
  echo "usage: $0 (no arguments)" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ns=iroh-gateway
operator_image=iroh-gateway-operator:e2e
edge_image=iroh-gateway-edge:e2e
gateway_api_crds=https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
tmp="$(mktemp -d)"

k() { kubectl -n "$ns" "$@"; }

diagnostics() {
  echo "=== e2e failed; cluster state follows ===" >&2
  kubectl get pods -A -o wide >&2 || true
  for resource in gateways.gateway.networking.k8s.io tcproutes.gateway.networking.k8s.io \
    edges.gateway.fables-for-robots.ch; do
    k get "$resource" -o wide >&2 || true
    k describe "$resource" >&2 || true
  done
  for pod in $(k get pods -o name 2>/dev/null || true); do
    echo "=== logs of $pod ===" >&2
    k logs "$pod" --all-containers --tail=200 >&2 || true
  done
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

step "Gateway API CRDs"
kubectl apply --server-side -f "$gateway_api_crds"
# deploy/ creates a GatewayClass, so its CRD must be served before that is applied.
kubectl wait --for=condition=Established --timeout=60s \
  crd/gatewayclasses.gateway.networking.k8s.io crd/gateways.gateway.networking.k8s.io \
  crd/tcproutes.gateway.networking.k8s.io

step "deploy/ and the operator"
kubectl apply -f "$root/deploy/"
kubectl wait --for=condition=Established --timeout=60s \
  crd/edges.gateway.fables-for-robots.ch
# Use the locally built image instead of the unpublished one in the manifest.
k patch deployment iroh-gateway-operator --type strategic -p \
  '{"spec":{"template":{"spec":{"containers":[{"name":"operator","imagePullPolicy":"IfNotPresent"}]}}}}'
k set image deployment/iroh-gateway-operator "operator=$operator_image"
k rollout status deployment/iroh-gateway-operator --timeout=180s

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

step "deleting the operator pod is prompt (the image's stop signal reaches the operator)"
# Well under the 60 s grace period: a pod that is only killed after the grace period fails here.
k delete pod -l app.kubernetes.io/name=iroh-gateway-operator --wait=true --timeout=30s
k wait --for=condition=Available deployment/iroh-gateway-operator --timeout=120s

echo "e2e passed"
