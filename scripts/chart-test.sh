#!/usr/bin/env bash
# Checks the Helm chart in charts/iroh-gateway without a cluster: it lints, renders it with
# several sets of values (helm template) and reads the objects back with yq (mikefarah's).
# Prints one "ok <check>" line per check and stops at the first failure with what it saw.
# Needs helm, yq and cargo (for the CRD check) on PATH. Takes no arguments.
set -euo pipefail

if [ "$#" -ne 0 ]; then
  echo "usage: $0 (no arguments)" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chart="$root/charts/iroh-gateway"
ns=iroh-gateway
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ok() { echo "ok $*"; }

# Prints "FAIL $1" and the remaining arguments, one per line, then exits non-zero.
fail() {
  echo "FAIL $1" >&2
  shift
  printf '%s\n' "$@" >&2
  exit 1
}

# Renders the chart as release $1 into file $2; the rest are helm's arguments. Fails the check
# with helm's output when the render fails.
render() {
  local release="$1" out="$2"
  shift 2
  if ! helm template "$release" "$chart" "$@" >"$out" 2>"$out.err"; then
    fail "helm template $release $*" "$(cat "$out.err")"
  fi
}

# Runs yq expression $2 on every document of file $1, without document separators.
q() { yq -N "$2" "$1"; }

# The number of rendered objects of kind $2 in file $1.
count() { q "$1" "select(.kind == \"$2\") | .kind" | grep -c . || true; }

# Fails unless file $1 holds exactly $3 objects of kind $2.
expect_count() {
  local n
  n="$(count "$1" "$2")"
  [ "$n" = "$3" ] || fail "expected $3 $2 in $1, got $n" "$(q "$1" '.kind + " " + (.metadata.namespace // "-") + "/" + .metadata.name')"
}

# Fails if two objects of file $1 share kind, namespace and name.
expect_no_duplicates() {
  local dups
  dups="$(q "$1" '.kind + " " + (.metadata.namespace // "-") + "/" + .metadata.name' | sort | uniq -d)"
  [ -z "$dups" ] || fail "objects rendered twice in $1" "$dups"
}

# The operator container's arguments in file $1, one per line.
args() { q "$1" 'select(.kind == "Deployment") | .spec.template.spec.containers[] | select(.name == "operator") | .args[]'; }

# Fails unless the operator's arguments in file $1 include $2 exactly.
expect_arg() {
  args "$1" | grep -qxF -- "$2" || fail "expected the argument $2 in $1" "$(args "$1")"
}

# "kind namespace/name" of every Role and RoleBinding in file $1, sorted.
roles() {
  q "$1" 'select(.kind == "Role" or .kind == "RoleBinding") | .kind + " " + .metadata.namespace + "/" + .metadata.name' | sort
}

# The namespaces whose Role in file $1 has a rule on Secrets alone with exactly the verbs $2
# and the resourceNames $3 (each comma-separated, in order; "" for none), sorted.
secret_rule_namespaces() {
  q "$1" "select(.kind == \"Role\") | select(.rules[] | ((.resources | join(\",\")) == \"secrets\" and (.verbs | join(\",\")) == \"$2\" and ((.resourceNames // []) | join(\",\")) == \"$3\")) | .metadata.namespace" | sort -u
}

step_lint() {
  local out
  if ! out="$(helm lint "$chart" 2>&1)"; then
    fail "helm lint" "$out"
  fi
  ok "helm lint"
}

step_defaults() {
  local f="$tmp/defaults.yaml"
  render iroh-gateway "$f" --namespace "$ns"
  for kind in Deployment ServiceAccount ClusterRole ClusterRoleBinding GatewayClass Service Role RoleBinding; do
    expect_count "$f" "$kind" 1
  done
  expect_count "$f" ServiceMonitor 0
  expect_count "$f" NetworkPolicy 0
  expect_no_duplicates "$f"
  ok "defaults: one of each object, no ServiceMonitor, no NetworkPolicy, no duplicate"

  expect_arg "$f" --metrics-listen=0.0.0.0:8080
  if args "$f" | grep -q -- '^--gateway-namespaces'; then
    fail "defaults: expected no --gateway-namespaces" "$(args "$f")"
  fi
  ok "defaults: --metrics-listen=0.0.0.0:8080 and no --gateway-namespaces"

  local image
  image="$(q "$f" 'select(.kind == "Deployment") | .spec.template.spec.containers[] | select(.name == "operator") | .image')"
  [ "$image" = ghcr.io/fables-for-robots/iroh-gateway-operator:0.0.0-dev ] ||
    fail "defaults: expected the image ghcr.io/fables-for-robots/iroh-gateway-operator:0.0.0-dev" "got '$image'"
  ok "defaults: image $image"

  local probes
  probes="$(q "$f" 'select(.kind == "Deployment") | .spec.template.spec.containers[] | select(.name == "operator") | (.livenessProbe.httpGet.path // "none") + " " + (.readinessProbe.httpGet.path // "none") + " " + (.ports[] | select(.name == "http") | .containerPort)')"
  [ "$probes" = "/healthz /readyz 8080" ] ||
    fail "defaults: expected liveness /healthz, readiness /readyz and port http 8080" "got '$probes'"
  ok "defaults: probes on /healthz and /readyz, port http 8080"

  local identity
  identity="$(secret_rule_namespaces "$f" get iroh-gateway-identity)"
  [ "$identity" = "$ns" ] || fail "defaults: expected the identity rule in $ns only" "got '$identity'" "$(roles "$f")"
  [ "$(secret_rule_namespaces "$f" create '')" = "$ns" ] ||
    fail "defaults: expected the create rule in $ns" "$(roles "$f")"
  [ "$(secret_rule_namespaces "$f" list,watch '')" = "$ns" ] ||
    fail "defaults: expected the Secret list and watch rule in $ns" "$(roles "$f")"
  ok "defaults: the Role in $ns gets the identity Secret, creates Secrets, lists and watches them"
}

step_gateway_namespaces() {
  local f="$tmp/namespaces.yaml"
  render iroh-gateway "$f" --namespace "$ns" --set 'gatewayNamespaces={iroh-gateway,apps,web}'
  expect_no_duplicates "$f"
  expect_count "$f" Role 3
  expect_count "$f" RoleBinding 3
  local readers bindings identity
  readers="$(secret_rule_namespaces "$f" list,watch '' | tr '\n' ' ')"
  [ "$readers" = "apps iroh-gateway web " ] ||
    fail "gatewayNamespaces: expected Secret list and watch in apps, iroh-gateway and web" "got '$readers'" "$(roles "$f")"
  bindings="$(q "$f" 'select(.kind == "RoleBinding") | .metadata.namespace' | sort | tr '\n' ' ')"
  [ "$bindings" = "apps iroh-gateway web " ] ||
    fail "gatewayNamespaces: expected a RoleBinding in apps, iroh-gateway and web" "got '$bindings'"
  identity="$(secret_rule_namespaces "$f" get iroh-gateway-identity)"
  [ "$identity" = "$ns" ] || fail "gatewayNamespaces: expected the identity rule in $ns only" "got '$identity'"
  ok "gatewayNamespaces: a Secret-reading Role and binding in each, the identity rule only in $ns, no duplicate"
  expect_arg "$f" --gateway-namespaces=iroh-gateway,apps,web
  ok "gatewayNamespaces: --gateway-namespaces=iroh-gateway,apps,web"
}

step_references() {
  local f="$tmp/gw.yaml" other=edge-system
  render gw "$f" --namespace "$other"
  expect_no_duplicates "$f"

  local selector labels missing
  selector="$(q "$f" 'select(.kind == "Service") | .spec.selector | to_entries | .[] | .key + "=" + .value' | sort)"
  labels="$(q "$f" 'select(.kind == "Deployment") | .spec.template.metadata.labels | to_entries | .[] | .key + "=" + .value' | sort)"
  missing="$(comm -23 <(echo "$selector") <(echo "$labels"))"
  [ -n "$selector" ] && [ -z "$missing" ] ||
    fail "release gw: the Service's selector is not a subset of the pod's labels" "selector:" "$selector" "pod labels:" "$labels"
  local matched
  matched="$(q "$f" 'select(.kind == "Deployment") | .spec.selector.matchLabels | to_entries | .[] | .key + "=" + .value' | sort)"
  missing="$(comm -23 <(echo "$matched") <(echo "$labels"))"
  [ -n "$matched" ] && [ -z "$missing" ] ||
    fail "release gw: the Deployment's selector is not a subset of its pod's labels" "selector:" "$matched" "pod labels:" "$labels"
  ok "release gw: the Service and the Deployment select the operator pod"

  local sa sa_ns used subjects
  sa="$(q "$f" 'select(.kind == "ServiceAccount") | .metadata.name')"
  sa_ns="$(q "$f" 'select(.kind == "ServiceAccount") | .metadata.namespace')"
  [ "$sa_ns" = "$other" ] || fail "release gw: expected the ServiceAccount in $other" "got '$sa_ns'"
  used="$(q "$f" 'select(.kind == "Deployment") | .spec.template.spec.serviceAccountName')"
  [ -n "$sa" ] && [ "$used" = "$sa" ] ||
    fail "release gw: the pod runs as '$used', the ServiceAccount is '$sa'"
  subjects="$(q "$f" 'select(.kind == "ClusterRoleBinding" or .kind == "RoleBinding") | .kind + " " + (.subjects[] | .kind + " " + .namespace + "/" + .name)' | sort -u)"
  [ "$subjects" = "$(printf 'ClusterRoleBinding ServiceAccount %s/%s\nRoleBinding ServiceAccount %s/%s' "$other" "$sa" "$other" "$sa")" ] ||
    fail "release gw: expected every binding to name ServiceAccount $other/$sa" "$subjects"
  ok "release gw: the ServiceAccount $sa is in $other, the pod and every binding name it"

  # Each binding's roleRef names a role rendered next to it.
  local refs rendered dangling
  refs="$(q "$f" 'select(.kind == "ClusterRoleBinding") | "ClusterRole -/" + .roleRef.name' && q "$f" 'select(.kind == "RoleBinding") | .roleRef.kind + " " + .metadata.namespace + "/" + .roleRef.name')"
  rendered="$(q "$f" 'select(.kind == "ClusterRole" or .kind == "Role") | .kind + " " + (.metadata.namespace // "-") + "/" + .metadata.name' | sort -u)"
  dangling="$(comm -23 <(echo "$refs" | sort -u) <(echo "$rendered"))"
  [ -z "$dangling" ] || fail "release gw: bindings refer to roles that are not rendered" "$dangling"
  ok "release gw: every binding refers to a rendered role"

  local controller class
  controller="$(args "$f" | sed -n 's/^--controller-name=//p')"
  class="$(q "$f" 'select(.kind == "GatewayClass") | .spec.controllerName')"
  [ -n "$controller" ] && [ "$controller" = "$class" ] ||
    fail "release gw: the GatewayClass names controller '$class', the operator is '$controller'"
  ok "release gw: the GatewayClass names the operator's controller $controller"
}

step_optional_objects() {
  local f="$tmp/optional.yaml"
  render iroh-gateway "$f" --namespace "$ns" --set networkPolicy.enabled=true --set metrics.serviceMonitor.enabled=true
  expect_count "$f" NetworkPolicy 1
  expect_count "$f" ServiceMonitor 1
  ok "networkPolicy and serviceMonitor render when enabled"

  local policy
  policy="$(q "$f" 'select(.kind == "NetworkPolicy") | (.spec.policyTypes | join(",")) + " " + (.spec.ingress | length) + " " + (.spec.ingress[0].ports[0].port) + " " + (.spec.ingress[0].from // "none")')"
  [ "$policy" = "Ingress 1 8080 none" ] ||
    fail "networkPolicy: expected policyTypes Ingress and one rule for port 8080 without from" "got '$policy'"
  local selector labels missing
  selector="$(q "$f" 'select(.kind == "NetworkPolicy") | .spec.podSelector.matchLabels | to_entries | .[] | .key + "=" + .value' | sort)"
  labels="$(q "$f" 'select(.kind == "Deployment") | .spec.template.metadata.labels | to_entries | .[] | .key + "=" + .value' | sort)"
  missing="$(comm -23 <(echo "$selector") <(echo "$labels"))"
  [ -n "$selector" ] && [ -z "$missing" ] ||
    fail "networkPolicy: its podSelector does not select the operator pod" "selector:" "$selector" "pod labels:" "$labels"
  ok "networkPolicy: selects the operator pod, Ingress only, port 8080 from anywhere"

  local g="$tmp/from.yaml" from
  render iroh-gateway "$g" --namespace "$ns" --set networkPolicy.enabled=true \
    --set 'networkPolicy.metricsFrom[0].namespaceSelector.matchLabels.name=monitoring'
  from="$(q "$g" 'select(.kind == "NetworkPolicy") | .spec.ingress[0].from[0].namespaceSelector.matchLabels.name')"
  [ "$from" = monitoring ] || fail "networkPolicy: expected metricsFrom as the rule's from" "got '$from'"
  ok "networkPolicy: metricsFrom becomes the rule's from"

  local out
  if out="$(helm template iroh-gateway "$chart" --namespace "$ns" \
    --set metrics.service.enabled=false --set metrics.serviceMonitor.enabled=true 2>&1)"; then
    fail "expected serviceMonitor without the Service to fail the render" "$out"
  fi
  ok "serviceMonitor without metrics.service fails the render"

  local h="$tmp/noservice.yaml"
  render iroh-gateway "$h" --namespace "$ns" --set metrics.service.enabled=false
  expect_count "$h" Service 0
  ok "metrics.service.enabled=false renders no Service"
}

step_switches() {
  local f="$tmp/relay.yaml"
  render iroh-gateway "$f" --namespace "$ns" --set relay=n0
  expect_arg "$f" --relay=n0
  ok "relay=n0 puts --relay=n0 on the container"

  local b="$tmp/bind.yaml"
  render iroh-gateway "$b" --namespace "$ns" --set 'metrics.bindAddress=[::]'
  expect_arg "$b" '--metrics-listen=[::]:8080'
  ok "metrics.bindAddress=[::] puts --metrics-listen=[::]:8080 on the container"

  local g="$tmp/noclass.yaml"
  render iroh-gateway "$g" --namespace "$ns" --set gatewayClass.create=false
  expect_count "$g" GatewayClass 0
  ok "gatewayClass.create=false renders no GatewayClass"

  local h="$tmp/norbac.yaml" kind
  render iroh-gateway "$h" --namespace "$ns" --set rbac.create=false
  for kind in ClusterRole ClusterRoleBinding Role RoleBinding; do
    expect_count "$h" "$kind" 0
  done
  ok "rbac.create=false renders no role and no binding"

  local s="$tmp/nosa.yaml" used
  render iroh-gateway "$s" --namespace "$ns" --set serviceAccount.create=false --set serviceAccount.name=existing
  expect_count "$s" ServiceAccount 0
  used="$(q "$s" 'select(.kind == "Deployment") | .spec.template.spec.serviceAccountName')"
  [ "$used" = existing ] || fail "serviceAccount.create=false: expected the pod to run as existing" "got '$used'"
  ok "serviceAccount.create=false uses serviceAccount.name"
}

step_crd() {
  local generated="$tmp/crd.yaml" out
  if ! (cd "$root" && cargo run -q -p iroh-gateway-operator --bin crdgen >"$generated"); then
    fail "crdgen did not run"
  fi
  if ! out="$(diff "$generated" "$chart/crds/edges.yaml" 2>&1)"; then
    fail "charts/iroh-gateway/crds/edges.yaml differs from crdgen's output" "$out"
  fi
  ok "charts/iroh-gateway/crds/edges.yaml equals crdgen's output"
}

step_lint
step_defaults
step_gateway_namespaces
step_references
step_optional_objects
step_switches
step_crd
echo "chart test passed"
