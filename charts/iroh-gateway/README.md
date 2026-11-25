# iroh-gateway Helm chart

Installs the [iroh-gateway operator](../../README.md#kubernetes), a Kubernetes Gateway API
controller that publishes Gateways through iroh-gateway edges, with its `Edge` CRD, its RBAC
rules, a `GatewayClass`, a Service for its metrics port, and optionally a ServiceMonitor and a
NetworkPolicy. The [README of the repository](../../README.md#install-in-a-cluster) explains
the install and walks through a complete setup.

## Install

The Gateway API v1.7.0 standard CRDs must be installed first:

```sh
kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
```

A released version, from the OCI registry (Helm 3.8 or later):

```sh
helm install iroh-gateway oci://ghcr.io/fables-for-robots/charts/iroh-gateway --version <X.Y.Z> \
  --namespace iroh-gateway --create-namespace --wait --timeout 180s
```

No version has been released yet, so the registry holds no chart. Until then, install from a
checkout of the repository, with the operator image that every push to `main` publishes under
the tag `edge`:

```sh
helm install iroh-gateway charts/iroh-gateway --namespace iroh-gateway --create-namespace \
  --set image.tag=edge --set image.pullPolicy=Always --wait --timeout 180s
```

`--wait` returns once the operator's pod is ready, which its readiness probe (`/readyz`)
reports after the operator's first pass over the cluster's objects. `scripts/e2e-kind.sh`
installs the chart from the checkout in CI, in a kind cluster, with its own image and
`networkPolicy.enabled=true`, and runs traffic through it. `scripts/chart-test.sh` lints the
chart, renders it with several sets of values and checks the objects.

## CRD lifecycle

`crds/edges.yaml` installs the `Edge` CRD on the first install. Helm never upgrades or
deletes a CRD from `crds/`, and skips it when it already exists. When a new version of the
chart changes the CRD, apply it yourself before `helm upgrade`, from a checkout:

```sh
kubectl apply --server-side -f charts/iroh-gateway/crds/edges.yaml
```

or from the released chart:

```sh
helm pull oci://ghcr.io/fables-for-robots/charts/iroh-gateway --version <X.Y.Z> --untar
kubectl apply --server-side -f iroh-gateway/crds/edges.yaml
```

## Values

| Key | Default | Meaning |
|---|---|---|
| `image.repository` | `ghcr.io/fables-for-robots/iroh-gateway-operator` | The operator's image |
| `image.tag` | `""` | `""` takes the chart's `appVersion`, the image released with the chart; `edge` for the image built from `main` |
| `image.pullPolicy` | `IfNotPresent` | `Always` with a tag that moves, such as `edge` |
| `imagePullSecrets` | `[]` | Secrets with registry credentials, for an image that is not public |
| `nameOverride` | `""` | Replaces the chart's name in object names and in the label `app.kubernetes.io/name` |
| `fullnameOverride` | `""` | The name of every object; by default the release name, with `-iroh-gateway` appended unless it contains it |
| `controllerName` | `gateway.fables-for-robots.ch/iroh-gateway` | `--controller-name`, and the `GatewayClass`'s `controllerName`; Gateways of any other class are ignored |
| `gatewayClass.create` | `true` | Render the `GatewayClass`; `false` when the class is managed elsewhere |
| `gatewayClass.name` | `iroh-gateway` | The `GatewayClass`'s name |
| `gatewayNamespaces` | `[]` | `--gateway-namespaces`, the namespaces whose `Gateway` and `Edge` objects are served; `[]` is the release namespace. Each gets a Role to list and watch its Secrets, which lets the operator read every Secret there. The chart creates no namespace: they must exist |
| `relay` | `disabled` | `--relay`: `disabled`, `n0` or a relay URL; must match the edges |
| `identity.secretName` | `iroh-gateway-identity` | `--identity-secret`, in the release namespace; created by the operator on first start, and the only Secret its Role may `get`. Back it up: every edge pins the key in it |
| `metrics.port` | `8080` | `--metrics-listen=<bindAddress>:<port>`: `/metrics`, `/healthz` and `/readyz`, where the probes go |
| `metrics.bindAddress` | `0.0.0.0` | The address of `--metrics-listen`; `0.0.0.0` is IPv4 only, `[::]` an IPv6 or dual-stack listener, for a cluster whose pod IPs are IPv6 |
| `metrics.service.enabled` | `true` | A ClusterIP Service in front of the port (port name `http`) |
| `metrics.serviceMonitor.enabled` | `false` | A ServiceMonitor for `/metrics`; needs `metrics.service.enabled` and the Prometheus Operator's CRDs |
| `networkPolicy.enabled` | `false` | A NetworkPolicy that admits ingress to the operator pod only on the metrics port; egress stays open |
| `networkPolicy.metricsFrom` | `[]` | The NetworkPolicyPeers allowed to reach the metrics port; `[]` is any source. With peers listed, the kubelet's probes must still reach the port |
| `resources.requests.cpu` | `50m` | |
| `resources.requests.memory` | `128Mi` | |
| `resources.limits.memory` | `1Gi` | Fits the worst case of one edge (about 830 MiB); add about that much for each further edge |
| `serviceAccount.create` | `true` | Create the operator's ServiceAccount |
| `serviceAccount.name` | `""` | `""` is the full name when created, `default` otherwise |
| `serviceAccount.annotations` | `{}` | |
| `rbac.create` | `true` | The ClusterRole, the Roles and their bindings; with `false`, grant the same rules yourself (see `templates/rbac.yaml`) |
| `podAnnotations` | `{}` | |
| `podLabels` | `{}` | |
| `nodeSelector` | `{}` | |
| `tolerations` | `[]` | |
| `affinity` | `{}` | |
| `priorityClassName` | `""` | |

`replicas` is deliberately not a value: two operators would both dial the edges and write the
same status (one replica, `strategy: Recreate`).
