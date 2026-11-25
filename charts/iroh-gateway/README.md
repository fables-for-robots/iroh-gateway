# iroh-gateway Helm chart

Installs the [iroh-gateway operator](../../README.md#kubernetes), a Kubernetes Gateway API
controller that publishes Gateways through iroh-gateway edges, with its `Edge` CRD, RBAC
rules and `GatewayClass`.

The Gateway API v1.7.0 standard CRDs must be installed first (see the
[prerequisites](../../README.md#prerequisites)). No release publishes the images or the
chart yet: build the operator image and make it available to the cluster, then install the
chart from this directory:

```sh
docker build --target operator -t iroh-gateway-operator:dev .
kind load docker-image iroh-gateway-operator:dev   # or push it to your registry
helm install iroh-gateway charts/iroh-gateway \
  --namespace iroh-gateway --create-namespace \
  --set image.repository=iroh-gateway-operator --set image.tag=dev
```

`scripts/e2e-kind.sh` installs the chart this way in CI, in a kind cluster, with
`networkPolicy.enabled=true`, and runs traffic through it. `scripts/chart-test.sh` renders it
with the values below and checks the objects.

## CRD lifecycle

`crds/edges.yaml` installs the `Edge` CRD on the first install. Helm never upgrades or
deletes a CRD from `crds/`; apply a changed CRD yourself before `helm upgrade`:

```sh
kubectl apply -f charts/iroh-gateway/crds/edges.yaml
```

## Values

| Key | Default | Meaning |
|---|---|---|
| `image.repository` | `ghcr.io/fables-for-robots/iroh-gateway-operator` | |
| `image.tag` | `""` (appVersion) | |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `nameOverride`, `fullnameOverride` | `""` | Object names; by default the release name, with `-iroh-gateway` appended unless it contains it |
| `controllerName` | `gateway.fables-for-robots.ch/iroh-gateway` | `--controller-name`, and the `GatewayClass`'s `controllerName` |
| `gatewayClass.create` | `true` | Render the `GatewayClass` |
| `gatewayClass.name` | `iroh-gateway` | |
| `gatewayNamespaces` | `[]` (the release namespace) | `--gateway-namespaces`; each gets a Role to list and watch its Secrets. The chart creates no namespace: they must exist |
| `relay` | `disabled` | `--relay`: `disabled`, `n0` or a relay URL; must match the edges |
| `identity.secretName` | `iroh-gateway-identity` | `--identity-secret`, in the release namespace; created by the operator on first start |
| `metrics.port` | `8080` | `--metrics-listen=0.0.0.0:<port>`: `/metrics`, `/healthz`, `/readyz` |
| `metrics.service.enabled` | `true` | A ClusterIP Service for `/metrics` (port name `http`) |
| `metrics.serviceMonitor.enabled` | `false` | A ServiceMonitor (needs the Service and the Prometheus Operator) |
| `networkPolicy.enabled` | `false` | A NetworkPolicy admitting ingress only to the metrics port |
| `networkPolicy.metricsFrom` | `[]` (any source) | NetworkPolicyPeers allowed to reach the metrics port |
| `resources` | requests `cpu: 50m`, `memory: 128Mi`; limit `memory: 1Gi` | 1 GiB fits the worst case of one edge (about 830 MiB); add about that much per further edge |
| `serviceAccount.create` | `true` | |
| `serviceAccount.name` | `""` | The full name when created, otherwise `default` |
| `serviceAccount.annotations` | `{}` | |
| `rbac.create` | `true` | The ClusterRole, the Roles and their bindings |
| `podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity`, `priorityClassName` | `{}`/`[]`/`""` | Standard pod settings |

`replicas` is deliberately not a value: two operators would both dial the edges and write the
same status (one replica, `strategy: Recreate`).
