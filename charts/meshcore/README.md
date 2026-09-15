# MeshTransit Core Helm chart

This chart deploys the product-owned `meshcore` image in either a single
`all`-role topology or independently scalable `api`, `control`, `worker`, and
`relay` roles. It never creates application credentials, private keys,
PostgreSQL, or Redis.

## Prerequisites

- Kubernetes 1.27 or newer and Helm 3.12 or newer.
- PostgreSQL 16 or newer with the MeshTransit roles and `btree_gist` extension.
- TLS- and ACL-protected Redis.
- A private CA ConfigMap containing `postgres-ca.pem` and `redis-ca.pem`.
- Existing runtime, control TLS, and migration Secrets.

The default object names and required keys are:

| Object | Required keys |
| --- | --- |
| `ConfigMap/meshcore-trust` | `postgres-ca.pem`, `redis-ca.pem` |
| `Secret/meshcore-runtime` | `postgres-runtime-password`, `postgres-worker-password`, `redis-password`, `enrollment-digest-active-key`, `control-noise-private-key` |
| `Secret/meshcore-control-tls` | `tls.crt`, `tls.key` |
| `Secret/meshcore-migration` | `postgres-password` |

When `config.enrollment.previousKeyID` is non-empty,
`Secret/meshcore-runtime` must also contain
`enrollment-digest-previous-key`. Provision secrets through an external secret
controller, encrypted GitOps source, or another secret manager; do not place
secret values in Helm values, command arguments, or repository files.

## Install

Copy non-secret overrides into an operator-owned values file, including the
PostgreSQL and Redis addresses and the published image digest. Then lint,
render, and install:

```text
helm lint ./charts/meshcore --strict -f /secure/path/meshcore-values.yaml
helm template meshcore ./charts/meshcore -f /secure/path/meshcore-values.yaml
helm upgrade --install meshcore ./charts/meshcore \
  --namespace meshtransit \
  --create-namespace \
  -f /secure/path/meshcore-values.yaml \
  --atomic \
  --timeout 10m
```

Pre-install and pre-upgrade hooks first validate every enabled runtime role,
then run forward-only migrations with the dedicated migration credential.
Serving Pods never run migrations.

The default NetworkPolicy allows public control ingress, operator ingress only
from the same namespace, DNS egress, and PostgreSQL/Redis traffic to Pods in the
same namespace. Configure `networkPolicy.extraEgress` before using external
database or Redis addresses. The public Service carries end-to-end TLS and
Noise upgrade traffic; use TCP/TLS passthrough and a load-balancer idle timeout
above the map keepalive interval.

Uninstalling the chart does not delete the externally managed Secrets,
ConfigMaps, PostgreSQL state, Redis deployment, backups, or key custody.
