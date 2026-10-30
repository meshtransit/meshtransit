# MeshTransit Kubernetes gateway

`meshtransit-kube-gateway` installs the MeshTransit gateway for one cluster.
People on the mesh run `kubectl` against the cluster's mesh name with no
Kubernetes credential: the gateway knows each Device by its WireGuard key,
calls the API server as the Kubernetes group the Device's rules grant, and
records every write in Core before it forwards it.

Requirements: Kubernetes 1.32 or later, a cluster created in the Console
(its name is `cluster`), and a dedicated, tainted node pool for the
gateway.

## 1. Prepare the cluster

**Gateway pool.** Label and taint the nodes the gateway may run on. Only an
administrator can set a `node-restriction.kubernetes.io/` label, so a node
cannot add itself to the pool:

```sh
kubectl label node <node> node-restriction.kubernetes.io/meshtransit-gateway-pool=<pool>
kubectl taint node <node> meshtransit.net/gateway=<pool>:NoSchedule
```

On managed clusters set both on the node group (EKS managed node group
`labels` and `taints`, GKE node pool, AKS `--labels`/`--node-taints`). Use
at least two nodes: replicas spread across nodes and an evicted replica must
have somewhere to go.

DigitalOcean (DOKS, measured in K1f): the API refuses `kubernetes.io`
labels on a node pool. Set the taint on the pool and label each node with
kubectl as above; a replaced node comes without the label, so the gateway
stays Pending there until it is labelled again (it fails closed). Also label
the pool's nodes `node.kubernetes.io/exclude-from-external-load-balancers=true`:
otherwise new nodes join every LoadBalancer Service, and one with
`externalTrafficPolicy: Local` answers errors while they join (seen as
Cloudflare 521 on the POC). DOKS accepts only the audience
`system:konnectivity-server`; DaemonSets are all in kube-system.

**Namespace.** Create it with Pod Security `restricted`:

```sh
kubectl create namespace meshtransit-gateway
kubectl label namespace meshtransit-gateway pod-security.kubernetes.io/enforce=restricted
```

Exclude it from sidecar injection and image-rewriting webhooks: the
namespace's admission policy admits only the pods the chart describes.

**Network policies.** The chart's egress allows DNS to kube-system pods,
TCP 443/6443 and UDP anywhere but link-local. Add `networkPolicy.extraEgress`
where that is not enough:

```yaml
networkPolicy:
  extraEgress:
    # NodeLocal DNSCache (GKE, EKS add-on)
    - to: [{ipBlock: {cidr: 169.254.20.10/32}}]
      ports: [{protocol: UDP, port: 53}, {protocol: TCP, port: 53}]
```

On Cilium the API server may carry the `kube-apiserver` entity, which an
`ipBlock` does not select: add a CiliumNetworkPolicy allowing
`toEntities: [kube-apiserver]` for the namespace.

**Secrets.** The chart never creates key material. Create the envelope keys
(32 random bytes per replica, made once) and the join key from the Console
(with at least as many uses as replicas). Use `kubectl create`, never
`kubectl apply` (apply copies the keys into an annotation), or External
Secrets:

```sh
kubectl -n meshtransit-gateway create secret generic meshgw-envelope \
  --from-file=key-0=<(openssl rand 32) --from-file=key-1=<(openssl rand 32)
kubectl -n meshtransit-gateway create secret generic meshgw-join \
  --from-file=key-0=join-key.txt --from-file=key-1=join-key.txt
```

## 2. Install

```sh
helm install gateway oci://.../meshtransit-kube-gateway -n meshtransit-gateway -f values.yaml
```

Minimal values:

```yaml
cluster: prod-eu
control:
  url: https://control.meshtransit.net
  fingerprint: sha256:<from the Console>
image:
  repository: <registry>/meshgw
  digest: sha256:<image digest>
apiServerAudiences: [https://kubernetes.default.svc]
gatewayPool: {enabled: true, name: <pool>}
groups:
  - {name: view, clusterRole: view, default: true}
  - {name: team-a, clusterRole: edit, namespaces: [team-a]}
  - {name: sre, clusterRole: cluster-admin, privileged: true, allowedPrincipals: [<person ID>]}
```

Do not use `--atomic` or `--wait` on the first install: each replica waits
for an administrator to approve it in the Console with the code it logs
(`kubectl logs <pod> | grep "enroll code"`), and a rollback would delete the
waiting pods with their codes.

Then:

```sh
helm test gateway -n meshtransit-gateway
kubectl -n meshtransit-gateway logs job/meshgw-check
```

`helm test` fails when a replica does not serve, a group is turned off, an
admission policy is missing, changed or not enforced, or `apiServerAudiences`
differs from the cluster's (it prints the value to set). It warns about
subjects as good as the gateway (running pods or reading Secrets in its
namespace, `nodes/proxy`, impersonation), replicas sharing a node, and a
namespace without Pod Security `restricted`. The result is also an Event on
the StatefulSet.

## 3. Values that matter

| Value | Meaning |
|---|---|
| `apiServerAudiences` | The API server's audiences (a token minted without one gets them). kind/kubeadm: `https://kubernetes.default.svc.cluster.local`; DOKS: `system:konnectivity-server` (the only one accepted); EKS usually `https://kubernetes.default.svc`; `helm test` prints the cluster's own |
| `groups` | Each group is a ServiceAccount `mt-<name>` bound to `clusterRole`, in `namespaces` or across the cluster. Exactly one default, never privileged. `cluster-admin`, `system:*` roles, and `admin`/`edit` across the cluster need `privileged: true` with `allowedPrincipals` |
| `nodeLevelNamespaces` | Namespaces whose pods run on every node, the pool included (CNI, CSI, monitoring agents). Default `[kube-system]`. Whoever runs pods there is as trusted as the gateway |
| `placement.enforce` | Deny pods outside `nodeLevelNamespaces` that tolerate every taint or name a node. Off: warn and audit only (see §4) |
| `binding.enforce`, `binding.trustedBinders` | Deny pod bindings by anyone but the scheduler and these usernames. Off by default |
| `gatewayNamespace.allowDebug` | Allow exec, attach, port-forward and proxy into the gateway's namespace (break-glass) |
| `network.*BufferBytes` | TCP buffers per connection; larger ones serve long round trips faster but leave fewer connections in the same memory |
| `resources` | Memory request must equal the limit, written the same way (`1Gi` and `1Gi`, not `1024Mi`); 1 GiB holds about 1,024 kubectl connections. Very large TCP buffers on a small pod make the gateway warn `kubernetes_tcp_buffers_exceed_memory` at start |
| `metrics.allowFrom` | NetworkPolicy peers allowed to scrape `:9090/metrics` |
| `profiles.enabled` | Apply MeshTransit access profiles: a Policy rule may narrow a group to a profile in some namespaces; the group's RBAC stays the ceiling. Off by default; needs Core with profiles on. The gateway reads the cluster's discovery with its own ServiceAccount |

Pods that target the gateway pool (its taint's key, or its label in a
selector) are always refused outside `nodeLevelNamespaces`.

## 4. Enforcing placement

Enforcing refuses, cluster-wide, new pods that tolerate every taint or name
a node outside `nodeLevelNamespaces`. Set `placement.enforce: true` and
upgrade: a pre-upgrade hook runs `meshgw check --preflight` first, which
pages through every pod template and pod in the cluster. If anything would
be refused, the hook fails, the upgrade stops, and nothing is enforced; its
log lists the workloads:

```sh
kubectl -n meshtransit-gateway logs job/meshgw-preflight
```

Add the namespaces it lists to `nodeLevelNamespaces`, or change those
workloads, and upgrade again. The hook runs on every upgrade while
enforcing; `preflight.skip: true` lets an urgent upgrade through. Argo CD
runs no hooks: enforce only after a Helm upgrade has passed the preflight.

Until enforced, whoever can create a privileged pod tolerating every taint
or naming a node can reach the gateway's node; `helm test` fails unless you
set `placement.acceptUnenforced: true`.

## 5. Operations

- **Never** `helm upgrade --force`, and never Argo CD `Replace=true`: both
  empty the replicas' state Secrets, and every replica must join again.
- **Argo CD:** the state Secrets carry `Prune=false,Delete=false`; add
  `ignoreDifferences` for their `data`. Argo runs no hooks: run
  `helm test`'s check by hand.
- **Velero:** exclude `pods` of the gateway's namespace from restores (the
  namespace's admission policy refuses them; the StatefulSet makes new ones).
- **Scaling up:** add `key-<n>` to both Secrets first.
- **Changing `imagePullSecrets`:** the namespace's policy admits only the names
  it knows, so change them in an upgrade with `preflight.skip: true` (the old
  policy would refuse the new preflight pod); gateway pods may be refused for
  a few seconds until the policy updates.
- **Renaming a group:** add the new group and change Core's rules, roll out,
  then remove the old one.
- **Uninstall** keeps the state Secrets (`helm.sh/resource-policy: keep`)
  and the last check Jobs; remove them with
  `kubectl -n <ns> delete job,secret -l app.kubernetes.io/part-of=meshtransit-kube-gateway`.
  Deleting the namespace without uninstalling leaves the cluster-wide
  policies: `kubectl delete validatingadmissionpolicy,validatingadmissionpolicybinding,flowschema,prioritylevelconfiguration,clusterrole,clusterrolebinding -l app.kubernetes.io/part-of=meshtransit-kube-gateway`.
- **Break-glass:** to mint a group's token by hand, delete the
  `meshtransit-kube-gateway-token-others` binding (the API server audits it);
  for exec into the namespace, set `gatewayNamespace.allowDebug: true`.
- One install per cluster: the cluster-wide objects have fixed names.
