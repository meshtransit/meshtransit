# Kubernetes access

People on the mesh run `kubectl` against a cluster with their own identity
and no Kubernetes credential of their own. A **gateway** installed in the
cluster knows each Device by its WireGuard key, calls the API server as the
Kubernetes group that Device's rules grant, and records every write, exec,
port-forward and Secret read in Core before it forwards it. The API server
needs no public address.

## The parts

- **Cluster.** Created in a Network in the Console
  (`…/networks/{network}/kubernetes-clusters`). Core keeps a certificate
  authority for it and gives it a name on the mesh, `<cluster>.kube.<zone>`.
- **Gateway.** The `meshtransit-kube-gateway` Helm chart, running as a few
  replicas on a dedicated node pool of the cluster. Each replica joins with a
  **join key**, as a request an administrator approves in the Console by the
  code the replica logs, or, for a cluster in `private_tofu` trust mode, with
  an **install token**, which Core approves in the name of the token's maker.
- **Groups.** The chart maps gateway groups to Kubernetes roles, such as
  `view` everywhere or `edit` in one namespace.
- **Rule to a cluster.** A source (a Device, Device Group, Identity Group or
  Device Tag) may reach the cluster, and the rule names the gateway groups
  that source gets. Without such a rule, `kubectl` does not connect. A
  permission set, where the deployment and the chart enable them, can narrow
  a group to some actions in some namespaces; the group's role stays the
  ceiling.

## Setting one up

1. **In the Console**, create the cluster in the Network and copy the
   values it shows: the control address and its fingerprint, and a join key
   or an install token.
2. **In the cluster**, prepare a tainted node pool, the gateway's namespace
   and the Secrets the chart's README lists, then install the chart:

   ```bash
   helm install gateway oci://…/meshtransit-kube-gateway \
     -n meshtransit-gateway -f values.yaml
   ```

   The chart's [README](../../deploy/charts/kube-gateway/README.md) lists
   every requirement and value, including managed clusters.
3. **Approve the gateway.** With a join key, approve each replica in the
   Console with the code it logged
   (`kubectl -n meshtransit-gateway logs <pod> | grep "enroll code"`). With
   an install token, compare the signing-key digest `helm test` prints with
   the one on the cluster's page and confirm it. Then run
   `helm test gateway -n meshtransit-gateway`.
4. **Write a rule** to the cluster that names the groups its source gets, and
   publish the policy.
5. **On each person's machine:**

   ```bash
   meshctl kube list
   meshctl kube login CLUSTER --use   # writes a kubeconfig context and makes it current
   kubectl get pods
   meshctl kube doctor                # explains what is missing when it fails
   ```

   Without `--use`, `meshctl kube login` adds the context and prints the
   `kubectl --context …` command to use it.

## What keeps it safe

- **No shared credential.** Nobody holds a kubeconfig token for the cluster;
  identity is the Device's key, and leaving the Workspace ends access.
- **A leaked join key is not enough.** It opens only a request with no
  Device; an administrator still approves each replica by its code, and the
  key lives an hour at most.
- **An install token is a bearer credential.** Whoever holds it adds
  approved replicas until it expires (an hour by default, at most 24 hours,
  up to 5 replicas). Pass it with `--set-file` and let it expire.
- **Recorded first.** The gateway records writes, exec, attach,
  port-forward, proxy, Secret reads and privileged requests in Core before
  they reach the API server, and does not forward them when the record fails.
- **Bounded.** The gateway limits each Device's connections, requests and
  watches; Core limits recorded operations per gateway and Workspace, and the
  certificates the gateway's replicas may request.

The protocol between the gateway and Core, with its threats and their
answers, is in [MTCP](../protocol/mtcp-v1.md).

## Turning it on

Self-hosted deployments let gateways join with `MESHTRANSIT_KUBERNETES_JOIN`
([configuration](../operations/configuration.md)); it is off by default.
