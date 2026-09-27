# POC HA, SSO, and policy qualification

Status date: 2026-09-27

This record captures one non-production qualification run. It is evidence for
the exact artifacts below, not a production availability or security claim.
No account identifiers, OAuth credentials, private endpoints, or secret values
are included.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source | `60ff4c6` |
| Core image | `manhdev2002/meshtransit-core:poc-v31` |
| Core image digest | `sha256:eb06b6eddba286063cfefc544764bcf56b7bd1c1b3d0e1bedf9aef177a39e5ed` |
| Embedded broker release | `v2.45.1+compat.8` |
| meshd source | `83fbb61` |
| meshd version | `0.1.0~poc55` |
| Helm chart | `0.2.13` |
| Helm release revision | `28` |
| Kubernetes topology | One cluster node; two replicas per Core role |

## Qualification matrix

| ID | Requirement | Result | Evidence |
| --- | --- | --- | --- |
| `POC-SSO-001` | Real Google authorization completes through the embedded broker | Pass | Browser reached the Core console with a verified Core-owned session |
| `POC-SSO-002` | Login state is durable and rejects expired transactions | Pass | A transaction older than five minutes was collected and its callback rejected; a fresh transaction completed |
| `POC-SSO-003` | Identity runs active-active without sticky-session configuration | Pass | Two Identity replicas remained Ready with zero restarts during login and policy qualification |
| `POC-SESSION-001` | Browser management uses the Core session cookie and CSRF preparation | Pass | Cookie-authenticated policy publication succeeded through the public API path |
| `POC-RBAC-001` | `policy.publish` requires exact Network authority | Pass | Publication succeeded only after the active membership, binding, role, permission, and generations resolved |
| `POC-POLICY-001` | Deny-all publication is atomic | Pass | Policy revision advanced from 18 to 19 with zero active compiled rules |
| `POC-POLICY-002` | Both clients converge to deny-all | Pass | Both control sessions synchronized with zero client-visible policy rules and the overlay ping was denied |
| `POC-POLICY-003` | Restore publication is atomic | Pass | Policy revision advanced from 19 to 20 with two directional ICMP rules |
| `POC-POLICY-004` | Both clients converge after restore | Pass | Each client received one reduced inbound rule and one direct peer path |
| `POC-DATAPLANE-001` | Restored ICMP works in both directions | Pass | 20 of 20 packets succeeded in each direction with zero loss; mean RTT was approximately 1.2 ms |
| `POC-HA-001` | Policy publication survives one Control replica replacement | Pass | One Control pod was deleted immediately before deny-all publication; the request succeeded and the Deployment returned to 2/2 |
| `POC-HA-002` | Core roles remain available after the test | Pass | API, Control, Identity, and Console Deployments were 2/2; all observed containers had zero restarts |
| `POC-ROLLOUT-001` | Console-only configuration rollout does not restart Core roles | Pass | Helm revisions 26 through 28 replaced only Console pods; API, Control, and Identity pod identities were unchanged and retained zero restarts |
| `POC-RELAY-001` | Relay directory and connections are available | Pass | Both clients reported two connected relay regions and maintained an encrypted relay path during direct-path impairment |
| `POC-RELAY-002` | A blocked direct path falls back to relay and later returns to direct | Pass | Both clients changed from direct `1/0` to relay `0/1`, enforced deny/restore policy there, and returned to direct `1/0` after fault removal |
| `POC-RELAY-003` | Relay-region selection and latency meet an operational target | Partial | Functional relay traffic passed, but observed mean RTT was approximately 0.92-1.20 seconds; no relay latency SLO is qualified |
| `POC-NODE-HA-001` | Workload survives Kubernetes node failure | Pending | The current POC deliberately uses one cluster node |
| `POC-DATA-HA-001` | PostgreSQL and Redis failover preserve authority and convergence | Pending | The current POC uses one external PostgreSQL/Redis host |

## State transition evidence

```text
revision 18: two directional ICMP rules, direct traffic allowed
revision 19: zero rules, clients synchronized, traffic denied
revision 20: two directional ICMP rules, clients synchronized, direct traffic restored
revision 21: zero rules, clients synchronized while the direct path was blocked
revision 22: two directional ICMP rules, clients synchronized on the relay path
```

The API recorded successful `policy_publish` operations for revisions 19 and
20. PostgreSQL remained authoritative for the active release. Client status
after revision 20 reported one peer, one direct path, zero relay paths, and one
Node-reduced policy rule on each side.

## Forced-relay evidence

The fault used a dedicated, non-persistent nftables table on one client. It
dropped only UDP whose source or destination matched any of the peer's three
advertised IPv4 underlay addresses. SSH, HTTPS control traffic, routes,
interfaces, and relay destinations were unchanged. A 15-minute rollback timer
was armed before the fault and canceled after explicit cleanup.

All six drop counters advanced. The final outbound counters were 45, 40, and
37 packets; the final inbound counters were 38, 0, and 31 packets. Both clients
then reported one peer, zero direct paths, one relay path, zero pending paths,
and two connected relay regions.

While the direct path remained blocked, revision 21 removed all compiled rules.
Both clients converged to zero peers and zero client-visible policy rules, and
five of five ICMP probes in each direction were denied. Revision 22 restored
the two directional ICMP rules. PostgreSQL recorded policy revision 22 as the
active release at Network revision 32 with two compiled rules. Both clients
returned to one peer and one reduced inbound rule while remaining on relay;
20 of 20 probes succeeded in each direction with zero loss.

The relay traffic was functionally correct but slow in this run. Mean RTT after
restore was approximately 916 ms in one direction and 1,197 ms in the other,
with individual samples up to approximately two seconds. The clients reported
home region 1. These observations require a separate relay-region selection and
latency investigation; this run does not qualify a relay performance target.

After deleting the nftables table, both clients automatically returned to one
direct path and zero relay paths. Twenty of 20 probes succeeded in each
direction with zero loss and mean RTT of approximately 1.28 ms. The rollback
timer was inactive and the qualification table no longer existed.

Helm release 28 then updated only the Console qualification configuration to
base revision 22. API, Control, and Identity Deployment generations and pod
identities were unchanged; all six Core containers remained Ready with zero
restarts. Reloading the public Console verified the existing browser session
and displayed revision 22.

## HA interpretation

This run qualifies replica replacement, not infrastructure-zone failure. All
Core roles were horizontally replicated and protected by a minimum-available
PodDisruptionBudget, but the replicas shared one Kubernetes node. PostgreSQL and
Redis were external dependencies with no failover exercised in this run.

No correctness path required sticky sessions. Browser transactions, Core
sessions, RBAC authority, and policy releases were reconstructed from durable
state. Redis remained non-authoritative.

## Remaining execution order

1. Investigate relay-region selection and the high observed forced-relay RTT;
   repeat the bounded impairment run with an explicit latency target.
2. Run rolling upgrades of API, Control, and Identity while preserving an
   active browser session and both client control streams.
3. Repeat the matrix on a multi-node cluster with topology spread and a node
   drain or loss.
4. Add PostgreSQL and Redis failover qualification with recovery-generation,
   missed-notification, and reconciliation evidence.
5. Extend publication cases to TCP, UDP, multiple devices, and multiple
   Networks before treating policy qualification as complete.
