# POC HA, SSO, and policy qualification

Status date: 2026-09-27

This record captures one non-production qualification run. It is evidence for
the exact artifacts below, not a production availability or security claim.
No account identifiers, OAuth credentials, private endpoints, or secret values
are included.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source | `d0ae93d98daaa650de61bf5a959319960f8e44fb` |
| Core image | `manhdev2002/meshtransit-core:poc-v32` |
| Core image digest | `sha256:61678225d85bff45ce032676d662d8832824c11850bdb621b42c8c9ab6bc02cf` |
| Embedded broker release | `v2.45.1+compat.8` |
| meshd source | `654adbd0ee4d34bca548a55dcf9c8b3adaa328b8` |
| meshd version | `0.1.0~poc56` |
| meshd package SHA-256 | `31218c5b4095a7f7124547e87bf0ce612b31b45458da3a84eb667bc61567d6af` |
| Helm chart | `0.2.14` |
| Helm release revision | `29` |
| Kubernetes topology | One cluster node; two replicas per Core role |

The SSO and policy cases were first executed on Core `60ff4c6` / `poc-v31`
and meshd `83fbb61` / `0.1.0~poc55`. The current artifacts add the bounded
dual-family probe scheduler and generation-fenced preferred-relay echo. The
relay-locality continuation below exercised those changes end to end without
changing the Google connector, session, RBAC, or policy implementations.

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
| `POC-ROLLOUT-002` | A rolling Core image update preserves control and data-plane convergence | Pass | Helm revision 29 replaced all API, Control, and Identity replicas with `poc-v32`; all roles returned to 2/2 with zero restarts and both clients remained synchronized |
| `POC-RELAY-001` | Relay directory and connections are available | Pass | Both clients reported two connected relay regions and maintained an encrypted relay path during direct-path impairment |
| `POC-RELAY-002` | A blocked direct path falls back to relay and later returns to direct | Pass | Both clients changed from direct `1/0` to relay `0/1`, enforced deny/restore policy there, and returned to direct `1/0` after fault removal |
| `POC-RELAY-003` | Relay-region selection and latency meet the POC operational target | Pass | Both clients selected Singapore region 3; forced-relay probes had zero loss and mean RTT of 3.675 ms and 4.594 ms, below the 100 ms POC target |
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

Five of the six drop counters advanced. The final outbound counters were 45,
40, and 37 packets; the final inbound counters were 38, 0, and 31 packets. The
zero counter guarded an alternate inbound candidate that was not selected
during this run. Both clients then reported one peer, zero direct paths, one
relay path, zero pending paths, and two connected relay regions.

While the direct path remained blocked, revision 21 removed all compiled rules.
Both clients converged to zero peers and zero client-visible policy rules, and
five of five ICMP probes in each direction were denied. Revision 22 restored
the two directional ICMP rules. PostgreSQL recorded policy revision 22 as the
active release at Network revision 32 with two compiled rules. Both clients
returned to one peer and one reduced inbound rule while remaining on relay;
20 of 20 probes succeeded in each direction with zero loss.

The initial relay traffic was functionally correct but slow. Mean RTT after
restore was approximately 916 ms in one direction and 1,197 ms in the other,
with individual samples up to approximately two seconds. Both clients reported
home region 1. This established the regression baseline for the locality work.

After deleting the nftables table, both clients automatically returned to one
direct path and zero relay paths. Twenty of 20 probes succeeded in each
direction with zero loss and mean RTT of approximately 1.28 ms. The rollback
timer was inactive and the qualification table no longer existed.

Helm release 28 then updated only the Console qualification configuration to
base revision 22. API, Control, and Identity Deployment generations and pod
identities were unchanged; all six Core containers remained Ready with zero
restarts. Reloading the public Console verified the existing browser session
and displayed revision 22.

## Relay-locality continuation

The follow-up fixed two independent causes. meshd now retains one IPv4 and one
IPv6 endpoint for the current home region in every bounded probe round, leaving
the remaining slots to rotate across the signed directory. Core now persists
the client's preferred relay as generation-fenced Redis observation metadata,
wakes map streams on a change, and projects only a still-usable region back to
the client. The endpoint payload version remained unchanged so mixed-version
Core replicas remain compatible during a rolling update.

Helm release 29 rolled Core `poc-v32` across API, Control, and Identity with
`maxUnavailable=0`. Every role returned to two Ready replicas, all six new Core
containers used the pinned image digest, and all had zero restarts. One client
selected region 3 immediately; the other prepared the region-3 relay, observed
two successful STUN rounds, published its preference, and then converged. Both
clients reported one connected relay region with home region 3.

The bounded impairment was then repeated with a dedicated nftables table that
dropped only UDP port 41641 between one client and the peer's three advertised
IPv4 underlay addresses. A 15-minute rollback timer was active before the rules
were installed. Both clients changed from one direct path to one relay path
with no pending path while retaining home region 3.

Twenty of 20 probes succeeded in each direction over relay with zero loss. The
first direction measured 2.677/3.675/9.080 ms minimum/mean/maximum RTT; the
reverse direction measured 2.642/4.594/18.275 ms. This passes the bounded POC
target of zero loss and mean RTT below 100 ms. The test table was deleted and
the timer canceled. Both clients automatically returned to one direct path;
ten of ten probes then succeeded in each direction with zero loss and mean RTT
of 1.699 ms and 1.366 ms. The table was absent, the timer was inactive, both
clients were synchronized, and Core remained 2/2 per role with zero restarts.

## HA interpretation

This run qualifies replica replacement, not infrastructure-zone failure. All
Core roles were horizontally replicated and protected by a minimum-available
PodDisruptionBudget, but the replicas shared one Kubernetes node. PostgreSQL and
Redis were external dependencies with no failover exercised in this run.

No correctness path required sticky sessions. Browser transactions, Core
sessions, RBAC authority, and policy releases were reconstructed from durable
state. Redis remained non-authoritative.

## Remaining execution order

1. Add relay-first bootstrap and direct-path promotion qualification, including
   convergence-time metrics rather than only steady-state path evidence.
2. Repeat rolling Core upgrades while preserving an active browser session in
   addition to both client control streams.
3. Repeat the matrix on a multi-node cluster with topology spread and a node
   drain or loss.
4. Add PostgreSQL and Redis failover qualification with recovery-generation,
   missed-notification, and reconciliation evidence.
5. Extend publication cases to TCP, UDP, multiple devices, and multiple
   Networks before treating policy qualification as complete.
