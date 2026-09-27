# POC HA, SSO, and policy qualification

Status date: 2026-09-28

This record captures one non-production qualification run. It is evidence for
the exact artifacts below, not a production availability or security claim.
No account identifiers, OAuth credentials, private endpoints, or secret values
are included.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source | `07144a57b61657ec80a3d0d336b56edf416c8b96` |
| Proxy-safe heartbeat default source | `57546a26498cec2e9f6930a3e58330522e06ef56` |
| Core image | `manhdev2002/meshtransit-core:poc-v33` |
| Core image digest | `sha256:380f78a452f5fef747dd963d4c08f66220a4a009dbf41295d980ae67ae5ee287` |
| Control source | `5578378` |
| Control image | `manhdev2002/meshtransit-core:poc-v35` |
| Control image digest | `sha256:e3f8b2a323e2e430b8051c460f2c7b3921a9e64e212fce4208c49fc4b9dadeff` |
| Embedded broker release | `v2.45.1+compat.8` |
| meshd source | `745db5193def2db0d8a1946eb762e75f898ddef0` |
| meshd version | `0.1.0~poc62` |
| meshd package SHA-256 | `d25645771bc86e3fda3ae6712bd61198a3da1b46d2f6aef686a5edebb68d3161` |
| meshctl source | `41bdcedbea9c479d8ae47f077adbc41d188e87ab` |
| meshctl version | `0.1.0~poc62` |
| meshctl package SHA-256 | `6f5e9240521b71200a9f1db34fe9c8f4c5b0b0477f0d122ae5492fa0a2e1ac57` |
| Helm chart | `0.2.18` |
| Helm release revision | `36` |
| Relay directory | Revision 2, `sha256:3c2b107253566ef1d79a551171b8fa4a88ccfdcc785148916d2116fdc61ab4fb` |
| Kubernetes topology | One cluster node; two replicas per Core role |

The SSO and policy cases were first executed on Core `60ff4c6` / `poc-v31`
and meshd `83fbb61` / `0.1.0~poc55`. Core `poc-v32` and meshd `poc56` added the
bounded dual-family probe scheduler and generation-fenced preferred-relay
echo. meshd and meshctl `poc57` add process-local aggregate evidence for relay
bootstrap, authenticated direct promotion, fallback, and promotion time. The
continuations below did not change the Google connector, session, RBAC, or
policy implementations.

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
| `POC-ROLLOUT-003` | A valid browser session survives replacement of every API, Control, and Identity replica | Pass | Helm revision 31 replaced both replicas of all three roles; fresh session checks passed during both replacement waves and after completion, while 1,500 bidirectional overlay probes had zero loss |
| `POC-RELAY-001` | Relay directory and connections are available | Pass | Both clients reported two connected relay regions and maintained an encrypted relay path during direct-path impairment |
| `POC-RELAY-002` | A blocked direct path falls back to relay and later returns to direct | Pass | Both clients changed from direct `1/0` to relay `0/1`, enforced deny/restore policy there, and returned to direct `1/0` after fault removal |
| `POC-RELAY-003` | Relay-region selection and latency meet the POC operational target | Pass | Both clients selected Singapore region 3; forced-relay probes had zero loss and mean RTT of 3.675 ms and 4.594 ms, below the 100 ms POC target |
| `POC-RELAY-004` | A fresh daemon starts from relay and promotes only after authenticated direct-path discovery | Pass | Independent rolling restarts produced nonzero relay-bootstrap and direct-promotion counters on both clients; observed promotion maxima were 577 ms and 1,068 ms, followed by direct overlay traffic with zero loss |
| `POC-PATH-001` | Equivalent map revisions and compatible peer home-relay changes do not overwrite authenticated direct endpoints | Pass | p60 carried only the remaining proof lease, converged both clients from home region 1 to 3 with zero fallback at the convergence checkpoint, and removed the p59 multi-second outage |
| `POC-PATH-002` | Direct-path transition rate remains bounded during continuing map churn | Pass | p62 classified the churn as peer authority remove/add caused by two-minute control-stream reconnects; a 30-second heartbeat plus unbuffered 180-second ingress window held both clients at unchanged map, peer-change, and fallback counters for four minutes while 480 overlay probes completed without loss |
| `POC-STREAM-001` | Idle control streams remain continuous through the public ingress | Pass | Helm revision 34 configured a 30-second Core heartbeat, disabled NGINX response buffering, and set 180-second read/write timeouts; neither control replica logged a stream termination during the four-minute soak |
| `POC-CHURN-001` | Endpoint add/remove and relay-directory revision changes preserve synchronized direct traffic | Pass | Both clients published two endpoint refreshes, revision 2 rolled through both Control replicas, and 4,183 bidirectional overlay probes completed without loss across the endpoint and rollout windows |
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

## Relay-first startup continuation

meshd `poc57` records process-local aggregate path transitions at the
WireGuard plan boundary. A relay bootstrap begins when a relay-backed peer plan
is successfully adopted. Direct promotion is counted only after authenticated
discovery has selected an authorized endpoint and the device accepted that
endpoint. The recorded duration therefore measures plan adoption through
successful direct-path reconfiguration. Reasserting the same direct endpoint
does not increment the counter. A direct-to-relay transition increments the
fallback counter and starts a new promotion interval.

The local API and meshctl expose only totals and last/maximum promotion time;
they do not expose peer identity, endpoint address, or key material. Unit tests
also cover relay-first startup, repeated direct reassertion, fallback, and
promotion after fallback. Full race tests, vet, module-diff checks, lint, and
secret scans passed for both repositories before packaging.

The amd64 packages were installed one client at a time. After the first client
restart, both meshd and meshnetd were active, the control stream was
synchronized, and the peer was direct. Its first observation reported one
relay bootstrap, two direct promotions, one fallback, and 332/577 ms
last/maximum promotion time. Three overlay probes to the still-running second
client had zero loss and 1.607 ms mean RTT.

After the second client restart, both services were active and the control
stream synchronized. It reported one relay bootstrap, one direct promotion,
zero fallbacks, and 979/979 ms last/maximum promotion time. Three reverse
overlay probes had zero loss and 1.873 ms mean RTT. Both clients ran meshd and
meshctl `0.1.0~poc57`; no Core rollout was required for the additive local
status fields.

After preferred-relay convergence, both clients selected Singapore region 3,
retained one direct peer path, and remained synchronized. The final snapshots
reported bootstrap/promotion/fallback totals of 4/5/2 and 2/3/1. Their
last/maximum promotion times were 15/577 ms and 1,068/1,068 ms respectively.
The additional transitions captured relay-region convergence and map
reapplication after startup; identical direct-endpoint reassertions remained
deduplicated.

## Active-session rolling continuation

Core `poc-v33` was built from the exact source revision above with the verified
embedded broker workspace. The registry artifact is a digest-pinned amd64 and
arm64 OCI index with provenance and SBOM attestations. Container identity and
read-only smoke checks passed, and a fresh Trivy database reported zero High or
Critical findings in the Go binary.

Helm revision 30 first rolled the `poc-v33` digest through API, Control, and
Identity. A browser page that had not been reloaded initially appeared to hold
a session, but its durable PostgreSQL record had already passed both idle and
absolute expiry before that rollout. Its later rejection was therefore not
counted as a rollout result.

A new Google login then created an active session at deployment recovery epoch
1. Immediately before the qualification rollout, PostgreSQL showed both expiry
conditions in the future, with approximately 3,509 seconds of idle lifetime
and 7,109 seconds of absolute lifetime remaining. The Console performed a
fresh protected-session check and displayed policy revision 22.

Helm revision 31 applied a qualification pod-template annotation while keeping
the exact `poc-v33` digest. This forced both replicas of API, Control, and
Identity through the chart's `maxUnavailable=0`, `maxSurge=1` rolling strategy.
The unchanged two-replica Console remained available. The browser reloaded and
verified the same session while the first replacement replicas were becoming
Ready, again while the second replicas were replacing their predecessors, and
once more after Helm reported `deployed`. No login redirect or new Google
authorization was required.

All six new Core containers were Ready with zero restarts and the pinned image
digest. Both clients remained synchronized, direct, on Singapore relay region
3, with zero runtime recovery failures or recoveries. During the rollout, 750
overlay probes in each direction completed with zero loss. Mean RTT was 1.324
ms and 1.407 ms; maximum RTT was 8.279 ms and 8.372 ms respectively.

## Direct-path map-churn continuation

The first transition-counter soak on meshd `poc57` showed that identical newer
map revisions repeatedly restored the relay endpoint and then promoted the same
direct endpoint. The first correction carries only the unexpired remainder of
authenticated proof across a newer revision when session scope, UDP socket,
peer identity, discovery identity, and candidate authority remain identical.
It neither renews the proof deadline nor weakens any authority check.

The first package containing that change, `poc58`, was installed only on the
first client. Activation incorrectly tried to apply a retired generation after
the data plane had already advanced, so the client failed closed and did not
open a data path. The second client remained on the previous package. The
generation reconciliation was corrected with explicit rollback, session,
socket, and previous-map boundary tests, then `poc59` was rolled one client at
a time. This recovered both clients to synchronized direct paths without a
mixed-version service outage.

A 240-second p59 soak exposed a second independent transition. Both clients
changed their measured home relay from region 1 to region 3. The signed base
endpoint update overwrote the still-authenticated direct endpoint, producing a
roughly five-second traffic window. One direction received 1,192 replies over
sequence 1 through 1,195 with three gaps, 52.828 ms mean RTT, and 4,946 ms
maximum RTT. The reverse direction received 1,167 replies with 27 gaps, 1.370
ms mean RTT, and 10.5 ms maximum RTT.

meshd `poc60` separates the device-level and peer data configuration from the
signed relay fallback metadata. A compatible peer home-relay change now updates
the retained fallback while leaving an authenticated direct endpoint installed.
The proof keeps its original deadline and expiry restores the newest signed
relay. A private key, peer key or route, discovery identity, candidate
authority, session, socket, self address, or relay-topology change still
restores or recreates the base path fail closed. Unit coverage verifies both
direct preservation and restoration to the new relay. The complete quality
gate passed 807 race tests across 28 packages, `go vet`, lint with zero issues,
and history plus working-tree secret scans before packaging.

The p60 package was installed on the first client, which synchronized and
promoted in 520 ms before 20 of 20 overlay probes succeeded with 1.520 ms mean
RTT. Only then was the second client upgraded; it synchronized and promoted in
601 ms before 20 of 20 reverse probes succeeded with 1.931 ms mean RTT. Both
clients then changed home relay from region 1 to region 3 while remaining on
one direct path. At that checkpoint both reported zero fallback transitions,
which directly exercises the corrected relay-base behavior.

During the same 240-second traffic window, both replicas of the Control role
were rolling-restarted. The Deployment returned to 2/2 Ready replicas and both
clients returned to synchronized direct paths. The first direction received
1,191 replies over sequence 1 through 1,195 with four isolated gaps, 1.362 ms
mean RTT, and 13.5 ms maximum RTT. The reverse direction received 1,192 replies
with three isolated gaps, 1.527 ms mean RTT, and 72.1 ms maximum RTT. The p59
multi-second interruption did not recur. A subsequent steady-state sample
received 299 of 300 and 300 of 300 replies; mean RTT was 1.425 ms and 1.294 ms,
and maximum RTT was 8.093 ms and 9.180 ms respectively.

This continuation does not close the general anti-flap item. After the rollout,
the first client remained stable while the second accumulated additional
proof-expiry fallback and promotion transitions, including one 7,072 ms
promotion. A five-second timeline observed a fallback as its local map revision
advanced from 51 to 53 and a promotion at revision 54. Ten Redis samples across
45 seconds showed unchanged endpoint payload hashes, generation 1, preferred
relay 3, and stable presence-owner hashes for both clients, with leases renewing
well before expiry. This initially localized the remaining fault to the
peer-probe/map-activation boundary rather than relay-base replacement or
authoritative Redis state. The redacted telemetry and control-stream
continuation below subsequently identified and removed its steady-state source.

## Control-stream continuity continuation

meshd `poc61` added aggregate path-probe lifecycle counters, and `poc62` added
redacted authority-change classification. No counter exposes a Node ID,
endpoint, key, packet, or payload. During reproduction, one client advanced
from map revision 6 to 9, incremented peer-set changes by two, retired one
direct proof, fell back once, and promoted once. Node-key, discovery-key,
endpoint-set, socket-expiry, send-failure, completion-rejection, and direct-
expiry counters did not explain that transition. Repeated samples later showed
the same remove/add pair on both clients.

The public control ingress used its default 60-second upstream idle timeout
while Core also used a 60-second stream heartbeat. That equality created an
edge race: an idle stream could be closed before its heartbeat became visible,
and the client's two-minute watchdog then reconnected it. The reconnection
temporarily withdrew exact-generation presence and endpoint observations,
which correctly caused the peer to retire its direct proof.

Core source `57546a2` changes the default heartbeat to 30 seconds and documents
that it must remain below every control-path proxy timeout. Helm chart `0.2.16`
sets the POC heartbeat explicitly to 30 seconds, disables NGINX response
buffering, and sets the ingress read and send timeouts to 180 seconds. The
running image remained the already-qualified embedded-broker `poc-v33` digest;
the explicit environment value therefore exercised the same runtime behavior
without changing the image.

An attempted revision 32 used an ordinary Core image that intentionally lacked
the embedded identity-broker build tag. Its new Identity pod failed readiness
while both old Identity replicas remained available. Helm's atomic timeout
rolled the release back as revision 33. Revision 34 then reused the exact
qualified `poc-v33` digest and changed only configuration. All API, Control,
and Identity Deployments returned to two Ready replicas with zero restarts.

At the post-rollout baseline, client `.4` reported map revision 75, 46 peer-set
changes, and 22 relay fallbacks; client `.5` reported revision 36, six peer-set
changes, and four fallbacks. After 239 seconds, every value remained unchanged,
both clients were synchronized with one direct path, and neither had a runtime
recovery. Bidirectional probes completed 240 of 240 packets in each direction
with zero loss. Mean RTT was 1.421 ms and 1.830 ms; maximum RTT was 5.132 ms
and 7.300 ms. Control logs contained readiness only and no stream termination
during the soak. This closes the reproduced steady-state anti-flap failure.

## Same-generation presence handover continuation

Core source `5578378` separates initial presence acquisition from owner-exact
renewal. An authenticated reconnect may atomically transfer the same durable
session generation to another Control replica without deleting matching
endpoint observations or publishing an offline/online edge. The superseded
replica cannot reacquire through its renewal loop, and an exact release cannot
delete its successor's lease. Normal stream exit leaves the lease to its
bounded TTL, so a load-balanced reconnect can complete before offline state is
projected.

The Redis/PostgreSQL TLS integration suite exercised same-generation transfer,
old-owner renewal rejection, new-owner renewal, higher-generation fencing, and
exact release against Redis `8.8.0`; the full 4,248-test unit and race suites and
`go vet` also passed. The integration harness now supplies the digest-pinned
relay directory required by Control composition, rather than bypassing that
startup invariant.

The standard multi-architecture Control image `poc-v35` was published as
`sha256:e3f8b2a323e2e430b8051c460f2c7b3921a9e64e212fce4208c49fc4b9dadeff`.
Helm chart `0.2.17` adds a per-component image override, allowing revision 35
to advance only Control while API and Identity remained on the qualified
`poc-v33` digest. Strict lint, render, and Kubernetes server-side dry-run passed
before the atomic rollout.

Both original Control pods were then deleted sequentially, waiting for 2/2
Ready replicas after each deletion. Client `.4` advanced from map revision 76
to 77 and recorded the activation as preserved; peer changes remained 46,
relay fallbacks 22, direct promotions 24, and direct expirations zero. Client
`.5` advanced from revision 37 to 38 with another preserved activation; peer
changes remained six, relay fallbacks four, direct promotions six, and direct
expirations one. Both remained synchronized with one direct path and no relay
path or runtime recovery.

During the two pod replacements, bidirectional probes each delivered 120 of
120 packets with zero loss. Mean RTT was 1.479 ms and 1.650 ms; maximum RTT was
2.693 ms and 5.190 ms. Replacement Control logs contained readiness only. This
closes same-generation presence handover for the single-node POC topology.

## Endpoint and relay-directory churn continuation

Each client received a temporary non-loopback dummy interface with a unique
documentation-only `/32` address. The test did not change either default route,
the mesh interface, the shared UDP socket, or the public control path. Interface
creation and later removal each produced one host-network event and one endpoint
refresh on both clients; the interfaces were absent after cleanup.

Client `.4` advanced from map revision 77 to 83 while endpoint-authority changes
advanced from one to three. Client `.5` advanced from revision 38 to 44 while
endpoint-authority changes advanced from zero to two. Peer, Node-key,
discovery-key, and socket authority counters remained unchanged at 46/6, 0/0,
0/0, and 1/1 respectively. Each client recorded two bounded fallback/direct
promotion pairs as endpoint candidates were added and removed. Direct promotion
completed in 12 ms and 13 ms at the final checkpoint. Both clients finished
synchronized with one direct path, zero relay paths, and no runtime recovery;
probe send failures, completion rejections, and datagram drops remained zero.

The first 240-second traffic window covered endpoint creation and its initial
convergence. Client `.4` delivered 1,195 of 1,195 replies with 1.421 ms mean and
11.900 ms maximum RTT. Client `.5` delivered 1,196 of 1,196 replies with 1.505
ms mean and 8.000 ms maximum RTT. Both directions had zero loss.

Relay-directory revision 2 changed only the monotonic revision field while
retaining the validated topology. Its exact payload was stored in immutable
ConfigMap `meshtransit-relay-directory-r2-3c2b1072`; the stored bytes, ConfigMap
annotation, chart value, and Control environment all matched digest
`sha256:3c2b107253566ef1d79a551171b8fa4a88ccfdcc785148916d2116fdc61ab4fb`.
Helm chart `0.2.18` passed strict lint, local render, and Kubernetes server-side
dry-run before atomic revision 36 mounted the new snapshot and rolled both
Control replicas with `maxUnavailable=0`.

The separate 180-second traffic window covered that rolling update and endpoint
removal. Both directions delivered 896 of 896 replies with zero loss. Mean RTT
was 1.324 ms and 1.432 ms; maximum RTT was 9.050 ms and 10.200 ms. The two new
Control pods were Ready with zero restarts, used the pinned `poc-v35` digest,
and logged readiness only. This closes the bounded endpoint and relay-directory
churn item for the single-node POC topology.

## HA interpretation

This run qualifies replica replacement, not infrastructure-zone failure. All
Core roles were horizontally replicated and protected by a minimum-available
PodDisruptionBudget, but the replicas shared one Kubernetes node. PostgreSQL and
Redis were external dependencies with no failover exercised in this run.

No correctness path required sticky sessions. Browser transactions, Core
sessions, RBAC authority, and policy releases were reconstructed from durable
state. Redis remained non-authoritative.

## Remaining execution order

1. Repeat the matrix on a multi-node cluster with topology spread and a node
   drain or loss.
2. Add PostgreSQL and Redis failover qualification with recovery-generation,
   missed-notification, and reconciliation evidence.
3. Extend publication cases to TCP, UDP, multiple devices, and multiple
   Networks before treating policy qualification as complete.
