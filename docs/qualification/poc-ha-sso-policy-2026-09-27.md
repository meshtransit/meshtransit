# POC HA, SSO, and policy qualification

Status date: 2026-09-28

This record captures one non-production qualification run. It is evidence for
the exact artifacts below, not a production availability or security claim.
No account identifiers, OAuth credentials, private endpoints, or secret values
are included.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source | `ab1c26c051994393e009ff8baef6e2e77b4f276c` |
| Signing-key rotation qualification source | `32834c987850912c2904408cc1be209a3c8f9558` |
| Duplicate-callback qualification source | `7e13d6513dd9e1d4f0ddec57be8b18c54934d68f` |
| Unknown-write qualification source | `4a84c9c18268c1b7f6717d32c691c671823afffa` |
| Proxy-safe heartbeat default source | `57546a26498cec2e9f6930a3e58330522e06ef56` |
| Core image | `manhdev2002/meshtransit-core:poc-v36` |
| Core image digest | `sha256:8dfc99c447475df44d3060b0993c434455ddd329898795fe385c2483e3d46bb8` |
| Control source | `ab1c26c051994393e009ff8baef6e2e77b4f276c` |
| Control image | `manhdev2002/meshtransit-core:poc-v36` |
| Control image digest | `sha256:8dfc99c447475df44d3060b0993c434455ddd329898795fe385c2483e3d46bb8` |
| Embedded broker release | `v2.45.1+compat.8` |
| meshd source | `745db5193def2db0d8a1946eb762e75f898ddef0` |
| meshd version | `0.1.0~poc62` |
| meshd package SHA-256 | `d25645771bc86e3fda3ae6712bd61198a3da1b46d2f6aef686a5edebb68d3161` |
| meshctl source | `41bdcedbea9c479d8ae47f077adbc41d188e87ab` |
| meshctl version | `0.1.0~poc62` |
| meshctl package SHA-256 | `6f5e9240521b71200a9f1db34fe9c8f4c5b0b0477f0d122ae5492fa0a2e1ac57` |
| Helm chart | Main `0.2.21`; private `role=all` canary `0.2.22` |
| Helm release revision | Main `39`; private `role=all` canary `6` |
| Relay directory | Revision 2, `sha256:3c2b107253566ef1d79a551171b8fa4a88ccfdcc785148916d2116fdc61ab4fb` |
| Kubernetes topology | One POC worker at the current checkpoint; two replicas per Core role |

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
| `POC-NODE-HA-001` | Workload survives Kubernetes node failure | Pass | Draining one of two workers kept one replica of every Core role Ready, preserved the active browser session on the surviving API replica, and completed all 6,273 bidirectional overlay probes without loss across drain and recovery windows |
| `POC-ARTIFACT-001` | The current embedded-broker source is bound to a reproducible immutable image | Pass | The manifested `compat.8` source and binary verified, all compile/runtime gates passed on Core `ab1c26c`, and multi-platform image `poc-v36` was published with SBOM/provenance at the pinned digest; hardened runtime smoke passed and Trivy found zero High/Critical vulnerabilities |
| `POC-ROLLOUT-004` | The current exact Core artifact rolls through every runtime role without loss of readiness | Pass | Atomic Helm revision 39 moved API, Control, and Identity to the same `poc-v36` digest; all roles returned to 2/2 with zero restarts and their public contracts remained available |
| `POC-IDENTITY-HA-001` | Loss of one current Identity replica does not interrupt broker or Core readiness | Pass | Forty OIDC discovery requests, 40 Control key requests, and 20 paired Core/login readiness checks completed with zero failures while one Identity pod was deleted and replaced |
| `POC-IDENTITY-HA-002` | Shared signing-key rotation preserves verification across a rolling Identity replacement | Pass | Two embedded runtimes used one shared storage contract; the surviving and replacement runtimes published the same active and retained keys, verified a pre-rotation signature through the overlap window, and removed the expired key at the next rotation boundary |
| `POC-IDENTITY-HA-003` | Concurrent delivery of one callback to different Core replicas creates at most one Session without stickiness | Pass | Two separately composed replicas with distinct PostgreSQL pools and Redis clients raced the same callback; exactly one provider exchange and Session succeeded, the losing response released no browser material, and the winning Session authenticated through the other replica |
| `POC-IDENTITY-HA-004` | A committed claim or Session write with a lost PostgreSQL acknowledgement cannot be retried or reconstructed by another replica | Pass | A verified-TLS wire relay dropped the selected committed claim and issuance acknowledgements; both callbacks failed closed with the exact unknown-commit signal, a newly composed replica rejected replay without effects, natural cleanup was exactly once, and only a new login produced a usable Session |
| `POC-ROLE-ALL-001` | One private Core process can own every runtime role, recover after process loss, and reject invalid listener topology before admission | Pass | The digest-pinned `role=all` canary reported all five roles and every dependency Ready; direct-TLS Control, API, Login, and Identity contracts passed; pod deletion recovered with zero restarts; an isolated listener-collision release exited with redacted `invalid_configuration` and no Ready endpoint |
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

## Multi-node node-drain continuation

The cluster node pool was expanded from one to two same-size workers. Helm
chart `0.2.19` first changed hostname spreading from advisory to mandatory. Its
first rollout exposed a rolling-update scheduler edge: predecessor pods from
the old ReplicaSet still counted toward the topology skew, so the new
generation could finish with both replicas on the newly added worker. Chart
`0.2.20` adds `matchLabelKeys: [pod-template-hash]` to make the hard hostname
constraint generation-aware. Strict lint, rendered-manifest validation, and a
Kubernetes server-side dry-run passed before atomic release revision 38.

Revision 38 placed exactly one API, Control, Identity, and Console replica on
each worker. All eight containers were Ready with zero restarts. Draining the
new worker evicted one replica of every role. The surviving worker retained one
Ready replica of every role; the replacement pods remained Pending because the
mandatory hostname constraint correctly refused to collapse both replicas into
one failure domain. Uncordoning the worker scheduled those replacements and
restored every Deployment to 2/2 with the original one-replica-per-worker
placement and zero restarts.

The first browser reload during this work rejected a pre-existing session. A
fresh login established that the rejection was normal session expiry rather
than replica loss: ingress evidence showed login prepare, start, continuation,
completion, and protected session preparation alternating across both API
replicas with successful responses. The protected session was first verified
through the API replica on the worker selected for eviction. After that worker
was drained, a fresh Console reload verified the same Core-owned session and
policy revision 22 through the surviving API replica. Another reload succeeded
after 2/2 recovery; no sticky-session configuration was present.

Three bounded traffic windows covered the initial drain, recovery, the
session-qualified drain, and final recovery. They delivered 6,273 of 6,273
overlay probes with zero loss. The session-qualified drain window delivered
747 of 747 and 746 of 746 replies with 1.210 ms and 1.224 ms mean RTT; maximum
RTT was 6.670 ms and 5.050 ms. At the final checkpoint both clients remained
synchronized with one direct path, zero relay or pending paths, and no runtime
recovery. Their map revisions, peer-authority changes, fallback totals, and
direct-promotion totals remained unchanged at 86/47, 46/6, 24/6, and 26/8.
Both Control replicas logged readiness only.

## Data-dependency failover preflight

The PostgreSQL serving pools now treat writer identity as part of readiness,
not merely TCP reachability. New connections require a read-write server. Each
periodic dependency check also validates an already-pooled connection; if a
demoted primary remains reachable but read-only, Core closes the pool so the
next acquisition resolves the stable endpoint and validates the promoted
writer. The operator metric records this bounded check as
`operation="writable_check"` for each least-privilege pool role.

Unit tests cover ordered ping, writer, and schema validation; rejection of a
read-only server; immediate pool retirement on that rejection; and fixed-label
success/error metrics. This closes the Core-side PostgreSQL reconnection
precondition, but it does not mark `POC-DATA-HA-001` as passed: a real quorum,
endpoint transition, recovery-generation check, and concurrent client traffic
still need to be exercised.

The two process-owned Redis wakeup feeds now recover a lost Pub/Sub
subscription without dropping their local map-stream watchers. Recovery uses a
bounded setup timeout and jittered exponential backoff, closes each failed
transport, and exports separate attempt and success counters. Notifications
missed while disconnected remain non-authoritative hints and are repaired by
the existing periodic PostgreSQL reconciliation. Unit and race coverage proves
watcher continuity, repeated subscribe failure, typed-nil rejection, terminal
invalid-value handling, cancellation, and resource closure. This is Core
failover readiness only; the POC still has one Redis host and does not qualify
Sentinel, quorum, or Redis infrastructure failover.

## Current embedded-broker artifact and replica-loss continuation

Core `ab1c26c051994393e009ff8baef6e2e77b4f276c` was qualified against the
manifested Dex `v2.45.1+compat.8` input. The verifier reproduced the eight-patch
source digest
`sha256:31e9f91bd3761028f838e7f00635cded92bbd661a4264b8b58ba391546422bae`
and the workspace-built Darwin qualification binary digest
`sha256:dfaf9cb0afd9b6c07790c55daae6e8eee5a59dbac86faffe366767def8a1165a`.
The upstream-negative/candidate-positive compile contract, build-tagged adapter
and composition tests, and unchanged black-box broker compatibility gate all
passed against those inputs.

The exact Core source was published as a Linux amd64/arm64 OCI index with
BuildKit provenance and SBOM attestations. The immutable index digest is
`sha256:8dfc99c447475df44d3060b0993c434455ddd329898795fe385c2483e3d46bb8`;
the mutable tag is recorded only as the human-readable `poc-v36` alias. Chart
`0.2.21` pins the digest. Strict chart lint, local render, and Kubernetes
server-side dry-run passed before atomic Helm revision 39. Image metadata and a
non-root, read-only, capability-dropped runtime smoke passed. Trivy 0.74 reported
zero High or Critical vulnerability findings in the exact image.

Revision 39 rolled the same digest through API, Control, Identity, and the
one-shot migrator. API, Control, and Identity returned to two Ready replicas
with zero restarts. Public OIDC discovery still advertised RFC 9207
authorization-response issuer support and the signed `auth_time` claim, and the
capability-142 key endpoint returned a non-zero control key.

One of the two Identity pods was then deleted without changing configuration or
traffic routing. During its replacement, 40 consecutive public OIDC discovery
requests, 40 consecutive public Control key requests, and 20 consecutive pairs
of Core `/ready` plus login `/ready/login` checks completed with zero failures.
The Identity Deployment restored two Ready replicas; the replacement and all
surviving Core containers had zero restarts.

This continuation qualifies process/replica loss for the current artifact. At
this checkpoint the POC cluster has one worker, so it does not claim worker,
availability-zone, or regional failure tolerance. The earlier two-worker drain
record remains historical evidence bound to the older artifacts named in that
section.

## Deterministic signing-key rotation evidence

Core source `32834c987850912c2904408cc1be209a3c8f9558` adds an adapter-boundary
contract test against the manifest-verified `v2.45.1+compat.8` workspace. Two
embedded runtimes first opened the same storage at one stable clock instant and
served exactly one shared active key. One runtime was then shut down and
recreated just after the persisted rotation boundary while the other remained
available.

The replacement promoted a new active key through the shared atomic key update.
Both the surviving and replacement runtimes immediately served the same JWKS:
the new active key plus the previous public key. The retained key expiry equaled
the configured ID-token lifetime from the rotation instant, and a payload signed
before rotation verified through JWKS returned by either runtime. Every served
key was public-only, `RS256`, `use=sig`, and had a non-empty key identifier.

A second deterministic rolling replacement advanced past the next rotation
boundary. Both remaining runtimes then served the second and third keys, while
the first expired key was absent. The clock is atomic and injected; the test
contains no wall-clock sleeps, external identity-provider traffic, or secret
material. The focused contract, tagged package and command tests passed with the
race detector, and both ordinary and tagged vet gates passed. The existing Core
consumer contract separately proves that an unknown key identifier performs
exactly two bounded JWKS reads, never changes the trusted route, and fails
closed when the key remains absent.

This closes the deterministic key-rotation/JWKS-overlap portion of
`SSO-BROKER-006` together with the live two-replica loss evidence above. It does
not claim a forced rotation against the POC broker database: the production
minimum rotation period remains one hour, and the runtime binary did not change,
so no new image or Helm rollout was required for this test-only source update.
Duplicate callback delivery and unknown-write uncertainty remained open at this
checkpoint.

## Concurrent duplicate-callback evidence

Core source `7e13d6513dd9e1d4f0ddec57be8b18c54934d68f` closes the
duplicate-delivery portion of `SSO-BROKER-006`. The disposable verified-TLS
Linux lane composed two independent Core factory graphs against one owned
PostgreSQL database and Redis fixture. Each replica used a distinct PostgreSQL
pool and Redis client; only durable authority, provider configuration, and
signing material were shared.

One replica initiated the browser transaction, then both replicas received the
same callback concurrently behind a start barrier. Exactly one replica claimed
the transaction, performed one provider token exchange and one JWKS read, and
issued one Session. The losing callback returned a closed invalid or unavailable
category and released no response body, cookie, or redirect. The Session issued
by the winner authenticated through the other replica, proving that the result
does not depend on stickiness or process-local session state.

The durable census advanced by exactly one terminal Session and its expected
claim/issuance mutation, audit, and outbox evidence. The duplicate attempt did
not change subject authority, create another terminal result, or contact an
unregistered provider endpoint. The same full lane passed expiry quarantine,
abandoned-process cleanup, claim/issuance ACK-loss cases, and split Core versus
login readiness. Ordinary and broker-tagged race tests, ordinary and tagged vet,
and integration-tagged vet also passed.

This qualification used a synthetic owned provider and disposable storage. It
did not use the live Google credential or mutate the POC cluster. Production
runtime source did not change, so no image or Helm rollout was required.
Unknown-write/commit uncertainty was the final open broker-continuity slice at
this checkpoint.

## Unknown-write and lost-acknowledgement evidence

Core source `4a84c9c18268c1b7f6717d32c691c671823afffa` closes the
unknown-write portion of `SSO-BROKER-006`. The disposable Linux lane placed a
bounded verified-TLS PostgreSQL relay between Core and the owned database. The
relay inspected only backend protocol frames and dropped exactly the selected
`COMMIT` completion frame after PostgreSQL had committed. It retained no SQL,
browser proof, token, identity, or Session material.

The first fault removed the committed claim acknowledgement. Core returned the
closed unavailable category joined with the exact unknown-commit signal, not a
timeout, and released no body, cookie, or redirect. Durable state contained one
consuming transition with exactly one mutation, audit event, and outbox event;
there was no provider token exchange or JWKS request. A replacement replica,
composed only after the fault with its own PostgreSQL pool and Redis client,
rejected the original callback without reclaiming, resolving, or exchanging it.
Natural expiry produced exactly one no-grant disposition, and a fresh worker
found no replayable work.

The second fault removed the committed Session-issuance acknowledgement. The
provider token exchange and JWKS read each occurred exactly once. PostgreSQL
contained one succeeded transaction, one active Session, and the exact three
claim/issuance evidence sequences, but Core released no bearer. Storage exposed
only the Session identity and token digest; neither the original nor replacement
replica could reconstruct the undisclosed token. The replacement rejected replay
without another exchange or write, and the expiry worker ignored the already
terminal outcome.

Recovery in both cases required a new browser login. That login completed on the
replacement replica, and its Session authenticated through the original replica
after the faulted connection re-established TLS. The full disposable platform
lane passed with the race detector, including duplicate callback, expiry,
abandoned-process, cleanup, and process-readiness suites. Ordinary and
broker-tagged race tests plus ordinary, broker-tagged, and integration-tagged vet
also passed.

Together with replica-loss, signing-key overlap, and concurrent duplicate
delivery evidence, this closes `SSO-BROKER-006` for the current source-level HA
scope. It does not claim PostgreSQL service failover, availability-zone failure,
or broker outage/recovery-generation behavior. The live Google credential and
POC cluster were untouched. Production runtime source did not change, so no new
image or Helm rollout was required.

## Upstream identity-provider outage and recovery evidence

Core source `8092e43e90dc1afaa5eb8bf841161659d03ccd70` closes the upstream
identity-provider portion of `SSO-BROKER-007`. A disposable verified-TLS Linux
lane exercised separate token-endpoint and signing-key-endpoint transport
outages against the concrete private-login factory. Each outage occurred only
after Core had created and captured an otherwise valid browser transaction.

The token-endpoint outage performed one bounded token request and no JWKS read.
The signing-key outage performed one token request and a bounded JWKS attempt.
Both callbacks returned the closed unavailable category and released no body,
cookie, redirect, Session bearer, or durable Session authority. Each consumed
transaction ended in the exact failed state with one claim and one termination
evidence sequence. Replaying either callback after failure performed no provider
I/O and no authority write; the fixture observed no unregistered endpoint or
alternate effect path.

During both stage-specific outages the factory's admission/discovery check
remained healthy, so the unavailable callback path did not evict healthy Core
admission. The existing compiled-process case separately proves the stronger
discovery-outage boundary: Core `/ready` remains `200`, only `/ready/login`
becomes `503`, and login readiness recovers on the same process after the
provider returns. Token and JWKS availability cannot be safely preflighted by
manufacturing an authorization code, so those failures are contained at the
real callback boundary rather than predicted by readiness.

After each provider dependency recovered, a fresh login succeeded through the
same factory without reconstruction or process restart. The new Session was
persisted, returned only in its protected cookie, and authenticated through the
resident Session authority. The earlier failed transaction remained failed and
unreplayable. The full disposable platform lane passed with the race detector,
as did ordinary and broker-tagged race tests plus ordinary, broker-tagged, and
integration-tagged vet.

This closes only the upstream provider outage slice. Broker-database outage,
signer outage, and recovery-generation fencing remained open under
`SSO-BROKER-007`. The live Google credential and POC cluster were untouched.
Production runtime source did not change, so no image or Helm rollout was
required.

## Broker-database outage and recovery evidence

Core source `c7c4aaae78c701eb4743a4788639d256465bc1df` closes the
source-level broker-database portion of `SSO-BROKER-007`. The deterministic
adapter test runs the exact pinned embedded broker component, product-owned
PostgreSQL resource boundary, immutable connector/client configuration, and
role-scoped Core readiness contract against one faultable storage handle.

After normal startup, the fixture made both the prepared-schema readiness check
and the connector authorization-request write unavailable. The database check
returned only the closed, redacted `ErrCheckPostgreSQLResource` category. An
Identity-only runtime became not Ready, while an aggregate `role=all` runtime
with healthy Core PostgreSQL and Redis remained Ready. The same broker runtime
continued serving its fixed discovery document instead of stopping or being
reconstructed.

A fresh authorization attempt reached the real connector handler and failed
with an exact no-store `500`. It returned no redirect or cookie, disclosed no
storage error detail, and persisted zero authorization requests. This proves
that loss of the broker system of record cannot route around persistence,
select a fallback identity path, or manufacture browser authority.

When the same storage and readiness check recovered, both role profiles became
Ready as appropriate. A fresh authorization attempt on the same runtime wrote
exactly one request and redirected only to the configured Google authorization
endpoint with the configured client, callback, authorization-code response, and
S256 binding. The failed attempt left no durable request to replay.

The fixture implements the pinned broker storage method inside the isolated
adapter, so a future dependency signature or behavior change fails the tagged
qualification rather than bypassing the outage gate. The focused test and full
broker-tagged suite passed with the race detector; ordinary race tests and
ordinary, broker-tagged, and integration-tagged vet also passed.

This closes the database service-outage contract, not PostgreSQL service
failover, multi-node database HA, or availability-zone recovery. Those
infrastructure claims remain paused and separate. At this checkpoint, signer
outage and recovery-generation fencing remained open under `SSO-BROKER-007`.
The live Google credential and POC cluster were untouched. Production runtime
source did not change, so no image or Helm rollout was required.

## Broker signer outage and recovery evidence

Core source `71939ab2bb4e2cd7fb142b41d9717187953df78c` closes the signer
outage portion of `SSO-BROKER-007`. Identity readiness now has a separate,
stable `identity_signer` component instead of inferring signer health from
database connectivity or immutable configuration. An aggregate process keeps
healthy API/control admission when only this login dependency is unavailable;
an Identity-only process fails readiness.

The pinned broker adapter performs a bounded cryptographic proof during startup
and on periodic readiness checks. It requires the approved RS256 algorithm, a
non-empty JWKS containing unique public signing keys with exact algorithm/use,
then signs a fixed non-secret probe and verifies the result against those
published keys. Startup cannot publish a runtime when this proof fails. Runtime
checks share the same admission/drain fence as HTTP handlers, so shutdown never
releases signer/storage resources while an admitted proof is still active.

The deterministic outage fixture makes only the signer's `GetKeys` operation
unavailable after healthy startup while the product PostgreSQL check remains
Ready. The signer check returns one redacted closed category. JWKS returns a
no-store `500`, and a real authorization-code token exchange returns a no-store
`500` with no redirect, cookie, access token, ID token, raw dependency detail,
or alternate signing path. The authorization code remains unconsumed because
no token was issued.

After the same signer handle recovers, readiness becomes healthy without
reconstructing the broker runtime. Retrying that authorization code succeeds
exactly once, consumes it, and returns access/ID tokens whose ID-token signature
verifies against the recovered JWKS. A separate startup case proves an unusable
signer publishes no runtime and releases its borrowed storage.

The focused tests, full broker-tagged suite, and ordinary repository suite
passed with the race detector. Ordinary, broker-tagged, and integration-tagged
vet passed. Ordinary and broker-tagged delta lint reported zero new findings;
the repository-wide lint baseline still contains four unrelated pre-existing
findings, so no full lint pass is claimed. The pinned vulnerability scan found
zero reachable or imported-package vulnerabilities.

This source qualification did not use the live Google credential, mutate the
POC cluster, build an image, or roll Helm. It does not claim an external KMS/
Vault outage test, PostgreSQL failover, multi-node database HA, or
availability-zone recovery. At that checkpoint, recovery-generation fencing was
the only remaining source slice under `SSO-BROKER-007`.

## Provider recovery-generation fencing evidence

Core source `d5066d5799bea6e1295375d0e1d71b3e57ab3378` closes the final
source-level slice of `SSO-BROKER-007`. A dedicated cold, verified-TLS Linux
fixture created one generation-one Account Session and a separate pending
browser continuation through the concrete private-login factory. It then
applied one audited synthetic recovery transition in Core PostgreSQL: generation
one became revoked, generation two became current with `unproven` recovery
evidence, and the provider entered quarantine.

The still-active generation-one Session failed authentication through both the
resident and replacement runtime pools. The prepared generation-one callback
failed before provider token/JWKS exchange or claim, and a replica retaining
the generation-one route could not start another login. A replacement replica
configured for generation two also remained unable to start login while the
provider was quarantined. The old Session and pending transaction rows remained
durably intact during these checks, proving denial came from the current
authority fence rather than deletion, cache loss, or test-only rewriting.

A separate audited approval changed only the provider recovery state to
verified. It did not restore generation one. The stale Session, callback, and
replica route remained denied, while the already-composed generation-two
replacement completed a fresh login through its independent PostgreSQL pool
and Redis client. The new Session recorded generation two and authenticated;
no sticky session, alternate provider effect, mutable subject update, or
generation-one authority reappeared.

The complete containerized platform integration lane passed on a fresh rerun,
including the new recovery gate, natural expiry, cleanup-wins, process-death,
wire-ACK-loss, and process-runtime cases. The ordinary repository race suite
passed 4,284 tests in 51 packages. Ordinary and integration vet, module
consistency, and ordinary/integration delta lint also passed.

This fixture qualifies the Core anti-rollback fence, not a production restore
controller, continuity witness, backup/WAL recovery, key-custody procedure, or
physical immediate deletion of retained stale rows. It did not use the live
Google credential, mutate the POC cluster, build an image, or roll Helm, and it
does not qualify PostgreSQL service failover, multi-node database HA, or
availability-zone recovery. `SSO-BROKER-007` is complete for the current
source-level scope; those infrastructure and recovery-operation claims remain
separate.

## Private aggregate-runtime canary

Chart `0.2.22` adds a private POC profile for the same immutable `poc-v36`
image digest. It disables the split API, Control, and Identity components and
runs one `role=all` component with no Ingress. The process uses distinct TLS
listeners for Control, management API, private Login, and Identity, a separate
health listener, the existing immutable relay-directory snapshot, the existing
runtime and Identity credentials, and a dedicated least-privilege
`mesh_worker` credential. Secret values remain Secret-backed file references;
the runtime ServiceAccount does not receive a Kubernetes API token.

Strict Helm lint, local render, and Kubernetes server-side dry-run passed.
Trivy's embedded manifest policies reported zero High or Critical
misconfigurations across the rendered ConfigMap, Deployment, NetworkPolicy,
ServiceAccount, and Service. The container remained non-root with a read-only
root filesystem, RuntimeDefault seccomp, no Linux capabilities, bounded
requests/limits, and a digest-pinned image. The chart's deployment-strategy
schema now accepts only `RollingUpdate` or `Recreate` and validates the optional
rolling parameters.

The one-worker POC could not schedule a surge replica beside the original
canary because the node had insufficient memory. This was a topology-capacity
constraint, not a Core failure: the atomic rolling attempt rolled back and the
existing pod remained Ready. The private one-replica canary therefore uses
`Recreate`; split production roles retain their zero-unavailable rolling
strategy. Revision 4 completed the replacement in 13 seconds and logged one
runtime owning `api`, `control`, `worker`, `relay`, and `identity`. Revision 5
added the exact `ingress-nginx:443` egress needed for public-issuer hairpin
discovery. Without that rule, PostgreSQL admission succeeded but only
`/ready/login` was unavailable; ordinary Core `/ready` correctly remained
Ready. After the rule, both endpoints returned `200` with PostgreSQL, Redis,
private Login, Identity PostgreSQL, and Identity configuration all Ready.
Revision 6 records the final chart metadata without changing the pod template.

The four private application listeners were then checked independently through
port-forward with full CA and hostname verification. Control capability 142,
the management API's structured not-found contract, a no-grant Login prepare,
and embedded Identity discovery returned their expected responses. Deleting
the canary pod restored a new Ready pod with zero container restarts; both Core
and Login readiness returned `200`. During that replacement, the public
Control key and OIDC discovery endpoints remained `200`, and the separate main
API, Control, Identity, and Console Deployments remained 2/2.

An isolated release deliberately assigned the Identity listener to the Control
port. The process exited before admission with only redacted
`error_code="invalid_configuration"`; its EndpointSlice reported
`ready=false` and `serving=false`. The test release was uninstalled after
capture. This proves aggregate-runtime compatibility and fail-closed startup on
the current artifact; one canary replica on one worker is not an HA claim for
the aggregate deployment profile.

## HA interpretation

This run qualifies rolling replacement and single-worker drain inside one
cluster. It does not qualify availability-zone or regional failure. All Core
roles were horizontally replicated, protected by a minimum-available
PodDisruptionBudget, and hard-spread across two workers. PostgreSQL and Redis
were external dependencies with no failover exercised in this run.

No correctness path required sticky sessions. Browser transactions, Core
sessions, RBAC authority, and policy releases were reconstructed from durable
state. Redis remained non-authoritative.

## Remaining execution order

1. Execute the `SSO-BROKER-008` adversarial security matrix, then close the
   remaining legal-review and signed-artifact items.
2. Extend publication cases to TCP, UDP, multiple devices, and multiple
   Networks before treating policy qualification as complete.
3. Resume PostgreSQL and Redis infrastructure failover only when that paused
   workstream is re-opened; the Core-side reconnect/reconciliation support is
   already present but does not qualify the external data services.
