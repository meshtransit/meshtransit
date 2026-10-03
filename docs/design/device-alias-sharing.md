# Device sharing through peer aliases

## Status and product decision

The product decision dated 2026-10-02 requires Device sharing to use the two
participating Device clients. It introduces no additional gateway machine,
application proxy, provider subnet route or packet hop. The consumer and provider
remain members of their original Networks.

This document specifies the required behavior. Client alias validation and packet translation are implemented in
`meshd` commit `bbe1ec7b77ea35e7217e53694bbe9f5201d82d89`, with the owned v1
contract documented in that repository. The client does not advertise support.
Schema 81 implements migration-only durable reservation and quarantine.
The authenticated worker command, alias projection reader and cross-Workspace
map delivery are not implemented or enabled on POC. The existing same-Workspace direct reader
remains a separate implementation path.

A Private Endpoint is the logical contract, local destination and lifecycle
object. For a Device-backed Resource, the provider enforcement process is
`meshd` on that Device. The architecture's agent role does not require another
host. Resources without a client and routed Resources remain later work.

WireGuard uses the authenticated direct path when available. The existing
encrypted relay fallback can carry the same ciphertext when NAT prevents a
direct path. Alias translation does not introduce a gateway or terminate
end-to-end encryption at a relay or Core.

## Address contract

Each peer pair has four address roles, separately for IPv4 and IPv6:

| Role | Meaning |
| --- | --- |
| Consumer canonical address | The consumer's address in its own Network |
| Provider canonical address | The provider's address in its own Network |
| Resource Alias | The provider destination visible to the consumer |
| Consumer Source Alias | The consumer source visible to the provider |

Both Workspaces may use identical canonical addresses. Cross-Workspace sharing
always allocates both alias roles from collision-checked federation pools;
current non-overlap is not a reason to expose canonical foreign addresses.
Same-Workspace Device sharing keeps canonical host addresses where the existing
address contract proves non-overlap.

A Resource Alias remains bound to one contract, Resource and consumer Network.
A Consumer Source Alias remains bound to one endpoint generation and consumer
Node. Neither alias is a new Device, membership or identity. Alias ownership is
bound to exact Node keys, key epochs, recovery epoch and exclusive deadlines.

Alias allocation must exclude ordinary leases, configured overlay pools,
reserved DNS addresses, active aliases and quarantined aliases. Configure IPv4
and IPv6 alias pools explicitly; no fixed example prefix becomes a runtime
allocation default. Install only exact host routes. Alias knowledge grants no
permission, and no peer may claim another peer's source alias.

## Packet behavior

The following requirements are protocol independent:

| Stage | Packet source | Packet destination |
| --- | --- | --- |
| Consumer kernel sends | Consumer canonical | Resource Alias |
| Consumer client encrypts | Consumer Source Alias | Resource Alias |
| Provider client delivers | Consumer Source Alias | Provider canonical |
| Provider kernel replies | Provider canonical | Consumer Source Alias |
| Provider client encrypts | Resource Alias | Consumer Source Alias |
| Consumer client delivers | Resource Alias | Consumer canonical |

The consumer rewrites its own source only for the selected provider peer. The
provider rewrites its own source only for the selected consumer peer. On ingress,
the receiving client accepts only its exact local alias for that authenticated
peer and rewrites that destination to its canonical local address. Other local
peers keep their canonical traffic and policy behavior.

WireGuard cryptokey routing must bind each inbound source alias to the expected
peer key before delivery. Validate the original alias destination before its
rewrite; a packet addressed to a raw provider address must not become an
implicit alias packet. The destination client enforces the effective inbound
protocol/port tuple against the consumer source alias and local Resource.

Translation preserves transport ports, TCP state and ICMP echo identifiers.
It updates the IPv4 header checksum and applicable TCP, UDP and ICMPv6 checksums.
IPv4 UDP's absent-checksum semantics must be preserved; invalid IPv6 UDP checksums
fail closed. Malformed, fragmented or unsupported packet forms remain denied.
ICMP error translation requires a separately tested contract for the quoted
packet and cannot be inferred from echo support.

## Policy after acceptance

The provider sets the export maximum. The consumer publishes one ordinary
Access Rule with local sources and the typed Imported Resource destination.
Effective access remains the intersection of export maximum, consumer rule,
both Guardrails, Resource constraints, active contract and endpoint grant.

Accepting without a consumer rule grants no packet access. A permission holder
can save and publish a rule directly. Console selects the imported destination;
users do not enter aliases, revisions, generations or a second provider rule.

The provider inbound projection is derived from that current intersection.
Only the consumer may initiate. Provider replies require the admitted flow;
provider initiation requires its own opposite-direction contract and rule.
Ordinary local wildcard selectors must not absorb imported peers. A local allow
rule or return-flow record cannot widen an alias grant or bypass its expiry.

## Atomic state and withdrawal

A client applies alias bindings, peer keys, routes, DNS and packet grants as one
validated authority generation. A partial or ambiguous replacement closes the
packet path. The same snapshot governs translation and policy; concurrent map
updates cannot mix an old alias with a new peer or rule.

Security changes invalidate tracked flows before replacement. Contract revoke,
rule removal, target replacement, ownership or membership loss, expiry, Node-key
change and recovery change withdraw the exact grant from both projections.
Per-packet exclusive deadlines remain enforced during a silent map stream.

Core commits authority, alias ownership, both Network revisions, audit and outbox
atomically. Bounded dependency discovery includes accepted ready contracts before
a consumer rule exists, so its first rule wakes the provider. Redis carries
post-commit hints; authoritative reconciliation repairs missed notifications.
Released aliases enter quarantine before any reuse. A new generation never
inherits a flow, packet grant or deadline from a withdrawn generation.

## Client and wire constraints

Numeric legacy capability 142 alone does not prove alias translation support.
Client commit `bbe1ec7` validates the versioned v1 grant alongside the
per-peer self-alias fields and translates at the packet gate. Earlier clients
drop those fields during conversion and have no translation stage. Core must admit an alias projection
only through an explicitly supported, versioned client contract, with both
participating clients qualified for the required address families and grants.

The legacy representation has one self alias per peer per address family, while
current client maps require unique peer keys. The first alias profile must reject
multiple incompatible active endpoint bindings for the same Node-key pair. It
must not duplicate a peer key, choose one alias silently or combine unrelated
generations. A richer multiple-Resource representation requires a separate
versioned contract and conformance cases.

The product contract includes exact contract/endpoint generations, directed
packet grants and deadlines. Legacy masquerade fields describe address behavior
only; they do not carry complete generation or permission evidence. They cannot
substitute for the Resource endpoint capability or create a raw-address fallback.

Use the existing 256-peer packet-engine bound and bounded grant counts. A map
that exceeds a profile limit fails as a whole; truncating its authority is not
permitted. The privileged helper still receives only validated host routes and
canonical self addresses, with alias pools explicitly included in its allowed
route pools. Packet translation remains in the unprivileged client.

## Threat boundaries

| Threat | Required control |
| --- | --- |
| Source spoofing | Exact source alias bound to the authenticated Node key |
| Raw-address bypass | Verify the peer-specific alias destination before rewrite |
| Cross-Workspace address collision | Separate alias allocation plus exact host routes |
| Stale or mixed generations | Atomic snapshot, generation checks and packet deadlines |
| Reverse or transitive access | Directed grants; stateful replies; imports cannot be re-exported |
| Alias reuse | Durable quarantine covering stale session and projection lifetimes |
| Resource exhaustion | Bounded peers, aliases, grants, parsing and flow state |
| Redis loss or forgery | Hints never grant access; re-read PostgreSQL and reconcile |

## Delivery gates

1. Define a versioned product-owned alias projection and synthetic packet/map
   vectors. Qualify observable legacy behavior independently where compatibility
   is intended; no reference implementation source or schema is copied.
2. Implement and qualify client alias validation, translation, checksums,
   peer-specific policy and atomic replacement for IPv4 and IPv6.
3. Add durable alias allocation, quarantine and bounded authenticated bilateral
   map reads without widening ordinary Network inventory.
4. Complete both-Network revision/connectivity dependencies, including first-rule
   creation and lost-hint reconciliation.
5. Use two real encrypted clients in distinct Networks. Test TCP, UDP and ICMP,
   identical canonical IPv4/IPv6, adjacent denied ports, raw-address and spoofed
   source rejection, reverse initiation, a third Network, policy narrowing,
   revoke, expiry, key replacement, reconnect and alias quarantine.
6. Qualify imported DNS names and lifecycle. Router and SSH remain deferred.

Implementation evidence and the exact reference revisions are recorded in
[the alias assessment](../research/custom-control-device-alias-assessment-2026-10-02.md).
The existing runtime checkpoint is documented in
[Same-Workspace direct Device sharing](same-workspace-direct-device-sharing.md).

## Bounded alias allocation proposal

Core implements `ipam.NextDeviceAliases` as a pure allocation
proposal, not a lease or packet grant. Explicit IPv4 and/or IPv6 pools are
mandatory. Each requested family yields both a Resource Alias and a Consumer
Source Alias; failure in any family returns no pair. No runtime prefix defaults
or inferred address family are permitted.

The caller must supply one authoritative, transactionally locked snapshot of
all excluded prefixes and in-use, quarantined and reserved addresses. Alias
pools cannot overlap any excluded prefix. Address exclusions include ordinary
leases and DNS reservations. Quarantined addresses remain excluded until a
durable lifecycle transition releases them; clock passage alone cannot release
an address. Duplicate exclusions are harmless and do not create identity.

The proposal excludes unsafe address blocks, network addresses and IPv4
broadcast addresses. It selects the lowest available hosts deterministically
within a bounded search window. Limits are 4,096 excluded prefixes, 65,536
combined excluded address entries and 65,536 candidates per individual host
search. Four searches at most are needed for a dual-family pair. Exhaustion
within that window does not prove the entire prefix is full.

Threat controls before implementation:

| STRIDE threat | Severity | Required boundary |
| --- | --- | --- |
| Spoofing/elevation through a proposed address | High | A proposal grants no authority; exact contract/generation/Node ownership remains mandatory |
| Tampered or incomplete exclusion snapshot | High | Caller loads durable authority under the realm lock; no Redis-only snapshot |
| Alias collision or stale-map reuse | High | Exclude ordinary/configured/DNS/active/quarantined addresses; durable uniqueness and quarantine remain mandatory |
| Partial family allocation | High | Any error returns a zero proposal; persistence must commit both families atomically |
| Work or memory exhaustion | Medium | Explicit collection and candidate bounds; no workers, timers or retries |
| Repudiation/disclosure | Medium | Persistence later requires atomic audit/outbox; the proposal emits no logs or topology |

This helper is not connected to runtime allocation. A future application use
case must lock the durable realm, check existing idempotent ownership, persist
both aliases with uniqueness constraints and exact generations, advance both
Network revisions, and write audit/outbox in the same transaction. A proposal
computed from stale state must never be retried or published independently.

### Local verification of the allocation proposal

The proposal is covered by complete-pair, explicit-family, immutable-input,
quarantine, exhaustion and adversarial pool/bounds tests. A bounded ten-second
fuzz run completed 1,543,739 executions. Whole-tree uncached race tests with
shuffle, vet, lint and `go mod tidy -diff` pass. `govulncheck` reports no reachable
or imported-package findings and three module-only findings outside the current
call graph. No dependency is added by this increment.

Full-tree and complete-history Gitleaks scans report six existing matches in
Dex patches committed before this change: five public module checksums in
`0003-security-dependency-updates.patch`, and the RSA test-key context hunk in
`0008-inject-connector-http-client.patch` (`server/server_test.go`). They are
outside this increment. No scanner baseline or exclusion is added. The full
secret-scan gate remains unresolved; an increment-scoped scan is recorded
separately. No release, migration or POC deployment is qualified by this proposal.

## Durable reservation foundation — schema 81

`mesh.device_alias_lease` retains one Resource alias per endpoint/family and one
Consumer Source alias per endpoint/consumer Device/family. IPv4 and IPv6 remain
explicit realm settings. Each enabled family requires exactly one active pool
for each role. The existing endpoint's legacy Resource alias is adopted only
under its exact owner; it is not replaced or allocated to a second owner.
Additional consumers reuse Resource aliases and receive distinct source aliases.

The internal reservation function is **SECURITY INVOKER**, executable only by the
migration role. No runtime, worker, observer or share-writer role can read, insert
or execute it. Deployment-local pool configuration policies apply solely to the
migration role. Existing revision RLS stays scoped to one Network at a time.
Derived ordinary and bilateral GUCs are restored on success and exception.
The table itself has FORCE RLS and immutable identity/Node pins.

The transaction locks both Network revision rows in scope order, the endpoint
and contract, Resource/target, ordered Devices and key epochs, the active realm,
and ordered pool cursors. Missing revision locks are errors. Fresh clock checks
run after waits and before returning. Allocation pins the endpoint, Resource
version/target generation, recovery epoch, Device session and machine/Node key
epochs, public Node key and exclusive finite deadline. A changed pin fails the
retry; this foundation does not rotate or renew an endpoint generation.

Allocation uses the existing durable pool cursors, separately for each role.
It rejects unsafe prefixes and overlap with configured ordinary/service pools,
excludes ordinary active/quarantined addresses and all retained legacy alias
addresses, and excludes reserved/quarantined new aliases throughout the
Deployment, including a suspended previous realm. A unique retained-address
index is the final arbiter. At most 65,536 candidates are inspected per lease;
IPv4 pools are /8–/30 and IPv6 pools /67–/126. At most 256 consumer owner slots,
including tombstones, exist per endpoint. Pool changes cannot expand the family
set of an existing reservation silently. A disabled legacy alias family fails.

Both Network and sharing revisions advance once per changed batch. All leases,
cursors and revisions roll back together on an error in any family. An exact
owner retry returns the stored addresses without extra leases, revision bumps
or evidence. A retry after an unknown commit may resolve the same exact owner
slot; it must not initiate a new generation or guess that the commit failed.

Deferred DB checks require audit/outbox in both exact Network scopes, with the
stored Network/sharing revisions. Audit payloads identify the endpoint and the
complete sorted set of mutated lease public IDs and versions. An unrelated or
incomplete batch cannot cover these mutations. Evidence is appended in the same
transaction by the privileged caller. A future serving command must derive and
validate its exact authority snapshot and evidence before this storage primitive
receives a narrowly reviewed runtime capability.

Quarantine is an explicit durable transition, never clock-based deletion. Its
finite deadline must cover the later of endpoint expiry or the current decision
plus at least 24 hours. Address ownership and owner slots remain retained.
Release is forbidden before that deadline or while the endpoint remains current;
no release worker or address reuse path is exposed by this increment. Allocation
never makes an endpoint ready, publishes DNS, changes a packet ACL or advertises
client support. The pure `NextDeviceAliases` proposal remains independent; the
SQL foundation uses the schema's separate role pools.

Verification uses a disposable PostgreSQL 18.6 database, with synthetic cloud
Workspaces and existing sharing authority fixtures. Cases cover two families,
explicit IPv6, legacy alias adoption, two consumers, exact owner replay, a
competing writer's finite lock timeout, foreign/stale owners, missing/overlapping
pools, final-family exhaustion, complete rollback, scope restoration, missing
bilateral evidence, incorrect evidence membership, quarantine collisions and
early release rejection. These are storage tests, not a live encrypted sharing
qualification. Worker admission, successor generations, automatic withdrawal,
bilateral maps, post-commit Redis hints and live packet/DNS qualification remain
required before activation.

## Owned map encoder checkpoint

Core now validates immutable Device alias ownership alongside each exact
bilateral sharing projection and emits the owned v1 grant on full maps and
complete peer replacements. Canonical cross-Workspace addresses may overlap;
only aliases become remote peer routes. The provider filter uses the Consumer
Source Alias and the canonical local destination after client normalization.
Grant-only revision changes replace the peer in the same atomic policy delta.

The six synthetic owned protocol fixtures and tests cover TCP, UDP and ICMP
for both families. This model/codec checkpoint does not connect a runtime
reader or worker and does not admit an unqualified client or enable POC sharing.
See the owned [wire contract](../../api/protocol/device-alias-v1.md).
