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

## Decision 2026-10-05: one alias technique for every Device share

This decision supersedes the canonical-address exception for same-Workspace
Device sharing. Every Device share uses the peer-alias path, whether the two
Networks are in one Workspace or in different Workspaces and whether or not
their canonical prefixes overlap. One packet path is easier to verify and
maintain than a direct path plus an alias path. The direct same-Workspace path
remains only until the alias path passes the live same-Workspace qualification;
it is then withdrawn and removed.

Address ownership:

- A Workspace owns its complete overlay space (`100.64.0.0/10` and its
  configured IPv6 overlay prefix). Users partition Network prefixes inside it.
  Alias pools therefore lie outside every Workspace overlay prefix.
- Alias pools are Deployment data, not code defaults. The reference POC and
  cloud values are IPv4 `198.18.0.0/16` (Resource Alias) and `198.19.0.0/16`
  (Consumer Source Alias), and IPv6 `fd02:48de:ec1b:1::/96` and
  `fd02:48de:ec1b:2::/96` from the random RFC 4193 prefix `fd02:48de:ec1b::/48`.
  `198.18.0.0/15` is the RFC 2544 special-purpose block: it is not globally
  reachable and does not conflict with RFC 1918 site prefixes.
- One Resource Alias is reserved per Private Endpoint (one contract); one
  Consumer Source Alias per endpoint and consumer Device.

Alias uniqueness is scoped to participating Networks, not to the Deployment. A
retained alias (reserved or quarantined) must be unique among every retained
alias whose provider or consumer Network is either Network of the new lease.
This is the exact condition the client enforces per map: a local alias cannot
collide with a mapped address, and one local alias cannot have incompatible
endpoint owners. A Device can be a provider and a consumer at once, so both
sides of each lease are checked. Capacity is consequently bounded per Network
instead of per Deployment, so one tenant cannot exhaust another tenant's pool.
Quarantine is scoped the same way. Logs and audit identify an alias together
with its Network.

Consumer-visible names use the provider identity:
`<label>.<provider-workspace-code>.<provider-network-code>.shared.mesh`, where
the codes are the immutable twelve-digit display codes. The share creator sets
the label when creating the share; the Console proposes a normalized Device
hostname. A label identifies exactly one Resource within its provider Network
and is frozen once a share uses it. Consumers do not choose the name. Names are
discovery metadata only; authorization remains the alias grant.

Schema 94 implements this on the Share Offer. `create_resource_share_offer_v3`
stores the canonical label (API `access_label`, defaulting to the shared
Resource name) and rejects a label that a live offer or contract in the same
provider Network uses for another Resource; the same Resource may reuse its
label for other consumer Networks. A trigger freezes the column.
`decide_resource_share_offer_v4` derives the name from the display codes and
rejects a consumer-supplied name that differs. Offer reads return the label and
the derived name only within the caller's exact Network scope. Offers created
before schema 94 have no label and keep the consumer-typed name. The existing
per-consumer-Network uniqueness of reserved names still rejects importing the
same label twice into one Network.

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

Both Networks may use identical canonical addresses. Every Device share
allocates both alias roles from collision-checked alias pools; current
non-overlap is not a reason to expose canonical foreign addresses, including
inside one Workspace.

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
| Canonical address collision | Network-scoped alias allocation plus exact host routes |
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
See the owned [wire contract](../../protocol/device-alias-v1.md).

## Compatibility observation checkpoint — schema82

The authenticated map service accepts the owned DeviceAliasVersion claim and,
only when alias support is explicitly enabled in its store, records the current
session/key pins through a dedicated NOLOGIN observer. Claim metadata grants no
access and ordinary serving roles cannot read or write its table. Repeated
unchanged declarations do not update a row. Metrics are aggregate operation,
latency and outcome only. No alias support is enabled by this schema increment.

Disposable PostgreSQL tests exercise exact retry/downgrade, machine/Node epoch
binding, a foreign key, caller scope poisoning/restoration and ownership/table
privileges. Decoder tests reject ambiguous versions. Store tests prove disabled
and canceled calls start no write, and write/unknown-commit failures join bounded
rollback errors. Worker reservation and authenticated bilateral alias reads
remain the next serving integration.

## Unified alias checkpoint — schema 92

Schema 92 implements the 2026-10-05 decision in storage, activation, the map
reader and the worker:

- `activate_resource_share_v4` activates every Device share as an alias
  endpoint (`provisioning`, legacy Resource Alias lease `reserved`) and never
  writes `mesh.direct_device_endpoint`. It first requires the exported Device
  to be active, unexpired and on current machine/Node keys, so an unusable
  target fails closed before any allocation.
- Workspace-inequality checks on alias leases, readiness and every worker or
  reader guard become Network-inequality checks. The work scan no longer
  requires the cloud Deployment profile, so self-hosted Deployments use the
  same path.
- The Deployment-wide unique address indexes are replaced by
  `device_alias_network_uniqueness`: a new lease is rejected when its address
  is retained (reserved/active legacy lease, reserved/quarantined client lease)
  by any lease whose provider or consumer Network is either Network of the new
  lease. Every writer already holds both Network revision row locks, so writers
  that share a Network serialize. `allocate_network_scoped_alias_v1` returns the
  lowest host free in that scope (at most 65,536 candidates) and checks pool
  overlap with overlay and service pools.
- `load_device_alias_map_edges_v2` selects local and remote aliases by Network.
  v1 compared Workspaces, which gives both sides of a same-Workspace share the
  provider's aliases; an integration test reproduces that failure.
- The operator script `migrations/operator/000092_unified_device_alias_ownership.sql`
  assigns the new functions to their NOLOGIN owners, grants the runtime and
  worker entry points, and closes `activate_resource_share_v3`, the v1 map
  reader and the v1 worker entry points.

Integration coverage: same-Workspace activation creates an alias endpoint with
no direct readiness; unusable targets fail before allocation; the rollback
writer still withdraws the alias endpoint with both revisions; a live
same-Workspace Resource Alias is unique in both Networks while an unrelated
Network pair reuses an address another Network retains; and the v2 reader gives
the consumer its Consumer Source Alias as local and the Resource Alias as the
only remote route, and the reverse for the provider. Runtime enablement still
needs the alias realm and pools on each Deployment, both alias runtime switches,
alias-capable clients and live packet qualification.
