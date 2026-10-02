# Same-Workspace direct Device sharing

## Status and approved product boundary

The protocol/domain checkpoint now supports separately validated directional
same-Workspace Device projections, exact traffic intersections, bounded host
routes, full/delta removal and independent sharing expiry. Migration 79 adds
distinct generation-bound direct Device readiness and transactional contract
withdrawal. Cross-Network packet access is not enabled on a live deployment:
the current PostgreSQL map reader still loads only same-Network candidates and
rules. Imported Resource publication
retains provenance until the dedicated bilateral direct reader is complete.

The canonical requirement is in
`10-resource-sharing-and-private-endpoints.md` in the architecture set: Networks
remain isolated, and sharing grants access only to an explicitly exported
Resource. Within a Workspace, non-overlapping overlay prefixes permit direct
Device projection. Across Workspaces, a Private Endpoint with federation aliases
remains mandatory even when current prefixes happen not to overlap.

## First executable slice

Support one active Device-backed Resource in a provider Network, imported by a
distinct consumer Network in the same Workspace. Consumer initiation is allowed
only for the intersection of the export maximum, current consumer Access Rule,
both Guardrails, Resource constraints and the exact endpoint grant. Replies are
stateful. Provider initiation requires a separate opposite-direction contract
and rule.

Keep the existing exact-scope Network inventory reader. Add a separate, bounded
sharing projection read; do not widen ordinary Device or policy queries to all
Networks in a Workspace. A stored contract alone is insufficient evidence.

## Authority read and projection

Read all participating facts from one consistent PostgreSQL snapshot:

- authenticated self Device, machine and Node epochs, session generation,
  primary leases, expiry, Workspace/Network state and recovery epoch;
- current active export, accepted offer, active Trust Contract and Imported
  Resource, including both authority generations and exclusive expiries;
- current provider Resource version, target generation, semantic hash and the
  exact active Device target;
- the consumer's active immutable PolicyRelease and Imported Resource selector,
  bound to a current consumer Device and the exact import/contract generations;
- the ready direct endpoint generation and its current primary-address binding;
- complete traffic intersection and both participating revision vectors.

For each authorized consumer Device, the consumer map receives only the provider
Device needed by that rule. The provider Device receives only the consumer peer
needed to enforce the same directed grant. Each projection includes only the
exact host prefixes and required key/routing observations. The provider's other
Devices, groups, routes and administrative authority remain absent.

Projection validity ends at the earliest Device, contract, export or endpoint
deadline. Source addresses must remain bound to the authenticated consumer Node.
An address collision, unrecognized path, unavailable authority or stale vector
fails closed. Imported Resources cannot be re-exported through this slice.

## Durable lifecycle and Redis

Direct readiness uses `mesh.direct_device_endpoint`, separately from federation
alias provisioning. Activation pins current Resource/Device/key/primary-lease
evidence in the existing two-Network transaction; a terminal contract transition
withdraws that proof atomically. The alias endpoint in `provisioning` retains its
route proof requirements. A ready direct proof grants no access until the
authenticated bilateral reader validates current consumer policy and all ceilings.

Activation and withdrawal commit state, both affected Network revisions,
immutable audit and outbox records atomically, using deterministic Network lock
order. Consumer policy changes that alter an imported grant must wake the
provider projection too; provider target, key, lease and policy changes must
wake the consumer projection. Unrelated Network membership creates no edge.

Redis carries generation-bound connectivity and post-commit revision hints.
Maps and permissions remain authoritative PostgreSQL reads. Duplicate, reordered
or lost wakeups must be repaired by reconciliation without broadening access.

## Acceptance cases before live enablement

1. Without a share or consumer rule, both maps omit the cross-Network peer.
2. An accepted but activating/provisioning contract permits no traffic.
3. A ready direct grant admits only the exported IPv4/IPv6 host destination and
   intersected TCP, UDP or ICMP tuple.
4. Provider initiation, widened ports, source spoofing and a third Network fail.
5. Export/contract revoke, expiry, Resource retarget, Node epoch and recovery
   changes withdraw both projections and invalidate tracked access.
6. Current consumer policy changes converge on both sides through Redis; missed
   wakeups converge through authoritative reconciliation.
7. Same-address foreign Workspaces are rejected by the direct path, including
   legacy-client downgrade attempts. No raw-address fallback exists.
8. RLS and runtime grants still prevent ordinary cross-Network inventory reads.

The next code change must include synthetic protocol fixtures, domain tests,
PostgreSQL/RLS integration, full/delta/withdrawal conformance and a two-client
same-Workspace packet test. DNS follows this sharing boundary; router and SSH
remain outside this slice.

## STRIDE: direct map projection boundary

Assets are Device keys, host routes, exact packet tuples, contract/import
versions and both Network revision vectors. An authenticated consumer, stale
replica or forged notification may try to substitute a provider Device, widen
ports, reveal siblings, retain an expired grant or transitively re-export it.

The authority transition is from a consistent PostgreSQL bilateral resolution
to an immutable map projection, then a single atomic protocol frame. Ordinary
inventory remains exactly scoped. Separate immutable Imported Resource rule
provenance binds the source, import and contract; a ready direct endpoint and
current Resource target must independently agree. Address/key/numeric identity
collisions reject the complete map. Cross-Workspace direct projections reject
before encoding. The consumer receives no provider-initiated inbound rule.

At most 256 direct projections are admitted, within existing peer/rule/frame
bounds. Connectivity is accepted only for the resulting authorized peers and
session generations. Expiry reconstructs authority independently of self expiry;
authority reload failure withdraws sharing rather than retaining old grants.
Notifications cannot create authority, and reconciliation repairs lost hints.
The protocol checkpoint remains unconnected to the runtime map reader.
Direct activation/withdrawal now has PostgreSQL/RLS integration; authenticated
bilateral reads and both-Network refresh remain required before live enablement.

## Protocol checkpoint and required client deadline gate

The separate projection preserves the foreign peer's real scope and never
inserts a foreign Device into ordinary Network inventory or product policy.
Only current exact Imported Resource rule provenance plus Resource, Export,
contract, ready direct endpoint and independent ceilings can construct a grant.
Provider maps receive an inbound tuple; consumer maps receive no reverse tuple.
Both maps cap the peer's wire KeyExpiry by the earliest sharing deadline.

Same-local-revision bilateral changes use a complete atomic map frame; a
connectivity-only delta cannot carry a sharing authority change. Consecutive
local authority revisions can withdraw a peer and its packet filter together.
An independent deadline timer reloads sharing at expiry without expiring a live
self Device; failed reload emits terminal withdrawal rather than retaining the
expired grant. Per-Device maps admit at most 256 sharing projections and retain
existing peer, rule and encoded-frame bounds. Repeated consumer rule identities
or ambiguous numeric/key/address bindings fail the complete map closed.

The old client does not enforce peer KeyExpiry at the TUN packet gate. Therefore
this direct slice requires the client deadline gate before runtime activation.
That gate checks each packet against self/peer deadlines before ACL or tracked
replies, and invalidates tracked flows on mapped identity, key or deadline
replacement. It adds no Network selector or sharing protocol fallback.

`TestExportDirectSharingFrames` is an explicit synthetic fixture producer:

```text
go test -count=1 ./internal/adapter/legacyts2021 \
  -run '^TestExportDirectSharingFrames$' \
  -args -direct-sharing-fixture-output=<existing-output-directory>
```

Ordinary tests never rewrite fixtures. The producer emits full provider/consumer,
full and delta share removal, and terminal withdrawal documents from the actual
adapter encoder. Fixture consumers must pin the producing Core revision and
verify these frames with the client decoder. Database direct readiness,
authenticated bilateral reads, both-Network revision wakeups and a real encrypted
packet cycle remain prerequisites for live enablement.

The durable readiness checkpoint and remaining runtime gates are recorded in
[`direct-device-readiness-2026-10-02.md`](../qualification/direct-device-readiness-2026-10-02.md).
