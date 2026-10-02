# Same-Workspace direct Device sharing

## Status and approved product boundary

This is the implementation plan for the next sharing slice, not a claim that
cross-Network packet access is already available. The current map reader accepts
only same-Network candidates and rules. Imported Resource publication currently
retains provenance without creating a packet edge.

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

Direct readiness must use a distinct validated path. The current alias endpoint
in `provisioning` cannot be reinterpreted as ready or have its route proof
bypassed. Extend the endpoint authority boundary with a reviewed direct readiness
contract before the map reader consumes direct grants.

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
