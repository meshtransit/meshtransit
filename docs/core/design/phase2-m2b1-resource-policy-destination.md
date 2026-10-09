# Phase 2 M2b1 Device Resource policy destination design

Status: implemented and locally qualified for active Device-backed Resource
destinations. Resource Group expansion remains M2b2.

Date: 2026-09-29

## Scope

M2b1 lets one Access Rule select exactly one direct Device or one active
Device-backed Resource. Core resolves the Resource through PostgreSQL authority
and compiles the same Node-level TCP, UDP, and fixed-profile ICMP semantics
already qualified by M2a. Clients, Redis, and the map protocol receive no new
selector or authorization semantics.

This slice does not add a graph database. PostgreSQL remains the relational
authority for Resource identity, lifecycle, target binding, policy releases,
audit, and outbox evidence. Access Graph explanation and simulation remain a
later derived model.

## Typed input and bounds

- Every rule contains one source Device and exactly one of
  `destination_device_id` or `destination_resource_id`.
- Unknown fields, missing or ambiguous destinations, malformed public IDs, and
  invalid transport ranges fail before compilation.
- One publication may reference at most 256 distinct Resources and 10,000 total
  rules. Resource IDs are de-duplicated and sorted before authority reads.
- Resource lookup runs in one repeatable-read, exact Network-scoped transaction
  after fresh `resource.read` authorization.
- Only an active Resource with a valid active Device target can compile.

## Immutable compiler evidence

The compiler emits the existing immutable Device-level `policy.Snapshot`. For
each Resource-selected edge it also records:

- stable Access Rule ID;
- exact Workspace and Network scope;
- Resource public ID and authority version;
- Resource target generation and inventory revision;
- resolved destination Device ID; and
- Resource semantic hash.

Direct Device-only candidates retain compiler format 1 and its original hash
encoding. Candidates with Resource provenance use compiler format 2 and a
separate hash domain that binds every fact above. Reordering equivalent input
does not change the canonical candidate.

## Atomic activation and race closure

Migration 43 adds immutable
`mesh.compiled_policy_resource_destination` provenance. Publication first
creates the candidate release and compiled Device edges, then calls the
least-privileged `mesh_ops.attach_policy_resource_destinations` function in the
same transaction, under the existing Network/release serialization boundary.

The function revalidates exact scope, active release, compiled rule identity,
active destination Device, active Resource lifecycle, Resource version, target
generation, inventory revision, semantic hash, and current active Device
binding. It requires the inserted provenance count to equal the candidate
count. Any stale or missing fact raises a conflict and rolls back the release,
revision changes, provenance, audit, and outbox together; the previous release
remains active.

Runtime receives only exact-scope `SELECT` on provenance and `EXECUTE` on the
attachment function. Rows are immutable, RLS is forced, and mutations are
covered by the existing audit completeness boundary.

## Management boundary

Bearer and private cookie management graphs use the same compiler service. The
private browser proof is validated before Resource authority is read. Resource
conflicts return a stable `409 resource_conflict`; authorization, malformed
input, timeout, and unavailable dependency responses preserve the existing safe
error shapes without database detail.

## STRIDE review

| Threat | Control |
| --- | --- |
| Spoofing | Typed Resource IDs, authenticated Account Session, exact Workspace/Network scope, and fresh `resource.read` plus `policy.publish`. |
| Tampering/replay | Format-2 semantic hash, exact version/generation/revision pins, Network lock, and transactional revalidation. |
| Repudiation | Immutable provenance plus release audit/outbox evidence commit in one transaction. |
| Information disclosure | Opaque cross-scope handling and safe HTTP errors expose no Resource or database detail. |
| Denial of service | 256 distinct Resource and 10,000 rule bounds, one snapshot transaction, bounded SQL waits, and bounded publication retries. |
| Elevation of privilege | Resource selection only narrows to its active Device target; it creates no client wildcard or implicit group authority. |

## Acceptance and non-claims

Executable evidence is recorded in
`docs/qualification/phase2-m2b1-resource-policy-destination-2026-09-29.md`.

This is non-production engineering evidence. It does not qualify deployed
artifacts, HA or data-service failover, Resource Group selectors, routed or
service Resources, Access Graph explanation/simulation, production SLOs, or GA.

## Next order

1. M2b2: resolve immutable Resource Group definitions, pin definition and group
   revisions, expand members deterministically, and revalidate every member.
2. M4: derive Access Graph explanation and simulation from the same exact
   compiler inputs; keep PostgreSQL relational authority.
3. M5: extend enforcement to routed/service Resources and trusted gateways.
