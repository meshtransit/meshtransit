# Phase 2 M2b2 Resource Group policy destination design

Status: implemented and locally qualified for active Resource Group destinations.

Date: 2026-09-29

## Scope

M2b2 lets one Access Rule select exactly one direct Device, active Device-backed
Resource, or active Resource Group. The compiler expands an immutable Resource
Group definition into the same Node-level TCP, UDP, and fixed-profile ICMP
edges already enforced by the M2a client projection. Resource Groups remain
destination-only and membership alone grants no access.

PostgreSQL remains the relational authority. This slice does not introduce a
graph database, Redis authority, client-side selectors, or a second policy
evaluator. Access Graph explanation and simulation remain derived products of
the same compiler semantics.

## Typed input and bounded resolution

- Every authoring rule contains one source Device and exactly one of
  `destination_device_id`, `destination_resource_id`, or
  `destination_resource_group_id`.
- Unknown fields, malformed IDs, missing or ambiguous destinations, and invalid
  transport ranges fail before authority reads.
- A publication may resolve at most 256 distinct Resources, 256 distinct
  Resource Groups, and 10,000 compiled edges after expansion. Each immutable
  Resource Group definition remains bounded to 256 members.
- Direct Resources, group definitions, and every member Resource are read in
  one exact Network-scoped repeatable-read transaction. Group compilation
  requires fresh `resource_group.read` and `resource.read` authorization at the
  same evaluation time.
- Only active groups and active Resources compile. Every immutable group member
  reference must still match the Resource authority version and target
  generation it pinned.

## Deterministic expansion and compiler format 3

One group-selected authoring rule expands to one compiled Device edge per
member. All expanded edges retain the stable authoring Access Rule ID; durable
projection IDs remain independently generated for each edge. Canonical group
definitions, sorted authority reads, canonical packet rules, and sorted
provenance make equivalent input order-independent.

Compiler format 3 and hash domain v3 bind:

- the complete Node-resolved rule set;
- any direct Resource provenance carried by the same release;
- Access Rule and Resource Group IDs;
- Resource Group authority version, immutable definition version, collection
  revision, and semantic hash; and
- every member Resource ID, authority version, target generation, inventory
  revision, semantic hash, and resolved destination Device.

Formats 1 and 2 and their hash encodings remain unchanged for Device-only and
direct-Resource-only releases.

## Atomic activation and race closure

Migration 44 adds immutable
`mesh.compiled_policy_resource_group_destination` provenance, one row per
expanded compiled edge. Publication inserts the release and Device edges, then
calls the least-privileged
`mesh_ops.attach_policy_resource_group_destinations` function in the same
transaction and under the existing Network/release serialization boundary.

The function revalidates:

- exact Workspace/Network scope and active release identity;
- compiled projection, authoring Access Rule, and destination Device identity;
- active Resource Group lifecycle, authority version, active definition
  version, group revision, and semantic hash;
- the complete definition member count and exact member set;
- each active Resource version, target generation, inventory revision,
  semantic hash, active Device binding, and definition pin; and
- exact inserted provenance count.

Any missing, stale, substituted, cross-scope, or inactive fact raises a typed
conflict. The release, policy and Network revision advances, provenance,
audit, and outbox all roll back together, so the previous active release
remains authoritative.

The provenance table is immutable, forced-RLS, exact-scope readable by the
runtime role, and writable only through the security-definer attachment
function. Worker and observer roles receive no access.

## Management and runtime boundary

Bearer and private-cookie management paths use the same compiler. Browser proof
is validated before catalog authorization. A Resource or Resource Group
conflict returns the stable `409 resource_conflict` shape without exposing
object existence or database detail.

Clients receive only the existing Node-resolved packet policy. They do not
learn Resource Group membership or evaluate group semantics. Default deny,
Node-reduced peer visibility, and destination-side enforcement therefore remain
unchanged.

## STRIDE review

| Threat | Control |
| --- | --- |
| Spoofing | Typed opaque IDs, authenticated Account Session, exact scope, and fresh group plus Resource permissions. |
| Tampering/replay | Format-3 semantic hash, immutable definition/member pins, Network lock, and transactional revalidation. |
| Repudiation | Immutable edge provenance plus release audit/outbox evidence in the same transaction. |
| Information disclosure | Opaque cross-scope behavior, safe HTTP errors, and no client group selector. |
| Denial of service | 256 Resource/group read bounds, 256 members per group, 10,000 expanded-edge ceiling, and bounded database waits. |
| Elevation of privilege | Every member is independently active and target-valid; a group cannot revive or widen a failed Resource. |

## Acceptance and non-claims

Executable evidence is recorded in
`docs/qualification/phase2-m2b2-resource-group-policy-destination-2026-09-29.md`.

This is non-production engineering evidence. It does not qualify deployed
artifacts, HA or data-service failover, production SLOs, routed/service
Resources, cross-Workspace imports, Access Graph explanation/simulation, or GA.

## Next order

1. M4: derive Access Graph explanation, impact preview, and simulation from the
   same format-3 compiler inputs without adding a second authorization model.
2. M5: add routed/service Resource resolution and trusted gateway enforcement.
3. Re-run deployed multi-client and HA qualification only after those semantics
   stabilize and the paused infrastructure workstream is explicitly reopened.
