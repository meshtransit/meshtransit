# Imported Resource policy simulation evidence

Date: 2026-10-04

## Boundary and threat model

The format-4 publication compiler retains Consumer-local Imported Resource
intent and freshly resolved bilateral provenance. It does not manufacture a
same-Network Device packet edge. A preview that silently drops these rules can
mislead an operator into publishing an unexplained access change.

Simulation must report added and removed Imported Resource intents separately
from effective local packet relationships. Each item binds the Access Rule,
Consumer source Device, local Imported Resource identity/version, Contract
identity/version, exact Provider/Consumer scopes, Export version, Resource
identity/version/target/hash, authority generations, recovery epoch, both
sharing revisions, Provider inventory revision, expiry, and narrowed traffic.
No Provider Device ID, canonical address, endpoint, or alias is disclosed.

The existing publication compiler remains the sole validator/resolver. The two
freshly authorized baseline reads remain mandatory. Consumer sharing provenance
newer than the stable local vector fails closed. Proposed Imported Resource
resolution must equal the current Consumer sharing revision; Provider counters are never
compared to unrelated Consumer counters. Older release provenance remains
reportable for removal. Publication independently revalidates current bilateral
authority and endpoint lifecycle; preview never creates a grant.

## Contract and compatibility

`impact.imported_intent_changes` is present exactly when either candidate is
format 4. It contains complete added/removed counts and canonical lists bounded
to 256 each. Changes in traffic or bilateral provenance produce a removed old
item and an added new item. Evaluation timestamps alone do not change intent.
Affected local Devices include Consumer sources of changed imported intents;
Provider Resources are not misreported as Consumer-local inventory.

The proposed compiled rule count includes local expanded rules and retained
Imported Resource rules. Impact hashing uses domain version 2 for previews with
format-4 candidates and binds the complete untruncated imported changes. Local
format-1/2/3 previews retain their version-1 digest and response shape.

`share_intersection` and `cross_scope_relationships` remain explicitly
unsupported in simulation. Imported intent evidence is not proof that a packet
path is active. Full effective cross-scope assurance requires current endpoint,
bilateral policy, lifecycle, and client enforcement qualification. Protected
approval format support is unchanged; this slice does not enable format-4
human-approval publication.

## Verification

Exercise the actual publication compiler for add/remove/narrow/preserve and
provenance changes. Verify no synthetic local packet edges, exact scope and
traffic, source impact, stale Consumer revisions, bounded/immutable lists,
deterministic complete hashes, management DTO/OpenAPI parity, and persisted
format-4 baseline simulation under actual PostgreSQL RLS/runtime roles.

## Persisted baseline reader proposal

The actual PostgreSQL regression exposed a persisted-read failure: the existing
baseline reader runs with Consumer scope, while reconstructing immutable
Imported provenance requires joins to Provider-owned metadata. Provider RLS
correctly hides those rows; silently returning an empty rule list is invalid.

Migration 88 adds a private, bounded reader owned by the existing
`mesh_share_writer` NOLOGIN role. It may select one immutable compiled Imported
projection identified in the current Consumer scope. The projection fixes the
Provider/Consumer pair and every Contract, Offer, Export and Resource join.
Only pinned provenance and traffic metadata are returned. Provider Device
identity, canonical addresses and endpoints remain absent.

The runtime cannot execute this helper directly. The baseline entry point must
perform its existing fresh Account session and Consumer authorization checks
first. The helper restores all temporary bilateral scope settings on both
success and exception; a missing provenance dependency fails the read instead
of omitting an intent. The new table grant is SELECT-only, with Consumer RLS;
there is no runtime table write, new role membership or BYPASSRLS permission.

The operator-approved change remains subject to actual PostgreSQL qualification
before deployment. Qualification must cover persisted compiler hash equality, removal and empty
policy restoration, denied foreign projection reads, denied direct runtime
execution, scope restoration, canonical ownership and deployment preflight.
