# Phase 2 M1 Resource authority design

Status: implemented engineering slice, pending the Phase 2 M2 API contract.

Date: 2026-09-28

## Purpose

Phase 2 M1 establishes the local Resource and Resource Group authority that later
Access Graph, policy compilation, and resource-oriented management APIs can
reference. It does not add an HTTP route, Console UI, connector inventory,
sharing, or production availability claim.

This design follows the canonical contracts in `core-docs`: PostgreSQL is the
authority, Resource IDs are stable UUIDv7 values, target bindings are typed,
Resource Group versions are immutable, names are presentation data, every
mutation is scoped to one Workspace and Network, and audit plus outbox evidence
commits in the same transaction as authority.

## M1 boundary

The first vertical slice supports two authenticated operations:

1. Create a creator-owned Device Resource from an existing active Device.
2. Create a creator-owned destination Resource Group with one immutable version
   containing version- and target-generation-pinned Resource references.

The authenticated Principal is both initial owner and custodian. Ownership
transfer, custodianship delegation, lifecycle mutation, target rebinding, group
version replacement, discovery/import, and policy consumption remain later
slices. This restriction avoids introducing an unreviewed delegation model.

## Domain model

`internal/resource` owns:

- distinct `Resource` and `Resource Group` typed IDs;
- Device as the only M1 Resource kind;
- active, suspended, and deleted lifecycle vocabulary;
- manual management provenance;
- validated presentation names and non-authoritative normalized name keys;
- a monotonically positive target generation;
- Resource references pinned to Resource version and target generation;
- immutable, canonically ordered Resource Group membership; and
- domain-separated SHA-256 semantic hashes.

The domain rejects empty groups, duplicate Resources, cross-scope references,
invalid versions or generations, control characters, malformed UTF-8, and more
than 256 members before a transaction starts.

## PostgreSQL authority

Migration `000037_resource_group_authority.up.sql` adds:

| Relation | Role |
| --- | --- |
| `mesh.resource` | Stable Resource identity, scope, owner/custodian, lifecycle, provenance, semantic hash, revisions, and target generation. |
| `mesh.resource_device_target` | Typed Device target binding for one Resource generation. |
| `mesh.resource_group` | Stable Resource Group identity and active immutable definition version. |
| `mesh.resource_group_version` | Immutable semantic hash and member-count snapshot. |
| `mesh.resource_group_version_member` | Ordered Resource/version/target-generation membership snapshot. |

All child relationships use composite Workspace/Network foreign keys. The
active Resource Group version uses a deferred composite foreign key so the root
and first immutable version can be inserted in one transaction without a
nullable authority gap. All five relations have forced row-level security with
exact Workspace and Network checks.

The runtime role has no direct table privileges. It receives only narrow
`SECURITY DEFINER` functions for Device Resource creation, Resource Group
creation, and exact-scope resolution. Worker and observer roles cannot execute
those functions.

## Transaction protocol

`internal/resource/authority.Service` owns the unit of work. A creation attempt:

1. Allocates UUIDv7 aggregate, projection, audit, outbox, and change IDs once.
2. Captures one decision time for every retry.
3. Begins a bounded READ COMMITTED transaction and sets the exact public scope.
4. Revalidates the Account Session and `resource.manage` or
   `resource_group.manage` authorization under database locks.
5. Locks the Network revision and audit stream head.
6. Applies compare-and-swap against inventory or group revision.
7. For groups, locks members in deterministic internal-ID order and validates
   every Resource version and target generation.
8. Advances the Network and selected subsystem revision once.
9. Inserts authority rows, then appends the hash-chained audit event and durable
   outbox event under the same change ID and transaction ID.
10. Commits, or rolls the complete attempt back.

Serialization failures, deadlocks, and lock timeouts retry the complete
transaction with bounded jitter. An uncertain commit is resolved by the stable
aggregate ID and exact semantic evidence; the mutation is never replayed
blindly.

## Security properties

- Authorization uses a live deployment-bound Account Session and the existing
  Network permission resolver. Missing membership, binding, role, session,
  provider, recovery, or permission evidence returns a generic forbidden result.
- Scope is fixed from public Workspace and Network IDs before any authority
  query. Opaque IDs from another scope resolve as unavailable.
- Stale inventory, group, Resource version, or target-generation evidence fails
  closed as a conflict.
- Resource and Resource Group names never participate in authorization or
  identity.
- The creator is the only permitted initial owner and custodian in M1.
- Authority mutation triggers require one transaction-local UUIDv7 change ID.
  Deferred constraints reject commit unless audit and outbox evidence exists in
  that same database transaction.
- Event hashes cover the prior stream hash, stable IDs, actor, action,
  permission, semantic hash, and payload hashes.

## Compatibility and operations

Migration 37 is additive and forward-only. Runtime startup still never runs
migrations. The existing schema compatibility generation remains unchanged
because old binaries do not read or write the new tables and the new slice does
not alter an existing contract.

The outbox event class remains `network.revision.advanced`; payloads identify
the `inventory` or `group` subsystem revision. Redis is not involved in the
authority decision and remains non-authoritative.

## Explicit non-claims

This milestone is an engineering foundation, not a production or GA gate. It
does not qualify multi-node, multi-AZ, or multi-region availability; PostgreSQL
or Redis failover; Resource management API compatibility; Console UX; Access
Graph evaluation; connector ingestion; or policy enforcement derived from
Resource Groups.
