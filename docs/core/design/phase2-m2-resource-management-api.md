# Phase 2 M2 Resource management API design

Status: implemented engineering slice, pending production availability qualification.

Date: 2026-09-28

## Purpose

Phase 2 M2 exposes the M1 PostgreSQL Resource authority through a versioned,
Bearer-authenticated management contract. PostgreSQL remains the only authority;
Redis is used for request admission only and no graph database is introduced.

This slice adds create, get, and deterministic list operations for Device-backed
Resources and immutable Resource Groups. Lifecycle mutation is implemented by
the subsequent M3a slice; target rebinding, group replacement, ownership
transfer, Access Graph evaluation, policy compilation from groups, connector
ingestion, sharing, and Console UI remain outside M2.

## Public contract

The Bearer management listener exposes:

| Method | Path | Permission |
| --- | --- | --- |
| `POST` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources` | `resource.manage` |
| `GET` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources` | `resource.read` |
| `GET` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}` | `resource.read` |
| `POST` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups` | `resource_group.manage` |
| `GET` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups` | `resource_group.read` |
| `GET` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups/{resource_group_id}` | `resource_group.read` |

Create requests require a strong quoted collection revision in `If-Match`, one
`Idempotency-Key`, strict JSON, a bounded audit reason, and an authenticated
Account Session. The authenticated Principal is the initial owner and custodian.
Success returns `201`, `Location`, an object ETag, a safe correlation ID, and the
committed Network plus inventory/group revision.

Detail reads return an object ETag. Lists accept only `state`, `page_size`, and
`page_token`; page size is 1 through 100 and defaults to 50. Items are ordered by
UUIDv7 public ID. The opaque token binds collection kind, state filter, locked
collection revision, and last public ID. A changed collection revision returns a
conflict instead of mixing snapshots.

The private Console document deliberately retains only the existing Device
revoke and Policy publish mutations. Adding the Bearer API does not admit a new
browser route or UI capability.

## Idempotent creation protocol

The API boundary HMAC-digests the raw idempotency key and discards the raw value.
The application request hash binds operation, exact scope, Account Session,
Principal, audit reason, aggregate semantic hash, and expected collection
revision. The PostgreSQL transaction:

1. revalidates the live Account Session and exact permission;
2. claims the `(principal, operation, key generation, key digest)` record;
3. rejects a reused key with different request semantics;
4. locks collection revision and audit stream state;
5. applies the M1 compare-and-swap mutation;
6. appends audit and outbox evidence; and
7. completes the idempotency record with the committed aggregate ID, versions,
   semantic hash, and outbox identity before commit.

An identical retry returns the original committed aggregate ID without applying
the mutation again. An uncertain commit is resolved through the same durable
idempotency evidence after fresh authorization. The replay window is bounded to
one hour in the production composition.

## Authorized read protocol

`internal/resource/catalog.Service` owns each short `REPEATABLE READ`
transaction. Every get or list operation sets exact Workspace and Network scope,
revalidates the live Account Session with `resource.read` or
`resource_group.read`, and only then invokes a narrow `SECURITY DEFINER`
function. Revision and page rows therefore come from one stable snapshot without
taking the mutation revision lock. The transaction permits the authorization
reader's row locks, but the runtime role still has no direct table-write grant.

Migration 38 adds one revision reader and four catalog read functions. Runtime
receives `EXECUTE` only; it has no direct table privileges. Worker and observer
roles cannot execute them. Detail functions constrain opaque IDs by the
transaction-local scope, so an ID from another Network is indistinguishable
from a missing ID. List functions return a bounded JSON aggregate in one query,
preventing N+1 behavior while preserving deterministic ordering.

## Error and availability behavior

- Missing or invalid authentication returns `401`; current permission denial
  returns `403`.
- Cross-scope and absent detail IDs return the same `404` shape.
- Stale create preconditions return `412`; missing preconditions return `428`.
- Idempotency intent reuse, expired replay evidence, and changed pagination
  snapshots return `409`.
- PostgreSQL, Redis request admission, retry exhaustion, or uncertain unresolved
  outcomes fail closed with retryable `503`; request deadlines return `504`.
- Responses never include database diagnostics, raw session tokens, raw
  idempotency keys, or rate-limit subjects.

## STRIDE review

| Threat | Control |
| --- | --- |
| Spoofing | Opaque Account Session authentication is deployment-bound and revalidated inside every authority transaction. |
| Tampering | Strong revision compare-and-swap, canonical semantic hashes, immutable group versions, hash-chained audit, and same-transaction outbox/idempotency completion. |
| Repudiation | Audit evidence binds actor, Account Session, role/binding generations, reason, permission, correlation ID, aggregate version, and semantic hash. |
| Information disclosure | Exact scope is transaction-local; cross-scope IDs return `404`; safe error envelopes and HMAC-derived request evidence avoid secret disclosure. |
| Denial of service | Source/session distributed rate limits, process concurrency bounds, request/body/page limits, statement/lock/idle timeouts, and bounded retries. |
| Elevation of privilege | Fresh exact permission resolution, creator-only initial ownership, no direct runtime table access, and no browser admission for the new routes. |

Residual uncertainty remains around production PostgreSQL/Redis failover,
multi-replica load behavior, operational SLOs, and future lifecycle/ownership
workflows. Those are separate qualification gates, not implicit claims of M2.

## Compatibility and next order

Migration 38 is additive and forward-only. Existing M1 tables and functions are
unchanged. Runtime startup still never applies migrations. The Bearer OpenAPI
document grows from two to six paths; the separately composed private Console
document remains four paths including session prepare and logout.

Next order:

1. M3a: Resource and Resource Group lifecycle actions (implemented after this
   design record).
2. M3b/M3c: target rebinding, immutable Resource Group replacement, and protected
   ownership/custodianship workflows.
3. M4: Access Graph references, explanations, simulation, and verification.
4. M5: policy compilation and client projection from stable Resource authority.
5. Later gates: connector ingestion, sharing/export, Console UX, and separate
   production availability qualification.
