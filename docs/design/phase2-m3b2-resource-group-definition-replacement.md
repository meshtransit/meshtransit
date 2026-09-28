# Phase 2 M3b2 Resource Group definition replacement design

Status: implemented engineering slice, pending production availability qualification.

Date: 2026-09-28

## Scope

M3b2 replaces the active definition of one Resource Group by appending a new
immutable version. PostgreSQL remains the sole authority. Existing definitions
and member rows are retained; no membership row is updated or deleted. Redis
remains request-admission infrastructure only, and this slice introduces no
graph database or Access Graph evaluator.

This slice completes the immutable Resource Group replacement deferred by M3b1.
Ownership transfer and custodian delegation remain M3c protected workflows.

## Bearer API

The public management listener exposes two exact-Network actions guarded by
`resource_group.manage`:

| Method | Path |
| --- | --- |
| `POST` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups/{resource_group_id}/actions/preview-replace` |
| `POST` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups/{resource_group_id}/actions/replace` |

Preview requires a strong quoted Resource Group aggregate-version `If-Match`.
Its strict JSON body contains only a non-empty, bounded `members` array. Every
member explicitly pins `resource_id`, `resource_version`, and
`target_generation`. Preview rejects an idempotency key.

Apply requires the same `If-Match` and exact member set, a bounded
`Idempotency-Key`, the lowercase hexadecimal preview `impact_hash`, and a
bounded audit reason. Both operations perform fresh Account Session and RBAC
evaluation. The private Console profile does not admit these Bearer routes.

The management body limit is 64 KiB, which admits the documented maximum of 256
version-pinned members while remaining explicitly bounded.

## Immutable definition and impact contract

Resource Group identity, display name, owner, and custodian remain unchanged.
The proposed definition version must be exactly the current version plus one.
Members are canonicalized by Resource public ID; duplicates, cross-scope
references, inactive Resources, stale Resource versions, and stale target
generations are rejected. A semantically unchanged definition is rejected.

Preview returns:

- current and proposed definition versions;
- complete current and proposed version-pinned members;
- exact added, removed, and retained pinned references;
- `approval_required`; and
- a deterministic `impact_hash`.

A changed pin for the same Resource is represented as removal of the old exact
reference and addition of the new exact reference. The impact hash binds exact
scope, Resource Group identity and expected aggregate version, immutable group
metadata, current/proposed definition versions and semantic hashes, both full
canonical membership sets, and the approval decision.

Apply recomputes the impact under database locks and accepts only the exact
acknowledged hash. This prevents a preview for one member version or target
generation from authorizing another.

The current authority schema has no policy, route, sharing, or Access Graph
consumer of Resource Groups. The scanner therefore reports
`approval_required=false` within that schema boundary. A future protected
consumer must extend the impact scan and hash, set `approval_required=true`, and
provide durable approval evidence. Apply already fails closed whenever approval
is required; it never fabricates approval.

## Transaction protocol

One application-owned transaction performs:

1. exact Workspace/Network scoping and fresh `resource_group.manage` evaluation;
2. durable request-hash/idempotency claim;
3. Network revision and audit-stream locking;
4. Resource Group and proposed Resource member locking;
5. current-definition reconstruction and impact recomputation;
6. insertion of the next immutable group-version row and immutable member rows;
7. active-definition pointer, semantic hash, aggregate version, Network
   revision, and group revision advancement;
8. hash-chained audit and durable revision outbox append; and
9. idempotency completion with committed result evidence.

All effects commit or roll back together. Aggregate and definition versions each
advance by exactly one. Unknown commit outcomes are resolved through durable
idempotency evidence after fresh authorization. Identical replay returns the
original result without appending another definition.

Migration 41 extends the authority transition guard only for this exact
same-state, next-definition replacement. Lifecycle transitions cannot change
definition semantics, and replacement cannot change lifecycle state. Immutable
version/member rows still reject update and delete.

Runtime receives `EXECUTE` only on narrow preview, lock, and apply functions.
The shared internal impact function is not executable by runtime. Worker,
observer, audit-writer, and share-writer roles cannot execute the replacement
functions, and runtime receives no direct Resource table grant.

## Error behavior

- Missing or malformed `If-Match` returns `428` or `400`.
- Stale Resource Group aggregate version returns `412`.
- Missing or cross-scope Resource Group identity returns the same `404` shape.
- Stale, inactive, missing, or cross-scope member pins return `409`.
- Deleted group state, unchanged semantics, changed impact, or required approval
  without evidence returns a typed `409`.
- Idempotency intent conflict returns `409`.
- Dependency/retry uncertainty fails closed with retryable `503`; deadlines
  return `504`.

Database diagnostics, raw credentials, raw idempotency keys, internal IDs, and
unrelated object existence never enter the response.

## Residual limits and next order

This engineering slice does not claim production availability, HA, failover,
multi-replica load behavior, SLO attainment, or GA. It does not re-open
PostgreSQL/Redis failover, require sticky sessions, consume Resource Groups in
policy/routing/sharing, or implement an Access Graph.

Next order:

1. M3c: protected ownership transfer and custodian delegation with step-up and
   second-actor/quorum enforcement.
2. M4: Access Graph references, explanations, simulation, and verification.
3. M5: policy compilation and client projection from stable Resource authority.
