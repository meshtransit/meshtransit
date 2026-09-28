# Phase 2 M3a Resource lifecycle API design

Status: implemented engineering slice, pending production availability qualification.

Date: 2026-09-28

## Scope

M3a adds explicit `suspend`, `resume`, and terminal `delete` actions for
Device-backed Resources and Resource Groups. PostgreSQL remains the sole
authority. Redis remains request-admission infrastructure only; no graph
database or Access Graph evaluator is introduced.

M3 is intentionally split. Device Resource target rebinding is implemented by
the subsequent M3b slice; immutable Resource Group replacement remains M3b2.
Ownership transfer and custodian delegation remain M3c because those workflows
require approved step-up/quorum semantics rather than a plain CRUD update.

## Bearer API

The public management listener exposes these action templates:

| Method | Path | Permission |
| --- | --- | --- |
| `POST` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}/actions/{suspend,resume,delete}` | `resource.manage` |
| `POST` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups/{resource_group_id}/actions/{suspend,resume,delete}` | `resource_group.manage` |

Every action requires a strong quoted aggregate-version `If-Match`, one bounded
`Idempotency-Key`, strict JSON containing only a bounded `reason`, and an active
Bearer Account Session. Success returns `200`, the new aggregate ETag, target
state and version, Network revision, and inventory or group revision.

The allowed state machine is:

- `active -> suspended` or `active -> deleted`;
- `suspended -> active` or `suspended -> deleted`;
- `deleted` is retained and terminal.

Delete is a logical authority transition. No Resource, target binding, Resource
Group version, membership, audit, outbox, or idempotency row is physically
deleted. Resource identity and semantic hash remain stable across lifecycle
changes.

The private Console profile does not admit these Bearer routes. It continues to
contain only Device revoke, Policy publish, session preparation, and logout.

## Transaction protocol

One application-owned transaction performs:

1. exact Workspace/Network scoping;
2. fresh Account Session and permission resolution;
3. durable idempotency claim using a request hash bound to operation, scope,
   aggregate ID, expected version, session, principal, and reason;
4. Network revision and audit-stream locking;
5. aggregate existence, state, and version validation;
6. state/version plus Network and subsystem revision advancement;
7. hash-chained audit and durable revision outbox append; and
8. idempotency completion with the committed result.

All eight effects commit or roll back together. Retry replays the whole
transaction with stable IDs and decision time. Unknown commit outcomes are
resolved from durable idempotency evidence after fresh authorization. Identical
replay returns the original result without a second state change.

Migration 39 replaces the Resource transition guard with a lifecycle-only
update rule and adds two narrow `SECURITY DEFINER` transition functions. Runtime
has `EXECUTE` only. Worker, observer, audit-writer, and share-writer roles cannot
execute the functions, and runtime receives no direct table grant.

## Error behavior

- Missing or malformed `If-Match` returns `428` or `400` respectively.
- A stale aggregate version returns `412`.
- An invalid source-to-target transition returns `409`.
- Idempotency intent reuse or expired replay evidence returns `409`.
- Absent and cross-scope aggregate IDs share the same `404` response.
- Current permission denial returns `403`; authentication failure returns `401`.
- Dependency/retry uncertainty fails closed with retryable `503`; deadlines
  return `504`.

Database diagnostics, raw credentials, raw idempotency keys, internal IDs, and
unrelated object existence never enter the response.

## Security and residual limits

Fresh authorization generations prevent a previously authenticated request from
bypassing revoked membership or RBAC. Strong object CAS prevents lost updates.
Exact transaction scope and identical hidden-target errors prevent cross-Network
enumeration. Audit evidence binds actor, session, role/binding generations,
reason, action, object version, semantic hash, and revision.

This slice does not claim production availability, HA, failover, multi-replica
load behavior, or SLO attainment. It does not re-open PostgreSQL/Redis failover
work, change sticky-session behavior, consume groups in policy, or implement an
Access Graph.

## Next order

1. M3b1: Resource target rebinding with deterministic impact analysis and an
   approval fail-closed boundary (implemented after this design record).
2. M3b2: immutable Resource Group replacement using the same impact boundary.
3. M3c: protected ownership transfer and custodian delegation with step-up and
   second-actor/quorum enforcement.
4. M4: Access Graph references, explanations, simulation, and verification.
5. M5: policy compilation and client projection from stable Resource authority.
