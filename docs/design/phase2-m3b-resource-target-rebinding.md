# Phase 2 M3b Resource target rebinding design

Status: implemented engineering slice, pending production availability qualification.

Date: 2026-09-28

## Scope

This M3b slice replaces the active Device target of one Device-backed Resource
without changing the stable Resource identity. PostgreSQL remains the sole
authority. Redis remains request-admission infrastructure only; no graph
database or Access Graph evaluator is introduced.

M3b is split deliberately. This slice implements Device target rebinding with a
deterministic impact preview and exact acknowledgement. Immutable Resource Group
replacement remains the next M3b slice and will reuse the same impact boundary.
Ownership transfer and custodian delegation remain M3c protected workflows.

## Bearer API

The public management listener exposes two exact-Network actions:

| Method | Path | Permission |
| --- | --- | --- |
| `POST` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}/actions/preview-rebind` | `resource.manage` |
| `POST` | `/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}/actions/rebind` | `resource.manage` |

Preview requires a strong quoted Resource-version `If-Match` and strict JSON
containing only `device_id`. It performs fresh authorization and returns the
current and proposed Device IDs, current and proposed target generations, a
sorted list of affected non-deleted Resource Groups, `approval_required`, and a
deterministic `impact_hash`. Preview is read-only and rejects an idempotency key.

Apply requires the same `If-Match`, a bounded `Idempotency-Key`, and strict JSON
containing `device_id`, the exact lowercase hexadecimal `impact_hash`, and a
bounded audit reason. The Resource must not be deleted, and the target Device
must still be active in the same Network. The proposed Device cannot already
have an active Resource binding.

Impact disclosure is bounded to 256 active groups. A larger impact returns
`422`; it is never truncated into an apparently complete preview. The private
Console profile does not admit either Bearer route.

## Impact and approval boundary

The impact hash binds:

- exact Workspace, Network, and Resource identity;
- expected Resource version;
- current and proposed Device identity;
- current and proposed target generation;
- before and proposed semantic hashes;
- the canonical sorted set of affected Resource Group IDs; and
- the approval-required decision.

Apply recomputes the impact under database locks and rejects a changed hash.
This prevents acknowledgement of one consequence set from authorizing another.

The current schema has no policy, route, sharing, or Access Graph consumer of a
Resource target. Consequently, the implemented scanner reports
`approval_required=false` after enumerating current non-deleted Resource Group definitions
that pin the old target generation. This is a schema-bounded decision, not a
general statement that rebinding is low risk. A future protected consumer must
extend the scanner and hash, set `approval_required=true`, and supply durable
approval evidence before apply. The mutation path already fails closed whenever
approval is required; it does not infer or bypass approval.

## Transaction protocol

One application-owned transaction performs:

1. exact Workspace/Network scoping and fresh Account Session authorization;
2. durable request-hash/idempotency claim;
3. Network revision and audit-stream locking;
4. Resource, current target, and proposed Device locking;
5. impact recomputation and exact hash acknowledgement;
6. old-target transition from `active` to retained `superseded`;
7. insertion of the next active target generation and Resource semantic/version
   update;
8. Network and inventory revision advancement;
9. hash-chained audit plus durable revision outbox append; and
10. idempotency completion with the committed result.

All effects commit or roll back together. Resource version and target generation
each advance by exactly one. Unknown commit outcomes are resolved from durable
idempotency evidence after fresh authorization. Identical replay returns the
original result without another target replacement.

Existing Resource Group versions remain immutable and keep their pinned
Resource version and target generation. Rebind reports those groups as impact;
it does not silently rewrite their meaning. Updating group membership therefore
requires the subsequent immutable Resource Group replacement workflow.

Migration 40 narrows the transition guard to allow only the exact retained
target replacement described above and adds one `SECURITY DEFINER` rebind
function. Runtime receives `EXECUTE` only. Worker, observer, audit-writer, and
share-writer roles cannot execute it, and runtime receives no direct Resource
table write grant.

## Error behavior

- Missing or malformed `If-Match` returns `428` or `400`.
- Stale Resource version returns `412`.
- Missing or cross-scope Resource/Device identity returns the same `404` shape.
- An unchanged or already-bound target, an inactive Device, or a deleted
  Resource returns `409`.
- Changed impact acknowledgement returns `409` with `impact_changed`.
- Required approval without durable evidence returns `409` with
  `approval_required`.
- More than 256 affected groups returns `422`.
- Idempotency intent conflict returns `409`.
- Dependency/retry uncertainty fails closed with retryable `503`; deadlines
  return `504`.

Database diagnostics, raw credentials, raw idempotency keys, internal IDs, and
unrelated object existence never enter the response.

## Security and residual limits

Fresh permission evaluation prevents revoked authority from surviving between
preview and apply. Strong Resource CAS prevents lost updates. Exact-scope SQL
and identical hidden-target responses prevent cross-Network enumeration. Audit
evidence binds actor/session/RBAC generations, reason, before and after semantic
hashes, impact hash, affected groups, target identity, and revisions.

This slice does not claim production availability, HA, failover,
multi-replica load behavior, SLO attainment, or GA. It does not re-open
PostgreSQL/Redis failover, change sticky-session behavior, consume Resources in
policy/routing/sharing, or implement an Access Graph.

## Next order

1. M3b2: immutable Resource Group replacement using versioned definitions,
   impact preview, exact acknowledgement, and durable approval when required.
2. M3c: protected ownership transfer and custodian delegation with step-up and
   second-actor/quorum enforcement.
3. M4: Access Graph references, explanations, simulation, and verification.
4. M5: policy compilation and client projection from stable Resource authority.
