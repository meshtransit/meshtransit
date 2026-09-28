# Phase 2 M3c protected Resource authority change design

Status: implemented engineering slice, pending production availability qualification.

Date: 2026-09-28

## Scope

M3c implements protected ownership transfer and custodian delegation for a
Device-backed Resource or immutable Resource Group. PostgreSQL remains the sole
authority. Redis remains request-admission infrastructure only; the workflow
requires neither sticky sessions nor a graph database.

Only one authority field changes per request:

- `owner_transfer` changes the owner and requires the proposed owner to confirm;
- `custodian_delegation` changes the custodian and requires the proposed
  custodian to confirm.

The current owner is the only proposer. The target must be a distinct active
Principal with a current Workspace membership. Version 1 fixes quorum at one
independent confirmation and expires an unconfirmed request after ten minutes.

## Bearer API

Each Resource and Resource Group exposes three explicit actions:

| Action | Purpose | Mutation headers |
| --- | --- | --- |
| `preview-authority-change` | Compute deterministic before/after evidence. | Strong aggregate `If-Match`; rejects `Idempotency-Key`. |
| `request-authority-change` | Persist the owner's protected proposal. | Strong aggregate `If-Match` and bounded `Idempotency-Key`. |
| `confirm-authority-change` | Confirm and atomically apply the pending request. | Strong request-version `If-Match` and bounded `Idempotency-Key`. |

The request and confirmation bodies carry the exact lowercase hexadecimal
`impact_hash` returned by preview. Mutation bodies also require a bounded audit
reason. Confirmation names the pending `change_request_id`; its `If-Match`
applies to the pending request, not the Resource or Resource Group version.

Resource operations require fresh `resource.transfer`; Resource Group
operations require fresh `resource_group.transfer`. The permissions are
privileged, exact-Network capabilities and are separate from ordinary
`resource.manage` and `resource_group.manage`. The private Console profile does
not admit these Bearer routes.

## Impact and authority invariants

The deterministic impact hash binds:

- exact Workspace/Network scope, subject kind, public ID and expected version;
- action and proposed target Principal;
- current and proposed owner/custodian identities;
- current and proposed semantic hashes;
- fixed confirmation quorum; and
- maximum step-up age.

For ownership transfer, custody is unchanged. For custodian delegation,
ownership is unchanged. Both aggregate transition guards enforce exactly one
authority-field change, unchanged lifecycle/target/group definition state, a
changed semantic hash, and monotonic aggregate and subsystem revisions.

Preview and every mutation re-resolve current authority from PostgreSQL.
Missing and cross-scope subjects or ineligible targets do not disclose unrelated
object existence. Request recomputes impact while locked and rejects a stale
acknowledgement. Confirmation locks the pending request and subject, verifies
that the current state still equals the acknowledged before-state, and rejects
changed impact before mutation.

## Step-up and independent confirmation

Both actors must present a valid Core Account Session whose authentication time
is strictly within five minutes of the database transaction time. The Session
ACR must exactly equal the Workspace provider routing row's non-null
`minimum_assurance`; a generic MFA label or client assertion is insufficient.

Step-up evidence is durable and immutable. Each Account Session may be consumed
only once by this workflow. Requester and confirmer must have distinct Account
Sessions and distinct Principals. The confirmer must be exactly the proposed
new owner or custodian. Self-confirmation and substitution by another privileged
administrator fail closed.

The pending request records exact before/after authority, target, subject
version, proposer Session, impact hash, quorum, state, and exclusive expiry.
The only permitted transition is `pending` version 1 to `applied` version 2 with
one confirmation before expiry. Requests and evidence cannot be deleted or
rewritten.

## PostgreSQL transaction protocol

Migration `000042_resource_authority_change_workflow.up.sql` adds the protected
permissions, retained request/evidence tables, forced RLS, mutation-capture
triggers, narrow preview/lock/apply functions, and least-privilege grants.
Runtime has function execution only and no direct table capability. Worker,
observer, audit-writer, and share-writer roles cannot run the workflow.

Proposal atomically performs:

1. exact scope and current owner/permission resolution;
2. durable idempotency claim;
3. Network, subsystem, subject, audit-stream and Account Session locking;
4. fresh single-use step-up validation and deterministic impact recomputation;
5. pending request plus requester evidence insertion;
6. Network/subsystem revision advancement, hash-chained audit and outbox append;
7. completed idempotency evidence; and
8. commit.

Confirmation atomically performs the corresponding idempotency claim, request
and subject locks, expiry/CAS/impact checks, distinct target-actor step-up
validation, authority mutation, request completion, revision advancement,
confirmer evidence, audit, outbox and idempotency completion.

All effects commit or roll back together. Identical replay returns the original
committed result. A reused key with different semantics conflicts. Unknown
commit outcomes are resolved from durable PostgreSQL evidence after fresh
authorization; no in-memory or Redis state decides the result.

## Error behavior

- Missing or malformed `If-Match` returns `428` or `400`; stale subject or
  request versions return `412`.
- Missing/cross-scope subjects and requests return the same `404` shape.
- Missing, stale, weak, or previously consumed step-up evidence returns `428`
  with `step_up_required`.
- An expired pending request returns `410`.
- Changed impact, ineligible target, state conflict, or idempotency conflict
  returns a typed `409`.
- Dependency or transaction uncertainty fails closed with retryable `503`;
  deadlines return `504`.

Database diagnostics, Account Session material, raw idempotency keys, internal
IDs, and unrelated object existence never enter the response.

## Residual limits and next order

This engineering slice does not claim production availability, HA, failover,
multi-replica load behavior, SLO attainment, or GA. It does not implement an
Access Graph or consume Resource Groups in packet-policy compilation.

Next order in the original Phase 2 roadmap:

1. M2 policy publication for TCP/UDP Resource and Resource Group destinations.
2. M4 Access Graph references, explanations, simulation, and verification.
3. M5 client projection from stable Resource authority.
