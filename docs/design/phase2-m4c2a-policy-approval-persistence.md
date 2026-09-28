# Phase 2 M4c2a policy approval persistence design

Status: implemented engineering persistence slice, pending management API and
publication integration.

Date: 2026-09-29

## Scope

M4c2a makes the M4c1 two-person policy-approval contract durable in
PostgreSQL. It adds retained request and decision evidence, application-owned
transaction adapters, exact-scope authorization, durable idempotency,
hash-chained audit/outbox evidence, commit-outcome replay, and bounded database
waits. PostgreSQL remains the only workflow authority; Redis and a graph
database are not introduced.

This slice deliberately stops before public or private management endpoints and
before policy publication consumes an approval. The separation keeps the
durable workflow authority independently reviewable before it becomes a
packet-policy gate.

## Durable model

Migration `000047_policy_approval_persistence.up.sql` adds two retained tables:

- `mesh.policy_approval_request` stores the exact Workspace/Network scope,
  proposer Principal and Account Session fences, all eight baseline and
  proposed authority dimensions, candidate semantic hash, compiler format,
  complete simulation impact hash, proposal request hash, reason, fixed quorum,
  state, version, and exclusive ten-minute expiry;
- `mesh.policy_approval_evidence` stores a distinct immutable Evidence ID,
  approver Principal and Account Session fences, request version, decision
  hash, reason, decision time, and inherited expiry.

Database constraints require the proposed vector to advance only Network and
Policy revision by one. Candidate, impact, request, and decision hashes are
non-zero SHA-256 values. The only request transitions are version-1 `pending`
to version-2 `approved`, followed by the reserved M4c2b version-3 `consumed`
transition. Approval evidence cannot be updated or deleted, and requests cannot
be deleted or have their immutable binding rewritten.

Both tables use forced row-level security and migrator-only policies. Runtime,
worker, observer, audit-writer, and share-writer roles receive no direct table
or sequence capability.

## Least-privilege operations

The runtime role can execute only five narrow security-definer operations:

1. create a pending request;
2. lock one exact-scope request;
3. load one request for immutable replay;
4. approve one locked request; and
5. load one approval Evidence record for immutable replay.

The creation and approval functions independently revalidate active,
deployment-bound Core Account Session fences. Approval additionally enforces
request CAS, pending state, exclusive expiry, unchanged candidate and impact
hashes, and distinct proposer/approver Principal and Account Session. Typed
SQLSTATE values preserve fail-closed domain errors without exposing unrelated
object existence.

## Transaction protocol

The proposal adapter performs one short read-write transaction:

1. configure statement, lock, and idle-in-transaction timeouts and set exact
   Network scope;
2. freshly resolve `policy.validate`;
3. lock the complete Network revision vector;
4. claim domain-separated idempotency evidence;
5. lock the Network audit stream;
6. insert the retained pending request;
7. append one hash-chained audit event and matching outbox event;
8. complete the idempotency record; and
9. commit.

The decision adapter follows the same boundary with fresh `policy.approve`,
then locks the pending request, advances it to `approved`, inserts immutable
approval evidence, appends audit/outbox evidence, completes idempotency, and
commits. All effects roll back together.

Completed idempotency claims reconstruct typed immutable results. Unknown
commit outcomes use separate read-only transactions and retry-stable mutation
identities. Rollback is idempotent after a commit attempt so cleanup cannot
mask commit uncertainty. Retryable serialization, deadlock, lock, and unique
conflicts remain typed for bounded whole-transaction retry.

## Observability and verification

The runtime PostgreSQL metric allowlist includes separate begin, resolve,
apply, commit, rollback, and replay operations for proposal and decision flows.
Unit tests assert exact SQL call order, permissions, immutable record
reconstruction, read-only replay, SQLSTATE mapping, and unknown-commit cleanup.
Migration catalog tests enforce required constraints and reject broad grants.

The integration-tag migration suite now also asserts, when a disposable
database is configured, that both tables have forced RLS, no application role
has direct DML access, only `mesh_runtime` can execute the five workflow
functions, and all retention/audit triggers are enabled.

## Security analysis

| Threat | M4c2a control |
| --- | --- |
| Spoofing | Active Core Account Session identity and authority generations are revalidated inside each mutation transaction. |
| Tampering | Scope, complete vectors, compiler format, candidate, impact, request/decision hash, CAS version, and expiry are constrained and transaction-bound. |
| Repudiation | Retained request/evidence rows plus hash-chained audit and atomic outbox evidence bind both human actions. |
| Information disclosure | Exact-scope functions, forced RLS, no direct table grants, and opaque forbidden mapping conceal unrelated authority. |
| Denial of service | Database waits, request lifetime, replay window, and application retry count are bounded. |
| Elevation of privilege | Proposal and decision use distinct permissions; self-approval, stale sessions, changed evidence, expired requests, and invalid state fail closed. |

## Non-claims and next order

M4c2a does not expose an approval management API, wire the approval service
into a runtime role, block existing policy publication, or consume approval
evidence. It does not qualify a deployed Console/API workflow, production
PostgreSQL failover, HA, SLOs, or GA.

M4c2b must integrate publication-time approval consumption. The publication
transaction must lock the approved request and Evidence row, freshly validate
the approver authority and complete eight-field vector, require the exact
candidate/impact/compiler binding, transition the request to `consumed`, and
commit that transition in the same transaction as Policy Release, audit, and
outbox effects. Management API/runtime composition can then expose proposal
and decision operations without weakening the atomic publication gate.
