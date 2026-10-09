# Phase 2 M4c1 policy approval domain design

Status: implemented domain slice, pending persistence and API integration.

Date: 2026-09-29

## Scope

M4c1 defines the application-domain contract for a durable two-person policy
approval workflow. It does not add a PostgreSQL migration, management endpoint,
or publication gate. Those effects remain M4c2 work.

The domain is intentionally downstream of the M4b compiler-identical simulator:

1. a proposing human supplies typed policy intent plus the candidate semantic
   hash and full impact hash they reviewed;
2. the service runs the production simulator again with the proposer's Account
   Session;
3. the proposal transaction reauthorizes the proposer and compares the locked
   complete baseline vector with the simulated vector;
4. a different human acknowledges the unchanged candidate and impact hashes;
5. the approval transaction reauthorizes `policy.approve`, locks the pending
   request, and commits immutable approval evidence; and
6. M4c2 publication will lock and consume that evidence only if every bound
   fact remains unchanged.

PostgreSQL remains the future durable workflow authority. Redis and a graph
database are not part of the approval contract.

## Immutable binding

`approval.Binding` contains exactly the evidence needed for a future atomic
publication gate:

- exact Workspace-qualified Network scope;
- all eight baseline authority revisions;
- the proposed vector produced by advancing only Network and Policy revision
  once;
- candidate semantic hash;
- compiler format version; and
- complete, untruncated simulation impact hash.

The binding constructor rejects incomplete vectors, an advance in any other
subsystem, zero hashes, and unsupported compiler-format values. The impact hash
already commits to the full before/after relationship and explanation sets,
affected entities, active release evidence, Resource/Group provenance, and
explicit unsupported-capability list.

## Proposal boundary

`Service.Request` accepts an immutable compilation request and both hashes the
human reviewed. It calls the injected M4b simulator rather than implementing a
second evaluator. A result from another scope or revision, a changed candidate,
or a changed impact fails before durable IDs or a transaction are allocated.

After simulation, the service obtains a fresh decision time and requires the
proposer Account Session to remain active. The future transaction adapter must
resolve fresh exact-scope proposal permission and lock the complete baseline
vector. Drift between simulation and the locked resolution returns no pending
request.

A successful request is version 1, state `pending`, and expires exactly ten
minutes after its stable proposal time. Creating workflow evidence must not
advance any Access Graph authority revision; otherwise the request would make
its own baseline stale.

## Independent approval boundary

`Service.Approve` consumes a strong request-version precondition plus the exact
candidate and impact hashes. The future transaction adapter must freshly
authorize `policy.approve`, claim idempotency, and lock the request before
returning its resolution.

Both Principal and Account Session must differ from the proposer. Account
Sessions are Core-owned authenticated human sessions, so a service identity or
caller-supplied identity string cannot satisfy this boundary. The decision must
occur strictly before the request expiry. Approval does not extend the expiry.

A successful decision advances the request to version 2 and produces a
separate version-1 immutable approval Evidence ID. This distinction lets
publication name and consume the exact human decision rather than treating a
mutable request row as sufficient evidence.

## Retry and idempotency

Proposal and approval operations allocate all public identities once before
the first transaction attempt. Decision time, expiry, request/decision hash,
and secret-safe idempotency proof remain stable across bounded whole-transaction
retries.

The service owns commit and rollback. A failed attempt rolls back with a short
cleanup context detached from caller cancellation. Unknown commit outcomes are
resolved by immutable mutation identities; replayed results must match the
original command exactly. Retry exhaustion and rollback failure remain explicit
error classes.

The two domain-separated SHA-256 request hashes include scope, vectors,
candidate and impact hashes, compiler format, Account Session identity and
authority generations, request version where applicable, and the normalized
human reason. Raw idempotency keys never enter the domain.

## Security analysis

| Threat | M4c1 control |
| --- | --- |
| Spoofing | Only validated Core Account Sessions represent proposer and approver. |
| Tampering | Candidate hash, full impact hash, complete vectors, scope, compiler format, and session fences are hash-bound. |
| Repudiation | Retry-stable change, audit, outbox, request, and approval Evidence IDs are mandatory transaction inputs. |
| Information disclosure | Domain errors do not expose object existence or permission-resolution detail. |
| Denial of service | Existing compilation limits apply; retries are capped at five and the request lifetime is bounded. |
| Elevation of privilege | Fresh transaction authorization is required, self-approval fails closed, and no approval can survive authority-vector drift. |

## Non-claims and next order

M4c1 does not claim durable approval, an exposed workflow, audit/outbox writes,
or enforced human approval before publication. Existing publication behavior is
unchanged until M4c2 lands.

M4c2 must add, as one integrated persistence/API slice:

1. forward-only approval request and immutable decision tables with exact-scope
   RLS and least-privileged security-definer operations;
2. fresh `policy.validate`/`policy.approve` authorization, idempotency, audit,
   and outbox evidence;
3. proposal and approval management endpoints with strong preconditions and
   private-browser protection; and
4. publication-time locking, complete-vector CAS, fresh approval validation,
   and single-use approval consumption in the same transaction as the Policy
   Release, audit event, and outbox event.
