# Phase 2 M4c2b policy approval publication gate design

Status: implemented engineering publication gate, pending approval-management
API and deployed workflow qualification.

Date: 2026-09-29

## Scope

M4c2b closes the packet-policy activation gap left by M4c2a. Every production
management publication must now identify one approved, immutable Evidence
record. Publication locks that Evidence and its retained request, freshly
revalidates the independent approver, compares the complete Access Graph
authority vector, creates the Policy Release, and consumes the approval in one
PostgreSQL transaction.

PostgreSQL remains the sole workflow and publication authority. Redis is still
only a revision-wakeup transport, and no graph database or second evaluator is
introduced.

## Management contract

The existing publish request requires `approval_evidence_id`, a canonical
UUIDv7. The HTTP adapter compiles the submitted rules using the authenticated
publisher Session and constructs only an approved management command. Missing
or malformed Evidence IDs fail as invalid requests before publication starts.

Stale, expired, consumed, cross-scope, changed, or no-longer-authorized
Evidence is deliberately collapsed to HTTP `409 approval_conflict`. The
response does not disclose whether a referenced request, Session, role, or
Evidence record exists.

The proposal and approval-decision HTTP operations are intentionally not part
of this slice. Until those operations are composed, the production publish
path is fail-closed rather than silently bypassing approval.

## Typed publication boundary

The publication domain now carries:

- a validated approval Evidence ID on management commands;
- all eight authority dimensions: Network, Inventory, Group, Policy, DNS,
  Route, Sharing, and Isolation;
- the retained request and Evidence versions;
- candidate semantic hash, compiler format, complete simulation impact hash,
  decision time, and exclusive expiry; and
- the exact baseline and proposed vectors, where only Network and Policy
  advance by one.

`NewApprovedManagementCommand` makes the required management path explicit.
Malformed non-zero Evidence and gate values are rejected rather than treated
as absent. The application service rechecks scope, Evidence identity,
candidate/compiler binding, baseline-vector equality, decision time, and
expiry before constructing a publication change.

## Explicit composition modes

`PolicyPublicationApprovalMode` has no valid zero/default behavior:

1. `Required` enforces durable single-use approval and is selected by both
   production management compositions;
2. `QualificationBypass` preserves only explicitly identified offline legacy
   and trusted-actor qualification paths.

Unknown mode values make store construction fail. A bypass-composed store
still enforces the gate whenever a command carries Evidence, preventing a
caller from downgrading an approved request after command construction.

## Atomic transaction protocol

The management publication transaction uses this lock and validation order:

1. freshly authorize the publisher for `policy.publish`;
2. lock the complete current Network authority vector;
3. lock the active Policy Release;
4. lock the exact approved request for update and immutable Evidence plus
   approver Session authority for share;
5. freshly resolve the retained approver Session for exact-scope
   `policy.approve`;
6. lock the Network audit stream;
7. insert the new release and its compiled projections while superseding the
   prior release;
8. verify the post-publication vector, active release, candidate, compiler,
   and impact binding, then transition the request from approved version 2 to
   consumed version 3;
9. append publication audit/outbox evidence; and
10. commit every effect together.

Any error rolls back release activation, approval consumption, audit, and
outbox effects. The consumption row retains the exact release foreign key and
policy revision. Reuse cannot publish another release.

## Database capability boundary

Migration `000048_policy_approval_publication_gate.up.sql` adds two narrow
`SECURITY DEFINER` functions:

- `lock_policy_approval_for_publication_v1` returns only exact-scope,
  unexpired, approved Evidence and the fenced approver identity needed for
  fresh authorization;
- `consume_policy_approval_for_publication_v1` rechecks request state,
  candidate, compiler, impact, complete proposed vector, and active release
  before the single lifecycle transition.

Both functions use fixed search paths, revoke `PUBLIC` and every application
role, and grant execute only to `mesh_runtime`. Application roles retain no
direct approval-table access.

## Audit, replay, and observability

The existing `policy.published` audit event now includes request and Evidence
IDs, the complete impact hash, both complete vectors, and fresh approver
authorization evidence in addition to publisher authorization. Payloads remain
bounded and hash-chained.

Unknown publication commit outcomes resolve through the immutable release ID.
Replay lookup joins the consumed approval and accepts the result only when the
exact Evidence ID matches the command. A release created without Evidence in
an explicit qualification path cannot be replayed as an approved management
publication.

Existing bounded PostgreSQL transaction metrics cover the additional lock and
consume operations without introducing unbounded labels.

## Security analysis

| Threat | M4c2b control |
| --- | --- |
| Spoofing | Publisher and retained approver Account Sessions are freshly revalidated inside the publication transaction. |
| Tampering | Exact scope, candidate, compiler, impact, request/Evidence versions, and all eight authority dimensions are transaction-bound. |
| Repudiation | The consumed request references the exact release; publication audit evidence records both human authorization paths. |
| Information disclosure | Opaque unavailable errors, exact-scope functions, forced RLS, and no direct table grants conceal unrelated approval state. |
| Denial of service | Statement, lock, idle, retry, rollback, request-lifetime, body-size, and rule-count bounds remain enforced. |
| Elevation of privilege | Publisher and approver permissions are resolved independently; self-approval, stale authority, expiry, and Evidence reuse fail closed. |

## Non-claims and next order

M4c2b does not add proposal/list/get/approve management endpoints, Console UI,
approval notifications, configurable quorum, sensitivity classes, graph
storage, or a second policy evaluator. It does not qualify production
PostgreSQL failover, multi-replica workflow behavior, SLOs, legal approval, or
GA.

M4c2c should expose the existing proposal and independent-decision services
through versioned management and private-browser contracts, compose their
runtime dependencies, and qualify the end-user workflow without weakening the
M4c2b atomic publication gate.

Local acceptance evidence is recorded in
`docs/qualification/phase2-m4c2b-policy-approval-publication-gate-2026-09-29.md`.
