# Phase 2 M4c2c policy approval management API design

Status: implemented engineering management API and locally qualified workflow;
deployed Console workflow qualification remains pending.

Date: 2026-09-29

Follow-up: M4c2d later admits the same catalog list/get operations through the
private Console profile; see
`phase2-m4c2d-private-console-policy-approval-catalog.md`. The boundary below
records the M4c2c candidate as qualified at that time.

## Scope

M4c2c exposes the retained M4c2a two-person approval workflow through the
versioned management API and composes it into both production management
graphs. It completes the operator-facing path needed by the M4c2b publication
gate without introducing another workflow authority or policy evaluator.

PostgreSQL remains the only approval and publication authority. Redis remains
revision-wakeup transport. No graph database is required: Access Graph
explanation and simulation continue to use bounded projections from the
authoritative relational model.

## Management contract

The API adds four exact-Network operations:

| Operation | Method and path | Authority and precondition |
| --- | --- | --- |
| Propose | `POST /api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/approval-requests` | Authenticated proposer, fresh `policy.validate`, current policy `If-Match`, `Idempotency-Key`, exact candidate and impact hashes |
| List | `GET /api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/approval-requests` | Fresh exact-scope `policy.approve`; optional state filter and bounded keyset pagination |
| Get | `GET /api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/approval-requests/{approval_request_id}` | Fresh exact-scope `policy.approve` |
| Approve | `POST /api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/approval-requests/{approval_request_id}/actions/approve` | Independent authenticated approver, fresh `policy.approve`, request-version `If-Match`, `Idempotency-Key`, exact candidate and impact hashes |

Proposal re-runs the compiler-identical simulation inside the approval service.
The caller must acknowledge both the candidate semantic hash and full impact
hash returned by simulation. The retained binding contains all eight authority
dimensions and only Network and Policy may advance by one.

Approval reloads and locks the request, rejects self-approval at both Principal
and Account Session boundaries, and re-simulates the unchanged intent before
creating immutable Evidence. Candidate, impact, version, state, and exclusive
expiry conflicts are deliberately collapsed to `409 approval_conflict`.

Proposal returns `201`, a strong request-version ETag, and a canonical Location
on the Bearer API. Approval returns `200` and the new version-2 ETag. The private
browser profile returns the created identifier in JSON but strips `Location`,
preserving its no-navigation response boundary.

## Catalog projection

List and get expose only retained workflow evidence needed by an approver:

- request identity, state, version, scope-bound candidate and impact binding;
- proposer Principal, proposal reason, and lifecycle timestamps;
- immutable approver Principal, reason, Evidence ID/version, and decision time;
- consumed Policy Release ID/revision and consumption time when present.

Account Session identifiers are intentionally omitted. Every response is
`Cache-Control: no-store`; get responses carry a strong request-version ETag.
Missing and cross-scope requests both become `404 not_found` after fresh
authorization, while dependency failures remain opaque and retryable.

List accepts `pending`, `approved`, or `consumed`, with page sizes from 1 to
100. Its opaque token binds the state filter and last UUIDv7 request identity.
The service requests one extra record, validates strict ordering and scope, and
emits a continuation token only when another page exists.

## Browser boundary

The private-browser OpenAPI profile exposes only the two mutations. Both use
the existing host-only Account Session cookie, exact Origin, explicit session
intent header, prepared CSRF proof, bounded body, shared rate limits, and
late-session revalidation. List and get remain Bearer-only and are not exposed
through cookie transport.

The browser wrapper buffers the entire candidate response until authority work
and session freshness have completed. It removes Bearer challenges and
navigation headers, never renews the Account Session cookie, and preserves the
same JSON status/error contract as the management handler.

## Runtime composition

The API composition constructs one PostgreSQL approval store, the M4c1
proposal/decision service, and the catalog service after the compiler-identical
simulator. Both the ordinary management graph and identity-owned private graph
receive the same workflow dependencies. Startup completeness rejects partial
composition rather than leaving a route with a nil authority port.

The workflow keeps bounded statement, lock, idle, retry, rollback, request,
idempotency, and concurrency windows. Metrics use a finite operation allowlist
for catalog read and list; identifiers and filter values never become labels.

## Database capability boundary

Migration `000049_policy_approval_management_read.up.sql` adds three fixed
search-path `SECURITY DEFINER` functions:

- a private payload helper for one exact-scope request;
- a public-to-runtime get entry point; and
- a public-to-runtime bounded keyset-list entry point.

`PUBLIC` and every application role are revoked from the helper. Only
`mesh_runtime` may execute the two entry points. No direct approval-table
privilege, default-privilege change, RLS bypass, or write function is added.
Two scope-prefixed UUIDv7 cursor indexes bound unfiltered and state-filtered
retained-history pagination without changing table authority.

Fresh permission resolution takes share locks on mutable RBAC rows. Therefore
the catalog owns a short PostgreSQL transaction that is not marked read-only,
even though the catalog itself performs no mutation. This is required for the
same locked authorization semantics used by protected mutations; its database
capability remains constrained by the runtime role and narrow functions.

## Security analysis

| Threat | M4c2c control |
| --- | --- |
| Spoofing | Bearer or private-browser Account Sessions are freshly authenticated; private mutations require an exact CSRF proof. |
| Tampering | Strong version preconditions, idempotency proofs, compiler-identical re-simulation, and exact candidate/impact hashes bind both mutations. |
| Repudiation | Existing retained request, immutable Evidence, audit, outbox, proposer, and approver records remain the durable evidence chain. |
| Information disclosure | Exact-scope functions, fresh `policy.approve`, opaque absent/error mapping, no Session IDs, `no-store`, and no cookie-authenticated reads bound disclosure. |
| Denial of service | Body, rule, page, token, timeout, lock, retry, rate, and concurrency limits remain finite. |
| Elevation of privilege | Proposal and decision permissions are distinct; approval requires a different Principal and Session; runtime receives no table access. |

## Non-claims and next order

M4c2c does not add a Console UI, notification delivery, configurable quorum,
approval-policy administration, sensitivity classes, legal signing, graph
storage, or a second evaluator. It does not qualify production PostgreSQL
failover, multi-replica approval behavior, production SLOs, legal approval,
release, or GA.

The approval domain, persistence, publication gate, and management API are now
connected as one local engineering workflow. A subsequent product slice should
integrate the Console/operator experience and qualify that deployed workflow;
production HA and release gates remain separate.

Local acceptance evidence is recorded in
`docs/qualification/phase2-m4c2c-policy-approval-management-api-2026-09-29.md`.
