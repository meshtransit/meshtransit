# Phase 2 M4c2e Console management-scope projection design

Status: implemented engineering projection; final local qualification is
recorded separately.

Date: 2026-09-29

## Scope

M4c2e gives the private same-origin Console a server-authoritative mapping from
the current authenticated Account Session to Phase 2 UUIDv7 management scope.
It closes the identity gap between the legacy Console's numeric Network model
and the M4c2d approval catalog without making browser state an authorization
source.

PostgreSQL remains the only Session, membership, RBAC, Workspace, and Network
authority. Redis remains revision-wakeup and rate-limit transport. This slice
adds no graph database, no new policy evaluator, and no Console component.

## Private projection contract

The private profile adds one exact safe-read route:

`GET /auth/v1/session/management-scopes`

Admission requires completed direct TLS 1.2 or later, the exact configured Host
and HTTPS Origin, `X-MeshTransit-Session: v1`, one canonical host-only Core
Session cookie, fresh durable authentication, and shared source/Session
budgets. `Authorization`, CSRF, body, content type, `If-Match`, idempotency,
transfer encoding, and mutation headers are rejected.

The response contains only:

- the current Principal public ID;
- the exact login Workspace public ID and bounded display name; and
- active Network public IDs and bounded display names where the current
  Principal freshly holds exact Network-scope `policy.approve`.

Network results use deterministic UUIDv7 keyset order. `page_size` accepts 1 to
100 and defaults to 50. The opaque `page_token` binds its Network cursor to the
login Workspace. Unknown, duplicated, empty, noncanonical, oversized, or
cross-Workspace query input is rejected. Responses are `Cache-Control:
no-store` and never expose Account Session IDs, provider claims, role names,
membership IDs, bindings, or credentials.

This projection is navigation evidence only. Approval list, get, propose,
approve, and publication continue to perform their own fresh exact-Network
authorization and precondition checks. Possessing or editing a projected ID
never grants an operation.

## Authority and capability boundary

Migration `000050_console_management_scope_projection.up.sql` adds one fixed
search-path `SECURITY DEFINER` function. Its complete input vector
binds Session, Deployment, Principal, identity subject, all authority
generations, recovery epoch, login Workspace, evaluation time, cursor, and
limit. The function revalidates the complete active Session chain, active
Workspace membership, active Network, binding validity, role definition,
role-permission state, and the hard-coded `policy.approve` permission.

The function owns a dedicated, transaction-local forced-RLS projection scope,
restores any prior setting on success or error, and can read Networks only from
the requested login Workspace. Only `mesh_runtime` may execute the function.
`PUBLIC`, worker, observer,
audit-writer, and share-writer roles are revoked, and runtime receives no table
privilege. The Go adapter uses a bounded transaction and returns a
concealed unauthenticated result when the authority vector no longer matches.
The domain service independently validates scope identity, labels, permission,
ordering, cursor monotonicity, page bounds, and defensive-copy ownership.

The SQL projection intentionally does not lock RBAC rows. It is a current
navigation snapshot, not an authorization decision. Every downstream approval
operation reauthorizes with its existing locking/current-authority contract,
so no projection race can elevate privilege.

## Dispatcher and OpenAPI ownership

`BrowserManagement` owns the route and preserves the existing correlation,
deadline, concurrency, response-buffer, rate-limit, authentication, late
freshness, and safe-error boundaries. The login dispatcher admits query text
only for the callback, approval collection, and this exact route; method aliases
or query-bearing unrelated routes remain closed.

The private OpenAPI compiler validates the standalone operation identity,
cookie-only security, exact method, four parameters, and absence of a request
body before composition. The released Bearer management document remains
byte-identical.

## Security analysis

| Threat | M4c2e control |
| --- | --- |
| Spoofing | Exact TLS/Host/Origin/channel/cookie admission and fresh complete-vector Session authentication. |
| Tampering | Canonical route/query checks, Workspace-bound opaque cursor, typed UUIDv7 identities, and hard-coded `policy.approve`. |
| Repudiation | Bounded correlation IDs, finite operation metrics, and existing safe completion logging without credential data. |
| Information disclosure | Exact login Workspace, current permission filter, concealed stale authority, bounded labels/page, no Session or RBAC internals, and no-store delivery. |
| Denial of service | Shared source/Session limits, finite deadline/concurrency/response bounds, page limit 100, and SQL limit 101. |
| Elevation of privilege | Projection is never accepted as operation authority; every approval route freshly reauthorizes exact scope. |

## Non-claims and next order

M4c2e does not add the Console approval queue, detail, confirmation action,
Principal display-name projection, notifications, configurable quorum,
approval-policy administration, deployment qualification, production HA/SLO,
legal signing, release, or GA.

The next slice should implement the Console queue/detail/approve experience
using this projection for navigation and the M4c2d routes for authority. It
must include accessible loading, empty, denied, stale, conflict, and success
states while retaining server-side exact-scope authorization.

Local acceptance evidence is recorded in
`docs/qualification/phase2-m4c2e-console-management-scope-projection-2026-09-29.md`.
