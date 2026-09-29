# Phase 2 M4c2e Console management-scope projection acceptance matrix

Status date: 2026-09-29

This record is engineering evidence for the local server-authoritative Console
management-scope projection. It does not qualify the Console UI, a deployed
multi-user workflow, production SLO, HA, legal approval, release, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `2c85618` |
| Core candidate | working tree containing this matrix; exact commit belongs in the delivery report |
| Database migration | `50` — Console management scope projection |
| Projection route | `GET /auth/v1/session/management-scopes` |
| Authentication | exact host-only Core Account Session cookie |
| Projected permission | exact active Network-scope `policy.approve` |
| Durable authority | PostgreSQL Session, membership, RBAC, Workspace, and Network state |
| Projection semantics | navigation only; every downstream operation reauthorizes |
| Graph storage | none |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M4C2E-01` | The route is an exact private safe read. | Browser ingress and dispatcher method/path/query tests. | Pass |
| `M4C2E-02` | TLS, Host, Origin, session channel, cookie, and fresh durable Session are mandatory. | Existing private admission plus projection-specific HTTP tests. | Pass |
| `M4C2E-03` | Mutation transport is rejected. | CSRF, Authorization, body, content type, ETag, idempotency, and method-alias regressions. | Pass |
| `M4C2E-04` | The response exposes only Principal, login Workspace, eligible Networks, and `policy.approve`. | Closed OpenAPI schema, domain model, and serialized-response assertions. | Pass |
| `M4C2E-05` | Account Session and RBAC internals remain concealed. | Response/schema field ownership and body non-disclosure tests. | Pass |
| `M4C2E-06` | Pagination is bounded and deterministic. | Page size 1–100, default 50, UUIDv7 keyset order, one-record lookahead, and strict cursor tests. | Pass |
| `M4C2E-07` | Page tokens cannot cross login Workspaces. | Workspace-bound opaque token parser/encoder tests. | Pass |
| `M4C2E-08` | Projection evidence cannot become operation authority. | Narrow interface and documentation contract; M4c2d approval services remain unchanged and freshly authorize. | Pass |
| `M4C2E-09` | PostgreSQL validates the complete current Session authority vector. | Migration predicate review plus live active/revoked Session integration. | Pass |
| `M4C2E-10` | Only active, valid `policy.approve` Networks are returned. | Hard-coded permission SQL, strict domain validation, positive approver and negative proposer integration. | Pass |
| `M4C2E-11` | Forced RLS permits only the requested projection Workspace. | Dedicated function-owned transaction-local RLS setting and live exact-Network result. | Pass |
| `M4C2E-12` | Projection RLS capability never leaks to the caller transaction. | Live prior-value restoration assertion after successful function execution. | Pass |
| `M4C2E-13` | Database capability remains least privilege. | Live ACL assertions: runtime-only execute, no `PUBLIC`/foreign-role execute, security definer, and existing no-table-access contract. | Pass |
| `M4C2E-14` | The private OpenAPI compiler rejects operation drift. | Exact method, operation ID, cookie-only security, parameter count, and no-body negative tests. | Pass |
| `M4C2E-15` | Production composition cannot omit the projection service. | Factory/application completeness and typed-nil tests. | Pass |
| `M4C2E-16` | Repository and disposable platform gates remain regression-safe. | Executed evidence below. | Pass |

## Executed evidence

- Focused domain, PostgreSQL adapter, HTTP adapter, OpenAPI, migration, and
  process-root suites pass 1,867 tests across six packages.
- `make fmt-check`, `make tidy-check`, `make vet`, `make test`, and
  `make test-race` pass on the candidate.
- The integration-tag package compiles independently.
- `govulncheck v1.8.0` reports no reachable vulnerability and
  `actionlint v1.7.12` passes.
- M4c2e introduces no lint finding. Repository-wide lint remains non-zero on
  the same five pre-existing findings recorded by M4c2d; integration-tag lint
  repeats only the existing `private_identity_factory.go` finding.
- The disposable platform runner passes with PostgreSQL 18.6 and Redis 8.8.
  Migration 50 is applied before live runtime projection, forced-RLS/ACL,
  negative-permission, RLS-restoration, and revoked-Session assertions. The
  remaining process/platform integration suites pass in the same run.
- A fail-first disposable run exposed that forced Network RLS needed an
  explicit projection capability. The final migration uses a dedicated
  function-owned, transaction-local Workspace setting, restores prior values
  on success or error, grants runtime no table access, and passes consecutive
  disposable platform runs after the correction.
- `git diff --check` passes. Changed-file review contains no production
  credential, private key, provider token, or Account Session secret.

## Residual work

- Implement the Console approval queue, detail view, independent approval
  confirmation, and accessible loading/empty/denied/stale/conflict/success
  states against M4c2d and this projection.
- Qualify the deployed same-origin flow with two independent human Sessions.
- Principal display names, notifications, configurable quorum,
  approval-policy administration, production HA/SLO, legal, signing, release,
  and GA remain separate gates.
