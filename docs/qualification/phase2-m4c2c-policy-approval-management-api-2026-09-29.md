# Phase 2 M4c2c policy approval management API acceptance matrix

Status date: 2026-09-29

Follow-up: M4c2d later supersedes only the qualified browser-read omission in
`M4C2C-12`; this matrix remains the historical M4c2c candidate evidence.

This record is engineering evidence for the local M4c2c proposal, catalog, and
independent-decision workflow. It does not qualify a deployed Console workflow,
production SLO, HA, legal approval, release, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `3e434c0` |
| Core candidate | working tree containing this matrix; exact commit belongs in the delivery report |
| Database migration | `49` — Policy approval management read API |
| Mutation authority | existing M4c2a `PolicyApprovalStore` and approval service |
| Catalog authority | `internal/adapter/postgres.PolicyApprovalStore` through narrow management-read functions |
| Proposal permission | `policy.validate` |
| Catalog and decision permission | `policy.approve` |
| Browser profile | proposal and approval mutations only |
| Graph storage | none |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M4C2C-01` | Proposal is exposed at a versioned exact-Network endpoint. | HTTP path parser, OpenAPI contract, handler tests, and live private-browser request. | Pass |
| `M4C2C-02` | Proposal acknowledges current policy revision, candidate hash, and impact hash. | Required policy ETag and SHA-256 fields; domain re-simulation in live integration. | Pass |
| `M4C2C-03` | Proposal remains replay-safe. | Required idempotency key, durable M4c2a claim/completion, and stable result validation. | Pass |
| `M4C2C-04` | Approval uses an independent Principal and Account Session. | Domain invariants, catalog projection invariant, distinct integration approver token/session, and live decision. | Pass |
| `M4C2C-05` | Approval binds exact request version, candidate, and impact. | Strong request ETag, required hashes, conflict mapping, and handler/domain tests. | Pass |
| `M4C2C-06` | Approval conflicts do not reveal state or authority details. | Candidate/impact/version/state/expiry/self conflicts collapse to `409 approval_conflict`. | Pass |
| `M4C2C-07` | Catalog list/get require fresh exact-scope `policy.approve`. | Adapter authorization order tests and live least-privileged approver reads. | Pass |
| `M4C2C-08` | Catalog does not expose Account Session identifiers. | Safe projection types, response schemas, handler tests, and live response assertions. | Pass |
| `M4C2C-09` | Catalog pages are bounded and deterministic. | Page size 1–100, UUIDv7 keyset ordering, one-record lookahead, filter-bound opaque tokens. | Pass |
| `M4C2C-10` | Cross-scope or absent requests remain concealed. | Exact transaction-local scope, scoped SQL functions, and `404 not_found` mapping. | Pass |
| `M4C2C-11` | Browser mutations require cookie, Origin, explicit intent, and CSRF proof. | Existing buffered browser admission plus live proposal/decision E2E. | Pass |
| `M4C2C-12` | Cookie transport cannot read approval catalog data. | Browser route profile omits GET and handler rejects browser catalog reads. | Pass |
| `M4C2C-13` | Private-browser proposal emits no navigation or credential authority. | Wrapper strips `Location`/Bearer challenge; live response has no cookie renewal. | Pass |
| `M4C2C-14` | Both production compositions receive complete approval dependencies. | Management and private-identity factory/application composition tests. | Pass |
| `M4C2C-15` | Database capability remains least privilege. | Migration catalog tests and live ACL assertions for helper plus get/list functions. | Pass |
| `M4C2C-16` | Fresh authorization locks are compatible with catalog reads. | Non-read-only short transaction regression tests and live PostgreSQL list/get. | Pass |
| `M4C2C-17` | Read responses are non-cacheable and versioned where applicable. | `Cache-Control: no-store`, strong item ETags, OpenAPI and HTTP tests. | Pass |
| `M4C2C-18` | End-to-end Evidence remains consumable exactly once by publication. | Live browser proposal/list/get/approve followed by M4c2b publication and consumed-state assertion. | Pass |
| `M4C2C-19` | Repository contract and focused behavior remain regression-safe. | Focused Go suite passes 1,669 tests across approval, PostgreSQL, HTTP, OpenAPI, and migration packages. | Pass |
| `M4C2C-20` | Platform integration remains convergent. | Disposable PostgreSQL/Redis runner applies migration 49 and passes integration/process suites. | Pass |

## Executed evidence

- `make integration-platform-container` passes against owned disposable
  PostgreSQL 18.6 and Redis 8.8 containers. Migration 49 is applied before the
  live private-browser proposal, Bearer list/get, independent private-browser
  decision, publication, and consumed-state assertions.
- Focused tests pass 1,669 cases across five approval, PostgreSQL, HTTP,
  OpenAPI, and migration packages. The integration-tag package also compiles
  independently before the live runner.
- Live ACL assertions verify three fixed-search-path `SECURITY DEFINER`
  functions, no `PUBLIC` or non-runtime execution, a private payload helper,
  runtime-only get/list entry points, and no direct approval-table capability.
- `make fmt-check`, `make tidy-check`, `make vet`, `make test`, and
  `make test-race` pass on the final working candidate.
- `govulncheck v1.8.0` reports no reachable vulnerability and
  `actionlint v1.7.12` passes.
- M4c2c introduces no lint finding. Repository-wide lint remains non-zero on
  the same five pre-existing findings recorded by M4c2b; integration-tag lint
  repeats only the existing `private_identity_factory.go` finding.
- `git diff --check` passes. Changed-file review contains no introduced
  production credential, private key, or secret material; browser tokens used
  by integration are deterministic synthetic fixtures.

## Residual work

- Console UI, notification delivery, configurable quorum, and approval-policy
  administration remain pending.
- Principal projection, sensitivity classes, cross-scope paths, Guardrails,
  share intersection, routed/service Resources, and a second evaluator remain
  explicitly unsupported.
- Multi-client deployment, production PostgreSQL failover, multi-replica
  approval qualification, production SLO, legal, signing, release, and GA
  qualification remain separate gates.
