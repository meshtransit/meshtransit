# Phase 2 M2 Resource management API acceptance matrix

Date: 2026-09-28

Scope: MeshCore engineering qualification for Resource and Resource Group
create/get/list management contracts. This matrix is not a production,
availability, or GA claim.

| ID | Acceptance criterion | Evidence | Status |
| --- | --- | --- | --- |
| M2-01 | Bearer OpenAPI defines create/get/list Resource and Resource Group operations with exact scope parameters. | `api/openapi/management_v1.json`; contract tests. | Pass |
| M2-02 | Create requires strong collection `If-Match`, HMAC-protected idempotency, strict bounded JSON, and an audit reason. | HTTP adapter tests; authority command validation. | Pass |
| M2-03 | Identical idempotent replay returns the original committed aggregate without another mutation. | Authority service replay unit test; PostgreSQL integration replay assertion. | Pass |
| M2-04 | Reusing an idempotency key with different request semantics fails closed. | Request hash and durable claim resolver; classified `409`. | Pass |
| M2-05 | Mutation, revision advance, audit, outbox, and completed idempotency evidence commit atomically. | Resource authority adapter; deferred evidence constraints; PostgreSQL integration. | Pass |
| M2-06 | Get/list revalidate live `resource.read` or `resource_group.read` in the exact Network scope. | Catalog service and PostgreSQL adapter; service permission tests. | Pass |
| M2-07 | Cross-scope opaque detail IDs are indistinguishable from absent IDs. | Scoped SQL functions; catalog integration and HTTP `404` tests. | Pass |
| M2-08 | Lists are deterministic, bounded to 100, revision-pinned, filter-bound, snapshot-consistent, and free of N+1 queries. | Short `REPEATABLE READ` catalog transaction; migration 38 revision/JSON aggregate functions; cursor and revision-conflict tests. | Pass |
| M2-09 | Runtime has no direct Resource table grants; worker and observer cannot execute management readers/writers. | Migration privilege assertions and integration negative tests. | Pass |
| M2-10 | Redis remains non-authoritative and request-admission failure closes access. | Existing management admission contract; composition review. | Pass |
| M2-11 | Safe errors distinguish authentication, authorization, hidden targets, stale preconditions, intent conflict, dependency failure, and deadlines without leaking diagnostics. | HTTP classification tests and response envelope contract. | Pass |
| M2-12 | The private browser profile does not inherit the new Bearer Resource routes. | OpenAPI profile composer and profile tests. | Pass |
| M2-13 | Migration 38 is additive, embedded, ordered, checksummed, and least privilege. | Migration catalog and disposable PostgreSQL migration tests. | Pass |
| M2-14 | Formatting, unit, race, vet, module, OpenAPI, migration, and focused integration gates pass. | Final delivery command evidence. | Pass |
| M2-15 | Documentation makes no graph-database, Access Graph, HA, SLO, or GA claim. | M2 design scope, STRIDE review, and residual limitations. | Pass |

## Final command evidence

- `make fmt-check`, `go mod tidy -diff`, `go vet ./...`, and workflow lint pass.
- `go test ./...` and `go test -race ./...` each pass 4,389 tests across
  56 packages.
- The disposable PostgreSQL/Redis platform integration gate passes all three
  suites, including migrations, idempotent replay, exact-scope reads, and role
  privilege negatives.
- `govulncheck v1.8.0` reports no reachable vulnerabilities.
- M2 introduces no lint findings. Repository-wide lint remains non-zero on five
  pre-existing findings outside this slice; integration lint repeats one of
  those findings in `cmd/meshcore/private_identity_factory.go`.

## Residual limitations

- Device remains the only Resource kind.
- M2 exposes creation and reading, not lifecycle mutation or deletion.
- Target rebinding, group replacement, ownership transfer, and custodian
  delegation remain M3.
- Resource Groups are not yet consumed by Access Graph or policy compilation.
- Search, connector ingestion, sharing/export, and Console UX are not included.
- Production PostgreSQL/Redis failover, multi-replica load, and SLO evidence
  remain separate gates.
