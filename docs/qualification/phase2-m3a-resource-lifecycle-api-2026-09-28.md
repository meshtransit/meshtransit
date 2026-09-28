# Phase 2 M3a Resource lifecycle API acceptance matrix

Date: 2026-09-28

Scope: MeshCore engineering qualification for Resource and Resource Group
lifecycle actions. This record is not a production, availability, HA, SLO, or
GA claim.

| ID | Acceptance criterion | Evidence | Status |
| --- | --- | --- | --- |
| M3A-01 | Bearer OpenAPI defines bounded Resource and Resource Group lifecycle actions while the private browser profile excludes them. | OpenAPI document, profile composer, and contract tests. | Pass |
| M3A-02 | Actions require a strong object ETag, durable idempotency evidence, strict bounded JSON, and audit reason. | HTTP adapter and command-validation tests. | Pass |
| M3A-03 | State machine permits active/suspended transitions and terminal retained deletion only. | Domain operation model, migration 39 guard, PostgreSQL lifecycle integration. | Pass |
| M3A-04 | Stale aggregate versions return a precondition failure without overwriting newer authority. | PostgreSQL compare-and-swap function, integration stale-version assertion, HTTP classification. | Pass |
| M3A-05 | Absent and cross-scope IDs are indistinguishable. | Exact-scope SQL and integration/HTTP hidden-target assertions. | Pass |
| M3A-06 | Identical replay returns the committed result without a second mutation. | Lifecycle service replay unit test and PostgreSQL replay/evidence counts. | Pass |
| M3A-07 | State, version, Network/subsystem revisions, audit, outbox, and completed idempotency commit atomically. | Deferred audit constraint, transaction adapter, incomplete-evidence rollback and committed evidence assertions. | Pass |
| M3A-08 | Authorization is revalidated inside every attempt and uncertain-commit resolution. | Lifecycle adapter authorization path and service retry tests. | Pass |
| M3A-09 | Runtime has no direct Resource table grants and worker cannot execute lifecycle functions. | Migration 39 grants plus PostgreSQL privilege negatives. | Pass |
| M3A-10 | Target generation, immutable Group versions/members, ownership, custody, and semantic hash do not change. | Migration transition guard and result validation. | Pass |
| M3A-11 | Target rebinding, group replacement, and ownership/custodianship are not silently implemented without impact/approval foundations. | M3a scope and next-order record. | Pass |
| M3A-12 | Repository quality and disposable PostgreSQL integration gates pass. | Final command evidence below. | Pass with recorded pre-existing lint baseline |

## Final command evidence

- `make fmt-check`, `go mod tidy -diff`, `go vet ./...`, and workflow lint pass.
- `go test ./...` and `go test -race ./...` each pass 4,397 tests across
  56 packages.
- The disposable PostgreSQL/Redis platform integration gate passes all three
  suites, including migration 39, lifecycle replay, evidence rollback,
  exact-scope denial, terminal deletion, and role privilege negatives.
- `govulncheck v1.8.0` reports no reachable vulnerabilities.
- M3a introduces no lint findings. Repository-wide lint remains non-zero on the
  same five pre-existing findings recorded by M2; integration lint repeats the
  existing `private_identity_factory.go` finding.

## Residual limits

- Device remains the only Resource kind.
- Target rebinding and immutable Resource Group replacement remain M3b.
- Ownership transfer and custodian delegation remain M3c and require protected
  approval/step-up semantics.
- Resource Groups are not yet consumed by Access Graph or policy compilation.
- Production failover, multi-replica load, and SLO evidence remain separate
  qualification gates.
