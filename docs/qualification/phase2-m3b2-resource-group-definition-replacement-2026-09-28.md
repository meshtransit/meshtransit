# Phase 2 M3b2 Resource Group definition replacement acceptance matrix

Date: 2026-09-28

Scope: MeshCore engineering qualification for immutable Resource Group
definition replacement. This record is not a production, availability, HA,
SLO, or GA claim.

| ID | Acceptance criterion | Evidence | Status |
| --- | --- | --- | --- |
| M3B2-01 | Bearer OpenAPI defines separate preview/apply actions while the private browser profile excludes them. | OpenAPI document, profile composer, and contract tests. | Pass |
| M3B2-02 | Preview requires strong aggregate CAS, fresh `resource_group.manage`, strict bounded membership, and no idempotency key. | HTTP adapter and PostgreSQL preview path. | Pass |
| M3B2-03 | Every proposed member is an exact same-scope active Resource/version/target-generation pin. | Domain reference validation and migration 41 resolution query. | Pass |
| M3B2-04 | Impact binds exact scope/group/version, immutable metadata, current/proposed versions and hashes, both membership sets, and approval decision. | `GroupReplaceImpact` hash tests and integration assertions. | Pass |
| M3B2-05 | Preview reports deterministic added, removed, and retained exact references; changed pins are remove-plus-add. | Domain diff tests, HTTP response test, and PostgreSQL re-pin integration case. | Pass |
| M3B2-06 | Apply recomputes impact under locks and rejects stale acknowledgement before mutation. | Transaction resolve boundary and exact hash comparison. | Pass |
| M3B2-07 | Any approval-required result fails closed until durable approval evidence exists. | Resolution validation, transaction guard, and typed HTTP mapping. | Pass |
| M3B2-08 | Apply appends definition/member rows and moves only the active pointer; previous versions remain unchanged. | Migration 41 transition guard and committed PostgreSQL old/new member counts. | Pass |
| M3B2-09 | Aggregate and definition versions advance exactly once with Network/group revisions. | Service validation and PostgreSQL integration result assertions. | Pass |
| M3B2-10 | Mutation, revisions, audit, outbox, and idempotency evidence commit atomically. | Adapter transaction and committed evidence counts. | Pass |
| M3B2-11 | Identical replay returns the original result without another version; stale/cross-scope requests fail closed. | PostgreSQL replay, stale CAS, and scope-isolation assertions. | Pass |
| M3B2-12 | Runtime has function-only capability; worker cannot preview/lock/apply and runtime has no direct table capability. | Migration grants and live PostgreSQL privilege assertions. | Pass |
| M3B2-13 | Current no-approval decision is explicitly bounded to absent protected consumers. | Design record and canonical API contract. | Pass |
| M3B2-14 | Repository quality and disposable PostgreSQL integration gates pass. | Final command evidence below. | Pass with recorded pre-existing lint baseline |

## Final command evidence

- `make fmt-check`, `go mod tidy -diff`, `go vet ./...`, and workflow lint pass.
- `go test ./...` and `go test -race ./...` each pass 4,423 tests across
  56 packages.
- A disposable PostgreSQL/Redis platform integration run passes migration 41,
  replacement preview/apply/replay, old-version retention, audit/outbox/
  idempotency evidence, stale/cross-scope denial, and privilege negatives.
- `govulncheck v1.8.0` reports no reachable vulnerabilities.
- M3b2 introduces no lint finding. Repository-wide lint remains non-zero on the
  same five pre-existing findings recorded by M3a/M3b1; integration lint repeats
  the existing `private_identity_factory.go` finding.
- Secret scanning and diff review report no credential or private-key material.

## Residual limits

- Device remains the only Resource kind.
- Ownership transfer and custodian delegation remain M3c protected workflows.
- Approval persistence is not fabricated: the current schema has no protected
  downstream consumer, while an approval-required impact fails closed.
- Resource Groups are not yet consumed by Access Graph or policy compilation.
- Production PostgreSQL/Redis failover, multi-replica load, and SLO evidence
  remain separate qualification gates.
