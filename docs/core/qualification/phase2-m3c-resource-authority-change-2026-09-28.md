# Phase 2 M3c protected Resource authority change acceptance matrix

Date: 2026-09-28

Scope: MeshCore engineering qualification for Resource and Resource Group owner
transfer and custodian delegation. This record is not a production,
availability, HA, SLO, or GA claim.

| ID | Acceptance criterion | Evidence | Status |
| --- | --- | --- | --- |
| M3C-01 | Bearer OpenAPI defines preview/request/confirm actions for Resource and Resource Group while the private browser profile excludes them. | OpenAPI source, profile compiler invariants, and contract tests. | Pass |
| M3C-02 | Current owner is the only proposer and the target is a distinct active Workspace Principal. | Domain validation, PostgreSQL resolution, and integration denial cases. | Pass |
| M3C-03 | Owner transfer changes only owner; custodian delegation changes only custodian. | Domain impact invariants, transition trigger, and semantic-hash assertions. | Pass |
| M3C-04 | Impact binds scope, typed subject, aggregate version, action, target, before/after authority and semantic hashes, quorum, and step-up age. | Deterministic domain hash tests and stale-preview integration case. | Pass |
| M3C-05 | Request requires exact acknowledged impact, strong aggregate CAS, durable idempotency, audit reason, and fresh `*.transfer` authorization. | HTTP boundary, service, SQL transaction, and integration flow. | Pass |
| M3C-06 | Requester step-up is at most five minutes old and its ACR exactly matches non-null Workspace provider `minimum_assurance`. | Narrow PostgreSQL step-up function and live fixture. | Pass |
| M3C-07 | Confirmation requires the exact target Principal using a distinct fresh Account Session and a distinct Principal. | Database constraints/function, self-confirmation denial, and two-Principal integration flow. | Pass |
| M3C-08 | Each Account Session is single-use for M3c and step-up evidence is immutable/retained. | Unique evidence constraint, transition trigger, and privilege assertions. | Pass |
| M3C-09 | Pending request has fixed quorum one, ten-minute exclusive expiry, and only version-1 pending to version-2 applied transition. | Table constraints, confirmation transaction, and HTTP `410/412` mapping. | Pass |
| M3C-10 | Authority mutation, request/evidence, revisions, audit, outbox, and idempotency completion commit atomically. | Application-owned transactions and committed PostgreSQL evidence assertions. | Pass |
| M3C-11 | Identical request/confirmation replay returns original evidence without a duplicate mutation; changed semantics conflict. | Domain service replay logic and live PostgreSQL replay assertions. | Pass |
| M3C-12 | Runtime has narrow function capability; non-runtime roles and direct table access cannot bypass the workflow. | Migration grants/RLS and live privilege assertions. | Pass |
| M3C-13 | Missing/cross-scope authority is concealed and stale state, target, impact, step-up, expiry, and CAS failures are typed and fail closed. | SQLSTATE adapter mapping, HTTP classification tests, and integration negatives. | Pass |
| M3C-14 | Repository quality and disposable PostgreSQL integration gates pass. | Final command evidence below. | Pass with recorded pre-existing lint baseline |

## Final command evidence

- `make fmt-check`, `go mod tidy -diff`, `go vet ./...`, and workflow lint pass.
- `go test ./...` and `go test -race ./...` each pass 4,435 tests across
  56 packages.
- A disposable PostgreSQL/Redis platform integration run passes migration 42,
  owner-only preview denial, proposal/replay, requester self-confirmation denial,
  distinct target-Principal confirmation/replay, stale impact/CAS denial,
  retained request and two step-up records, audit/outbox/idempotency evidence,
  and least-privilege assertions.
- `govulncheck v1.8.0` reports no reachable vulnerabilities.
- M3c introduces no lint finding. Repository-wide lint remains non-zero on the
  same five pre-existing findings recorded by M3b2; integration lint repeats
  only the existing `private_identity_factory.go` finding.
- Secret scanning, JSON validation, diff review, and whitespace checks report
  no credential/private-key material or malformed contract.

## Residual limits

- Device remains the only Resource kind.
- Quorum is fixed at one target-Principal confirmation; configurable approval
  policy is not fabricated by this slice.
- Resource Groups are not yet consumed by Access Graph or TCP/UDP policy
  compilation, and no graph database is introduced.
- Production PostgreSQL/Redis failover, multi-replica load, and SLO evidence
  remain separate qualification gates.
