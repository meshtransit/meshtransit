# Phase 2 M3b Resource target rebinding acceptance matrix

Date: 2026-09-28

Scope: MeshCore engineering qualification for Device Resource target rebinding.
This record is not a production, availability, HA, SLO, or GA claim.

| ID | Acceptance criterion | Evidence | Status |
| --- | --- | --- | --- |
| M3B-01 | Bearer OpenAPI defines separate preview and apply actions while the private browser profile excludes them. | OpenAPI document, profile composer, and contract tests. | Pass |
| M3B-02 | Preview requires strong Resource CAS, fresh `resource.manage`, strict bounded input, and no idempotency key. | HTTP adapter and PostgreSQL preview transaction tests. | Pass |
| M3B-03 | Impact binds exact scope, Resource/version, old/new Device, target generations, semantic hashes, approval decision, and canonical affected groups. | `RebindImpact` validation/hash tests and integration assertions. | Pass |
| M3B-04 | Impact enumeration is deterministic and fails rather than truncates above 256 non-deleted groups. | Sorted bounded SQL aggregate, domain maximum, parser classification, and `422` mapping. | Pass |
| M3B-05 | Apply recomputes impact under locks and rejects a changed acknowledgement before mutation. | Rebind transaction and service changed-impact tests. | Pass |
| M3B-06 | Any approval-required result fails closed until durable approval evidence exists. | Locked transaction guard and HTTP `approval_required` classification. | Pass |
| M3B-07 | Rebind retains the previous target as `superseded`, inserts exactly the next active generation, and advances Resource version/semantic hash. | Migration 40 guard/function and PostgreSQL integration evidence. | Pass |
| M3B-08 | Existing immutable Resource Group definitions remain pinned to the previous Resource version and target generation. | Impact query plus committed PostgreSQL group-member assertion. | Pass |
| M3B-09 | Resource mutation, Network/inventory revisions, audit, outbox, and completed idempotency evidence commit atomically. | Rebind adapter, deferred evidence constraints, and PostgreSQL evidence counts. | Pass |
| M3B-10 | Identical replay returns the committed result without another mutation; changed intent and stale version fail closed. | Service and PostgreSQL replay/CAS assertions. | Pass |
| M3B-11 | Missing and cross-scope identities remain indistinguishable, and a proposed Device cannot already be actively bound. | Exact-scope SQL, integration negatives, and safe HTTP mapping. | Pass |
| M3B-12 | Runtime has no direct Resource table grants and worker cannot execute the rebind function. | Migration 40 grants and PostgreSQL privilege negatives. | Pass |
| M3B-13 | Current no-approval decision is explicitly limited to the absence of policy/route/share/Access Graph consumers. | Design record and canonical API contract. | Pass |
| M3B-14 | Repository quality and disposable PostgreSQL integration gates pass. | Final command evidence below. | Pass with recorded pre-existing lint baseline |

## Final command evidence

- `make fmt-check`, `go mod tidy -diff`, `go vet ./...`, and workflow lint pass.
- `go test ./...` and `go test -race ./...` each pass 4,413 tests across
  56 packages.
- The disposable PostgreSQL/Redis platform integration gate passes all suites,
  including migration 40, preview, apply, replay, stale/cross-scope denial,
  pinned group membership, audit/outbox/idempotency evidence, and privilege
  negatives.
- `govulncheck v1.8.0` reports no reachable vulnerabilities.
- M3b introduces no lint finding. Repository-wide lint remains non-zero on the
  same five pre-existing findings recorded by M3a; integration lint repeats the
  existing `private_identity_factory.go` finding.
- Secret scanning and diff review report no credential or private-key material.

## Residual limits

- Device remains the only Resource kind.
- Immutable Resource Group replacement remains M3b2.
- Ownership transfer and custodian delegation remain M3c protected workflows.
- Approval persistence is not fabricated: current rebinding has no protected
  downstream consumer, while a future approval-required impact fails closed.
- Resource Groups are not yet consumed by Access Graph or policy compilation.
- Production PostgreSQL/Redis failover, multi-replica load, and SLO evidence
  remain separate qualification gates.
