# Phase 2 M2b1 Device Resource policy destination acceptance matrix

Status date: 2026-09-29

This record is non-production engineering evidence for active Device-backed
Resource destinations. It does not qualify Resource Group compilation, deployed
artifacts, HA, data-service failover, production SLOs, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `0d6d12e` |
| Core candidate | working tree containing this matrix; exact commit belongs in the delivery report |
| Direct Device compiler format | `1`, unchanged |
| Resource destination compiler format | `2` |
| Client protocol | unchanged Node-resolved packet-policy projection |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M2B1-01` | Every rule chooses exactly one direct Device or Resource destination. | HTTP decoder tests and OpenAPI `oneOf` contract. | Pass |
| `M2B1-02` | Resource lookup is exact-scope, freshly authorized, snapshot-consistent, active-only, and bounded to 256 distinct IDs. | `internal/resource/catalog` service and tests. | Pass |
| `M2B1-03` | Compilation emits the existing Node-level policy plus exact Resource ID/version/target-generation/inventory/hash provenance. | `internal/policy/compilation` and publication artifact tests. | Pass |
| `M2B1-04` | Direct Device candidates preserve compiler format 1 and its prior hash encoding; Resource candidates use hash domain/format 2. | Candidate construction and hash provenance tests. | Pass |
| `M2B1-05` | Publication revalidates active Resource and active Device binding under the existing Network transaction boundary. | Migration 43 function plus PostgreSQL transaction unit fixture. | Pass |
| `M2B1-06` | Stale or mismatched Resource evidence rolls back activation and cannot replace the old release. | Exact-count conflict path and atomic transaction ordering tests. | Pass |
| `M2B1-07` | Durable provenance is immutable, exact-scoped, RLS-protected, audited, and least-privilege. | Migration catalog assertions and disposable PostgreSQL migration gate. | Pass |
| `M2B1-08` | Bearer and private browser management graphs share the compiler; browser proof precedes Resource reads. | Production composition plus HTTP/browser tests. | Pass |
| `M2B1-09` | Rebound Resources with target generation greater than one remain valid catalog snapshots. | `TestResourceAcceptsCurrentReboundDeviceRevision` and live integration discovery. | Pass |
| `M2B1-10` | Real PostgreSQL compilation, browser publication, provenance persistence, map projection, deny-all, and restore succeed together. | Disposable `TestPostgreSQLMigrations` scenario. | Pass |
| `M2B1-11` | No graph database, Redis authority, or client selector semantics are introduced. | Dependency and data-flow inspection; unchanged client projection. | Pass |

## Integration notes

- The first disposable run exposed an invalid test setup that attempted a
  second active Resource binding for one Device; the fixture was corrected to
  consume existing authority rather than weaken the uniqueness invariant.
- The next run exposed a real catalog validation defect for rebound Resources:
  current generation-2 semantics were compared with an initial generation-1
  definition. Validation now uses the exact `DeviceRevision`, with a regression
  test.
- The final disposable platform wrapper passed the complete PostgreSQL scenario
  in 18.333 seconds, the qualification tool suite in 1.666 seconds, and the
  process/platform integration suite in 8.684 seconds.
- No deployed cluster or production environment was used as evidence.

## Final command evidence

- Focused OpenAPI, HTTP, compiler, publication, catalog, PostgreSQL adapter, and
  migration tests pass.
- Integration-tag compilation passes.
- The disposable PostgreSQL 18.6 and Redis 8.8.0 platform wrapper passes,
  including migration 43 and the live M2b1 publication lifecycle.
- Repository-wide formatting, `go mod tidy -diff`, `go vet ./...`, unit tests,
  race tests, and workflow lint pass.
- `govulncheck v1.8.0` reports zero reachable vulnerabilities.
- M2b1 introduces no lint finding. Repository-wide lint remains non-zero on the
  same five pre-existing findings recorded by M2a/M3c; integration lint repeats
  only the existing `private_identity_factory.go` finding.

## Residual work

- M2b2 must expand immutable Resource Group definitions, pin group definition
  and collection revisions, and revalidate each member Resource.
- A deployed multi-client traffic matrix remains a separate qualification gate.
- PostgreSQL/Redis infrastructure failover remains outside this engineering
  slice.
