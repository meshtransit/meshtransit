# Phase 2 M2b2 Resource Group policy destination acceptance matrix

Status date: 2026-09-29

This record is non-production engineering evidence for active Resource Group
policy destinations. It does not qualify deployed artifacts, HA,
data-service failover, routed/service Resources, production SLOs, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `950d71a` |
| Core candidate | working tree containing this matrix; exact commit belongs in the delivery report |
| Direct Device compiler format | `1`, unchanged |
| Direct Resource compiler format | `2`, unchanged |
| Resource Group compiler format | `3` |
| Database migration | `44`, forward-only |
| Client protocol | unchanged Node-resolved packet-policy projection |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M2B2-01` | Every rule selects exactly one Device, Resource, or Resource Group destination. | HTTP decoder tests and OpenAPI three-way `oneOf`. | Pass |
| `M2B2-02` | Group and member reads are exact-scope, snapshot-consistent, freshly authorized, active-only, and bounded. | Resource catalog service/unit tests plus live PostgreSQL compilation. | Pass |
| `M2B2-03` | Expansion is deterministic and preserves one authoring Access Rule ID across member edges. | Compiler and publication artifact tests. | Pass |
| `M2B2-04` | Expansion rejects stale member version/generation, duplicate destination Devices, and more than 10,000 compiled edges. | Catalog/compiler negative paths and domain bounds. | Pass |
| `M2B2-05` | Format 3 binds group version, definition version, group revision/hash, and every member Resource/Device pin without changing formats 1 or 2. | Semantic-hash compatibility and provenance tests. | Pass |
| `M2B2-06` | Publication revalidates the complete active definition and every member under the existing Network transaction boundary. | Migration 44 and PostgreSQL adapter transaction tests. | Pass |
| `M2B2-07` | A group lifecycle race rolls back the candidate release and preserves the prior active release. | Disposable PostgreSQL stale-candidate integration scenario. | Pass |
| `M2B2-08` | Provenance is immutable, forced-RLS, exact-scoped, audited, and least-privilege. | Migration catalog assertions and live database privilege contract. | Pass |
| `M2B2-09` | Browser management recompiles the authoring group selector and clients receive only Node-resolved edges. | Browser publication and map projection integration scenario. | Pass |
| `M2B2-10` | Audit/outbox and revision changes remain atomic with release and provenance writes. | Existing publication transaction plus live rollback/commit evidence. | Pass |
| `M2B2-11` | PostgreSQL remains authority; no graph database, Redis authority, or client selector semantics are introduced. | Dependency and data-flow inspection. | Pass |

## Integration evidence

- The disposable PostgreSQL 18.6 and Redis 8.8.0 platform wrapper applied all
  44 migrations and passed the complete PostgreSQL scenario in 18.396 seconds.
- The scenario created a fresh active Resource Group, compiled it through the
  real catalog, suspended it after compilation, confirmed publication conflict
  and old-release preservation, resumed and recompiled it, published through
  private browser management, persisted member provenance, and loaded the
  Node-resolved map projection.
- The wrapper also passed the qualification tool suite in 1.666 seconds and the
  process/platform integration suite in 9.068 seconds.
- No deployed cluster or production environment was used as evidence.

## Quality evidence

- Focused catalog, compiler, publication, HTTP, OpenAPI, PostgreSQL adapter,
  migration, and integration-build tests pass.
- Repository-wide formatting, `go mod tidy -diff`, `go vet ./...`, unit tests,
  race tests, and workflow lint pass.
- `govulncheck v1.8.0` reports zero reachable vulnerabilities.
- M2b2 introduces no lint finding. Repository-wide lint remains non-zero on the
  same five pre-existing findings recorded by M2a/M2b1/M3c; integration lint
  repeats only the existing `private_identity_factory.go` finding.

## Residual work

- M4 Access Graph explanation, impact preview, and simulation must consume the
  same compiler semantics and immutable provenance.
- M5 routed/service Resources and trusted gateway enforcement remain pending.
- A deployed multi-client traffic matrix remains a separate qualification gate.
- PostgreSQL/Redis infrastructure failover remains outside this engineering
  slice until explicitly reopened.
