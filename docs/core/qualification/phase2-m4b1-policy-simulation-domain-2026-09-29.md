# Phase 2 M4b1 policy simulation domain acceptance matrix

Status date: 2026-09-29

This record is non-production engineering evidence for the M4b1 simulation
domain. It does not qualify a management endpoint, PostgreSQL adapter, durable
approval, deployed artifacts, HA, production SLOs, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `65d9d26` |
| Core candidate | working tree containing this matrix; exact commit belongs in the delivery report |
| Database migration | none |
| Public management operation | none in M4b1 |
| Publication compiler formats | `1`, `2`, and `3`, reused unchanged |
| Graph storage | none |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M4B1-01` | Simulation invokes the publication compiler contract, not an alternate evaluator. | Service dependency shape and actual `compilation.Service` tests. | Pass |
| `M4B1-02` | The complete authority baseline is identical before and after compilation. | Two-read orchestration and drift rejection test. | Pass |
| `M4B1-03` | Current and proposed evidence binds all eight authority revisions. | `RevisionVector` invariants, successor test, and impact hash encoding. | Pass |
| `M4B1-04` | Bootstrap simulation preserves explicit default deny. | Canonical empty format-v1 baseline test. | Pass |
| `M4B1-05` | Added/removed packet authority is deterministic and interval-exact. | Overlapping TCP range delta test (`80-90` to `85-95`). | Pass |
| `M4B1-06` | Explanation/provenance changes remain distinct from effective relationship changes. | Device-to-Resource provenance-only test. | Pass |
| `M4B1-07` | Resource and Group provenance cannot be newer than the stable input vector. | Domain validation on all direct and expanded destinations. | Pass |
| `M4B1-08` | Impact hash binds complete, untruncated evidence and draft semantics. | Domain-separated canonical hash plus deterministic replay test. | Pass |
| `M4B1-09` | Public evidence is bounded while total counts and truncation are explicit. | 257-relationship boundary test. | Pass |
| `M4B1-10` | Unsupported product dimensions are explicit rather than inferred. | Stable six-capability result contract. | Pass |
| `M4B1-11` | Compiler errors remain typed and no false result is emitted. | Compiler conflict and stale-input negative tests. | Pass |
| `M4B1-12` | Simulation has no authority side effects or new datastore. | Dependency and data-flow inspection. | Pass |
| `M4B1-13` | Repository quality gates pass. | Final command evidence below. | Pass with recorded pre-existing lint baseline |

## Focused evidence

- Access Graph and simulation unit tests pass, including deterministic replay,
  exact interval subtraction, provenance-only changes, stale authority,
  bootstrap default deny, explicit truncation, and compiler failure behavior.
- Twenty shuffled focused repetitions pass (380 package-test executions).
- Focused race tests and `go vet` pass.
- Focused `golangci-lint` reports zero findings.
- Repository-wide formatting, `go mod tidy -diff`, `go vet ./...`, unit tests,
  race tests, workflow lint, and `govulncheck` pass.
- `govulncheck v1.8.0` reports zero reachable vulnerabilities.
- M4b1 introduces no lint finding. Repository-wide lint remains non-zero on the
  same five pre-existing findings recorded by M4a; integration lint repeats
  only the existing `private_identity_factory.go` finding.

## Residual work

- M4b2 PostgreSQL baseline reconstruction, authorization, HTTP response, and
  OpenAPI integration remain pending.
- M4c durable approval and publication-time complete-vector CAS remain pending.
- Principal mapping, sensitivity classes, cross-scope paths, Guardrails, share
  intersection, and routed/service Resources remain explicit unsupported
  capabilities.
- Deployed multi-client and HA qualification remain separate gates.
