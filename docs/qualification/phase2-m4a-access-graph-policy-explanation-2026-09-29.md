# Phase 2 M4a Access Graph active-policy explanation acceptance matrix

Status date: 2026-09-29

This record is non-production engineering evidence for bounded explanation of
active compiled policy. It does not qualify deployed artifacts, policy
simulation, human approval, packet execution, HA, production SLOs, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `ba9eee1` |
| Core candidate | working tree containing this matrix; exact commit belongs in the delivery report |
| Database migration | `45`, forward-only |
| Management operation | `explainActivePolicy` |
| Permission | `policy.explain` |
| Compiler formats | `1`, `2`, and `3`, unchanged |
| Graph storage | none; derived from PostgreSQL active compiled policy |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M4A-01` | One query selects an exact Network, source Device, exactly one Device/Resource target, and exact protocol/port action. | Domain, HTTP decoder, and OpenAPI schema tests. | Pass |
| `M4A-02` | Explanation derives only from the release matching the current policy revision and active compiled edges. | Migration 45 and live PostgreSQL allow/deny scenario. | Pass |
| `M4A-03` | Resource targets resolve to their current active Device in the same repeatable-read snapshot. | SQL target CTE and Resource Group integration scenario. | Pass |
| `M4A-04` | Device, Resource, and Resource Group authoring provenance survives Node-level compilation. | Adapter decoding tests and live group-provenance assertion. | Pass |
| `M4A-05` | No matching edge, release, or active target fails closed to default deny without an existence oracle. | Domain/HTTP negative tests and live UDP deny query. | Pass |
| `M4A-06` | Evidence binds all authority revisions and immutable active-release ID, compiler format, and semantic hash. | Snapshot invariants, API response test, and live release assertions. | Pass |
| `M4A-07` | Paths are deterministic, canonical, unique, query-matching, capped at 64, and explicitly truncated. | Domain canonicalization and 65-path bound test. | Pass |
| `M4A-08` | Fresh exact-scope `policy.explain` authority is checked inside the database read boundary. | Security-definer function, RBAC fixture, and PostgreSQL integration. | Pass |
| `M4A-09` | Runtime has execute-only access while worker and other roles cannot execute the function. | Migration grants and live privilege contract. | Pass |
| `M4A-10` | Bearer and private Console profiles share one resource contract; Console retains origin/channel/CSRF proof. | OpenAPI profile and HTTP browser-admission tests. | Pass |
| `M4A-11` | Responses are no-store, bounded, opaque, and use safe stable error classifications. | HTTP response/negative tests and OpenAPI contract. | Pass |
| `M4A-12` | Process composition fails closed if the explainer dependency is absent. | Handler and private-identity composition tests. | Pass |
| `M4A-13` | PostgreSQL remains sole authority; no graph database, Redis authority, or second evaluator is added. | Dependency and data-flow inspection. | Pass |
| `M4A-14` | Repository quality and disposable platform gates pass. | Final command evidence below. | Pass with recorded pre-existing lint baseline |

## Integration evidence

- The disposable PostgreSQL 18.6 and Redis 8.8.0 wrapper applied all 45
  migrations and passed the complete PostgreSQL scenario in 18.402 seconds.
- The scenario published an active Resource Group policy, read it through the
  runtime-only Access Graph function, verified the exact release/revision/hash
  and group/member provenance, then confirmed an unmatched UDP query returns
  default deny with no paths.
- The wrapper also passed the qualification tool suite in 1.697 seconds and the
  process/platform integration suite in 9.142 seconds.
- No deployed cluster or production environment was used as evidence.

## Quality evidence

- Focused Access Graph domain, HTTP, OpenAPI, PostgreSQL adapter, migration, and
  integration-build tests pass.
- Repository-wide formatting, `go mod tidy -diff`, `go vet ./...`, unit tests,
  race tests, and workflow lint pass.
- `govulncheck v1.8.0` reports zero reachable vulnerabilities.
- M4a introduces no lint finding. Repository-wide lint remains non-zero on the
  same five pre-existing findings recorded by M2a/M2b1/M2b2; integration lint
  repeats only the existing `private_identity_factory.go` finding.

## Residual work

- M4b draft simulation and deterministic before/after impact remain pending.
- M4c durable human approval over unchanged simulation evidence remains pending.
- Historical/reverse graph queries, principal mapping, packet receipts, and a
  Resource Console UI remain outside this slice.
- M5 routed/service Resources and trusted gateway enforcement remain pending.
- Deployed multi-client and HA qualification remain separate gates.
