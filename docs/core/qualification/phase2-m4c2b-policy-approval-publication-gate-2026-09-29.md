# Phase 2 M4c2b policy approval publication gate acceptance matrix

Status date: 2026-09-29

This record is engineering evidence for the local M4c2b atomic publication
gate. It does not qualify proposal/decision management endpoints, a deployed
Console workflow, production SLO, HA, legal approval, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `7225786` |
| Core candidate | working tree containing this matrix; exact commit belongs in the delivery report |
| Database migration | `48` — Policy approval publication gate |
| Publication adapter | `internal/adapter/postgres.PolicyPublicationStore` in explicit required mode |
| Publication wire field | required `approval_evidence_id` UUIDv7 |
| Publisher permission | `policy.publish` |
| Fresh approver permission | `policy.approve` |
| Approval lifecycle | `approved` version 2 to `consumed` version 3 |
| Graph storage | none |
| Approval proposal/decision API | not present in M4c2b |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M4C2B-01` | Production management publication requires an approval Evidence ID. | Required composition mode, approved-command constructor, HTTP and OpenAPI contract tests. | Pass |
| `M4C2B-02` | Store configuration cannot silently default to fail-open behavior. | Invalid zero mode and explicit required/bypass constructor tests. | Pass |
| `M4C2B-03` | Publication locks and compares all eight authority dimensions. | Typed `AuthorityVector`, migration function, SQL order tests, and live stale-group integration scenario. | Pass |
| `M4C2B-04` | Evidence binds exact scope, candidate semantic hash, compiler format, and complete impact hash. | `ApprovalGate` validation, adapter scanning, consume function, and mismatch tests. | Pass |
| `M4C2B-05` | Only approved version-2 requests with immutable version-1 Evidence are eligible. | Lock-function filters, typed gate validation, and migration constraints. | Pass |
| `M4C2B-06` | Publication observes the exclusive ten-minute Evidence deadline. | Decision/expiry guards in SQL and domain validation. | Pass |
| `M4C2B-07` | The retained approver is freshly authorized for exact-scope `policy.approve`. | Publication-time permission resolution and separate least-privilege approver integration role. | Pass |
| `M4C2B-08` | Publisher and approver authority remain independent. | Separate `policy.publish` and `policy.approve` resolution; integration assertions deny the opposite permission to each role. | Pass |
| `M4C2B-09` | Release activation and approval consumption are one transaction. | Apply SQL order, request release foreign key, rollback behavior, and live integration result. | Pass |
| `M4C2B-10` | Consumption verifies the newly active release and exact proposed vector. | Migration 48 consume function and catalog contract tests. | Pass |
| `M4C2B-11` | Evidence is single-use. | Live second-use rejection as `ErrApprovalUnavailable` plus consumed version-3 row assertion. | Pass |
| `M4C2B-12` | Stale authority cannot consume Evidence or alter the active release. | Live Resource Group suspend-after-approval scenario leaves the request approved and release unchanged. | Pass |
| `M4C2B-13` | Unknown commit replay binds the exact Evidence ID. | Committed-release join and replay mismatch tests. | Pass |
| `M4C2B-14` | Publication audit evidence binds both humans and the full approval proof. | Bounded audit payload test for IDs, impact, vectors, and approver role/session generations. | Pass |
| `M4C2B-15` | Approval failure does not disclose record, state, or authority details. | SQLSTATE mapping and HTTP `409 approval_conflict` classification tests. | Pass |
| `M4C2B-16` | Runtime alone can execute the two new functions and no role gains direct table access. | Catalog tests and live `pg_proc`/ACL integration assertions. | Pass |
| `M4C2B-17` | Browser publication uses compiler-identical rules and exact Evidence. | Live private-browser allow, deny-all, restore, Resource, and Resource Group publications. | Pass |
| `M4C2B-18` | Existing trusted qualification is explicit and cannot become a production default. | Qualification-bypass mode only on named offline compositions; production compositions use required mode. | Pass |
| `M4C2B-19` | Expanded legitimate outbox backlog still converges through process restart qualification. | Platform integration runner drains the bounded backlog and passes restart/replay tests. | Pass |
| `M4C2B-20` | Repository quality and security gates pass or preserve only documented pre-existing findings. | Final command evidence below. | Pass |

## Executed evidence

- `make integration-platform-container` passes against owned disposable
  PostgreSQL 18.6 and Redis 8.8 containers. Migration 48 is applied before the
  live request, independent approval, browser publication, consumed-state,
  stale-vector, Evidence-reuse, and process-restart scenarios.
- Approval/publication unit tests cover malformed and missing Evidence,
  complete-vector validation, exact SQL order, fresh approver authorization,
  consumption-before-audit, audit payload binding, replay Evidence matching,
  SQLSTATE concealment, required-mode configuration, and HTTP/OpenAPI behavior.
- Migration catalog and live integration assertions cover both new
  `SECURITY DEFINER` functions, fixed runtime-only execute capability, no
  `PUBLIC` execute grant, forced RLS inherited from M4c2a, and the version-3
  consumed lifecycle.
- `make fmt-check`, `make tidy-check`, `make vet`, `make test`, and
  `make test-race` pass on the final working candidate.
- `govulncheck v1.8.0` reports no reachable vulnerability and
  `actionlint v1.7.12` passes.
- M4c2b introduces no lint finding. Repository-wide lint remains non-zero on
  the same five pre-existing findings recorded by M4c2a; integration-tag lint
  repeats only the existing `private_identity_factory.go` finding.
- `git diff --check` passes. Changed-file review contains no introduced
  credential, bearer token, private key, or secret material.

## Residual work

- Proposal, list/get, and independent approval-decision HTTP/private-browser
  contracts plus production runtime composition remain M4c2c.
- Console UI, notifications, configurable quorum, and approval policy
  administration remain pending.
- Principal projection, sensitivity classes, cross-scope paths, Guardrails,
  share intersection, routed/service Resources, and a second evaluator remain
  explicitly unsupported.
- Multi-client deployment, production PostgreSQL failover, HA, production SLO,
  legal, signing, release, and GA qualification remain separate gates.
