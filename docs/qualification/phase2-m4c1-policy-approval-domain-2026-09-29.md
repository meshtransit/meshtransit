# Phase 2 M4c1 policy approval domain acceptance matrix

Status date: 2026-09-29

This record is engineering evidence for the local M4c1 domain slice. It does
not qualify PostgreSQL persistence, a management API, enforced publication
approval, a deployed environment, production SLO, HA, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `7796265` |
| Core candidate | working tree containing this matrix; exact commit belongs in the delivery report |
| Domain package | `internal/policy/approval` |
| Required future permissions | proposal reuses `policy.validate`; decision uses existing `policy.approve` |
| Request lifetime | 10 minutes, exclusive |
| Required independent approvals | 1 |
| Persistence/API/publication integration | not present in M4c1 |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M4C1-01` | Proposal uses the production compiler-identical simulator. | `Simulator` port and `Service.Request` orchestration test. | Pass |
| `M4C1-02` | Client acknowledges both candidate semantics and complete impact. | Candidate- and impact-mismatch negative tests stop before transaction allocation. | Pass |
| `M4C1-03` | Approval binds exact Workspace/Network scope. | Binding validation and cross-scope simulator-result rejection. | Pass |
| `M4C1-04` | All eight authority dimensions are bound. | `Binding` stores both complete revision vectors and hash encoding covers each field. | Pass |
| `M4C1-05` | Proposed state is exactly one Policy publication successor. | Inventory-change negative test and `NextPolicy` equality validation. | Pass |
| `M4C1-06` | Authority drift after simulation fails closed. | Locked-baseline mismatch test returns `ErrImpactChanged` before apply. | Pass |
| `M4C1-07` | Proposer and approver are authenticated humans. | Commands require structurally valid Core Account Sessions active at decision time. | Pass |
| `M4C1-08` | Proposer cannot approve their own request. | Same-Principal and same-Session model tests plus service negative test. | Pass |
| `M4C1-09` | Approval cannot alter candidate or impact. | Decision command comparison against locked binding. | Pass |
| `M4C1-10` | Approval is bounded in time and does not extend expiry. | Ten-minute request invariant and exclusive expiry negative test. | Pass |
| `M4C1-11` | Pending and approved evidence have distinct typed identities. | Request ID and immutable approval Evidence ID types plus distinct mutation-ID validation. | Pass |
| `M4C1-12` | Request and decision idempotency are domain separated. | Separate canonical SHA-256 domains and reason/session-fence sensitivity test. | Pass |
| `M4C1-13` | Retries reuse time and durable identities. | Whole-proposal retry test observes one simulation, clock read, and ID allocation. | Pass |
| `M4C1-14` | Transaction cleanup is bounded and cancellation-safe. | Service inspection and failure-path rollback assertions. | Pass |
| `M4C1-15` | Workflow state spelling is closed. | Parser accepts only `pending`, `approved`, and `consumed`. | Pass |
| `M4C1-16` | M4c1 does not mutate packet authority. | Package dependency and contract inspection; no PostgreSQL or publication adapter change. | Pass |
| `M4C1-17` | Focused code quality gates pass. | Final command evidence below. | Pass |

## Focused evidence

- 28 policy approval tests pass in normal and race modes, with 77.9% statement
  coverage.
- All 88 Policy and Access Graph tests pass in normal and race modes.
- Focused `go vet` passes.
- Focused `golangci-lint v2.13.2` reports zero issues.
- Repository-wide format, module-tidy, vet, unit, race, vulnerability, and
  workflow lint gates pass. `govulncheck v1.8.0` finds no reachable
  vulnerability.
- M4c1 introduces no lint finding. Full lint remains at the same five
  pre-existing findings recorded by M4b2; integration-tag lint repeats only
  the existing `private_identity_factory.go` finding.
- The tests cover exact vector succession, candidate/impact mismatch,
  cross-scope simulation output, simulation-to-lock drift, distinct-human
  enforcement, expiry, and stable whole-transaction retry evidence.
- Diff and secret-leakage review contains no newly introduced credential.

## Residual work

- M4c2 PostgreSQL schema, transaction adapters, management endpoints, OpenAPI,
  and runtime composition remain pending.
- Existing policy publication is not yet blocked on approval evidence.
- Publication-time complete-vector CAS, fresh approver-authority validation, and
  single-use approval consumption remain pending.
- Principal projection, sensitivity classes, cross-scope paths, Guardrails,
  share intersection, and routed/service Resources remain explicitly
  unsupported.
- Deployed Console/API, multi-client, HA, production SLO, legal, signing, and
  GA qualification remain separate gates.
