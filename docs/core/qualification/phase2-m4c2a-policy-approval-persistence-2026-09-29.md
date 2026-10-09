# Phase 2 M4c2a policy approval persistence acceptance matrix

Status date: 2026-09-29

This record is engineering evidence for the local M4c2a persistence slice. It
does not qualify management endpoints, enforced publication approval, a
deployed environment, production SLO, HA, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `95d6f14` |
| Core candidate | working tree containing this matrix; exact commit belongs in the delivery report |
| Database migration | `47` — Policy approval persistence |
| Application adapter | `internal/adapter/postgres.PolicyApprovalStore` |
| Proposal permission | existing `policy.validate` |
| Decision permission | existing `policy.approve` |
| Request lifetime/quorum | ten minutes exclusive / one distinct approval |
| Graph storage | none |
| Management API/publication consumption | not present in M4c2a |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M4C2A-01` | PostgreSQL is the sole durable workflow authority. | Migration 47 and adapter dependency inspection; no Redis or graph storage. | Pass |
| `M4C2A-02` | Pending requests bind exact scope and all eight baseline/proposed authority dimensions. | Table constraints, creation function, adapter argument-order test, and record reconstruction. | Pass |
| `M4C2A-03` | Proposed state advances only Network and Policy revision once. | Database vector constraint plus typed `approval.Binding` reconstruction. | Pass |
| `M4C2A-04` | Candidate, compiler format, complete impact, reasons, hashes, quorum, versions, and ten-minute expiry are constrained. | Migration checks and catalog contract test. | Pass |
| `M4C2A-05` | Proposal uses fresh exact-scope `policy.validate` and complete-vector locking. | Exact SQL-order test and authorization argument assertion. | Pass |
| `M4C2A-06` | Approval uses fresh `policy.approve`, request CAS/lock, exclusive expiry, and unchanged candidate/impact. | Decision transaction test, SQL function guards, and SQLSTATE mapping tests. | Pass |
| `M4C2A-07` | Proposer and approver must be distinct active human Sessions and Principals. | Session-fence columns, database revalidation, `MT010` mapping, and typed result validation. | Pass |
| `M4C2A-08` | Approval evidence is immutable and requests permit only closed lifecycle transitions. | Retention trigger, transition trigger, table checks, and integration-tag trigger assertion. | Pass |
| `M4C2A-09` | Runtime has function-only capability; other application roles cannot execute the workflow. | Revoke/grant catalog tests and integration-tag privilege assertions. | Pass |
| `M4C2A-10` | Proposal/decision effects, audit, outbox, and idempotency completion are atomic. | Application-owned transaction implementation and exact SQL-order tests. | Pass |
| `M4C2A-11` | Replays reconstruct typed immutable evidence without direct table reads. | Completed-record scanners and read-only committed resolver test. | Pass |
| `M4C2A-12` | Unknown commit cleanup preserves replay classification. | Idempotent post-commit rollback regression test. | Pass |
| `M4C2A-13` | Authorization, stale state, changed evidence, expiry, self-approval, and transient conflicts fail closed with typed errors. | SQLSTATE classification table and domain validation. | Pass |
| `M4C2A-14` | Every transaction phase has bounded waits and allowlisted metrics. | Store option validation and twelve runtime metric operations. | Pass |
| `M4C2A-15` | Migration integration coverage is ready for a configured disposable database. | Integration-tag forced-RLS, privilege, and trigger assertions compile; local database execution status recorded below. | Pass with environment limitation |
| `M4C2A-16` | Focused code quality gates pass. | Final command evidence below. | Pass |

## Focused evidence

- Adapter, approval domain, and migration catalog tests pass 432 tests in both
  normal and race modes.
- Proposal and decision transaction tests cover exact SQL order, permission,
  vector binding, immutable audit/outbox append, idempotency completion, commit,
  and replay behavior.
- The migration integration target and integration-tag package compile. The
  current session did not set `MESHTRANSIT_MIGRATION_INTEGRATION=1`, so no
  disposable PostgreSQL execution is claimed.
- Repository-wide format, module-tidy, vet, unit, and race gates pass.
  `govulncheck v1.8.0` reports no reachable vulnerability, and workflow lint
  passes.
- M4c2a introduces no lint finding. Repository-wide lint remains non-zero on
  the same five pre-existing findings recorded by M4c1; integration-tag lint
  repeats only the existing `private_identity_factory.go` finding.
- Diff, whitespace, and changed-file secret-pattern review contain no newly
  introduced credential or private-key material.

## Residual work

- Approval proposal/decision HTTP and private-browser contracts plus runtime
  composition remain pending.
- Existing policy publication is not yet blocked on approval evidence.
- M4c2b publication-time complete-vector CAS, fresh approval validation, and
  single-use consumption remain pending.
- Principal projection, sensitivity classes, cross-scope paths, Guardrails,
  share intersection, and routed/service Resources remain explicitly
  unsupported.
- Deployed Console/API, disposable database execution, multi-client, HA,
  production SLO, legal, signing, and GA qualification remain separate gates.
