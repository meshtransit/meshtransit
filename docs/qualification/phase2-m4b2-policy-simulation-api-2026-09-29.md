# Phase 2 M4b2 policy simulation persistence and API acceptance matrix

Status date: 2026-09-29

This record is engineering evidence for the local M4b2 slice. It does not
qualify a deployed environment, durable approval, production SLO, HA, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `48233c9` |
| Core candidate | working tree containing this matrix; exact commit belongs in the delivery report |
| Database migration | `46` — Policy simulation active baseline |
| Public operation | `simulatePolicy` |
| Required permission | `policy.validate` |
| Publication compiler formats | `1`, `2`, and `3`, reconstructed and rehashed |
| Graph storage | none |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M4B2-01` | PostgreSQL remains the only baseline authority. | Migration 46 and repeatable-read adapter inspection. | Pass |
| `M4B2-02` | Baseline reads require fresh exact-scope `policy.validate`. | Security-definer resolver call, application timestamps, and opaque forbidden mapping. | Pass |
| `M4B2-03` | Runtime receives no direct table capability. | Migration grant/revoke contract tests. | Pass |
| `M4B2-04` | Active formats 1/2/3 reconstruct with complete Resource/Group provenance. | Adapter reconstruction tests, including two-member Group plus direct Resource. | Pass |
| `M4B2-05` | Durable semantic evidence is independently verified. | Recomputed candidate hash and mismatch rejection test. | Pass |
| `M4B2-06` | Bootstrap remains canonical format-v1 default deny. | No-release reconstruction test. | Pass |
| `M4B2-07` | Stale `If-Match` stops before compiler invocation. | Simulation service stale-base test. | Pass |
| `M4B2-08` | HTTP uses the publication rule schema without mutation-only fields. | Shared rule decoder, unknown-field rejection, and no-reason test. | Pass |
| `M4B2-09` | Response exposes complete counts, bounded evidence, full impact hash, and capability gaps. | Successful endpoint response test and OpenAPI schemas. | Pass |
| `M4B2-10` | Sensitive simulation evidence is non-cacheable. | HTTP header test and OpenAPI response contract. | Pass |
| `M4B2-11` | Bearer and private Console sources share one protected operation contract. | Composition/profile tests and browser admission dispatch. | Pass |
| `M4B2-12` | Authorization, stale input, corruption, and outage fail closed with safe errors. | HTTP classification table and adapter error tests. | Pass |
| `M4B2-13` | Simulation performs no policy publication or authority write. | Dependency graph and success-path endpoint test. | Pass |
| `M4B2-14` | Focused code quality gates pass. | Final command evidence below. | Pass |

## Focused evidence

- Migration, PostgreSQL adapter, simulation domain, HTTP management, OpenAPI,
  and public/private composition qualification passes 1,799 focused tests in
  both normal and race modes; focused `go vet` passes.
- Repository-wide format, module-tidy, vet, unit, race, vulnerability, and
  workflow lint gates pass. `govulncheck v1.8.0` finds no reachable
  vulnerability.
- M4b2 introduces no lint finding. Full lint remains at the same five
  pre-existing findings recorded by M4b1; integration-tag lint repeats only
  the existing `private_identity_factory.go` finding.
- The migration integration target and integration-tag production composition
  compile and return successfully; the current session did not activate a
  disposable PostgreSQL execution environment.
- Diff and secret-leakage review contains no newly introduced credential.

## Residual work

- Disposable PostgreSQL execution of migration 46 and end-to-end simulation is
  still required when the integration database gate is available.
- M4c durable approval and publication-time complete-vector CAS remain pending.
- Principal projection, sensitivity classes, cross-scope paths, Guardrails,
  share intersection, and routed/service Resources remain explicitly
  unsupported.
- Deployed Console/API, multi-client, HA, production SLO, legal, signing, and
  GA qualification remain separate gates.
