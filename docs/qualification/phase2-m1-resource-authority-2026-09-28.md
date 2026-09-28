# Phase 2 M1 Resource authority acceptance matrix

Date: 2026-09-28

Scope: MeshCore engineering qualification for the first Resource and Resource
Group authority slice. This matrix is not a production, availability, or GA
claim.

| ID | Acceptance criterion | Evidence | Status |
| --- | --- | --- | --- |
| M1-01 | Stable typed Resource and Resource Group UUIDv7 identities exist. | `internal/resource/id.go`; domain tests. | Pass |
| M1-02 | Device Resource has typed target, owner, custodian, provenance, lifecycle, semantic hash, and target generation. | `internal/resource/model.go`; migration 37 constraints. | Pass |
| M1-03 | Resource Group is Network-scoped, destination-only, versioned, immutable, and bounded. | Domain canonicalization tests; version/member tables; immutable triggers. | Pass |
| M1-04 | Every scope relationship is enforced with composite foreign keys and exact forced RLS. | Migration 37 schema and privilege assertions. | Pass |
| M1-05 | Runtime cannot directly read or mutate authority tables; worker cannot invoke resolvers or writers. | PostgreSQL integration privilege negative tests. | Pass |
| M1-06 | Create requires a live Account Session and `resource.manage` or `resource_group.manage`. | Adapter authorization path; missing-membership integration negative. | Pass |
| M1-07 | Creator is initial owner and custodian; unreviewed delegation is rejected. | Command validation and unit negative test. | Pass |
| M1-08 | Inventory/group compare-and-swap rejects stale revisions. | Service unit test and PostgreSQL stale-revision integration test. | Pass |
| M1-09 | Group membership rejects stale Resource version/target generation and cross-scope IDs. | Domain and PostgreSQL integration negative tests. | Pass |
| M1-10 | Authority, Network revision, subsystem revision, audit, and outbox commit atomically. | Deferred evidence constraint and incomplete-evidence rollback integration test. | Pass |
| M1-11 | Retry reuses stable IDs and decision time; uncertain commits use a stable-ID resolver. | Application service unit test; PostgreSQL replay resolver. | Pass |
| M1-12 | Migration is forward-only, embedded, checksummed, idempotently applied, and runtime-compatible. | Migration catalog tests and disposable PostgreSQL migration fixture. | Pass |
| M1-13 | Go formatting, module tidiness, vet, full unit tests, race tests, and focused integration gates pass. | Final command evidence in the delivery report. | Pass |
| M1-14 | No management HTTP route or UI is introduced in M1. | Repository diff. | Pass |
| M1-15 | Documentation does not claim data-service failover or multi-node/AZ/region HA. | This matrix and M1 design non-claims. | Pass |

## Residual limitations

- Device is the only Resource kind.
- One active Device can back only one active Resource in this initial slice.
- Resource and Resource Group creation are application/adapter capabilities, not
  yet public management API contracts.
- Ownership transfer, target rebinding, lifecycle transitions, and new immutable
  Resource Group versions are not exposed by an application use case.
- Resource Groups are not yet consumed by Access Graph or packet-policy
  compilation.
- Connector inventory, sharing/export, UI, and search/list pagination are not
  implemented.
- PostgreSQL and Redis infrastructure failover remain intentionally outside this
  milestone.

## Next order

1. M2: read/list and mutation API contracts with ETags, idempotency, rate limits,
   pagination, and resource-safe error shapes.
2. M3: Resource lifecycle, target rebinding, immutable Resource Group replacement,
   and ownership/custodianship workflows.
3. M4: Access Graph references and explain/simulate/verify semantics.
4. M5: policy compilation and client projection from stable Resource authority.
5. Later gates: connector ingestion, sharing/export, Console UX, and separate
   production availability qualification.
