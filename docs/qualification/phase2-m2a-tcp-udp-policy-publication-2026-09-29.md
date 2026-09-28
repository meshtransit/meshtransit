# Phase 2 M2a TCP/UDP policy publication acceptance matrix

Status date: 2026-09-29

This record is non-production engineering evidence for Device-to-Device TCP/UDP
policy. It does not qualify a deployed image, Resource selector compilation,
HA, data-service failover, cross-platform enforcement, production SLOs, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `3646b3d` |
| Core candidate | commit containing this matrix; exact commit is recorded in the delivery report |
| Client source | `484cb397cde7d1a9e199035cd1360127189319c2` |
| Compiler format | `1` |
| Client profile | `legacy-ts2021-cap142-v1` |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M2A-01` | Only explicit TCP, UDP, and fixed-profile ICMP are accepted; wildcard protocols fail closed. | `internal/policy/protocol_test.go`; HTTP negative tests. | Pass |
| `M2A-02` | TCP/UDP ports are bounded to 1-65535 and at most 64 input ranges per rule. | Domain boundary tests plus HTTP zero/overflow rejection. | Pass |
| `M2A-03` | Equivalent range/rule order produces deterministic normalized policy, semantic hash, and map bytes. | Rule/snapshot/artifact tests and reversed-input map encoding test. | Pass |
| `M2A-04` | Projection emits exact TCP/UDP protocol numbers and destination ranges. | `TestEncodeFullMapResponseProjectsTCPAndUDPPortRanges`. | Pass |
| `M2A-05` | Projection is Node-reduced; outbound-only authority is not emitted as local inbound authority. | Existing outbound-only test plus inbound transport fixture. | Pass |
| `M2A-06` | Empty policy is explicit deny-all and clears prior client authority. | Full/delta map explicit-empty tests and PostgreSQL lifecycle scenario. | Pass |
| `M2A-07` | Allow, deny-all, and TCP/UDP restore activate atomically with audit/outbox/revisions. | Disposable `TestPostgreSQLMigrations` policy lifecycle. | Pass |
| `M2A-08` | A stale candidate or stale deny-all request creates no replacement release. | Publication service/unit adapter tests and lifecycle replay after restore. | Pass |
| `M2A-09` | PostgreSQL is authoritative and Redis loss cannot widen access. | Publication store and map loader path inspection; no Redis policy input. | Pass |
| `M2A-10` | `meshd` enforces IPv4/IPv6 TCP/UDP ports and clears tracked return-flow authority on policy changes. | 208 focused client tests in `internal/dataplane`, `internal/networkmap`, and `internal/compat/ts2021`. | Pass |
| `M2A-11` | Core focused policy, HTTP, and projection suites pass. | 1,295 tests across four packages. | Pass |
| `M2A-12` | Integration-tag compilation and disposable PostgreSQL migration/publication scenario pass. | Integration compile succeeded; `TestPostgreSQLMigrations` passed in 18.129 s on the second disposable run. | Pass |

## Gate notes

- The first disposable run stopped before policy publication at a pre-existing
  OIDC browser-verification timing assertion (`created_after_database_now=true`,
  approximately 27 ms clock offset). No gate was weakened; the second run passed
  the complete migration/publication scenario.
- In that second wrapper run, a later unrelated process-restart case failed
  because its disposable PostgreSQL dependency became unavailable. The M2a
  PostgreSQL test had already passed. The final delivery report records the full
  unit, race, vet, tidy, lint, vulnerability, and wrapper rerun outcomes without
  converting unrelated failure into a pass.
- The current POC cluster and image were not changed or used as evidence.

## Final command evidence

- Formatting, `go mod tidy -diff`, and `go vet ./...` pass.
- `go test ./...` and `go test -race ./...` each pass 4,441 tests across
  56 packages.
- Core focused policy, HTTP, and projection tests pass 1,295 tests across four
  packages. The pinned `meshd` policy/network-map/compatibility selection passes
  208 tests across three packages.
- Integration-tag compilation passes. The second disposable platform run passes
  the complete PostgreSQL migration/publication scenario in 18.129 seconds,
  including the M2a lifecycle.
- `govulncheck v1.8.0` reports zero reachable vulnerabilities.
- M2a introduces no lint finding. Repository-wide lint remains non-zero on the
  same five pre-existing findings recorded by M3c; integration lint repeats only
  the existing `private_identity_factory.go` finding.

## Residual work

- M2b must resolve Resource and Resource Group destinations under exact scope,
  pin every Resource version/target generation and Group definition version,
  and revalidate those facts inside the publication transaction.
- A disposable live two-client TCP/UDP matrix on immutable Core/client artifacts
  remains a deployment qualification gate.
- PostgreSQL/Redis infrastructure failover remains paused by owner direction.
