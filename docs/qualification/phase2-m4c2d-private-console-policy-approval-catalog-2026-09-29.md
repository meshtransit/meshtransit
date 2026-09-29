# Phase 2 M4c2d private Console Policy approval catalog acceptance matrix

Status date: 2026-09-29

Follow-up: M4c2e later completes the first residual item with a
server-authoritative UUIDv7 management-scope projection. This matrix remains
the historical M4c2d candidate evidence.

This record is engineering evidence for the local private Console catalog and
dispatcher-parity slice. It does not qualify the Console UI, a deployed
workflow, production SLO, HA, legal approval, release, or GA.

## Artifact identity

| Artifact | Qualified value |
| --- | --- |
| Core source base | `6a6dfe4` |
| Core candidate | working tree containing this matrix; exact commit belongs in the delivery report |
| Database migration | none; reuses M4c2c migration `49` and catalog authority |
| Bearer contract | byte-identical `management_v1.json` |
| Private read authority | host-only Core Session plus fresh exact-scope `policy.approve` |
| Mutation authority | unchanged cookie, Origin, explicit channel, and CSRF proof |
| Graph storage | none |

## Acceptance matrix

| ID | Requirement | Evidence | Result |
| --- | --- | --- | --- |
| `M4C2D-01` | Private source document reuses the Bearer approval list/get resource contract. | Deterministic profile composition and field-equivalence contract tests. | Pass |
| `M4C2D-02` | Bearer management bytes remain unchanged. | Existing byte-identity regression test. | Pass |
| `M4C2D-03` | Safe reads require the exact cookie, HTTPS Origin, and explicit Session channel. | OpenAPI security/parameter assertions and browser adapter tests. | Pass |
| `M4C2D-04` | Catalog reads do not accept mutation proof or mutation headers/body. | Closed ingress tests for CSRF, content type, body, ETag, idempotency, and route aliases. | Pass |
| `M4C2D-05` | Every read uses fresh durable Session authentication and shared source/session budgets. | Adapter counters and late freshness checks around the buffered candidate. | Pass |
| `M4C2D-06` | Current exact-scope `policy.approve` remains mandatory. | Reuse of the M4c2c catalog service and handler; no browser-specific authorization branch. | Pass |
| `M4C2D-07` | List filters and pagination remain bounded by the shared contract. | Existing parser/catalog tests plus private list query coverage. | Pass |
| `M4C2D-08` | A maximum 100-item catalog page fits the finite private response buffer. | Explicit maximum-page regression over a 32 KiB payload within the 256 KiB cap. | Pass |
| `M4C2D-09` | Private response memory remains bounded under maximum concurrency. | 256 KiB candidate cap multiplied by the existing 128-request cap equals 32 MiB. | Pass |
| `M4C2D-10` | Reads emit no cookie, Bearer challenge, or navigation authority. | Buffered response assertions for list/get. | Pass |
| `M4C2D-11` | Item ETag and no-store semantics remain unchanged. | Browser item/list response assertions and shared OpenAPI fields. | Pass |
| `M4C2D-12` | Dispatcher owns Policy simulation and all approval routes exactly once. | Dispatcher ownership tests for simulation, proposal, decision, list, and get. | Pass |
| `M4C2D-13` | Unknown methods and aliases perform no authority effect. | Closed ingress and dispatcher alias tests. | Pass |
| `M4C2D-14` | Focused and repository-wide quality gates remain regression-safe. | Executed evidence below. | Pass |

## Executed evidence

- Focused OpenAPI, HTTP adapter, and process-root tests pass 1,429 tests across
  three packages.
- `make fmt-check`, `make tidy-check`, `make vet`, `make test`, and
  `make test-race` pass on the final candidate.
- `govulncheck v1.8.0` reports no reachable vulnerability and
  `actionlint v1.7.12` passes.
- M4c2d introduces no lint finding. Repository-wide lint remains non-zero on
  the same five pre-existing findings recorded by M4c2c; integration-tag lint
  repeats only the existing `private_identity_factory.go` finding.
- The disposable platform runner passes against PostgreSQL 18.6 and Redis 8.8.
  Two earlier attempts reached unrelated existing OIDC verification fixtures
  and returned opaque rejections; a safe timing/status diagnostic was added to
  that helper without logging state, cookie, ciphertext, or code. The final
  complete runner then passes twice consecutively.
- `git diff --check` passes.

## Residual work

- Add a server-authoritative Console management-scope projection that maps the
  signed-in membership to UUIDv7 Workspace and Network public IDs.
- Implement the Console approval queue, detail, independent approval action,
  loading/empty/error states, and accessible confirmation feedback.
- Qualify the deployed same-origin workflow with real PostgreSQL/Redis and two
  independent human Sessions.
- Principal display names, notifications, configurable quorum, production HA,
  SLO, legal, signing, release, and GA remain separate gates.
