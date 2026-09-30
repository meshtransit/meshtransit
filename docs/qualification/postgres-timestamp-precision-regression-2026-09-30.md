# PostgreSQL timestamp precision regression — 2026-09-30

## Observed failure

The disposable Core platform runner initially reached `Resource Sharing
CreateOffer(): sharing: unavailable`. After that boundary was corrected, it
reached `request independent Policy approval` and rejected the idempotency
record as invalid. Both operations compared a Go timestamp with nanosecond
precision to its PostgreSQL `timestamptz` round trip, which retains
microseconds. A successful write could therefore be reported as an invalid
committed result. The existing fail-closed behavior prevented the caller from
using unverified authority.

## Correction and invariant

`sharing.NewCreateOffer` canonicalizes the requested exclusive expiry to UTC
microseconds before hashing, persistence and response matching. Policy Approval
uses one canonical UTC microsecond instant for request/decision events, the
ten-minute request lifetime and idempotency leases. Both transformations round
down, so neither extends an expiry or lease beyond the caller's observed time.
PostgreSQL remains the final authority for Session, permission, revision and
workflow state checks.

## Evidence

- The focused `internal/sharing` and `internal/policy/approval` regression
  tests cover sub-microsecond inputs and committed-result matching.
- `go test -race` passed for `internal/sharing`, `internal/policy/approval`,
  `internal/adapter/postgres` and `internal/adapter/httpapi`; `go vet` passed
  for the same packages, and `make fmt-check` passed.
- `PLATFORM_GO_RUNNER=container bash scripts/ci/run-platform-integration.sh`
  passed with disposable PostgreSQL 18.6 and Redis 8.8. It included migration,
  Resource Sharing, Policy Approval, private OIDC factory, process restart,
  natural expiry and committed-ACK-loss cases. The runner removed its
  containers afterward.

The host-runner attempt failed earlier in synthetic immediate OIDC browser
verification: PostgreSQL time lagged the macOS clock by about 22 ms, and the
strict SQL read correctly rejected a future `created_at`. The container run
uses one clock domain. Native-host clock qualification and deployed browser
testing remain separate gates.

This evidence does not establish a two-human Console workflow, MeshClient
packet behavior, production failover or release readiness.
