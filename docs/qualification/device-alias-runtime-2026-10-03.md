# Device alias runtime composition checkpoint (2026-10-03)

This checkpoint composes the guarded PostgreSQL worker from schemas 85–87 into
an owned Core service. It is not a deployed or qualified sharing release.

## Explicit installation settings

Both switches default to false. Control/all replicas may set
`MESHTRANSIT_DEVICE_ALIASES_ENABLED=true` to observe authenticated client v1
claims and read Device aliases and bilateral dependencies. No setting widens
membership, policy, map scope or packet authority.

Worker/all replicas may set:

| Setting | Default | Bound |
| --- | --- | --- |
| `MESHTRANSIT_DEVICE_ALIAS_WORKER_ENABLED` | `false` | Exactly `true` or `false` |
| `MESHTRANSIT_DEVICE_ALIAS_DEPLOYMENT_PUBLIC_ID` | Required when enabled | Canonical UUIDv7 installation assignment |
| `MESHTRANSIT_DEVICE_ALIAS_WORKER_BATCH_SIZE` | `8` | 1–128 visited candidates |
| `MESHTRANSIT_DEVICE_ALIAS_WORKER_POLL_INTERVAL` | `500ms` | 100ms–1min |
| `MESHTRANSIT_DEVICE_ALIAS_WORKER_OPERATION_TIMEOUT` | `10s` | 100ms–15s |

Settings while disabled and invalid role assignments fail startup. The worker
requires the dedicated worker PostgreSQL pool; runtime-table access cannot be
substituted. Schema 87 discovery accepts only cloud installations. Self-host
retains exactly one Workspace and direct same-Workspace sharing. This slice
rejects simultaneous configuration of the legacy gateway worker and the Device
alias worker. It requires no gateway agent URL, TLS key or packet-path service.

## Ownership and observability

Core starts and joins the worker through the existing application service
lifecycle. Each discovery page and each guarded change has its own finite
context. Only committed authoritative state can publish grants. Redis remains
an optional wakeup hint; reconciliation rereads PostgreSQL. Failure is counted
and the next finite sweep rediscovers work.

Five fixed metrics expose running state, discovery passes, discovery errors,
committed changes and deferred changes. They have no labels or installation,
Workspace, Network, endpoint, Device or key identifiers. Generic config logging
redacts the installation assignment.

## Evidence and remaining gates

Whole-tree normal/race tests, vet, normal/integration lint and reachable
vulnerability scans pass. Tests cover opt-in defaults, strict switches, wrong
roles, missing/invalid assignment, disabled settings, finite bounds, config
redaction, invalid worker composition and identifier-free metric exposition.
Schema 1–87 uncached integration/race qualification is recorded separately.

No live POC image, schema, profile or feature flag changed at this checkpoint.
Client opt-in advertisement, complete Core/client runtime qualification,
successor generations, third-Network isolation and imported DNS remain gates.
