# MeshTransit Core

MeshTransit Core is the product-owned MeshTransit control plane. This checkout
currently contains the Phase 1 platform spine: validated process configuration,
runtime role selection, bounded lifecycle management, safe JSON logging,
health/readiness endpoints, and TLS-only PostgreSQL and Redis dependency
adapters. It also contains the forward-only PostgreSQL migration foundation and
the first canonical authority schema for tenancy, network identity, address
realms, address pools, prefixes, and revision state. Authority changes are
guarded by an atomic audit/outbox integrity foundation. The repository does not
contain serving mutations or product protocol implementations yet. Redis
already exposes the bounded, versioned `NetworkRevisionAdvanced` wakeup
transport, and the worker PostgreSQL adapter can lease, reconcile, and complete
the matching durable outbox work without treating Redis as authority.

The module path is `github.com/meshtransit/meshtransit`; the process binary
is `meshcore`. Development and security gates run with Go 1.26.8.

Run `meshcore version` for machine-readable build, revision, Go, and
configuration-schema versions. Run `meshcore config validate` to validate the
selected role, bounded values, secret files, and CA bundles without dialing a
dependency or opening a listener. The process serves normally with either no
arguments or the explicit `meshcore serve` command.

Database migrations are explicit one-shot operations: use
`meshcore migrate status` to inspect compatibility and `meshcore migrate up` to
apply every known pending migration. Normal `serve` startup never applies or
repairs migrations.

## Runtime configuration

Configuration is read once at process startup. An explicitly set empty or
invalid value stops startup before a listener is opened.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_ROLE` | `all` | One of `all`, `api`, `control`, `worker`, or `relay`. |
| `MESHTRANSIT_HEALTH_ADDRESS` | `127.0.0.1:8081` | TCP host and non-zero port for the operator health listener. |
| `MESHTRANSIT_SHUTDOWN_TIMEOUT` | `15s` | Drain deadline from 1 second through 5 minutes. |
| `MESHTRANSIT_LOG_LEVEL` | `info` | One of `debug`, `info`, `warn`, or `error`. |
| `MESHTRANSIT_DEPENDENCY_CHECK_TIMEOUT` | `2s` | Per-dependency check deadline from 100ms through 30s. Must be below the interval. |
| `MESHTRANSIT_DEPENDENCY_CHECK_INTERVAL` | `10s` | Dependency polling interval from 1 second through 5 minutes. |

The `api`, `control`, and `worker` responsibilities require the shared
PostgreSQL and Redis settings below. The `api` and `control` roles additionally
require the runtime PostgreSQL credential; `worker` requires the worker
credential; and `all` requires both. Runtime and worker credentials open
separate least-privilege connection pools and are never used interchangeably.
The `relay` role intentionally does not load or require direct storage settings.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_POSTGRES_ADDRESS` | none | PostgreSQL TLS host and non-zero port. |
| `MESHTRANSIT_POSTGRES_DATABASE` | none | PostgreSQL database name. |
| `MESHTRANSIT_POSTGRES_CA_FILE` | none | Absolute path to the trusted CA bundle. |
| `MESHTRANSIT_POSTGRES_RUNTIME_USER` | none | Least-privilege PostgreSQL role used by `api` and `control`. |
| `MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE` | none | Absolute path to the runtime role's bounded, single-line credential file. |
| `MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS` | `10` | Runtime pool cap from 1 through 50. |
| `MESHTRANSIT_POSTGRES_WORKER_USER` | none | Least-privilege PostgreSQL role used by `worker`. |
| `MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE` | none | Absolute path to the worker role's bounded, single-line credential file. |
| `MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS` | `10` | Worker pool cap from 1 through 50. |
| `MESHTRANSIT_REDIS_ADDRESS` | none | Redis TLS host and non-zero port. |
| `MESHTRANSIT_REDIS_USERNAME` | none | Redis ACL username. |
| `MESHTRANSIT_REDIS_PASSWORD_FILE` | none | Absolute path to a bounded, single-line credential file. |
| `MESHTRANSIT_REDIS_CA_FILE` | none | Absolute path to the trusted CA bundle. |
| `MESHTRANSIT_REDIS_POOL_SIZE` | `10` | Per-process active-connection cap from 1 through 50. |

The `worker` and `all` roles also load the bounded Network-revision delivery
settings below. A batch is leased as one ordered unit, so the lease must exceed
`batch size * 3 * operation timeout`; this preserves enough worst-case budget
for load/publish/finish work without relying on an unbounded goroutine fan-out.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_NETWORK_REVISION_BATCH_SIZE` | `8` | Ordered claim size from 1 through 256. |
| `MESHTRANSIT_NETWORK_REVISION_LEASE` | `30s` | Fenced claim lifetime from 1 second through 5 minutes and above the batch operation budget. |
| `MESHTRANSIT_NETWORK_REVISION_POLL_INTERVAL` | `1s` | Idle polling interval from 100ms through 1 minute. |
| `MESHTRANSIT_NETWORK_REVISION_RETRY_DELAY` | `5s` | Delay after a failed delivery from 100ms through 24 hours. |
| `MESHTRANSIT_NETWORK_REVISION_OPERATION_TIMEOUT` | `1s` | Per PostgreSQL or Redis call deadline from 100ms through 30 seconds. |

Passwords are never accepted as direct environment values or DSN fragments.
Credential and CA files are loaded before listeners open, and file references
format as redacted values.

## Database migrations

Migration commands use a separate, narrowly privileged PostgreSQL identity and
never fall back to runtime database credentials. All fields below are validated
before a network connection is opened.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_MIGRATION_POSTGRES_ADDRESS` | none | PostgreSQL TLS host and non-zero port. |
| `MESHTRANSIT_MIGRATION_POSTGRES_DATABASE` | none | Disposable or target database name. |
| `MESHTRANSIT_MIGRATION_POSTGRES_USER` | none | Dedicated SCRAM-SHA-256 migration role. |
| `MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE` | none | Absolute path to a bounded, single-line credential file. |
| `MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE` | none | Absolute path to the trusted CA bundle. |
| `MESHTRANSIT_MIGRATION_ACTOR` | none | Stable, non-secret deployment actor written to migration metadata. |
| `MESHTRANSIT_MIGRATION_CONNECT_TIMEOUT` | `5s` | Direct connection timeout from 100ms through 30s. |
| `MESHTRANSIT_MIGRATION_LOCK_TIMEOUT` | `5s` | Transaction-local lock timeout from 100ms through 30s. |
| `MESHTRANSIT_MIGRATION_STATEMENT_TIMEOUT` | `30s` | Transaction-local statement timeout from 1 second through 10 minutes; must exceed the lock timeout. |

The migrator requires PostgreSQL 16 or newer, an installed `btree_gist`
extension at an explicitly supported version, and a role without superuser,
database creation, role creation, replication, or row-level-security bypass
attributes. It must own the target database but must not hold role memberships.
It uses a direct TLS connection, takes a transaction-scoped advisory lock, and
records each embedded migration and checksum in the same transaction as its
DDL. Concurrent runners therefore serialize without leaving a durable lock
behind.

Database roles are operator-provisioned before the first migration. The
migrator deliberately cannot create or alter them. Migration preflight requires
the exact privilege shape below and fails closed if a role is missing, has an
elevated attribute, or participates in any role membership.

| Role | Login | Ownership and grants after migration `000004` |
| --- | --- | --- |
| `mesh_migrator` | yes | Owns the target database and migration-created objects. |
| `mesh_runtime` | yes | Scope-filtered reads for serving processes; owns no database or MeshTransit object. |
| `mesh_worker` | yes | Scope-filtered tenant reads plus column-limited outbox claim/delivery operations; owns no database or MeshTransit object. |
| `mesh_audit_writer` | no | Reserved for a future audited write path; currently no grants. |
| `mesh_share_writer` | no | Reserved for a future sharing write path; currently no grants. |
| `mesh_observer` | yes | Reserved for a future observability contract; currently no grants. |

Migration history is immutable and forward-only. Unknown future versions,
missing or changed checksums, failed records, dirty state, and incompatible
reader/writer generations fail closed. Runtime PostgreSQL readiness also checks
this contract after connectivity; it never attempts repair. The first migration
creates only the `mesh`, `mesh_ops`, and `mesh_audit` namespaces plus migration,
compatibility, and backfill-operation metadata. Migration `000002` creates the
deployment, principal, workspace, network, address-realm, address-pool,
network-prefix, and network-revision authority tables. Composite foreign keys
prevent cross-scope references and GiST exclusions prevent overlapping active
CIDRs inside one address realm while allowing overlap between isolated realms.

Migration `000003` adds the durable outbox, immutable authority-mutation ledger,
non-partitioned audit identity spine, monthly audit payload partitions, and
per-scope audit stream heads. Each critical authority-table change requires a
fresh transaction-local UUIDv7 change identifier. A deferred constraint trigger
rejects commit unless the same transaction also contains a matching audit event
and outbox event. Stream sequence and previous-hash compare-and-swap serialize
only the affected audit stream. Audit and outbox JSON payloads are bounded to
16 KiB. Serving identities cannot read, append, or mutate these records; the
append capability remains restricted to the migration identity until an
authorized application write path is introduced.

Migration `000004` enables only the worker delivery surface. `mesh_worker` can read
non-payload outbox metadata, update lease/lifecycle columns, and append
immutable delivery attempts; it still cannot update event identity or payload,
read attempt history, delete/truncate records, or use audit DML. Claims use
ordered bounded batches with `FOR UPDATE SKIP LOCKED`, expiring leases, and a
CSPRNG fencing token. Revision reconciliation opens a read-only transaction,
sets one exact Workspace/Network RLS scope, and publishes the current durable
revision rather than trusting a stale notification value. Delivered and retry
outcomes update the event and append attempt evidence atomically.

`mesh_runtime` receives no direct `INSERT`, `UPDATE`, or `DELETE` grants.
Tenant reads for serving roles are protected by forced row-level security using transaction-local
`mesh.workspace_id` and `mesh.network_id` settings; missing, malformed, or
cross-paired scope fails closed. Runtime readiness also rejects an elevated,
object-owning, member role or a connection whose authenticated user differs
from configuration. The process lifecycle owns the revision dispatcher only for
the `worker` and `all` roles. It starts exactly one polling goroutine, processes
bounded claims sequentially, cancels in-flight I/O during shutdown, and joins
before Redis and PostgreSQL are closed. Authorization-aware serving mutations
remain deferred to later vertical slices.

`all` expands to the `api`, `control`, `worker`, and `relay` responsibilities.
This slice deliberately does not implement their business protocols yet; role
selection changes the declared process responsibility without creating empty
domain packages.

## Authorization foundation

The `internal/authorization` package owns the complete 72-entry v1 management
permission catalog and a pure scoped-grant evaluator. Permissions are exact
stable identifiers; wildcard or unknown permissions are rejected. Evaluation
uses validated UUIDv7 Principal, Deployment, Workspace, and Network IDs and a
fully qualified target scope, so a matching name or identifier in another
Workspace cannot inherit authority.

The evaluator is deny-by-default, considers at most 256 resolved grants, and
rejects revoked, expired, stale-generation, malformed, or cross-scope
authority. The current catalog permits exact-scope grants only. Parent-to-child
application remains fail-closed until the permission-specific inheritance
matrix is approved; Deployment permissions never expose tenant scope by
default. Decision reason codes are stable internal audit classifications and
must map to a generic public forbidden response where revealing grant state
would disclose hidden authority.

An allowed scoped-grant decision is one step in the authorization pipeline, not
a final mutation approval. Authentication, active membership, delegation
ceiling, operation invariants, Approval Policy, step-up evidence, ETag/CAS, and
the atomic audit/outbox transaction remain mandatory. Built-in/custom roles,
bindings, approval persistence, and management HTTP endpoints are deliberately
deferred until their storage and authentication slices are implemented.

## Health surface

The operator listener exposes:

- `GET /live`: process listener is responsive;
- `GET /ready`: configured work may be admitted;
- `GET /health`: redacted runtime component summary;
- `GET /metrics`: Prometheus/OpenMetrics runtime and operator telemetry.

Worker and `all` processes additionally expose bounded Network-revision worker
signals: ready backlog depth, oldest ready-event age, backlog observation and
claim outcomes, claimed-event count, and delivery outcomes. Outcome labels are
closed sets (`success`/`error` and `delivered`/`deferred`/`failed`); event,
Workspace, Network, and worker identifiers are never metric labels.

Readiness opens only after the initial PostgreSQL and Redis checks succeed and
the listener starts. Periodic bounded checks lower readiness on dependency loss
and restore it after recovery. Graceful shutdown closes admission before
draining the listener, joining the monitor, and releasing Redis then PostgreSQL.
`/live` never depends on infrastructure availability. Health responses expose
only stable component names and `ready`, `unavailable`, or `unknown` states.
The listener defaults to loopback and should not be exposed on public client
ingress.

Metrics use a process-owned registry rather than global mutable collectors.
They include Go/process signals, build information, concrete roles, runtime and
dependency readiness, and operator HTTP request count/duration. Labels are
restricted to fixed routes, HTTP status classes, closed role names, and known
component names. Unknown request paths collapse to `not_found`; addresses,
hostnames, raw paths, configuration values, and error text are never labels.
The endpoint inherits the bounded operator-server timeouts and returns
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

## Development gates

Run individual gates with `make fmt-check`, `make tidy-check`, `make vet`,
`make test`, `make test-race`, `make lint`, and `make vuln`. `make quality` runs
the complete bootstrap set. The lint and vulnerability commands pin tool
versions for reproducible execution with the module's Go 1.26.8 baseline.

`make integration-deps` runs the build-tagged TLS/auth dependency test when
`MESHTRANSIT_INTEGRATION=1` and the required file-backed settings above are
present. It performs health round trips only and never creates application
schema or data.

`make integration-migrations` runs the build-tagged migration test when
`MESHTRANSIT_MIGRATION_INTEGRATION=1` and the separate migration settings above
point to an empty disposable database. It starts two concurrent migration
runners, proves exactly one application wins, checks clean compatibility, and
verifies that a repeat run is a no-op. It also exercises RLS isolation and the
audit/outbox commit, rollback, UUID reuse, immutability, sequence, and hash-chain
invariants, plus real worker claim/reconciliation/delivered/retry behavior.
Never point this test at a shared or production database.
`make integration-migrations-container` provisions the same isolated PostgreSQL
18.6 TLS/SCRAM fixture used by CI and removes it when the test exits.

## Container image

`make container-build` creates `manhdev2002/meshtransit-core:dev` by default.
Override `CONTAINER_IMAGE`, `CONTAINER_TAG`, or `CONTAINER_PLATFORM` without
editing repository files. `make container-inspect` verifies the numeric
non-root identity and fixed entrypoint, `make container-smoke` exercises the
relay health surface under a read-only filesystem with all Linux capabilities
dropped, and `make container-scan` rejects High or Critical findings. Use
`make container-build-multiarch` to compile both Linux amd64 and arm64 images
without publishing them.

The image uses a digest-pinned Go 1.26.8 builder and a `scratch` runtime. It has
no shell or package manager, contains only the static binary, public CA bundle,
and third-party notices, and runs as UID/GID `65532:65532`. The health listener
remains bound to loopback unless `MESHTRANSIT_HEALTH_ADDRESS` is explicitly
changed. Storage roles must receive credential and private CA files through
read-only mounts;
credentials must not be baked into the image or supplied as environment
values.

The repository workflow builds, inspects, smoke-tests, and scans the image but
never pushes it. Publishing is a separate, explicitly authorized release
operation and should use an immutable version tag plus the resulting digest.
Release automation should pass the source commit through `CONTAINER_REVISION`;
the workflow already records its Git commit in the OCI image metadata.
