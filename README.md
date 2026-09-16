# MeshTransit Core

MeshTransit Core is the product-owned MeshTransit control plane. This checkout
currently contains the Phase 1 platform spine: validated process configuration,
runtime role selection, bounded lifecycle management, safe JSON logging,
health/readiness endpoints, TLS-only PostgreSQL and Redis dependency adapters,
and a bounded TLS plus authenticated Noise client-control ingress. It also
contains the forward-only PostgreSQL migration foundation and
the first canonical authority schema for tenancy, network identity, address
realms, address pools, prefixes, and revision state. Authority changes are
guarded by an atomic audit/outbox integrity foundation. The current client
protocol slice exposes control-key discovery, credential-backed registration,
authenticated Node-key rotation, and authenticated one-shot and streaming
full-map snapshots. Every snapshot
contains the authoritative self Node, only packet-policy-authorized peers, and
the Node-reduced inbound packet filter; explicit empty collections clear prior
client state. Long-lived streams use generation-fenced Redis presence, bounded
keepalives, exact release, process-owned revision and connectivity feeds, and
periodic PostgreSQL plus Redis resync. One-shot endpoint updates validate and
record canonical generation-fenced discovery keys and endpoint sets in Redis.
Maps project exact-generation endpoint and online observations only after
PostgreSQL membership and packet policy authorize the peer. Redis exposes
bounded, versioned `NetworkRevisionAdvanced` and connectivity-change wakeup
transports. A control replica holds one subscription for each feed and fans
wakeups into bounded, coalescing Network-local channels. PostgreSQL remains the
source of peer visibility and packet authority; Redis loss never widens access.
Same-revision endpoint and online changes use bounded complete-node deltas;
authority, DNS, and relay deltas, durable endpoint history, and relay behavior
are not implemented.
The first versioned management HTTPS route authenticates an opaque Account
Session and atomically revokes one exact Device under `device.manage`, strong
ETag, and HMAC-protected idempotency constraints. A committed revocation
advances the Network revision and writes its outbox event in the same
transaction; the worker publishes that wakeup and live control streams resync
immediately, while periodic reconciliation remains the recovery path.
Source and authenticated-session request budgets are enforced atomically in
Redis before authority mutation. Counter identities are purpose-separated
HMACs; Redis failure closes management admission rather than bypassing it.
The worker PostgreSQL adapter leases, reconciles, and completes the matching
durable outbox work without treating Redis as authority.

Node-key rotation reuses `/machine/register` only after the Noise session proves
the active machine key. The request carries the exact old and proposed new Node
public keys, no enrollment credential, and no caller-selected scope. One
transaction expires the old key epoch, creates the next epoch, advances the
Device version and session generation, advances Network and inventory revisions,
and appends audit plus outbox evidence. The logical Device, hostname, machine-key
epoch, and address leases remain unchanged. An exact old/new retry converges on
the committed epoch; stale transitions and any reuse of a historical Node key
fail closed.

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
When both pools are configured, their PostgreSQL usernames and credential-file
paths must be distinct.
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

The Redis ACL user must be limited to the presence, endpoint, and
`meshtransit:v1:ratelimit:management:*` key patterns, the fixed `PING`, `GET`,
`SET`, `TIME`, hash, expiry, delete, script, publish, and subscribe commands,
and exactly these Pub/Sub channels:
`meshtransit:v1:wakeup:network_revision_advanced` and
`meshtransit:v1:wakeup:connectivity_changed`. `resetchannels` without both
explicit channel grants prevents `control` and `all` startup and endpoint or
presence updates; wildcard channel access is not required.

The `control` and `all` roles require an enrollment credential-digest key. A
rotation window contains exactly one active key and at most one previous key.
Key IDs and file paths must be distinct. Previous-key ID and file settings must
either both be present or both be absent. Each key file contains the canonical,
unpadded base64url encoding of exactly 32 non-zero random bytes.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID` | none | Public version identifier used for newly created credential digests. |
| `MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_FILE` | none | Absolute path to the active credential-digest key file. |
| `MESHTRANSIT_ENROLLMENT_DIGEST_PREVIOUS_KEY_ID` | none | Optional public version identifier accepted during bounded key rotation. |
| `MESHTRANSIT_ENROLLMENT_DIGEST_PREVIOUS_KEY_FILE` | none | Absolute path to the optional previous credential-digest key file. |

The `api` and `all` roles expose a separate TLS-only management listener on
port `8444`. It accepts HTTP/1.1 and bounds connections, headers, request
bodies, concurrent work, and duration. Browser cookies are never accepted as
authentication. Account Session and idempotency key files must contain the
canonical unpadded base64url encoding of exactly 32 non-zero random bytes. The
Account Session verifier accepts one active key and at most one previous key.
The management TLS pair may be shared with the control listener, but HMAC,
enrollment, Noise, and TLS private-key material must remain purpose-separated.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_API_ADDRESS` | `0.0.0.0:8444` | TCP host and non-zero port distinct from health and control listeners. |
| `MESHTRANSIT_API_TLS_CERTIFICATE_FILE` | none | Absolute path to the management TLS certificate-chain PEM. |
| `MESHTRANSIT_API_TLS_PRIVATE_KEY_FILE` | none | Absolute path to the bounded management TLS private-key PEM. |
| `MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_ID` | none | Public version identifier for the active Account Session HMAC key. |
| `MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_FILE` | none | Absolute path to the active Account Session HMAC key. |
| `MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_PREVIOUS_KEY_ID` | none | Optional previous Account Session HMAC key identifier. |
| `MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_PREVIOUS_KEY_FILE` | none | Absolute path to the optional previous Account Session HMAC key. |
| `MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_ID` | none | Public version identifier for management idempotency HMACs. |
| `MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_FILE` | none | Absolute path to the idempotency HMAC key. |
| `MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_ID` | none | Public version identifier for rate-limit subject HMACs. |
| `MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_FILE` | none | Absolute path to the purpose-separated rate-limit HMAC key. |
| `MESHTRANSIT_API_TRUSTED_PROXY_CIDRS` | empty | Comma-separated canonical CIDRs allowed to supply `X-Forwarded-For`; all other peers' forwarding headers are ignored. |
| `MESHTRANSIT_API_SOURCE_RATE_LIMIT_CAPACITY` | `30` | Maximum per-source burst from 1 through 100000 requests. |
| `MESHTRANSIT_API_SOURCE_RATE_LIMIT_REFILL_INTERVAL` | `1s` | Time to restore one per-source token, from 10ms through 1 hour. |
| `MESHTRANSIT_API_SESSION_RATE_LIMIT_CAPACITY` | `60` | Maximum per-Account-Session burst from 1 through 100000 requests. |
| `MESHTRANSIT_API_SESSION_RATE_LIMIT_REFILL_INTERVAL` | `500ms` | Time to restore one per-session token, from 10ms through 1 hour. |
| `MESHTRANSIT_API_REQUEST_TIMEOUT` | `10s` | Whole-request deadline from 100ms through 30 seconds. |
| `MESHTRANSIT_API_MAX_CONNECTIONS` | `256` | TLS connection cap from 1 through 4096. |
| `MESHTRANSIT_API_MAX_CONCURRENT_REQUESTS` | `128` | Admitted-request cap from 1 through the connection cap. |

The first Device lifecycle endpoint is:

```text
POST /api/v1/workspaces/{workspace_id}/networks/{network_id}/devices/{device_id}/actions/revoke
Authorization: Bearer <opaque Account Session>
If-Match: "<current Device version>"
Idempotency-Key: <16..128 canonical characters>
Content-Type: application/json

{"reason":"operator supplied reason"}
```

Success returns `200`, a new strong `ETag`, Device/session/Network/inventory
revisions, and a correlation ID. Errors use one stable JSON envelope without
authority, database, token, or raw idempotency-key detail. The machine-readable
contract is `api/openapi/management_v1.json`. Login and Account Session
issuance are not exposed yet, so this slice cannot mint a new management bearer.
Exhausted request budgets return `429` with bounded `RateLimit-*` and
`Retry-After` headers. Redis admission failure returns retryable `503` before
authentication or PostgreSQL mutation.

Compiled packet policy can be activated through the same SSO-only boundary:

```text
POST /api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/actions/publish
Authorization: Bearer <opaque Account Session>
If-Match: "<current Policy revision>"
Content-Type: application/json

{"reason":"operator supplied reason","rules":[...]}
```

Core requires current exact-Network `policy.publish` authority and holds that
RBAC evidence under the same PostgreSQL transaction that advances the Policy
and Network revisions, appends audit evidence, and records the outbox wakeup.
An explicit empty `rules` array publishes deny-all. Successful publication
returns the immutable release ID, Policy/Network revisions, semantic hash, rule
count, and the new Policy revision as a strong `ETag`.

Those roles also expose the public client-control listener. It accepts TLS only;
the client session inside TLS must then authenticate with the pinned Noise
capability. Port `8443` is the non-root container default; a load balancer or
Kubernetes Service may publish it as port `443`, but must preserve HTTP upgrade
semantics. TLS, Noise, and enrollment private-key files must be purpose-separated.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_CONTROL_ADDRESS` | `0.0.0.0:8443` | TCP host and non-zero port for public client control traffic. |
| `MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE` | none | Absolute path to the TLS certificate-chain PEM. |
| `MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE` | none | Absolute path to the bounded TLS private-key PEM. |
| `MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE` | none | Absolute path to the canonical, single-line Noise machine private key. |
| `MESHTRANSIT_CONTROL_MAX_SESSIONS` | `1024` | Per-process connection and session admission cap from 1 through 4096. |
| `MESHTRANSIT_CONTROL_MAX_STREAMS_PER_SESSION` | `8` | HTTP/2 stream cap per authenticated session from 1 through 64. |
| `MESHTRANSIT_CONTROL_HANDSHAKE_TIMEOUT` | `5s` | TLS, header, and Noise handshake deadline from 100ms through 30 seconds. |
| `MESHTRANSIT_CONTROL_READ_IDLE_TIMEOUT` | `1m` | Authenticated session read-idle probe interval from 100ms through 5 minutes. |
| `MESHTRANSIT_CONTROL_PING_TIMEOUT` | `15s` | Probe-response deadline from 100ms through the read-idle timeout. |
| `MESHTRANSIT_CONTROL_WRITE_TIMEOUT` | `15s` | Authenticated session write deadline from 100ms through 5 minutes. |
| `MESHTRANSIT_CONTROL_MAP_REQUEST_TIMEOUT` | `10s` | Total application deadline for one authenticated map snapshot, from 100ms through 1 minute. |
| `MESHTRANSIT_CONTROL_MAP_STATEMENT_TIMEOUT` | `3s` | PostgreSQL statement timeout for one authenticated map snapshot, from 1ms through 1 minute. |
| `MESHTRANSIT_CONTROL_MAP_TRANSACTION_IDLE_LIMIT` | `5s` | PostgreSQL idle-in-transaction limit for one map snapshot, from 1ms through 1 minute. |
| `MESHTRANSIT_CONTROL_MAP_PRESENCE_TTL` | `30s` | Generation-fenced Redis presence and endpoint-observation TTL from 3 seconds through 5 minutes. |
| `MESHTRANSIT_CONTROL_MAP_COORDINATION_TIMEOUT` | `2s` | Redis presence and endpoint-operation deadline from 100ms through 30 seconds and below one third of the presence TTL. |
| `MESHTRANSIT_CONTROL_MAP_KEEPALIVE_INTERVAL` | `1m` | Silent-stream keepalive interval from 1 second through 90 seconds. |
| `MESHTRANSIT_CONTROL_MAP_RECONCILE_INTERVAL` | `30s` | Authoritative PostgreSQL resync interval from 1 second through 5 minutes. |

Control connection saturation, session admission results, Noise handshake
duration, authenticated-session duration, registration results/duration, and
map snapshot results/duration are exported only through the private operator
`/metrics` endpoint. Result labels come from fixed internal sets and never
contain machine identity, endpoint, credential, or request data.

Enrollment credentials use the canonical transport grammar
`mtc1.<credential-uuid>.<base64url-32-byte-token>`. The complete value is a
bearer secret: it is disclosed only when issued, never persisted in plaintext,
and must not appear in configuration, errors, or logs.

Credential registration for the same roles uses bounded settings for durable
intent preparation and the authoritative Node/address mutation. The lock
timeout cannot exceed the statement timeout, the retry maximum cannot be below
its initial delay, rollback must fit within the process shutdown timeout, and
address allocation examines only the configured candidate snapshot.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_REGISTRATION_MAX_ATTEMPTS` | `3` | Whole-transaction attempt budget from 1 through 5. |
| `MESHTRANSIT_REGISTRATION_ROLLBACK_TIMEOUT` | `1s` | Rollback cleanup deadline from 1ms through 5s. |
| `MESHTRANSIT_REGISTRATION_PENDING_TTL` | `10m` | Pending intent lifetime from 1 second through 24 hours. |
| `MESHTRANSIT_REGISTRATION_ADDRESS_CANDIDATE_LIMIT` | `256` | Maximum canonical address candidates examined per allocation, from 1 through 65536. |
| `MESHTRANSIT_REGISTRATION_STATEMENT_TIMEOUT` | `5s` | PostgreSQL statement deadline from 1ms through 1 minute. |
| `MESHTRANSIT_REGISTRATION_LOCK_TIMEOUT` | `1s` | PostgreSQL lock deadline from 1ms through 30 seconds. |
| `MESHTRANSIT_REGISTRATION_IDLE_TIMEOUT` | `10s` | PostgreSQL idle-in-transaction deadline from 1ms through 1 minute. |
| `MESHTRANSIT_REGISTRATION_RETRY_INITIAL` | `10ms` | Initial retry delay from 1ms through 1 minute. |
| `MESHTRANSIT_REGISTRATION_RETRY_MAXIMUM` | `250ms` | Maximum retry delay from the initial value through 1 minute. |

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
the `worker` and `all` roles, and the revision and connectivity feeds only for
the `control` and `all` roles. Each service starts exactly one owned goroutine.
The worker processes bounded claims sequentially; each feed uses one Redis
subscription and bounded local fan-out. All cancel in-flight I/O during shutdown
and join before Redis and PostgreSQL are closed. Broader management-plane
mutations remain deferred to later vertical slices.

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
the atomic audit/outbox transaction remain mandatory. Approval persistence and
management mutations beyond the explicitly exposed Device-revoke route remain
deliberately deferred.

## Network management RBAC authority

Migration `000025` adds durable Workspace memberships, Workspace-scoped Role
Definitions and RolePermissions, and direct-Principal RoleBindings at an exact
Network scope. Every authority row is tenant-qualified, forced through RLS,
versioned, lifecycle constrained, and covered by the existing mandatory
authority-mutation plus audit/outbox evidence contract. Runtime processes keep
no direct table privileges; only `mesh_runtime` may call the purpose-built
Network permission resolver.

The resolver rechecks the exact deployment-bound Account Session, Principal,
Account, identity subject, provider/client, Workspace, Network, membership,
RoleBinding, RoleDefinition, RolePermission, permission, generations, and
exclusive expiries. Mutable authority rows are locked in the same short
transaction as the protected mutation. Device revocation now requires this
resolver for exact `device.manage` authority before idempotency claim or Device
locks, and an uncertain-commit replay is reauthorized too. Its audit payload
binds the Account Session, RoleBinding, RoleDefinition, and all resolved
authority generations.

This first storage slice intentionally supports direct Principal bindings at
exact Network scope. Identity-group subjects, inherited Deployment/Workspace
bindings, delegation ceilings, and approval policy remain fail-closed until
their dedicated vertical slices land. The first management HTTPS route exposes
only exact-Network Device revocation.

## OIDC browser-login foundation

The provider-neutral `internal/identity/oidcauth` package now owns the security
primitives for the SSO-only browser flow. Every transaction creates independent
256-bit state, nonce, and PKCE verifier values. State and nonce use distinct,
domain-separated HMAC-SHA-256 digests bound to the Deployment public ID and
recovery epoch. The PKCE verifier is stored only as an AES-256-GCM envelope whose
authenticated context binds the exact Deployment,
Workspace, provider, client, transaction, provider generation, recovery epoch,
redirect ID, and return-route ID. Secret-bearing values redact ordinary,
detailed, and structured-log formatting.

The `internal/adapter/oidc` discovery boundary fetches only the configured HTTPS
metadata URI through a bounded TLS client with proxies and redirects disabled.
It rejects oversized or duplicate security-field JSON, issuer or endpoint drift
from the exact discovery/authorization/token/JWKS allowlist, missing
Authorization Code or PKCE S256 support, and client-authentication or
signing-algorithm mismatch.
Split-host providers remain compatible because every HTTPS endpoint is
allowlisted independently. The resulting authorization request contains one
exact client, callback, scope, state, nonce, and S256 challenge; no
caller-selected issuer, endpoint, or redirect is accepted.

The PostgreSQL `AuthTransactionStore` now creates a pending browser transaction
with immutable audit-chain and outbox evidence in one short READ COMMITTED unit.
Hardened runtime-only functions recheck and lock the exact active Deployment,
Workspace, provider generation, confidential client, and Workspace routing
binding. Issuer, independently allowlisted endpoints, client method/scopes/
algorithms, registered callback URI, and recovery epoch must match durable
configuration. Organization-routed bindings remain fail-closed until their
expected-digest context is implemented. Runtime still has no direct table DML.

Only state/nonce HMAC digests and encrypted verifier material enter PostgreSQL.
A binding semantic hash fixes the route, redirect/return-route IDs,
secret-derived evidence, and microsecond-canonical deadlines.
Open expiry indexing covers both
pending and consuming states. Exact transaction ID plus this hash resolves an
uncertain creation commit without inserting a second row. Audit/outbox payloads
contain only bounded non-secret IDs, generations, route labels, and expiry;
Deployment-scoped events have no Network revision.

This slice intentionally does not expose a login route yet. The browser start
endpoint and host-only pre-authentication cookie are next, followed by callback
exchange, ID-token validation, Account reconciliation, and Account Session issuance.

`oidcauth.StartService` now owns the application boundary: bounded discovery and
one secret/ID preparation before Begin, exact creation-evidence validation,
explicit audit/outbox Commit, and a live release-time check before returning a
redacted redirect result. An uncertain commit triggers one bounded read-only
lookup using the original transaction ID and binding hash; it never retries
creation. Missing, mismatched, canceled, expired, or cleanup-failed evidence
returns no redirect. Request budgets are capped at 30 seconds, with separate
rollback/resolution budgets capped at 5 seconds each. `oidc.StartTelemetry`
provides isolated active/count/histogram metrics with only closed result labels.
It must be wired to the private operator registry when browser HTTP admission is
implemented. Public HTTP login, pre-auth cookie binding/CSRF, callback claiming,
and Account Session issuance remain unimplemented; the service is not enabled in
runtime composition yet. No supported Mesh Client wire contract changed.

The boundary threat model is fail-closed:

- Spoofing and mix-up: exact issuer, discovery, authorization, token, JWKS,
  client, redirect, and provider capabilities must match Core-owned
  configuration.
- Tampering and replay: state and nonce have separate HMAC domains; the PKCE
  verifier is AEAD-bound to every transaction authority generation.
- Repudiation: transaction creation commits with the existing immutable
  audit/outbox contract; evidence failure prevents creation commit.
- Information disclosure: state, nonce, verifier, ciphertext, and the full
  redirect always format redacted and must not enter logs or metrics.
- Denial of service: discovery time, response headers, decompressed body size,
  endpoint count, capability count, and redirects are bounded.
- Elevation of privilege: provider roles, groups, Organization, email, and
  mutable claims are absent from authorization construction and cannot create
  Core membership or RBAC.

## Account Session authentication

The `internal/identity/accountsession` package now owns the first human-session
authentication slice. A presented token uses one canonical versioned envelope
with 256 bits of bearer entropy and explicit Deployment/recovery qualifiers.
The raw token, HMAC key, and verifier all redact default, detailed, and
structured-log formatting. The immutable keyring evaluates exactly one active
and at most one previous HMAC-SHA-256 generation.

Migration `000024` adds a narrow `mesh_runtime`-only Account Session resolution
function. Resolution must match the token's exact Deployment public ID,
Deployment recovery epoch, HMAC algorithm, key ID, and digest before it returns
the current session, Principal, identity-subject, login-Workspace, assurance,
generation, and expiry evidence. The function rechecks active Deployment,
Principal, Account, subject, provider, client, Workspace, recovery, and session
generations. Serving roles retain no direct Account Session table privileges.

The PostgreSQL adapter uses a bounded read-only transaction and rejects
malformed or mismatched durable evidence. Authentication performs at most two
lookups for key rotation and maps absent, expired, stale-generation, or
cross-Deployment authority to one generic unauthenticated result. The
management HTTP boundary uses this authenticator as an opaque bearer verifier.
It validates route, method, media type, bounded JSON, strong `If-Match`,
HMAC-destroyed idempotency evidence, and exact result evidence before returning
public JSON. Login, OIDC callbacks, and Account Session issuance remain future
slices; the cryptographic transaction and strict discovery foundation described
above is now complete.

## Node-key rotation threat model

The trust boundary is the TLS-protected, Noise-authenticated control session.
The transport-proven machine key is the only rotation principal. Request JSON
cannot provide Workspace, Network, Device, session generation, revision, or
audit authority.

- Spoofing: the server binds rotation to the Noise machine key and requires its
  active machine-key epoch. A missing, revoked, expired, or cross-scope Device
  receives one generic unauthenticated result.
- Tampering and replay: the transaction locks current Device, machine-key,
  Node-key, revision, and audit-stream rows. A domain-separated proof binds the
  machine key and exact old/new Node keys. One full-history uniqueness index
  prevents rollback to any earlier Node key. Exact committed retries are the
  only accepted replay.
- Repudiation: Device, key epoch, session generation, Network revision, audit
  event, and outbox event commit atomically under one change ID. Audit payloads
  record versions and generations, never raw key material.
- Information disclosure: errors, logs, metrics, audit payloads, and outbox
  payloads omit public-key bytes and database authority detail. Scope resolution
  is executable only by `mesh_runtime`.
- Denial of service: statement, lock, idle, rollback, and whole-transaction
  retry budgets are bounded. Control admission and per-session stream limits
  apply before application mutation.
- Elevation of privilege: the caller cannot select tenant scope. A
  `SECURITY DEFINER` resolver validates the active machine and current Node-key
  relationship before the adapter sets exact transaction-local RLS scope.

Successful rotation increments `session_generation` and Network revision.
Existing map streams fail their generation fence, while the durable outbox
wakeup prompts other clients to resync. Periodic reconciliation remains the
missed-notification recovery path.

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

Processes with storage dependencies also expose Redis command count and
latency for the fixed connection, wakeup, presence, endpoint, connectivity, and
rate-limit
projection operations,
plus command-pool usage, pending requests, pool timeouts, and active
subscriptions. Operation and result labels are closed sets; Node IDs, endpoint
values, and discovery keys are never labels. Pool state is sampled only when
metrics are scraped; no observability goroutine or unbounded label is introduced.

Control and `all` processes expose revision-feed and connectivity-feed subscriber
state, active watchers, received wakeups, and bounded `delivered`/`coalesced`
fan-out results.
Workspace, Network, Node, session, and replica identities are never metric
labels. Each process-owned feed subscriber serves all local map streams; no
client creates its own Redis connection or goroutine.

PostgreSQL telemetry is partitioned only by the fixed `runtime` and `worker`
credential-pool roles. It reports bounded semantic operation outcomes and
latency, connection usage, acquisition/cancellation counts and wait duration,
and connection creation/destruction. Pool state is also sampled at scrape time;
SQL text, usernames, addresses, database names, and domain identifiers are
never metric labels.

Readiness opens only after the initial required dependency checks succeed and
all role services start. For `control` and `all`, both wakeup-feed subscriptions
must succeed before the control listener starts. Periodic bounded checks lower
readiness on dependency loss and restore it after recovery. Graceful shutdown
closes admission before draining control streams, stopping and joining both
wakeup feeds, joining the monitor, and releasing Redis then PostgreSQL. Those
phases share one configured shutdown deadline; resource cleanup is not started
after that deadline is exhausted. PostgreSQL
cleanup also refuses to call the pool's blocking close while a connection is
still acquired, so shutdown never relies on an unowned timeout goroutine.
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
`make test`, `make test-race`, `make lint`, `make lint-integration`, and
`make vuln`. `make quality` runs the complete bootstrap set. The integration
lint target compiles and analyzes the build-tagged test harness without dialing
dependencies. The lint and vulnerability commands pin tool versions for
reproducible execution with the module's Go 1.26.8 baseline.

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
`make integration-platform-container` provisions the same isolated PostgreSQL
18.6 TLS/SCRAM and Redis 8.8.0 TLS/ACL fixtures used by CI. It additionally
proves end-to-end Network-revision wakeup delivery, transactional retry, and
lease-expiry replay after a post-publish/pre-completion process failure. The
gate also launches the real binary as `role=all`, checks every concrete role in
operator metrics, performs a bounded SIGTERM shutdown, and proves a second
process reaches readiness against the same durable state. A negative process
case proves invalid `role=all` configuration exits with redacted diagnostics
before starting the operator listener. The same gate also discovers the
control key over validated TLS, establishes Noise plus HTTP/2, registers a
synthetic one-off credential, and verifies the committed Node, key epochs,
primary address, revision, audit, and outbox evidence. Repeating that exchange
after process restart must replay the canonical result without consuming or
creating any additional authority. Both containers are removed when the test
exits.

## Container image

`make container-build` creates `manhdev2002/meshtransit-core:dev` by default.
Override `CONTAINER_IMAGE`, `CONTAINER_TAG`, or `CONTAINER_PLATFORM` without
editing repository files. `make container-inspect` verifies the numeric
non-root identity and fixed entrypoint, `make container-smoke` exercises the
relay health surface under a read-only filesystem with all Linux capabilities
dropped, and `make container-scan` rejects High or Critical findings. Use
`make container-build-multiarch` to compile both Linux amd64 and arm64 images
without publishing them. An explicitly authorized release can use
`make container-push-multiarch` to publish both platforms with BuildKit SBOM
and provenance attestations.

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
