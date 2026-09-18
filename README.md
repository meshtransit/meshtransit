# MeshTransit Core

Temporary owner-approved delivery change (2026-09-17): CVE remediation is deferred
only for isolated non-production Keycloak qualification, using a separate dated
acknowledged candidate workflow. Existing scan findings and production artifact
gates remain unresolved; the ordinary guarded build is unchanged. No auth/TLS,
Secret custody, membership or revoked-client exception follows. Priority is now
private provider runtime, Google broker/confidential Core client and real Google
SSO/browser/client acceptance. All six live Google requirements remain open.
The canonical decision is `SSO-KEYCLOAK-POC-CVE-DEFER-001` in the original
architecture document 27; historical no-POC-waiver statements are superseded only
within this explicit scope.

The optimized amd64 POC candidate now builds and passes immutable non-root/read-only
native CLI checks, and is published with index
`sha256:89e58aafc3a58c3c80f7f41c0873d86fafd2cebaecf405690fb28c94451539d2`.
Root SSH is now verified. Private target startup awaits explicit approval of the
shared-host new-role-only HBA/independent DB/new Secret delivery scope; auto-review
rejected the write before execution. Google registration/redirect binding and
human consent still require qualification; finding old Secret metadata alone
does not establish those bindings.
No Core/client binary, schema, wire contract or target authority change occurs.

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
configuration-schema versions (currently 16). Run `meshcore config validate` to validate the
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
256-bit pre-auth cookie, state, nonce, and PKCE verifier values. State and nonce use distinct,
domain-separated HMAC-SHA-256 digests bound to the Deployment public ID and
recovery epoch. The PKCE verifier and a versioned cookie HMAC digest are stored
only as an AES-256-GCM browser-proof envelope whose
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

Only state/nonce HMAC digests and encrypted browser-proof material enter PostgreSQL.
A binding semantic hash fixes the route, redirect/return-route IDs,
secret-derived evidence, and microsecond-canonical deadlines.
Open expiry indexing covers both
pending and consuming states. Exact transaction ID plus this hash resolves an
uncertain creation commit without inserting a second row. Audit/outbox payloads
contain only bounded non-secret IDs, generations, route labels, and expiry;
Deployment-scoped events have no Network revision.

No public listener exposes browser login yet. Bounded pre-session HTTP start and
durable route admission are implemented as foundation adapters; callback claim/
exchange and ID-token validation foundations are described below. Account
reconciliation/JIT/linking, abandoned-row expiry and public callback wiring
remain required before public composition. Existing-subject issuance and
confirmed-claim failure foundations are described below.

`oidcauth.StartService` now owns the application boundary: bounded discovery and
one secret/ID preparation before Begin, exact creation-evidence validation,
explicit audit/outbox Commit, and a live release-time check before returning a
redacted redirect result and its exact independent cookie. An uncertain commit triggers one bounded read-only
lookup using the original transaction ID and binding hash; it never retries
creation. Missing, mismatched, canceled, expired, or cleanup-failed evidence
returns no redirect. Request budgets are capped at 30 seconds, with separate
rollback/resolution budgets capped at 5 seconds each. `oidc.StartTelemetry`
provides isolated active/count/histogram metrics with only closed result labels.
It must be wired to the private operator registry when browser HTTP admission is
implemented. A bounded HTTP prepare/start adapter now enforces the pre-session
CSRF contract below. `AuthTransactionStore.Admit` implements its mandatory
durable route admission seam, but public runtime composition/callback wiring
remains unimplemented. Existing-subject Account Session issuance now has the
separate application/database foundation described below.
No supported Mesh Client wire contract changed.

Initial real Google SSO THROUGH the Keycloak broker is now a required Phase 1
exit, approved by the owner on 2026-09-17 (ADR-044). Phase 1 includes runtime/
configuration/listener wiring, safe target readiness, fresh Core Account Session
delivery and unchanged supported meshd/meshctl compatibility. Private source
tests, synthetic providers and schema foundations do not complete this milestone.
The scope change does not enable public login or waive its security/HA gates.

The first live SSO qualification remains planned for Google through the Keycloak
Google identity broker. Other social/enterprise providers, directory
integration, external OIDC replacement, and Organization-specific routing follow
later. Core stays provider-neutral and validates the exact configured Keycloak
issuer/client/JWKS and `(iss, sub)`; it does not add a direct Google OAuth path,
retrieve upstream Google tokens, or use email/domain/provider claims as Core
membership or RBAC. Human product login remains SSO-only, with no local password
or outage fallback.

Before that live test, operators must configure separate Google-to-Keycloak
broker and Keycloak-to-Core client registrations with exact HTTPS callbacks,
protected credentials, controlled Google test accounts, a reviewed SSO-only
browser flow, and no automatic email-based identity linking. Selecting a default
broker alone does not enforce SSO-only login; missing/disabled Google must reject
instead of exposing a local password fallback. See the official
[Keycloak broker/flow guidance](https://www.keycloak.org/docs/latest/server_admin/)
and [Google redirect registration contract](https://developers.google.com/identity/protocols/oauth2/web-server)
when preparing the pinned deployment.

Planned Google acceptance (`SSO-GOOGLE-001` through `SSO-GOOGLE-006`) covers
approved member login with fresh Core-session rotation, valid-login/no-membership
denial, canceled/invalid/expired/replayed
callbacks, two-replica single-use claim and lost-acknowledgement rejection,
generation/revocation and dependency failure, and local Core logout while the
upstream Google browser session remains active. Record exact source/client
commits, schema version, image digests, and sanitized configuration fingerprints.
All six requirements are mandatory Phase 1 acceptance, not optional Phase 2 work.
No live Google test has run. The public-login prerequisites below remain
mandatory; a unit or disposable synthetic-provider test is not Google evidence.

Pre-authentication cookie HMAC evidence has an independent keyed purpose and
binds every transaction authority dimension. It resides with PKCE inside a
bounded, versioned browser payload under a browser-specific AEAD purpose. The
existing storage algorithm, SQL signature, schema, and binding hash remain
compatible; no migration is changed. Browser and legacy verifier-only openers
mutually reject each other's payloads, with no downgrade fallback. Terminal
encrypted-proof erasure removes both PKCE and cookie evidence; automated
callback/expiry transitions are not implemented by this slice.

HTTP helpers prepare `__Host-mt_pre_auth` with Secure, HttpOnly, SameSite=Lax,
Path=/, no Domain, and expiry no later than confirmed creation. Cookie parsing
rejects missing/duplicate/quoted/noncanonical handles, with limits of 8192 total
header bytes, 8 Cookie fields, and 64 pairs. A newer start replaces the host
cookie, so an older concurrent tab must restart login. Helpers alone neither
emit responses nor open public login; trusted HTTPS origin, CSRF, authoritative
cookie verification, callback claiming, and fresh session rotation remain
mandatory before browser admission. Every callback replica must support the
browser payload before public login is enabled; legacy pending rows restart.

The browser HTTP foundation owns one immutable Core-selected route. Both
`POST /auth/v1/login/prepare` and `POST /auth/v1/login/start` require an exact
configured HTTPS Host/Origin, `X-MeshTransit-Login: v1`, and an exact empty JSON
object within 32 bytes. GET/HEAD/OPTIONS, Referer-only admission, proxy-selected
scheme/origin, request scope/URL selectors, ambiguous headers, and simple content
types reject before any dependency effect. Total headers are bounded to 16384
bytes, 64 names, and 128 values. A non-queuing 1–128 request gate and a maximum
30-second context plus transport read/write deadline bound work. Wrappers that
cannot support ResponseController deadlines fail closed.

Prepare creates a private independent 256-bit `__Host-mt_login_init` cookie
(Secure, HttpOnly, SameSite=Strict, Path=/, no Domain) and a separate versioned
HMAC-SHA-256 CSRF proof in JSON. The private cookie handle never enters
JavaScript. The authenticated payload fixes its exact key ID, issued/expiry
seconds, and independent 256-bit random value. The MAC has a dedicated purpose
and binds the cookie plus every configured route/origin/generation value.
Lifetime is 60–300 seconds. Start requires exactly one custom
`X-MeshTransit-CSRF` header and one canonical cookie; substituted browser,
route, key, generation, epoch, malformed payload, and expired proof reject.
Proof is checked again after admission and before response release. Neither
proof nor cookie is an Account Session or membership evidence; concurrent
pre-session replay is not claimed single-use.

Both endpoints consume a shared, purpose-separated HMAC source budget using the
existing distributed Redis adapter before durable admission or OIDC work.
Redis failure/malformed evidence rejects with generic 503; budget exhaustion
returns 429 with bounded Retry-After. An explicit durable admission dependency
is mandatory, and creation rechecks route authority in PostgreSQL. Only a
confirmed live StartResult returns the independent pre-auth cookie and an
authorization URL in no-store JSON for explicit browser navigation. The
initiation cookie is then expired. No automatic AJAX-followed redirect or
provider token is returned. All errors are static, and private
`LoginHTTPTelemetry` records only closed outcome counts and latency.

Durable admission uses a separate READ COMMITTED, READ ONLY unit, capped at
30 seconds with independently bounded cleanup. Forward migration 28 exposes only
`mesh_ops.admit_oidc_login_route_v1` to runtime, with a fixed search_path and
FORCE-RLS requested Workspace scope; it grants no general provider-table SELECT
or DML. One snapshot checks every durable identity/lifecycle/generation/endpoint,
recovery epoch, confidential client method, PKCE S256, code flow, exact ordered
scopes/algorithms, and registered callback URI. Organization-routed bindings
remain rejected. Core-owned redirect/return labels are registry configuration,
not durable mappings or caller-selected values. Scope is cleared and resources
close before discovery. Missing/false/malformed results, cancellation, database
and read-completion errors fail closed, with no write replay or positive cache.
Admission makes no transaction/audit/outbox/Network-revision writes. Success is
not a revocation lease: creation repeats all checks under locks after discovery.
Private pool telemetry adds only the fixed `auth_transaction_admission` operation
with existing closed results and duration. Released migration 27 and reader/
writer generation 1 are unchanged.

These adapters are tested with the real StartService and verified TLS transport;
authority effects in HTTP unit tests are controlled fakes. Disposable verified-
TLS integration additionally connects real PostgreSQL admission/creation and the
distributed Redis limiter. It covers successful prepare/start, stale-route
rejection with no browser state, and provider revocation committed during
discovery after admission preventing creation. No public listener
registers these routes yet. Trusted route-registry/runtime composition,
callback single-use claim/token validation, fresh Core-session rotation,
terminal expiry/erasure, layered abuse controls, and HA composition must pass
before enabling browser login. Keycloak remains the reference IdP; SSO-only
login and Mesh Client wire contracts are unchanged.

Pending browser verification now uses a separate owned READ COMMITTED, READ ONLY
unit and forward migration 29's runtime-only
`mesh_ops.load_oidc_pending_browser_v1`. It selects only current version-one
pending browser login evidence by the purpose-separated state HMAC and exact
Core-owned route, including redirect/return labels. Requested Workspace scope
is cleared on every path; runtime keeps no AuthTransaction table grants.
Typed scanning validates raw algorithms and exact lengths, then recomputes the
unchanged creation binding hash from original ciphertext and canonical times.
It neither reseals nor backfills legacy evidence. The complete database unit has
a 30-second maximum deadline and separately bounded joined cleanup. Missing,
malformed, canceled, completion-failed, or cleanup-failed reads release no proof.
Private pool metrics add only the fixed `auth_transaction_pending` operation.

`BrowserVerificationService` opens browser AEAD and checks constant-time state/
cookie HMACs only after read resources close, using exact resident key generations
without fallback. Fresh time and cancellation checks precede opaque
`VerifiedBrowser` release. That value contains no plaintext PKCE verifier and has
no verifier accessor. Disposable PostgreSQL/TLS integration round-trips real
StartService evidence, checks route/lifecycle/generation/epoch and privilege/
scope boundaries, rejects URL-only possession, and confirms reads do not change
authority, audit, outbox, or Network revision. Equivalent verification instances
need no sticky routing, but verification can succeed more than once: it is not a
single-use claim, exchange grant, session, or revocation lease.

`ClaimService` now atomically consumes opaque verified browser possession through
forward migration 30's runtime-only `mesh_ops.claim_oidc_browser_v1`. Serial
Workspace/authority class locks precede auth-row FOR UPDATE; current full route,
original pending version/hash, and live database expiry are rechecked after
waits. Deployment audit head is last, followed by another live DB expiry check.
Consuming/version two preserves the original binding hash and encrypted PKCE;
fresh mutation/audit/outbox commit together with separate lifecycle before/after
hashes. No Principal/session or Network revision is created. Non-queuing atomic
method ownership prevents overlapping database I/O without a mutex across I/O.
Private metrics add only fixed `auth_claim_{begin,apply,commit,rollback}` labels.

Only confirmed Commit and fresh cancellation/time checks release an opaque
consumption receipt, with no plaintext verifier or reusable exchange API.
Unknown completion returns zero receipt, never uses creation resolution or
Commit retry, and cannot reclaim consuming state. Disposable PostgreSQL/TLS
tests exercise independent concurrent callbacks, real committed-but-lost ACK,
unchanged ciphertext/binding, exact lifecycle mutation/audit/outbox, stale
authority after proof, and hardened scope/privileges. Public callback/listeners
remain disabled. Core-session rotation, terminal expiry/erasure, abuse controls,
and HA/Google-through-Keycloak acceptance are still required.
Released migrations 27/28/29, application generation 1, SSO-only policy, and Mesh
Client wire contracts remain unchanged.

`ExchangeService` now gives copies of one confirmed claim receipt a shared,
non-queuing single-attempt gate. It burns that attempt before opening the original
browser AEAD proof, recovers only the original PKCE verifier, and uses a bounded
trusted `TokenAuthenticator` port. After provider verification Core independently
checks the nonce HMAC, claim expiry and cancellation. The opaque result preserves
exact issuer/case-sensitive subject and optional assurance/sid; it is not a Core
session, membership or role grant. Failed attempts cannot retry the provider POST.

The OIDC adapter supports confidential `client_secret_basic` with one POST and
at most two independently configured JWKS GETs (one extra only for unknown kid).
Owned TLS transport disables proxy, redirects and compression; joined body Close,
bounded parsing, static errors and redacted types prevent unsafe result release
and accidental secret formatting. RS256/PS256/ES256 use standard Go crypto, exact
declared JWK signing use/algorithm, bounded 2048–8192-bit RSA or checked P-256,
strict compact base64url and duplicate-name/Unicode validation. Issuer, singleton
client audience, present authorized party, nonce, strict expiration and bounded
issue/not-before/authentication times are checked. Additional audiences reject
until explicit trust configuration exists; absent assurance never implies MFA.

The complete budget is at most 30 seconds, with a fail-fast 1–256 exchange cap;
JWT/header/claims limits are 32/1/16 KiB and each JWKS is at most 256 KiB/64 keys.
There is no process signing-key cache, provider bearer credential persistence,
new dependency or SQL mutation in this exchange slice. Tests cover real TLS with
separate trusted token/JWKS origins, malformed/forged claims and keys, rotation,
receipt-copy replay, no POST retry, cancellation, cleanup and parser fuzz seeds.
`private_key_jwt`, step-up and Organization flows remain fail-closed. Public login
is still disabled pending public callback composition, abandoned-row expiry,
abuse controls and Google/HA acceptance. JIT/linking is not implemented. This slice does not change
the wire contract; compatibility reference pins remain `meshd` `87a3dd2` and
`meshctl` `ce2a856` (not a new claim of live client or Google qualification).

`FailureService` now terminalizes a confirmed consuming claim through forward
migration 31's runtime-only `mesh_ops.fail_oidc_browser_v1`. Receipt copies share
one non-queuing failure attempt; starting failure burns unused exchange capability
before effects. It does not undo an already running provider exchange or grant a
session; the separate successful issuance unit CASes the consuming row independently.

Only immutable exact scope, original version-two binding hash and claim time are
used for cleanup. Provider/Workspace revocation cannot strand browser proof.
Auth-row lock precedes Deployment audit head; fresh `clock_timestamp()` after
both locks selects failed/authentication_failed or expired/deadline_expired.
Version three preserves original consumed_at, binding/digests/scope and erases
all three PKCE algorithm/key/ciphertext columns, with fresh atomic mutation/audit/
outbox and terminal lifecycle hashes. No Account Session, Principal, membership,
role or Network revision is created. Bounded joined rollback releases resources;
unknown Commit returns zero receipt, with no resolver or retry.

Private pool metrics add only fixed `auth_failure_{begin,apply,commit,rollback}`
operations and reuse bounded success/error, latency and pool-saturation signals.
Disposable PostgreSQL/TLS tests cover exact scope/CAS, independent SQL contenders,
missing-evidence rollback including erasure, provider/Workspace revocation,
expiry during audit-lock wait and a hidden ACK after real durable Commit. The
existing Deployment audit helper still requires active/verified Deployment;
quarantine recovery cleanup and bounded workers for abandoned pending/consuming
rows remain unfinished. Identity JIT/linking, public callback composition,
abuse controls and Google/HA/client acceptance
remain release gates. Released migrations, application generation 1 and client
wire contracts are unchanged; this is source qualification, not a live rollout.

Secret scanning for this slice uses pinned Gitleaks v8.30.1 with 100% redaction,
default rules and no blanket test/history exclusions: full Git history and the
working source tree. No report, secret, dependency change or history rewrite is
committed. This scan does not replace remaining SBOM/image/provenance and target
release qualification gates.

`SubjectResolutionService` now resolves only an existing exact `(issuer, subject)`
binding after opaque validated exchange evidence. A purpose-owned resident HMAC
keyring prepares one active and at most one previous candidate, preserving exact
UTF-8 bytes. The versioned length-prefixed namespace includes Deployment, provider
and key ID; Workspace, client, provider generation and recovery epoch remain
authority fences, not stable identity. No email/profile linking or provisioning
is performed. Stable-binding key retirement requires audited binding migration,
not simply waiting for pending browser transactions to expire.

Forward migration 32 exposes only runtime EXECUTE on
`mesh_ops.resolve_oidc_login_subject_v1`. Its bounded primary read checks all
current route/lifecycle/recovery predicates, original consuming claim version,
binding hash, consumed_at and route labels, active Account Principal, verified
Account and the exact existing login-Workspace membership. Both subject
candidates are counted before lifecycle filtering; multiple matches reject even
for the same Principal or an inactive binding. Final statement decisions use
live database time and exclusive claim/member expiry, with cleared requested RLS
scope. No table grants, schema/index/backfill changes, locks, last-seen updates,
Session, role, audit/outbox or Network revision writes are added. Released
migrations and reader/writer generation 1 remain unchanged.

The complete application/adapter budget is at most 30 seconds, with a fail-fast
1–256 request gate and independently bounded joined read cleanup. No positive
snapshot escapes failed read completion, malformed evidence, cancellation or
expired release-time checks; no read retry or uncertain-write resolver is used.
Private metrics use only closed results and the fixed `auth_subject_resolve`
operation. Disposable PostgreSQL/TLS tests compose real start/verify/claim,
controlled trusted provider-port exchange evidence and real lookup. They cover
missing membership without provisioning, independent service instances,
previous-key lookup/ambiguity, all SQL inputs, revocation, terminal claims and
live expiry past frozen transaction Begin. This is not live Keycloak/Google or
client/deployment acceptance.

The result is a snapshot, never Session issuance authority: the separate
`IssueService` write independently locks/rechecks current subject, Account,
membership, route and CAS before releasing a fresh Core handle. Plain provider
evidence may omit `auth_time`; initial issuance instead requires signed validated
`auth_time`, preserving the released mandatory Session schema/domain. Never
fabricate authentication_time from iat/Now. Public browser login stays disabled.

### Atomic existing-subject Account Session issuance

`IssueService` prepares a fresh 256-bit Core bearer, the existing `mtas1` envelope,
active-key-only verifier HMAC, six distinct UUIDv7 mutation/evidence IDs and an
optional purpose-separated upstream SID HMAC before opening the write unit.
Copies of validated exchange evidence share one non-queuing issuance attempt.
Missing signed `auth_time`, expired membership, invalid preparation and overload
cannot enter a write unit. No provider refresh, re-exchange, secret lookup or
randomness occurs inside the database transaction.

Forward migration 33 exposes only runtime EXECUTE on
`mesh_ops.issue_oidc_existing_subject_v1`, without broad table grants or released
schema/generation changes. The short READ COMMITTED unit takes an explicit
identity-subject SHARE relation barrier before deterministic authority row locks
and the Deployment audit head. It rechecks exact current subject/Account/member,
route, versions, generations, original consuming claim and exclusive deadlines
with fresh DB time after lock waits. The relation barrier also blocks a previously
nonmatching subject changing only its digest into a candidate. Compatible issuers
remain allowed, but subject writes across providers temporarily wait under finite
SQL budgets; future binding writers must take their relation lock before parent
or audit locks. A finer scoped guard requires separate qualification.

One active/version-one Session and consuming -> succeeded/version-three transition,
exact Session result reference, complete PKCE erasure and two chained audit/outbox
events commit atomically under one change ID, without a Network revision or role
grant. DB issue time anchors configured whole-second idle/absolute ceilings, both
intersected with finite membership expiry. Configured minimum assurance is exact
opaque ACR equality, never an inferred hierarchy or AMR-as-MFA alias. Absent SID
stores an all-NULL triple; present SID preserves exact UTF-8 bytes in a separate
Deployment/provider/key-version HMAC namespace. Default/detailed/structured
formatting and operational labels never disclose bearer, SID, subject or proof.

Only exact validated metadata, confirmed Commit and fresh live/cancellation checks
release the new bearer. Any partial audit/outbox failure rolls everything back.
Unknown Commit returns no handle and never resolves, retries or exchanges again;
it can leave a committed but undisclosed Session bounded by normal expiry/revocation.
Request/cleanup ceilings are 30/5 seconds with fail-fast concurrency at most 256.
Private issuance metrics have fixed names/closed outcome labels; database metrics
add only `auth_issue_{begin,apply,commit,rollback}` operations.

Source qualification covers real verified-TLS PostgreSQL start/verify/claim,
controlled trusted provider-port exchange, lookup, issuance and authentication of
the new bearer by the current Account Session verifier. Cases include absent
auth_time/SID, exact ACR rejection, membership lifetime intersection, rollback on
the second outbox append, hidden ACK after real durable Commit, complete event
semantics/hash chaining and two independent durable contenders. Independent DB
connections also prove INSERT/digest-only UPDATE exclusion and barrier cleanup.
Unit/race tests cover preparation failures, copied/burned attempts, malformed
metadata, joined cleanup, closed metrics and non-queued method overlap. Cross-language
HMAC vectors preserve both the existing verifier and new SID encoding.

This foundation neither exposes a public callback/Set-Cookie route nor qualifies
live Keycloak/Google, client deployment, operational HA/failover or Phase 1 completion.
Keycloak remains the reference authority and Google through its broker remains
the first live SSO target. Exact-target abandoned-row expiry coverage, bounded public
composition/abuse controls and target acceptance remain release gates.
Supported Mesh Client wire contracts are unchanged.

Vulnerability qualification remains reachability-specific: the current Go 1.26.8
scan reports zero imported-package/reachable vulnerabilities, but retains three
module-only `golang.org/x/crypto` advisories: GO-2026-6354, GO-2026-6355 (SSH,
fixed in v0.56.0), and GO-2026-5932 (unmaintained OpenPGP, no fix). This exchange
adds no dependency or SSH/OpenPGP imports. Do not label the dependency graph or
production release advisory-free; dependency remediation and target-platform
release scans remain separate release work.

### Bounded abandoned browser-login expiry engine

`ExpiryService` now runs an explicit Deployment-assigned, bounded no-grant pass.
Forward migration 34 registers three worker-only capabilities: bounded original
lifecycle selection, exact expiry and purpose-restricted evidence append. No
auth/session table, generic audit/head or login/issuance grant is added to worker.
No Workspace/provider join or broad FORCE-RLS policy is needed. Legacy NULL/zero
creation hashes are explicitly excluded, not fabricated or silently repaired.

One Auth per short owned unit locks the exact original pending1/consuming2 row
before its existing Deployment audit head, even through quarantine/deletion, then
uses fresh DB time after all waits. Deadline equality expires. Pending becomes
expired2 with consumed_at equal to terminal time (a tombstone, NOT a browser
claim); consuming becomes expired3 retaining original claim time. Immutable
bindings remain; all three PKCE columns are erased atomically with
deadline_expired, one fixed actor-NULL expiry audit/outbox pair and no Network
revision, Session, Principal or role change. Existing issued Sessions are untouched.

The new expiry function requires a fresh change and no other authority mutation
in the current transaction before any row/head locks, including another change
ID. An explicit transaction_id ledger index bounds this ownership guard; the
existing Auth open-expiry index is reused. The evidence wrapper rejects unrelated
mutations/scopes/payload fields, duplicate pairs and NULL/malformed head CAS inputs.
The existing generic active/verified Deployment helper remains unchanged.

The app prepares three fresh evidence UUIDv7 IDs before Begin and owns
Expire/Commit plus separately bounded joined Rollback. Methods reject overlap
without queuing. Only confirmed Commit releases opaque no-grant terminal evidence.
Unknown Commit releases zero receipt and ends the current pass, never resolving
or replaying that attempt. A later pass may reread durable open rows and use fresh
IDs for new cleanup, not login/exchange retry. Batch/pass/unit/cleanup ceilings
are 128/30s/30s/5s. PG metrics add only worker
auth_expiry_{list,begin,apply,commit,rollback}, with fixed labels and sanitized errors.

Source qualification covers real verified-TLS PostgreSQL pending/consuming expiry,
revoked provider/Workspace, quarantined/deleted Deployment, stale metadata CAS,
missing evidence rollback, hidden ACK after real durable Commit, duplicate and
borrowed same/fresh-change evidence rejection, NULL head expectations, unchanged
issued Sessions, canonical lifecycle/audit hash checks, two independent durable
contenders and an actual audit-head wait with post-wait DB decision time. Unit/race
tests cover bounded passes, preparation/cleanup failure, malformed metadata,
nonqueued unit ownership, typed-nil safety and no-data labels; bounded parser fuzz
and independent Ruby-generated hash vectors pin encoding.

An opt-in owned poller now composes this engine on `all` and `worker`, using only
the worker PostgreSQL pool. Configuration schema 15 adds the settings below.
It starts one sequential loop, runs the first pass immediately, then waits the
poll interval after each completed pass. Shutdown cancels and joins the current
pass and independent cleanup before shared storage is closed. Unresolved cleanup
is fatal, including selector/setup rollback failure; ordinary errors end the pass
without replay. Dependency error text and Deployment/Auth IDs never enter worker
logs or metric labels.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_AUTH_EXPIRY_ENABLED` | `false` | Exact `true`/`false`; opt-in only on `all`/`worker`. |
| `MESHTRANSIT_AUTH_EXPIRY_DEPLOYMENT_PUBLIC_ID` | None | Required canonical UUIDv7 installation assignment when enabled; trusted configuration, not a request scope. |
| `MESHTRANSIT_AUTH_EXPIRY_BATCH_SIZE` | `8` | 1–128 candidates per pass. |
| `MESHTRANSIT_AUTH_EXPIRY_POLL_INTERVAL` | `1s` | 100ms–1m; no overlapping passes. |
| `MESHTRANSIT_AUTH_EXPIRY_SWEEP_TIMEOUT` | `10s` | 100ms–30s pass deadline. |
| `MESHTRANSIT_AUTH_EXPIRY_UNIT_TIMEOUT` | `1s` | 100ms–30s, no greater than sweep timeout. |
| `MESHTRANSIT_AUTH_EXPIRY_ROLLBACK_TIMEOUT` | `1s` | 100ms–5s independent joined cleanup. |

When disabled, unset every other expiry setting: latent assignments/limits fail
validation. Shutdown timeout must be strictly greater than
`max(2s, rollback timeout) + 1s` to reserve adapter-owned cleanup and owner join.
Changing this configuration requires a process restart; it is not client policy.

Private health metrics use `meshtransit_oidc_expiry_` with only closed `result`
labels: worker_running, passes_active, last_success_timestamp_seconds,
passes_total, pass_duration_seconds, units_attempted_total, units_confirmed_total
and batch_limit_reached_total. Running/last-success do NOT prove intended target
coverage. Confirmed units count released receipts, not hidden durable commits;
reaching the batch limit does not prove remaining backlog. Adapter comments pin
operator query/alert intent, not installed dashboard or alert resources.

Worker unit/race tests cover immediate sequential polling, lifecycle misuse,
cancel-and-join, bounded deadlines, unknown Commit followed by fresh selection,
fatal cleanup, malformed counts, typed-nil ports and secret-free telemetry.
Disposable verified-TLS process tests exercise pending and consuming rows on both
roles, exact audit/outbox evidence, unchanged Network/Session authority, and a
same-assignment restart without terminal mutation replay.

This does not enable public login. Next: protected BFF callback/abuse controls,
exact-target coverage (including legacy exclusions and restore lineage), then
live Google/Keycloak/client and operational HA/recovery acceptance.
Keycloak and SSO-only remain unchanged; first live login is Google through its
broker. Supported Mesh Client wire contracts are unchanged. No live deployment,
operational HA/failover or Phase 1 completion is claimed.

### No-grant code-query callback ingress reader

`LoginCallbackReader` validates one fixed Core-owned Route's incoming GET syntax;
it is not a public handler or authenticated browser proof. It requires completed
direct TLS 1.2+, the exact registered Host/canonical callback path and origin-form
target, no body/transfer/trailers, existing bounded headers/cookies, and coherent
document-navigation metadata when present. Proxy/Referer claims cannot replace
TLS/Host/issuer checks. Optional Origin must equal the BFF origin.

Eight pairs and 8192 raw query bytes bound parsing before allocation. Names are
canonical bounded ASCII tokens; duplicate known OR ignored names, encoded aliases,
bad escapes, semicolons, empty pairs and conflicting variants reject. Form-decode
once; require existing canonical state/pre-auth-cookie handles and exact configured
`iss` on code AND provider-error responses under the initial
[RFC 9207 profile](https://www.rfc-editor.org/rfc/rfc9207.html). The first live issuer
remains Keycloak, never Google directly. Use the existing 4096-byte printable code
bound, subject to total transport limits. Provider diagnostics/URI, session_state
and bounded unknown extensions are discarded, never fetched or treated as identity.
Implicit/provider-token/JARM fields reject. Cancellation releases zero input;
only closed cancellation classes survive, not arbitrary context error text.

The returned immutable typed input has redacted formatting/logging and refuses
JSON serialization. It changes no Auth/Session/membership/Network authority.
Isolated private telemetry records only code_received/provider_error_received/
invalid/unavailable/unknown counts and parse duration; received is NOT authenticated.
The caller must explicitly own private metric registration; runtime is not wired.

Source unit/race tests cover variants, exact issuer, parser/field budgets,
transport/metadata/cookie ambiguity, cancellation, immutable input, redaction and
fixed telemetry labels; bounded fuzz smoke qualifies adversarial query input.
No schema/configuration version, client protocol or public login default changes.

GET/HEAD authority remains read-only. The encrypted host-cookie capture and clean
redirect primitive below is now present; next is a protected same-origin POST
continuation with shared abuse budgets and fresh durable proof/claim/exchange/
issuance. Before public deployment, suppress callback query logging/tracing at
both edge and BFF and prove exact-target expiry/recovery coverage. These are
still gates, not implemented public Google/Keycloak or client acceptance.

### Encrypted no-grant callback capture

`LoginCallbackCapsuleCodec` seals reader input under a separately resident
AES-256-GCM key, fresh OS-CSPRNG nonce and authenticated version/key ID. Its AAD
binds every ordered fixed Route parameter, generations/recovery epoch, cookie
purpose, clean destination and the current independent pre-auth cookie. Replacing
route/key/cookie invalidates capture; no old-key, verifier or sticky-session fallback.
Operators must rotate before 2^32 aggregate seals per key across replicas/restarts,
as required by the [GCM random-nonce budget](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce).
No process-local counter proves that deployment-wide limit.

The canonical bounded plaintext contains issued/expiry seconds, the closed kind,
state and exact length-prefixed code or generic provider-error disposition. Strict
30–120-second TTL, no future/skew/expiry-equality grace, initial code bound 2048
bytes, base64url value bound 3800 bytes and full Set-Cookie <4096 bytes reject
oversize/ambiguous input without compression, splitting or URL/storage spillover.
This temporary deadline is not the durable AuthTransaction's authority deadline.
Pinned Keycloak code lengths and actual browser/proxy behavior still need proof.

`LoginCallbackCapture.WriteRedirect` releases only a checked live encrypted
`__Host-mt_login_callback` Secure/HttpOnly/Lax/Path=/ cookie, no Domain, and a
fixed clean `/auth/v1/login/continue` 303 with zero body/query and no-store/CSP/
framing/referrer protections. No active content or original query is emitted.
Open returns untrusted typed input only: replayable within TTL, never verified
browser possession, claim, exchange or Session authority. Clear expires only
this cookie scope; it does not erase durable proof or revoke Sessions.

Unit/shuffled race tests cover both variants, byte tamper, every route dimension,
key/cookie replacement, expiry/cancellation, entropy failure, bounds, defensive
key ownership, redaction and clean redirect. Separate bounded fuzz targets cover
the envelope, authenticated payload parser and cookie parser. Isolated private
capsule count/duration metrics have only closed operation/result labels; accepted
is not authentication or HTTP delivery. No public metric registration is added.

This source primitive opens no listener and changes no schema/config version or
supported client wire. The no-grant protected POST admission below is now present;
next: whole-pipeline composition with fresh durable verification, single-use claim, exchange,
exact-subject issuance and fresh session rotation. Before any public login,
qualify edge/BFF query-log/trace suppression, nonce/key operational limits,
exact-target expiry/recovery and Google-through-Keycloak/client acceptance.

### Protected no-grant callback continuation admission

Strict creation/release-time checks are unchanged. Synthetic platform tests
run against a separate Docker VM clock; even a small negative database offset
can reject immediate pending verification. Failure-only integration diagnostics
report clock offset and safe presence flags, never credentials. Qualify clock
health and immediate start-to-verify behavior before enabling public login;
do not bypass the check, pad persisted evidence or retry an unknown claim.
Following a Docker Desktop restart, the unchanged Go source passed three
consecutive full platform runs on fresh disposable fixtures. This local result
does not qualify clock behavior across production replicas or recovery.

A fresh native-host run during callback orchestration again failed before the
new callback tests, with PostgreSQL about 26 ms behind the application host.
The earlier three passes are historical; the native-host lane is not currently
clock-qualified. No Docker restart, freshness grace, timestamp adjustment or
repeat-until-green is used. The explicit Linux source lane is selected with
`PLATFORM_GO_RUNNER=container make integration-platform-container`.
It runs the same uncached race suites and process binary on the fixtures'
Linux engine clock. Source is mounted
read-only; only owned fixture/cache directories and a private bridge are added,
without Docker socket, host credentials, privileges or capabilities. Generated
CA/exact DNS verification, SCRAM and least-privilege roles remain unchanged.
This separate Linux source lane does not waive cross-replica clock/recovery
acceptance, or relabel the native-host failure as a pass.
Auto-review initially blocked source/fixture access in the network-enabled
runner. After specific operator approval, its first execution exposed a wrong
new test assertion: anonymous login was expected to acquire an auth-row
Principal, contrary to migration 19's operation CHECK. Only the assertion was
corrected; exact persisted Session identity/result checks were added. The final
reviewed source passes the complete Linux platform gate with fresh fixtures,
including migration/authority/callback and TLS/process/restart/expiry suites.
Go uses the Dockerfile's digest-pinned 1.26.8 runner; fixture versions remain
PostgreSQL 18.6 and Redis 8.8.0. This is local Linux evidence, not a claim that
remote CI, the native-host clock lane, live Google/client or operational HA pass.

`LoginContinuationGuard` issues a NEW stateless CSRF proof, not the already
cleared Start proof/cookie. A separate resident HMAC-SHA-256 purpose/key binds
the full ordered Route/origin, current private pre-auth handle, exact encrypted
capsule commitment and canonical version/key/issued/expiry/random payload.
Independent 256-bit CSPRNG challenge, strict whole-second 30–120-second lifetime,
canonical base64url, exact key and constant-time MAC are required. No skew,
previous-key or Start-purpose fallback exists. Proof contains no raw cookie,
capsule, state, code or identity; implicit formatting/logging/JSON is redacted or
refused. No new cookie/session is created. See the
[OWASP signed binding guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#signed-double-submit-cookie-recommended);
this is pre-auth intent only, never an authenticated session or replay claim.

`LoginContinuationGate.Prepare` accepts only POST
`/auth/v1/login/continue/prepare`, authenticates live capsule transport, and writes
no-store `csrf_token`/`expires_in` JSON only. `Read` accepts only POST
`/auth/v1/login/continue` plus the custom-header proof and returns untrusted
`LoginCallbackInput`; it writes no success status/body, clears no cookie and
performs no durable browser verification, claim, exchange or Session issuance.
Both variants require completed direct TLS 1.2+, exact Host/Origin, origin-form
fixed target without query/encoded path, `X-MeshTransit-Login: v1`, JSON `{}` within
32 bytes and coherent same-origin AJAX metadata when present. Authorization,
ambiguous headers, transfer/trailers, Referer-only or proxy-selected admission
reject. Existing header/cookie budgets remain unchanged.

Source HMAC budget precedes crypto; an exact Deployment/epoch/state HMAC budget
precedes release. Both use shared Redis with separate purpose/counter namespaces,
including the additive `auth_transaction` kind. Unavailable/malformed decisions
fail closed; exhaustion returns a closed limited error with bounded Retry-After.
Callers map invalid/limited/unavailable-or-saturated to safe 403/429/503 responses,
not dependency error text. A non-queuing 1–128-slot semaphore and at most 30-second
admission context enforce bounds, together with mandatory transport read/write
deadlines. Fresh proof/capsule checks after Redis waits reject expiry/cancellation.
The future caller must separately own the WHOLE application/response deadline
and capacity. Partial proof-response write failure cannot be retried or rewritten.

`SSO-CONTINUATION-ADMISSION-001` source tests cover exact bindings, key ownership,
malformed authenticated payload, byte tamper, both callback variants, dependency/
time/cancellation/capacity failures, no secret/authority response, synthetic
verified-HTTPS transport and bounded proof/HTTP fuzz. Disposable verified-TLS
Redis tests also cover the new kind's isolated shared counter identity; this is
not operational HA/real browser/Google acceptance. Private count/duration metrics
have closed operation/result labels; `input_released` is not authentication.

No public route/metric registration, BFF page, client wire, configuration/schema
version or public login default changes. Application orchestration is implemented
separately below; fresh session-cookie rotation and safe read-only BFF landing
remain next. Query-log suppression,
operational expiry/recovery coverage and live Google through Keycloak remain
release gates, not implied by these primitives or existing client regressions.

### Confirmed-only browser callback application orchestration

`SSO-BROWSER-ORCHESTRATION-001` constructs the existing verification, claim,
exchange, subject-resolution, issuance and failure services exactly once from
explicit ports and resident crypto, with one live clock. `CallbackCommand` is
immutable redacted syntax only; `LoginCallbackInput.Command()` translates it
without I/O or authentication. HTTP continuation POST/CSRF admission must
precede execution and the HTTP caller still owns the entire response deadline.

`CallbackService.CompleteBrowser` owns one <=30-second application context and
non-queuing 1–128-slot capacity retained until synchronous cleanup joins. Fresh
durable route/state/pre-auth verification precedes confirmed claim, one original
receipt-bound PKCE exchange, exact existing-subject read and atomic issuance.
Provider-error input verifies/claims but never exchanges. Before invoking
issuance, failures may erase ONLY a confirmed claim once in an independent
<=5-second failure window; each owned rollback is separately bounded <=5 seconds.
Cleanup never extends provider/issuance work or permits expired/canceled release.
No goroutines, open database unit across provider I/O, code retry, resolver,
receipt reconstruction, email linking, JIT provisioning, refresh or role grant.

Every claim error returns zero result and no downstream effects. Once issuance
is invoked, ANY error returns zero and NEVER invokes failure/resolution/retry,
including unknown Commit and cancellation/time failure AFTER confirmed Commit.
An error is not proof of non-commit: consuming rows use expiry; undisclosed
committed Sessions use normal expiry/revocation. Final fresh uncanceled release
exposes either confirmed issued evidence or provider-error no-grant erasure,
never both. Input/params/result JSON is refused and formatting/logging redacted.

Anonymous login keeps the original auth-row principal_id NULL even after
success, as required by migration 19's operation CHECK. The newly issued
Session carries the resolved Principal/subject instead. DB assertions check
the account_session result kind/reference and persisted Session identity;
they do not change the original operation binding or released migrations.

Named unit/race tests cover sequencing, proof/substitution fences, both callback
variants, unknown acknowledgements, post-commit cancellation/expiry, incomplete
cleanup, typed-nil construction, global deadlines and nonqueued cleanup ownership.
Ten disposable verified-TLS PostgreSQL callback scenarios pass in the explicit
Linux lane: confirmed issuance, provider error/failure, absent exact subject or
auth_time, hidden claim/issue/failure ACK after real Commit, cancellation after
confirmed issue Commit and issuance-evidence rollback. They verify exact
Session identity/result, original anonymous operation, atomic lifecycle evidence,
proof erasure, no JIT/membership/role/Network mutation and replay rejection.
They use a controlled trusted provider port, not live Google/signature/broker
evidence. Full native-host `make quality` and a 10-second/two-worker callback
command fuzz run pass. Native-host clock and remote/live target qualification
remain separate and are not implied. Isolated private
callback active/count/duration metrics have only a closed result label; no
global/public registration or raw error/identity/credential data.

No wire, schema, configuration or disabled public-login default changes.
The private completion and clean landing profiles below address cookie/response
and read-only page source composition. Public runtime
metrics/tracing, query-log suppression, intended expiry/clock/recovery coverage,
and pinned Google-through-Keycloak/client/HA acceptance remain separate gates.

The boundary threat model is fail-closed:

- Spoofing and mix-up: exact issuer, discovery, authorization, token, JWKS,
  client, redirect, and provider capabilities must match Core-owned
  configuration.
- Tampering and replay: state and nonce have separate HMAC domains; the PKCE
  verifier is AEAD-bound to every transaction authority generation.
- Repudiation: transaction creation commits with the existing immutable
  audit/outbox contract; evidence failure prevents creation commit.
- Information disclosure: cookie, state, nonce, verifier, ciphertext, and the full
  redirect always format redacted and must not enter logs or metrics.
- Denial of service: discovery time, response headers, decompressed body size,
  endpoint count, capability count, and redirects are bounded.
- Elevation of privilege: provider roles, groups, Organization, email, and
  mutable claims are absent from authorization construction and cannot create
  Core membership or RBAC.

### Confirmed browser completion response

`SSO-BROWSER-COMPLETION-001` privately composes protected continuation admission,
callback orchestration and response delivery. `LoginCompletion.Complete` owns one
request-derived <=30-second context and non-queuing 1–128-slot capacity through
joined cleanup and delivery; it creates no goroutine, route or per-browser state.
It rejects invalid/typed-nil dependencies, unsafe return mappings and dirty
credential/redirect/length/transfer response headers before effects. It bounds
HTTP input before copying headers. The gate's shorter child context/deadlines
never replace the whole request: restore transport deadlines before provider/
database work, and clamp to an earlier caller deadline.

Only an opaque confirmed fresh callback result matching the entire configured
Route can reach delivery. `CallbackResult.Route/IsLiveAt` preserve original
binding and exclusive claim/provider/Session expiry plus DB issue/subject-read
time; these are release checks, NOT a current RBAC or revocation decision.
Continuation CSRF/capsule checks remain fresh after provider/DB waits. Fixed
Core-owned ReturnRouteID maps to a canonical local ASCII return_path <=256 bytes;
no request-selected URL, query, fragment, encoding, backslash, dot/double-slash
path or auth loop is allowed.

Successful AJAX POST returns 200 JSON with only return_path. Bearer material
exists only in one __Host-mt_session Set-Cookie: Secure, HttpOnly, SameSite=Lax,
Path=/, no Domain. Expires/Max-Age round DOWN to the earlier idle/absolute expiry,
require at least one remaining second and never exceed 24h. No new lifetime or
refresh is implied. Incoming Session/pre-auth/capture/intent material never
becomes the new CSPRNG bearer. A private bounded complete header candidate passes
encoding/cancellation checks before touching the writer; each full cookie <4096
bytes, combined headers retain the existing 16384-byte/64-field/128-value bounds.

Success replaces the Session and expires the exact pre-auth, callback capture and
login-init cookie scopes. Confirmed provider error returns generic 403 JSON and
expires only those three transient scopes, never a retained Session. Other
failures release no status/body/cookies; closed errors preserve only safe
cancellation/unknown-Commit classifications for the future caller. No arbitrary
dependency diagnostics or credential/identity/header material enters metrics,
logs, body, URL or redirects. Security/no-store headers remain mandatory.

`ErrLoginCompletionDelivery` means response delivery began and may be partial.
Never rewrite/retry it or infer non-commit; no post-issuance failure/resolver is
called. Write success does not acknowledge browser receipt. An undisclosed
committed Session uses normal expiry/revocation. Isolated private
meshtransit_browser_completion_requests_active, requests_total and
duration_seconds metrics have only a closed result label; duration includes
joined cleanup/delivery. Runtime tracing/metrics registration is a separate gate.

Unit/race tests target typed-nil construction, clean local paths, HTTP/CSRF
admission, response-header ownership, parent/transport deadlines, zero-output
unknown commits, fail-fast whole-request capacity/leak-free joins and closed
telemetry. Fuzz targets local return-path parsing. Disposable verified-TLS
PostgreSQL fixtures exercise the complete reader/capture/continuation/application/
cookie pipeline with a controlled trusted provider and budget port; they are
not live Google signatures, Redis failover or public browser acceptance.
All 18 durable completion scenarios and the full platform gate pass in the
explicit pinned Linux lane. They retain exact Session/anonymous-operation,
audit/outbox/proof-erasure and no-JIT/role/membership/Network assertions. Additional
delivery cases cover partial/short writes and suppression after real confirmed
issuance for expired continuation while Session remains live, backward clock,
subsecond cookie lifetime, cancellation, complete-route substitution and combined
header budget. The already documented native-host clock failure is not waived.
Public runtime/routes and browser landing acceptance, authenticated management
cookie-CSRF, proxy/query-log suppression, intended expiry/clock/recovery coverage
and pinned Google-through-Keycloak/client/HA acceptance remain separate gates.
No wire, schema, dependency, configuration or disabled public-login default changes.

### Private browser composition recipe

`SSO-BROWSER-COMPOSITION-001` constructs private initiation, callback
reader/capture, continuation, confirmed completion and clean landing from one
Core-owned Route/Origin/local return mapping and a shared live clock. Explicit
application and shared-budget ports reject nil/typed-nil before effects. Three
resident 256-bit keys require distinct IDs and nonzero distinct material;
transaction, Session and rate-limit keys must remain separate too. Constructors
copy resident keys and bounded proxy inputs; caller owns input erasure. At most
16 canonical distinct proxy prefixes, never /0 or IPv4-mapped prefixes. No
provider/database/budget/entropy/listener effect occurs during construction.
Seven component collectors register only in a new isolated private registry;
the root must explicitly register its combined collector on private telemetry.

Callback GET Capture owns its complete <=30-second caller-clamped context,
mandatory read/write deadlines and non-queuing 1–128-slot capacity through
submission. Strict reader admission (plus rejection of Authorization custody)
precedes purpose-separated shared source/state budgets and OS entropy. It never
verifies durable possession, claims, exchanges or issues authority. Prepare
the complete redirect headers privately, reject credential/navigation/encoding/
reporting middleware, check combined header limits and fresh time/cancellation,
then submit exactly one encrypted host-cookie/zero-body 303 to the fixed clean
path. Pre-release errors change no caller header/status/body; no retry or rewrite.
Closed capture active/count/duration metrics mean submission, not browser receipt
or authentication. Other components retain independent documented capacities
and deadlines; admission/capture and whole-completion timeouts are explicit and
separate. The durable fixture retains 5-second admission/25-second completion.

Named source/race tests cover invalid profiles/key-purpose reuse, immutable keys
and observable source/state budget bindings, initiation-only behavior, protected
continuation, fail-closed budget/transport/time/header boundaries, joined capacity,
redaction, closed telemetry and verified test-CA HTTPS. Bounded capture HTTP fuzz
checks no GET authority/reflection. The existing 18 durable completion scenarios
now run through the recipe/capture and read-only GET/HEAD landing without changing
authority oracles; provider/budget ports remain controlled, not live acceptance.

This recipe is not public runtime/config wiring: no environment flag, secret
loader, public dispatcher or listener is added. Management cookie authentication/
CSRF runtime binding, private runtime metrics/tracing, edge/BFF query-log
suppression, native-host clock, intended expiry/recovery,
Google-through-Keycloak/client/HA and artifact
acceptance remain separate gates. No schema, client wire, dependencies,
configuration or disabled public-login default changes.

### Clean read-only continuation landing

`SSO-CONTINUATION-LANDING-001` privately presents exact clean origin-form GET/HEAD
on /auth/v1/login/continue, completed direct TLS 1.2+ and the configured Host.
No query/fragment/encoded/foreign URL, body, ambiguous credential/routing header
or incoherent navigation metadata may reach active content. Optional Origin is
exact. The constructor extracts immutable origin/local return mapping from
validated private completion; it never retains or invokes an application port.
GET/HEAD neither parse/open cookies nor mint proof, consume budgets, call DB/OIDC,
claim, exchange or issue authority. Missing cookies receive the same static page.

Pre-render <=16384-byte embedded HTML/script/style before requests. Escape only
the Core-owned local mapping; no request material participates in rendering.
No-store/no-referrer/framing protections and hash-only script/style CSP permit
self-only fetch, never unsafe-inline/eval, CDN, analytics, forms or external
assets. Reject middleware navigation/encoding/reporting/authentication headers;
HEAD has identical bounded safe headers with no body. Scrub browser history to
the fixed clean path without reading query/fragment/cookies/storage.

An accessible explicit button starts one fixed same-origin POST prepare/continue
chain. Only {} / application/json / X-MeshTransit-Login: v1 and the fresh
continuation CSRF header are sent. Credentials are same-origin; redirects reject;
cache/referrer are no-store/no-referrer. Proof exists only in function memory,
never DOM/storage/URL. Read <=1024 bytes of successful JSON with exact Core-owned
canonical encodings/schemas, reject duplicates/aliases/unknown fields/empty chunks,
and navigate only if return_path equals the exact configured local mapping.
One <=30-second browser abort budget includes fetch and response reads, with
pagehide/reader/timer/listener cleanup. No automatic POST, retry or button re-enable.
Generic failure never claims non-commit; server claim, not UI state, owns single
use. Uncertain committed Sessions retain ordinary expiry/revocation semantics.

HTTP presentation owns a non-queuing 1–128-slot cap through delivery and one
caller-clamped <=30-second context with mandatory read/write deadlines. Always
deliver through ResponseWriter.Write, never a promoted StringWriter bypass.
Partial/short delivery has a distinct closed error: never rewrite/retry. Isolated
private browser_landing active/count/duration metrics expose only a closed result
label, no topology, request, credential or identity. No queue, goroutine, listener
or per-browser server memory is created.

Source tests cover strict admission, zero authority/reflection, HEAD, exact CSP
bytes, finite deadlines/cancellation/capacity/leak-free delivery, verified test-CA
HTTPS and closed telemetry. Bounded Go HTTP fuzz and the deterministic embedded
script harness qualify source behavior, not a browser engine/CSP/rendered UI or
live Google signatures. Run script checks separately from Go quality gates:

```sh
node --test internal/adapter/httpapi/login_continuation_landing_test.mjs
```

The harness uses only Node built-ins, no packages/network. This source lane is
qualified with Node 22.20.0; Node is not a build/runtime dependency of meshcore.
The disposable PostgreSQL fixture also presents GET/HEAD before the existing
18 protected durable completion scenarios, with controlled provider/budget ports.
Public runtime/config/routes, private metrics/tracing registration, authenticated
management cookie-CSRF runtime binding, edge/BFF query-log suppression,
native-host clock, intended expiry/recovery and pinned
Google-through-Keycloak/client/HA acceptance
remain separate gates. No schema, Go-module, client wire, configuration or
disabled public-login default changes.

### Private cookie-authenticated management

`SSO-MANAGEMENT-COOKIE-CSRF-001` constructs a private Console profile around the
same versioned management handler, with explicit Deployment, exact canonical
HTTPS Origin, shared live clock and a dedicated resident 256-bit HMAC key.
Reject incomplete/typed-nil ports, unsafe proxy trust, noncanonical origin/key
and lifetime/capacity bounds before effects. Copy key material; caller owns
input erasure and separation from login/capture/continuation/Session/rate keys.
The later composition root must validate cross-component key separation; this
profile cannot inspect secret custody hidden behind its durable application ports.
No constructor calls DB/budgets/entropy or starts workers/listeners.

Only completed direct TLS 1.2+ origin-form POST, exact Host/Origin, canonical JSON
and X-MeshTransit-Session: v1 are admitted. No Referer fallback, Authorization
custody (even empty), routing/query/fragment/transfer/trailer/upgrade ambiguity
or incoherent Fetch Metadata. Header limits are 16384 bytes/64 fields/128 values;
Cookie limits are 8192 bytes/8 fields/64 pairs, with exactly one canonical nonzero
mtas1 __Host-mt_session. Proxy claims never replace TLS/Host/Origin.

Fixed POST /auth/v1/session/prepare reads only {} with optional surrounding JSON
whitespace (4 KiB maximum). Purpose-separated shared source and authenticated
Session budgets precede independent 256-bit OS nonce generation. Fresh durable
Session authority matches Deployment/recovery and exclusive live time. Return
only csrf_token and expires_at in bounded no-store JSON, never identity, bearer,
provider data, cookie issue/renew/clear or operation authority.

The <=256-byte mtscsrf1 envelope has canonical key ID/times/nonce/MAC. Dedicated
HMAC-SHA-256 purpose binds exact Deployment/Origin and the complete resident
Session bearer, not public Session ID alone. Lifetime is 30–120 whole seconds,
shortened/floored to idle/absolute Session expiry, with at least one second left
at preparation submission. No future issue, expiry equality or clock grace.
Each mutation verifies one X-MeshTransit-CSRF before freshly authenticating its
cookie; recheck Session/scope/proof/time before application admission. The proof
is replayable intent transport, not cached identity/RBAC or an operation grant.
Key/profile/cookie/recovery changes reject; replicas use the same profile/key.

Device revoke and policy publish keep the same decoding, exact-scope RBAC,
ETag/idempotency, source/Session budgets, transaction/audit/outbox/result contracts
and original 4 KiB/8 MiB input bounds. Never synthesize Authorization or forward
cookie credentials to the Bearer entry point; its existing behavior is unchanged.
Prepare and mutations own one <=30-second caller-clamped context, mandatory
transport deadlines and non-queuing 1–128 cap through actual response delivery.
Management's independent deadline/cap remains. A <=32768-byte private JSON
candidate, combined header limits and final fresh Session/proof/cancellation
checks precede one actual status/body submission. Final freshness/remaining
lifetime use one live clock snapshot and recheck cancellation after validation;
deterministic prepare/mutation tests cover cancellation during that clock read.
Reject credential/navigation/
encoding/reporting/CORS middleware and omit Bearer challenges. Pre-release errors
leave caller headers/status/body untouched; short/failed writes are closed
uncertainty, never proof of non-commit, rollback, retry or rewrite. Closed isolated
active/count/duration labels mean submission, not commit or browser receipt.

Source contracts cover constructor/input/clock/authority/budget boundaries,
MAC tampering and purpose/scope replacement, cookie ambiguity, redaction, final
freshness, joined capacity/leaks, bounded candidate/delivery and verified test-CA
HTTPS. Separate bounded fuzz targets exercise cookie/proof parsers. Disposable
TLS PostgreSQL fixtures use actual durable Session authentication, cookie policy
publication and an idempotent cookie revocation replay; existing exact audit/
outbox/revision oracles remain unchanged. Budget/TLS-header fixtures are controlled,
not live Redis/browser/Google/Keycloak or public dispatcher qualification.

No public runtime/config/OpenAPI profile, listener/env flag/secret loader, schema,
client wire, dependency or disabled-login default changes. Runtime authentication
profile/OpenAPI/private metrics/tracing/dashboards/alerts, query-log suppression,
native-host clock,
intended expiry/recovery, Google-through-Keycloak/client/HA and immutable artifact
acceptance remain separate release gates. Canonical local identity/security/ADR
docs are updated; the sibling core-docs tree is not a Git repository, so this
versioned mirror travels with source. Move canonical docs into a versioned release
path before public enablement; this slice does not silently initialize/move them.

Final local source qualification (2026-09-17): make quality passes, including
whole-repository shuffled unit/race, pinned lint/integration lint, vet, module/
format consistency, vulnerability-symbol and workflow checks. Govulncheck finds
zero affected symbols/imported packages but three module-only advisories; this
is not a zero-advisory claim. The unchanged Node 22.20.0 landing harness passes
all 49 tests. Ten-second/two-worker proof and cookie fuzz pass 270573/244274
executions. The uncached same-kernel Linux TLS PostgreSQL/Redis platform lane
passes 15.918s/6.445s on the final corrected source. Cancellation during the final
clock read was demonstrated failing before correction, then both preparation
and mutation regressions pass, including joined race repetition. Tree secret
scan passes with full redaction and no added baseline/exclusions. This evidence
does not waive the previously recorded native-host clock failure, qualify remote
CI/live Google/browser/client/HA, or constitute an immutable release artifact.

### Private identity key preparation

`SSO-PRIVATE-KEY-LOADING-001` prepares a coherent private composition-root key
candidate, not public SSO. An explicit immutable file-reference profile names
eleven required purposes: initiation, capture, continuation, management CSRF,
transaction digest, verifier encryption, subject binding, provider Session
binding, Account Session, idempotency and rate-limit subjects. Subject and
Account Session alone admit one optional previous key each. Reject missing
purposes, duplicate paths/IDs and invalid references before filesystem effects.
No map, service locator, env flag, default/generated key or secret literal.

This narrower private profile uses distinct canonical absolute <=4096-byte
references and distinct 1–64-byte ASCII letter/digit/hyphen/underscore IDs,
starting with a letter/digit. It does not change existing key-ID/environment
contracts. All 11–13 decoded nonzero 256-bit materials must also be distinct,
including previous keys; comparison is constant time. Reject the entire
candidate on any failure; no partial key release or per-purpose fallback.

On operator-trusted local Linux/macOS mounts, os.Root scopes each file to its
parent. In-root projected-volume symlinks work; escaping links reject.
Nonblocking open rejects FIFO/special-file admission without waiting for a
writer. Opened files must be regular, owner-readable, with only 0400/0600
permissions; no special/executable/group/world bits. Reads stop at 46 bytes.
Accept exactly 43 canonical unpadded base64url characters with at most one LF
or CRLF. Reject whitespace, padding, extra lines, zero or substituted material.
Recheck descriptor/path metadata after each read, then every recorded path
snapshot after the complete candidate, without reloading/merging individual
keys. Ordinary projected-mount rotation withholds the entire candidate.

One caller-clamped five-second context covers loading/resident construction,
with cancellation checks around filesystem work, comparisons and final release.
No detached worker/retry/background context. Check read/close errors, conceal
raw diagnostics and erase owned encoded/decoded/partial buffers on all exits.
Copy into the existing typed transaction/verifier/subject/provider-Session/
Account Session/idempotency/rate-limit owners and four independent browser key
buffers, then clear the loader result. Formatting/logging/JSON are redacted or
refused. Tests retain the exact nil-context failure oracle.

Operators own mount/ancestor custody and atomic rotation. Context cannot preempt
local filesystem syscalls; remote/NFS mounts are unsupported by this profile.
Snapshot checks are not a global filesystem transaction or resistance to a
privileged writer restoring inode metadata. Erasure is best effort, not a Go
heap/core-dump zeroization guarantee. Unsupported operating systems fail closed.
The private identity application root below uses the same resident owners rather
than reload/replace individual purposes; production binding remains separate.

Source tests cover hostile profiles, all-or-nothing loading, optional rotation,
resident ownership, exact Session digests, redaction, scoped symlinks, owner-only
permissions, FIFO rejection, earlier-file rotation and late read/cancellation.
Separate bounded fuzz gates cover the key decoder and private ID parser.
No listener, public dispatcher, provider/DB/budget/entropy work, environment
schema, client wire, dependency or disabled public-login default changes.
Private application-port composition and collector binding are described below;
production auth-profile/OpenAPI and dependency-factory binding remain next steps.
Query-log suppression, native-host clock, intended expiry/recovery,
live Google through Keycloak/client/HA, remote CI and immutable-artifact gates
are not qualified by source preparation. Canonical original docs are updated
locally; this README is the versioned mirror, not a claim that the sibling
core-docs directory was committed.

Local source qualification (2026-09-17): unchanged make quality passes full unit/
race/shuffle, vet, pinned lint/integration lint, format/module, vulnerability and
workflow checks. Govulncheck reports zero affected symbols/imported packages and
three module-only advisories. Ten-second/two-worker key-decoder/ID fuzz passes
1225706/1253836 executions. Uncached config/cmd race/shuffle passes under pinned
Go 1.26.8 on Linux as UID/GID 65532, with no network, capabilities, writable source,
host credentials or Docker socket (1.046s/1.035s). The first disposable scratch
mount was noexec, so no test executed; the corrected harness permits execution
only in its isolated scratch while retaining nosuid/nodev/non-root/read-only
boundaries. This is source-file loading evidence, not a PostgreSQL/Redis/live
provider, public SSO, client or operational clock qualification. Fully redacted
tree and complete-history secret scans pass with no new baseline/exclusions.

### Private identity application root

`SSO-PRIVATE-APPLICATION-ROOT-001` composes actual Start, Callback and Account
Session services, the existing browser login BFF and cookie-management wrapper
from one resident private key bundle. Start and Callback share the exact
transaction/verifier owners; Callback issuance and fresh Session authentication
share the exact Account Session keyring. Subject and provider-Session binding,
idempotency and rate-limit purposes retain their existing typed owners. The
caller exclusively owns the four mutable browser buffers; constructors copy
them before the caller may erase them. No key reload, alternate key/clock/
Deployment or prebuilt authentication-service injection.

Typed effect ports explicitly supply route admission, metadata, creation and
confirmed-creation lookup, pending/claim/failure/issuance authority, provider and
subject resolution, fresh Session authority, ID/secret/material generation,
revocation/policy services, shared budgets, clock and logger. Reject absent and
typed-nil ports before construction. The composition helper opens/probes no DB,
provider, entropy, budget or listener and does not establish dependency readiness.
Production binding must supply current durable authority and shared budgets;
passing typed ports alone is not operational qualification.

One caller-clamped five-second context covers effect-free construction and final
all-or-nothing release. Start/Callback windows cannot exceed their corresponding
HTTP windows; existing constructor guards retain route/origin/return, lifetime,
capacity and proxy contracts. No detached worker, queue, retry or partial root.
Existing independent per-component admission caps remain independent, not a
deployment-wide concurrency claim. Options, ports and root redact formatting/
structured logging and refuse JSON serialization.

The root owns a pedantic private registry collecting Start, Callback, subject,
issuance, browser login, resource management and cookie-management telemetry.
It performs no global/public registration and adds no identity/provider/query/
cookie/token/proof/path labels. Operator registration, dashboards/alerts and
tracing remain production work, not consequences of constructor success.

Synthetic contracts cover all 21 absent/typed-nil ports, invalid profiles/key
drift, effect-free construction and cancellation before/during release; actual
creation/claim/issuance plus authentication with the newly issued token; fresh
authority after revocation; no-grant, exclusive expiry and uncertain Commit
rules; BFF intent/Start/GET capture after caller-buffer erasure; cookie proof,
resident budget/idempotency binding, fresh mutation authentication; and registry
isolation/redaction. Controlled provider evidence and in-memory lost-ACK effects
are not signature validation, PostgreSQL acknowledgement, durable mutation or
browser/client/HA qualification. Fixture corrections retained existing confirmed
Commit/no-rollback, failure-class and origin-form API-path contracts; no guard,
oracle, gate, baseline or exclusion was weakened.

No main/runtime/config/public dispatcher/listener, public SSO activation, Bearer
API, client wire, SQL/schema, dependency or default changes. Public SSO remains
disabled. Auth/OpenAPI profile and production dependency factories come next,
then query-log suppression, native-host clock and intended expiry/recovery,
Google-through-Keycloak/client/HA and immutable-artifact release gates. Canonical
identity/security/observability/ADR documents are updated locally first; this
README is their versioned mirror, not a claim that the non-Git sibling core-docs
directory was committed.

Local source qualification (2026-09-17): unchanged make quality passes whole-
repository shuffled unit/race, vet, pinned normal/integration lint, format/module,
vulnerability-symbol and workflow gates. Govulncheck reports zero affected symbols/
imported packages and three module-only advisories, not zero advisories. Initial
lint rejected request-cookie literals and a credential-like TokenEndpoint field;
complete cookie attributes and endpoint derivation from one reserved URL retain
the exact fixture profile without suppression. Uncached config/cmd race/shuffle
passes under pinned Go 1.26.8 Linux UID/GID 65532 with no network, capabilities,
writable source, host credentials or Docker socket (1.034s/1.061s). Ten-second/
two-worker unchanged HTTP capture/proof/cookie fuzz passes 52540/225987/256034
executions. Fully redacted tree and complete-history secret scans pass without
new baseline/exclusions. No PostgreSQL/Redis/provider integration or live client/
browser test runs in this slice; native-host clock remains unqualified. Source
evidence does not qualify public enablement, remote CI or immutable artifacts.

### Private direct-TLS login service

`SSO-PRIVATE-LOGIN-TLS-SERVICE-001` adds `httpapi.LoginServer`, an owned
Start/Shutdown/Done service, not public runtime activation. The concrete factory
can compose it only from its own existing dispatcher. There is no alternate
handler/route/clock/provider, forwarding-based TLS assertion, environment flag,
main binding, public docs/metrics endpoint or readiness claim. Client wire,
Bearer entry point, authority/revision propagation, schema and dependencies
remain unchanged. Google login remains THROUGH Keycloak, SSO-only.

Require an explicit canonical non-wildcard/non-multicast IP bind and connection
cap 1–4096. Port zero exists for owned fixtures only. Parse separately owned
resident PEM inputs (at most 64 KiB each/eight certificates), with a non-CA
server-auth leaf and exactly the callback hostname as its sole SAN. Reject
wildcards/shared identities, weak signatures and unsupported/weak key profiles;
support RSA 2048–8192, NIST ECDSA P-256/P-384/P-521 and Ed25519. Construction
opens no socket or clock/dependency effect; the one-shot cancellable Start uses
actual system certificate validity. Caller PEM may be erased after construction.
No live certificate reload or shared TLS ticket-key owner is added.

Serve direct TLS 1.2/1.3 and HTTP/1.1 only, no ServeMux normalization, HTTP/2/h2c,
general OPTIONS fallback or raw net/http error logging. Header/handshake,
read/write, idle and header-size caps are five seconds, 35 seconds, 60 seconds
and 16 KiB. Connection capacity bounds accepted handshake/HTTP goroutines;
existing component body/work/non-queuing/distributed-budget bounds still apply.
Delegate the original request/context/writer. ConnContext installs a private
connection-scoped raw socket owner, never identity metadata. On dispatch failure
close that owned raw TCP socket before returning; otherwise staged cookies could
implicitly flush as HTTP 200. No expected-error panic/`ErrAbortHandler`, Hijack
or TLS close-notify write is used for abort. Check/classify close failures into
the service's final closed result. Never overwrite partial submission, infer
non-commit or retry effects. Component-owned normal responses remain intact;
this is not the future public friendly-error mapper.

Shutdown fences handler admission and drains within its caller context. On
expiry cancel request ownership and close sockets. The serving owner joins
every ConnState-tracked handler, including handshakes/connection teardown,
before Done. Shutdown success includes that join; timeout is not join proof or
permission to close factory/storage. Only after join may the process close
factory idle clients; PostgreSQL/Redis remain borrowed. Profiles and owners
redact formatting/structured diagnostics and refuse JSON serialization.

Canonical runtime/security/identity/acceptance/ADR originals were updated
locally before implementation. This README is their Git mirror; the sibling
core-docs directory is not a Git repository. Public SSO stays disabled. Edge/
query/key custody, native-host clocks, intended expiry/recovery, real Google/
Keycloak/browser/client/HA, remote CI and immutable-artifact gates remain open.
Next: validate the immutable runtime configuration and readiness prerequisites,
then wire the service into `api`/`all` ownership without bypassing release gates.

Source qualification (2026-09-17): final corrected no-panic bytes pass unchanged
full `make quality`: whole-repository shuffled unit/race, formatting/tidy/vet,
pinned normal/integration-tag lint, symbol-vulnerability and workflow gates.
Govulncheck reports zero affected symbols/imported packages and three non-called
required-module advisories, not zero advisories. Final uncached host full
httpapi/cmd race passes 1.872s/2.209s; exact pinned Go 1.26.8 Linux/arm64 source
race passes 1.407s/1.094s, UID/GID 65532, no network/capabilities/credentials/
Docker socket, read-only source/modules and isolated writable scratch. The
missing exact-image metadata was resolved by an approved exact-digest pull
reporting up-to-date, not an alternate image/mount. Earlier panic-based-byte QA
is superseded. Tests cover owned TLS/no-grant GET/HEAD, erased caller PEM,
Host/path/method/query/plaintext/ALPN fencing, certificate/bind/startup bounds,
staged/partial raw TCP abort, checked close errors, parent context preservation,
graceful/forced handler joins, connection capacity and goleak. Factory-service
composition uses actual lazy adapters without requests; no live PostgreSQL/
Redis/provider/Google/browser/client/HA or native-host-clock qualification runs.
This is source evidence, not remote CI or an immutable release artifact.
Fresh unfiltered pre/post lint and scoped pinned v2.13.2 autofix pass with no
changes; all 710 repository Go hashes and exact six target texts stay frozen.
Gitleaks v8.30.1 redacted full code/docs trees and all 134 pre-commit history
commits pass without new baseline, exclusion, suppression or gate changes.

### Private identity production dependency factory

`SSO-PRIVATE-DEPENDENCY-FACTORY-001` binds the private identity graph to concrete
production adapters, not runtime enablement. `composePrivateIdentityFactory`
accepts the same resident key bundle and Core-selected Route/HTTPS Origin/local
return mapping, borrowed runtime PostgreSQL/TLS Redis dependencies, a resident
confidential-client `oidc.BasicSecret` and a logger. It accepts no alternate
clock/provider port, prebuilt login/mutation service, individual replacement key,
environment input, secret loader or service locator. One owned
`oidcauth.SystemStartClock` serves token validation, login/Session services,
browser/cookie management and both durable resource mutations. No construction
clock read; native-host clock remains a separate, unqualified release gate.

One runtime `AuthTransactionStore` supplies route admission, creation/replay,
pending, claim/failure/issuance and exact subject effects; one
`AccountSessionStore` supplies current durable Session authentication. Existing
constructors reject worker/zero/incomplete pools. Redis is shared directly for
distributed budgets, never identity/membership/RBAC/cache authority or a local
limiter fallback. Pure `ValidateRateLimiter` rejects nil/zero Redis clients
without issuing a command; it does not prove connectivity/readiness. Existing
Device revocation and Policy publication services retain scope/RBAC, atomic
audit/outbox, confirmed replay and bounded retry/idempotency rules. OS-CSPRNG
ID/secret/issuance generators are constructed, not invoked.

Discovery/token clients share the exact reviewed Route and existing TLS-only,
no-proxy/no-redirect constructors. Require explicit nonzero discovery timeout/
metadata limits within Start's work window; token timeout stays within Callback's
window. Existing token age/skew and `client_secret_basic` validation apply.
Google-first still means Google THROUGH the reviewed Keycloak broker; no direct
Google/local password/provider fallback or trust-discovery branch is added.

Clamp existing DB statement/lock/idle caps (five/two/ten seconds) to their work
owners. Auth uses the lesser Start/Callback window; Session/resource work uses
Management's window. Require at least two milliseconds, floor SQL limits to
whole milliseconds and cap lock at half the statement window. No positive
sub-millisecond value becomes PostgreSQL `0ms`/disabled timeout. Caller request
contexts still bound pool acquisition and all effects; SQL limits cannot replace
them. No new query, schema, grant, migration or database retry policy.

Five-second caller-clamped construction releases either the complete graph or
nothing, without network, authority, budget, entropy, clock or listener work.
The factory owns discovery/token clients and closes their idle connections on
failed construction or repeatable explicit `Close`. Added `oidc.Resolver.Close`
has the same idle-only ownership contract. Close neither gates admission nor
cancels/joins active requests: process owners must stop/drain first. PostgreSQL/
Redis remain borrowed and are never closed/reopened here. Redact factory/options/
dependency formatting/structured diagnostics and refuse JSON. Existing private
pedantic registry stays isolated, with no public auth logger/metrics middleware.

Source contracts use real lazy adapters and reserved synthetic endpoints, not
live requests. Cover complete construction, worker/nil/zero dependencies, unsafe
OIDC/application windows, late profile validation, cancellation/redaction, owned
idle cleanup and repeated independent registry/client construction. Named/fuzz
contracts cover SQL millisecond rounding, nonzero caps, bounds and overflow.
These do not prove borrowed dependency health, active draining, durable/provider
traffic or operational HA. No main/config/default/listener/public dispatcher or
SSO activation, Bearer entry point, client wire, dependency or CI changes.
Canonical identity/security/ADR/Keycloak docs were updated locally before code;
this README is their versioned mirror, not a commit of the non-Git sibling tree.
Full login-route OpenAPI/private dispatcher, query custody, clocks, intended
expiry/recovery, live Google/Keycloak/browser/client/HA, remote CI and immutable
artifact gates remain open. Public SSO remains disabled.

Source qualification (2026-09-17): unchanged full `make quality` passes host
format/module/vet, shuffled unit/race, pinned regular/integration-tag lint and
workflow checks. Govulncheck reports zero affected symbols/imported-package
vulnerabilities and three non-called required-module advisories; no dependency/
container zero-advisory claim. Final uncached host cmd/oidc/redis race tests pass
(6.761s/6.022s/5.835s). Final SQL-window fuzz passes 130,919 executions with two
workers over ten seconds. Scoped pinned autofix/read-only lint passes; the sole
literal-to-equivalent-options conversion was reviewed by reconstructing the exact
pre-fix SHA-256. No guard, oracle, dependency or gate was changed. Redacted
tree/full-125-pre-commit-history secret scans pass without new baselines/exclusions.

The operator authorized the earlier rejected source exposure. The exact pinned
Go 1.26.8 Linux source gate then passes uncached shuffled race tests for
`api/openapi`, `internal/config`, `cmd/meshcore`, `internal/adapter/oidc` and
`internal/adapter/redis` (1.094s/1.044s/1.210s/1.217s/1.277s), as UID/GID 65532
with no network/capabilities/host credentials/Docker socket and read-only source/
modules. Only isolated test scratch is writable/executable. The approved image
was initially absent locally and fetched by its exact digest; no alternate image,
mount/copy or indirect workaround. This qualifies current source only, including
the unchanged renderer below, not a historical commit/artifact, native clock,
durable/provider traffic, live Google/browser/client/HA, remote CI or release
artifact. Those gates remain open; public SSO remains disabled.

### Concrete private factory initiation integration

`SSO-PRIVATE-FACTORY-INITIATION-INTEGRATION-001` adds an integration-tag gate for
the actual compile-time private factory and dispatcher, with no injected clock,
transport or effect ports. It uses a separate cold `meshtransit_private_factory`
database on disposable PostgreSQL, all released migrations, audited privileged
fixture seeds and distinct least-privilege runtime credentials. Verified-TLS
SCRAM PostgreSQL and TLS/ACL Redis are checked before requests; initialized
storage is refused before writes. Existing platform/process gates remain intact.

Five sequential independent cases cover prepare/start pending creation, exact
metadata mismatch, discovery redirect, untrusted provider TLS and a closed
borrowed Redis client. Prepare grants no authority and contacts no provider.
Successful start persists one anonymous pending/version-1 auth transaction and
one mutation/audit/outbox event, with resident-key nonce/state, encrypted PKCE and
browser-cookie binding verified from durable reads. Failures release neither an
authorization URL nor login cookies. Principal/Account/Session/subject/membership/RBAC and
Network/revision counts cannot change. Token/JWKS/redirect-trap calls remain zero;
repeated factory Close leaves healthy borrowed PostgreSQL/Redis usable. Checked
cleanup, race and joined goroutine-leak verification cover owned fixture resources.

The explicit Linux platform lane now uses an internal-only owned Docker network,
read-only source and existing host module cache, offline module resolution,
non-root host UID/GID, no capabilities, host credentials or Docker socket, and
only owned fixture/scratch writes. A fixture-process startup OS-root environment
trusts its disposable HTTPS provider; production resolver TLS/no-proxy/no-redirect
behavior and runtime configuration remain unchanged. Missing offline modules
fail, never trigger Internet fallback. Integration-tag lint now additionally
covers `cmd/meshcore`; no old test/guard/constraint/schema/grant/dependency gate is
weakened. Canonical docs 13/17/18/26 were updated locally before code; this README
is their versioned mirror, not a commit of the non-Git sibling tree.

This gate qualifies initiation source behavior only, not signed callback or
Session issuance. Next add signed-provider callback, exact-subject/membership
denial, nonce/token failure and single-use replay qualification through this same
factory. Query custody, expiry/recovery, native/cross-host clocks, real Google
through Keycloak, browser/client/HA, remote CI and immutable release artifacts
remain open. No deployment, public listener or SSO activation; meshd/meshctl wire
compatibility is unchanged.

Source qualification (2026-09-17): final full `make quality` passes formatting,
module/vet, shuffled unit/race, pinned regular and expanded integration-tag lint,
symbol-vulnerability and workflow gates. Govulncheck reports zero affected
symbols/imported-package vulnerabilities and three non-called required-module
advisories; no zero-advisory dependency/container claim. Scoped pinned autofix
and read-only lint make no fixes; both new-file texts and all 38 cmd Go hashes
remain unchanged. Bounded DB review fixes give every seed SQL its owned context
and add Principal census. Final uncached host private-identity race contracts
pass (2.306s), not host storage integration. Existing dispatcher-routing fuzz
passes 55,251 executions over ten seconds with two workers. Shell syntax and
invalid-mode rejection pass; redacted tree/all-127-pre-commit-history secret scans
pass without new baselines/exclusions.

Final fresh Linux source execution passes the complete released-migration suite
(15.478s), all five named initiation cases without Skip (cmd race package
1.434s), joined leak checks, and unchanged dependency/process restart/expiry
suites (6.277s). Go uses the existing exact Dockerfile image digest; PostgreSQL
18.6 and Redis 8.8.0 use observed manifest digests
`1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af` and
`234c902a2db49461a129e2d4aeff85b28cf20187ed274a67f6e50995fa713c7b`.
Missing named references resolved via the exact pulls, not alternative images/
mount profiles. An initial internal-network run failed before Go at the obsolete
host-port lookup; Linux now uses owned DNS with no published ports, while native
mode preserves loopback bindings. The first full quality run exposed an int-to-
byte fixture conversion; typed table values resolve it without suppression.
All disposable resources are removed on exit. No production Go, old oracle/guard,
schema/grant/constraint, dependency or freshness rule change. This is current
initiation source evidence, not signed callback/Session issuance, native clocks,
Google/browser/client/HA, remote CI or an immutable artifact. Public SSO stays off.

### Concrete private factory signed-callback integration

`SSO-PRIVATE-FACTORY-CALLBACK-INTEGRATION-001` extends the source-only gate through
the actual private factory, system clock/CSPRNG, runtime PostgreSQL stores and
shared Redis budgets. An owned verified-TLS provider signs synthetic RS256 ID
tokens and serves exact registered discovery/token/JWKS endpoints. Production
OS-root TLS, no-proxy/no-redirect clients remain untouched; no effect/provider/
clock/transport override or runtime activation setting is added.

A separate cold `meshtransit_private_factory_callback` database applies all
released migrations and refuses initialized storage before writes. Audited admin
seeds configure a verified Account, exact opaque issuer/subject HMAC binding and
independent exact-Workspace membership, never provider email/roles as grants.
Existing initiation and platform/process suites remain intact. GET capture,
clean landing and protected continuation preparation change no durable authority.

Five independent route cases cover fresh cookie-only Session issuance,
case-sensitive subject denial, missing membership, signed wrong nonce and a
provider-error callback with no exchange. Same-ring Session authentication checks
exact Principal/subject/Workspace/generations; durable reads check provider/client
and active token digest. From the post-Start baseline, success adds one Session
and three mutation/audit/outbox events (claim, Session, auth success), with the
last two sharing one change and consecutive hashes. Denial adds only claim and
termination; auth remains anonymous, terminal/version three, proof erased and
result either exactly that Session or NULL. No provisioning, subject last-seen,
membership/RBAC/Network/revision write occurs. Consumed replay makes no further
exchange, Session or evidence and releases no browser material. Request/cleanup
owners remain bounded, checked and joined, including race/leak verification.

The internal-only offline Linux source lane retains its previously reviewed
mount/trust/privilege profile. Canonical docs 13/17/18/26 were updated locally
before code; this README is the Git-versioned mirror, not a commit of that non-Git
sibling tree. This is synthetic source qualification, not live Google through
Keycloak, browser/client/HA, native/cross-host clocks, intended expiry/recovery,
remote CI or immutable artifact evidence. Public SSO stays off; no deployment
or meshd/meshctl wire change. Next: operational key/query custody and intended
expiry/recovery qualification before reviewing public runtime activation and
the controlled Google-through-Keycloak acceptance.

Source qualification (2026-09-17): final full `make quality` passes all existing
format/module/vet, shuffled unit/race, unfiltered pinned regular/integration-tag
lint, symbol-vulnerability and workflow gates. Govulncheck reports zero affected
symbols/imported-package vulnerabilities and three non-called module advisories,
not zero dependency/container advisories. Pinned context-safe changed-file
autofix and final unfiltered cmd lint pass without fixes; all 41 cmd Go hashes
and five exact modified Go texts stay unchanged. The initial file-only autofix
failed typecheck from missing package context, made no edits and is not evidence.
No new baseline, suppression, exclusion, dependency or guard change.

Final fresh internal-only offline Linux execution passes all released migrations
(15.695s), five initiation cases (cmd race 1.439s), all five named signed-callback
cases without Skip (cmd race 2.274s), joined leak checks and unchanged dependency/
process restart/expiry suites (6.414s). The exact pinned Go/PostgreSQL/Redis image
digests and reviewed mount/trust/privilege profile are unchanged. Earlier new
fixture findings were corrected: initiation erasure retains its existing Strict
SameSite contract; bounded canonical subject encoding returns an error, fixing
G115 without suppression or altered bytes. Native uncached private-identity unit
race contracts pass (1.732s), not host storage/clock integration. Existing compact
ID-token/JWK fuzz smokes pass 267,945/14,345 executions over ten seconds with two
workers. Shell syntax/invalid-mode and fully redacted source/canonical-doc/all-128-
pre-commit-history secret scans pass. All disposable resources are removed on exit.
No production Go/schema/grant/constraint/old-oracle/freshness or client-wire change.
This qualifies synthetic current source only; public SSO and live/release gates
remain disabled/deferred.

New source SHA-256 records against base `0a7eed7`: callback fixture
`40b7c3b08ce2faaa6aa4340e39f7939413d4f02b61690adce898436ea87e4b21`,
callback test `093c4651656dedcec71e618a783eb973831d16d968a14f33e73a04301a112aa3`,
signing-provider fixture
`317ac5e1e7f6efa7db875db03636f9b12aa0985ec2e36f8e59eb4e53937e3984`.
These are source records, not Google/browser/HA/clock or release-artifact evidence.

### Concrete private factory natural-expiry/quarantine integration

`SSO-PRIVATE-FACTORY-EXPIRY-QUARANTINE-INTEGRATION-001` adds a third exclusively
owned cold `meshtransit_private_factory_expiry` database to the same isolated
offline verified-TLS Linux lane. All released migrations, original clock/CSPRNG,
resident keys, OS-root provider clients and existing initiation/callback/process
oracles remain unchanged. Runtime and worker pools retain distinct credentials;
the actual `composeAuthExpiry` worker owns no-grant cleanup.

The factory creates and authenticates one Session, then independently creates
one pending login and prepares its protected continuation. Pending lifetime is
the already permitted one-minute minimum, never weakened or backdated. Observe
one real empty worker pass before the original deadline. A bounded audited
synthetic Deployment UPDATE advances version/generation/epoch to two and marks
recovery quarantined. Old same-ring Session authentication and continuation must
immediately fail without exchange, claim, Session or evidence. Original pending
metadata and the durable issued Session remain unchanged.

Bounded 100-ms durable-state predicate probes (at most 75 seconds from creation),
not sleeps or `pg_sleep`, observe natural expiry through quarantine. The worker
must commit exactly one pending-to-expired/version-two mutation/audit/outbox,
`deadline_expired`, NULL actor/result, original binding/timestamps, canonical
lifecycle/event hashes and complete three-column PKCE erasure. Session, subject,
membership, RBAC, Network and revision authority do not change. After checked
shutdown/Done join, stale continuation replay and one independently composed
fresh empty worker pass must add no exchange/evidence. All cleanup is bounded,
checked and joined before the final race/leak check.

Canonical docs 13/17/18/26 were updated locally before code; this is their Git
mirror, not a commit of the non-Git sibling tree. Synthetic epoch/quarantine is
a fence fixture only, not a recovery controller, external witness, restored-ledger
lineage or recovery audit semantic-hash claim. Factory consuming abandonment,
full intended-target cleanup/legacy remediation, operational key/query custody,
native/cross-host clocks, real Google through Keycloak, browser/client/HA,
remote CI and immutable artifacts remain separate gates. Public SSO stays off;
production Go/schema/grants/constraints/dependencies and meshd/meshctl wire are
unchanged. Status: implemented and source-qualified in the owned Linux lane only.

Source qualification (2026-09-17, base `53289a7`): final full `make quality`
passes unchanged format/tidy/vet, shuffled unit/race, unfiltered pinned normal/
integration-tag lint, symbol-vulnerability and workflow gates. Govulncheck finds
zero affected symbols/imported packages and three non-called module advisories,
not zero dependency/container advisories. An obsolete baseline tool could not
load Go 1.26 and is not evidence; the repository-pinned successful target is.
Context-safe scoped pinned autofix makes no edits; all 43 cmd Go hashes and exact
three target texts remain unchanged. Probe cleanup now defers cancellation even
on assertion exit and rechecks the deadline before accepting a result; final
gates were rerun on those corrected bytes.

Final fresh internal-only offline verified-TLS Linux execution passes all
released migrations (16.057s), five unchanged initiation cases (cmd race 1.435s),
five unchanged signed callback cases (2.588s), the new natural-expiry workflow
and both named quarantine denial probes without Skip (61.818s), joined leak
checks and existing dependency/process restart/expiry suites (6.352s). Exact
Go/PostgreSQL/Redis digests and mount/trust/privilege profiles are unchanged.
All owned disposable resources are removed after exit. Host uncached focused
compiler/unit race passes (1.765s), not host TLS/clock acceptance. Existing
two-worker ten-second expiry-batch fuzz passes 73,161 executions. Shell syntax,
pre-effect invalid-mode rejection and fully redacted tree/canonical-doc/all-129-
pre-commit-history secret scans pass without new exclusions/baselines.

New fixture/test SHA-256 records:
`48ac40cfcb83f6bf373cc73fbc7e414020e06fbf32c508ffc33e7f3478560f83` and
`cbb57dcdcfee1d9f40bf5ed680408f30f83cae3fff50407cc5b679432ff30825`.
Current source only; no public activation or live/recovery/clock/artifact waiver.
Next: factory consuming-abandonment qualification, operational key/query custody,
then controlled Google-through-Keycloak acceptance after remaining release gates.

### Concrete private factory consuming cleanup-wins integration

`SSO-PRIVATE-FACTORY-CONSUMING-CLEANUP-INTEGRATION-001` adds an additional
source gate specified before implementation. A fourth exclusive cold
`meshtransit_private_factory_consuming` database retains all released migrations,
independent runtime/worker/admin roles and the existing offline Linux/TLS trust
profile. The unchanged actual factory creates a minimum-one-minute pending login.
Observe an actual empty worker pass; bounded live-DB probes approach its original
exclusive deadline. Fresh capture/protected preparation then invokes the actual
dispatcher under a bounded request owner. A context-aware synthetic token barrier
signals only after exact TLS/Basic/form/PKCE verification and confirmed claim.

While that one token POST remains in flight, the actual worker must naturally
commit consuming2 -> expired3 with original consumed_at/binding/times, complete
three-column PKCE erasure and exactly one canonical expiry mutation/audit/outbox.
Join worker before evidence census. Release a valid signed token, join callback,
and require no Session/browser material, duplicate termination/evidence or retry.
Replay and a fresh empty worker pass must have zero additional effects. Original
subject/member/role/Network authority and revisions remain unchanged. Existing
pending/version-two and signed-callback oracles are not broadened.

The overall predicate bound is 75 seconds from creation with 100-ms bounded-query
probes; no sleep/pg_sleep, backdating/timestamp rewrite, alternate clock/effect
ports or weakened safety bounds. Request and provider/worker owners cancel and
join before clients/pools close and final race/leak verification. This is cleanup
winning before exchange release, not a forced issuance-CAS race or process-crash/
unknown-claim abandonment test. Full intended-target cleanup, witness/restore
lineage, operational key/query custody, native/cross-host clocks, Google through
Keycloak/browser/client/HA, remote CI and immutable artifacts remain open.
Canonical docs 13/17/18/26 were updated locally first; this is their Git mirror,
not a commit of that non-Git sibling tree. Public SSO and client wire unchanged.
Status: implemented and source-qualified in the owned Linux fixture lane only.

Source qualification (2026-09-17, base `6c780df`): full `make quality` passes the
unchanged format/tidy/vet, shuffled unit/race, unfiltered pinned normal/integration
lint, vulnerability and workflow gates. Govulncheck reports zero affected symbols/
imported-package vulnerabilities and three non-called required-module advisories,
not zero dependency/container advisories. Fresh unfiltered cmd lint before/after
context-safe scoped pinned autofix passes without edits; all 45 cmd Go hashes and
exact five target texts remain unchanged, no processor warnings/errors. Final
read-only delivery was retried after agent bookkeeping serialization, not a lint
failure. No suppression, exclusion, baseline or gate weakening.

Final fresh internal-only offline verified-TLS Linux execution passes all 34
released migrations (15.683s), five unchanged initiation cases (cmd race 1.459s),
five unchanged signed callback cases (2.467s), unchanged pending-quarantine
workflow/both denial probes (61.949s), new consuming cleanup-wins workflow/both
named replay/fresh-worker probes without Skip (61.562s), joined race/leak checks
and existing dependency/process restart/expiry suites (6.363s). Exact image
digests and mount/trust/privilege profiles remain unchanged. Durable assertions
verify natural deadline, original consumed_at/binding, proof preserved until
complete erasure, separate canonical claim payload hashes, exact expiry hashes
and no Session/duplicate failure/evidence after one valid signed late exchange.

Host focused uncached tagged compiler/unit race passes (1.770s), not host TLS/
clock acceptance. Existing two-worker ten-second callback syntax fuzz passes
413,560 executions. Shell syntax/pre-effect invalid-mode rejection and redacted
source/canonical-doc/all-130-pre-commit-history secret scans pass. Fixture review
corrected the released epoch JSON field and fail-closed request/handler join;
all final gates ran on those bytes. Production Go/schema/grants/constraints/
dependencies, old oracles and client wire remain unchanged; public SSO stays off.

New consuming fixture/test SHA-256:
`b8ef80225f17d45979eace81063952f9f3608365c917f247954adc195fdab790`,
`173782fa32e14d3fac8a0e9c5fc3f0d27b23a314f1932c20c80486766237accb`.
Updated optional signing-provider fixture SHA-256:
`dea760c999165af71e3082a310625bea922b4616857f2c1ad519d2a78396a6b2`.
Source only; no crash/restore/native-clock/live/artifact waiver.
Next: exact process-abandoned/unknown-claim cleanup qualification, then key/query
custody; controlled Google-through-Keycloak acceptance after remaining gates.

### Concrete private factory process-abandoned consuming integration

`SSO-PRIVATE-FACTORY-PROCESS-ABANDONED-INTEGRATION-001` adds a fifth exclusive
cold `meshtransit_private_factory_abandoned` database and all released migrations.
Parent alone owns admin seeds/reads and actual factory Start/capture/preparation.
One owned same-test-executable child attaches checked runtime PostgreSQL/Redis,
recreates identical deterministic file-backed synthetic resident keys, and calls
actual protected Continue with unchanged factory clocks/effects/provider clients.
Bounded canonical private inherited fd3 carries synthetic provider/cookie/proof
data; separate bounded raw fd4 carries Basic credential, never general JSON or
argv/env/stdout/stderr. Private fd5 carries eight closed monotonic phase bytes
only. Restore nonblocking mode before wrapping inherited pipes for bounded I/O;
exec's File.Fd otherwise makes them blocking. Child inherits only explicit runtime
profile references/startup trust, not migration/admin/worker or host credentials.

Exact TLS/Basic/form/PKCE token barrier precedes independently checked consuming2
claim/proof/canonical evidence. Parent kills ONLY its own child PID, owns one Wait
and requires checked SIGKILL plus exactly one accepted request-cancellation join;
no token is released/minted. AFTER joins and BEFORE any worker starts, durable
consuming2 still has original timestamps/binding/consumed_at and intact PKCE,
sufficient live original deadline, no Session/failure or repeated claim evidence.
Fresh actual worker first observes not-due empty, then naturally commits expired3
once with preserved original consumed_at/binding and full PKCE erasure. Join before
strict canonical expiry/census checks. Stale continuation replay and a fresh empty
worker add zero effects; unrelated subject/member/role/Network authority unchanged.

75-second original-creation predicate bound, 100-ms bounded probes; no sleep,
backdating, alternate clock/transport/effect or lifetime/schema/grant weakening.
Every parent-owned process/pipe/handler/worker is finitely joined before clients/
storage close and race/leak verification; SIGKILL child cannot run leak cleanup.
This is confirmed-claim process death in compiled test-source composition, NOT
unknown claim ACK, production binary/artifact crash, restore, full intended-target
cleanup, operational key/query custody, native/cross-host clocks, Google through
Keycloak/browser/client/HA, remote CI or immutable artifact acceptance.
Canonical docs 13/17/18/26 were updated locally before code; this README is their
Git mirror, not a commit of that non-Git sibling. Public SSO off; client wire
unchanged. Status: implemented and source-qualified in owned Linux fixtures only.
Next: keep unknown-claim disposition separate, then key/query custody before
controlled Google-through-Keycloak acceptance and remaining release gates.

Source qualification (2026-09-17, base `3a63767`): final full `make quality` passes
unchanged format/tidy/vet, shuffled unit/race, unfiltered normal/integration lint,
vulnerability and workflow gates. Zero affected symbols/imported-package
vulnerabilities; three non-called required-module advisories remain, not zero
dependency/container advisories. Corrected-final-source fresh unfiltered cmd lint
before/after scoped pinned autofix passes without edits; all 48 cmd Go hashes and
exact seven target texts unchanged. Diff 63.038541ms, no processor warning/error;
no new suppression, exclusion, baseline or weakened gate.

Final fresh internal-only offline verified-TLS Linux execution AFTER source freeze
passes all 34 released migrations (15.729s), five unchanged initiation cases
(cmd race 1.440s), five unchanged signed callback cases (2.381s), unchanged pending
quarantine/both denial probes (61.859s), unchanged consuming cleanup-wins/both
zero-effect probes (61.619s), new process-abandoned/both zero-effect probes without
Skip (61.559s), joined race/leak and existing dependency/process restart/expiry
suites (6.278s). Exact previous image digests/mount/trust/privilege profiles remain.
Checked SIGKILL/reap, eight closed helper phases, exactly one accepted disconnect,
no JWT/JWKS, live original consuming2/proof before worker, canonical natural
expiry3/preserved consumed_at and exactly-one evidence, no Session/failure/Network
revision or replay are asserted. All owned disposable resources removed on exit.

Host final focused tagged compiler/unit race passes (1.883s), not native TLS/clock
acceptance. Final pure IPC syntax fuzz, two workers/ten seconds, passes 1,641
executions with cached corpus, not performance/coverage proof. Shell syntax,
pre-effect invalid-mode rejection and fully redacted source/canonical-doc/all-131
pre-commit-history secret scans pass. Initial sandbox port/DNS denials rerun with
scoped authority, not counted as passes. Secret-serialization lint led to separate
raw credential fd4 without suppression. First Linux crash attempt failed before
barrier: exec File.Fd made inherited pipes blocking. Restore nonblocking before
NewFile plus fixed private phase fd5; final whole-lane/quality run on corrected
frozen bytes. No production Go/schema/grant/constraint/dependency/client wire change.

New IPC syntax-test/fixture/workflow SHA-256 respectively:
`65bb4429d5bec9bf15450d602b0d266e5ad85ebdb059c15c6ccd02613dd76623`,
`898175f699fada560245cf951685d4970631e1f01be68216cbdecdec46c87446`,
`6447c2c41945007cc27b08db887ebaf161c4e7d768a50622ec13ba28b610415c`.
Optional signing-provider fixture:
`db693a2d02208fc8bfbe1f6637a3124ad8f0d7fb2ea78dae0dfaa0e41af6aa73`.
Source only; all named unknown-ACK/production-crash/restore/live/artifact exclusions
remain. Canonical originals updated locally, Git mirror only pushed; public SSO off.

### Process log callback-custody defense

`SSO-PROCESS-LOG-CUSTODY-001` closes an attribute-name/group-path gap in the
existing process JSON logger. Exact normalized callback code/state/nonce,
verifier/challenge, proof/CSRF, claims/email, query/request-target and referrer
aliases redact in addition to the existing key/token/cookie/error defenses.
Normalization ignores case and underscore/hyphen/dot separators. Exact matching
preserves closed status_code, error_code, state_version, operation and result.

Every leaf beneath ANY sensitive group also redacts, including With-bound
attributes, WithGroup and nested groups returned by LogValuer. The stdlib
ReplaceAttr callback visits leaves, not group attributes; checking only the leaf
name would leak generically named payloads under raw_query/authorization groups.
Group structure/names and independent sibling fields remain intact.

This is defense in depth, not evidence of a live leak: private auth flows already
avoid generic request logging. Fixed messages, static trusted names and closed
values remain mandatory. No value-content inspection or safe arbitrary-object
serialization is claimed. Secrets in messages/names, innocently named opaque
maps/structs, custom LogValuer side effects and other sinks are outside this
defense. No new request middleware, auth route, trace, listener or public switch.
Client wire, authority/revision propagation, dependencies and disabled public SSO
defaults are unchanged. Operational edge/database/query-trace suppression,
key-mount custody, separate unknown-claim ACK, native clocks and real
Google-through-Keycloak/browser/client/HA/artifact acceptance remain gates.

Canonical STRIDE, observability, ADR and test requirements were updated before
code in the original sibling core-docs directory. Those originals are local;
this README is the versioned Git mirror. Next: operational key-mount/ingress query-custody qualification,
retaining the separate unknown-claim ACK disposition gate before live SSO.

Final frozen-source qualification (2026-09-17, baseline b336596): named alias and
all six group-path regressions fail before correction and pass afterwards.
Uncached shuffled package race passes (1.496s); ten-second/two-worker pure path
fuzz passes 998606 executions (11.461s package), not performance/coverage proof.
Fresh unfiltered package lint before/after scoped autofix passes with zero issues,
no fixes and all 704 repository Go hashes/exact two target texts unchanged.
Tool 2.13.2, Go 1.26.8, module
`h1:bCyq3E4vo9qwzifjpzJqYndEt7Ncva80qkk8G2B4TXU=`; Diff stage 42ns on the
zero-issue path, no processor warning/error. Unchanged full make quality passes
format/module, vet, shuffled unit/race, full/integration lint, vuln and workflow.
Vuln reports zero affected symbols/imported packages plus three non-called
required-module advisories, not zero advisories. Fully redacted source/original-
doc trees and complete history require clean secret scans before landing, without
added exclusions/baselines. No Linux/live/target/browser/clock qualification is
claimed by this sink-only change; no disposable or external services are needed.

Source SHA-256: logging.go
`55c17afd54d26b469fe976f280c91c67915e3ac06208fd09ef51a155b6b38612`,
logging_test.go
`c40a46598b88e1a6aa089a85dc9474b61995b76ddcd83156cbf8360da16189da`.
Delivery checkpoint (owner-approved 2026-09-17): canonical roadmap 18 now places
initial real Google-through-Keycloak login, Core BFF/Sessions and unchanged
supported client compatibility in Phase 1, superseding the earlier Phase 2-only
login checkpoint. Other providers and broader identity/routing capabilities stay
later. Private SSO source tests do not close Phase 1's operational or live exits.
Consolidate the remaining runtime/config/listener wiring, target custody/clock/
uncertainty requirements and pinned Keycloak/browser/client acceptance into
delivery milestones; do not substitute repeated tiny test slices or commit
counts for capability progress, or waive existing public security gates.

### Private browser login document and dispatcher

`SSO-LOGIN-ROUTE-CONTRACT-001` and `SSO-PRIVATE-LOGIN-DISPATCHER-001` prepare
source contracts, not public admission. The private root now constructs one
`httpapi.LoginDispatcher` from its complete `BrowserLogin` graph and renders
`openapi.LoginDocument` from that SAME callback path. Construction releases both
or nothing without I/O, authority, budget, entropy, clock or listener effects.
Only explicit `console-cookie-csrf-private-v1` is supported for login; zero,
unknown and management Bearer profile selections fail without document bytes.
Both existing management documents retain their exact contract/byte oracles.

The reviewed, embedded OpenAPI 3.1.0 asset is a separate, bounded login document,
not an operator JSON patch, runtime provider discovery or documentation endpoint.
Rendering is deterministic with independently owned bytes and a 128 KiB cap.
Callback remapping permits only canonical ASCII paths within `/auth/`, at most
256 bytes, without encoded/dot/double/trailing-slash aliases or overlap with the
four fixed login paths or management Session preparation. This narrower private
profile does not change the standalone browser component's path contract.

Exactly seven operation pairs are supported:

- POST `/auth/v1/login/prepare` and POST `/auth/v1/login/start`.
- GET the graph-selected callback path, capture only, never Session issuance.
- POST `/auth/v1/login/continue/prepare` for the protected continuation proof.
- GET and HEAD `/auth/v1/login/continue` for read-only clean presentation.
- POST `/auth/v1/login/continue` for the complete confirmed-Session pipeline.

Each operation has explicit security: anonymous preparation/clean presentation
cannot inherit a global grant; start requires initiation cookie AND its intent
proof; capture requires pre-auth cookie; continuation preparation requires both
pre-auth and captured-callback cookies; completion requires both cookies AND the
distinct continuation proof. No OR alternative, authenticated browser Session,
Bearer, provider token or query-selected authentication profile is introduced.
Success JSON stays closed: initiation/continuation proof plus expiry,
authorization URL, or a fixed local return path. Confirmed Session delivery stays
cookie-only; OpenAPI's HEAD response has no body contract. Response ownership,
generic denials, bounded query/capsule/body limits and partial-delivery uncertainty
are explicit. Local references/shape/security tests are not a formal full-schema
validator, real browser CSP execution or provider qualification.

`Handle` delegates the ORIGINAL request, context and writer to exactly one owner.
Require completed direct TLS, exact Host, bounded canonical headers, a pristine
response, coherent origin-form target and no Authorization field. Only callback
GET may carry a query. Reject unknown paths/methods and aliases before body reads,
delegation or response changes. No ServeMux, redirect, URL cleaning, middleware
error mapper, retry or alternate service/profile is added. Existing owners retain
their work/transport deadlines, budgets, source checks, audit and transaction
semantics. Canceled admission fails closed; delegated closed errors and uncertain
partial output are preserved. Nil means normal dispatch return, NOT a grant,
confirmed commit, delivery acknowledgement or successful login.

Private root telemetry adds active/total/duration collectors only to its fresh
registry. Operation/result labels are fixed enums, never a path, provider URL,
principal, cookie or token. Normal delegation can still be a generic HTTP denial;
metrics never infer a Session. No public metrics endpoint, auth RUM/request logger,
raw traces or global collector registration is added. Operational dashboards and
alerts remain activation gates, as recorded in the canonical observability doc.

Canonical API, identity, STRIDE, observability and ADR documents were updated
locally before implementation; this README is the versioned mirror of that
non-Git sibling tree. No main/config/default/listener activation, deployment,
migration/schema/query, dependency, management/client wire or meshd/meshctl change.
Keycloak remains SSO-only, Google through Keycloak first; public SSO stays disabled.
Next qualify the concrete private factory with durable/provider fixtures, then
end-to-end query custody, native clocks, intended expiry/recovery and live Google/
Keycloak/browser/client/HA. Remote CI and immutable release artifacts remain open.

Source qualification (2026-09-17): unchanged full `make quality` passes shuffled
unit/race, vet, format/module, pinned regular/integration-tag lint and workflow
gates. Govulncheck reports zero affected symbols/imported-package vulnerabilities
and three non-called required-module advisories, not zero advisories. Final
uncached host OpenAPI/httpapi/cmd race passes (1.588s/1.415s/1.928s). Exact pinned
Go 1.26.8 Linux uncached race/shuffle passes OpenAPI/httpapi/cmd/config
(1.242s/1.257s/1.138s/1.042s), UID/GID 65532, read-only source/modules, no network,
capabilities, credentials or Docker socket; only isolated scratch is writable.
The approved exact image reference was missing and resolved by an exact-digest
pull reporting up-to-date. Two-worker ten-second document/dispatch fuzz passes
147653/31787 executions; 49 unchanged deterministic landing-script checks pass,
not browser-engine/CSP acceptance. Scoped pinned autofix/read-only lint passes
with no fixes and exact before/after Go snapshots unchanged. Contract review
corrected the NEW asset's Origin maximum to the existing 255-byte guard; a new
regression pins it, success bounds and zero-body HEAD/capture. No prior test,
guard, oracle, config, dependency or gate changed. Redacted tree and complete
126-pre-commit-history secret scans pass without a new baseline/exclusion.
Pipeline tests use actual private services with synthetic ports/clock/provider
input, not durable/provider integration: cover no-grant GET, confirmed-result
cookie-only delivery, single-use replay, method aliases and preserved finite
deadline/partial-delivery errors. No live PostgreSQL/Redis/Google/browser/client/
HA or native-clock qualification. Public SSO stays disabled.

### Private management OpenAPI authentication profiles

`SSO-MANAGEMENT-AUTH-PROFILE-001` adds pure compile-time document composition,
not runtime admission or public SSO. `openapi.ManagementDocument` requires an
explicit server-owned `account-session-bearer-v1` or
`console-cookie-csrf-private-v1` profile; zero/unknown values return a closed error
and no bytes. No query/header/credential negotiation or authentication default.
The Bearer document remains byte-identical to `api/openapi/management_v1.json`.

The private Console document derives from that SAME versioned product API and
one reviewed MeshTransit build-time fragment, not a generic operator JSON patch
or OpenAPI Overlay standard document. Existing device-revoke/policy-publish POST
operations retain exact operation IDs, body/scope schemas, resource responses,
ETags and idempotency parameters. Reject baseline version/operation/method/
authentication drift and component-name collisions rather than adding unknown
browser resources. One security requirement contains BOTH canonical
`__Host-mt_session` cookie and `X-MeshTransit-CSRF` proof (AND, never anonymous or
Bearer OR). Exact configured HTTPS Origin and `X-MeshTransit-Session: v1` are
required. Authorization custody, including empty values, is forbidden; there
is no Referer/CORS/provider-token or browser-session-to-IaC fallback. These
descriptions never replace current Core membership/RBAC, fresh durable Session
generations, transaction scope or response-submission checks.

Only no-grant POST `/auth/v1/session/prepare` is added: current cookie, Origin/
channel headers and a bounded literal empty JSON object, without a proof that
does not yet exist. Success is no-store JSON containing ONLY `csrf_token` and
`expires_at`, no provider/identity/bearer data or Set-Cookie/renewal. Its default
response records private zero-output pre-release failure, not an enabled public
HTTP error mapper. Existing wrapper limits, independent admission capacities,
budgets, exclusive expiry and uncertain-delivery/no-retry rules remain unchanged.

Compiled inputs/output each stay within 128 KiB. Rendering owns local maps and
independent deterministic bytes; no mutable cache, runtime OS file read, clock,
provider/DB/budget/entropy effect, worker or retry. The composed OpenAPI 3.1.0
document is marked `private-source-only` and uses only a reserved Console example
origin, never an operator/deployment default. Contract tests retain exact shared
resource components, require cookie AND proof plus Origin/channel, verify every
local reference, no-grant/ownership/size/drift rules and fuzz closed profile
selection. A controlled private-root bridge compares the actual newly issued
Session's preparation response with the compiled shape and verifies that empty
Authorization is rejected before effects or output. This is not a full formal
OpenAPI/JSON-Schema validator or live provider/client/browser qualification.

No main/runtime/config/public auth selection, dispatcher, documentation endpoint,
listener, secret loader, client wire, SQL/schema, dependency or default changes.
Public SSO remains disabled. Production PostgreSQL/Redis/Keycloak factories and
complete login-route OpenAPI/dispatcher come next; query custody, native-host
clock, intended expiry/recovery, Google-through-Keycloak/client/HA, remote CI and
immutable-artifact release gates remain open. Canonical API/identity/security/ADR
documents were updated locally first; this README is their versioned mirror,
not a claim that the non-Git sibling core-docs directory was committed.

Source qualification (2026-09-17): full `make quality` passes host formatting,
tidy/vet, unit/shuffled race tests, pinned regular/integration-tag lint and
workflow lint. Govulncheck reports zero affected symbols/imported-package
vulnerabilities, but three non-called required-module advisories, not a
zero-advisory dependency/container assessment. Uncached host race tests pass
`api/openapi`, `internal/config` and `cmd/meshcore` (1.449s, 1.330s, 1.639s).
Profile-selection fuzzing passes 1,653,618 executions with two workers over ten
seconds. Gitleaks finds no leaks in the full tree and 124 pre-commit history
commits; no baseline/exclusion was added. Scoped pinned autofix/read-only lint
both report zero issues and leave the four reviewed Go files unchanged.

The attempted pinned Linux source-container gate did NOT execute: automated
review rejected a complete read-only repository mount into a container without
specific payload/destination authorization. No alternate mount/copy/indirect
workaround was used. This source's Linux gate remains unqualified, not passed or
waived; host or historical results do not substitute for it. A retry requires
explicit authorization for that source/image exposure. Native-host clock,
durable integration, live SSO/client/HA, remote CI and immutable artifacts remain
unqualified. No public activation or deployment is part of this change.

Authorized follow-up qualification in the private dependency-factory slice above
now passes the same pinned no-network/read-only Linux source gate including
`api/openapi` (1.094s). The original rejected attempt remains unexecuted. No bypass
occurred; only current source is qualified, not historical commits/artifacts or
public/live browser readiness. The remaining release gates above remain open.

### Private login process configuration and readiness

`SSO-PRIVATE-PROCESS-PROFILE-001` consolidates immutable configuration, concrete
dependency readiness and compiled `meshcore serve` ownership. It supersedes
historical statements above that main/config/readiness binding is absent ONLY
for this opt-in PRIVATE loopback source profile. Public login remains disabled.
There is no public bind/origin, enable/qualification-waiver switch, proxy
assertion or direct Google adapter. Keycloak remains the SSO-only broker, with
Google first. Never publish or forward the private listener.

Configuration schema 16 adds `MESHTRANSIT_PRIVATE_LOGIN_CONFIG_FILE` for `api`
and `all` only. Absent means unchanged behavior; explicitly empty, relative,
noncanonical, unreadable or unsafe files fail closed. Read one owner-only
(0400/0600), parent-confined regular JSON file of at most 16 KiB under the
caller's finite context. Version 1 requires exactly these 20 fields:

- `version`, `address`;
- `deployment_id`, `workspace_id`, `provider_id`, `client_id`;
- `provider_generation`, `recovery_epoch`;
- `issuer`, `discovery_uri`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`;
- `oidc_client_id`, `redirect_id`, `return_route_id`;
- `tls_certificate_file`, `tls_private_key_file`, `client_secret_file`, `keys`.

`address` is an exact canonical loopback IP/nonzero port, such as
`127.0.0.1:9443` or `[::1]:9443`, distinct from existing listener addresses.
Origin and callback are derived as HTTPS on that exact authority with
`/auth/v1/callback`, not independently operator-selected. The local return path
is `/console`. Route IDs and positive generation/epoch bind one independently
authorized durable Keycloak route. The profile fixes confidential
`client_secret_basic`, `openid` and `RS256`. Unknown/case-aliased/duplicate/null
fields, malformed/trailing JSON and public/wildcard/mapped addresses are denied.

`keys` requires exactly `initiation`, `capture`, `continuation`,
`management_csrf`, `transaction_digest`, `verifier_encryption`,
`subject_active` and `provider_session`, with optional `subject_previous`.
Each value has exactly `id` and `file`: distinct bounded purpose IDs and
canonical absolute protected key-file references. Session current/previous,
idempotency and rate-limit refs/IDs come from the EXISTING bearer API settings,
not private overrides. All 11–13 purposes load as one complete candidate with
distinct material. Bearer API and cookie graph share the exact same resident
keyring/digester owners; there is no second API key-file read or reload split.
Cross-purpose key material and file-reference/ID aliases are rejected.
Credential/TLS/control/storage file-reference aliases and enrollment key-ID
aliases are denied. This does not prove global material uniqueness across
external files/hardlinks or one transactional filesystem snapshot; public
key-custody qualification remains open.

TLS PEM files are bounded to 64 KiB each and the client-secret file to 4096
bytes, with the same protected regular-file custody/change checks. Modern
single-host certificate identity must match the exact callback host. All raw
errors and formatting remain closed/redacted; temporary buffers are cleared
after constructor copies, not a promise of Go heap zeroization. Trusted local
mounts are required because cancellation cannot preempt filesystem syscalls.
Request/lifetime/concurrency/rate bounds are fixed and finite.

`meshcore config validate` loads this profile, complete keys, TLS and client
secret through the same concrete effect-free constructors, without listeners,
provider traffic or durable route admission. A valid result proves only local
configuration. `serve` adds the closed `private_login` readiness component:
current durable route admission then exact provider discovery, before ANY
listener starts, repeated under the owned monitor deadline. A health snapshot
is not a trust lease; actual requests retain current admission/fences.

The owned health registry retains both auth collectors with fixed
`auth_profile` labels `console_cookie_private_v1` and `core_session_bearer_v1`,
avoiding descriptor/series collisions without dropping either owner. No metrics
surface is exposed on login routes. All services AND the monitor must positively
join before factory HTTP-client/storage cleanup; incomplete shutdown retains
the graph and exits nonzero. Expiry ownership remains explicitly configured,
not implicitly activated or certified by the private profile.
This prerequisite affects process-wide readiness, including configured `all`;
public API/control readiness isolation is not qualified by this private profile.

The owned Linux integration lane adds the sixth cold database
`meshtransit_private_process`, applies released migrations, and seeds only the
audited synthetic route. Run the actual container lane explicitly:

    PLATFORM_GO_RUNNER=container make integration-platform-container

The target's default host lane does not execute Linux-only private fixtures.
The new gate launches the just-built production binary with runtime-only
fixture credentials and explicit startup trust, checks effect-free config
validation, failed initial provider readiness BEFORE all listeners, real TLS
landing/prepare/pending creation with no Session grant, both metrics profiles,
readiness loss/recovery without authority effects, and exact-PID SIGTERM/join.
This private process fixture runs `api`. The unchanged final platform gate runs
`all` with the private profile absent; it does not qualify private `all` serving.
This is synthetic source qualification, not release-image, native-clock,
real Google/browser/meshd/meshctl or HA acceptance.

Final source qualification (2026-09-17) passes:

- Unchanged `make quality`: format/tidy, vet, all shuffled unit/race tests,
  normal/integration lint, govulncheck and workflow lint. Govulncheck has zero
  reachable symbols/imported-package vulnerabilities; three required-module
  advisories are not apparently called, not absent.
- Uncached integration-tagged shuffled race runs on macOS and pinned nonroot
  Linux with network disabled, source/modules read-only and owned scratch.
- Pure config fuzz smoke: 23,251 executions, ten-second budget, two workers,
  no failure corpus or provider/filesystem effects in the fuzz target.
- Full owned Linux PostgreSQL 18.6/Redis 8.8 TLS/ACL lane: all previous private
  initiation/callback/replay and three intact natural expiry/death gates; new
  compiled `api` private process (cmd race 7.347s); unchanged `all`/default-profile
  platform/restart/Noise integration (6.289s).
- Fresh pinned golangci-lint 2.13.2/Go 1.26.8 scoped pre/fix/post: zero issues,
  no fixes. All 719 Go SHA/exact bytes, 700 files outside the 19-file scope,
  index and base HEAD remain unchanged across that pass. Existing suppression
  then Diff then Fixer order/fail-open is verified; successful Diff 67.902333ms
  is not a runtime patch-parser claim.

Initial failed NEW fixture assumptions remain recorded: missing closed operator
component label, wrong health alias, omitted existing prepare JSON/login headers,
wrong start 303 expectation, and insufficient metrics budget. The full lazy
PG/Redis/auth/Go/process collector response measured 274,034 bytes; only fixture
`/metrics` reads now permit 1 MiB while login reads stay 256 KiB. No production
collector, request bound or prior expiry gate is dropped. The initial offline
scratch executable denial is resolved using owned `/work` GOTMPDIR, not a looser
container. The new unit's noctx finding is fixed with the caller context.
These corrections are not historical passing qualification or a public waiver.
Redacted full-tree/pre-commit full-history scans use go-run Gitleaks source
`v8.30.1`, not released-binary CLI version metadata; final scans must pass
before the authorized commit/push without added baselines or exclusions.

Original contracts were updated first in canonical core-docs 26, 02, 13 and 18;
qualification and telemetry are routed through 17 and 14. This README is the
versioned Git mirror; the sibling core-docs directory is not itself a Git repo.
Public key/query custody, unknown-ACK, target expiry/recovery/native clocks,
all six live Google cases, clients/HA and immutable-artifact gates remain open.
The committed-wire unknown-claim/issuance branch is source-qualified below.
Next consolidated milestone: protected key/query custody and intended-target
expiry/recovery/clock/runtime qualification; then pinned Keycloak Google,
real browser/client/HA and immutable-artifact acceptance before public activation.
Google stays in Phase 1.

### Private factory wire Commit acknowledgement integration

`SSO-PRIVATE-FACTORY-WIRE-ACK-001` is an integration-only owned verified-TLS
loopback PostgreSQL relay against a seventh cold `meshtransit_private_factory_ack`
database. It drops exactly one selected backend `CommandComplete COMMIT` before
forwarding that frame to the unchanged runtime pool/factory. Migration/admin
reads/worker remain separate roles; no adapter/effect-port/clock override or
production fault knob. Bounded transient frames, connection/lifetime limits and
positive socket/copy joins retain query/proof custody without logging frame data.

Source-qualified committed claim/issuance ACK loss must
deliver no Session cookies, retain exact durable evidence/provider counts, reject replay
through transport reconnect and naturally expire the original consuming row.
Auth-row expiry must leave the undisclosed succeeded Session unchanged; a new
independent login may succeed without resolving/recovering an unknown receipt.
Fault selection skips one/three read-only and prior completions to target actual
claim/issuance writes; independent durable evidence rejects a wrong phase.
Dedicated ACK errors must be unavailable+unknown, not invalid or timeout/cancel;
the old rejected-replay oracle remains unchanged. Initial fixture compile assumed
a nonexistent Session-ID parser; use released publicid syntax rather than adding
a production API. Initial gosec conversion failures now have an explicit bounded
return, no nolint. First Linux execution passed the five previous private cases
but stopped before the new lane because its added shell continuation was double-
escaped; correct only that new block. These are not complete/wire qualification.
Final unchanged make quality and pure frame bounds/suppression race x25 pass.
Govulncheck reports zero called/imported-package vulnerabilities, but three
required-module advisories not called. Scoped pinned v2.13.2/Go1.26.8 lint made
no fixes; all 721 Go exact byte/SHA snapshots, 717 outside-scope paths and the
781-entry raw index fence remain unchanged. Diff 121.677042 ms before Fixer is only
lint accounting; existing nolint filtering left no input, not runtime proof.
The second full Linux attempt passed both real wire subcases but root worker
pool cleanup/leak assertions failed: pinned pgx v5.11.0/puddle v2.2.2 destruction
is asynchronous and can temporarily retain an acquired lease after worker Done.
Only this new ACK scope now probes unchanged Pool.Shutdown on classified busy,
within its independent five-second cleanup budget after consumer joins. No SQL/
Commit retry, force-close or leak exclusion; prior scopes retain their immediate
cleanup assertions. A timeout still retains resources and fails the test.
The third full attempt passes complete ACK cleanup/leak and private api process,
but fails three old all/worker expiry evidence queries. The base fixtures retain
five-minute open Auth rows; their batch-one total-confirmation metric cannot
identify a row after unrelated natural waits mature that backlog.
Final corrected Linux execution passes the whole lane: base migration/primitive
15.746s, intact all/default-profile platform/restart/Noise matrix 6.370s, all five
earlier private cases, complete ACK cleanup/leak 62.531s and private api process
7.336s. Run the unchanged base matrix adjacent to its fixture before slow cold
scopes, then restore api/no-worker environment for private initiation/callback.
Natural earlier waits remain 61.733s/61.505s/61.477s. Bounded read-only canonical
candidate counts are zero before the base matrix and sixteen after private
scopes, confirming the timing precondition; the paired matrix pass supports
fixture contamination, not an oracle waiver. No deletion/deadline/clock shortcut,
production source/schema/client-wire change or scan exclusion was introduced.
Prior failed attempts are not reclassified as passing evidence.
This is not every uncertain network outcome,
target recovery/restore, failover, Google/browser/client/HA or artifact proof.
The original contracts were updated first in core-docs 26/13/17/18; this README
is their Git mirror, not a claim that sibling non-Git docs were pushed.

### Private startup credential construction custody

`SSO-PRIVATE-CONSTRUCTION-CUSTODY-001` binds the originally loaded protected
JSON, complete 11–13 purpose keys and three TLS/client-secret files into one
exclusively owned candidate. Serving and config validate share the same loader.
One caller-clamped five-second construction budget, existing scoped owner-only
regular-file checks and byte bounds remain unchanged. Read each dependency once;
recheck retained metadata after the full load and before returning the unstarted
factory/service. Detected atomic/projected-mount replacement, mode/size/mtime
changes or cancellation return only closed errors, no graph on failure. There
is no retry, merge, reload, replacement generation or public enablement knob.
Bearer/BFF owners remain identical; no schema/client-wire change.

Clear failed/consumed candidate bytes and metadata, including both optional
previous keys. Resident constructors own their copies; erasure is best effort,
not a Go-heap guarantee. These checks are not a global filesystem snapshot,
privileged metadata-restoration defense, remote-filesystem syscall deadline,
post-release reload or operational secret-manager/target-mount qualification.
Each input is compared to its own read-time snapshot; already-mixed inputs or
changes before its first snapshot are not certified. Provision complete matching
operator generations before startup.

Owned real-JSON fixtures cover all seventeen references with both previous
keys, early JSON/key/TLS replacement during later reads, late read failure/
cancellation, redaction and use after Clear. The initial material-rotation
regression failed because the old loader released a mixed candidate; the final
whole-material guard now passes focused configuration/composition race tests.
An initial new-test compile error (slicing a returned array) was fixed by storing
the array first, without changing a production contract or test oracle.

The existing compiled private-api process fixture adds three direct verified-TLS
callback queries: ambiguous duplicate state, shape-valid code without possession,
and provider diagnostic markers without possession. They must close before any
response, exchange or durable effect; counters prove actual dispatcher traversal.
Scan health/metrics and the complete joined stdout/stderr diagnostic window for
synthetic code/state/description/URI markers. Identical os/exec writers are
serialized, and only joined output is inspected. Reject truncation, never print
raw logs. The detector/truncation regression passes under race instrumentation.
Final unchanged `make quality` passes fmt/tidy/vet, shuffled unit/race tests,
normal/integration lint, govulncheck and workflow lint. Govulncheck finds zero
called/imported-package vulnerabilities and three required-module advisories
not called. Final frozen-source construction/material race ×10 passes (2.298s).
Initial fixture-only gosec path/mode findings were fixed using os.Root-scoped
replacement operations and table-driven unsafe modes, without suppressions;
final scoped pinned v2.13.2 normal/integration lint passes with no auto-fix edits.
Redacted full-code/full-original-docs and all-history scans pass with pinned
Gitleaks v8.30.1; no baselines or exclusions added.

The first whole Linux execution passed older suites and wire ACK but failed the
new exact three-capture counter. Initial canary syntax also omitted the required
fixed issuer; corrected before accepting any process evidence. A focused owned
verified-TLS transport test then reproduced four attempts for three canaries:
Request.Close does not prevent reusing the landing socket, and Go retries an
idempotent no-response GET on that reused socket. Close only the client's owned
idle sockets before the new canary group; keep Request.Close, the exact three-
capture oracle and all production transport/effect contracts unchanged. The
transport/no-retry and diagnostic detector/truncation regressions pass race ×25
(2.262s), including positive cleanup/leak checks. Final scoped lint again passes
without Go auto-fix changes. Full frozen-source quality and whole Linux reruns
pass; the failed first attempt is not reclassified as passing evidence.

Final whole owned Linux lane passes base migrations/primitives (15.800s), intact
default/all platform/restart/Noise matrix (6.326s), initiation (1.441s), callback
(2.339s), natural expiry/quarantine (61.829s), consuming cleanup (61.563s),
process-abandoned cleanup (61.589s), complete wire ACK cleanup/leak (62.420s) and
compiled private-api process (7.332s). The process preserves exact three capture
errors, zero query-canary authority/exchange/response and a complete untruncated
joined output window with no synthetic markers in outputs/health/metrics.
Read-only base expiry candidate counts are zero before the old matrix and thirteen
after private scopes; aggregate timing diagnostics are not row/target cleanup proof.
No old suite, oracle, natural lifetime, trust, runtime fence or client wire changed.

Original contracts/threat model/operations/qualification/roadmap were updated
first in sibling core-docs 26/13/16/17/18; this README is the Git mirror, not a claim
those non-Git originals were pushed. This closes no external LB/proxy/Keycloak
query-log custody, target key management, native clocks, intended expiry/recovery,
real Google/browser/client/HA or immutable-artifact gate. Google remains Phase 1,
SSO-only through Keycloak; private loopback source proof is not public activation.

### Deployment-owned nginx edge preparation

SSO-EDGE-TRANSPORT-PREPARATION-001 is implemented in the separate deployment
repository's chart 0.1.10, not a new Core login listener. Original threat model,
operations and roadmap 13/16/18 were updated before implementation; qualification
17 and this Git mirror record the bounded evidence. Non-Git original docs are
saved locally, not pushed as part of Core.

The nginx Ingress requires a same-namespace independently provisioned CA-only
trust Secret. The chart owns verified HTTPS, exact serving hostname/SNI, depth
three and HTTPS redirect; disables access/rewrite logs and OpenTelemetry; and
rejects owned annotation/snippet overrides or missing trust configuration.
The serving private key is never copied to the trust Secret. Rendering cannot
attest a live controller: generated directives and actual serving paths must
also be verified. Future Helm upgrades must use reviewed chart/values rather
than old stored overrides after an ingress-only apply.

Owned chart regression failed against the old chart, then strict default/POC
lint/render and twelve reason-checked override rejections pass on final chart.
Existing Console isolation checks also pass. Local Trivy 0.74.0 with the cached
check bundle reports no High/Critical findings in the actual rendered POC;
this is not container-vulnerability, chart-signature or release-artifact proof.
Server dry-run and ingress-only apply pass. No binary rollout, migration,
dependency/controller configuration or client-wire change is made.

Actual scoped nginx configuration has four verified TLS/CA/name/SNI directives,
no verify-off directive, three access-log-off locations, and no trace/rewrite-on
directive. Control HTTP is 200 with frontend TLS verification successful; a
synthetic revoke route without bearer returns 401. A disposable .invalid virtual
host returns 502 for the wrong backend certificate hostname after effective
configuration convergence. Its first pre-reload 404 was not a passing negative
test; the disposable Ingress was removed. Fresh ts2021/142 Noise probes pass on
both existing Linux clients before and after apply. Both clients were already
offline/blocked with no map revision before apply and remain so; no map-stream,
reconnect, data-plane or real Google acceptance is claimed.

Running Core remains git-c291741 at its existing immutable image digest;
private construction source 9da65be is NOT deployed or target-qualified here.
NTP synchronization flags on client hosts are inventory, not clock-skew proof.
nginx error logs, other TLS/collector/Keycloak/browser sinks, protected identity
mounts, native/dependency clocks, intended expiry/recovery, readiness isolation,
real Google/browser/client/HA and signed immutable artifacts remain gates.
Public SSO stays disabled; do not forward the private loopback profile.

### Separate private Keycloak preparation

`SSO-KEYCLOAK-PRIVATE-DEPLOYMENT-001` prepares the separate deployment repository's
private Keycloak chart and optimized provider image recipe; no provider runs
inside Core. Official Keycloak 26.7.4 is version/digest pinned, with PostgreSQL,
health/metrics placement and disabled tracing persisted during the build.
Actual offline CLI checks exposed and corrected build-only flags mistakenly
repeated at runtime. The final local arm64 image passes numeric UID/GID 1000,
exact version and supported build/runtime option checks without network, under
read-only root and dropped capabilities. This is not a server-startup test.

The chart has one fixed private production-mode instance, local cache, ClusterIP
HTTPS only, no Ingress/public Service, realm import, Google egress, arbitrary
startup/environment or credential values. It references three distinct existing
Secrets for native `keycloak.conf`, serving TLS and PostgreSQL CA. Database TLS
verification, private operator ingress, bounded pool/scratch/resources, tokenless
non-root process and immutable image digest are fixed contracts. Provider
0440/fsGroup projections do not qualify Core's owner-only startup gate.

Helm 3.19.0 strict lint/render and unsafe-value rejection pass; unchanged Core/
Console chart checks pass. Trivy 0.74.0 cached-check High/Critical manifest scan
and three-resource Kubernetes server dry-run pass on synthetic values only.
No live apply, DB/schema/client/Core artifact change, Secret payload or credential
provisioning occurs. The example intentionally lacks a releasable image digest
and actual DB/operator-origin inputs. Image vulnerability/signature/SBOM/provenance,
DB ownership/backup/migration, actual Secret/mount/health/issuer/isolation, all-hop
query custody, clocks/recovery/HA and all six real Google tests remain gates.
The current local candidate fails the complete image gate: Trivy reports High
OpenJDK CVE-2026-22020, High MSSQL JDBC CVE-2025-59250 and Critical Netty
CVE-2026-75595. The final immutable arm64 artifact is
sha256:5b8492eef37a32714af713861dbbf62b7f837f947966b936020e51e8f527d6c3.
After two DB repository timeouts, official DockerHub DBs complete OS/JAR scanning
and exact three-occurrence deduplicated metadata; no clean-image claim. The
[Netty maintainer advisory](https://github.com/netty/netty/security/advisories/GHSA-c4c3-7fpv-j4q5)
lists installed 4.1.136.Final as affected with specific SNI/mTLS preconditions;
At this initial scan, POC exploitability and vendor JVM/MSSQL triage were not
established. No VEX or scan waiver is accepted. No candidate image is published
or installed.

The supported preparation build path now requires matching recipe/base pins,
Trivy 0.74.0, complete OS/library pre/post scans by immutable identity, no ignore
file/unfixed exclusion/unreviewed scanner environment/extra build arguments,
then actual CLI checks. Offline fixtures prove failed/unavailable scan prevents
Docker build and override/platform rejection. This is not a positive guarded
build or a usable release. Select a supported clean upstream artifact before
rollout; no undocumented JAR replacement/Java fork. Public SSO stays off.

Fresh ts2021/142 Noise diagnostics pass on both existing Ubuntu clients. Their
actual daemon is 87a3dd2; the separate CLI is ce2a856. Closed journal counters
contain explicit authority withdrawal, not evidence of a transport/wire bug.
Both already-offline/blocked states are preserved; no automated unfencing or
map/reconnect/data-plane acceptance is claimed. Original core-docs/13/16/17/18/27
are updated locally; those non-Git documents are not part of a Core push.

### Keycloak vendor triage and report integrity

Follow-up (2026-09-17): vendor triage establishes Red Hat's JVM CNA-rejection
statement and Microsoft's MSSQL manifest-version mismatch. The exact bundled
13.2.1.jre11 JAR hash matches the published hotfix. Netty's bundled 4.1.136.Final
hash also matches upstream, in the affected range from the
[maintainer advisory](https://github.com/netty/netty/security/advisories/GHSA-c4c3-7fpv-j4q5).
No backport, POC exploitability or not-affected runtime is inferred. Detailed
public-package hashes/references are in the separate deployment repository's
`images/keycloak/VULNERABILITY_TRIAGE.md`. Latest upstream remains 26.7.4; the
fresh full immutable arm64 scan still has two High/one Critical and exits 1.
No exclusion, VEX or release waiver is accepted.

`SSO-KEYCLOAK-SCAN-REPORT-001` requires more than scanner exit zero: exactly one
parseable Trivy v2 container-image report, requested immutable artifact/Linux
architecture, local ImageID and both Red Hat OS/JAR classes with zero findings.
Incomplete/malformed/non-clean reports reject. The initial positive fixture
fails before implementation; synthetic Docker/remote and arm64/amd64 reports
plus adversarial report tests now pass. No-build fixtures confirm zero scanner
exit with missing report or Critical findings cannot reach Docker. The real
supported base guard exits 1 before a new build; no positive guarded release
is claimed. Helm/Core/Console and shell checks are source-only regression gates,
not provider startup, image trust or live Google evidence.

No Go, migration, Core/client wire or live environment changes occur. Original
13/17/18/27 documents are updated locally, not pushed; Core README mirrors the
record. Whole Go quality/Linux integration is not rerun for these script/docs
changes. Public login and all six real Google cases remain open. The independent
Google-only configuration milestone below does not waive the image/target gates.

### Google-only Keycloak configuration and native canary

`SSO-KEYCLOAK-GOOGLE-CONFIG-001` adds a closed, credential-free profile and native
realm renderer to the separate deployment repository. Realm/client/Google are
always disabled in source output. The confidential client fixes code flow,
PKCE S256, RS256, one exact HTTPS callback and same-origin distinct logout URI;
default/optional/offline scopes, password/implicit/service/device/token-exchange
grants and refresh issuance are off. Only Google is declared, without upstream
token storage, trusted-email/role/group mapping or Core membership grants.
Browser and first-broker flows contain only REQUIRED fixed Google redirect and
create-user-if-unique, without password/form/cookie or auto-link alternatives.
The native AUTH_TIME/ACR mappers are configured; successful real token assurance
and collision behavior still require live proof, not email-based recovery.

The initial source test fails before implementation. All 30 Node 22.20.0
source/CLI tests now pass: exact non-secret fields/profile/version/identifiers/
URIs, disabled output, declared native flow UUID binding and bounded regular
non-symlink CLI input with no invalid stdout. The final native canary passes
on the existing immutable Linux/arm64 blocked candidate, using generated TLS/
operational/client/broker credentials and scratch H2/augmentation/imports. Two
non-root/read-only bounded peers share only an internal network, with no host
ports, upstream requests, Docker/native logs or proxy transport. HTTPS inputs
travel on stdin, with certificate/hostname validation, bounded responses and no
redirect following. Exact owned resources/private data are cleaned before pass.

Actual native import checks client/broker/flows, disabled built-in clients and
empty scope assignments. Browser checks exact Google redirect URI/scopes without
following that Location; missing/disabled broker, empty/unknown hints and
prompt-none fail without local credentials. Missing/plain PKCE, implicit,
redirect origin/path/query changes, offline scope and password/client-credentials
grants with valid client authentication reject. Initial alias override and
internal-network port-publication failures were fixed with native mapped flow
IDs and an internal HTTPS peer, not skipped or an open network. Unsupported
implicit requests may emit only an unauthorized_client error fragment with
exact issuer/no code or token. Normal code-flow query/issuer assertions remain;
Core still does not accept fragment callbacks.

This is disposable provider configuration evidence, not successful Google
login/token, actual collision/linking, Core membership/session, native PostgreSQL
Secret/escaping, enforced target Kubernetes mounts/policy, client wire/data-plane,
HA, remote CI or signed clean-image release evidence. No image is pulled/built/
published or live realm installed; no Core Go/schema/meshd/meshctl change occurs.
The existing 2 High/1 Critical image blocker and all six live Google gates remain.
No whole Go/Linux quality rerun is claimed for these script/docs changes.
Original core-docs/13/17/18/27 are updated locally, not pushed; this is their Git
mirror. Commands, immutable artifacts and pinned vendor references are in the
deployment repository's `identity/keycloak/README.md`.

The protected bundle milestone below implements offline declared-registration
preflight; it does not qualify installed Core/Google state or target delivery.

### Protected Google preparation bundle

`SSO-KEYCLOAK-GOOGLE-BUNDLE-001` adds offline platform-operator preparation in
the separate deployment repository. A closed 20-field credential-free
registration fixes the pinned realm/origin, exact Core issuer/discovery/auth/
token/JWKS/client/callback/logout, confidential Basic/openid/RS256/query, and
Google Web client/identity scopes/exact broker redirect. These declare reviewed
operator registrations, not current Google Console state, Core enabled handlers
or remote provider drift. Core's private loopback process is not exposed/changed.

Three fixed private input files contain registration and distinct Core/Google
credentials. Canonical operator-owned 0700 directories, root/operator-owned
non-writable ancestors (root-owned sticky temp allowed), single-link regular
0400/0600 files, bounded descriptor/path/metadata rechecks and exclusion of all
Git ancestors reject ordinary custody/alias/replacement mistakes. Core's actual
resident BasicSecret requires 32–4096 printable non-whitespace ASCII bytes;
Google's issued credential is bounded to 1–4096 bytes. Neither is trimmed or
normalized. Protected generation/delivery remains responsible for entropy and
installed secret-reference equality; metadata is not filesystem/KMS attestation.

Only an exclusive private bundle is created: bounded native realm JSON with
exact credentials and registration JSON without secrets/hashes, mode 0600 under
0700, checked/synchronized files/directory/parent. Realm/client/Google stay
disabled. No import, Admin API, network/listener, Google request, Core membership/
audit/outbox or enable/waiver option results. Diagnostics are fixed/generated
basename only; owned byte buffers are cleared, not JavaScript heap-zeroization
proof. Ordinary partial failures remove only identity-checked new output;
replacement operator data is preserved. Cleanup failure/process interruption
can leave private secret material: stop delivery, protect/remove leftovers and
remove completed bundles after reviewed delivery, never retain as evidence.

Initial tests fail on the missing implementation. Node 22.20.0 passes 70 new
source/CLI contracts plus the unchanged 30 renderer tests (100, no skip), including
256 deterministic parser mutations, binding/custody drift, source/output change,
partial writes/sync failure, exact special-character bytes and operator data
retention. The final disposable native canary now consumes four protected
bundles, checks staged realm/client/Google remain disabled after import, exact
generated Core secret round-trip and Core-equivalent RFC 6749 form-before-Basic
negative-grant authentication. Existing verified TLS/browser/PKCE/redirect/scope/
grant assertions and owned cleanup pass. Two internal bounded non-root peers,
existing immutable arm64 images, generated H2/TLS/credentials, no host ports/
logs/proxy/upstream requests; no image pull/build/publish or production apply.

Scan-report/no-build guard and Node syntax regressions pass; they are not image
acceptance. Core Go/schema/dependencies/meshd/meshctl wire are unchanged, no new
whole Go/Linux/client/HA qualification claimed. No actual Google registration/
consent/token/collision, Core Session, native PostgreSQL properties escaping,
enforced target Secret/DB/mounts/isolation/runtime or release trust is qualified.
The previous image blocker and all six live Google gates remain, public SSO off.
Original core-docs/13/16/17/18/27 are updated locally, not pushed; README is their
Git mirror. Commands/scope/vendor references are in deployment
`identity/keycloak/README.md`. The runtime milestone below supersedes this
milestone's H2 fixture and adds native credential/TLS checks. Existing servers
suffice; actual rollout/live testing still
waits for image/signature/SBOM/provenance and target custody/runtime gates.

### Protected native Keycloak runtime configuration

`SSO-KEYCLOAK-RUNTIME-CONFIG-001` implements offline protected `keycloak.conf`
preparation in the separate deployment repository. Eight closed credential-free
registration fields bind native profile/version, distinct exact HTTPS frontend/
admin origins, independent PostgreSQL host/port/database and initial/steady
bootstrap mode. Fixed private files supply DB username/password; initial mode
also reads operational bootstrap username/password. Steady mode never reads or
emits bootstrap credentials. Usernames are 1–63 ASCII identifier bytes; passwords
are exact 32–4096 printable non-whitespace ASCII bytes with distinct purposes,
no trimming/normalization or entropy/remote-state attestation.

The shared protected file boundary preserves owner-only canonical directories/
secure ancestors/outside-Git/single-link files, bounded descriptors/path metadata
rechecks, exclusive checked/fsynced private output and identity-checked partial
cleanup. Only native credentials plus credential-free metadata are emitted;
diagnostics remain fixed/generated basename only. Protect/remove completed or
interrupted bundles; this does not guarantee hostile-filesystem transactions or
JavaScript heap zeroization. No import/install/enable/Secret apply is performed.

Exact escaping is pinned to the bundled SmallRye 3.16.0: protect dollars, then
backslashes for Java properties. Unlike moving latest implementation, the pinned
interceptor does not enable general expression escapes. Initial native startup
failed because doubling other backslashes at both layers changed the DB password;
closed failure classification identified it and exact-byte regressions guard
the corrected algorithm. No credential rotation/authentication waiver hides it.

Node 22.20.0 passes 46 new runtime, 100 older Google contracts and a maximum-
length realm preservation regression (147, no skip). Final current-source native
qualification passes actual optimized Keycloak at its original installation
path, ephemeral PostgreSQL 18.6 with
CA-signed verified TLS/SCRAM, encrypted provider DB sessions, special-character
DB credentials and exact bootstrap authentication. Existing staged-disabled
realm/client/Google import, Core-secret/Basic/browser/PKCE/grant assertions pass.
Wrong password/CA/hostname each produces a specifically classified native
startup denial, never arbitrary exit/timeout. The internal unpublished baseline
has three bounded non-root/read-only/capability-free peers; each sequential denial
probe adds only one temporary provider. All owned containers/network/private
credentials/DB/TLS resources are checked clean before pass. Docker logging stays
off; bounded private tmpfs startup errors are classified locally, never raw
returned/retained evidence or operational/public query-custody proof.

Source syntax and scan-report/no-build regressions pass. No image pull/build/
publish, production storage/target apply, Google request, Core Go/schema/
dependencies or meshd/meshctl wire change results. Whole Go/Linux/client/HA is
not rerun or claimed. The image remains CVE-blocked; public SSO and all six live
Google cases remain open. Target immutable Secret contents/0440 projections,
independent DB ownership/grants/backup, serving/CA TLS rotation/certificate
coverage/policy, release signature/SBOM/provenance and actual runtime custody are
not qualified by a source fixture. Original core-docs/13/16/17/18/27 are updated
locally, not pushed; README is the Git mirror. Commands/resource/artifact pins
are in deployment `identity/keycloak/README.md`. Next: select a supported clean
release artifact, then protected target delivery/runtime qualification before
controlled real Google/browser/client acceptance. No new server is needed now.

### Private Keycloak startup/admission hardening

`SSO-KEYCLOAK-STARTUP-ADMISSION-001` fixes separate private chart 0.1.1's native
`--http-max-queued-requests=128` and `--server-async-bootstrap=false`. The finite
queue uses native 503 overflow behavior; it is not a global in-flight/rate limit
or load-qualified capacity. HTTPS/management listeners wait for successful
bootstrap instead of opening while database initialization is unfinished.
No Helm/native-file override can weaken the chart-owned CLI directives.

New directive assertions first fail on the old chart. Final strict Helm lint/
render/single-occurrence/override rejection and actual pinned CLI checks pass.
Current optimized PostgreSQL canary verifies both listeners 8443/9000 after
positive discovery readiness, and sampled IPv4/IPv6 listener absence during
specifically classified wrong-password/CA/hostname startup denials. At least
one valid sample per failure and checked owned cleanup are required; sampling
does not prove continuous absence, queue saturation/503 behavior or capacity.

All 147 protected source tests pass without skips, alongside scan-report/no-build
and unchanged Core/Console Helm regressions. Trivy 0.74.0 cached-check synthetic
manifest configuration scan has no High/Critical failures. Kubesec is unavailable;
no Kubesec or fresh cluster dry-run/install result is claimed. No image pull/
build/publish, target DB/Secret/apply, Google request, Go/schema/dependency or
meshd/meshctl wire change occurs; no whole Go/Linux/client/HA rerun is claimed.
Original core-docs/13/16/17/18/27 are updated locally, not pushed; this README is
their Git mirror. Target mount/DB/TLS/isolation, queue load and release trust
remain gates. Public SSO stays off; all six live Google cases remain open.

Fresh official release/index checks still return 26.7.4 and the same immutable
base pin. The real arm64 guard exits 1 before build. The real amd64 pre-scan
stalls beyond six minutes; the exact PID/parent/platform/reference-matched
scanner is hard-stopped after SIGTERM fails to end it. The guard exits 137,
unavailable before build, not clean or new occurrence-count evidence. See
deployment `images/keycloak/VULNERABILITY_TRIAGE.md` for current disposition.

Next remains supported clean image selection, then protected target delivery/
runtime qualification and controlled real Google/browser/client acceptance.
No new server is needed for this source step.

### Bounded private Keycloak scan lifecycle

`SSO-KEYCLOAK-SCAN-LIFECYCLE-001` implements a fixed external 180-second scan
deadline/five-second close budget in the deployment repository. Reviewed
build-only Node 22.20.0 owns one detached Unix scanner group, captures a validated
PID once, kills only that group on deadline/cancel, and requires leader close and
observed group absence before success. Ambiguous kill/reap/group inspection is
an unresolved cleanup failure; stop delivery and check owned leftovers. Node
preload/module overrides and deadline overrides are forbidden. Scanner output
is discarded; diagnostics contain only closed outcome/exit/duration metadata.
This does not add Node to Core/Keycloak runtime or weaken image/report gates.

Twenty-eight new deterministic/CLI tests plus existing 147 source contracts pass
(175, no skip). One bounded native Unix-group smoke passes actual SIGKILL/close/
group absence using only an accelerated internal clock, not production Trivy
timing. Scan-report/no-build, syntax and unchanged private-provider/Core/Console
Helm regressions pass. An early measured amd64 invocation overruns at 354,724 ms
and remains failed timing evidence; cause is not established. Subsequent matching
scanner/runner inventory is zero. Final-source real guards exit 1 before build:
amd64 17,190 ms, arm64 2,364 ms. Neither is a clean-image/new CVE-count verdict
or universal wall-clock guarantee. The official base index pin is unchanged;
no supported clean replacement is selected. Read-only target inventory has zero
matching Keycloak Deployments, not runtime acceptance.

No Docker build/push/install, target Secret/DB mutation, Google request, Go/schema/
dependency or meshd/meshctl wire change occurs. Whole Go/Linux/client/HA/provider-
runtime canary is not rerun or claimed. Original core-docs/13/16/17/18/27 are
updated locally, not pushed; this README is their Git mirror. The release blocker
and all six live Google cases remain open. Next: supported clean image/release
trust, protected target DB/TLS/immutable Secrets/runtime, then controlled Google/
browser/client acceptance. Existing servers suffice for current source work.

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
public JSON. Public login and OIDC callback composition remain future slices;
the existing-subject issuance foundation described above is now implemented.

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
phases share one configured shutdown deadline. `RUNTIME-RESOURCE-JOIN-FENCE-001`
requires positive `Done` evidence from every successfully started service and
monitor before calling the resource closer. A reported component error still
proves termination; a missing channel, successful `Shutdown` without `Done`,
or join timeout does not. Already published results are observed before treating
an expired context as missing evidence.

If any owner cannot join, all other owners still receive reverse-order stop
signals, but the complete resource graph is retained. `Run` returns terminal
`app.ErrIncompleteShutdown` together with the original errors. The composition
root keeps application resource custody and exits nonzero without fallback
cleanup. Do not restart the application, close provider/key/storage resources,
spawn a detached waiter, or claim a clean drain. OS process teardown releases
retained state. Resource cleanup also refuses to start after the shared deadline
is exhausted. PostgreSQL
cleanup also refuses to call the pool's blocking close while a connection is
still acquired, so shutdown never relies on an unowned timeout goroutine.
`/live` never depends on infrastructure availability. Health responses expose
only stable component names and `ready`, `unavailable`, or `unknown` states.
The listener defaults to loopback and should not be exposed on public client
ingress.

This lifecycle correction applies to existing roles and is a prerequisite for
private login runtime binding, not its completion. No new environment settings,
listener activation, schema, client wire or public Google SSO readiness is added.
Deterministic contracts cover missing/unjoined owners, partial startup,
already-observed unexpected exits, reported error/closed-channel joins and an
owned goroutine whose late cleanup outlives the application shutdown deadline.
Original runtime/security/test/ADR documents are updated in the development
workspace; this section is the versioned mirror of the correction.

Source-only acceptance (2026-09-17): the nine negative join contracts first
reproduce unsafe ResourceCloser invocation on the pre-fix lifecycle. Corrected
source passes unchanged full `make quality` and uncached shuffled race/goleak
tests for `internal/app` and `cmd/meshcore` on host Go 1.26.8 and digest-pinned
Linux/arm64 Go 1.26.8. Linux is offline/nonroot with read-only source/modules and
isolated scratch, no host credentials/socket/live services. Govulncheck reports
zero affected symbols/imported packages and three non-called required-module
advisories, not zero advisories. These are source contracts, not real provider/
storage/browser/client/HA, native-clock, or immutable release qualification.

Fresh pinned v2.13.2 unfiltered pre/post lint and modified-file-only autofix pass
with no changes. All 711 Go hashes and exact three target texts remain frozen;
708 outside files are untouched. Zero raw issues means Diff/Fixer receive no
input; scoping/order is source-verified, not runtime patch-parser qualification.

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
