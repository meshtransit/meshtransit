# MeshTransit Core

Product direction: MeshTransit targets **Zero Trust Access Assurance for private
infrastructure**. Secure Private Resource Fabric remains architecture foundation;
Access Graph becomes authorization, explanation, simulation, and verification
model. Current Phase 1 scope is unchanged. See
[PRODUCT_DIRECTION.md](PRODUCT_DIRECTION.md).

Current POC status (2026-09-28): Phase 1 POC engineering is closed. The embedded
Dex identity broker, Google OIDC
connector, Core-owned browser session, cookie-authenticated policy publication,
and two-replica API, Control, Identity, and Console roles are qualified on
Kubernetes. Policy publication was verified through allow, deny-all, and
restore transitions while a Control replica was replaced. The deployable Core
image is built from a manifest-verified Dex workspace; provider-specific
deployment artifacts are not part of this repository.
Provider-neutral identity migration and broker upgrade, backup, restore, and
rollback are qualified on disposable PostgreSQL. External legal/release
approval, production data-service failover, multi-node fault domains, and
production SLOs remain separate gates. The exact non-production evidence and
remaining gaps are recorded in the
[POC HA, SSO, and policy qualification matrix](docs/qualification/poc-ha-sso-policy-2026-09-27.md).

Phase 2 M1 includes the first PostgreSQL-authoritative Device Resource and
immutable Resource Group slice. Phase 2 M2 adds Bearer management create/get/list
contracts. M3a adds retained lifecycle actions, M3b1 adds deterministic impact
preview plus atomic Device target rebinding, and M3b2 appends and activates
immutable Resource Group definitions through the same preview boundary. These slices use fresh
exact-scope authorization, strong revision preconditions, durable idempotency,
and safe errors. No Resource Console UI, Access Graph evaluation, or graph
database is introduced.
Design, security boundaries, acceptance evidence, and explicit non-claims are
recorded in the
[Phase 2 M1 Resource authority design](docs/design/phase2-m1-resource-authority.md)
and
[acceptance matrix](docs/qualification/phase2-m1-resource-authority-2026-09-28.md),
plus the
[Phase 2 M2 Resource management API design](docs/design/phase2-m2-resource-management-api.md)
and
[M2 acceptance matrix](docs/qualification/phase2-m2-resource-management-api-2026-09-28.md),
the
[M3a Resource lifecycle design](docs/design/phase2-m3a-resource-lifecycle-api.md)
and
[M3a acceptance matrix](docs/qualification/phase2-m3a-resource-lifecycle-api-2026-09-28.md),
plus the
[M3b Resource target rebinding design](docs/design/phase2-m3b-resource-target-rebinding.md)
and
[M3b acceptance matrix](docs/qualification/phase2-m3b-resource-target-rebinding-2026-09-28.md),
plus the
[M3b2 Resource Group replacement design](docs/design/phase2-m3b2-resource-group-definition-replacement.md)
and
[M3b2 acceptance matrix](docs/qualification/phase2-m3b2-resource-group-definition-replacement-2026-09-28.md).

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
client state. Long-lived streams use generation-fenced Redis presence with
same-generation replica handover, owner-exact renewal, bounded lease expiry,
bounded keepalives, process-owned revision and connectivity feeds, and periodic
PostgreSQL plus Redis resync. One-shot connectivity updates validate
and record canonical discovery keys, endpoint sets, and usable preferred-relay
observations under the same Redis session-generation fence. Maps project those
exact-generation routing observations and online state only after PostgreSQL
membership and packet policy authorize the peer. Redis exposes
bounded, versioned `NetworkRevisionAdvanced` and connectivity-change wakeup
transports. A control replica holds one subscription for each feed and fans
wakeups into bounded, coalescing Network-local channels. PostgreSQL remains the
source of peer visibility and packet authority; Redis loss never widens access.
Transient subscription loss keeps existing watchers registered while each feed
reconnects with bounded jittered exponential backoff. Reconnect attempts and
successful recoveries are exported as bounded metrics. A notification missed
during recovery is repaired by periodic authoritative PostgreSQL reconciliation.
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
configuration-schema versions (currently 22). Run `meshcore config validate` to
validate the selected role, bounded values, secret files, and CA bundles without
opening a listener. Dependency-backed profiles also perform bounded connectivity
checks; `role=identity` requires an exact prepared broker schema and never runs a
migration from either `config validate` or `serve`. The process serves normally
with either no arguments or the explicit `meshcore serve` command.

Database migrations are explicit one-shot operations: use
`meshcore migrate status` to inspect compatibility and `meshcore migrate up` to
apply every known pending migration. Normal `serve` startup never applies or
repairs migrations.

## Runtime configuration

Configuration is read once at process startup. An explicitly set empty or
invalid value stops startup before a listener is opened.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_ROLE` | `all` | One of `all`, `api`, `control`, `worker`, `relay`, or `identity`. |
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

The isolated `identity` role does not load Core PostgreSQL, Redis, API, control,
worker, enrollment, or private-login configuration. It uses the dedicated
broker database contract below. `role=all` now composes API, control, worker,
relay, and the same embedded identity broker. Both `identity` and `all` require
a binary built from the manifest-verified Dex workspace with the `dexbroker`
build tag; ordinary builds reject broker composition. One immutable
generic-OIDC Google connector and one
confidential Core client are composed from protected files. Their generations,
metadata, fixed protocol policy, derived broker callback, redirect URI, and
secret contents, exact upstream endpoints, and outbound-policy version are bound
into an approved `sha256-v2` fingerprint. Startup and periodic readiness re-read
the files and fail closed on drift. Dynamic connector and client records remain
invisible and their CRUD paths are denied, so those secrets are never written to
broker PostgreSQL. The generic-OIDC client now permits only the fixed Google
discovery, token, and JWKS method/URL pairs. It ignores ambient proxies, rejects
redirects and non-public DNS results, pins each validated IP for the dial, and
enforces bounded TLS, request, response, connection, and lifecycle behavior.
The isolated role mounts that handler on a separate direct-TLS listener. It may
bind an unspecified address inside a container; the Kubernetes Service and
network policy own external reachability. Configuration schema 23 also adds the version-2 Core BFF
profile described below: a fixed public application origin is separated from
the private backend bind, exact trusted ingress prefixes are carried into client
source resolution, and the existing callback/token/session graph is served only
through the bounded direct-TLS login listener. No public DNS, ingress route or
Google credential is created by source configuration, so completed browser
login and public deployment acceptance remain open.

Run `meshcore identity fingerprint` with every identity setting except
`MESHTRANSIT_IDENTITY_CONFIGURATION_FINGERPRINT` to produce the exact approved
digest without printing secret contents or file paths. Put that result into the
fingerprint setting before `config validate` or `serve`. Both connector and Core
client secrets must contain at least 32 bytes of high-entropy single-line
material.

The schema-20 Linux/arm64 EC2 POC used binary digest
`490c53dd3e4d723f965c2dcf69916f84a2bca07ef595ccf5511582007fab2f9c`,
validated fingerprint
`sha256-v2:1332d4b1a9d1a801a2af4f03252512b2bf40b794d7c6bc3f62a3475d937a5bf7`.
`config validate` reported schema 20 and the private listener served discovery
over TLS 1.2+/HTTP/1 with the fixed security headers. The authorization request
redirected through the configured connector to the real
`accounts.google.com` authorization endpoint with
`code_challenge_method=S256` and the exact broker callback. Userinfo returned
404, plaintext did not reach the handler, and both readiness components were
ready. Bounded shutdown left zero runtime connections, while PostgreSQL still
contained zero connector and zero client rows. Non-production client metadata
was used, so this qualifies the private transport and outbound redirect, not a
completed Google login, token exchange, Core session, public ingress, or HA
Kubernetes deployment.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_IDENTITY_ISSUER` | none | Exact HTTPS broker issuer. Userinfo, query, fragment, root path, and trailing slash are rejected. |
| `MESHTRANSIT_IDENTITY_CONFIGURATION_FINGERPRINT` | none | Exact `sha256-v2:<64 lowercase hex>` output approved for this immutable connector/client and outbound-policy configuration. Not required by `identity fingerprint`; required by validation and serving. |
| `MESHTRANSIT_IDENTITY_ADDRESS` | none | Canonical private, loopback, or unspecified IP and non-zero port for the isolated broker listener. Unspecified binds support container networking; DNS, public, mapped, zoned, and link-local addresses are rejected. |
| `MESHTRANSIT_IDENTITY_TLS_CERTIFICATE_FILE` | none | Absolute path to the direct-TLS certificate chain. The leaf must have exactly the issuer hostname SAN, server-auth usage, a strong key/signature, and current validity. |
| `MESHTRANSIT_IDENTITY_TLS_PRIVATE_KEY_FILE` | none | Absolute path to the dedicated listener private key. It must differ from the certificate and every identity credential path. |
| `MESHTRANSIT_IDENTITY_REQUEST_TIMEOUT` | `15s` | Whole-second request-context/read bound from 1 through 30 seconds. |
| `MESHTRANSIT_IDENTITY_MAX_CONNECTIONS` | `256` | Per-replica TCP/TLS connection cap from 1 through 4096. |
| `MESHTRANSIT_IDENTITY_MAX_CONCURRENT_REQUESTS` | `128` | Non-queuing request cap from 1 through the connection cap; overflow receives 429 with `Retry-After`. |
| `MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ID` | none | Immutable lowercase connector security ID. Changing it creates a new identity namespace. |
| `MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_DISPLAY_NAME` | none | Bounded display label; it is not an identity key. |
| `MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_GENERATION` | none | Positive decimal trust-configuration generation. |
| `MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ISSUER` | none | Phase 1 requires exactly `https://accounts.google.com`; arbitrary upstream issuers remain disabled. |
| `MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_ID` | none | Exact Google OAuth client ID. |
| `MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_SECRET_FILE` | none | Absolute path to the bounded single-line Google client secret; never persisted to broker storage. |
| `MESHTRANSIT_IDENTITY_CORE_CLIENT_ID` | none | Immutable lowercase ID for the confidential Core BFF client. |
| `MESHTRANSIT_IDENTITY_CORE_CLIENT_DISPLAY_NAME` | none | Bounded Core client display label. |
| `MESHTRANSIT_IDENTITY_CORE_CLIENT_GENERATION` | none | Positive decimal confidential-client generation. |
| `MESHTRANSIT_IDENTITY_CORE_CLIENT_SECRET_FILE` | none | Absolute path to the bounded single-line confidential client secret; never persisted to broker storage. |
| `MESHTRANSIT_IDENTITY_CORE_CLIENT_REDIRECT_URI` | none | One exact canonical HTTPS Core BFF callback URI; query, fragment, root/trailing-slash, and dot-segment paths are rejected. |
| `MESHTRANSIT_IDENTITY_POSTGRES_ADDRESS` | none | Dedicated broker PostgreSQL TLS host and non-zero port. |
| `MESHTRANSIT_IDENTITY_POSTGRES_DATABASE` | none | Dedicated broker database; no Core database fallback. |
| `MESHTRANSIT_IDENTITY_POSTGRES_RUNTIME_USER` | none | DML-only broker runtime role; never the migration role. |
| `MESHTRANSIT_IDENTITY_POSTGRES_RUNTIME_PASSWORD_FILE` | none | Absolute path to the runtime role's bounded single-line credential file. |
| `MESHTRANSIT_IDENTITY_POSTGRES_CA_FILE` | none | Absolute path to the PostgreSQL trust bundle used with TLS `verify-full`. |
| `MESHTRANSIT_IDENTITY_POSTGRES_MAX_OPEN_CONNECTIONS` | `10` | Per-replica open-connection cap from 1 through 50. |
| `MESHTRANSIT_IDENTITY_POSTGRES_MAX_IDLE_CONNECTIONS` | `5` | Per-replica idle cap from 1 through the open cap. |
| `MESHTRANSIT_IDENTITY_POSTGRES_CONNECT_TIMEOUT` | `1s` | Whole-second connect timeout from 1 through 30 seconds and no greater than the dependency check timeout. |
| `MESHTRANSIT_IDENTITY_POSTGRES_CONNECTION_LIFETIME` | `30m` | Whole-second connection lifetime from 1 minute through 24 hours. |
| `MESHTRANSIT_IDENTITY_ID_TOKEN_LIFETIME` | `5m` | ID-token lifetime from 1 minute through 1 hour. |
| `MESHTRANSIT_IDENTITY_AUTH_REQUEST_LIFETIME` | `5m` | Broker authentication-request lifetime from 1 through 30 minutes. |
| `MESHTRANSIT_IDENTITY_SIGNING_KEY_ROTATION` | `6h` | Signing-key rotation interval from 1 hour through 30 days. |
| `MESHTRANSIT_IDENTITY_GARBAGE_COLLECTION_INTERVAL` | `5m` | Broker garbage-collection interval from 1 minute through 1 hour. |

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_POSTGRES_ADDRESS` | none | PostgreSQL TLS host and non-zero port. For HA, the host must be a stable writer endpoint whose certificate covers that name. Every new connection is accepted only when it is read-write; periodic readiness retires the entire pool if a demoted primary remains reachable so the next acquisition resolves the promoted writer. |
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
| `MESHTRANSIT_CONTROL_MAP_KEEPALIVE_INTERVAL` | `30s` | Silent-stream keepalive interval from 1 second through 90 seconds. Keep it below every proxy idle timeout on the control path. |
| `MESHTRANSIT_CONTROL_MAP_RECONCILE_INTERVAL` | `30s` | Authoritative PostgreSQL resync interval from 1 second through 5 minutes. |
| `MESHTRANSIT_RELAY_DIRECTORY_FILE` | none | Absolute path to the bounded, product-schema relay directory snapshot loaded at control-role startup. |
| `MESHTRANSIT_RELAY_DIRECTORY_SHA256` | none | Canonical lowercase `sha256:<64 hex digits>` digest pin for the exact relay directory file. |

The control role fails startup when the relay directory file is absent, unsafe,
oversized, malformed, or does not match its digest pin. Core never fetches relay
metadata at runtime. A directory revision increase is published as a complete
replacement in the next full map snapshot; revision regression or different
topology under the same revision terminates the stream fail-closed. Relay
metadata grants no peer visibility, route, packet-policy, or Network authority.

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

## Embedded identity broker and browser SSO

The `identity` runtime role embeds a manifest-verified Dex broker behind a
narrow adapter and dedicated PostgreSQL schema. It is built with the
`dexbroker` build tag; ordinary builds fail closed when the role is selected.
Broker version preparation, patch verification, and the final multi-platform
image build remain explicit so a future Dex upgrade is isolated from Core
domain code.

The initial connector is Google through generic OIDC. Connector and
confidential Core-client metadata are static, generation-bound configuration;
secret values are read from protected files and are never persisted through
dynamic broker CRUD. Core validates the exact issuer, subject, audience,
authorized party, nonce, state, PKCE, signed authentication time, algorithms,
and trusted keys. Email, provider groups, and provider roles never grant
Workspace membership or RBAC.

Browser login uses independent pre-authentication, initiation, and Account
Session cookies with exact host, origin, CSRF, expiry, replay, and generation
checks. PostgreSQL owns authentication transactions, subject bindings, sessions,
audit evidence, and recovery fencing, so login and callback processing do not
require sticky routing. The public login dispatcher exposes only the bounded
start, callback, continuation, session, logout, and cookie-authenticated
management paths.

Identity replicas share durable broker state and may scale independently from
API and Control replicas. Readiness verifies the broker schema, configured
connector/client fingerprint, protected files, and upstream discovery contract.
Startup never runs broker migrations. Upgrades prepare and qualify a new Dex
workspace and image before rollout; Core code imports the broker only through
the adapter composition boundary.

The Kubernetes POC verified real Google login, Core session issuance,
authenticated policy publication, two Identity replicas, and a Control-replica
replacement during a deny-all publication. The active policy was restored to
revision 20 with two directional ICMP rules, and both clients converged without
sticky-session assumptions.

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
public JSON. Public login and callback composition are enabled only through the
bounded Identity and API role surfaces described above.

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
- `GET /ready`: Core API/control/worker/relay work may be admitted;
- `GET /ready/login`: new browser login may be admitted, or `404` when login is not configured;
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
state, active watchers, received wakeups, bounded `delivered`/`coalesced`
fan-out results, and bounded reconnect attempt/success counters.
Workspace, Network, Node, session, and replica identities are never metric
labels. Each process-owned feed subscriber serves all local map streams; no
client creates its own Redis connection or goroutine.

PostgreSQL telemetry is partitioned only by the fixed `runtime` and `worker`
credential-pool roles. It reports bounded semantic operation outcomes and
latency, connection usage, acquisition/cancellation counts and wait duration,
and connection creation/destruction. Pool state is also sampled at scrape time;
SQL text, usernames, addresses, database names, and domain identifiers are
never metric labels.

Readiness opens only after the initial Core dependency checks succeed and all
role services start. Identity-only processes continue to fail closed on both
broker checks. In a successfully started `all` process, later identity or
private-login dependency loss lowers `/ready/login` while `/ready` remains
available for healthy Core work; fixed component metrics and the
`meshtransit_login_configured`/`meshtransit_login_ready` gauges expose both
states. Co-location still shares a process failure domain, so a broker
composition failure during cold start stops `all`; deployments requiring that
isolation use independently replicated `identity` processes. For `control` and
`all`, both wakeup-feed subscriptions
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

The lifecycle correction also protects the embedded broker and private login
services. Configuration schema 23 adds aggregate-role identity binding and the
separate login readiness contract; it does not change client wire protocols or
authorize public ingress by itself.
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

`make qualification-dex DEX_QUALIFICATION_BINARY=/absolute/path/to/dex`
runs `SSO-BROKER-000` against the default pinned release. Override
`DEX_QUALIFICATION_RELEASE` only when qualifying an exact replacement artifact.
The suite treats Dex as a black-box OIDC server and does not import Dex packages,
so an upgrade reruns the same discovery, successful/error callback, signature,
and `auth_time` contracts. The target fails while any hard requirement is absent.

`make qualification-dex-boundary` enforces the adapter-only portion of
`SSO-BROKER-001`. `internal/adapter/dexbroker` is the only MeshCore package that
may import `github.com/dexidp/dex` or any of its subpackages. The contract test
parses every Go source file, including files excluded by current build tags, and
fails closed on malformed or symlinked Go source. The package now exposes a
product-owned lifecycle shell whose public surface is only `http.Handler`,
`Ready`, `Shutdown`, and `Done`; Dex configuration and runtime types remain
private to the adapter. It does not enable a listener, route, or public login.

ADR-049 permits only temporary upstream-oriented compatibility patches. RFC 9207
response issuer support and persisted signed authentication time remain separate
patches so each can be removed when an upstream stable release supplies that
behavior. A third independent patch pins the Go toolchain floor and dependency
versions needed to clear reachable vulnerability findings. A fourth independent
patch adds a completion fence for signer rotation and garbage collection so
storage teardown can join every Dex-owned background worker. The ordered
version-scoped inputs, platform manifest, CycloneDX SBOM, license inventory,
vulnerability report, and qualification report are stored under
[`third_party/dex/v2.45.1`](third_party/dex/v2.45.1/README.md); Dex source is not
vendored and no Dex fork is maintained. Compatibility inputs live outside
MeshCore domain code, record the exact upstream commit and patch digests,
preserve original authentication time across refresh, and cannot derive claims
from token issue time or request headers. The unchanged black-box gate, not
patch presence, decides whether an artifact is eligible for the embedded broker
adapter.

`make verify-dex-artifact DEX_ARTIFACT_MANIFEST=/absolute/path/manifest.json
DEX_UPSTREAM_SOURCE=/absolute/path/dex
DEX_ARTIFACT_BINARY=/absolute/path/dex-binary` verifies ADR-049 artifact identity
before the black-box gate runs. It operates offline, applies ordered patch copies
to a temporary detached checkout, verifies all declared SHA-256 evidence, and
leaves the supplied source checkout unchanged. The manifest schema and operator
contract are in
[`tools/qualification/dexartifact`](tools/qualification/dexartifact/README.md).

`make prepare-dex-source` accepts the same three verified inputs plus
`DEX_PREPARED_ROOT`, which must identify an existing empty private directory.
Only after every manifest check passes does it preserve the exact patched tree
under `DEX_PREPARED_ROOT/source`, without Git metadata. It refuses a non-empty
root and never writes Dex source into the MeshCore repository. This produces the
ephemeral dependency input for the compile gate; it does not enable the broker
runtime or public login.

`make qualification-dex-compile DEX_UPSTREAM_SOURCE=/absolute/path/dex
DEX_PREPARED_ROOT=/absolute/path/prepared` runs the adapter compile contract
against both trees. It first proves the base Dex server/configuration/storage
API compiles against unmodified upstream, then proves that adding only the
required `storage.Claims.AuthTime` field fails there with the expected compiler
diagnostic. Two further negative checks independently prove that unmodified
upstream lacks `server.Server.Done` and the signer join-channel signature. A
fifth negative check proves the prepared PostgreSQL runtime/readiness contract
is also absent upstream. The sixth and seventh independently prove upstream
lacks the connector HTTP-client map and generic-OIDC client-injection API; the
eighth compiles the complete contract against the verified prepared source. The
generated package also locks `server.NewServer` and `http.Handler`
compatibility. It builds but never
executes the temporary test binary, stores no Dex source in MeshCore, and
enables no runtime or route.
The exact contract and upgrade behavior are documented in
[`tools/qualification/dexcompile`](tools/qualification/dexcompile/README.md).

`make prepare-dex-workspace` accepts the artifact inputs used by
`prepare-dex-source`, verifies them again, and additionally requires the
MeshCore `go.mod` to pin the manifest's exact Go module coordinate. It rejects
any checked-in Dex `replace`, then writes an ephemeral `go.work` beside the
prepared source. The workspace contains MeshCore, the verified Dex root module,
and Dex's `api/v2` module; no workspace file or Dex source is written into the
repository. `make qualification-dex-workspace DEX_PREPARED_ROOT=/absolute/path`
then compiles the real build-tagged adapter and process composition in
`internal/adapter/dexbroker` and `cmd/meshcore`.
The current pin is
`github.com/dexidp/dex@v0.0.0-20260303133905-11d2eeb52b42`, derived from the
manifest commit and its UTC timestamp. The direct dependency and workspace are
build wiring only: the ordinary image excludes the `dexbroker` tag, and no Dex
component, listener, route, or login is enabled.

The adapter lifecycle shell fences new requests before shutdown, drains every
already-admitted handler, calls component stop exactly once, and closes `Done`
only after the component reports that all owned background work has joined.
Concurrent and repeated shutdown calls share one stable result; a caller
deadline does not abandon cleanup. Unexpected component completion immediately
removes readiness and subsequent requests fail with a generic no-store 503.
The runtime graph is redacted from formatting and structured logging and refuses
JSON serialization. Unit and race tests cover typed-nil construction, admission
fencing, drain order, timeout continuation, concurrent shutdown, unexpected
completion, and fail-closed zero values. The verified `compat.8` input supplies
the worker/connector join fences, no-DDL prepared-schema open, a context-bounded
exact-schema readiness check, and caller-owned per-connector HTTP clients.
Upstream-negative compile checks, candidate compilation, full
storage/server/signer/OIDC tests, black-box
`SSO-BROKER-000`, and race tests pass.

The exact component bridge now constructs the pinned server and signer lazily
from product-owned scalar options but borrows storage; it never closes the
shared handle. A private PostgreSQL resource opens only the prepared-schema path
with
TLS `verify-full`, file-backed password/CA references, explicit per-replica
max-open/max-idle limits, bounded connect/lifetime values, redacted outward
errors, and context-bounded connectivity/schema checks. Shutdown stops new uses,
joins both admitted checks and the long-lived service borrow, preserves the
handle after a caller timeout, and closes exactly once on retry. `role=identity`
now maps this resource into readiness, registers it under `resourceOwner`, and
owns the lazy broker service followed by its private HTTPS listener. Reverse
shutdown stops and drains the listener before broker workers release their
long-lived PostgreSQL borrow. Only discovery, authorization, the configured
connector hop, callback, token, and keys are admitted with exact Host/path/method
checks; userinfo, introspection, device flow, health, root, static UI, and every
unconfigured route fail closed. Forwarded assertions are stripped, request and
body/query/header sizes are bounded, plaintext and HTTP/2 are disabled, and
security headers are reasserted at write time. Public ingress and Core BFF
callback remain explicit deployment concerns; aggregate `role=all` composition
is enabled only in the manifest-verified tagged binary.

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
gate launches the ordinary binary in separated `control` and `worker` roles,
performs bounded SIGTERM shutdowns, and proves restarted processes reach
readiness against the same durable state. A negative process case proves
invalid control configuration exits with redacted diagnostics
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

The embedded identity-broker image is an explicit release path, not an implicit
dependency of the ordinary image. First create a verified ephemeral workspace
with `make prepare-dex-workspace`; then pass that directory as
`DEX_PREPARED_ROOT` to `make container-push-dexbroker-multiarch`. The dedicated
`Dockerfile.dexbroker` receives the prepared Dex tree as a named BuildKit context,
creates a temporary Go workspace inside the builder, and selects only the
`dexbroker` build tag. No Dex source, workspace path, or Git metadata enters the
MeshCore repository. A future Dex release must produce its own verified prepared
workspace before it can use the unchanged image target.

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

## License

Except for third-party components identified in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), the community distribution of
MeshTransit Core is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).

The same MeshTransit-owned code may also be licensed under a separate written
commercial agreement. See
[COMMERCIAL-LICENSING.md](COMMERCIAL-LICENSING.md) for the licensing boundary;
that document does not itself grant a commercial license.
