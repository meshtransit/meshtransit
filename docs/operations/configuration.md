# Configuration

Core is configured only with environment variables, read once at start.
`meshcore config validate` checks a configuration without serving: it also
reads the secret files and connects to PostgreSQL and Redis, so it needs them
reachable. It prints the configuration schema version (26) and the role. `meshrelay` takes flags
or `MESHRELAY_*` variables; `meshd` and `meshnetd` take flags only.

## Rules for every variable

- **A configuration error is logged as `error_code=invalid_configuration`.**
  The error text names the variable, never its value, but Core's log
  redaction currently hides it too, so use [common errors](#common-errors) to
  find the setting.
- **Set but empty is set.** A default applies only when the variable is
  absent; `VAR=""` is validated and usually refused. Templates must leave out
  variables they do not set.
- **Durations** use Go syntax (`500ms`, `30s`, `5m`); **booleans** are exactly
  `true` or `false`; numbers and durations may not have spaces.
- **Addresses** are `host:port`, port 1–65535; a dependency address needs a
  host.
- **Paths** are absolute and clean. Whether the file exists is checked when it
  is read, at start.
- **CIDR lists** are comma-separated canonical prefixes, at most 16, no
  spaces, no duplicates.
- **Deployment IDs** are lowercase UUIDv7.
- **Key IDs** are 1–128 bytes: an ASCII letter or digit, then letters,
  digits, `.`, `_`, `:` or `-` (idempotency and rate-limit key IDs also allow
  `/`).
- **A setting a role does not use is ignored** unless the table says it is
  refused on other roles.

### Secret files

| Kind | Used for | Rules |
|---|---|---|
| Secret | Passwords, HMAC digest keys, the MTCP control key, mail credentials, the entitlement, the browser registration key | Regular file, one line, at most 4 KiB; a trailing newline is removed |
| Trust | CA bundles, TLS certificates | At most 1 MiB |
| TLS key | TLS private keys | At most 64 KiB |
| Private identity key | Relay signing keys, the installation key, the Console login keys | Exactly 43 base64url characters (an Ed25519 seed); mode 0400, 0440, 0600 or 0640; must not change while being read; Linux and macOS only |

Encodings:

- HMAC digest keys (enrollment, Account Session, idempotency, rate limit) are
  32 bytes in unpadded base64url.
- The browser registration key is 32 bytes in **padded standard** base64.
- The MTCP control key is `privkey:` followed by 64 lowercase hex characters.

Each secret has one purpose: Core refuses to start when two settings point to
the same file (for example the API TLS key and the MTCP control key, or the
runtime and worker passwords), or when two key IDs are equal. When the
Console login is configured:

- the API's Account Session, idempotency and rate-limit key files, the login
  TLS certificate and key and the client secret file must also have one of
  the private-key modes above;
- every key ID (the login purpose keys, including an optional previous subject
  key, and those three) must be 1–64 characters of letters, digits, `_` and `-`, starting with a letter
  or digit.

Generating keys:

| Key | Command |
|---|---|
| MTCP control key | `printf 'privkey:%s\n' "$(openssl rand -hex 32)"` |
| HMAC digest key | `openssl rand -base64 32 \| tr '+/' '-_' \| tr -d '=\n'` |
| Browser registration key | `openssl rand -base64 32` |
| Ed25519 seed (relay signing key, installation key, login purpose keys) | 32 random bytes in unpadded base64url, as for an HMAC key |
| Relay key | `meshrelay genkey --out <file>` |

## Process

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_ROLE` | `all` | `all`, `api`, `control`, `worker`, `relay`, `identity` | What the process runs; `all` includes `identity`, see [Core](../architecture/core.md). `relay` runs only the operator listener; the relay is `meshrelay` |
| `MESHTRANSIT_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` | JSON logs on standard error |
| `MESHTRANSIT_HEALTH_ADDRESS` | `127.0.0.1:8081` | address | Operator listener: health, readiness, metrics |
| `MESHTRANSIT_PROFILE_ADDRESS` | off | loopback IP:port | `pprof` listener |
| `MESHTRANSIT_SHUTDOWN_TIMEOUT` | `15s` | 1s–5m | Deadline for a graceful stop |
| `MESHTRANSIT_DEPENDENCY_CHECK_TIMEOUT` | `2s` | 100ms–30s, below the interval | Deadline of one dependency check |
| `MESHTRANSIT_DEPENDENCY_CHECK_INTERVAL` | `10s` | 1s–5m | How often readiness checks dependencies |
| `MESHTRANSIT_DNS_SUFFIX` | `mesh.internal` | DNS name of at least two labels, at most 155 bytes; labels of `a-z`, `0-9` and `-`, the last not all digits; not `local`, `localhost`, `arpa`, `invalid`, `test`, `onion`, `example`, `example.com/net/org` or under them; lowercased | Suffix of Device names (`<label>.<Workspace code>.<Network code>.<suffix>`) and share names (`….shared.<suffix>`) in maps and API responses. Set the same value on every role. Changing it renames every Device and share at the next map; see [DNS](../concepts/dns.md) |

The API, control, identity and Console login listeners may not share a port
with each other or with the health listener; a wildcard host on the same port
counts as shared. (Control against health and the profile listener is not
checked.)

## PostgreSQL

For `api`, `control`, `worker` and `all`. The `api` and `control` roles use
the runtime user, `worker` uses the worker user, `all` both.

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_POSTGRES_ADDRESS` | required | address | TLS endpoint |
| `MESHTRANSIT_POSTGRES_DATABASE` | required | name | Database |
| `MESHTRANSIT_POSTGRES_CA_FILE` | required | path | CA bundle |
| `MESHTRANSIT_POSTGRES_RUNTIME_USER` | required (`api`, `control`) | must be `mesh_runtime`: migrations grant to that name | Runtime role |
| `MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE` | required (`api`, `control`) | path | Its password |
| `MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS` | `10` | 1–50 | Pool size |
| `MESHTRANSIT_POSTGRES_WORKER_USER` | required (`worker`) | must be `mesh_worker` | Worker role |
| `MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE` | required (`worker`) | path, not the runtime password | Its password |
| `MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS` | `10` | 1–50 | Pool size |

### Migrations and bootstrap

Read only by `meshcore migrate status|up|verify`, `meshcore bootstrap check|apply`
and `meshcore account`;
they never fall back to the runtime credentials.

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_MIGRATION_POSTGRES_ADDRESS` | required | address | Migrator endpoint |
| `MESHTRANSIT_MIGRATION_POSTGRES_DATABASE` | required | name | Database |
| `MESHTRANSIT_MIGRATION_POSTGRES_USER` | required | name | Migrator role (owns the database) |
| `MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE` | required | path | Its password |
| `MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE` | required | path | CA bundle |
| `MESHTRANSIT_MIGRATION_ACTOR` | required | name | Recorded with each applied migration |
| `MESHTRANSIT_MIGRATION_CONNECT_TIMEOUT` | `5s` | 100ms–30s | |
| `MESHTRANSIT_MIGRATION_LOCK_TIMEOUT` | `5s` | 100ms–30s, below the statement timeout | |
| `MESHTRANSIT_MIGRATION_STATEMENT_TIMEOUT` | `30s` | 1s–10m | |
| `MESHTRANSIT_BOOTSTRAP_PLAN_FILE` | required for `bootstrap` | path, at most 64 KiB | The installation plan |

`bootstrap` also loads the configuration of `MESHTRANSIT_ROLE`, which must be
`api` (or `all`) with the Console login.

### Operator steps

Read only by `meshcore migrate operator status|apply`; they never fall back
to the migrator's or the runtime's settings. The user is the database
operator, a superuser (or, on PostgreSQL 16 and later, a `CREATEROLE` role
with the limits in the deployment guide), never a MeshTransit role
([deployment](deployment.md#migrations-and-operator-steps)).

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_OPERATOR_POSTGRES_ADDRESS` | required | address | Database endpoint |
| `MESHTRANSIT_OPERATOR_POSTGRES_DATABASE` | required | name | Database |
| `MESHTRANSIT_OPERATOR_POSTGRES_USER` | required | name | Operator role |
| `MESHTRANSIT_OPERATOR_POSTGRES_PASSWORD_FILE` | required | path | Its password |
| `MESHTRANSIT_OPERATOR_POSTGRES_CA_FILE` | required | path | CA bundle |
| `MESHTRANSIT_OPERATOR_CONNECT_TIMEOUT` | `5s` | 100ms–30s | |
| `MESHTRANSIT_OPERATOR_LOCK_TIMEOUT` | `5s` | 100ms–30s, below the statement timeout | |
| `MESHTRANSIT_OPERATOR_STATEMENT_TIMEOUT` | `30s` | 1s–10m | Applies to each statement of a step |

## Redis

For `api`, `control`, `worker` and `all`. The ACL the user needs is in
[deployment](deployment.md#redis).

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_REDIS_ADDRESS` | required | address | TLS endpoint |
| `MESHTRANSIT_REDIS_USERNAME` | required | name | ACL user |
| `MESHTRANSIT_REDIS_PASSWORD_FILE` | required | path | Its password |
| `MESHTRANSIT_REDIS_CA_FILE` | required | path | CA bundle |
| `MESHTRANSIT_REDIS_POOL_SIZE` | `10` | 1–50 | Active connections |

## Management API

For `api` and `all`.

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_API_ADDRESS` | `0.0.0.0:8444` | address | TLS listener |
| `MESHTRANSIT_API_TLS_CERTIFICATE_FILE` | required | path | Certificate chain |
| `MESHTRANSIT_API_TLS_PRIVATE_KEY_FILE` | required | path | TLS key (may be the control role's TLS key) |
| `MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_ID`, `…_FILE` | required | key ID, path | HMAC key for Account Session digests |
| `MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_PREVIOUS_KEY_ID`, `…_FILE` | unset | both or neither | The previous key, during rotation |
| `MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_ID`, `…_FILE` | required | key ID, path | HMAC key for idempotency keys |
| `MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_ID`, `…_FILE` | required | key ID, path | HMAC key for rate-limit subjects |
| `MESHTRANSIT_API_TRUSTED_PROXY_CIDRS` | empty | CIDR list | Proxies whose `X-Forwarded-For` is believed |
| `MESHTRANSIT_API_SOURCE_RATE_LIMIT_CAPACITY` | `30` | 1–100000 | Requests per source address, burst |
| `MESHTRANSIT_API_SOURCE_RATE_LIMIT_REFILL_INTERVAL` | `1s` | 10ms–1h, whole ms | One request back per interval |
| `MESHTRANSIT_API_SESSION_RATE_LIMIT_CAPACITY` | `60` | 1–100000 | Requests per Account Session, burst |
| `MESHTRANSIT_API_SESSION_RATE_LIMIT_REFILL_INTERVAL` | `500ms` | 10ms–1h, whole ms | |
| `MESHTRANSIT_API_REQUEST_TIMEOUT` | `10s` | 100ms–30s | Whole-request deadline |
| `MESHTRANSIT_API_MAX_CONNECTIONS` | `256` | 1–4096 | TLS connections |
| `MESHTRANSIT_API_MAX_CONCURRENT_REQUESTS` | `128` | 1 to the connection limit | Requests served at once |

### Console login and browser registration

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_PRIVATE_LOGIN_CONFIG_FILE` | off | path; `api` and `all` only | The Console login profile (below) |
| `MESHTRANSIT_BROWSER_REGISTRATION_ORIGIN` | unset | `https://host`, no port or path | Origin of the approval pages |
| `MESHTRANSIT_BROWSER_REGISTRATION_DEPLOYMENT_ID` | unset | UUIDv7 | Deployment named in approval tokens |
| `MESHTRANSIT_BROWSER_REGISTRATION_RECOVERY_EPOCH` | unset | integer > 0 | Recovery epoch bound into tokens |
| `MESHTRANSIT_BROWSER_REGISTRATION_KEY_ID`, `…_KEY_FILE` | unset | key ID; padded base64 key | HMAC key for approval tokens |

The five browser registration variables go together, on `api`, `control` and
`all`; on `api` they need the Console login, and the origin, deployment ID and
recovery epoch must equal the login profile's (checked when serving, not by
`config validate`).

The **Console login profile** is a JSON file of at most 16 KiB, with one of
the private-key modes. Version 4 (current) holds: the listener `address`
(loopback, private or unspecified) and public `origin` (https, a host name
distinct from the issuer's), `trusted_proxy_prefixes` (1–16 private or
loopback prefixes), the deployment, provider and client identifiers and
generations, the recovery epoch, the OIDC issuer and endpoints, the client ID
and redirect, the connector and scopes, the TLS certificate and key files,
the client secret file, and the purpose keys (`initiation`, `capture`,
`continuation`, `management_csrf`, `transaction_digest`,
`verifier_encryption`, `subject_active`, optionally `subject_previous`,
`provider_session`), each as `{id, file}`. Unknown, duplicate or null fields
are refused. The scopes must include `email` for invitations to work: an
invitation is accepted only when the ID token carries a verified email
(`email_verified` as a JSON `true`) equal to the invited address. Profiles
before version 3 have no scopes field and request `openid federated:id` only,
so their sign-ins cannot accept invitations. The profile's scopes must also
equal the client's stored `allowed_scopes` exactly, or every sign-in is
refused: change both together, never only the profile.

### Self sign-up, entitlement, mail

For `api` and `all`, with the Console login.

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_SELF_SIGNUP_ENABLED` | off | bool | First sign-in without an invitation creates an Account and Workspace (Cloud with an entitlement only) |
| `MESHTRANSIT_SELF_SIGNUP_SOURCE_DAILY_LIMIT` | `5` | 1–1000 | Sign-ups per source network per day |
| `MESHTRANSIT_SELF_SIGNUP_HOURLY_LIMIT` | `30` | 1–100000 | Sign-ups per deployment per hour |
| `MESHTRANSIT_ENTITLEMENT_DEPLOYMENT_PUBLIC_ID` | unset | UUIDv7 | Deployment the entitlement names |
| `MESHTRANSIT_DEPLOYMENT_ENTITLEMENT_FILE` | unset | path, one line, at most 4 KiB | Signed entitlement |
| `MESHTRANSIT_DEPLOYMENT_INSTALLATION_KEY_FILE` | unset | private identity key | Installation key |
| `MESHTRANSIT_MAIL_TRANSPORT` | off (invitations are not emailed) | `ses`, `smtp` | Mail transport |
| `MESHTRANSIT_MAIL_FROM` | required with a transport | address | From |
| `MESHTRANSIT_MAIL_TIMEOUT` | `15s` | 1s–1m | Send timeout |
| `MESHTRANSIT_MAIL_SES_REGION`, `…_SES_ACCESS_KEY_ID_FILE`, `…_SES_SECRET_ACCESS_KEY_FILE`, `…_SES_CONFIGURATION_SET` | required for `ses` (configuration set optional) | | Amazon SES |
| `MESHTRANSIT_MAIL_SMTP_HOST`, `…_SMTP_PORT`, `…_SMTP_TLS` (`tls`, `starttls`) | required for `smtp` | | SMTP server |
| `MESHTRANSIT_MAIL_SMTP_USERNAME`, `…_SMTP_PASSWORD_FILE` | optional, together | | SMTP authentication |

The sign-up limits are allowed only with sign-up on; the three entitlement
variables go together; mail variables are refused without a transport, and
SES and SMTP variables exclude each other.

### Private Interchange command

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_INTERCHANGE_CORE_URL` | unset | `https://host[:port]` | Control URL in the relay start command the Console shows |
| `MESHTRANSIT_INTERCHANGE_RELAY_SIGNING_KEYS` | unset | 1–4 `mtsign:` keys | Signing keys in that command |

The two go together.

## Identity broker

For `identity` and `all`, in a build with the `dexbroker` tag. Its secret
files must all differ, and from every Core secret; its database and user must
differ from Core's on the same server.

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_IDENTITY_ISSUER` | required | https URL, no trailing slash | Broker issuer |
| `MESHTRANSIT_IDENTITY_CONFIGURATION_FINGERPRINT` | required | `sha256-v2:` + 64 hex | Approved configuration digest, from `meshcore identity fingerprint` |
| `MESHTRANSIT_IDENTITY_ADDRESS` | required | private, loopback or unspecified IP:port | Listener |
| `MESHTRANSIT_IDENTITY_TLS_CERTIFICATE_FILE`, `…_TLS_PRIVATE_KEY_FILE` | required | paths | TLS |
| `MESHTRANSIT_IDENTITY_REQUEST_TIMEOUT` | `15s` | 1s–30s | |
| `MESHTRANSIT_IDENTITY_MAX_CONNECTIONS` | `256` | 1–4096 | |
| `MESHTRANSIT_IDENTITY_MAX_CONCURRENT_REQUESTS` | `128` | 1 to the connection limit | |
| `MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ID`, `…_DISPLAY_NAME`, `…_GENERATION` | required | | The upstream connector |
| `MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ISSUER` | required | exactly `https://accounts.google.com` | Upstream provider |
| `MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_ID`, `…_CLIENT_SECRET_FILE` | required | secret ≥ 32 bytes | Upstream client |
| `MESHTRANSIT_IDENTITY_CORE_CLIENT_ID`, `…_DISPLAY_NAME`, `…_GENERATION`, `…_SECRET_FILE`, `…_REDIRECT_URI` | required | secret ≥ 32 bytes; https redirect | Core as the broker's client |
| `MESHTRANSIT_IDENTITY_POSTGRES_ADDRESS`, `…_DATABASE`, `…_RUNTIME_USER`, `…_RUNTIME_PASSWORD_FILE`, `…_CA_FILE` | required | | The broker's own database |
| `MESHTRANSIT_IDENTITY_POSTGRES_MAX_OPEN_CONNECTIONS` | `10` | 1–50 | |
| `MESHTRANSIT_IDENTITY_POSTGRES_MAX_IDLE_CONNECTIONS` | `5` | 1 to the open limit | |
| `MESHTRANSIT_IDENTITY_POSTGRES_CONNECT_TIMEOUT` | `1s` | 1s–30s, at most the dependency check timeout | |
| `MESHTRANSIT_IDENTITY_POSTGRES_CONNECTION_LIFETIME` | `30m` | 1m–24h | |
| `MESHTRANSIT_IDENTITY_ID_TOKEN_LIFETIME` | `5m` | 1m–1h | |
| `MESHTRANSIT_IDENTITY_AUTH_REQUEST_LIFETIME` | `5m` | 1m–30m | |
| `MESHTRANSIT_IDENTITY_SIGNING_KEY_ROTATION` | `6h` | 1h–30d | How often the broker rotates its token signing key |
| `MESHTRANSIT_IDENTITY_GARBAGE_COLLECTION_INTERVAL` | `5m` | 1m–1h | |

## Control

For `control` and `all`.

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_CONTROL_ADDRESS` | `0.0.0.0:8443` | address | TLS listener for MTCP and `/relay/v1/` |
| `MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE`, `…_TLS_PRIVATE_KEY_FILE` | required | paths | TLS |
| `MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE` | required | secret, `privkey:` + hex | MTCP control key |
| `MESHTRANSIT_CONTROL_NOISE_NEXT_PRIVATE_KEY_FILE` | unset | secret | The next control key, during rotation |
| `MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER` | required | RFC 3339, in the future, at most 5 years ahead | Expiry announced for the control key |
| `MESHTRANSIT_CONTROL_MTCP_NEXT_KEY_NOT_AFTER` | required with the next key | as above | Expiry of the next key |
| `MESHTRANSIT_CONTROL_MAX_SESSIONS` | `1024` | 1–16384 | Sessions per process |
| `MESHTRANSIT_CONTROL_HANDSHAKE_TIMEOUT` | `5s` | 100ms–30s | TLS and request header deadline |
| `MESHTRANSIT_CONTROL_READ_IDLE_TIMEOUT` | `1m` | 100ms–5m | Idle timeout before a connection becomes MTCP |
| `MESHTRANSIT_CONTROL_DRAIN_WINDOW` | `30s` | 0–5m | Spread of reconnects at shutdown |
| `MESHTRANSIT_CONTROL_REBALANCE` | `true` | bool | Shed sessions above the fair share |
| `MESHTRANSIT_CONTROL_REBALANCE_INTERVAL` | `15s` | 1s–5m | Load publication and rebalancing period |
| `MESHTRANSIT_CONTROL_MTCP_TRUSTED_PROXY_CIDRS` | empty | CIDR list | Proxies whose client address is believed for admission |
| `MESHTRANSIT_CONTROL_MTCP_DENIED_ENDPOINT_CIDRS` | empty | CIDR list, no `/0`, no IPv4-mapped | Prefixes dropped from endpoint reports |
| `MESHTRANSIT_CONTROL_MTCP_HANDSHAKE_RATE` | `10` | 1–10000 | Handshakes per second per source |
| `MESHTRANSIT_CONTROL_MTCP_HANDSHAKE_BURST` | `max(50, rate)` | 1–100000, at least the rate | Handshake burst |
| `MESHTRANSIT_CONTROL_MTCP_UNAUTHENTICATED_PER_SOURCE` | `min(burst + 10 × rate, 10000)` | 1–10000 | Connections per source before a map |
| `MESHTRANSIT_CONTROL_MTCP_UNPROVEN_SESSION_LIFETIME` | `15m` | 11m–24h | Closes sessions that never prove a Device |
| `MESHTRANSIT_CONTROL_MTCP_ENABLED` | absent | if set, `true` | Kept for old deployments |

`MESHTRANSIT_CONTROL_MAX_STREAMS_PER_SESSION`, `…_PING_TIMEOUT` and
`…_WRITE_TIMEOUT` belong to the retired protocol and are refused.

### Maps

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_CONTROL_MAP_PEER_LIMIT` | `10000` | 100–10000 | Peers per map |
| `MESHTRANSIT_CONTROL_MAP_ENDPOINT_ANNOUNCE_INTERVAL` | 5 s (at most half the presence TTL, at least 1 s) | 1s–30s, below the TTL | Spacing of endpoint changes to peers |
| `MESHTRANSIT_CONTROL_MAP_RECONCILE_INTERVAL` | `30s` | 1s–5m | Periodic reread from PostgreSQL |
| `MESHTRANSIT_CONTROL_MAP_KEEPALIVE_INTERVAL` | `30s` | 1s–90s | Stream keepalive |
| `MESHTRANSIT_CONTROL_MAP_PRESENCE_TTL` | `30s` | 3s–5m | Lifetime of presence and endpoints in Redis |
| `MESHTRANSIT_CONTROL_MAP_COORDINATION_TIMEOUT` | `2s` | 100ms–30s, below a third of the TTL | Redis deadline |
| `MESHTRANSIT_CONTROL_MAP_REQUEST_TIMEOUT` | `10s` | 100ms–1m | Deadline to build a snapshot |
| `MESHTRANSIT_CONTROL_MAP_STATEMENT_TIMEOUT` | `3s` | 1ms–1m | PostgreSQL statement deadline |
| `MESHTRANSIT_CONTROL_MAP_TRANSACTION_IDLE_LIMIT` | `5s` | 1ms–1m | Idle-in-transaction limit |
| `MESHTRANSIT_CONTROL_MAP_INVENTORY_STATEMENT_TIMEOUT` | `30s` | 1ms–1m | Network inventory read |
| `MESHTRANSIT_CONTROL_MAP_SHARE_STATEMENT_TIMEOUT` | `10s` | 1ms–1m | Share read |
| `MESHTRANSIT_CONTROL_MAP_SHARED_INVENTORY` | `true` | bool | One inventory read per Network, shared by its sessions |
| `MESHTRANSIT_CONTROL_MAP_SHARED_CONNECTIVITY` | `true` | bool | One connectivity table per replica |
| `MESHTRANSIT_DEVICE_ALIASES_ENABLED` | `false` | bool | Offer Device alias peers ([sharing](../concepts/sharing.md#turning-it-on)) |
| `MESHTRANSIT_SUBNET_ROUTES_ENABLED` | `false` | bool | Accept Access Rules to Sites ([policy](../concepts/policy.md#rules-to-sites)). Set it the same on every role, only once every replica runs a Core that knows Site rules, and do not turn it off while the active policy holds them |

### Relays

A control role needs a relay source: the relay authority with a relay map, or
a static relay directory file.

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_RELAY_AUTHORITY_ENABLED` | `false` | bool, `control` and `all` | Serve `/relay/v1/` and sign relay documents |
| `MESHTRANSIT_RELAY_SIGNING_KEY_FILE` | required when enabled | private identity key | Ed25519 signing key |
| `MESHTRANSIT_RELAY_NEXT_SIGNING_KEY_FILE` | unset | private identity key | Next signing key, published before use |
| `MESHTRANSIT_RELAY_MAP_FILE`, `MESHTRANSIT_RELAY_MAP_SHA256` | unset; together | path (at most 256 KiB, not group- or world-writable), `sha256:` + hex | The relay map and its pinned digest |
| `MESHTRANSIT_RELAY_DRAIN` | unset | up to 64 `mtrelay:` keys | Relays told to drain |
| `MESHTRANSIT_RELAY_TRUSTED_PROXY_CIDRS` | empty | CIDR list | Proxies for relay document rate limits |
| `MESHTRANSIT_RELAY_DEPLOYMENT_PUBLIC_ID` | unset | UUIDv7; needs the map | Turns on relay tickets |
| `MESHTRANSIT_RELAY_TICKET_ZONES_V2` | `false` | bool; needs the deployment ID | Tickets with up to 16,384 zones (MTT2) |
| `MESHTRANSIT_RELAY_DIRECTORY_FILE`, `MESHTRANSIT_RELAY_DIRECTORY_SHA256` | unset; together | path, `sha256:` + hex | Static relay directory, ignored when the authority has a map |

With the authority disabled, its other variables are refused.

### Registration

| Variable | Default | Allowed | Meaning |
|---|---|---|---|
| `MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID`, `…_FILE` | required | key ID, HMAC key | Digest key for enrollment keys |
| `MESHTRANSIT_ENROLLMENT_DIGEST_PREVIOUS_KEY_ID`, `…_FILE` | unset; together | | Previous key, during rotation |
| `MESHTRANSIT_REGISTRATION_MAX_ATTEMPTS` | `5` | 1–5 | Transaction attempts |
| `MESHTRANSIT_REGISTRATION_PENDING_TTL` | `10m` | 1s–24h | Lifetime of a pending registration |
| `MESHTRANSIT_REGISTRATION_STATEMENT_TIMEOUT` | `5s` | 1ms–1m | |
| `MESHTRANSIT_REGISTRATION_LOCK_TIMEOUT` | `3s` | 1ms–30s, at most the statement timeout | |
| `MESHTRANSIT_REGISTRATION_IDLE_TIMEOUT` | `10s` | 1ms–1m | |
| `MESHTRANSIT_REGISTRATION_ROLLBACK_TIMEOUT` | `1s` | 1ms–5s, at most the shutdown timeout | |
| `MESHTRANSIT_REGISTRATION_RETRY_INITIAL` | `10ms` | 1ms–1m | |
| `MESHTRANSIT_REGISTRATION_RETRY_MAXIMUM` | `500ms` | the initial delay to 1m | |
| `MESHTRANSIT_REGISTRATION_ADDRESS_CANDIDATE_LIMIT` | `256` | 1–65536 | Addresses tried per allocation |

The `api` role reads the two digest key settings too, when set, to issue
enrollment keys; it ignores the registration settings. Give it the same
keys as `control`. Without them, enrollment key endpoints answer
`temporarily_unavailable`.

## Worker

For `worker` and `all`. The revision dispatcher always runs:

| Variable | Default | Allowed |
|---|---|---|
| `MESHTRANSIT_NETWORK_REVISION_BATCH_SIZE` | `32` | 1–256 |
| `MESHTRANSIT_NETWORK_REVISION_LEASE` | `1m` | 1s–5m, above batch × 3 × operation timeout |
| `MESHTRANSIT_NETWORK_REVISION_POLL_INTERVAL` | `200ms` | 100ms–1m |
| `MESHTRANSIT_NETWORK_REVISION_RETRY_DELAY` | `5s` | 100ms–24h |
| `MESHTRANSIT_NETWORK_REVISION_OPERATION_TIMEOUT` | `500ms` | 100ms–30s |

The other jobs are off by default. Each is turned on with its `…_ENABLED`
variable and needs the deployment ID; while it is off, its other variables
must be absent.

| Job | Variables (defaults) |
|---|---|
| Access ledger | `MESHTRANSIT_ACCESS_LEDGER_WORKER_ENABLED`, `…_DEPLOYMENT_PUBLIC_ID`, `…_BATCH_SIZE` (16, 1–64), `…_POLL_INTERVAL` (3s), `…_PRUNE_INTERVAL` (1h), `…_OPERATION_TIMEOUT` (25s) |
| Enforcement ledger | `MESHTRANSIT_ENFORCEMENT_LEDGER_WORKER_ENABLED`, `…_DEPLOYMENT_PUBLIC_ID`, `…_POLL_INTERVAL` (15s), `…_PRUNE_INTERVAL` (1h), `…_OPERATION_TIMEOUT` (10s) |
| Trust Contract expiry | `MESHTRANSIT_CONTRACT_EXPIRY_WORKER_ENABLED`, `…_DEPLOYMENT_PUBLIC_ID`, `…_BATCH_SIZE` (16, 1–128), `…_POLL_INTERVAL` (2s), `…_OPERATION_TIMEOUT` (10s); the same settings run the worker that ends shares of removed provider Devices (metrics `meshtransit_contract_device_removal_worker_*`, needs operator step 000178) and the worker that retires their unused Resources (metrics `meshtransit_resource_retirement_worker_*`; `blocked_total` counts Resources still in use, `deferred_total` failures) |
| Device alias | `MESHTRANSIT_DEVICE_ALIAS_WORKER_ENABLED`, `MESHTRANSIT_DEVICE_ALIAS_DEPLOYMENT_PUBLIC_ID`, `…_WORKER_BATCH_SIZE` (8, 1–128), `…_WORKER_POLL_INTERVAL` (500ms), `…_WORKER_OPERATION_TIMEOUT` (10s) |
| Private endpoint | `MESHTRANSIT_PRIVATE_ENDPOINT_WORKER_ENABLED`, `…_DEPLOYMENT_PUBLIC_ID`, `…_RECONCILER_ID`, `…_BATCH_SIZE` (8), `…_POLL_INTERVAL` (1s), `…_OPERATION_TIMEOUT` (5s), `…_INITIAL_RETRY_DELAY` (1s), `…_MAXIMUM_RETRY_DELAY` (1m), `…_AGENT_ORIGIN`, `…_AGENT_CA_FILE`, `…_AGENT_CERTIFICATE_FILE`, `…_AGENT_PRIVATE_KEY_FILE` |
| Browser login expiry | `MESHTRANSIT_AUTH_EXPIRY_ENABLED`, `…_DEPLOYMENT_PUBLIC_ID`, `…_BATCH_SIZE` (8), `…_POLL_INTERVAL` (1s), `…_SWEEP_TIMEOUT` (10s), `…_UNIT_TIMEOUT` (1s, at most the sweep), `…_ROLLBACK_TIMEOUT` (1s); needs a shutdown timeout above max(2s, rollback) + 1s |

The Device alias worker and the private endpoint worker cannot run together.

## Required per role

| Role | Required |
|---|---|
| `api` | PostgreSQL with the runtime user; Redis; API TLS; the Account Session, idempotency and rate-limit keys. The Console login for the Console, mail, sign-up, browser registration and bootstrap |
| `control` | PostgreSQL with the runtime user; Redis; control TLS; the control key and its expiry; the enrollment digest key; a relay source |
| `worker` | PostgreSQL with the worker user; Redis |
| `identity` | Every identity variable without a default, and a `dexbroker` build |
| `all` | All of the above |
| `relay` | Nothing |

## Common errors

Since the log does not show which variable failed, check these first:

- **A feature is off but one of its variables is set**, often left empty by
  a template: workers, relay authority, mail, sign-up.
- **An incomplete group:** browser registration (5 variables), entitlement
  (3), the Interchange command (2), a previous key ID without its file, a map
  without its digest, a next control key without its expiry, SMTP user without
  password.
- **The wrong role:** the Console login, mail, sign-up and entitlement are for
  `api`; the relay authority for `control`; workers for `worker`.
- **Order between values:** a check timeout above the interval, a lock
  timeout above the statement timeout, a handshake burst below the rate, a
  concurrency above the connection limit, a coordination timeout above a
  third of the presence TTL.
- **No relay source** on a control role: check the relay authority and map,
  or `MESHTRANSIT_RELAY_DIRECTORY_FILE`.
- **The control key's expiry** is past, or more than five years ahead.
- **The same file used for two secrets**, or two equal key IDs.
- **`all` without the identity broker**: every identity variable without a
  default is required, and a build without `dexbroker` fails after
  configuration.

## meshrelay

Every flag can also be set as `MESHRELAY_<FLAG>` (upper case, `-` as `_`);
the flag wins. See [Relay](../architecture/relay.md).

| Flag | Default | Meaning |
|---|---|---|
| `--key-file` | required | Relay key from `meshrelay genkey --out <file>`; refused if it has any group or other permission (inside `$CREDENTIALS_DIRECTORY`, group read is allowed) |
| `--trusted-signing-keys` | required | Comma-separated `mtsign:` keys of Core; with `--core-url` they only bootstrap trust |
| `--core-url` | unset | `https://host[:port]` of Core's control role, for relay state |
| `--private-interchange` | `false` | Serve only the Networks Core grants this relay; needs `--core-url` |
| `--udp` | `0.0.0.0:3479` | MTRP over UDP |
| `--udp-readers` | `4` | 1–64 |
| `--stun`, `--stun-alt` | `0.0.0.0:3478`, `0.0.0.0:3480` | STUN; empty turns off |
| `--public-ip`, `--public-ipv6` | unset | Public addresses, for the NAT classification attributes |
| `--tls` | off | TLS and WebSocket listener |
| `--tls-cert`, `--tls-key` | unset | PEM files, reloaded when they change |
| `--acme-host`, `--acme-cache`, `--acme-email` | unset | Let's Encrypt with TLS-ALPN-01 on the TLS port |
| `--tls-self-signed` | `false` | For labs |
| `--tls-max-conns`, `--tls-max-conns-per-ip` | `10000`, `64` | TLS connection limits (IPv6 per /64) |
| `--network-bandwidth-mbit` | `500` | 1–100000; per-Network forwarding budget |
| `--admin` | `127.0.0.1:9479` | Metrics and health |
| `--drain-timeout` | `5s` | Time sessions get to move at shutdown |
| `--log-level` | `info` | |

With `--tls`, exactly one certificate source is allowed.

## meshd and meshnetd

`meshd` flags (no environment variables):

| Flag | Default | Meaning |
|---|---|---|
| `--socket` | per platform ([Client](../architecture/client.md#local-api-and-meshctl)) | Local API socket or pipe |
| `--netadmin-socket` | `/run/meshnetd/meshnetd.sock` (macOS `/var/run/…`) | Socket of `meshnetd` |
| `--state-dir` | `/var/lib/meshd`; macOS `/Library/Application Support/MeshTransit/state`; Windows `C:\ProgramData\MeshTransit\state` | State |
| `--identity-key-file` | `/run/credentials/meshd.service/meshd.identity-key` on Linux | Host key that encrypts the identity |
| `--enable-data-plane` | `false` | Run WireGuard; needs `--wireguard-listen-port` |
| `--wireguard-listen-port` | `0` | UDP port |
| `--enable-dns` | `false` | MeshTransit DNS |
| `--enable-device-aliases` | `false` | Device alias v1; needs the data plane |
| `--port-mapping` | `auto` | `auto` or `off` |
| `--cloud-metadata` | `auto` | `auto` or `off` |
| `--lazy-peers` | `auto` | `auto`, `off` or `always` |
| `--advertise-endpoint` | none | Repeatable, up to 16 global addresses on the listen port |
| `--allow-uid`, `--allow-socket-peers` | none, `false` | Who may use the local API |
| `--enable-flow-logs`, `--flow-log-url`, `--flow-log-interval`, `--flow-log-timeout` | off | Flow logs (not usable yet) |
| `--log-level` | `info` | |
| `--control-protocol` | `auto` | Kept for old units: `auto` or `mtcp` |

The packages run `meshd` with `--enable-data-plane --enable-dns
--enable-device-aliases --wireguard-listen-port=41641` (and
`--allow-socket-peers` on Linux and macOS).

`meshnetd` flags (root, Linux and macOS): `--allow-user` or `--allow-uid`
(exactly one), `--socket`, `--mtu` (1280, 1280–9000), `--enable-dns`,
`--dns-address` (`192.0.2.53`) and `--dns-port` (1053), `--allow-prefix`
(narrows `100.64.0.0/10`, `198.18.0.0/15`, `fd00::/8`); on Linux also
`--interface` (`mesh0`), `--dns-interface` (`meshdns0`) and
`--resolvectl-path`; on macOS `--scutil-path`.
