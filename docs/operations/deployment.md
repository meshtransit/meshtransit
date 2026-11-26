# Deployment

What a MeshTransit deployment needs and how to set it up: Core's processes,
PostgreSQL, Redis, TLS and ingress, the first data, and relays. Every setting
named here is described in [configuration](configuration.md); how the parts
fit is in [Core](../architecture/core.md) and [Relay](../architecture/relay.md).

## Processes

Run each Core role as its own process (container, pod or service), with as
many replicas as the load needs; they are stateless.

| Role | Replicas | Listens on | Reached by |
|---|---|---|---|
| `control` | 2 or more | `:8443` (MTCP, relay documents) | Nodes and relays, through HTTPS port 443 |
| `api` | 2 or more | `:8444` (management API); the Console login listener from its profile | The Console and tools |
| `worker` | 1 or more | — | — |
| `identity` | 2 or more, if the embedded broker is used | from `MESHTRANSIT_IDENTITY_ADDRESS` | The Console's sign-in, through `api` |
| `meshrelay` | at least one per region | UDP 3479, STUN 3478/3480, TLS 443 | Nodes |

Every Core process also has its operator listener (`/live`, `/ready`,
`/metrics`; [monitoring](monitoring.md)), on `127.0.0.1:8081` by default; in
a container set `MESHTRANSIT_HEALTH_ADDRESS=0.0.0.0:8081` and keep that port
private.

### Images

| Image | Built from | Contents |
|---|---|---|
| Core | `core/Dockerfile` (`make container-build`) | `/meshcore` on `scratch`, user 65532, CA bundle and licences; exposes 8081 and 8443 |
| Core with the identity broker | `core/Dockerfile.dexbroker` (`make container-push-dexbroker-multiarch`) | As above, built with the `dexbroker` tag; also exposes 9443 |
| Relay | `relay/Dockerfile` (`make container-push-relay-multiarch`) | `/meshrelay serve`, user 65532, with the file capability to bind port 443 |

Images run read-only, as their non-root user, with no capabilities. The relay
binary carries a file capability to bind port 443: keep `NET_BIND_SERVICE`
(`--cap-add=NET_BIND_SERVICE` after `--cap-drop=ALL`). File capabilities do
not apply under `no-new-privileges` or Kubernetes
`allowPrivilegeEscalation: false`; there, listen on a port above 1024 and map
443 to it.

## PostgreSQL

PostgreSQL 18 or later (Core uses `uuidv7()`), a primary (Core refuses a read-only connection), with
TLS and SCRAM-SHA-256 authentication. One database holds Core; the identity
broker, if used, has its own database.

### Before the first migration

As a superuser, create the login roles and the database, then the extension
inside that database. The NOLOGIN roles that own functions come from
`meshcore migrate operator apply` (next section); Core's serving roles never
create roles.

```sql
-- Login roles: give each its own password, stored in a file for Core.
-- The runtime and worker names are fixed: migrations grant to them.
CREATE ROLE mesh_migrator LOGIN PASSWORD '…';
CREATE ROLE mesh_runtime  LOGIN PASSWORD '…';
CREATE ROLE mesh_worker   LOGIN PASSWORD '…';
CREATE ROLE mesh_observer LOGIN;            -- reserved, no grants yet

CREATE DATABASE meshtransit OWNER mesh_migrator;
\connect meshtransit
CREATE EXTENSION IF NOT EXISTS btree_gist;  -- version 1.7 or 1.8
```

`mesh_observer` must be able to log in but has no password: make
`pg_hba.conf` reject it.

Every role must be `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
NOBYPASSRLS` (the defaults) and no role may be a member of another, except the
memberships the operator command keeps (below): the migrator checks this
before every run and refuses otherwise, and the serving roles' readiness
checks it again.

Role isolation: grants go to two NOLOGIN group roles,
`mesh_api_rights` and `mesh_control_rights`, and each serving login holds them
through membership (inherit only, never `SET` or `ADMIN`). The operator
command creates the groups and keeps the memberships; migrations need the
groups to exist, so it runs before `migrate up`:

| Login | Member of (kept by `migrate operator apply`) |
|---|---|
| `mesh_runtime` (api) | `mesh_api_rights` |
| `mesh_control` (control) | `mesh_control_rights` only (schema 300 and later; the operator removes a membership of `mesh_runtime` an older release left) |
| `mesh_all` (self-host, one process) | `mesh_api_rights`, `mesh_control_rights` (likewise) |

From schema 300 (role isolation S2.3) `mesh_runtime` holds nothing directly:
the api reaches exactly what `mesh_api_rights` holds, control what
`mesh_control_rights` holds, and no row-level security policy names
`mesh_runtime`. Operator step 300 takes the owner-held functions away from it.

A serving login outside its groups stays closed (readiness error
`postgres login lacks its group roles`). The operator keeps `mesh_control` and
`mesh_all` only when given their passwords
(`MESHTRANSIT_OPERATOR_LOGIN_PASSWORD_FILES`); it needs to be a superuser for
logins, and the `ADMIN` option on a group (or superuser) to add a membership.

| Role | Used by | Holds |
|---|---|---|
| `mesh_migrator` | `meshcore migrate` | Owns the database and every object migrations create |
| `mesh_runtime` | `api` (and `control` before role isolation) | Reads through row-level security and calls functions; owns nothing |
| `mesh_control`, `mesh_all` | `control`; self-host's one process | Logins of the operator command: privileges through the group roles |
| `mesh_worker` | `worker` | As above, plus outbox delivery |
| The NOLOGIN roles | — | Own the functions that need a particular privilege; runtime roles may only execute them |

For high availability, give Core a stable writer endpoint whose certificate
covers that name: every new connection must reach the primary, and readiness
drops a pool whose server became read-only.

### Migrations and operator steps

1. As the database operator, run `meshcore migrate operator apply` with the
   operator's settings (`MESHTRANSIT_OPERATOR_*`,
   [configuration](configuration.md#operator-steps)). On a new database it
   creates every NOLOGIN function owner (`mesh_audit_writer`,
   `mesh_share_writer` and the later ones); the migration refuses to run
   without them.
2. Run `meshcore migrate up` with the migrator's settings (`MESHTRANSIT_MIGRATION_*`).
   It applies every pending migration in one transaction, under an advisory
   lock, so concurrent runs serialize. Core refuses to start on a schema
   older than its binary, so run this before starting a new release. See
   [upgrades](upgrades.md).
3. Run `meshcore migrate operator apply --after-rollout` (on a fresh install
   no previous release runs), then `meshcore migrate verify`, which must exit 0.

On Kubernetes the chart can run step 3 itself (`operator.afterRollout`): a
post-install/post-upgrade Job first runs `meshcore install wait-rollout`,
which lists the release's pods and ReplicaSets (a token that may only list
them) and waits until every pod whose container serves Core
(`MESHTRANSIT_ROLE` api, control, worker or all) runs this release's image
for its component (compared by digest), none is shutting down, no
ReplicaSet with another image has a replica, and no component this release
removed has a pod left (`MESHTRANSIT_ROLLOUT_INSTANCE`,
`MESHTRANSIT_ROLLOUT_CHART`, `MESHTRANSIT_ROLLOUT_IMAGES` as
`component=image,…`, `MESHTRANSIT_ROLLOUT_TIMEOUT`, at most 30m). A passing
API error is retried; a denied one fails at once. A pod stuck terminating
holds the wait until it is removed. Run Helm with `--wait` and a
`--timeout` above the wait plus the Job's deadline, and not with
`--atomic`: once these steps ran, the previous release's code lacks grants
it needs, so rolling back to it is a forward fix instead.

The operator steps are the SQL files in `core/migrations/operator/`, embedded
in the binary. The command never runs a file from disk, nor a file's text:
it parses each file with a narrow grammar (whole-line `--` comments only;
`ALTER FUNCTION … OWNER TO`, `GRANT EXECUTE`, `REVOKE` on `mesh_ops`
functions; MeshTransit roles only) and runs the statements it rebuilds from
what it read:

- `…_role.sql` creates a NOLOGIN role and must run **before** the migration
  of the same number. It creates the role only if it is missing, and resets
  the attributes of an existing one to NOLOGIN and no other privilege, so it
  is safe to run again.
- `…_ownership.sql` moves the new functions to their owner role and grants
  `EXECUTE` to the runtime or worker role; it runs **after** its migration.
  Its first line, `-- operator-step: rollout=before` or `rollout=after`,
  says whether it may run while a replica of the previous release is left;
  those of migrations 53 to 93, 170 and 171 are `after`
  ([upgrades](upgrades.md)).

`meshcore migrate operator apply`:

- connects as the operator and is refused as the migrator, the runtime or
  worker role, any role the steps manage, a role that is neither a superuser
  nor `CREATEROLE`, or a role that may act as a MeshTransit role (a
  membership with `INHERIT` or `SET`);
- statements run with `MESHTRANSIT_OPERATOR_STATEMENT_TIMEOUT` applied to
  each statement of a step (not to the whole step or apply) and
  `MESHTRANSIT_OPERATOR_LOCK_TIMEOUT` to each lock wait; a timeout rolls back
  the whole apply;
- takes the migration lock, so it never runs during `meshcore migrate up`,
  and refuses a schema whose migration state is not clean;
- runs, in file order and in one transaction, every step that does not hold
  and, after the earliest such step, the steps after it again (each is
  idempotent), so a later step stays the last word;
- leaves a step whose migration is not applied, and with `--through N`
  refuses one up to migration `N`;
- leaves a step that waits for the rollout, and every ownership step after it, unless
  `--after-rollout` says no replica of the previous release is left;
- checks afterwards that every step it ran holds and that no step that held
  before stopped holding, and otherwise rolls everything back;
- with `--dry-run`, does all of this and rolls back.

It prints JSON: the steps it ran (`applied`), those it ran again
(`replayed`), those it left with the reason (`awaiting_migration`,
`after_rollout`, `after_earlier_step`, `beyond_through`) and those still
pending. `meshcore migrate operator status` lists every step and what is
missing, without changing anything (it runs in a transaction that always
rolls back, so it needs the primary, and it waits for an apply in progress
when the operator joins `mesh_migrator` to read the schema); it needs the operator's settings too,
while `meshcore migrate verify` gives the same report with the migrator's. A step holds when PostgreSQL shows what
its file sets: the role and its attributes, the owner of each function, and
which roles hold `EXECUTE` on it (a revoked role must not reach it through
PUBLIC or a membership either); nothing else records that a step ran, so
steps applied by hand count as well. `meshcore migrate verify` also reports
any role membership a MeshTransit role takes part in, since none is allowed.

**A superuser is the simplest operator; a managed service's administrator
also works.** An operator with `CREATEROLE` and `CREATEDB` (such as
`doadmin`, `rds_superuser` or `cloudsqlsuperuser`) runs every step when the
MeshTransit roles are its own (it created them, so PostgreSQL gives it an
`ADMIN`-only grant on each, which the command does not count as a
membership):

- `meshcore install bootstrap postgres` ([configuration](configuration.md#database-bootstrap)) creates the logins, the group
  roles and the databases, and gives the operator `CONNECT` on the Core
  database (the migrations take it from `PUBLIC`);
- inside its own transaction the command joins the migrator and each owner
  role (`INHERIT`, `SET`) and gives the owner roles `CREATE` on the schemas,
  which PostgreSQL requires to hand a function over unless the operator is a
  superuser; it takes all of it back before it commits;
- it removes the memberships `createrole_self_grant` adds for the roles it
  creates, and never names `SUPERUSER`, `REPLICATION` or `BYPASSRLS` to a role
  that does not have them (PostgreSQL refuses that to a non-superuser).

`core/scripts/ci/run-managed-postgres.sh` checks the whole chain this way on
PostgreSQL 18, for `createrole_self_grant` empty and `set,inherit`.

Without the command, run the files with `psql -X -v ON_ERROR_STOP=1 -f` as a
database superuser, in file order, at the same points (a `…_role.sql` file
before its migration, an `…_ownership.sql` file after it), then check with
`meshcore migrate verify`.

Some features use the functions these steps grant, and fall back to earlier,
smaller limits without them (for example sharing; see the
[Device sharing deployment gate](../core/design/device-sharing-deployment-gate.md)).
`meshtransit_postgres_function_version` shows the version each path uses.

## Redis

Redis with TLS (`--tls-port`; client certificates are not needed) and ACLs
with key selectors and channel rules (7.0 or later; the integration tests use
Redis 8).

Each serving role has its own Redis user with only what its code sends
(role isolation): `mesh_api`, `mesh_control`, `mesh_worker`, and
`mesh_all` for a process that runs every role. The rules are generated from the
code; print them with:

```
meshcore redis acl rules api|control|worker|all
```

Keep the users with `meshcore redis acl apply`, run as a Redis administrator
(a user that may run `ACL`), which no serving role ever gets:

- `MESHTRANSIT_REDIS_ADDRESS`, `MESHTRANSIT_REDIS_CA_FILE`;
- `MESHTRANSIT_REDIS_ADMIN_USERNAME`, `MESHTRANSIT_REDIS_ADMIN_PASSWORD_FILE`;
- `MESHTRANSIT_REDIS_ACL_PASSWORD_FILES`, for example
  `api=/run/secrets/redis-api,control=/run/secrets/redis-control,worker=/run/secrets/redis-worker`
  (each password 32–256 printable characters, no spaces);
- `MESHTRANSIT_REDIS_ACL_ROTATE=true` only to replace a password on purpose:
  without it a user whose stored password differs is refused, since running
  pods still use the stored one.

The command stores each password only as its SHA-256 (the password never
reaches Redis), resets each user to exactly its rules, then runs `ACL SAVE` and
checks each user with `ACL DRYRUN`. Redis must run with an `aclfile` it can
write (not a read-only mount): otherwise the command fails, since a restart
would lose the users. Each role then sets `MESHTRANSIT_REDIS_USERNAME` to its
user and `MESHTRANSIT_REDIS_PASSWORD_FILE` to its password.

Read-only paths run their scripts with `EVALSHA_RO`, so a user written by hand
for an older Core also needs `+evalsha_ro +eval_ro` before this Core starts.

Turn the `default` user off. Core uses a single Redis node (no Cluster or
Sentinel). Redis holds only short-lived state and needs no persistence for
correctness, but a restart loses the 30-day delivery and enforcement records.
Set `maxmemory-policy noeviction`, with enough memory for the delivery records
(kept 30 days): presence, rate-limit and Kubernetes gateway contest keys must
never be evicted under pressure. An evicted or flushed gateway contest key lets
a holder of a copied gateway Secret rotate the gateway's keys sooner. The
Kubernetes CA restore marks (`~meshtransit:v1:kubeca:*`) carry a TTL too: an
evicted mark hides a database restore from the tripwire until it is seen
again. Core
cannot check the policy itself (its user has no `CONFIG` or `INFO`).

While Core replicas of two versions run side by side during an upgrade, a
replica without the gateway presence checks protects gateway key rotation only
within itself.

## TLS

- The `control`, `api` and `identity` listeners each need a certificate and
  key (`…_TLS_CERTIFICATE_FILE`, `…_TLS_PRIVATE_KEY_FILE`). Core reads them at
  start; a new certificate needs a restart.
- Connections to PostgreSQL and Redis are always TLS, verified against the
  configured CA bundle and the host name.
- Nodes do not trust the control role's certificate for authentication: they
  pin Core's MTCP control key. The certificate still must be valid for the
  host nodes connect to.

## Ingress

Nodes connect to `https://<control host>:443`. Put a load balancer or ingress
in front of the control role that:

- passes HTTP Upgrade (`Upgrade: mtcp/1` on `POST /mtcp/v1`), or at least
  WebSocket (`/mtcp/v1/ws`); nodes fall back to WebSocket themselves;
- passes the headers `MTCP-Key` and `MTCP-Handshake`;
- keeps idle connections open longer than 75 seconds;
- also routes `/mtcp/v1/key` and `/relay/v1/` to the control role.

The Console and tools reach the `api` role. The Console's host, which is also
the browser registration origin, reaches the `api` role's Console login
listener: it serves `/auth/v1/`, the Console API and the Device approval
pages `/register/v1/`. The identity broker is reached only through the
sign-in flow.

Keep idle timeouts on the path longer than the map keepalive
(`MESHTRANSIT_CONTROL_MAP_KEEPALIVE_INTERVAL`, 30 s) and the MTCP idle timeout
(75 s).

### Client addresses behind a proxy

Per-source limits count clients by address (an IPv4 address or an IPv6 /64).
Core takes the client from `X-Forwarded-For` only when the TCP peer is in the
role's trusted proxy list (`MESHTRANSIT_CONTROL_MTCP_TRUSTED_PROXY_CIDRS`,
`MESHTRANSIT_API_TRUSTED_PROXY_CIDRS`, `MESHTRANSIT_RELAY_TRUSTED_PROXY_CIDRS`,
and `trusted_proxy_prefixes` in the Console login profile), and then uses the
rightmost hop that is not itself a trusted proxy. From any other peer the
header is ignored. `Forwarded`, `X-Real-IP` and `CF-Connecting-IP` are never
read.

| In front of Core | Trusted proxies | Notes |
|---|---|---|
| Nothing | leave unset | The peer address is the client |
| nginx, Caddy, Traefik or HAProxy | the proxy's addresses | The proxy must terminate HTTP and append the client to `X-Forwarded-For` (nginx `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`, HAProxy `option forwardfor`). A TCP or TLS passthrough proxy cannot name the client, and the PROXY protocol is not supported |
| Cloudflare directly | Cloudflare's published ranges | Keep the list current |
| Cloudflare, then a proxy | the proxy only | The proxy restores the client from `CF-Connecting-IP`, trusting it only from Cloudflare's ranges, and forwards it in `X-Forwarded-For` |

Never trust a range ordinary clients connect from. A proxy missing from the
list does not break anything, but every client then shares its address;
Core counts such requests in `meshtransit_mtcp_untrusted_forwarding_total`.

Also list Core's own public addresses (load balancers) in
`MESHTRANSIT_CONTROL_MTCP_DENIED_ENDPOINT_CIDRS`, so no Device can make its
peers probe them.

## First data

- **Self-hosted:** create the deployment, the first Accounts and their
  Workspaces with `meshcore bootstrap check` (a dry run that rolls back) and
  then `meshcore bootstrap apply`. Running it again changes nothing. The plan
  (`MESHTRANSIT_BOOTSTRAP_PLAN_FILE`) is JSON:

  ```json
  {"format": "meshtransit-bootstrap/v1",
   "profile": "self_hosted",
   "accounts": [{"subject": "<OIDC subject>",
                 "display_name": "Ada Admin",
                 "workspace_name": "Example"}]}
  ```

  Up to 100 accounts, each with its `subject` or its `subject_digest`
  (computed with the Console login's active subject key); a self-hosted plan
  needs at least one. An optional `minimum_assurance` label (up to 255 characters) is
  set as the minimum sign-in assurance of the Workspaces it creates. Run bootstrap with `MESHTRANSIT_ROLE=api`, the full
  `api` configuration with the Console login, and the migrator's settings.
- **Cloud:** run bootstrap the same way with `"profile": "cloud"` (accounts may
  be empty) to create the deployment and its identity provider. Give the `api`
  role the signed entitlement (`MESHTRANSIT_DEPLOYMENT_ENTITLEMENT_FILE` with
  its deployment ID and installation key). Core verifies it at start and
  refuses one it does not trust; an expired entitlement keeps existing tenants
  working but blocks new Workspaces. With self sign-up on, people create their
  own Accounts.

Enable the worker jobs the deployment needs
([configuration](configuration.md#worker)), and Device aliases if Networks
will share Devices ([sharing](../concepts/sharing.md#turning-it-on)).

## Accounts

When an Account may be compromised, the operator acts on it by its principal
ID (the member ID the Console shows), with the migrator's settings like
`meshcore migrate`:

| Command | Effect |
|---|---|
| `meshcore account revoke-sessions <principal>` | Ends every Console session of the Account; the person can sign in again |
| `meshcore account quarantine <principal>` | Ends every session and refuses sign-in and every session until released |
| `meshcore account release <principal>` | Lets a quarantined Account sign in again |

Each prints the result as JSON and writes one audit event on the
deployment's stream, with no actor. None of them touches the Account's
Devices, enrollment keys, memberships or roles: suspend or remove the member,
or revoke the Devices, for that.

## Relays

On each relay host:

1. `meshrelay genkey --out /etc/meshrelay/relay.key` creates the key (mode
   0600) and prints its `mtrelay:` public key.
2. Open UDP 3479, 3478 and 3480 and TCP 443.
3. Run it, for example:

   ```
   meshrelay serve --key-file /etc/meshrelay/relay.key \
     --trusted-signing-keys mtsign:<Core's signing key> \
     --core-url https://control.example.com \
     --public-ip 192.0.2.10 \
     --tls 0.0.0.0:443 --acme-host relay-1.example.com \
     --acme-cache /var/lib/meshrelay/acme
   ```

   The key file may have no group or other permissions; under systemd it can
   come from `LoadCredential=`, where group read is allowed. Core's signing
   key in `mtsign:` form is the Ed25519 public key of
   `MESHTRANSIT_RELAY_SIGNING_KEY_FILE`; Core publishes it in the relay state
   at `/relay/v1/state`. There is no command that prints it yet: derive it
   from the seed offline, or read it from the relay state over a TLS
   connection you verify, since whatever you put here is trusted.

Then describe it in Core's **relay map** (`MESHTRANSIT_RELAY_MAP_FILE`, with
its digest in `MESHTRANSIT_RELAY_MAP_SHA256`):

```json
{"schema_version": 1, "revision": 1,
 "regions": [{"id": 1, "code": "ams", "name": "Amsterdam",
   "nodes": [{"name": "ams1", "host_name": "relay-1.example.com",
     "ipv4": "192.0.2.10", "key": "mtrelay:…",
     "udp_port": 3479, "tls_port": 443,
     "stun_port": 3478, "stun_alt_port": 3480, "weight": 100}]}]}
```

- Up to 128 regions of up to 16 nodes; region `code` is lowercase, at most 16
  characters. Each node needs IPv4 or IPv6, its key, the UDP and STUN ports.
- Increase `revision` on every change: nodes accept only a newer map.
- The file must not be group- or world-writable. Core reads it at start, so a
  change means a new file, a new digest and restarting the control replicas.
- Core signs the map for nodes and serves the relay state to relays; that
  needs `MESHTRANSIT_RELAY_AUTHORITY_ENABLED=true` with the signing key, and
  `MESHTRANSIT_RELAY_DEPLOYMENT_PUBLIC_ID` for relay tickets.

To take a relay out of service, add its key to `MESHTRANSIT_RELAY_DRAIN` and
restart the control replicas (Core reads it at start): its sessions move
elsewhere within its drain timeout.

## Identity broker

The embedded broker (`identity` role, `dexbroker` image) federates one upstream
OIDC provider, today Google. It needs its own PostgreSQL database and roles,
distinct from Core's, and a listener certificate whose only DNS name is the
issuer's host name, for server authentication. Its configuration is pinned by
`MESHTRANSIT_IDENTITY_CONFIGURATION_FINGERPRINT`: run
`meshcore identity fingerprint` with every identity setting except the
fingerprint, then set the result. Run it as its own `identity` processes: in an
`all` process a broker that fails to start stops the whole process. The pinned
broker version and how it is qualified are described in
`core/third_party/dex/v2.45.1/README.md`.
