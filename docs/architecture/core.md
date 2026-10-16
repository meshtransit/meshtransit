# Core

MeshTransit Core is the control plane. It holds the authority over who exists
and who may reach whom, and tells every node what it needs to know. It never
carries data-plane traffic. Code: `core/` (AGPL-3.0); entry point
`core/cmd/meshcore`, wiring in `core/cmd/meshcore/serve.go`.

## Process and roles

One binary, `meshcore`, runs one role per process, chosen with
`MESHTRANSIT_ROLE`. The default, `all`, runs every role in one process; it
includes `identity`, so it needs the identity broker's build and
configuration. Deployments run the roles as separate processes.

| Role | Starts | Needs |
|---|---|---|
| `api` | Management API (TLS, default `:8444`); optionally the Console's private surface (login, cookie session, Console API) | PostgreSQL, Redis |
| `control` | Client-control listener (TLS, default `:8443`): [MTCP](../protocol/mtcp-v1.md) and, when enabled, the relay authority under `/relay/v1/`; wakeup feeds; session rebalancing. Nodes connect on HTTPS port 443, so a load balancer or ingress forwards 443 to it | PostgreSQL, Redis |
| `worker` | Background work (below) | PostgreSQL, Redis |
| `identity` | Embedded OIDC identity broker (a build with the `dexbroker` tag, image `core/Dockerfile.dexbroker`) | Its own PostgreSQL database |
| `relay` | Health and metrics only; packets are relayed by `meshrelay` ([Relay](relay.md)) | nothing |

Every role also serves an operator listener (default `127.0.0.1:8081`) with
`/live`, `/ready`, `/health` and `/metrics`; the control role adds
`/scale/v1/sessions` for autoscaling. Readiness reports each dependency of the
role.

Other subcommands: `config validate` (checks configuration and files without
serving), `migrate status` and `migrate up`, `bootstrap check` and
`bootstrap apply` (install an initial plan of Accounts and Workspaces), and
`identity fingerprint`.

Replicas of every role are stateless: all authority is in PostgreSQL, all
shared session state in Redis, so any replica can be replaced at any time.

## PostgreSQL: the authority

PostgreSQL is the only source of truth for tenancy, Devices, keys, addresses,
policy, sharing and audit.

- **Schemas:** `mesh` (domain data), `mesh_ops` (revisions, outbox,
  idempotency, migration state, read functions), `mesh_audit` (sealed audit
  events, partitioned by month).
- **Database roles:** the `api` and `control` roles connect as `mesh_runtime`,
  `worker` as `mesh_worker`; migrations run as `mesh_migrator`. Further
  NOLOGIN roles own the functions that read or write sensitive views, so a
  runtime connection gets exactly the access a function grants.
- **Row-level security** is forced on tenant tables. A transaction sets its
  exact Workspace and Network scope, and policies check every row against it.
- **Every change** to authority writes its audit event (see
  [audit records](../protocol/audit-record-v2.md)) and an outbox event in the
  same transaction, and advances the Network's revision when it changes what
  nodes see.

### Time

The PostgreSQL clock is the single source of truth for every time Core
persists or compares with persisted state: creation, update, withdrawal and
revocation times, expiry, leases, quarantine, idempotency windows, the
instant an authorization is evaluated at and the order of state transitions.
A store reads `transaction_timestamp()` inside the transaction that decides,
and every statement of that unit of work uses that one instant; durations
(a lifetime, a time to live) are added to it. That instant is when the
transaction started, not when a statement runs: a decision is taken as of the
start of its unit of work, and a write that would move `updated_at` before
the version it replaces keeps the previous time instead (Resource sharing
rows, schema 172), logging it to the server log (schema 173). Times SQL stamps itself use
the same clock. A retried attempt reads its own transaction's time.

Map streams measure a key or projection deadline from the database time of
the read that produced their map plus the time elapsed since on the host's
monotonic clock, so wall-clock skew does not move it.

A Core host's clock only bounds local timeouts, retry backoff and how long to
wait, and a few early checks that can only refuse (a session past its expiry
on the host clock is refused before any database work; the database decides
whether it is really live). Times signed for relays and nodes (relay state,
maps) are protocol times on the issuing host's clock, which relays and nodes
check against their own clocks within a stated skew.

Core samples the database clock at start and every minute and exports how
far the host's clock is from it ([monitoring](../operations/monitoring.md#clocks)).

### Migrations

Migrations are forward-only and embedded in the binary with a SHA-256 checksum
each. `meshcore migrate up` applies the pending ones under an advisory lock;
every process checks at start that the database's applied versions and
checksums match its catalog, and refuses to run otherwise. An applied
migration is therefore never edited, not even its comments. A migration must
keep the previous release working on the new schema, so a rollback is a
binary rollback. Ownership changes that need an operator run separately from
`core/migrations/operator/`, embedded in the binary, with
`meshcore migrate operator apply`; `meshcore migrate verify` checks that the
roles, owners and grants each step sets hold. An operator step may take only a function its own
migration creates for the first time away from `mesh_runtime` or
`mesh_worker`; the previous version stays executable until a later release
removes it. A test checks the operator steps for this. The steps of migrations 53 to 93 predate this rule and do
revoke previous versions, so a rollback across them needs those grants back
([upgrades](../operations/upgrades.md#rolling-back)). The `…_role.sql` steps
create their role only if it does not exist, so running one again is safe.

## Redis: shared session state

Redis holds what is short-lived and per session; it is never an authority.
Losing Redis ends map streams and slows convergence, but never widens access:
peers and packet filters always come from PostgreSQL.

| Key or channel | Holds |
|---|---|
| `meshtransit:v1:presence:node:<id>` | Which control replica serves a node, fenced by the node's session generation |
| `meshtransit:v1:endpoints:node:<id>` | The node's reported endpoints, disco key and preferred relay, with announce pacing |
| `meshtransit:v1:delivery:node:<id>`, `…:delivery:node:session:<key>` | What each node was sent and reports enforcing, its NAT and port-mapping state, path statistics (30-day TTL) |
| `meshtransit:v1:ratelimit:management:…` | Management API rate limits |
| `meshtransit:v1:control:replicas` | Session count of every control replica |
| `meshtransit:v1:wakeup:network_revision_advanced`, `…:connectivity_changed` | Pub/sub wakeups |

Core connects with TLS as its own ACL user. That user needs only the key
patterns above and the commands `GET`, `SET`, `DEL`, `EXISTS`, `PEXPIRE`,
`HGET`, `HSET`, `HMGET`, `HGETALL`, `HDEL`, `EVAL`, `EVALSHA`, `TIME`,
`PUBLISH`, `SUBSCRIBE` and `PING`.

## Control: maps for nodes

A node holds one MTCP session to one control replica: Noise IK from the node's
machine key to the Deployment's control key, over HTTP Upgrade or WebSocket.
On it the node registers, rotates keys and receives its **map**: itself, the
peers it may reach, its packet filter, DNS settings and the relay map
(mtcp-v1 §7).

- **Building a map.** The replica reads the node's view from PostgreSQL in one
  read-only, repeatable-read transaction through the `mesh_ops` map functions.
  A peer appears only if policy, or a share, lets the two Devices talk; the
  packet filter is reduced to the rules that concern the node.
- **Presence.** Before streaming, the replica takes the node's presence lease
  in Redis. A newer session generation wins; a lease moves between replicas
  at most 10 times a minute.
- **Keeping it current.** After a change commits, the worker publishes one
  wakeup per Network revision; every replica with a watcher in that Network
  rereads and sends a delta. Endpoint changes travel through the connectivity
  wakeup and reach peers at most once per announce interval (5 s by default).
  A periodic reconciliation (30 s by default) rereads PostgreSQL, so a lost
  wakeup only delays a change.
- **Flow control.** A node acknowledges maps; a replica keeps at most 8
  unacknowledged messages and coalesces further changes into the next delta.
  A node that leaves the window full for too long loses its stream and
  reconnects.
- **Session limits.** Each session has budgets for inbound messages and
  bytes, registrations, resyncs and enforcement reports; exceeding one ends
  the session with a retry time (mtcp-v1 §14).
- **Scale-out.** Each replica publishes its session count. A replica above
  the average by more than the tolerance asks some of its sessions to
  reconnect, which spreads them over the other replicas; it sheds in small
  steps, spares young sessions, and waits while the total is changing. This
  is on by default (`MESHTRANSIT_CONTROL_REBALANCE`). KEDA can scale the
  replica count from `/scale/v1/sessions`. On shutdown a replica spreads its
  sessions' reconnects over the drain window (30 s by default).

### Relay authority

When enabled on the control role, Core signs and serves, under `/relay/v1/`:

- the **relay map** that nodes receive in their maps;
- the **relay state** that relays poll: trusted signing keys, hashed
  revocations, the drain list;
- **grants** for Private Interchange relays;
- **relay tickets**, issued to nodes in their maps, valid for at most
  15 minutes and naming the node's zones (its Network and Trust Contracts).

Replicas produce identical signed documents, so any replica can answer.

## API

The `api` role serves two surfaces over the same domain services:

- the **management API** (`api/openapi/management_v1.json`), for tools, with
  an Account Session as a bearer token;
- the **Console's private API**, for the web Console only, with the Account
  Session in a host-only cookie and a CSRF header on every change; and the
  login flow under `/auth/v1/`.

People sign in through OIDC; the `identity` role can run an embedded broker
for that. Authorization is permission-based: a principal holds roles bound to
a Workspace or to one Network, and each operation needs an exact permission in
its exact scope. Mutations take an `Idempotency-Key` and an `If-Match`
revision, so retries are safe and concurrent edits do not overwrite each
other.

## Worker

| Job | Does |
|---|---|
| Revision dispatcher | Claims outbox events and publishes the revision wakeups |
| Audit partition maintainer | Creates monthly audit partitions ahead of time |
| Unrouted outbox retirer | Marks outbox events no consumer handles |
| Access ledger (opt-in) | Records each Network's effective access per revision as sealed audit events |
| Enforcement ledger (opt-in) | Records whether each Device enforces the rules it was sent |
| Trust Contract expiry (opt-in) | Finalizes expired contracts |
| Device alias worker (opt-in) | Advances the lifecycle of alias leases |
| Private endpoint worker (opt-in) | Applies Private Endpoint routes through a route agent |
| Browser login expiry (opt-in) | Expires abandoned browser logins |

Opt-in jobs are enabled one by one with their `…_ENABLED` setting; see the
configuration in [`core/README.md`](../../core/README.md).

## Keys Core holds

| Key | Use |
|---|---|
| Control key (`mtcontrol:`), current and next | MTCP responder key, pinned by nodes |
| Relay signing key (`mtsign:`), current and next | Signs relay maps, relay state, grants and tickets |
| Identity broker signing keys | OIDC tokens of the embedded broker; rotated automatically |
| TLS keys and HMAC keys | Listeners; digests of enrollment credentials, sessions and idempotency keys |

A current and a next key let the control and signing keys rotate without
breaking sessions: nodes and relays learn the next key before it is used.
