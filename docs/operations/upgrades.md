# Upgrades

How to move a deployment to a new Core or relay release, and back.

## The rules that make it safe

- **Migrations only go forward.** There are no down migrations. Every applied
  migration is recorded with its checksum; an applied migration is never
  edited or reordered.
- **A release works on the next release's schema.** Migrations expand first
  (new tables, columns, functions), and only a later release removes what an
  older release still uses. So after migrating, the previous binary still
  runs: **a rollback is a binary rollback.**
- **Core checks the schema before serving.** At start, and at every
  dependency check, a Core process requires a clean migration state and a
  continuous, successful history whose checksums match its own catalog, at
  least up to the newest migration the binary knows. A schema newer than the
  binary is accepted. A schema **older** than the binary, a failed or dirty
  migration, or a changed checksum is refused: a process that starts on it
  exits with an error, and a running process reports PostgreSQL unavailable
  and stops being ready. So migrate before rolling out a new binary; replicas
  of the new release stay down until the migration has run.

`meshcore migrate status` prints the schema version, the newest version the
binary knows and the state (`uninitialized`, `pending` or `clean`) as JSON.

## Upgrading Core

1. **Read the release notes** for operator steps and feature gates.
2. **Back up** the database.
3. **Create new roles:** run any new `…_role.sql` operator file before the
   migration of the same number.
4. **Migrate:** run `meshcore migrate up` with the new binary and the
   migrator's settings. All pending migrations apply in one transaction (the
   statement timeout, 30 s by default, applies to each statement); it takes an
   advisory lock, so a second runner waits. Old replicas keep serving on the
   new schema; replicas of the new release refuse to start until this step
   has finished.
5. **Roll out** the new binary, role by role. Any order works, since old and
   new binaries run on the new schema.
6. **Run the new `…_ownership.sql` operator files**, as a database superuser,
   once no replica of the previous release is left: those of migrations 53 to
   93 revoke the previous version of a function, which the previous binary
   still calls ([deployment](deployment.md#migrations-and-operator-steps)).
   Later ones keep previous versions executable.

During the rollout:

- A control replica that stops sends each of its nodes a `RECONNECT` with a
  random delay within the drain window (`MESHTRANSIT_CONTROL_DRAIN_WINDOW`,
  30 s by default), so the nodes spread over the other replicas instead of
  arriving at once. Give the process at least that long to stop
  (`MESHTRANSIT_SHUTDOWN_TIMEOUT`, and the orchestrator's grace period).
- Nodes keep their tunnels while they reconnect: the data plane does not
  depend on the control session.
- Once the new replicas run, rebalancing (on by default) evens out sessions
  within a few intervals.

A Helm hook or a job can run step 3 before the rollout; the migrator's
credentials should be available to that job only.

## Rolling back

Deploy the previous binary. It runs on the migrated schema. Do not try to
undo migrations.

If step 6 has run for migrations 53 to 93, the previous binary may lack
`EXECUTE` on function versions an ownership file revoked, so features that use them (sharing,
Device aliases) fail on it. Grant those versions back to `mesh_runtime` or
`mesh_worker` for the rollback, or roll back before step 6.

`meshcore migrate` from an older binary refuses a schema newer than it knows;
that is expected after a rollback, since there is nothing for it to apply.

## Feature gates

Some changes need every component to be ready before they are turned on:

- `MESHTRANSIT_RELAY_TICKET_ZONES_V2=true` only after every relay in the map
  accepts tickets with zone frames (MTT2).
- `MESHTRANSIT_DEVICE_ALIASES_ENABLED=true` only after the operator steps of
  the [Device sharing deployment gate](../core/design/device-sharing-deployment-gate.md).
- Settings of the retired control protocol
  (`MESHTRANSIT_CONTROL_MAX_STREAMS_PER_SESSION`, `…_PING_TIMEOUT`,
  `…_WRITE_TIMEOUT`) now stop Core from starting; remove them.

Core does not yet enforce a minimum client version.

## Changes that take effect with the binary

Some changes are made by the new binary, not by the migration, and need no
operator step:

- **Enforced guardrails cut existing shares** (schemas 164 and 167). Maps
  built by the new binary leave out every existing share an enforce-mode
  guardrail blocks. The migration advances no revision: an old binary would
  rebuild the same maps, and the new one reaches every map anyway. Its
  rollout reconnects the nodes of each control replica it replaces, and every
  map stream rereads PostgreSQL at the reconcile interval
  (`MESHTRANSIT_CONTROL_MAP_RECONCILE_INTERVAL`, 30 s by default), which
  rebuilds the map of every Device that takes part in a share. So within one
  interval of the last control replica running the new binary, shares that
  existing guardrails block are gone from every map. Until then, the previous
  binary keeps them, as it did before the upgrade.
- **Do not change enforce-mode guardrails while binaries from before and
  after schema 167 run together**, during a rollout or a rollback. A share
  change made by an older binary does not take the Workspace's guardrail
  state lock, so a guardrail saved at the same time can miss it: the share
  stays in maps until the next reconcile interval, or longer with an older
  binary building the map. Save guardrails before the rollout starts or
  after every API and control replica runs the same binary.

## Relays

Replace relay nodes one at a time. On `SIGTERM` a relay stops admitting
sessions and tells its sessions to move within its drain timeout (5 s); nodes
use another node or region meanwhile. To move clients off a relay before
stopping it, add its key to `MESHTRANSIT_RELAY_DRAIN` on Core and restart the
control replicas.

A relay's own key stays the same across upgrades. Changing it, or its
address, means a new relay map revision ([deployment](deployment.md#relays)).

## The identity broker

The broker is pinned to one reviewed upstream version with a fixed set of
patches. Upgrading it is a separate, qualified change: see
`core/third_party/dex/v2.45.1/README.md`. Its runtime never migrates its own
database and requires the exact schema level it was built for, so the broker's
database must be migrated with the qualified procedure before the new image
runs.
