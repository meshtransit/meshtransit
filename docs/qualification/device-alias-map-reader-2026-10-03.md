# Device alias map reader qualification

## Scope

Schema 83 provides client readiness and an authenticated alias projection reader.
Client readiness is independent of the legacy gateway route/DNS publication.
The ordinary runtime receives only EXECUTE on the bounded reader; its Device
inventory RLS remains unchanged. The isolated owner is NOLOGIN/NOBYPASSRLS and
has no role memberships. No worker writer or runtime feature activation is
introduced in this increment.

The reader requires current bilateral consent, exact Workspace/Network scope,
active contract/export/import/Resource/target, current consumer compiled policy,
current Device keys and sessions, client version claims, exact reserved leases,
explicit address families/pools, recovery epoch and finite typed readiness.
Foreign canonical addresses never appear in its peer projection. Caller remote
scope settings are discarded before authentication and restored on every exit.

Readiness pins immutable lease IDs, both Devices and authority generations.
Mutation capture and deferred constraints require the complete readiness batch,
matching revisions, audit and outbox in both Network scopes in the same
transaction. Missing-side or wrong-batch evidence is rejected. Readiness cannot
be deleted or renewed after withdrawal.

## Evidence

Disposable PostgreSQL 18.6 and Redis 8.8: clean migrations 1–83, race-enabled
`TestPostgreSQLMigrations`, uncached: PASS (32.222 seconds). The synthetic intent
is rolled back and does not alter a deployed database.

Covered: no readiness denies both sides; complete readiness projects both sides;
missing/wrong evidence fails; expired readiness, withdrawal, changed recovery,
policy, endpoint generation, peer session/key, compatibility claim, alias pool
and legacy-family ownership all deny. Malformed/foreign identity, wrong/missing
scope, invalid bounds and worker execution are rejected. Serving roles cannot
read or write readiness directly. Peer addresses match remote aliases and expiry
is later than evaluation. Ordinary Device inventory remains exactly scoped.

Qualification found and fixed the trigger's revision/alias-pool RLS scope:
revision validation runs under each exact Network and pool validation under the
derived Deployment, with caller settings restored. No migration-owner RLS was
broadened. Earlier migration-suite runs exposed clock-sensitive preexisting OIDC
fixture failures; no OIDC checks were weakened.

The client dataplane qualification is recorded separately in
`device-alias-stream-adapter-2026-10-03.md`. Live Core enrollment, guarded worker
publication, Redis wakeup latency and imported DNS remain separate required
gates before runtime activation.
