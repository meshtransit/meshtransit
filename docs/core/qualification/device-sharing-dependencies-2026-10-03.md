# Device sharing dependency qualification

Schema 84 exposes a bounded authenticated refresh-scope reader owned by the
existing isolated NOLOGIN alias map reader. Runtime receives only EXECUTE.
Accepted activating/active contracts can return remote Workspace/Network scopes
before packet rules or client readiness exist. These scopes are wakeup hints;
they never add peers, routes or packet permission. PostgreSQL map readers retain
all live authority, policy and readiness checks.

The optional map path reads dependencies in the same read-only repeatable-read
transaction as ordinary and alias edges. It remains disabled by default. The
reader checks exact self keys and scope, accepted offer, contract/export/import,
Resource target, current authority generations and recovery. Caller-controlled
remote GUC values are cleared before authentication and restored on every exit.
Both contract and distinct Network bounds fail closed at 256.

Verification: full make quality passed. Disposable PostgreSQL 18.6/Redis 8.8
migrations 1–84 with uncached race integration passed in 38.057 seconds. Tests
compare exact public Workspace/Network pairs, deny wrong key pairs, stale
Resource/export/import, expired contracts, changed authority and recovery.
Before policy rules, both alias maps remain empty while dependencies exist.
Ordinary Device inventory remains scoped, including after poisoned GUC input.
Adapter tests cover optional activation, no foreign peers, malformed/duplicate/
self scopes and overflow with complete row/transaction cleanup.

Required next gates: guarded reservation/readiness worker, closed subscription
startup gap, explicit runtime composition, current client claim, live Core/SSO
client enrollment, encrypted isolation/withdrawal/reconnect tests and DNS.
No deployed POC database, membership or packet rule changed in this increment.

## Stream subscription catchup

Before releasing an initial sharing map, Core subscribes to every derived scope
and rereads PostgreSQL. A removed grant cannot escape through the initial map.
Changed scope sets are resubscribed with at most four attempts; read failure,
identity discontinuity or sustained churn releases no map or presence. Later
subscription replacements queue a complete authority reconciliation after the
new watches exist. Each replaced watcher is canceled, joined and released.

Uncached race-enabled map-session regression tests and package lint passed.
Tests cover removal between the first read and subscription without a Redis hint,
bounded scope churn, read failure, expiry after startup and lifecycle cleanup.
