# Device alias withdrawal qualification

Schema 86 adds no-grant worker operations using the existing isolated NOLOGIN
owner. Direct table, private proof and runtime grants stay closed. It does not
change released schema 85 or the live POC deployment.

Withdraw targets one consumer readiness; quarantine_consumer targets only that
consumer source alias pair; quarantine_resource targets only the Resource alias
pair and invalidates every dependent map. Calls pin public Deployment, endpoint
generation and exact consumer scope. Revocation does not depend on current keys
or positive authority: it remains usable after loss, revocation and expiry.

Every bounded operation locks sorted bilateral Network revisions, endpoint and
its lifecycle rows, then audit heads last. Mutation, both revisions and exact
bilateral audit/outbox evidence commit together. Canonical evidence binds the
specific action, kind and actual mutation batch. Quarantined leases retain their
owner slots and cannot be reused or renewed. Quarantine covers the latest of
clock, lease and endpoint expiry plus 24 hours. Readiness withdrawal is terminal
for that endpoint/consumer slot; policy denial alone must not call this terminal
operation, since live map readers already enforce policy narrowing.

Uncached race PostgreSQL 18.6 migrations 1–86 passed in 33.416 seconds. Actual
mesh_worker tests cover all three commands, missing evidence rejection, exclusive
expiry, empty-map removal, idempotent replay and quarantine lifetime. The fixture
contains two consumers: quarantining the selected pair preserves the other pair
and Resource aliases. Adapter race tests and normal/integration package lint
passed, including rejected action confusion, no-key revocation and cancellation
immediately after a successful commit. Successful commit is reported accurately;
uncertain commit still cannot trigger an internal retry.

Automatic candidate selection, runtime loop/composition, successor admission,
client capability advertisement and genuine Core/client qualification remain
activation gates. No terminal lifecycle operation is automatically enabled yet.
