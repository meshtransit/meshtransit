# Device sharing database deployment gate

Schema version alone does not establish the serving function profile. Migrations
create the functions, while operator scripts transfer ownership to dedicated
NOLOGIN/NOBYPASSRLS roles and grant only supported entry points. The PostgreSQL
integration fixture runs those scripts explicitly. Deployment must do the same.

Before enabling sharing, run `scripts/qualification/check-device-sharing-database.sql`
as the database operator with `psql -X -v ON_ERROR_STOP=1 -f`. This gate reads only
catalog metadata and the schema version. It checks current and supported rollback
entry points, closed legacy/internal entry points, dedicated ownership, fixed
search paths, role confinement, forced RLS and absence of runtime table writes.
It does not disclose credentials, Device keys, offer tokens or row payloads.

For a schema87 deployment missing the older sharing operator steps, prepare a
single transaction from the repository's canonical operator sources:

```sh
python3 scripts/qualification/prepare-device-sharing-operator-repair.py --output /tmp/device-sharing-operator-repair.sql
psql -X -v ON_ERROR_STOP=1 -f /tmp/device-sharing-operator-repair.sql
psql -X -v ON_ERROR_STOP=1 -f scripts/qualification/check-device-sharing-database.sql
```

The operator supplies normal connection settings outside these files. The
prepared transaction does not create roles, grant role membership, alter schema,
change RLS policies or update application rows. It applies the existing ownership
scripts in order, including later closures of legacy functions, and executes the
full gate before committing. Any assertion failure rolls back all metadata changes.

The migration integration suite runs the exact deployable gate, proves that a
missing runtime create-offer grant fails it, rolls back the negative fixture, and
checks that the gate passes again. A green unit suite cannot replace this gate.
Browser creation/acceptance and actual client packets remain separate required
qualification evidence before sharing is reported complete.
