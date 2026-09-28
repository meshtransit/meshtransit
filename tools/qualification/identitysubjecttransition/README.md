# Identity subject transition qualification

`identitysubjecttransition` plans or atomically applies one exact
cross-provider identity-subject transition. It is an offline qualification
tool, not a runtime API.

The protected JSON manifest binds the migration, deployment, actor, source and
target providers, expected provider generations and versions, exact source and
target subject IDs, stable audit/outbox IDs, an operator reason, and bounded
Session/AuthTransaction counts. The file must be a local
regular file with mode `0400`, `0600`, `0440`, or `0640`, at most 64 KiB, and
must be supplied with its exact SHA-256. Source and target subject-key files use
the same custody rules and contain one unpadded base64url-encoded 256-bit key.

The tool rejects unknown or duplicate JSON names, noncanonical ordering,
incomplete active-subject coverage, stale versions, source digest mismatch,
target collisions in any state, and unexpected active Session or open
AuthTransaction counts. Output contains only public IDs, the manifest hash, and
counts. Raw issuer and subject values are never emitted.

The PostgreSQL credential must be a dedicated qualification administrator with
TLS `verify-full` and SCRAM-SHA-256. Runtime, worker, and migrator role names are
rejected. Plan mode uses one `SERIALIZABLE READ ONLY` transaction. Apply mode
uses one `SERIALIZABLE READ WRITE` transaction and requires authority-table and
audit append privileges.

Apply first locks the exact source-provider row, preventing new admitted login
transactions from crossing the transition. It then takes relation locks on the
subject, Session, and AuthTransaction tables and revalidates every plan
invariant. In the same transaction it suspends the source provider, unlinks
source subjects, inserts their target bindings, revokes every active source
Session, fails every pending or consuming source AuthTransaction, and appends
one canonical audit/outbox event. Exact mutation counts are verified before
commit. Any mismatch rolls back the complete transition.

The confirmation environment value is:

```text
<migration-id>/<deployment-id>/<source-provider-id>/<target-provider-id>/<manifest-sha256>
```

Example:

```sh
MESHTRANSIT_QUALIFICATION_CONFIRM_IDENTITY_SUBJECT_TRANSITION="$confirmation" \
MESHTRANSIT_POSTGRES_ADDRESS="database.example:5432" \
MESHTRANSIT_POSTGRES_DATABASE="meshtransit" \
MESHTRANSIT_POSTGRES_ADMIN_USER="qualification_admin" \
MESHTRANSIT_POSTGRES_ADMIN_PASSWORD_FILE="/run/secrets/qualification-password" \
MESHTRANSIT_POSTGRES_CA_FILE="/run/secrets/postgres-ca.pem" \
go run ./tools/qualification/identitysubjecttransition \
  -mode plan \
  -manifest /run/qualification/identity-subject-transition.json \
  -expected-manifest-sha256 "$manifest_sha256" \
  -source-key-file /run/secrets/source-subject-key \
  -target-key-file /run/secrets/target-subject-key
```

A successful plan is evidence for one snapshot only. It is not a lease or
permission to mutate data. Apply requires the same exact manifest and hash plus:

```text
MESHTRANSIT_QUALIFICATION_ENABLE_IDENTITY_SUBJECT_TRANSITION=identity-subject-transition-apply-v1
```

Run the command with `-mode apply`; it opens a new transaction, takes the
maintenance fence, and revalidates the complete plan. The manifest migration
ID is also the change and correlation ID. Do not blindly retry an ambiguous
commit response: verify the manifest's migration, audit-event, outbox-event,
and target-subject IDs first. A normal retry after a known committed apply is
rejected without mutation.
