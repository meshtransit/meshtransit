# Identity subject transition qualification

`identitysubjecttransition` validates one exact cross-provider identity-subject
transition plan against a serializable, read-only PostgreSQL snapshot. It is a
qualification tool, not a runtime API and not a mutation command.

The protected JSON manifest binds the migration, deployment, actor, source and
target providers, expected provider generations and versions, exact subject
mappings, and bounded Session/AuthTransaction counts. The file must be a local
regular file with mode `0400`, `0600`, `0440`, or `0640`, at most 64 KiB, and
must be supplied with its exact SHA-256. Source and target subject-key files use
the same custody rules and contain one unpadded base64url-encoded 256-bit key.

The tool rejects unknown or duplicate JSON names, noncanonical ordering,
incomplete active-subject coverage, stale versions, source digest mismatch,
target collisions in any state, and unexpected active Session or open
AuthTransaction counts. Output contains only public IDs, the manifest hash, and
counts. Raw issuer and subject values are never emitted.

The PostgreSQL credential must be a dedicated qualification administrator with
TLS `verify-full`, SCRAM-SHA-256, and read access to the exact authority tables.
Runtime, worker, and migrator role names are rejected. Every database operation
runs inside one `SERIALIZABLE READ ONLY` transaction with local timeouts.

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
  -manifest /run/qualification/identity-subject-transition.json \
  -expected-manifest-sha256 "$manifest_sha256" \
  -source-key-file /run/secrets/source-subject-key \
  -target-key-file /run/secrets/target-subject-key
```

A successful dry-run is evidence for one snapshot only. It is not a lease or
permission to mutate data. A later apply command must open a new transaction,
take the required maintenance fence, and revalidate every invariant.
