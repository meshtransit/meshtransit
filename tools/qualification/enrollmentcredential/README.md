# Enrollment credential qualification tool

`enrollmentcredential` issues one short-lived, single-use enrollment credential
for a disposable self-hosted MeshTransit Network. It exists only to qualify the
registration and control path before the versioned management API exposes
credential issuance.

The command is not built into the `meshcore` image and is not a management RBAC
bypass for production. It writes the bearer presentation exactly once to a new
private file and stores only the production HMAC digest in PostgreSQL.

Safety controls:

- exact Deployment, Workspace, Network, Enrollment Profile, and issuer IDs;
- an exact confirmation environment value plus a separate qualification-only enable value;
- active, verified `self_hosted` deployment and active same-scope authority;
- active persistent Profile with an exact bounded one-use policy;
- refusal while another credential for the Profile is still usable;
- one-to-fifteen-minute whole-second lifetime;
- TLS, SCRAM-SHA-256, one connection, and bounded operation/transaction timeouts;
- bearer output created with `O_EXCL` and mode `0600`, never overwritten;
- credential insert, mutation ledger, audit, and outbox evidence committed atomically;
- generic stderr and bounded JSON stdout without bearer, digest, fingerprint, or file path.

Example with synthetic identifiers:

```sh
export MESHTRANSIT_QUALIFICATION_CONFIRM_ENROLLMENT_SCOPE=01890f00-0000-7000-8000-000000000001/01890f00-0000-7000-8000-000000000101/01890f00-0000-7000-8000-000000000201/01890f00-0000-7000-8000-000000000601/01890f00-0000-7000-8000-000000000011
export MESHTRANSIT_QUALIFICATION_ENABLE_ENROLLMENT_ISSUE=qualification-only
export MESHTRANSIT_POSTGRES_ADDRESS=database.example:5432
export MESHTRANSIT_POSTGRES_DATABASE=meshtransit
export MESHTRANSIT_POSTGRES_ADMIN_USER=meshcore
export MESHTRANSIT_POSTGRES_ADMIN_PASSWORD_FILE=/run/secrets/postgres-password
export MESHTRANSIT_POSTGRES_CA_FILE=/run/trust/postgres-ca.pem
export MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID=enrollment-v1
export MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_FILE=/run/secrets/enrollment-digest-key

go run ./tools/qualification/enrollmentcredential \
  -deployment-id 01890f00-0000-7000-8000-000000000001 \
  -workspace-id 01890f00-0000-7000-8000-000000000101 \
  -network-id 01890f00-0000-7000-8000-000000000201 \
  -profile-id 01890f00-0000-7000-8000-000000000601 \
  -issuer-principal-id 01890f00-0000-7000-8000-000000000011 \
  -token-output-file /run/private/enrollment-credential \
  -expires-in 10m \
  -audit-reason 'disposable two-node registration qualification'
```

The command does not advance the Network revision because issuing a credential
does not change any active client projection. A failed or uncertain commit
removes the staged bearer file; the possibly committed credential then remains
unusable by the caller and expires within the configured short lifetime.

For a disposable database-host qualification only, the tool also supports the
exact Unix socket `/var/run/postgresql`. This mode must run inside the PostgreSQL
container, requires
`MESHTRANSIT_QUALIFICATION_CONFIRM_LOCAL_POSTGRES=database-container-local-only`,
accepts only the `meshcore` role, and rejects network address, password-file,
and CA settings. It never disables TLS for a network connection.
