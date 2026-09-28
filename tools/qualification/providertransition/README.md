# Provider-client scope transition

`providertransition` is a one-shot qualification command for the first brokered
login rollout. It changes one exact managed OIDC client from `openid` to the
closed scope set `openid`, `federated:id` and advances the provider generation.
The old generation is superseded; provider, client, generation, immutable audit,
and deployment-scoped outbox evidence commit in one serializable transaction.

The command is intentionally not a general provider editor. The source and
target scope sets, event class, permission, and continuous-recovery transition
are fixed in code. Exact public IDs and expected row versions are required.

## Safety envelope

- Use a separately supplied qualification administrator credential. Runtime,
  worker, and migrator role names are rejected.
- PostgreSQL TLS with a supplied CA and SCRAM authentication is mandatory.
- `dry-run` validates the exact current state in a read-only transaction.
- `apply` additionally requires
  `MESHTRANSIT_QUALIFICATION_ENABLE_PROVIDER_TRANSITION=provider-client-scope-v1`.
- Set `MESHTRANSIT_QUALIFICATION_CONFIRM_PROVIDER_TRANSITION` to the exact
  `<deployment-id>/<provider-id>/<client-id>` tuple for both modes.
- Standard output contains only public IDs, versions, generations, and scope
  names. Failures are redacted on standard error.

Database connection settings are read from:

- `MESHTRANSIT_POSTGRES_ADDRESS`
- `MESHTRANSIT_POSTGRES_DATABASE`
- `MESHTRANSIT_POSTGRES_ADMIN_USER`
- `MESHTRANSIT_POSTGRES_ADMIN_PASSWORD_FILE`
- `MESHTRANSIT_POSTGRES_CA_FILE`

Run `dry-run` first with the exact current generation and row versions. Re-run
the same arguments with `--mode apply` only after the output matches the planned
transition. A successful apply returns the change, new generation, audit, and
outbox public IDs for operator evidence.
