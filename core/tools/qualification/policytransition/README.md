# Policy transition qualification tool

`policytransition` is a deliberately narrow acceptance-test tool for disposable
MeshTransit Networks. It publishes either a bidirectional ICMP allow release or
an empty deny release through the production policy publication application
service. The service preserves CAS, immutable release, Network revision, audit,
mutation-ledger, and outbox invariants.

The tool is not built into the `meshcore` image and is not a management API. It
must not be used as a human-login or RBAC bypass. Use it only with a dedicated
runtime database credential for a controlled qualification Network.

Safety controls:

- one exact Workspace and Network per invocation;
- an exact base policy revision is mandatory;
- `MESHTRANSIT_QUALIFICATION_CONFIRM_NETWORK_ID` must exactly equal the target
  Network public ID;
- TLS, SCRAM-SHA-256, a one-connection pool, and bounded operation timeouts;
- database passwords are accepted only through an absolute credential-file
  reference, never a flag or environment value;
- one release is published atomically or the previous active release remains;
- stdout contains only a bounded JSON result; internal errors and secrets are
  not printed.

Example with synthetic IDs:

```sh
export MESHTRANSIT_QUALIFICATION_CONFIRM_NETWORK_ID=01890f00-0000-7000-8000-000000000201
export MESHTRANSIT_POSTGRES_ADDRESS=database.example:5432
export MESHTRANSIT_POSTGRES_DATABASE=meshtransit
export MESHTRANSIT_POSTGRES_RUNTIME_USER=mesh_runtime
export MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE=/run/secrets/postgres-password
export MESHTRANSIT_POSTGRES_CA_FILE=/run/trust/postgres-ca.pem

go run ./tools/qualification/policytransition \
  --workspace-id 01890f00-0000-7000-8000-000000000101 \
  --network-id 01890f00-0000-7000-8000-000000000201 \
  --actor-principal-id 01890f00-0000-7000-8000-000000000011 \
  --base-policy-revision 1 \
  --mode bidirectional-icmp \
  --source-node-id 01890f00-0000-7000-8000-000000000701 \
  --destination-node-id 01890f00-0000-7000-8000-000000000702 \
  --audit-reason 'disposable two-node propagation qualification'
```

Publish a fresh deny release after the positive test. Never reuse a stale base
revision, and retain the JSON result with the client/source artifact digests in
the qualification evidence.
