# Management Account Session qualification fixture

This command creates a short-lived Account Session and the minimum
`device.manage` RBAC authority needed to qualify the management API in a
pristine, self-hosted test deployment.

It is not a login implementation. It does not contact, replace, or bypass the
production Keycloak/OIDC SSO flow. The synthetic identity uses an unreachable
`.example` issuer and an ephemeral digest key that is discarded immediately,
so it cannot be used to authenticate through OIDC. The command is kept below
`tools/qualification` and must not be copied into the MeshCore runtime image.

Safety properties:

- requires a database owner/admin role and rejects runtime, worker, and
  migrator roles;
- requires exact Deployment, Workspace, Network, and Principal public IDs in
  both flags and `MESHTRANSIT_QUALIFICATION_CONFIRM_AUTH_SCOPE`;
- requires `MESHTRANSIT_QUALIFICATION_ENABLE_SYNTHETIC_IDENTITY=qualification-only`;
- accepts a lifetime from one to fifteen whole minutes;
- refuses any deployment that already contains Account, identity-provider,
  Account Session, Workspace membership, or management-RBAC authority;
- inserts identity, session, RBAC, audit, and outbox rows atomically under one
  UUIDv7 authority change ID;
- writes the bearer once to a new absolute path with mode `0600`; the bearer is
  never written to stdout, stderr, logs, or command arguments.

Supply PostgreSQL TLS/admin settings and the same active Account Session digest
key ID/file used by MeshCore. Pass `-h` locally to inspect the bounded flags.
Delete the bearer file immediately after the qualification request. The
fixture's durable authority evidence remains immutable and the short-lived
session, membership, and binding become unusable after their common expiry.
