# Qualification Network bootstrap

This operator utility creates a Network in a disposable qualification installation when a serving Network creation API is unavailable. It requires an existing active Workspace owner and current Workspace membership, and schema 87. It does not create users, Workspace memberships, RBAC grants, credentials, or packet allow rules.

The database operator must supply `MESHTRANSIT_QUALIFICATION_DSN` through a protected environment. The utility requires a database superuser because fixture creation spans FORCE RLS authority tables. Never provide this login to a serving process. It does not change roles, grants, RLS, or authentication configuration.

Build the utility for the database operator host architecture. Supply `--deployment-id`, `--workspace-id`, `--owner-id`, `--name`, `--ipv4-prefix`, and `--ipv6-prefix`. Prefixes must be canonical, fit exactly one active Workspace overlay pool, and satisfy the database exclusion constraints.

Without `--apply`, the utility constructs the complete transaction, appends canonical audit and outbox evidence, validates deferred constraints, and rolls back. PostgreSQL sequences can advance during this check. With `--apply`, it commits the same transaction. Execution is bounded to 20 seconds; lock waits and statements have shorter deadlines.

The transaction creates a Network and revision, two prefixes, the existing owner's Network membership, a persistent interactive enrollment profile with a one-hour node lifetime, and a Network audit stream. New Networks have no published allow policy. Confirm fail-closed behavior with a real client before introducing test rules.

A commit error can have an unknown outcome. Reconcile the Network by its unique name before another apply attempt. This is a qualification fixture tool, not a production provisioning interface.
