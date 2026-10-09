# Default Workspace and display identifiers

## Product contract

Cloud accounts receive one owned Workspace named `Default` at creation. The
creator can rename it and can own additional Workspaces. Self-hosted deployments
retain exactly one Workspace; invited accounts do not receive another Workspace
or inherit ownership. Public self-registration requires an explicit admission
policy and a separate verified provisioning path. Existing login rejects unknown
subjects and never grants entrypoint Workspace membership implicitly.

Workspace and Network have globally unique immutable twelve-digit display codes.
Codes are stored as strings, preserving leading zeros. Rename and suspension keep
the code. Soft-deleted identities retain their code, which is never reassigned.
The existing UUIDv7 IDs remain API paths, foreign keys and authorization identity.
Codes are labels, not credentials; knowing one never grants access.

## Display identity storage

Migration 77 stores display codes in an immutable sidecar with exact Workspace
or Network UUID foreign keys. It backfills existing identities without rewriting
tenant authority rows. New identity inserts reserve a random code atomically in
the same transaction. A unique index across both kinds rejects collisions; at
most eight allocation attempts are permitted. Deleted rows are not reused.

The runtime cannot enumerate or modify the sidecar directly. Console scope v2
adds labels only after the unchanged v1 authority projection has authorized the
current session and exact Workspace/Network pair. Legacy v1 readers remain
compatible. API display fields are additive and optional during rolling upgrades.

## Workspace rename

Migration 78 adds a separate owner-authorized rename operation. The runtime uses
an explicit READ WRITE transaction port; Session and scope resolution remain READ
ONLY. The operation locks the exact login Workspace, current SSO authority,
active membership and Deployment audit head before a fresh expiry decision.
Optimistic concurrency uses the projected version and strong `If-Match` header.
The name change, immutable audit event and outbox record commit together. Unknown
commit outcomes return no success and are never automatically retried.

Names are unique among active Workspaces owned by the same Principal in one
Deployment. Separate cloud owners can each use `Default`. This changes label
uniqueness only; UUIDs, display codes, membership and owner authority remain
unchanged. Self-hosted singleton enforcement remains authoritative.

Console scope v3 adds optional `version` and `can_rename` metadata after the
existing scope projection. The hint controls presentation, never mutation
permission. The form asks only for a name; Console supplies the observed version
and a fresh CSRF proof. A stale or uncertain response requires a fresh read.

## Delivery boundaries

Display-code delivery does not create accounts, alter ownership, enroll Devices,
or change packet policy. Workspace rename is delivered separately. Cloud Default Workspace provisioning
remains a separate verified, audited admission operation; unknown login subjects
continue to be rejected until that operation is implemented.
