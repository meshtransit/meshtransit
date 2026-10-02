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

## Delivery boundaries

Display-code delivery does not create accounts, alter ownership, enroll Devices,
or change packet policy. Default Workspace provisioning and rename must use
separate audited application operations with generation/ownership validation.
