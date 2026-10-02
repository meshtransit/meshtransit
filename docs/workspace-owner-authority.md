# Workspace owner authority

## Product decision

The human who owns a Workspace administers its Networks and their resources
without manually assigning or renewing individual Network roles. Invited
members receive only explicitly delegated permissions. This implements the
WorkspaceOwner semantics in the canonical administrative authorization model.

Ownership is identified by the stable Core Principal in
`mesh.workspace.owner_principal_id`. Email addresses and identity-provider
claims never establish ownership. Creating an Account does not establish
ownership of any existing Workspace.

## Durable authorization

Migration 76 adds `mesh_ops.resolve_network_permission_v2`. It first checks
current ownership and locks the authenticated Account Session, Deployment,
Principal, Account, identity subject, provider/client, active Workspace,
Network, current Workspace membership and exact catalog permission.

The owner decision covers every known permission whose approved target scope
includes Network, for every active Network in that exact Workspace. It grants
no Deployment permission and never broadens an operation's Workspace/Network
pair. Account/session expiry, recovery quarantine, suspension and membership
revocation still deny access. Ownership has no separate role expiry.

Owner evidence records `workspace_owner_authority_generation`; role identities
and role generations are absent. The existing resolver v1 remains the exact
Network authority path for members. Partial or mixed owner/role evidence is
rejected. Writes retain their existing transaction, revision, immutable audit
and outbox requirements. Ownership changes take effect on the next operation
and cannot race an operation holding the Workspace authorization lock.

The Console projects the ten permissions implemented by its current Network
features for an owner. This projection only controls UI availability; every
read, preview and mutation authorizes again on the server. Ownership of a
Workspace automatically covers a Network subsequently created inside it.

## Separate admission and packet policy

Owner administration does not add users to another Workspace, invent Network
membership, enroll a Device, or change a packet rule. Device login continues
to require its existing exact Workspace/Network enrollment authority. The
same-Workspace/same-Network boundary and explicit Resource sharing remain.

Workspace signup/provisioning and the two invitation flows must persist the
creator as owner plus active membership in their audited creation transaction.
The existing browser SSO path authenticates provisioned identities; migration
76 does not claim to add public signup or invitation APIs. Workspace lifecycle
APIs must use Workspace target permissions when they are implemented; this
Network resolver cannot authorize Workspace deletion or owner transfer.

## Qualification

- PostgreSQL contract covers every Network catalog permission with the
  owner's explicit RoleBindings suspended, two Networks, Console projection,
  mismatched Workspace/Network, ordinary members, unknown/Deployment permissions
  and loss of implicit authority after ownership transfer.
- Existing member-only tests use an independent Workspace owner so tests for
  role revocation, expiry and bounded delegation remain meaningful.
- Adapter and Device authorization tests reject absent, mixed and malformed
  evidence. Policy publication records owner generation in immutable evidence
  without invented RoleBinding/RoleDefinition identifiers.

Released migrations 1–75 remain byte-for-byte unchanged. Older binaries keep
their existing role resolver; rollout of the new binary is required for owner
management writes. No packet policy revision is changed by this migration.
