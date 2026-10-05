# ADR-050: Cloud deployment profile, Workspace lifecycle and built-in Workspace roles

- Status: Accepted by the product owner on 2026-10-05
- Date: 2026-10-05
- Supersedes: nothing. Implements ADR-013 (Cloud many Workspaces) and the
  Cloud half of core-docs/29. Builds on ADR-022 (administrative RBAC).

## Context

MeshTransit is built Cloud first. Core today runs only `self_hosted`:

- `CapabilityService` and `read_console_deployment_capabilities_v1` accept only
  the tuple `self_hosted / single / max 1 / bootstrap_only`; any other profile
  fails closed ("Cloud remains unsupported until signed entitlement authority is
  implemented").
- No code creates a Deployment or a Workspace outside test fixtures. Private
  login names one `workspace_id`; the Account Session is bound to one
  `login_workspace_id`, which scopes reads, rename, approvals and registration.
- There is no `workspace.create` permission, no Workspace list/create API, and
  no Workspace switcher. Workspace authority is the single
  `workspace.owner_principal_id`; no built-in role definition is seeded, so
  members only receive ad hoc custom roles.
- Core sharing already supports `cross_workspace` (bilateral consent, Private
  Endpoint, alias realm, per-Network alias uniqueness). The Console rejects it.
- The database has no single-Workspace constraint; the limit lives only in the
  capability code and the login configuration.

core-docs/29 specifies Cloud enforcement (signed entitlement, activation slots,
`WorkspaceLimitGuard`, quarantine) but leaves the product surface open: the
Cloud capability tuple, the entitlement transport and grace policy, who may
create a Workspace, signup, Workspace switching, and quotas. This ADR closes
those gaps for a first Cloud release.

## Decisions

### D1. Signed Deployment Entitlement

- An Ed25519-signed JSON envelope issued by the MeshTransit deployment
  authority, with claims: format version, entitlement ID, Deployment public ID,
  installation public-key fingerprint, profile, `max_active_workspaces`,
  `max_owned_workspaces_per_account`, capability set, generation, issued,
  not-before, expiry, grace period, signer key ID.
- Core embeds the allowlisted public verification keys (key ID → key). Private
  signing keys stay in the issuance boundary (KMS/offline) and never enter an
  image, database, Console bundle, CI log or self-host package.
- Delivery: a mounted file (Kubernetes Secret) whose path is configuration. On
  startup and on change, Core verifies signature, key ID, algorithm, Deployment
  binding, installation-key proof, time and generation, then records the
  accepted generation through a narrow SECURITY DEFINER procedure into
  `mesh.deployment_entitlement`. A lower or equal generation with different
  content, a foreign Deployment or a failed proof is rejected; the previous
  verified generation stays current.
- Installation-key proof: the installation private key is held in a Kubernetes
  Secret for the first release (KMS-bound later, same interface); Core signs a
  fresh startup challenge and verifies it against the fingerprint in the
  entitlement. A copied entitlement without the key fails.
- Expiry: during the grace period everything works and capabilities report
  `entitlement_state=grace`. After grace, Workspace creation and Cloud-only
  capabilities fail closed with `deployment_entitlement_expired`; existing
  Workspaces, Devices and packet authority keep working. Tenants never lose
  connectivity because of a lapsed licence.
- Logs and APIs expose only entitlement ID, profile, generation, capability
  hash and state.

### D2. Profile and capability tuple

- Profile is fixed at bootstrap and immutable. `cloud` requires a verified
  entitlement whose profile is `cloud`; configuration alone never selects it.
- Cloud capabilities: `profile=cloud`, `workspace_mode=multi`,
  `max_active_workspaces=<entitlement>`, `workspace_creation=account`,
  `cloud_billing=false` (until billing exists), `platform_operations=false`,
  `entitlement_state=active|grace`, `revision=<capability revision>`.
- Amended 2026-10-05 by the product owner: self-host has exactly the same core
  features as Cloud (multiple Workspaces, Workspace creation, switching,
  cross-Workspace sharing). Profiles differ only in numeric limits
  (`max_active_workspaces`, `max_owned_workspaces_per_account`, later Device
  and Network counts) and in Cloud-only operations such as billing. Code has one
  path; limits are data from the verified entitlement, never feature branches
  on the profile name. Tightening self-host limits is a later, separate change;
  until then the current self-host tuple stays as it is.
- `read_console_deployment_capabilities_v2` derives the tuple from the
  Deployment row plus the current verified entitlement; v1 stays for rollback.

### D3. Workspace creation

- Any authenticated Account in a Cloud Deployment may create a Workspace; the
  creator becomes owner. This is an Account rule bounded by quotas, not a
  Workspace-scoped role (no Workspace exists yet to scope it).
- `create_workspace_v1` runs one transaction: lock the Deployment and
  entitlement rows (`WorkspaceLimitGuard`), check active count against
  `max_active_workspaces` and the Account's owned count against
  `max_owned_workspaces_per_account`, insert the Workspace (display code is
  assigned by the existing trigger), owner membership, identity-provider routing
  copied from the creating Session's provider, the `workspace_overlay` address
  realm (IPv4 `100.64.0.0/10`, random IPv6 ULA `/48`), idempotency record,
  audit and outbox. No first Network is created implicitly.
- `POST /api/v1/workspaces` with `Idempotency-Key`; errors
  `deployment_workspace_limit` and `account_workspace_limit` (both
  non-retryable). Names stay unique per owner (migration 78 rule).
- Workspace delete/suspend is out of scope for this ADR (later ADR with slot
  reuse and retention).

### D4. Workspace switching

- The Account Session stays bound to exactly one Workspace at a time, so every
  existing SQL function keeps its proven `login_workspace_id` scoping.
- `POST /auth/v1/session/workspace` rebinds the Session to another Workspace
  after checking active membership or ownership, increments the Session
  version, rotates the CSRF proof and records audit. In-flight requests bound
  to the old version fail with 409 and the Console reloads.
- `read_console_management_scopes_v4` adds the list of Workspaces the Principal
  may switch to (ID, name, display code, role summary), bounded and paged.

### D5. Signup

- Out of scope for the first release. Only provisioned identities can sign in,
  as today. A later ADR adds a Cloud admission policy (open or invite-only
  signup) that creates an Account plus a `Default` Workspace.
- Consequence: the first Cloud release serves existing Accounts, which can
  create additional Workspaces. That is sufficient for cross-Workspace
  qualification and for operator-provisioned customers.

### D6. Built-in roles aligned with enterprise teams

Roles follow the teams that operate a private network in a company rather than
the permission families: one contract owner, full administrators, a networking
team, an IT/helpdesk team, finance, compliance, and everyone else. The set
matches what customers already know from comparable products, so migration
needs no relearning. Seven immutable built-in roles are seeded by migration;
custom roles remain for exceptions.

| Role | Team | Can | Cannot |
| --- | --- | --- | --- |
| `owner` | Contract holder | Everything, including owner transfer and Workspace deletion. Exactly one, held through `owner_principal_id`, never by binding. | Leave or be suspended without first transferring ownership. |
| `admin` | Platform/IT leads | Everything except owner transfer and Workspace deletion: members and roles, SSO/SCIM, Networks, Devices, policy, routes, DNS, Resources, sharing, keys, settings, billing, audit. | Transfer ownership, delete the Workspace, approve their own policy change when approval is required. |
| `network_admin` | Networking team | Policy draft/validate/publish, DNS, routes and exit nodes, Resources, share offers/acceptance/revocation, Network create/update; read members and Devices. | Members, roles, Device lifecycle, enrollment keys, SSO, billing, Workspace settings. |
| `it_admin` | IT/helpdesk | Members (invite, approve, suspend, remove), assign roles up to `it_admin`, Device approve/rename/transfer/remove, enrollment keys, session revocation and Device quarantine, SSO/SCIM; read policy and Networks. | Policy, DNS, routes, sharing, billing; grant `admin` or `owner`. |
| `billing_admin` | Finance | Plan, invoices, payment, billing contacts; read Workspace summary. | Anything operational. |
| `auditor` | Compliance/security review | Read every configuration, member, Device and policy; read and export audit. | Any mutation, secret or credential value. |
| `member` | Everyone (default) | Join the Workspace, enroll their own Devices, view/rename/remove Devices they own, connect only as policy allows. | Any administration or other people's Devices. |

Scope and delegation rules:

- `member` is implicit for every active membership; other roles add to it.
- `network_admin`, `it_admin` and `auditor` can be bound at Workspace scope
  (every Network, including future ones) or at a single Network, so each team
  can own its Networks. `owner`, `admin` and `billing_admin` are Workspace-only.
- Nobody grants a role above their own: `it_admin` may assign `member`,
  `auditor`, `billing_admin`, `network_admin` and `it_admin`; only `owner` and
  `admin` assign `admin`; nobody assigns `owner` (transfer only). Nobody changes
  their own roles.
- Any role binding may carry an expiry for contractors and temporary elevation;
  expiry is enforced on every request by the existing authority checks.
- Sensitive actions (SSO/SCIM change, role grant to `admin`, owner transfer,
  Workspace deletion) require recent re-authentication and notify the owner and
  admins. Optional four-eyes approval for policy publication remains the
  existing approval workflow.
- The Workspace should keep at least two people able to administer it; the
  Console warns when only the owner holds `admin`-level authority.
- `security_admin` and `identity_admin` from core-docs/19 are folded into
  `it_admin` and `network_admin`; the remaining fine-grained Network roles stay
  available only as custom roles.

### D6a. Member lifecycle (joiner, mover, leaver)

States: `invited → pending_approval → active ⇄ suspended → removed`.

- Join: an expiring single-use invitation (default 7 days) carrying the
  initial role and optional membership expiry; SSO just-in-time join for a
  verified company domain, landing in `pending_approval` unless the Workspace
  enables automatic approval; SCIM provisioning with group-to-role mapping.
  Until approved, a member can sign in and register a Device that receives no
  peers.
- Move: role changes take effect on the next request and are audited; SCIM
  group changes update roles automatically.
- Suspend (offboarding first step, reversible): sessions, API tokens and
  enrollment keys stop immediately; owned Devices are withdrawn from every map
  (no peers, no shares); nothing is deleted. SCIM deactivation suspends.
- Remove: membership ends; Devices owned by the member are revoked and their
  keys rejected; Devices whose owner is the Workspace (servers, connectors)
  are unaffected. Before removal an `it_admin` can transfer selected Devices to
  another member or to the Workspace. Audit history keeps the person.
- Contractors: membership and role expiry move them to `suspended`
  automatically.
- Hygiene: last-activity timestamps and an exportable member/role report for
  periodic access reviews; optional automatic suspension after a configurable
  inactivity period.

### D6b. Workspace lifecycle

States: `active → suspended → pending_deletion → deleted`.

- Create (D3): creator becomes owner; quota-bounded.
- Rename: owner or `admin` (current owner-only rule widened).
- Owner transfer: to an existing `admin`, who must accept; re-authentication on
  both sides; previous owner keeps `admin`.
- Suspend: by the platform (abuse, billing) or the owner. Configuration stays
  readable; Devices lose peers; no new enrollment.
- Delete: owner only, after re-authentication and typing the Workspace name.
  It enters `pending_deletion` for 30 days (reversible by the owner), during
  which all Devices are disconnected and shares toward or from it are revoked.
  Afterwards data is purged per retention, the activation slot is freed, and
  the display code is never reused.
- Cross-Workspace shares never outlive either side: suspension withdraws them,
  deletion revokes them.

### D7. Cross-Workspace sharing in the Console

- When capabilities say `workspace_mode=multi`, the Console accepts
  `cross_workspace` offers and contracts and drops the same-Workspace guards.
- The New share form picks the consumer Network from every Workspace the user
  can switch to; other targets are entered by consumer Network display code,
  which Core resolves without revealing anything beyond existence to an
  authorized creator.
- Cross-Workspace share lifetime keeps the existing 30-day maximum (see open
  decision O3).

## Delivery phases

1. Entitlement and capabilities: schema (`deployment_entitlement`,
   `workspace_activation`), verifier, installation-key proof, capability v2,
   startup quarantine, Cloud-pinned and self-host-pinned tests.
2. Workspaces and roles: seven built-in roles migration and resolver,
   Network- or Workspace-scoped bindings with expiry, member suspend/remove
   with Device withdrawal, permission
   catalog additions, `create_workspace_v1`, `POST /api/v1/workspaces`, Session
   switch, scopes v4, OpenAPI, abuse matrix (copied entitlement, downgrade,
   limit races, foreign switch, role escalation).
3. Console: capability parser, Workspace switcher, create-Workspace flow,
   member and role binding screen for existing Principals, cross-Workspace
   sharing.
4. Live qualification: a Cloud deployment with two Workspaces whose Networks
   use identical CIDRs; cross-Workspace share, DNS, ACL, revoke and isolation on
   real clients (open decision O4 decides where).

## Resolved decisions

Approved by the product owner on 2026-10-05 with the recommended options:

- O1. The seven roles in D6. `admin` may change SSO only after
  re-authentication and owner notification. The fine-grained Network roles,
  `security_admin` and `identity_admin` are not built in.
- O2. `max_owned_workspaces_per_account=5`; `max_active_workspaces` per
  entitlement (POC: 50).
- O3. Cross-Workspace shares keep the 30-day maximum and are renewable;
  same-Workspace shares keep "Never".
- O4. Cloud is qualified live on a freshly bootstrapped Cloud deployment.
- Delivery order: built-in roles first, then the remaining Device-sharing work,
  then entitlement, Workspace creation and Console.

## Consequences

- Self-host behaviour stays unchanged for now. Cloud and self-host share one
  feature path whose limits come from the entitlement (D2 amendment).
- Existing SQL functions keep single-Workspace Session scoping; switching is a
  Session rebinding, not a multi-scope Session.
- Signup, invitations, SSO just-in-time join, SCIM, Workspace suspension and
  deletion, owner transfer and billing are specified here (D6a, D6b) but
  delivered after the first release; cells and the ops application remain later
  ADRs.
