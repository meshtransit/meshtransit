# Phase 2 Resource Sharing authority

## Goal

Resource Sharing grants bounded access to one Device-backed Resource without
merging Networks or widening tenant identity. One Share Offer binds:

- one provider Workspace and Network;
- one consumer Workspace and Network;
- one active Device-backed Resource, including its Resource version, target
  generation, and semantic hash;
- an explicit allowlist of TCP, UDP, or ICMP traffic and destination ports;
- an exclusive expiry and one-time acceptance token.

The provider and consumer Network must be distinct. The relationship is derived
server-side as `within_workspace` or `cross_workspace`; callers cannot choose or
override it.

## Tenancy and CIDR invariants

A Principal may own multiple Workspaces. A Workspace may contain multiple
Networks. Every active Workspace has one active `workspace_overlay`
`address_realm`. Active, reserved, and quarantined address pools and Network
prefixes are protected by PostgreSQL GiST exclusion constraints on
`(address_realm_id, prefix &&)`.

Consequently:

- overlapping CIDRs inside one Workspace realm are rejected;
- the same CIDR may be reused by different Workspaces because their realm IDs
  differ;
- a Network cannot substitute a realm, pool, or prefix belonging to another
  Workspace because composite foreign keys bind all three authorities.

CIDR equality is therefore not a globally unique identity and must never be
used to authorize cross-Workspace traffic.

## Consent model

### Within one Workspace

The provider-side actor needs fresh `share.offer` on the exact provider
Network. Acceptance needs fresh `share.accept` on the exact consumer Network.
A Workspace administrator or delegated management role can perform the
workflow when its active membership and Network role bindings carry those
permissions. Workspace ownership alone is not an authorization bypass.

This supports one administrator managing two Networks while preserving exact
Network scope, optimistic revision checks, expiry, idempotency, and audit
evidence.

### Across Workspaces

Cross-Workspace authority is bilateral:

1. an authorized provider creates the offer; this is provider consent;
2. an independently authorized consumer accepts the unchanged offer with its
   one-time token; this is consumer consent.

The consumer decision is resolved against the consumer Workspace membership
and exact consumer Network role binding. Provider authority cannot accept on
behalf of a foreign Workspace. The model requires two Workspace authorities,
not necessarily two distinct human identities; a Principal legitimately
authorized in both Workspaces must still pass both independent permission
resolutions.

Every successful mutation records `scope_relation`, `authority_side`, actor
Principal, Account Session, role binding, role definition, authority
generations, both Network scopes, audit reason, and correlation evidence in
both Network audit streams.

## Lifecycle and safety

The lifecycle is monotonic:

`offered -> accepted -> activating -> active -> revoked|expired|invalidated`

Acceptance creates a Trust Contract and an Imported Resource. Activation
revalidates both Network authority generations, both sharing revisions, the
deployment recovery epoch, Resource version, target generation, semantic hash,
active Device target, export, and expiry. Either side can revoke using fresh
local `share.revoke` authority.

Mutation functions lock both Network revision rows in deterministic order and
commit state, revision advancement, audit, outbox, and idempotency evidence in
one PostgreSQL transaction. Forced RLS and the no-login `mesh_share_writer`
owner constrain the bilateral tables and security-definer functions.

## Data-plane boundary

The current Phase 2 slice persists and compiles Imported Resource provenance,
but it does not invent a direct packet edge. Explanation and simulation remain
fail closed when a safe endpoint path is unavailable.

This is mandatory for cross-Workspace sharing: two Workspaces may use the same
CIDR, so exposing the provider Device address directly would create ambiguous
routing and tenant-confusion risk. Executable cross-Workspace traffic requires
a later trusted Private Endpoint or gateway with a federation alias, explicit
route authority, and contract-bound packet policy.

Within-Workspace direct Device access is also not claimed by this slice. It
requires an explicit cross-Network peer/map projection and packet-filter path;
the control plane must not treat a stored Trust Contract as connectivity by
itself.

## Consumer access name

Applications must address a shared Resource through a consumer-local stable
name, not a provider overlay IP. The intended shape is similar to
`db-prod.shared.<consumer-network-domain>`. The name is discovery metadata; the
Imported Resource UUID and Trust Contract remain the authorization identities.

The executable endpoint slice must enforce all of the following:

- store a separately validated, unique consumer-local access name instead of
  treating the human `display_name` as DNS-safe;
- publish DNS only when the Trust Contract is active and a current Private
  Endpoint or gateway alias is ready;
- resolve cross-Workspace names to a consumer-visible federation alias, never
  directly to the provider overlay address;
- bind DNS publication to the Imported Resource version, contract version,
  endpoint generation, and `dns_revision`;
- remove or suppress the record when the contract is revoked, expired, or
  invalidated, with authoritative revision advancement;
- continue enforcing protocol and destination-port policy after resolution.

DNS therefore improves usability but grants no access by itself. Before the
endpoint and DNS projection exist, the safe response is no usable resolution,
not a provider IP fallback.

## Non-claims

- No graph database is required; PostgreSQL remains authoritative.
- No Network merge, CIDR renumbering, or global CIDR uniqueness is introduced.
- No UI is included in Phase 2.
- No cross-Workspace packet path is enabled without a trusted endpoint or
  gateway.
- No consumable DNS access name is published before that endpoint authority is
  implemented.
- No mandatory human separation-of-duty is inferred beyond the two independent
  Workspace authority checks.
