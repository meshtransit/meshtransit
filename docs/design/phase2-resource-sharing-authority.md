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

The current Phase 2 slice persists and compiles Imported Resource provenance
and now defines the trusted publication transaction, but it does not invent a
direct packet edge. Explanation and simulation remain fail closed when a safe
endpoint path is unavailable.

This is mandatory for cross-Workspace sharing: two Workspaces may use the same
CIDR, so exposing the provider Device address directly would create ambiguous
routing and tenant-confusion risk. Executable cross-Workspace traffic requires
a trusted Private Endpoint or gateway with a federation alias, explicit route
authority, and contract-bound packet policy. Migration 55 provides the database
boundary through which that trusted reconciler proves readiness; it does not
implement the packet gateway itself.

Within-Workspace direct Device access is also not claimed by this slice. It
requires an explicit cross-Network peer/map projection and packet-filter path;
the control plane must not treat a stored Trust Contract as connectivity by
itself.

## Consumer access name

Applications must address a shared Resource through a consumer-local stable
name, not a provider overlay IP. The intended shape is similar to
`db-prod.shared.<consumer-network-domain>`. The name is discovery metadata; the
Imported Resource UUID and Trust Contract remain the authorization identities.

The complete executable endpoint path must enforce all of the following:

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

The domain layer now enforces the foundation for that projection:

- `AccessName` is a canonical lowercase ASCII DNS name, separate from
  `display_name`; relative labels, root-dot forms, Unicode without an explicit
  IDNA boundary, numeric pseudo-addresses, and IP literals are rejected;
- `PrivateEndpoint` pins the Trust Contract and Imported Resource versions,
  both exact scopes, recovery epoch, endpoint generation, consumer access
  name, consumer-visible address, traffic grant, expiry, and lifecycle;
- cross-Workspace endpoints cannot use direct mode and must declare a
  Federation Alias path;
- the effective-access evaluator consumes the complete validated endpoint
  object instead of trusting a caller-supplied readiness boolean and separate
  traffic set.

Migration 53 now persists the first non-executable naming authority. Accepting
an offer requires `access_name` and atomically creates one `reserved` row bound
to the Imported Resource in the consumer Workspace and Network. A partial
unique index serializes collisions only inside that Network namespace; another
Network may use the same name. Reject and offer revoke cannot carry a name.
Trust Contract revoke atomically moves the reservation to `withdrawn`, retains
the evidence row, and releases the namespace for later reuse.

The table is forced-RLS. Runtime can only read rows in its current consumer
scope and cannot mutate them directly. The `mesh_share_writer` NOLOGIN owner is
the only application role with write capability. Runtime access to the old
decision and revoke functions is removed; access-name-aware v2 functions are
the only callable mutation boundary. Go validation and PostgreSQL constraints
independently reject malformed names, while a database unique violation maps
to a stable conflict and rolls back offer, contract, import, revisions, audit,
outbox, and idempotency writes together.

Migration 54 adds the next fail-closed boundary. Contract activation selects an
active Deployment-scoped `federation_resource_alias` pool, serializes its
monotonic cursor, reserves a never-reused host alias, and persists a Private
Endpoint in `provisioning`. The endpoint pins the exact Trust Contract and
Imported Resource versions, both Network scopes, access-name reservation,
authority generations, recovery epoch, constraint hash, expiry, alias lease,
and endpoint generation. Composite foreign keys make cross-record substitution
invalid even for the dedicated writer.

Allocation is performed inside the same transaction as activation, revision
advancement, audit, outbox, and idempotency evidence. A failed pool lookup,
exhausted cursor, address collision, or endpoint invariant rolls the entire
activation back. The cursor is row-locked and monotonically advances, while
withdrawn addresses are not recycled, avoiding delayed-packet confusion.
Forced RLS exposes consumer-scoped reads only; runtime cannot write either
authority table. Runtime access to `activate_resource_share_v1` and
`revoke_resource_share_v2` is closed in favor of endpoint-aware v2/v3 entry
points owned by `mesh_share_writer`. Revoke atomically terminalizes a current
endpoint and withdraws its alias lease together with the access name.

The access-name reservation deliberately has no `published` state. Activation
still ends with the endpoint in `provisioning` and therefore creates neither a
DNS record nor a packet path by itself.

Migration 55 adds the trusted publication boundary. A worker can list bounded
deployment candidates, then must read an exact authoritative snapshot before
reconciling the route. The snapshot revalidates the active contract, import,
reserved access name and alias lease, exact Device target and primary node
addresses, both Network authority generations, both revision vectors, and both
audit stream heads. Its `snapshot_at` value comes from PostgreSQL, avoiding
host/container clock-skew in the readiness proof.

Publication is a single fail-closed transaction. It locks both Network revision
rows in deterministic order, repeats exact scope and authority validation,
checks every expected version and audit head, records immutable route-readiness
evidence, changes the endpoint and alias to `ready`/`active`, and creates the
consumer-local DNS publication. Provider route/sharing revisions and consumer
DNS/route/sharing revisions advance atomically with two hash-chained audit and
outbox events. The candidate list is only a hint; the exact snapshot and publish
checks are authoritative.

The three publication entry points are executable only by `mesh_worker` and
are security-definer functions with fixed search paths. The worker has no
direct write privilege on readiness, DNS publication, endpoints, alias leases,
or revision tables. A separate internal scope assertion is owned by the
`mesh_share_writer` NOLOGIN role and callable only by the migration owner,
preserving the bilateral Workspace/Network RLS boundary without widening table
grants.

DNS-aware revoke v4 first performs the existing contract/import/access-name/
endpoint/alias transition, then withdraws the current DNS publication and
advances both route revisions plus the consumer DNS revision. The caller's
original runtime scope is restored before the surrounding mutation continues,
so later authorization, projection, audit, and idempotency reads remain scoped.

## Non-claims

- No graph database is required; PostgreSQL remains authoritative.
- No Network merge, CIDR renumbering, or global CIDR uniqueness is introduced.
- No UI is included in Phase 2.
- No cross-Workspace packet path is enabled merely by storing a contract or
  activating it; a trusted endpoint/gateway must reconcile the route and submit
  the worker-only readiness proof.
- No consumable DNS access name is published while the endpoint remains
  `provisioning`.
- The migration defines the route/DNS publication authority and evidence, not
  the external gateway or route-agent implementation.
- No mandatory human separation-of-duty is inferred beyond the two independent
  Workspace authority checks.
