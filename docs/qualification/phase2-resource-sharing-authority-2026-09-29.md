# Phase 2 Resource Sharing qualification — 2026-09-29

## Accepted behavior

| Requirement | Evidence |
| --- | --- |
| One Principal can own multiple Workspaces | PostgreSQL integration fixture has one active owner for multiple active Workspaces and asserts the cardinality. |
| One Workspace can contain multiple Networks | Resource Sharing integration asserts at least two active Networks in the management Workspace. |
| CIDRs cannot overlap inside one Workspace | `network_prefix_realm_prefix_excl` rejects an overlapping prefix with SQLSTATE `23P01`. |
| Different Workspaces can reuse a CIDR | Integration fixtures retain identical active CIDRs in different Workspace realms and assert the cross-realm reuse. |
| Cross-scope substitution is rejected | Composite foreign keys reject a Network/Workspace/realm substitution with SQLSTATE `23503`. |
| One share is Device- and traffic-bounded | Offer creation revalidates one active Device-backed Resource plus pinned Resource version, target generation, semantic hash, protocol, ports, and expiry. |
| Same-Workspace sharing uses management RBAC | The existing end-to-end flow offers from Network 203 and accepts into Network 204 using explicit `share.offer` and `share.accept` grants. |
| Cross-Workspace sharing requires both sides | Provider Principal 11 creates the offer; the same provider is denied consumer acceptance; consumer Principal 13 with an independent Workspace 102 membership and Network 202 role accepts. |
| Consent is attributable | Each of the two Network audit streams records provider and consumer events with actor, permission, `scope_relation=cross_workspace`, and the correct `authority_side`. |
| Cross-Workspace connectivity remains fail closed | Activation persists only a `provisioning` Private Endpoint. No direct provider Device edge or DNS record is created; effective access still requires a separately confirmed `ready` endpoint. |
| Provider IP is not the consumer contract | Share Offer and Imported Resource management projections expose identities and provenance, not a raw provider overlay IP. Consumer-local DNS plus Private Endpoint alias publication remains the required executable path. |
| DNS access names reject address fallback | `AccessName` unit tests reject IPv4 literals, numeric pseudo-addresses, relative labels, unsafe labels, trailing root dots, and Unicode without an explicit IDNA boundary. |
| Endpoint readiness is generation-bound | `PrivateEndpoint` tests bind contract/import versions, exact scopes, recovery epoch, endpoint generation, alias, traffic grant, expiry, and lifecycle; stale inputs fail closed. |
| Cross-Workspace routing requires alias mode | A direct cross-Workspace endpoint is invalid even if current CIDRs do not overlap; the domain accepts only the explicit Federation Alias mode. |
| Access-name allocation is consumer-local | Migration 53 reserves a canonical name under `(consumer Workspace, consumer Network)`; the same name succeeds in another Network while a duplicate in the same active namespace returns conflict. |
| Name collision rolls back atomically | PostgreSQL integration creates a second offer, attempts the same reserved name, observes `ErrConflict`, and confirms the offer remains `offered` at version 1 with no Trust Contract. |
| Runtime cannot bypass sharing authority | Forced RLS exposes scoped reads only; direct runtime writes are denied. Legacy decide/activate/revoke entry points are closed and only the current v2/v3 functions are callable through `mesh_share_writer`. |
| Federation Alias allocation is serialized | Migration 54 row-locks a Deployment pool cursor and allocates `fd00:feed::1`, then `fd00:feed::2` for a cross-Workspace activation; active aliases are unique and withdrawn offsets are not reused. |
| Private Endpoint provenance is exact | Composite foreign keys bind one endpoint to the same contract, Imported Resource, access-name reservation, alias lease, consumer scope, versions, generations, recovery epoch, constraint hash, and expiry. |
| Provisioning is not publication | Activation creates endpoint state `provisioning` and alias state `reserved`; `ready_at` and `activated_at` remain null and no DNS state or revision is created. |
| Revoke withdraws without deleting evidence | Contract revoke moves the access name and alias lease to `withdrawn` and the endpoint to `revoked`, all at version 2 in the same transaction. |

## Verification commands

```text
go test ./migrations ./internal/sharing ./internal/adapter/httpapi ./internal/adapter/postgres
make integration-platform-container
```

Observed results:

- full Go suite after the access-name and Private Endpoint domain slice: 4,738
  tests passed across 62 packages;
- focused sharing race suite: 73 tests passed;
- focused migration, sharing, HTTP, and PostgreSQL adapter suite: 1,657 tests
  passed across 4 packages;
- PostgreSQL/container integration after migration 54: passed, including
  migration replay, privilege/RLS checks, v1 entry-point closure, scoped name
  reuse, same-Network collision rollback, sequential Federation Alias
  allocation, Private Endpoint provisioning, revoke withdrawal, CIDR
  isolation, bilateral consent, audit, and qualification tooling.

## Security conclusions

- Relationship type is derived from exact UUIDv7 Workspace and Network scopes;
  it is not caller-controlled.
- Provider authority cannot approve a foreign consumer scope without a current
  membership and role binding there.
- CIDR overlap across Workspaces cannot be used as identity or authorization.
- Audit/outbox/idempotency evidence remains atomic with the sharing mutation.
- Effective access no longer accepts a free-standing endpoint-ready boolean or
  caller-supplied endpoint grant; it evaluates one validated, contract-bound
  Private Endpoint snapshot.
- The implementation does not claim an executable cross-Workspace data path;
  a trusted Private Endpoint or gateway is still required.
- Trusted route-readiness confirmation, DNS publication with `dns_revision`
  advancement, and terminal expiry/invalidation withdrawal are the next
  implementation slice.
