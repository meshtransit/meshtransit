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
| Cross-Workspace connectivity remains fail closed | Activation persists only a `provisioning` Private Endpoint. A worker must read an exact snapshot and submit route-readiness proof before endpoint/alias activation and DNS publication; no provider overlay address is exposed. |
| Provider IP is not the consumer contract | Share Offer and Imported Resource management projections expose identities and provenance, not a raw provider overlay IP. Consumer-local DNS plus Private Endpoint alias publication remains the required executable path. |
| DNS access names reject address fallback | `AccessName` unit tests reject IPv4 literals, numeric pseudo-addresses, relative labels, unsafe labels, trailing root dots, and Unicode without an explicit IDNA boundary. |
| Endpoint readiness is generation-bound | `PrivateEndpoint` tests bind contract/import versions, exact scopes, recovery epoch, endpoint generation, alias, traffic grant, expiry, and lifecycle; stale inputs fail closed. |
| Cross-Workspace routing requires alias mode | A direct cross-Workspace endpoint is invalid even if current CIDRs do not overlap; the domain accepts only the explicit Federation Alias mode. |
| Access-name allocation is consumer-local | Migration 53 reserves a canonical name under `(consumer Workspace, consumer Network)`; the same name succeeds in another Network while a duplicate in the same active namespace returns conflict. |
| Name collision rolls back atomically | PostgreSQL integration creates a second offer, attempts the same reserved name, observes `ErrConflict`, and confirms the offer remains `offered` at version 1 with no Trust Contract. |
| Runtime cannot bypass sharing authority | Forced RLS exposes scoped reads only; direct runtime writes are denied. Legacy entry points are closed; only decision v2, activation v2, and revocation v4 are callable through `mesh_share_writer`. |
| Federation Alias allocation is serialized | Migration 54 row-locks a Deployment pool cursor and allocates `fd00:feed::1`, then `fd00:feed::2` for a cross-Workspace activation; active aliases are unique and withdrawn offsets are not reused. |
| Private Endpoint provenance is exact | Composite foreign keys bind one endpoint to the same contract, Imported Resource, access-name reservation, alias lease, consumer scope, versions, generations, recovery epoch, constraint hash, and expiry. |
| Provisioning is not publication | Activation creates endpoint state `provisioning` and alias state `reserved`; `ready_at` and `activated_at` remain null and no DNS state or revision is created. |
| Publication is worker-only and atomic | Migration 55 revalidates exact scope, target, versions, generations, revisions, and audit heads; then records immutable readiness, publishes the consumer name, moves endpoint/alias to `ready`/`active`, advances provider route plus consumer DNS/route revisions, and appends both evidence streams in one transaction. |
| Same- and cross-Workspace publication are qualified | Container integration publishes `fd00:feed::1/128` into a second Network of the same Workspace and `fd00:feed::2/128` into Network 202 of a different Workspace, always through the stable consumer-local name. |
| Worker cannot mutate authority tables directly | `mesh_worker` can execute only candidate, snapshot, and publish functions; it has no direct table or sequence write privilege. Runtime, observer, audit writer, and public roles cannot execute publication. |
| Revoke withdraws without deleting evidence | After publication, contract revoke moves the access name and alias lease to `withdrawn`, the endpoint to `revoked`, and the DNS publication to `withdrawn`; readiness remains immutable and terminal timestamps remain attributable. |

## Verification commands

```text
go test ./migrations ./internal/sharing ./internal/adapter/httpapi ./internal/adapter/postgres
make integration-platform-container
```

Observed results:

- full Go and race suites after migration 55: passed across 62 packages;
- focused sharing race suite: 73 tests passed;
- focused migration and PostgreSQL adapter suite: 415 tests passed;
- PostgreSQL/container integration after migration 55: passed, including
  migration replay, privilege/RLS checks, v1 entry-point closure, scoped name
  reuse, same-Network collision rollback, sequential Federation Alias
  allocation, same- and cross-Workspace Private Endpoint publication,
  DNS/route revision advancement, revoke withdrawal, CIDR isolation, bilateral
  consent, dual-stream audit, and qualification tooling.

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
- The implementation defines and qualifies the database transaction used by a
  trusted Private Endpoint/gateway reconciler; it does not claim the external
  packet gateway or route agent is implemented in this repository.
- Explicit expiry/invalidation reconciliation and the production worker loop
  that applies gateway routes are the next implementation slice.
