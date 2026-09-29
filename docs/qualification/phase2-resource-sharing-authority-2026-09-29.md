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
| Cross-Workspace connectivity remains fail closed | Accepted contract remains `activating`; no direct provider Device edge is created. Imported Resource evaluation requires separately resolved safe path authority. |
| Provider IP is not the consumer contract | Share Offer and Imported Resource management projections expose identities and provenance, not a raw provider overlay IP. Consumer-local DNS plus Private Endpoint alias publication remains the required executable path. |

## Verification commands

```text
go test ./internal/sharing ./internal/adapter/httpapi ./internal/adapter/postgres
make integration-platform-container
```

Observed results:

- focused unit and adapter suite: 1,606 tests passed across 3 packages;
- PostgreSQL/container integration: passed, including migration replay,
  privilege/RLS checks, CIDR isolation, bilateral consent, audit, and
  qualification tooling.

## Security conclusions

- Relationship type is derived from exact UUIDv7 Workspace and Network scopes;
  it is not caller-controlled.
- Provider authority cannot approve a foreign consumer scope without a current
  membership and role binding there.
- CIDR overlap across Workspaces cannot be used as identity or authorization.
- Audit/outbox/idempotency evidence remains atomic with the sharing mutation.
- The implementation does not claim an executable cross-Workspace data path;
  a trusted Private Endpoint or gateway is still required.
- Stable consumer-local DNS naming, alias allocation, DNS revision publication,
  and revoke-time record withdrawal are the next implementation slice.
