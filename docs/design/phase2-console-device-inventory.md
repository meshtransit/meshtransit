# Console device inventory

## Invariants

- The private Console read requires the existing direct TLS, exact Host and
  Origin, cookie-only Session channel, fresh durable Session and shared budgets.
- Navigation projects only explicitly bound `network.read`, `device.read`, and
  the existing policy/sharing permissions. It does not grant any permission.
- Every Device page independently authorizes `device.read` for the exact
  Workspace and Network. Membership, ownership labels, IdP claims and policy
  permissions do not substitute for the Role Binding.
- Reads are bounded UUIDv7 keyset pages, with a cursor bound to both scope IDs
  and the inventory revision. Changed inventory rejects continuation.
- The Device projection includes only public ID, hostname, durable registration
  state, ephemeral flag, version, registration/update/expiry timestamps. It
  includes no credentials, key material, endpoints or unverified presence.
- PostgreSQL retains forced exact-scope RLS. No new table grants or broad
  inventory capability are introduced. Unknown and unauthorized scope reads
  return the same denial.
- Existing issued login URLs and client registration behavior remain compatible.

## Qualification

Contract tests cover read-only scopes, strict private routing, missing/revoked
permission, scope substitution, cursor revision changes and malformed durable
output. PostgreSQL integration exercises the runtime role and function grants.
Console validates every page and clears previous inventory on scope change or
failed refresh. POC role issuance uses a separate audited, bounded bootstrap.

POC qualification on 2026-10-01 reached schema 73 and Helm revision 58. API,
Control, Console and Identity are Ready 2/2; canary is Ready 1/1. The approved
inventory images are pinned by digest in the chart overlay. A new SSO Session
initially projected zero managed Networks. An exact Network Role Binding with
only device.read and network.read, no expiry, then projected one Network and
seven Device registrations. Refresh succeeded; both current meshd clients
remained registered and synchronized. Four audit and four outbox records
accompany the POC role grant.

Full qualification and screenshot evidence are recorded in the shared workspace
MESH_CONSOLE_INVENTORY_POC_2026-10-01.md. This read exposes durable registration
metadata; Device presence and packet connectivity remain separate work.
