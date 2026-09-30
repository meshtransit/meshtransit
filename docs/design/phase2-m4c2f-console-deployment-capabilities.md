# Phase 2 M4c2f Console Deployment capability projection

Status: implemented engineering projection; production browser/BFF qualification
and signed cloud entitlement remain pending.

Date: 2026-09-30

## Scope

M4c2f adds the authenticated, non-secret Deployment capability projection
required by the shared Console source. It prevents Console navigation and route
guards from inferring product mode from build variables, browser storage,
hostnames, query parameters, or failed feature probes.

This slice publishes only the official self-hosted baseline. Cloud capability
remains fail-closed until the signed Deployment Entitlement, installation-key
proof, activation-slot authority, quarantine, and reconciliation contracts are
implemented and qualified.

## Contract

The private Console profile adds one exact safe-read route:

`GET /v1/system/capabilities`

Admission requires completed direct TLS 1.2 or later, the exact configured Host
and HTTPS Origin, `X-MeshTransit-Session: v1`, one canonical host-only Core
Session cookie, fresh durable authentication, and shared source/Session budgets.
`Authorization`, CSRF, query, body, content type, conditional, idempotency,
transfer, and alternate-route input are rejected.

The successful response contains exactly:

- `deployment_profile = self_hosted`;
- `workspace_mode = single`;
- `max_active_workspaces = 1`;
- `workspace_creation = bootstrap_only`;
- `cloud_billing = false`;
- `platform_operations = false`; and
- a positive durable `capability_revision`.

It contains no Deployment ID, Workspace ID, entitlement, installation key,
Session ID, provider claim, role, billing record, topology, or operator route.
The projection is Console navigation evidence only. It never authorizes an API
operation and cannot override Workspace, Network, RBAC, approval, or product
guards.

## Durable authority and fail-closed behavior

Migration `000057_console_deployment_capability_projection.up.sql` adds one
fixed-search-path `SECURITY DEFINER` function. The complete input vector binds
Session, Deployment, Principal, identity subject, all authority generations,
recovery epoch, login Workspace, and evaluation time. The function revalidates
the active Session chain, Deployment recovery state, current login Workspace,
membership, provider/client state, and the immutable `self_hosted` profile.

Only `mesh_runtime` may execute the function. `PUBLIC`, worker, observer,
audit-writer, and share-writer roles are revoked. The runtime application role
receives no table grant. The Go service independently validates exact
Deployment identity, the closed profile set, positive revision, active Session,
and the complete self-hosted capability tuple.

Unknown, cloud, stale, contradictory, malformed, unavailable, or canceled
evidence releases no capability document. PostgreSQL remains authoritative;
Redis and frontend state cannot create or widen a capability.

## Security analysis

| Threat | M4c2f control |
| --- | --- |
| Spoofing | Exact TLS/Host/Origin/channel/cookie admission plus fresh complete-vector Session authentication. |
| Tampering | Closed route/header/query shape, typed UUIDv7 identity, fixed self-hosted tuple, and positive durable revision. |
| Repudiation | Bounded correlation headers and fixed-cardinality HTTP/PostgreSQL operation metrics without credential data. |
| Information disclosure | No tenant/resource identity, entitlement, installation proof, Session, provider, role, billing, or topology fields. |
| Denial of service | Shared source/Session budgets, finite deadline/concurrency/response bounds, one bounded read-only transaction, and no retry. |
| Elevation of privilege | Projection is never operation authority; cloud and unknown profiles fail closed and every downstream API reauthorizes independently. |

## Browser transport qualification

The Fetch Standard does not guarantee an `Origin` header on same-origin
`GET`/`HEAD`, and browser JavaScript cannot set `Origin` itself. This slice does
not weaken the established exact-Origin private profile. Production activation
therefore still requires the separately reviewed same-origin BFF/edge transport
and browser qualification. A direct browser-to-Core deployment that cannot
satisfy this admission remains unavailable rather than falling back to
`Referer`, forwarding headers, frontend inference, or a less strict profile.

## Non-claims and next order

M4c2f does not implement signed cloud entitlement, Workspace activation slots,
second-Workspace rejection, edition-integrity quarantine, cloud billing,
platform operations, public documentation, BFF deployment, live browser
qualification, production HA/SLO, release, or GA.

The next ordered work is:

1. consume this projection before management-scope bootstrap in Console and
   fail closed on unknown or contradictory fields;
2. qualify the exact same-origin BFF/edge transport without trusting forwarded
   browser headers;
3. implement signed cloud entitlement and activation-slot authority before
   publishing any cloud capability; and
4. add Console mutation transport for independent Policy approval decisions.
