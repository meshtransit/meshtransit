# Phase 2 M4c2d private Console Policy approval catalog design

Status: implemented and locally qualified; Console UI and deployed workflow
qualification remain pending.

Date: 2026-09-29

Follow-up: M4c2e later adds the server-authoritative UUIDv7 management-scope
projection required by the Console; see
`phase2-m4c2e-console-management-scope-projection.md`. The boundary below
records the M4c2d candidate as qualified at that time.

## Scope

M4c2d exposes the retained M4c2c Policy approval catalog to the private
same-origin Console profile. This closes the transport gap between the existing
Console-authenticated proposal/decision mutations and the independent reviewer
queue without adding a UI-only API, a second authorization path, or another
workflow authority.

The Bearer management document remains byte-identical. PostgreSQL remains the
only approval and publication authority, and Redis remains revision-wakeup
transport. This slice adds no migration and no graph database.

## Private read contract

The private Console source document now composes both existing catalog reads
from the same management resource contract:

| Operation | Method and path | Browser admission |
| --- | --- | --- |
| List | `GET /api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/approval-requests` | Exact host and HTTPS Origin, explicit `X-MeshTransit-Session: v1`, one host-only Core Session cookie, fresh session authentication, shared source/session budgets, and current exact-scope `policy.approve` |
| Get | `GET /api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/approval-requests/{approval_request_id}` | Same admission and authorization as list |

These safe reads do not require or accept the mutation CSRF proof. They also do
not accept a request body, content type, `If-Match`, idempotency key, transfer
encoding, or mutation-route alias. List accepts only the existing bounded
`state`, `page_size`, and opaque `page_token` query contract. Item reads accept
no query.

The cookie is authentication transport only. Both reads still execute the same
fresh PostgreSQL permission resolution and catalog service as Bearer clients.
The browser cannot supply Authorization, negotiate another profile, or use
frontend state as authority.

## Dispatcher and response ownership

The private login dispatcher now recognizes the complete browser-management
route set owned by `BrowserManagement`, including Policy simulation, approval
proposal, approval decision, approval list, and approval item reads. It forwards
the original writer and request to exactly one owner and does not interpret,
retry, or rewrite delegated outcomes.

Every candidate response remains fully buffered until late session freshness
and request cancellation checks pass. The response cap is 256 KiB, which holds
the documented maximum page of 100 bounded approval projections. With the
existing maximum of 128 concurrent private requests, response buffering is
bounded to 32 MiB. Responses remain `Cache-Control: no-store`, emit no Session
cookie or Bearer challenge, and item reads preserve the strong request-version
ETag.

## Security analysis

| Threat | M4c2d control |
| --- | --- |
| Spoofing | Exact host/TLS/Origin/channel/cookie validation plus fresh durable Session authentication; provider tokens and Authorization are rejected. |
| Tampering | Canonical path/query validation, closed read headers, typed UUIDv7 scope parsing, and exact-scope catalog authorization. |
| Repudiation | Reads use existing correlation IDs, bounded operation metrics, and structured completion logs without credential data. |
| Information disclosure | Current `policy.approve`, same-scope concealment, no Session IDs, no-store responses, and buffered late-freshness delivery. |
| Denial of service | Shared source/session limits, finite deadlines and concurrency, 8 KiB query bound, page size 1–100, and 256 KiB response bound. |
| Elevation of privilege | Browser routing adds no permission, mutation, or cached authority; CSRF remains mandatory for every mutation and absent from safe reads. |

## Non-claims and next order

M4c2d does not add Console components, scope projection, Principal display-name
projection, notifications, configurable quorum, approval-policy administration,
or production rollout. The current legacy Console Account API still identifies
Networks with numeric IDs, while the Phase 2 management contract uses UUIDv7
Workspace and Network public IDs. M4c2e subsequently closes that projection
gap; the remaining Console slice adds the queue/detail and independent approval
experience against the private contracts.

Local acceptance evidence is recorded in
`docs/qualification/phase2-m4c2d-private-console-policy-approval-catalog-2026-09-29.md`.
