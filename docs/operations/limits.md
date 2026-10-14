# Limits

Every bound an operator or a large tenant can reach, where it is enforced and
what happens when it is reached. Settings are in
[configuration](configuration.md); product limits (rules, groups, shares) are
also listed in the concept documents.

## Control (MTCP)

The normative list is MTCP v1 §14.

| Limit | Default | Setting | When reached |
|---|---|---|---|
| Sessions per control process | 1,024 | `MESHTRANSIT_CONTROL_MAX_SESSIONS` (1–16,384) | New TCP connections refused before TLS |
| Handshakes per source (IPv4 address or IPv6 /64) | 10/s, burst 50 | `MESHTRANSIT_CONTROL_MTCP_HANDSHAKE_RATE`, `…_BURST` | 503 with `Retry-After`, before any cryptography |
| Connections per source before a map | 150 | `MESHTRANSIT_CONTROL_MTCP_UNAUTHENTICATED_PER_SOURCE` | Refused |
| Session that never proves a Device | 15 min | `MESHTRANSIT_CONTROL_MTCP_UNPROVEN_SESSION_LIFETIME` | Closed |
| Inbound per session | 200 messages then 50/s; 1 MiB then 256 KiB/s | — | Session ends with `OVERLOADED` and a retry time |
| Registrations and key rotations per session | 4, then 1/s | — | `OVERLOADED` |
| Browser approvals per session | 2, then 1 per 10 s | — | `OVERLOADED` |
| Map resyncs per session | 2, then 1 per 5 s | — | Session ends |
| Enforcement reports per session | 4, then 1/s | — | Kept and stored later, not refused |
| Node key changes per Device | 4 an hour | — | `NOT_PERMITTED` with a retry time |
| Browser sign-in Devices | 20 per person per Network per 24 h | — | `NOT_PERMITTED` |
| Moves of a Device between replicas | 10 a minute | — | Session ends with `RECONNECT` and a retry time |
| Unacknowledged map messages | 8 | — | Core waits; 60 s full ends the stream |
| Endpoint changes seen by peers | 1 per 5 s | `MESHTRANSIT_CONTROL_MAP_ENDPOINT_ANNOUNCE_INTERVAL` | Coalesced |
| Peers in a map | 10,000; 256 without `map.large1` | `MESHTRANSIT_CONTROL_MAP_PEER_LIMIT` (100–10,000) | Shares first, then online peers; the Device shows the cut |
| Endpoints in a report | 32 | — | Report refused |
| Snapshot / delta size | 32 MiB / 8 MiB | — | — |

`meshtransit_mtcp_session_limits_total{limit}` counts the per-session limits
reached.

## Management API

| Limit | Default | Setting | When reached |
|---|---|---|---|
| Requests per source address | 30, then 1/s | `MESHTRANSIT_API_SOURCE_RATE_LIMIT_*` | 429 `rate_limited` with `RateLimit-*` and `Retry-After` headers |
| Requests per Account Session | 60, then 2/s | `MESHTRANSIT_API_SESSION_RATE_LIMIT_*` | Same |
| Rate limiting unavailable (Redis down) | — | — | 503 `rate_limit_unavailable`: fails closed |
| Connections | 256 | `MESHTRANSIT_API_MAX_CONNECTIONS` | Refused |
| Concurrent requests | 128 | `MESHTRANSIT_API_MAX_CONCURRENT_REQUESTS` | 503 |
| Request time | 10 s | `MESHTRANSIT_API_REQUEST_TIMEOUT` | Cancelled |
| Request body | 64 KiB; 8 MiB for policy publication | — | 400 or 413 |
| Page size | usually 50, at most 100; access graph 100, at most 500 | — | Bounded |
| Audit window | 90 days by default, at most 93 | — | 400 `invalid_request` |
| Audit export | 10,000 records, about 14 MiB | — | 422 `audit_export_too_large` |
| Self sign-up | 5 per source network a day, 30 an hour | `MESHTRANSIT_SELF_SIGNUP_*` | Refused |

## Product

| Limit | Value | Document |
|---|---|---|
| Rules in a policy | 10,000 compiled rules | [policy](../concepts/policy.md#limits) |
| Rule edges reaching one Device | 10,000 | [policy](../concepts/policy.md#limits) |
| Device Groups, Identity Groups, Device Tags | 200 per Network; 500 per Workspace; 200 per Workspace | [policy](../concepts/policy.md#limits) |
| Live shares into a Network / of a Device | 10,000 each | [sharing](../concepts/sharing.md#limits) |
| Members removed with a Device plan | 250 Devices per plan | [devices](../concepts/devices.md#members-leaving) |
| Pending invitations | 200 per Workspace | [identity and access](../concepts/identity-and-access.md#members-and-invitations) |
| Private Interchanges | 16 per Workspace, 256 Networks each | [paths and relays](../concepts/paths-and-relays.md#private-interchange) |
| Guardrails | 100 per Workspace | — |
| Bootstrap plan | 100 Accounts, 64 KiB | [deployment](deployment.md#first-data) |

Without the operator steps of the
[Device sharing deployment gate](../core/design/device-sharing-deployment-gate.md),
some limits stay at their earlier values (for example 256 Imported Resources
per policy).

## Relay

Per relay node; see [Relay](../architecture/relay.md#limits).

| Limit | Value |
|---|---|
| Sessions | 100,000 |
| Routes per session | 4,096 (or the ticket's) |
| Handshakes | 1,000/s, then cookies; 10/s per source |
| Packets / bytes per session | 50,000/s; 1 Gbit/s (or the ticket's) |
| Bytes per Network | 500 Mbit/s (`--network-bandwidth-mbit`) |
| TLS and WebSocket connections | 10,000; 64 per source |
| STUN | 20,000/s; 20/s per source |
| Relay map | 128 regions, 16 nodes each, at most 256 KiB |
| Relay tickets | at most 15 minutes |

## Node

| Limit | Value |
|---|---|
| Peers | 10,000; lazy above 1,000 |
| Candidates published | 16 |
| Remembered flows | 4,096 |
| DNS records in a map | 32,768; 256 names routed on the host |
| Filter rules | 10,000 |
| Relay regions open | 16 |
