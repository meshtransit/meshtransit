# Audit and evidence

MeshTransit records every change of authority as a sealed audit event, and
keeps evidence of who could reach what and whether Devices enforce what they
were sent. The record format, the seal and exports are specified in
[audit record v2](../protocol/audit-record-v2.md); this document describes
what is recorded and how to read it.

## What is recorded

Every change to Core's authority tables writes an audit event in the same
transaction. The database enforces this per change: tables that hold
authority (the Deployment, principals, Workspaces, Networks, address pools,
Devices, enrollment, policy releases, Resources, shares, Trust Contracts,
guardrails, groups, tags, invitations, …) capture each row change, and a
transaction that changed them cannot commit without an audit event and an
outbox event for that change. A read never writes one.

Actions are named `<object>.<verb>`, for example:

| Area | Actions |
|---|---|
| Policy | `policy.published`, `policy.approval.requested`, `policy.approval.approved` |
| Devices | `device.registered`, `device.renamed`, `device.suspended`, `device.reactivated`, `device.ownership_transferred`, `device.handover_started`, `device.handover_completed`, `device.node_key_rotated`, `device.tags_changed`, `device.logged_out`, `device.revoked` |
| Registration | `registration.requested`, `registration.browser.requested`, `registration.browser.approved`, `registration.expired` |
| Members | `member.invited`, `member.invitation_accepted`, `member.invitation_revoked`, `member.suspended`, `member.reactivated`, `member.removed`, `network.member.added`, `network.member.removed` |
| Workspaces and Networks | `workspace.created`, `workspace.renamed`, `workspace_role.assigned`, `workspace_role.revoked`, `network.created`, `network.alias_range.updated` |
| Groups, tags, guardrails | `device_group.*`, `identity_group.*`, `device_tag.*`, `guardrail.*`, `interchange.*` |
| Resources and sharing | `resource.*`, `resource_group.*`, `share_offer.*`, `trust_contract.*`, `sharing.private_endpoint.published` |
| Sign-in | `auth_transaction.*`, `account_session.*`, `account.signed_up` |
| Evidence | `access_graph.recorded`, `device.enforcement_mismatch`, `device.enforcement_restored` |

Only changes that happened are recorded: every event today has the result
`succeeded`. A refused request changes nothing and writes nothing; a failure
that changes state is recorded as that change (for example
`member.invitation_delivery_failed`). The record format can also carry
`denied` and `failed` results.

Changes Core makes on its own (expiry, ledgers, private endpoint
reconciliation) have no actor principal and read as `actor_kind: system`.

## Streams

Events are kept in streams, each a sealed chain:

- one **Deployment** stream: sign-in, Account Sessions, browser registration
  requests, entitlement and bootstrap;
- one **Workspace** stream per Workspace: its creation, name, roles, members,
  invitations, guardrails and identity catalog;
- one **Network** stream per Network: everything that concerns one Network.

A change that affects several Networks is one change (`change_id`) with one
event in each affected stream. A member's suspension, for example, writes the
Workspace event and one event in each Network whose Devices it changes; a
share decision is written in both the provider's and the consumer's Network.
`correlation_id` is normally the API request's correlation ID, so all events
of one request can be found together.

## Reading the history

`GET /api/v1/workspaces/{workspace}/audit-events` (the Console's Activity
page) lists events newest first.

- **Filters:** `network_id`, `since`, `until`, `target_kind` (up to 16),
  `target_id`, `actor_id`, `actor_kind`, `action`, `result`,
  `correlation_id`, `change_id`.
- **Window:** without `until` it ends now on the database clock; without
  `since` it covers the 90 days before `until`; longer than 93 days is
  refused. Read older history window by window.
- **Pages:** 50 records by default, at most 100, with an opaque
  `page_token`.
- **Who may read:** `audit.read` on the Workspace reads the Workspace stream
  and every Network stream; `audit.read` on one Network reads only that
  Network, and the request must name it. Deployment streams are not part of
  any Workspace's history.
- **Integrity:** Core recomputes the seal of every record it returns and marks
  one that does not match as `seal_mismatch`.
- **Names:** actors are returned by ID, with display names for principals who
  are or were members of the Workspace.

Exports of the same history, for verification outside Core, are described in
[audit record v2 §5](../protocol/audit-record-v2.md#5-exports).

## Connection history

The **access ledger** answers who could reach whom in a Network at any past
moment. It is a worker job, off by default
(`MESHTRANSIT_ACCESS_LEDGER_WORKER_ENABLED`).

For every new Network revision, the worker computes the Network's effective
access edges: the published rules, with groups, identity groups and tags at
their membership at that time, the Devices reachable through active shares,
and each Device a rule grants a Site to (not the Site's own routers), keeping
only active, unexpired Devices. An edge that appears opens at
that revision's time, one that disappears closes there. Each change also
writes a sealed `access_graph.recorded` event whose hash is the digest of the
edge set, so the ledger can be checked against the audit trail.

`GET /api/v1/workspaces/{workspace}/networks/{network}/access-graph/history`,
an operation of the Console's private API, answers for an instant `at`
(default now), which must be at or before the server's time (the database
clock's); a later instant is refused. It is optionally filtered by Device,
source, destination or protocol. It needs `policy.read` and `device.read`.
The answer includes `recorded_since`: before the first recorded state there
is no history. An edge to a Site has `selector_kind` `site`, no destination
Device, and `destination_site_id` and `destination_prefixes` (the prefixes the
rule grants). The snapshot's `edge_count` and `digest` cover every recorded
edge, Site edges included.

The ledger polls every few seconds, so a change that is undone within one
poll may not appear.

## Policy distribution and enforcement

Core knows what it sent each Device, and each Device reports what it enforces:
after a rule change, again 30 seconds later and every 5 minutes, a node sends
the [policy digest](../protocol/policy-digest-v1.md) of the packet filter it
actually installed.

`GET …/networks/{network}/devices/{device}/status` (Console private API, needs
`device.read`) shows for an active or suspended Device:

- **distribution:** `in_sync` (online with the current revision), `behind`
  (online with an older one), `offline`, `never_connected`, or `unknown`
  when the session store cannot be read;
- **enforcement:** `enforced` (the reported digest equals the one sent),
  `applying` (within a minute of delivery), `not_reported`, `mismatch` (a
  different digest after that minute), or `unknown` (nothing delivered yet).

The **enforcement ledger** (a worker job, off by default,
`MESHTRANSIT_ENFORCEMENT_LEDGER_WORKER_ENABLED`) keeps this over time:
`GET …/networks/{network}/enforcement-history?at=…` (Console private API) shows each
Device's state at an instant at or before the server's time (default now),
and a Device entering or leaving `mismatch` writes a sealed
`device.enforcement_mismatch` or `device.enforcement_restored` event.

## Explaining access

The Access Graph lists who may reach what in a Network, Explain says why a
given connection is allowed or denied, and Simulate shows the effect of a
policy change before it is published. These are reads and write no audit
events; see [policy](policy.md#explaining-access).

## Retention

- Audit events are never updated or deleted: database triggers refuse it,
  and no job prunes them. Monthly partitions are created a year ahead.
- The access and enforcement ledgers prune closed intervals older than 13
  months, keeping each Network's latest state. Their sealed audit events
  remain.
- What each Device was sent and reports enforcing is kept in Redis for 30
  days; it is operational state, not evidence.
