# Policy

A Network's **policy** is the list of its Access Rules. Everything a rule does
not allow is denied. This document describes rules, how a policy change is
checked and published, how nodes enforce it, and how to ask why something is
allowed. Sharing a Device with another Network is in [sharing](sharing.md).

## Access Rules

A rule allows one direction: a **source** may open connections to a
**destination** on one **protocol**.

| Part | Choices |
|---|---|
| Source | one Device, Device Group, Identity Group or Device Tag |
| Destination | one Device, Device Group, Device Tag, Resource, Resource Group, Imported Resource or Site |
| Protocol | `tcp` or `udp` with 1 to 64 destination port ranges (1–65535), or `icmp` with none |

- Replies to an allowed connection are allowed; the destination cannot open
  new connections back unless another rule says so.
- There is no wildcard: no "any" source, destination or protocol.
- `icmp` covers ICMP for IPv4 and ICMPv6 for IPv6, as the destination's
  addresses require.
- An **Identity Group** can only be a source; it means the untagged Devices
  that its active members own in the Network.
- When either side is a group, an Identity Group or a tag, the destination
  must be a Device, a Device Group or a tag. Resources, Resource Groups and
  Imported Resources take a single Device as source.
- A rule from a Device to itself is refused.
- An **Imported Resource** is a Device another Network shares with this one;
  the rule is further limited by the share's terms ([sharing](sharing.md)).
- A **Site** is an address space behind a router Device; see
  [rules to Sites](#rules-to-sites).

### When selectors are resolved

- **Resources** resolve to their Device, and **Resource Groups** to their
  member Resources, when the policy is published.
- **Device Groups, Identity Groups and tags** are kept as selectors and
  resolved every time a map is built. Adding a Device to a group, tagging it,
  or a member joining an Identity Group changes what nodes get at once,
  without publishing the policy again.
- Rules may name suspended or expired Devices, directly, through a Resource
  or Resource Group on that Device, or as the source of an Imported Resource
  rule. Such a rule grants nothing while the Device is not live and takes
  effect again when the Device is resumed or renewed.
- Once a Device is revoked or deleted, rules the active policy already holds
  for it keep publishing as long as they are resent unchanged (same rule ID,
  both sides, protocol, ports and destination), so other edits to the policy
  still go through; remove them when convenient. A new rule naming that
  Device, or a kept rule changed in any part, is refused with 409
  `device_unavailable`, never with a stale revision.

### Limits

| Limit | Value |
|---|---|
| Compiled rules in a policy (a Resource Group rule counts once per member) | 10,000 |
| Port ranges per rule | 64 |
| Resources, Resource Groups named by one policy | 256 each |
| Imported Resources named by one policy | 10,000 |
| Rule edges reaching one Device, checked at publication and on group or tag changes | 10,000 (`device_policy_edge_limit`) |
| Device Groups | 200 per Network, 5,000 members each |
| Identity Groups | 500 per Workspace, 10,000 members |
| Device Tags | 200 per Workspace |
| Prefixes granted by all rules to Sites in one policy | 16,384 |

### Rules to Sites

A **Site** (`…/networks/{network}/sites`, managed with `route.approve` and
`route.withdraw`) is an address space behind the mesh, such as an office LAN
or a VPC, with its IPv4 and IPv6 prefixes and one or more router Devices. A
rule to a Site lets its source reach addresses of that Site through its
primary router ([routers and failover](#routers-and-failover)):

```json
{
  "id": "…",
  "source_device_group_id": "…",
  "destination_site_id": "…",
  "destination_prefixes": ["10.20.5.0/24"],
  "protocol": "tcp",
  "destination_port_ranges": [{"first": 443, "last": 443}]
}
```

- The source is a Device, Device Group, Identity Group or Device Tag, kept as
  a selector like any group rule.
- `destination_prefixes` is optional. Without it the rule grants the Site's
  prefixes as they are at publication; with it, the listed prefixes, each
  inside one of the Site's (otherwise 422 `route_outside_site`). The release
  keeps the granted prefixes, and `GET …/policy` returns them on every Site
  rule.
- Growing a Site does not widen its rules: publish again to grant the new
  prefixes. A Site change that drops address space active rules grant is
  refused (409 `site_prefixes_in_use`), as is deleting a Device Group,
  Identity Group or tag that such a rule selects (409, as for any rule);
  change the rules first.
- Rules to two different Sites must not grant overlapping prefixes, whatever
  their sources (409 `route_overlap`): group memberships change without a new
  publication, so any two such rules could reach the same Device, and it could
  not tell which router a packet is for. Overlapping Sites themselves are
  allowed, as long as rules grant disjoint parts.
- A Site that rules of the active policy name cannot be deleted (409
  `site_in_use`); publish a policy without them first.
- All rules to Sites of one policy grant at most 16,384 prefixes, counting a
  rule without `destination_prefixes` as all its Site's prefixes (422
  `route_prefix_limit`).
- Rules to Sites are refused with 409 `subnet_routes_disabled` while the
  deployment has `MESHTRANSIT_SUBNET_ROUTES_ENABLED` off, its default
  ([configuration](../operations/configuration.md)). Turning it off while the
  active policy holds such rules makes every publication fail until they are
  removed, so remove them first.
- The activity log reports them with `destination_kind` `site`. Simulation
  reports, per source Device, the part of a Site a proposal grants or takes
  away. Explain answers for an address inside a Site; the access graph does
  not include Sites yet.

### Routers and failover

A Site has up to 32 routers, each an active Workspace Device of the Network
that offers all the Site's prefixes, with a priority (a smaller number is
preferred) and a state, `active` or `draining`. Core elects one of them the
Site's **primary**, and every node sends the Site's traffic through it:

- Core judges each router about every 10 seconds, and at once when a router
  reports a Site failed, from the health the router reports (a router whose
  service stops reports its Sites failed as `going_away` first, so stopping
  meshd on a router moves its Sites within a second or two; a package upgrade
  that restarts meshd does not): a router that reports the Site failed (such as
  `forward_blocked`), stays silent for more than 2 minutes after it has
  reported, is draining, or can no longer serve the Site (expired, moved out of
  the Workspace, or no longer offering its prefixes) is replaced by the next
  usable router in priority order. A router that never reported health, such
  as an older client, counts as usable.
- A router that failed must be healthy for 30 seconds before it is chosen
  again. A Site with `failback` returns to a preferred router once it has been
  usable for 5 minutes; without it, the primary stays until it fails.
- When no router is usable, the Site keeps the best of the rest and its
  current primary when it is as good as any; when every router fails the
  Site's probes alike, the probe target, not the routers, is the likely
  fault, and the primary is kept.
- When Core cannot read router health, or many routers turn silent at once
  (Core or its store is the likely fault), silence and health prove nothing
  and the primary only changes when a router can no longer serve.
- Each change is recorded as `site.primary_changed` with its reason
  (`elected`, `failover`, `failback`, `degraded` or `none`) and advances the
  Network's revision, so maps follow at once.
- One Site's read (`GET …/sites/{site}`) carries `primary`: the elected
  `device_id` (null when no router can serve), its `generation`, `reason` and
  `elected_at`; it is absent before the first election, when the first active
  router by priority serves. `GET …/sites/{site}/primary-changes` lists the
  changes newest first, 10 per page by default (`limit` up to 50, `after` the
  `next_after` of the previous page), with `route.read`.
- A node that sends to a Site and hears nothing back for 5 seconds, while
  its router stopped answering its path probes and another router of the
  Site still answers, sends the Site's traffic through that router until
  Core elects again; a router that still answers keeps the Site, since the
  host in the Site may be the one that does not. This needs a direct path to
  the routers (one only reached through a relay is left to Core), and it
  goes back to Core's choice only once the Site carries no traffic for a
  minute, so a flow is not cut twice. Flows through the old router end.
- Each node reports which router it uses for each Site, and why (Core's
  primary, its own choice, or none), on change and every minute. One Site's
  read gives each router's `clients` and `local_failover_clients` (Devices
  that reported using it in the last three minutes), and a Device's status
  its `subnet_routes`; `meshctl status` shows the same on the node.
- A Site without `masquerade` has one router: the network behind it sends
  replies to a single router. Adding a second one, or turning masquerade off
  while it has two, is refused (409 `site_masquerade_requires_single_router`).

## Changing policy

A policy is replaced as a whole: there is no draft on the server. Every
change runs the same compiler that publication uses.

1. **Simulate** (`POST …/policy/actions/simulate`, `policy.validate`): the
   proposed rules compared with the active ones: local relationships added
   and removed, affected Devices and Resources, an estimate of peers per
   Device (a warning at 5,000, the limit at 10,000), and a hash of the impact.
   Rules to Imported Resources are listed separately as intent changes,
   without provider details. Their guardrail findings come in
   `guardrail_findings`, as publication applies them: this Workspace's
   guardrails by name, and the provider Workspace's only where they block,
   without any detail. `blocks` marks an enforced guardrail on a path the
   active release does not already open (publication will refuse it). Simulation does not yet
   evaluate share terms or effective access across Networks; the response
   lists what it leaves out in `unsupported_capabilities`. The impact hash
   covers the guardrail findings; an approval request expires within 10
   minutes, and publication checks guardrails again in any case.
2. **Request approval** (optional; `POST …/policy/approval-requests`,
   `policy.validate`): binds the simulated change and its impact.
3. **Approve** (`POST …/policy/approval-requests/{id}/actions/approve`,
   `policy.approve`): a different person, in a different session, approves
   exactly that change. The request, its approval and the publication that
   uses it must all happen within 10 minutes of the request.
4. **Publish** (`POST …/policy/actions/publish`, `policy.publish`): with
   `If-Match` set to the current policy revision (`"N"`). A missing revision
   is refused with 428, a stale one with 412. The result is an immutable
   **Policy Release** with the next revision and a semantic hash.

Approval is optional: a person with `policy.publish` can publish directly,
and no setting makes approval mandatory. The `approval_policy.manage`
permission is reserved and grants nothing yet. When an approval is presented,
publication checks that it matches the change exactly and uses it once. A
policy that names Imported Resources cannot go through approval yet. Every
publication, approved or not, is recorded in the activity log (see below).

At publication Core authorizes the person again, checks that every named
Device and Resource is valid, and applies the Workspace's enforced
[guardrails](identity-and-access.md#guardrails) to rules that open new paths to
shared Devices. A refused publication answers `guardrail_violation` with its
findings. The release, its audit event and the revision wakeup commit
together.

### What each publication records

Every publication, from the Console or with a bearer token, with or without
an approval, and whatever its destinations, appends one `policy.published`
event to the Network's audit stream ([audit](audit.md)) in the same
transaction as the release. The event records:

| Field | Meaning |
|---|---|
| `actor_principal_id`, `network_id` | who published, in which Network |
| `target_id` | the Policy Release |
| `before_semantic_hash`, `after_semantic_hash` | semantic hash of the replaced and the new release |
| `payload.base_policy_revision`, `payload.policy_revision` | revision replaced and revision published |
| `payload.audit_reason` | the reason given with the request |
| `payload.rule_count`, `payload.compiler_format_version` | compiled rules and compiler format |
| `payload.account_session_id`, `role_binding_id`, `role_definition_id` | the session and role that authorized it |
| `payload.approval_*`, `approver_*` | the approval used, when there was one |
| `payload.guardrail_findings` | audit-mode guardrails the change breaks; `guardrail_finding_count` and `guardrail_findings_truncated` when not all fit |
| `payload.change_summary` | which Access Rules changed |

`change_summary` compares the new release's rules with the replaced
release's. Core computes it from a fingerprint of each rule that every
release keeps; it is Core's account of the change, not something the
database derives from the stored rules.

- `added`, `removed`, `changed`, `unchanged`: counts over every rule the
  release compiled. A rule is **changed** when it keeps its ID but its
  source, destination, protocol or ports differ. A new version of a Resource
  or share behind an unchanged rule, or new members in its groups, is not a
  rule change; the semantic hashes show the first. A rule that compiles to
  nothing, such as one to a Resource Group without members, is not in the
  release, so it counts as removed and later as added again.
- `rules`: at most 20 of the changed rules (removed, then changed, then
  added, shared between the three), each with its ID, `destination_kind`
  (`device`, `device_group`, `device_tag`, `resource`, `resource_group`,
  `imported_resource` or `site`) and `destination_id`. An Imported Resource appears by
  its consumer-local ID. `truncated` is true when more rules changed, or
  when the list was shortened to keep the event within 16 KiB.
- `baseline`:
  - `none`: the Network had no release, so every rule is added;
  - `previous_release`: compared with the replaced release;
  - `unavailable`: the replaced release was published by a Core version that
    did not keep fingerprints;
  - `unreadable`: its stored fingerprints did not decode, which only a change
    made directly in the database can cause. Publication still goes ahead,
    since it may be revoking access.

  The counts are zero for the last two.

There is no rollback operation: to undo a change, publish the earlier rules
again. The semantic hash covers the rules (with their IDs) and what their
Resources and shares resolved to, so it is identical only if neither changed.

`GET …/policy` (`policy.read`) returns the active rules, at most 1,000, with
the total count and whether the list is complete, and the revision as ETag.
An Imported Resource appears only by its consumer-local ID.

| Role | Policy permissions |
|---|---|
| `admin`, `network_admin`, the owner | all |
| `auditor` | read, simulate (and so request approval), explain |
| `it_admin`, `security_admin` | read, explain |

## On the node

Core sends each node only the rules whose destination is that node: its
**packet filter**, as allowed sources, protocols and ports (MTCP §7.3).
Source lists are split at 1,024 entries, and a node takes at most 10,000
filter rules. The peers in a node's map are the Devices a rule connects it
to.

`meshd` enforces the filter at its TUN interface:

- A packet must come from a peer's address (WireGuard binds each address to
  its peer) and go to one of the node's own addresses.
- Outbound traffic to a peer is allowed and remembered; inbound traffic is
  allowed if it replies to a remembered flow or matches the filter.
- A reply must match the exact reversed tuple of a remembered flow; an ICMP
  reply must be an echo reply with the same identifier.
- Remembered flows: at most 4,096; TCP for 5 minutes (10 seconds after FIN,
  removed on RST), UDP for 30 seconds, ICMP echo for 10 seconds. An outbound
  TCP ACK alone does not create one. When the table is full, new state is not
  created.
- A rule for ICMP carries no ports; the node matches it only as the full
  port range, which is how Core sends it.
- A new filter replaces the old one at once. Remembered flows are cleared when
  the node's addresses, its peers, the rules or the aliases change, not when
  only endpoints do.
- Fragments, malformed packets (a zero TCP port, a wrong UDP length), a
  suspended Device and expired node keys fail closed.

After installing a filter the node reports its
[policy digest](../protocol/policy-digest-v1.md); Core compares it with the
digest of what it sent ([enforcement](audit.md#policy-distribution-and-enforcement)).

## Explaining access

| Operation | Needs | Answers |
|---|---|---|
| `GET …/access-graph` | `policy.read`, `device.read` | Every allowed path, optionally for one Device or protocol, page by page |
| `POST …/access-graph/actions/explain` | `policy.explain` | For a source Device, a destination (Device, Resource, Imported Resource or an address inside a Site), protocol and port: allow or deny, the rules that allow it, and why not otherwise |
| `GET …/access-graph/history` (Console private API) | `policy.read`, `device.read` | Paths at a past instant ([audit](audit.md#connection-history)) |

Explain uses the same resolver as maps. A deny says why: no published policy,
an inactive source or destination, a share that is not active yet or has
ended, or no matching rule. Every answer carries the revisions it was
computed at.

For `destination_address`, the target is the active Site whose prefixes hold
the address (`target.site_id`, context `kind` `site`); when no Site holds it
the target is `missing` and the deny reason is `target_inactive`. A path is a
rule to that Site whose source holds the Device now, whose granted prefixes
hold the address and whose protocol and ports match; it names the Site
(`destination_site_id`), the prefixes the rule grants
(`destination_prefixes`) and, as `projection_id`, the compiled route rule.
Explain answers what policy allows: whether a router of the Site is up is
shown on the Site.

## Not yet

Exit nodes and connectors are not implemented. Subnet routes reach Sites
through Linux routers. The permissions
`connector.*`, `policy.draft`, `policy.rollback` and
`approval_policy.manage` exist in the catalog without an operation.
