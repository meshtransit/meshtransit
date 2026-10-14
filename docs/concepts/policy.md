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
| Destination | one Device, Device Group, Device Tag, Resource, Resource Group or Imported Resource |
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

### When selectors are resolved

- **Resources** resolve to their Device, and **Resource Groups** to their
  member Resources, when the policy is published.
- **Device Groups, Identity Groups and tags** are kept as selectors and
  resolved every time a map is built. Adding a Device to a group, tagging it,
  or a member joining an Identity Group changes what nodes get at once,
  without publishing the policy again.
- Rules may keep naming suspended or expired Devices; they take effect again
  when the Device does. A new rule cannot name a revoked Device
  (`device_unavailable`).

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

## Changing policy

A policy is replaced as a whole: there is no draft on the server. Every
change runs the same compiler that publication uses.

1. **Simulate** (`POST …/policy/actions/simulate`, `policy.validate`): the
   proposed rules compared with the active ones: local relationships added
   and removed, affected Devices and Resources, an estimate of peers per
   Device (a warning at 5,000, the limit at 10,000), and a hash of the impact.
   Rules to Imported Resources are listed separately as intent changes,
   without provider details. Simulation does not yet evaluate guardrails,
   share terms or effective access across Networks; the response lists what
   it leaves out in `unsupported_capabilities`.
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

Approval is not required today: a person with `policy.publish` can publish
directly. When an approval is presented, publication checks that it matches
the change exactly and uses it once. A policy that names Imported Resources
cannot go through approval yet.

At publication Core authorizes the person again, checks that every named
Device and Resource is valid, and applies the Workspace's enforced
[guardrails](identity-and-access.md#guardrails) to rules that open new paths to
shared Devices. A refused publication answers `guardrail_violation` with its
findings. The release, its audit event and the revision wakeup commit
together.

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
| `POST …/access-graph/actions/explain` | `policy.explain` | For a source Device, a destination (Device, Resource or Imported Resource), protocol and port: allow or deny, the rules that allow it, and why not otherwise |
| `GET …/access-graph/history` (Console private API) | `policy.read`, `device.read` | Paths at a past instant ([audit](audit.md#connection-history)) |

Explain uses the same resolver as maps. A deny says why: no published policy,
an inactive source or destination, a share that is not active yet or has
ended, or no matching rule. Every answer carries the revisions it was
computed at.

## Not yet

Subnet routes, exit nodes and connectors are not implemented: nodes accept
only routes to Devices' own addresses inside the overlay. The permissions
`route.*`, `connector.*`, `policy.draft`, `policy.rollback` and
`approval_policy.manage` exist in the catalog without an operation.
