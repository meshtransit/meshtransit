# Devices

A Device is a machine registered in one Network: a laptop, a server, a phone
or a container. This document describes how a Device is registered, owned,
renewed, suspended, handed over and removed. The protocol messages are in
[MTCP v1](../protocol/mtcp-v1.md) §6 and §10.

## Registration

A node registers over its MTCP session in one of two ways.

### Signing in from the browser

The node asks Core to register; Core answers with an approval link on the
Console's host, `/register/v1/<token>`, which `meshctl up` prints or opens. A
signed-in person opens it, picks the Workspace and Network (Core never picks
one) and approves. Approving needs no role: the person must be an active
member of the Workspace and of that Network. The node waits up to 10 minutes
on one session (the link stays valid 14 minutes); Core checks the approval
every 2 seconds and completes the registration on the same session.

Browser sign-in works only in a Network that has an active enrollment profile
with interactive sign-in enabled. Every new Network gets one, "Interactive
login": persistent Devices that expire after 30 days.

A person can register at most 20 new Devices by browser sign-in per Network
in 24 hours, revoked ones included; signing in again on an existing Device
does not count.

### Enrollment keys

An enrollment key lets a machine register without a browser, for servers and
automation. It belongs to an **enrollment profile**, which sets what the
Devices it registers become: how long they live and whether they are
persistent or ephemeral. Core accepts and consumes keys, but has no API or
Console page that issues them yet; today they are created by operator
tooling. A key:

- has the form `mtc1.<credential id>.<secret>`, with a 256-bit random
  secret; Core stores only an HMAC digest of it;
- is valid from a start time until an expiry, for a bounded or unlimited
  number of uses, never more than its profile allows;
- can be revoked; revocation is final.

A Device registered with a key is owned by the person who issued the key.
Using a key again on a Device that is already registered renews it and
consumes one use.

### What Core checks

- The node proves it holds its node key and its disco key, bound to the
  session's handshake; the two keys must differ.
- A node key belongs to one Device for the life of the Deployment: a key
  that belonged to another Device is refused, and a revoked Device's keys
  can never register again.
- The hostname must be a valid DNS name.
- Failures do not reveal other tenants: every enrollment key problem
  (unknown, expired, used up, revoked) is reported as `CREDENTIAL_INVALID`, a
  key or intent conflict as `CONFLICT`. A full Network and the sign-in limit
  above are reported as `NOT_PERMITTED`.

The node pins Core's control key before registering, from the fingerprint in
the enrollment link or given to `meshctl up`; see
[Client](../architecture/client.md#identity-and-profiles).

## Addresses and names

Each Network has one IPv4 range inside `100.64.0.0/10` and one IPv6 range
from its Workspace's overlay prefix; ranges of one Workspace never overlap. A
new Device gets the lowest free address in each range. When a range is full,
registration fails with "the Network has no free address".

A revoked Device's addresses are **quarantined for 24 hours** before they are
given to another Device, so a peer that still holds the old address cannot
reach the new owner by mistake. Suspended and expired Devices keep their
addresses until they are revoked; so do ephemeral Devices, which are not yet
removed automatically. Revoking unused Devices is how a full Network gets
addresses back.

The Device's name is its hostname, lowercase, unique in the Network. A
second Device with the same name gets the lowest free suffix (`laptop-1`).
Renaming a Device (`device.manage`) locks the name: the node's own hostname no
longer changes it. A revoked Device's name can be taken at once by a new
Device of the same owner (so signing in again after a logout keeps the name),
and by anyone after 24 hours.

## Ownership

| Ownership | Owned by | Expiry |
|---|---|---|
| **Member** | The person who registered it or issued its enrollment key, or the member it was handed over to | From its enrollment profile; renewed by signing in again |
| **Workspace** | The Workspace itself | Never |

A member's Devices take part in the member's Identity Groups. A Device with
Device Tags is matched by its tags instead, whoever owns it.

## Lifecycle

Administrators act on a Device with
`POST /api/v1/workspaces/{workspace}/networks/{network}/devices/{device}/actions/…`.
Every action needs `If-Match` with the Device's current version; `revoke` also
needs an `Idempotency-Key`. Each action writes an
[audit event](audit.md).

| Action | Permission | Effect |
|---|---|---|
| `suspend` | `device.quarantine` | An active Device loses its peers until resumed; keeps its keys and addresses |
| `resume` | `device.quarantine` | Ends an administrator's suspension, or cancels a pending handover. A Device suspended because its member is suspended resumes only with the member |
| `rename` | `device.manage` | New name, locked |
| `transfer` to the Workspace | `device.transfer` | Becomes Workspace-owned, never expires |
| `transfer` to a member | `device.transfer` | Suspended until the new member signs in on it (below). The member must be active in the Workspace and the Network; an administrator's suspension must be resumed first |
| `revoke` | `device.manage` | Removes an active Device: keys revoked, addresses quarantined |

These permissions come with the `admin` and `it_admin` roles and with
ownership of the Workspace. A node can also remove its own Device: `meshctl
logout` sends an MTCP `Logout`, which revokes an active Device like an
administrator's revoke and needs only the node's current keys.

- **Revocation reaches the node.** A connected node is told `REVOKED`; a node
  that connects later with the revoked keys is told so on connect. The node
  drops its peers, replaces the profile's machine and node keys and shows the
  profile as not registered; `meshctl login` then registers a new Device.
  Core says `REVOKED` only for the exact keys it revoked; any other key
  without authority is told `EXPIRED` and keeps its keys.

- **Expiry.** A Device whose expiry has passed loses its peers. It is renewed
  by signing in again from the browser on the same machine, with the same
  profile and keys and the same owner; the new expiry comes from the
  profile. A Workspace-owned Device never expires.
- **Handover.** The Device stays suspended until the new member signs in on
  it through the browser; that person then owns it and its expiry restarts.
- **Node key rotation.** A node can replace its node key at most 4 times an
  hour; the Device, its name and addresses stay the same. Only the session's
  proven machine key may rotate, the request names the exact old and new keys
  with a proof bound to the session, no earlier node key can ever come back,
  and the change commits with its audit event and a new session generation,
  so existing map streams are fenced.
- **Ephemeral Devices** are marked as such; they are not yet removed
  automatically.

## Members leaving

- **Suspending a member** suspends their active member-owned Devices and ends
  their Console sessions; Workspace-owned Devices keep working. Resuming the
  member resumes exactly those Devices.
- **Removing a member** applies a plan for their Devices, up to 250 entries:
  transfer to the Workspace, hand over to another member, or revoke. Devices
  the plan does not name are revoked. Their enrollment keys are revoked and
  their roles and group memberships end.

Nobody can suspend themselves or the Workspace owner, and an administrator can
act on a member only if they could grant every role that member holds.

## How a node learns

Each suspension, revocation, transfer or key rotation advances the Device's
session generation. Core rereads the Device's authority on every change of
its Network and at least every 30 seconds by default, and tells the node with
an MTCP
`Lifecycle` message:

| Device | Core sends | The node |
|---|---|---|
| Suspended | `SUSPENDED` | Drops its peers, keeps its keys, retries every 3 s for a minute, every 10 s until 5 minutes, then every 30 s |
| Expired or revoked | `EXPIRED` | Stops. An expired Device signs in again with the same keys; a revoked one cannot, and needs new keys (`meshctl logout`) before it registers again |
| Logged out | `LOGGED_OUT` | Stops; `meshctl logout` already replaced its keys |

## Limits

- A map holds at most 10,000 peers by default
  (`MESHTRANSIT_CONTROL_MAP_PEER_LIMIT`, 100 to 10,000), and 256 for a client
  that does not support large maps. When a Device may reach more, shared
  Devices come first, then online ones; the Device's status shows how many
  were sent and how many are authorized.
- A Network holds as many Devices as its address ranges allow; there is no
  separate Device quota.

## Where to see Devices

These are endpoints of the Console's private API (Account Session cookie),
not of the bearer-token management API.

| Endpoint (under `…/networks/{network}/`) | Needs | Shows |
|---|---|---|
| `devices` | `device.read` | Inventory: state, ownership, owner, expiry, suspension reason, pending handover |
| `devices/distribution` | `device.read` | Online state, the policy revision it has, enforcement, paths, NAT, peer limit; see [audit](audit.md#policy-distribution-and-enforcement) |
| `devices/enforcement-history` | `device.read` | Enforcement at a past instant |
| `address-usage` | `network.read` | Addresses used and free in the Network's ranges |
