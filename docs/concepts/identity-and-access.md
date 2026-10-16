# Identity and access

How people sign in to MeshTransit, how Workspaces and their members are
managed, and how Core decides what each person may do. Devices are covered in
[devices](devices.md), packet access in [policy](policy.md).

## Signing in

People sign in with OpenID Connect; Core never stores passwords. Core is a
confidential OIDC client and accepts only RS256 ID tokens. Two setups exist:

- **Embedded broker.** The `identity` role runs an OIDC broker in front of the
  upstream provider. Its only supported upstream is Google, and it always asks
  the person to choose an account, so signing out lets someone else sign in.
- **Direct.** Core points at an issuer itself.

The login flow lives under `/auth/v1/` on the Console's host, with the fixed
callback `/auth/v1/callback`.

What Core keeps about a person:

- the provider's subject only as a keyed HMAC digest, never in clear;
- a display name, set once when the Account is created: from a self sign-up,
  the provider's name, else the verified email, else "MeshTransit user"; from
  an invitation, the verified email as the provider spells it (the invited
  address when that is longer than 128 characters); from a bootstrap plan, the
  plan's name.

Core does not store a person's email as an attribute, and an email never
identifies or links anyone. Only invitations keep the address they were sent
to, and an invitation is accepted only by a sign-in whose provider verified
that address.

Every Workspace and Network also has a **display code** of twelve digits,
for example in the names of shared Devices.

### Self sign-up

On a Cloud deployment, `MESHTRANSIT_SELF_SIGNUP_ENABLED=true` lets a person
who signs in for the first time get an Account and a Workspace of their own,
named after their display name. It needs a current entitlement with room for
another Workspace, and is rate-limited: by default 5 sign-ups a day per source
network (the client's IPv4 `/24` or IPv6 `/48`, kept only as a keyed digest)
and 30 an hour per deployment.

A self-hosted deployment starts from a bootstrap plan instead
(`meshcore bootstrap apply`), which creates the first Accounts and their
Workspaces.

## Sessions

Signing in creates an **Account Session**, an opaque token
(`mtas1.<deployment>.<recovery epoch>.<secret>`).

- **Lifetime:** it expires 1 hour after sign-in unless renewed, and at most
  24 hours after sign-in. Only the Console's activity check renews it, never
  past the absolute expiry; a session used only by a tool lasts 1 hour.
- **Console:** the token is in the `__Host-mt_session` cookie (`Secure`,
  `HttpOnly`, `SameSite=Lax`). Every change also needs a short-lived CSRF
  proof from `/auth/v1/session/prepare` in `X-Meshtransit-Csrf`, an `Origin`
  equal to the Console's and `X-Meshtransit-Session: v1`. If any
  `Sec-Fetch-*` header is sent, all three must be present and say
  `same-origin`, `cors` and `empty`.
- **Tools:** the management API takes the same token as
  `Authorization: Bearer`. Its OpenAPI document,
  `api/openapi/management_v1.json`, does not yet list every operation it
  serves. Reads that only the Console uses, such as the Device inventory and
  distribution, need the Console session.
- **Workspace:** a session works in one Workspace at a time and can switch to
  another one of the person's Workspaces without signing in again. At sign-in
  Core picks the Workspace of the last session, else one the person owns,
  else their oldest membership.
- **Ending:** signing out ends that session. **Sign out everywhere**
  (`POST /auth/v1/session/logout-all`, in the Console's account menu) ends
  every session of the Account in every Workspace, including the current
  one; Devices keep working. Suspending or removing a member ends their
  sessions in that Workspace.
- **An administrator** with `member.manage` can end the sessions a member
  signed in to their Workspace
  (`POST /api/v1/workspaces/{workspace}/members/{member}/actions/revoke-sessions`,
  with a reason). Sessions the member signed in to other Workspaces stay, and
  the member can sign in again; suspending the member is what cuts them off
  in the Workspace.
- **The operator** can end every session of an Account, or quarantine it,
  with `meshcore account` ([deployment](../operations/deployment.md#accounts)).

## Workspaces

A **Workspace** is an organisation: its owner, members, roles, Networks,
address space, guardrails and audit history.

- **Creating one** (`POST /api/v1/workspaces`) is open to any signed-in
  person within the deployment's entitlement: a limit on active Workspaces and
  on Workspaces owned per Account. Without an entitlement no Workspace can be
  created this way; the bootstrap plan creates them.
- A new Workspace gets its owner membership, its own overlay address space
  (IPv4 and IPv6) and its audit stream.
- **The owner** is one Principal. Only the owner renames the Workspace. Owner
  transfer and Workspace deletion have permissions in the catalog but no
  operation yet.

### Members and invitations

People join a Workspace by invitation (`member.invite`):

- An invitation goes to an email address, may carry one Workspace role up to
  what the inviter may grant, and is valid for 7 days. A Workspace has at
  most 200 pending invitations, one per address; a resend waits at least a
  minute.
- **The link and the address together are the proof.** The person must
  complete sign-in with the link through a provider that verifies the
  invited address: the provider's verified email must equal it, ignoring
  ASCII letter case only. Invited addresses are ASCII, so a verified address
  with any other character is refused rather than folded. A sign-in that
  proves another address, or none, fails;
  the invitation stays pending and nothing is created, so the right person
  can still use it. The link works once.
- The address only narrows who may use the link. The provider's subject
  still decides who the person is.
- A person without an Account gets one on acceptance; an existing member
  keeps their membership and gains the role; a suspended member is refused.
- A new member joins every Network that is active at acceptance. A Network
  created later starts with only its creator as a member; others are added
  to it as described in [Network members](#network-members).

Members are suspended, resumed and removed with `member.manage`; what happens
to their Devices is described in [devices](devices.md#members-leaving).
Nobody can suspend, sign out or remove themselves or the owner, and an administrator
can act on a member only if they could grant every role the member holds.

### Network members

Being a member of a Network lets a Workspace member enroll Devices into it
from the browser and receive Devices handed over in it. It grants no packet
access and no management permission; those come from policy and roles.
`network.member.manage` changes a Network's members. The owner, `admin` and
`it_admin` hold it; an `it_admin` bound to one Network manages only that
Network's members.

- **Listing** (`GET /api/v1/workspaces/{workspace}/networks/{network}/members`,
  `network.read`) pages the Workspace's members, up to 200 at a time ordered
  by principal ID, each with their membership of the Network or none, and
  says whether the caller can change them. Members of the Network are always
  listed; the rest of the Workspace only to a caller who can add them or read
  the Workspace's members (`member.read`).
- **Adding** (`POST .../members` with `principal_ids`, up to 150
  at once) adds active Workspace members; anyone already in the Network is
  reported unchanged. A suspended Workspace member cannot be added. Maps are
  not rebuilt: membership decides who may enroll, not who can reach whom.
- **Removing** (`POST .../members/{member}/actions/remove` with a reason and
  a Device plan) handles the member's Devices in that Network as a Workspace
  removal does (see [devices](devices.md#members-leaving)), revokes the
  enrollment keys they issued for it and their roles bound to it (built-in
  and custom), and ends the membership. Their Workspace membership,
  Workspace roles, Identity Groups, other Networks and sessions are
  untouched.
- **What removal does not take away.** A Workspace-scope role still applies
  to the Network: a Workspace `it_admin` removed from a Network can still
  manage its Devices and issue enrollment keys for it. A browser registration
  the member started but nobody approved yet stays pending; approving it is
  refused, because approval needs a current Network membership.
- **Who may remove whom.** Nobody removes the owner or themselves. The actor
  must outrank each role the member holds in its own scope: a Workspace-scope
  role needs the owner or a Workspace-scope `admin` or `it_admin` who could
  grant it; a role bound to this Network may also be outranked by the
  actor's own `admin` or `it_admin` role bound to this Network (never to
  another Network); and a custom role binding of the Network needs a
  Workspace-scope assigner. So an `it_admin` bound to one Network removes
  members whose only roles are bound to that Network, but not a holder of a
  Workspace-scope role.

## Roles and permissions

Every operation needs one exact permission in one exact scope: the
Deployment, a Workspace, or one Network of a Workspace. There are about 80
permissions, such as `device.manage`, `policy.publish` or `audit.export`.
Permissions come from roles:

| Role | Scope | Assigned by |
|---|---|---|
| `admin` | Workspace | owner, `admin` |
| `security_admin` | Workspace | owner, `admin` |
| `billing_admin` | Workspace | owner, `admin`, `it_admin` |
| `it_admin` | Workspace or one Network | owner, `admin`, `it_admin` |
| `network_admin` | Workspace or one Network | owner, `admin`, `it_admin` |
| `auditor` | Workspace or one Network | owner, `admin`, `it_admin` |

- Only holders bound to the whole Workspace assign roles.
- A role assignment can expire. Nobody changes their own roles, and the owner
  holds no role assignment.
- In short: `it_admin` manages members (including each Network's members,
  `network.member.manage`), Devices (`device.manage`, `device.transfer`,
  `device.quarantine`), enrollment and groups;
  `network_admin` manages Networks' settings, DNS, Device Groups, policy,
  Resources and shares; `auditor` reads everything and exports audit;
  `admin` holds both administrators' permissions and more.
- **The owner** needs no role: they hold every Workspace permission and every
  Network permission in the Workspace's Networks, but no Deployment
  permission.
- A role bound to one Network never administers the Workspace.

### How a request is authorized

Core resolves the permission in PostgreSQL at the moment of the request, in
the same transaction as the change. The check covers the session (its
version, idle and absolute expiry), the Account, the identity provider, the
Workspace and Network, and the membership with its validity window. Anything
missing means denied. Row-level security then limits the transaction to the
exact Workspace and Network.

The permissions the Console receives only decide what it shows; every change
is authorized again by Core.

## Groups and tags

- **Identity Groups** are named sets of Workspace members (up to 500 groups
  and 10,000 members), used as rule sources. A member's untagged Devices take
  part in the member's groups.
- **Device Tags** come from a Workspace catalog. A tagged Device is a service
  Device: it matches rules by its tags only, never by its owner's groups. A
  tag's owners (Identity Groups or roles; the Workspace owner owns every tag)
  may apply it to Devices they own or manage; `device_tag.manage` applies any
  tag.

Membership of groups and tags is resolved when maps are built, so a change
reaches nodes without republishing policy.

## Guardrails

**Guardrails** are Workspace-wide limits on what crosses Networks: Network
isolation, Network sharing and external sharing. Each runs in audit mode
(recorded) or enforce mode (refused). An enforced guardrail refuses share
offers, acceptances and Trust Contract activations, and policy publications
whose rules reach shared or imported Devices, whoever makes the change; rules
inside one Network are not affected. Closing access is never refused.

An enforced guardrail is also retroactive for shares: every existing share it
blocks is cut from the maps of both sides, while the share and its Trust
Contract stay as they are. Switching the guardrail to audit mode, loosening it
or deleting it puts the shares back. A policy publication still keeps paths
its release already had; maps leave out the ones a guardrail blocks. Saving
a guardrail in enforce mode therefore needs a preview first:
`POST /api/v1/workspaces/{workspace}/guardrails/actions/preview` with the
create or update body (and `guardrail_id` with `expected_version` for an
update) returns the shares the save would cut that no guardrail cuts yet
(listed up to 256, with `affected_count`) and an `impact_hash`. The create or
update sends that `impact_hash`; when the shares it cuts changed in between,
the save is refused with `guardrail_impact_changed` (409). In audit mode the
preview lists the shares the guardrail would report and the save needs no
hash; deleting never needs one. The preview needs `guardrail.manage` or
`guardrail.weaken`. A Workspace with more than 20,000 active shares cannot
preview or save a guardrail whose result is in enforce mode, not even to
loosen it; it can switch the guardrail to audit mode or delete it, which
needs no preview. A share offered, accepted or enabled while a guardrail of
either Workspace of the share is being saved fails as a retryable conflict;
a guardrail save that a share changed under is redone by Core up to three
times, then fails with `version_conflict`; retrying either is safe
([limits](../operations/limits.md#product)). A save in enforce mode advances
the Network revision of both sides of each share it cuts or restores;
switching an enforced guardrail to audit mode or deleting it advances the
Networks of the shares of the Networks it named (at most 1,024 at once; the
others follow at the next map reconcile interval). Each advanced Network
records the change on its audit stream, so connected Devices receive new
maps.

Across Workspaces, each side's guardrails apply. When the consumer accepts an
offer, activates its Trust Contract or publishes rules to the Imported
Resource, the provider Workspace's guardrails are checked too, so a provider
can stop a share it already offered. The consumer then gets only
`counterpart_guardrail_violation` (409), which names nothing of the provider's
guardrails. The provider's audit-mode findings on an acceptance or activation
are recorded in the provider Network's audit record of that change, never the
consumer's; on a publication they are not recorded. Adding or narrowing a
guardrail needs `guardrail.manage`; loosening one needs `guardrail.weaken`,
held by the owner, `admin` and `security_admin`.
