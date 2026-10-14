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
  an invitation, the invited address; from a bootstrap plan, the plan's name.

Core does not store a person's email as an attribute, and an email never
identifies, links or authorizes anyone. Only invitations keep the address
they were sent to.

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
- **Ending:** signing out revokes the session. Suspending or removing a
  member ends their sessions in that Workspace.

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
- **The link is the proof.** Whoever completes sign-in with it joins the
  Workspace; the invited address is not compared with the person's email.
  Treat an invitation link like a password. It works once.
- A person without an Account gets one on acceptance; an existing member
  keeps their membership and gains the role; a suspended member is refused.
- A new member joins every Network that is active at acceptance. A Network
  created later has only its creator as a member; no operation adds members
  to an existing Network yet.

Members are suspended, resumed and removed with `member.manage`; what happens
to their Devices is described in [devices](devices.md#members-leaving).
Nobody can suspend or remove themselves or the owner, and an administrator
can act on a member only if they could grant every role the member holds.

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
- In short: `it_admin` manages members, Devices (`device.manage`,
  `device.transfer`, `device.quarantine`), enrollment and groups;
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
inside one Network are not affected. It is not retroactive: it does not cut
existing paths, and closing access is never refused. Adding or narrowing a
guardrail needs `guardrail.manage`; loosening one needs `guardrail.weaken`,
held by the owner, `admin` and `security_admin`.
