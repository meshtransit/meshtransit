# Glossary

Terms as MeshTransit uses them, in alphabetical order.

**Access Rule.** One directional allow: a source (Devices, a Device Group, a
Device Tag or an Identity Group) may reach a destination on given protocols
and ports. Everything not allowed by a rule is denied.

**Account.** A person who can sign in. An Account is a Principal of kind
`account`.

**Account Session.** The proof that a person signed in: an opaque token with
an idle and an absolute expiry. The Console carries it in a cookie; tools send
it as a bearer token.

**Approval.** A two-person check before a policy change is published: one
person proposes a simulated change, another approves exactly that change.

**Audit event.** The record of one change, sealed into its stream's hash
chain. See [audit records](protocol/audit-record-v2.md).

**Console.** The web interface to Core. It uses Core's private API with an
Account Session cookie.

**Control key.** Core's MTCP key. A node pins it when it first trusts a
deployment and accepts only that key, or the next key Core announces.

**Core.** The control plane. See [Core](architecture/core.md).

**Deployment.** One installation of MeshTransit, with its own Core, keys and
data. A deployment runs the **Cloud** profile (many Workspaces, limited by a
signed entitlement) or the **self-hosted** profile (one Workspace unless an
entitlement allows more).

**Device.** A machine registered in a Network: a laptop, server, phone or
container. It has an owner (a member, or the Workspace itself), a hostname,
overlay addresses, an expiry and its keys. See [devices](concepts/devices.md).

**Device alias.** The address under which a shared Device and its consumers
see each other, so neither side learns the other's real overlay address and
both may even use the same addresses. A **Resource Alias** is the shared
Device as the consumer sees it; a **Consumer Source Alias** is a consumer
Device as the shared Device sees it. Aliases come from the Deployment's alias
pools, outside every Workspace's overlay space. Core allocates them and
issues the grant; the two nodes translate packets. See
[Device alias v1](protocol/device-alias-v1.md).

**Device Group.** A named set of Devices of one Network, used in Access Rules.
Membership is resolved when maps are built, so changing a group does not
republish rules.

**Device Tag.** A label from the Workspace's catalog applied to Devices. A
tagged Device is a service Device: it matches rules by its tags, not by its
owner's groups.

**Disco key.** A node's per-session key for path discovery (disco v2) and
relay sessions.

**Endpoint.** An IP address and UDP port where a node may be reachable
directly. Nodes report their endpoints to Core, which passes them to the
node's peers.

**Enrollment key.** A secret that lets a new Device register without a
browser sign-in. It belongs to an enrollment profile, which sets what such
Devices become (their lifetime, persistent or ephemeral).

**Guardrail.** A Workspace-wide rule set by the owner that blocks risky
changes; it can only narrow what policy allows.

**Home relay.** The relay region a node keeps a session with, so peers can
always reach it through the relay.

**Identity Group.** A named set of Workspace members, used as the source of
Access Rules. A member's untagged Devices take part in the member's groups.

**Interchange.** The relay service, `meshrelay`. See [Relay](architecture/relay.md).

**Machine key.** A node installation's key for MTCP. It identifies the
installation to Core.

**Map.** What Core tells a node: the node itself, the peers it may reach, its
packet filter, DNS settings and the relay map. A node receives a **snapshot**
and then **deltas**.

**MeshTransit DNS.** The resolver in `meshd` that answers names of the mesh;
today the names of shared Devices. See [DNS](concepts/dns.md).

**Network.** The unit of connectivity inside a Workspace: an overlay address
range, its Devices, policy and DNS. Devices in different Networks are isolated
unless a share connects them.

**Network revision.** A number that grows with every committed change of what
a Network's nodes see. Maps list the revisions they reflect.

**Node.** The client running on a Device (`meshd`), or the Device as the
protocol sees it.

**Node key.** A node's WireGuard key. It names the Device in maps and can be
rotated.

**Overlay address.** A Device's address inside its Network. A Workspace owns
an overlay space (`100.64.0.0/10` and an IPv6 prefix under `fd00::/8`) and
divides it into its Networks' ranges.

**Packet filter.** The policy of one node: the rules that let traffic in,
reduced from the Network's policy to what concerns the node.

**Policy.** The Access Rules of a Network. A change is published as an
immutable **Policy Release**, optionally after a simulation and an approval.
See [policy](concepts/policy.md).

**Principal.** Anyone who can act: an Account (a person) or a service
identity.

**Private Endpoint.** The consumer-side address and name through which a
shared Device is reached.

**Private Interchange.** Relays a Workspace runs itself and offers to some of
its Networks; their nodes prefer them over shared relays.

**Relay map.** The signed list of relay regions and nodes that Core sends to
nodes in their maps.

**Relay region.** A group of relay nodes in one place; a node fails over
between the nodes of a region.

**Relay ticket.** A short-lived token, signed by Core, that lets one node use
the relays. It names the node's keys and its zones.

**Resource.** Something a policy or a share can name as a destination;
today, a Device. A **Resource Group** is a fixed set of Resources.

**Role.** A named set of permissions bound to a Principal on a Workspace or on
one Network, such as `admin`, `network_admin` or `auditor`. The Workspace
owner needs no role for Network administration: ownership grants every
Network-scoped permission in the Workspace's Networks.

**Share.** An offer from one Network to another, in the same or another
Workspace, to reach one Device on given protocols and ports. A **share offer**
is accepted or declined once; acceptance creates a **Trust Contract**. See
[sharing](concepts/sharing.md).

**Trust Contract.** The agreement that lets a consumer Network reach a shared
Device: both sides' consent, the terms and an expiry. Either side can revoke
it.

**Workspace.** An organisation: its members, roles, Networks, address plan,
guardrails and audit history. Overlay ranges of its Networks never overlap.

**Zone.** What a relay checks before opening a route: a Network or a Trust
Contract that both nodes' tickets name.
