# Sharing

A Network can share one of its Devices with another Network, in the same
Workspace or in another one, so that chosen Devices of the other Network can
reach it on chosen protocols and ports. Neither side learns the other's
addresses, and either side can end the share. Rules inside one Network are in
[policy](policy.md).

## The parts

| Part | Side | What it is |
|---|---|---|
| **Resource** | provider | The Device to share, as a policy destination |
| **Share offer** | provider → consumer | An invitation to one consumer Network: the Resource, the most traffic allowed, an expiry and a name label |
| **Trust Contract** | both | The accepted offer: the terms both sides agreed to |
| **Imported Resource** | consumer | The shared Device as the consumer's policy sees it |
| **Private Endpoint** | consumer | The addresses and name the consumer reaches it at |

A share needs three decisions: the provider offers, the consumer accepts and
activates, and the consumer publishes a rule that lets its own Devices reach
the Imported Resource. Until all three exist, no packet flows.

## Offering

The provider first makes the Device a **Resource** (`resource.manage`). With
`share.offer` it then finds the consumer Network by its twelve-digit display
code (`GET …/share-targets/{code}`, which reveals only identifiers and codes,
never names) and creates an offer for it. The offer states:

- **Maximum traffic:** `tcp`, `udp` and `icmp`, with up to 64 port ranges for
  TCP and UDP; Core merges it into one entry per protocol. The consumer's
  rules can only narrow it.
- **Expiry:** a time at most 30 days ahead, or never. An offer that is not
  decided expires with the share's deadline, or after 7 days for a share that
  never expires.
- **Access label:** one DNS label, by default derived from the Resource's
  display name. It names the share for the consumer (below), is frozen in the
  offer, and within the provider Network names only that Resource.

The offer comes with a one-time **offer token**, returned only in the
response that creates it; the provider passes it to the consumer, who needs
it to decide. Core keeps only a digest. Changes take an `Idempotency-Key`;
decisions on an existing offer or contract also take its version in
`If-Match`.

## Accepting

The consumer (`share.accept`) accepts or rejects the offer once. Accepting
creates the Trust Contract and the Imported Resource, with a display name
unique in the consumer Network. A Device can have only one live contract into
a given Network: a second acceptance is refused with `device_already_shared`.
The consumer then **activates** the contract, which reserves the Resource
Alias and prepares the Private Endpoint; the Consumer Source Aliases are
reserved afterwards by the Device alias worker, for the consumer Devices the
consumer's rules let through.

For a share between Workspaces, each Workspace gives its own consent with its
own authority. [Guardrails](identity-and-access.md#guardrails) are checked when
a change is made: the provider's when the offer is created, and both the
consumer's and the provider's when it is accepted, activated, and when the
consumer publishes new rules that reach it. An enforce-mode guardrail of
either Workspace also applies to shares that already exist: while it blocks a
share, Core leaves that share out of both sides' maps (no peer, alias or rule),
and puts it back once the guardrail is switched to audit mode, loosened or
deleted. The share itself, its Trust Contract and the consumer's published
rules stay as they are; a policy release keeps the existing paths, which maps
leave out.

The consumer reaches the shared Device by name:

```
<label>.<provider Workspace code>.<provider Network code>.shared.<suffix>
```

The suffix is the deployment's DNS suffix, `mesh.internal` unless it sets
another ([DNS](dns.md)); the API shows the name the same way. The codes are
the provider's display codes, so a name always says where the Device lives. Names are only for finding the Device; authorization is the
contract and the rules.

## Addresses: Device aliases

Both Networks may use the same overlay addresses, and neither should learn the
other's. So the two sides never see each other's real addresses; they see
**aliases** from the Deployment's alias pools, which lie outside every
Workspace's overlay space:

- the **Resource Alias**: the shared Device as the consumer sees it;
- a **Consumer Source Alias** for each consumer Device that reaches it: that
  Device as the shared Device sees it.

Core allocates aliases (the lowest free address, unique among the Networks
involved) and sends each node an **alias grant** with its peer. The two nodes
translate addresses in each packet. Core never carries the traffic, and a
relay that carries it when there is no direct path sees only WireGuard
ciphertext. A receiving Network can narrow the range its Resource Aliases come from.
An alias that is released is quarantined for at least 24 hours before reuse.
When a consumer Device stops being allowed (suspended, expired, or its session
or keys changed), Core withdraws its grant and quarantines its Consumer Source
Alias; once the Device is active again on current keys, still a rule source and
its client has reconnected, it gets a new Consumer Source Alias and the grant
returns.
The grant and how nodes apply it are specified in
[Device alias v1](../protocol/device-alias-v1.md).

On the node the traffic follows the contract strictly: the consumer may open
connections to the shared Device on the granted services, the shared Device
may only reply. The provider's filter sees the Consumer Source Alias as source.

## What a consumer Device may reach

The consumer's rules name the Imported Resource as destination. A packet
passes only within all of:

- the provider's maximum traffic in the contract;
- the consumer's rule;
- the contract and endpoint lifetimes, and both Devices' key expiries.

Map building rechecks the rule against the current contract, so ending the
contract ends the path without changing policy. An Imported Resource cannot
be shared on: a consumer cannot offer it to a third Network.

## Ending a share

- The provider can withdraw an undecided offer (`share.revoke`).
- Either side can revoke the contract (`share.revoke` on its side). This is
  final.
- An expired contract stops traffic at its deadline. A worker (off by default,
  `MESHTRANSIT_CONTRACT_EXPIRY_WORKER_ENABLED`) then finalizes it and frees its
  name for reuse.

Every decision is recorded in both Networks' audit streams; the other side's
record names the relation but not the acting side's reason or session
([audit records](../protocol/audit-record-v2.md#6-sharing-decisions)).

## API

Under `/api/v1/workspaces/{workspace}/networks/{network}/`:

| Operation | Side | Permission |
|---|---|---|
| `GET share-targets/{code}` | provider | `share.offer` |
| `GET`, `POST share-offers`; `GET share-offers/{id}` | provider | `share.read`, `share.offer` |
| `POST share-offers/{id}/actions/accept`, `…/reject` | consumer | `share.accept` |
| `POST share-offers/{id}/actions/revoke` | provider | `share.revoke` |
| `GET trust-contracts/{id}` | consumer | `share.read` |
| `POST trust-contracts/{id}/actions/activate` | consumer | `share.accept` |
| `POST trust-contracts/{id}/actions/revoke` | either | `share.revoke` |

`admin`, `network_admin` and the owner hold all four permissions;
`it_admin`, `auditor` and `security_admin` can read.

## Limits

| Limit | Value | Checked |
|---|---|---|
| Live shares into one Network | 10,000 | at acceptance (`share_limit_reached`) |
| Live shares of one Device | 10,000 | at acceptance |
| Services in one grant | 64 | when maps are built |
| Shared peers in one map | 10,000, or 256 for a node without large-map support | when maps are built |

These limits, the 10,000 Imported Resources per policy and the
one-contract-per-Network check need the database functions that the
operator step of the
[Device sharing deployment gate](../core/design/device-sharing-deployment-gate.md)
grants; without it Core keeps the earlier limits (256 Imported Resources per
policy).

## Turning it on

Sharing with aliases needs, on the deployment:

- the operator step and checks of the
  [Device sharing deployment gate](../core/design/device-sharing-deployment-gate.md);
- the alias pools, created once with `core/tools/operator/devicealiaspools`.
  Place them in `198.18.0.0/15` (IPv4) and under `fd00::/8` (IPv6): the client
  installs routes only there, although the tool does not enforce it;
- `MESHTRANSIT_DEVICE_ALIASES_ENABLED=true` on the control role;
- the Device alias worker (`MESHTRANSIT_DEVICE_ALIAS_WORKER_ENABLED`, with
  `MESHTRANSIT_DEVICE_ALIAS_DEPLOYMENT_PUBLIC_ID`) and the contract expiry
  worker on the worker role;

and on the nodes `--enable-data-plane` and `--enable-device-aliases`, which
the packages set.
