# MeshTransit documentation

Documentation of the code in this repository: how MeshTransit is built, the
protocols its parts speak, and how they behave. New to the project? Read the
[architecture overview](architecture/overview.md) and the
[glossary](glossary.md) first.

## Architecture

| Document | For |
|---|---|
| [Overview](architecture/overview.md) | Components, protocols, trust boundaries, keys |
| [Core](architecture/core.md) | Roles, PostgreSQL and Redis, maps, relay authority, API, worker |
| [Client](architecture/client.md) | `meshd` and its helpers, privilege boundary, data plane, paths, DNS, mobile |
| [Relay](architecture/relay.md) | `meshrelay`: sessions, tickets, limits, drain |

## Concepts

How the product behaves, as implemented:

| Document | Covers |
|---|---|
| [Identity and access](concepts/identity-and-access.md) | Sign-in, sessions, Workspaces, members, invitations, roles, groups, tags, guardrails |
| [Devices](concepts/devices.md) | Registration, addresses and names, ownership, lifecycle, members leaving, limits |
| [Policy](concepts/policy.md) | Access Rules, changing policy (simulate, approve, publish), enforcement on the node, explaining access |
| [Sharing](concepts/sharing.md) | Share offers, Trust Contracts, Imported Resources, Device aliases, ending a share |
| [DNS](concepts/dns.md) | What resolves, how the resolver answers, wiring into each platform, limits |
| [Paths and relays](concepts/paths-and-relays.md) | A node's addresses, what peers learn, finding a direct path, relays, Private Interchange |
| [Audit and evidence](concepts/audit.md) | What is recorded, reading the history, connection history, policy distribution and enforcement |

## Protocols

Language-independent specifications, with test vectors: see
[protocol/README.md](protocol/README.md). The main ones are
[MTCP v1](protocol/mtcp-v1.md) (node and Core),
[MTRP v1](protocol/mtrp-v1.md) (node and relay),
[disco v2](protocol/disco-v2.md) (path discovery) and
[audit record v2](protocol/audit-record-v2.md).

## Client

[Security model](client/security-model.md),
[platform contracts](client/platform-contracts.md),
[Linux packaging](client/linux-packaging.md) and
[Linux qualification](client/linux-qualification.md).

## Core

[Device sharing deployment gate](core/design/device-sharing-deployment-gate.md):
the checks before enabling sharing on a deployment.

Component READMEs: [`core/README.md`](../core/README.md) (configuration),
[`client/README.md`](../client/README.md),
[`relay/README.md`](../relay/README.md).

## Writing docs

- English, for someone who knows networking but not this code base.
- Describe what the code does now. A change to behaviour updates its document
  in the same commit.
- One topic has one home; elsewhere, link to it instead of repeating it.
  Protocol specifications are normative; other documents describe how the
  system uses them.
- No dated test records, evidence, deployment details, internal ticket or
  milestone names, or real addresses: use the documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`)
  and `example.com`.
- Every link must resolve: `make check-boundaries` runs
  `hack/check-doc-links.sh`.
