# Architecture overview

MeshTransit connects Devices with end-to-end encrypted WireGuard tunnels. A
control plane decides who may reach whom; nodes connect to each other
directly when they can and through a relay when they cannot.

```
                      ┌──────────────────────────────┐
     Console ───────▶ │ Core                          │ ◀── management API
     (browser)        │ api · control · worker ·     │
                      │ identity                      │
                      └──────┬──────────────┬─────────┘
                    MTCP     │              │ relay state
                  (maps)     │              │ (signed)
              ┌──────────────┴──┐       ┌───┴───────────┐
              │ node: meshd     │◀─────▶│ meshrelay     │
              │ (+ meshnetd)    │ MTRP  │ (Interchange) │
              └───────┬─────────┘       └───┬───────────┘
                      │  WireGuard, direct  │ or relayed
                      └──────────▶ peer node ◀┘
```

## Components

| Component | Code | Does | License |
|---|---|---|---|
| [Core](core.md) | `core/` | Control plane: tenancy, Devices, policy, sharing, audit; serves maps to nodes and the API to people and tools | AGPL-3.0 |
| [Client](client.md) | `client/` | `meshd` node daemon, `meshnetd` network helper, `meshcred`, `meshctl`; mobile bindings | Apache-2.0 |
| [Relay](relay.md) | `relay/` | `meshrelay`, MeshTransit Interchange: forwards encrypted traffic between nodes and answers STUN | AGPL-3.0 |
| Console | separate repository | Web interface; talks only to Core's private API | — |
| Protocol libraries | `shared/` | MTCP, MTRP, disco v2, keys, endpoint policy, policy digest, STUN, NAT classification | Apache-2.0 |
| Contracts | `api/` | MTCP schema (`api/mtcp/v1`) and the OpenAPI documents of the management and Console APIs | Apache-2.0 |

Code under `client/`, `shared/`, `api/` and `test/` never imports `core/` or
`relay/` (`make check-boundaries`), so the Apache-2.0 parts stand alone.

## Protocols

| Between | Protocol | Carries |
|---|---|---|
| Node and Core | [MTCP v1](../protocol/mtcp-v1.md) over HTTPS | Registration, key rotation, maps, endpoint and enforcement reports |
| Node and relay | [MTRP v1](../protocol/mtrp-v1.md) over UDP, TLS or WebSocket | Relayed WireGuard and disco datagrams |
| Node and node | WireGuard, [disco v2](../protocol/disco-v2.md) | Traffic; path discovery |
| Relay and Core | HTTPS long-poll | Signed relay state: trusted keys, revocations, drain |
| People and tools and Core | HTTPS JSON APIs | Management; sealed [audit records](../protocol/audit-record-v2.md) |

## Trust boundaries

- **Core is the authority.** It decides membership, policy and sharing, and
  everything it tells nodes and relays is authenticated: MTCP sessions end at
  a control key the node pinned, and relay maps, relay state and tickets are
  signed by Core's signing key. Core sees Device endpoints, NAT types and
  policy, but no traffic.
- **Relays are trusted for availability and for enforcing tickets**, not with
  data. They forward WireGuard ciphertext and encrypted disco messages, admit
  only nodes with a valid ticket, and open a route only between nodes whose
  tickets share a zone.
- **Nodes trust Core for who their peers are**, and nothing else on the
  network: every map is validated before use, endpoints that could aim probes
  at infrastructure are dropped, and inbound traffic is filtered by the
  node-reduced policy.
- **The network between them is hostile.** See the
  [threat model](../protocol/threat-model.md).

## Who holds which key

| Key | Held by | Use |
|---|---|---|
| Machine key (`mtmachine:`) | Each node installation | Authenticates the node to Core (MTCP initiator) |
| Node key (`mtnode:`) | Each node | WireGuard static key; names the Device in maps |
| Disco key (`mtdisco:`) | Each node, per session | Authenticates disco messages and relay sessions |
| Control key (`mtcontrol:`) | Core | MTCP responder; pinned by nodes |
| Signing key (`mtsign:`) | Core | Signs relay maps, relay state and relay tickets |
| Relay key (`mtrelay:`) | Each relay | MTRP responder; published in the relay map |

Private keys never leave their holder, and no key serves two purposes; see
[keys](../protocol/keys.md).

## State

- **PostgreSQL** is the only authority: Workspaces, Networks, Devices, keys,
  policy, shares and audit.
- **Redis** holds per-session state: which control replica serves a node, its
  endpoints, what it was delivered, and wakeups between replicas. Losing it
  slows convergence but never grants access.
- **Nodes** keep their identity keys encrypted at rest. Every new
  control session starts from a fresh map snapshot.
