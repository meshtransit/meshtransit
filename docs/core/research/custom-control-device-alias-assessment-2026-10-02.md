# Device alias interoperability assessment

Assessment date: 2026-10-02. This is a source-boundary inspection, not a live
packet qualification or proof that either deployment enables cross-Workspace
sharing.

## Pinned evidence

- Read-only custom Headscale reference:
  `412b020d50ac18e1a5b2ba54da07b1aa1d7ac0e5`.
- MeshTransit client inspection baseline:
  `f60e40e8a1a9d3d83a5ce10b7b7dec25fbcfe885`.
- Implemented client alias checkpoint:
  `bbe1ec7b77ea35e7217e53694bbe9f5201d82d89`.
- Client legacy-protocol dependency: a pinned third-party library, since removed (P6).
- Core runtime baseline: `a70546e`; documentation baseline:
  `44cb533be5c378573f85db8cf50b01029ad6a998`.

## Reference wire observations

The reference mapper's shared-Device output retains the actual Device key and
projects exact peer host addresses. For a cross-tenant pair, it uses per-peer
self-address masquerade fields rather than an additional gateway peer:

- `SelfNodeV4MasqAddrForThisPeer` describes the local source address visible to
  that peer.
- `SelfNodeV6MasqAddrForThisPeer` supplies the analogous IPv6 behavior when a
  different local address is needed.
- Peer `Addresses` and `AllowedIPs` contain the address visible to that viewer.
- The provider receives the directional inbound filter; the consumer receives
  the shared destination and an exact DNS route rather than a remote zone.
- The reference gates IPv4 masquerade at capability 59 and working IPv6
  masquerade at 104.

Evidence locations: `hscontrol/mapper/device_share.go` and the assertions in
`hscontrol/mapper/device_share_test.go`. These files were inspected read-only.
No reference code, test, SQL, type or schema was copied into Core or the client.
The pinned legacy library's per-peer Node documentation independently defines
masquerading as local-source translation limited to that peer.

The reference's reverse IPv6 observation keeps the consumer's canonical IPv6
address. It is not evidence for two independently overlapping IPv6 address
realms. MeshTransit must qualify that case with its own two-sided alias contract.

No reference tests, oracle service or real cross-Workspace traffic were run for
this assessment. Source and test assertions indicate intended wire output;
black-box qualification remains a delivery gate.

## Previous client gap (inspection baseline)

The legacy client adapter (since removed) copied identity, host addresses,
routes, endpoints and expiry. It did not transfer either per-peer masquerade
field into the product-owned Node.

`internal/dataplane/observed_tun.go` performs packet policy checks and observation
around TUN reads/writes. It has no alias translation stage. The policy gate
requires canonical self ownership and mapped peer ownership. The Linux factory
wraps this TUN directly in the WireGuard device; there is no hidden compatibility
client that supplies masquerading on its behalf.

Therefore ordinary meshd login/packet compatibility with this control reference
must not be described as qualified cross-Workspace alias compatibility. Sending
only peer alias addresses to that baseline client cannot implement the required
source rewrite or return path. A numeric capability of 142 does not prove that
missing code exists.

## Implemented client checkpoint

Client commit `bbe1ec7` adds the independently specified v1 grant model, strict
adapter decoding, per-peer atomic packet translation and engine replacement
fencing. Exact keys, generation/revision/recovery, direction, service lists,
local/remote address ownership and exclusive deadlines are validated. Legacy
self-alias fields without the new grant are rejected. The feature is not yet
advertised by clients or delivered by Core.

Eight synthetic checksum vectors and six two-client roundtrip vectors cover
both IP families with identical canonical addresses, TCP, UDP and ICMP echo.
Tests cover raw destinations, spoofed sources, reverse initiation, grant expiry,
revoke, replacement, full flow state and concurrent maps. Whole-tree race/vet/
lint pass. Packet fuzzing completed 1,527,250 executions after retaining and
fixing an invalid-original-address regression; strict grant fuzzing completed
69,943 executions. Client tree/history secret checks are clean. These tests
qualify the owned synthetic contract; they do not prove real encrypted sharing
or parity with the isolated legacy oracle.

The client contract and remaining gates are documented in its `docs/device-alias.md`.
Outbound alias flow reporting is a known gap: observers see the translated
source, which the current reporter does not index. Core allocation/quarantine,
client admission, bilateral map delivery/wakeups, real encrypted isolation and
imported DNS remain unfinished. Current Core work adds only a pure bounded
allocation proposal, with no runtime lease or authority changes.

## Product decision

For Device sharing, both participating meshd processes perform peer-specific
translation and enforcement. Core supplies authority and aliases but stays out
of the packet path. No separate gateway or application proxy is required.

The independently specified requirements, known wire limits and delivery gates
are in [Device sharing through peer aliases](../design/device-alias-sharing.md).
Resources without a client and routed Resources remain outside this slice.

## Durable storage checkpoint — 2026-10-03

Core schema 81 adds migration-only alias reservation/quarantine with exact
endpoint/Device/key pins, separate role/family pools, shared endpoint Resource
aliases and distinct consumer source aliases. Legacy Resource ownership is
adopted exactly. Both Network revisions and scoped audit/outbox commit atomically;
partial family failures roll back and retained addresses survive realm changes.
No worker/runtime capability, client advertisement, alias map emission, DNS
publication, deployment or live packet qualification is enabled by this step.
See [the owned design](../design/device-alias-sharing.md#durable-reservation-foundation--schema-81)
for the bounded allocator, evidence, migration and verification contract.
