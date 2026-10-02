# Device alias interoperability assessment

Assessment date: 2026-10-02. This is a source-boundary inspection, not a live
packet qualification or proof that either deployment enables cross-Workspace
sharing.

## Pinned evidence

- Read-only custom Headscale reference:
  `412b020d50ac18e1a5b2ba54da07b1aa1d7ac0e5`.
- MeshTransit client:
  `f60e40e8a1a9d3d83a5ce10b7b7dec25fbcfe885`.
- Client compatibility dependency: `tailscale.com v1.102.3`.
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
The pinned dependency's `tailcfg.Node` field documentation independently defines
masquerading as local-source translation limited to that peer.

The reference's reverse IPv6 observation keeps the consumer's canonical IPv6
address. It is not evidence for two independently overlapping IPv6 address
realms. MeshTransit must qualify that case with its own two-sided alias contract.

No reference tests, oracle service or real cross-Workspace traffic were run for
this assessment. Source and test assertions indicate intended wire output;
black-box qualification remains a delivery gate.

## Current client gap

`internal/compat/ts2021/netmap.go:convertNode` copies identity, host addresses,
routes, endpoints and expiry. It does not transfer either per-peer masquerade
field into the product-owned Node.

`internal/dataplane/observed_tun.go` performs packet policy checks and observation
around TUN reads/writes. It has no alias translation stage. The policy gate
requires canonical self ownership and mapped peer ownership. The Linux factory
wraps this TUN directly in the WireGuard device; there is no hidden compatibility
client that supplies masquerading on its behalf.

Therefore ordinary meshd login/packet compatibility with this control reference
must not be described as qualified cross-Workspace alias compatibility. Sending
only peer alias addresses to the current client cannot implement the required
source rewrite or return path. A numeric capability of 142 does not prove that
missing code exists.

## Product decision

For Device sharing, both participating meshd processes perform peer-specific
translation and enforcement. Core supplies authority and aliases but stays out
of the packet path. No separate gateway or application proxy is required.

The independently specified requirements, known wire limits and delivery gates
are in [Device sharing through peer aliases](../design/device-alias-sharing.md).
Resources without a client and routed Resources remain outside this slice.
