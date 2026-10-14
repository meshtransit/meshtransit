# Device alias v1

Draft 2, 2026-10-14. Implementation: Core `core/internal/control/mapsession`
(projection) and `core/internal/adapter/mtcp/mapencode.go` (encoding); node
`client/internal/networkmap/alias.go` (validation),
`client/internal/dataplane/alias.go` (enforcement) and
`client/internal/packetmeta` (rewriting). Schema: `AliasGrant` in
[`api/mtcp/v1/mtcp.proto`](../../api/mtcp/v1/mtcp.proto), carried by MTCP v1
§7.4.

A Device shared from a **provider** Network to a **consumer** Network is
reached through aliases, so that neither node learns the other's overlay
addresses and both Networks may use the same ones. The consumer node sees the
provider at its **Resource Alias**; the provider node sees each consumer
Device at its **Consumer Source Alias**. The two nodes translate addresses in
every packet. Core and relays never translate or decrypt packets. How shares
are made is described in [sharing](../concepts/sharing.md).

## 1. Negotiation

- A node that supports this document advertises the MTCP capability
  `device-alias.v1` in `ClientHello`.
- Core MUST NOT send a peer with an `alias` to a node that did not advertise
  it. When a node's view contains alias peers and the node did not advertise
  the capability, Core refuses the map rather than send those peers as
  ordinary peers.
- The capability is a declaration only: it grants no access. Core allocates an
  alias for a pair of Devices only while both have declared the capability in
  their current session, with their current keys.

## 2. The grant

A peer that is reached through an alias carries `Device.alias` (field 16), an
`AliasGrant`:

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | `contract_id` | string | The Trust Contract (lowercase UUID) |
| 2 | `endpoint_id` | string | The Private Endpoint (lowercase UUID) |
| 3 | `generation` | uint64 | The endpoint generation, ≥ 1 |
| 4 | `grant_revision` | uint64 | Provider Network revision plus consumer Network revision, ≥ 1 |
| 5 | `recovery_epoch` | uint64 | The Deployment's recovery epoch, ≥ 1 |
| 6 | `role` | enum | This node's role: `CONSUMER` (1) or `PROVIDER` (2) |
| 7 | `expires_ms` | int64 | Exclusive deadline, Unix milliseconds |
| 8 | `services` | repeated `AliasService` | What the consumer may open |
| 9 | `masquerade_v4` | bytes | This node's own alias toward this peer, IPv4 |
| 10 | `masquerade_v6` | bytes | This node's own alias toward this peer, IPv6 |

`AliasService` is `protocol` (uint32), `port_from` and `port_to` (uint32):

- TCP (6) and UDP (17): `1 ≤ port_from ≤ port_to ≤ 65535`;
- ICMP echo: protocol 1 for IPv4 or 58 for IPv6, both ports 0, present only
  for a family the node has an alias in.

The grant names no keys: it belongs to the peer entry it is in and to the
node's own entry.

### 2.1 What Core sends

- The peer's `addresses` and `allowed_prefixes` are the peer's aliases as
  exact host routes (`/32`, `/128`), never its overlay addresses.
- `masquerade_v4` and `masquerade_v6` are the receiving node's aliases toward
  that peer.
- `services` is the exact intersection of the contract's maximum traffic and
  the consumer's current rules for this pair: 1 to 64 entries, sorted by
  protocol then `port_from`, disjoint. (Guardrails act when a share or a
  policy changes, not here.)
- When several current consumer rules connect the same pair, Core merges them
  into one grant with the earliest deadline.
- `expires_ms` is no later than either Device's key expiry or the Private
  Endpoint's expiry.
- The provider's packet filter (MTCP §7.3) names the Consumer Source Alias as
  source and the provider's own overlay address as destination. The consumer
  receives no rule allowing the provider in.

## 3. Validating a grant

A node MUST reject the whole map if any alias peer breaks a rule below.

- The node's own entry carries no alias.
- `contract_id` and `endpoint_id` are non-zero lowercase UUIDs; `generation`,
  `grant_revision` and `recovery_epoch` are non-zero.
- Both node keys have an expiry, and `expires_ms` is in the future and no
  later than either; the peer is authorized and not expired.
- The peer has one or two addresses, at most one per family, and its
  `allowed_prefixes` equal them exactly.
- The node has a masquerade address in exactly the families the peer has,
  and exactly one overlay address of its own in each of them.
- Alias addresses and those overlay addresses are global unicast: not
  IPv4-mapped, without zone, not loopback, not link-local.
- A local alias does not collide with any other address in the map. Two
  peers may share a local alias only when both grants have role `PROVIDER`
  and the same contract, endpoint, generation and recovery epoch.
- `services` has 1 to 64 entries, ordered and disjoint, valid as in §2.
- At most 10,000 alias peers per map. (Core sends at most 256 peers of any
  kind to a node that did not advertise `map.large1`, MTCP §13.)

### 3.1 Replacing a grant

When a later map changes a grant for the same contract:

- a peer MUST NOT turn from an alias peer into an ordinary peer;
- `role` and `recovery_epoch` MUST NOT change;
- `generation` and `grant_revision` MUST NOT decrease;
- within one `generation`, the node and peer keys and the node's masquerade
  addresses MUST NOT change;
- within one `generation` and `grant_revision`, nothing changes.

A change of the grant alone replaces the peer atomically in the same map
message. Removing the share removes the peer and its filter rules together.

## 4. Packets

The node applies a grant at its TUN interface, before its ordinary packet
filter; alias addresses never match ordinary rules.

**Consumer.**

- Outbound to the Resource Alias: the source must be the node's overlay
  address and the packet must match a service. The node records the flow and
  rewrites the source to its Consumer Source Alias.
- Inbound from the Resource Alias to its Consumer Source Alias: allowed only
  as a reply to a recorded flow. The destination is rewritten back to the
  node's overlay address.

**Provider.**

- Inbound from a Consumer Source Alias to its Resource Alias: the packet must
  match a service and the provider's packet filter. The node records the flow
  and rewrites the destination to its overlay address.
- Outbound to a Consumer Source Alias: allowed only as a reply to a recorded
  flow, with the source rewritten to the Resource Alias. The provider can
  never open a connection to the consumer.

In both roles:

- every packet is refused at or after `expires_ms`;
- a bare TCP SYN is never a reply;
- ICMP grants cover echo requests and their replies only;
- rewriting accepts IPv4 without options and IPv6 without extension headers,
  carrying TCP, UDP or ICMP echo with an identifier. It changes only the
  addresses and checksums: ports, TCP flags, echo identifiers and payload are
  unchanged. A packet that cannot be rewritten is dropped.

Checksums:

- The IPv4 header checksum and the TCP, UDP and ICMPv6 checksums are verified
  before rewriting and recomputed after.
- An IPv4 UDP packet with checksum 0 (no checksum) is accepted without
  verification and keeps checksum 0.
- An IPv6 UDP packet with checksum 0 is refused.
- A recomputed UDP checksum of 0 is written as `0xffff`.

## 5. Test vectors

- `client/internal/packetmeta/testdata/alias_packets_v1.json`: packets before
  and after rewriting, both directions, both families, including a UDP packet
  without checksum.
- `client/internal/dataplane/testdata/alias_roundtrips_v1.json`: complete
  request and reply exchanges through both nodes.
- `core/internal/adapter/mtcp/mapencode_test.go`: encoded alias peers.
- `core/test/integration/testdata/device_alias_map_intent.sql`: a full share
  for the integration tests.

An implementation MUST reproduce the rewriting vectors byte for byte.
