# Phase 2 M2a TCP/UDP policy publication design

Status: implemented and locally qualified for Device-to-Device policy. Active
Device Resource destinations are implemented by M2b1; Resource Groups remain
M2b2.

Date: 2026-09-29

## Scope

This slice qualifies the existing immutable packet-policy path for explicit TCP
and UDP destination ports. It covers the complete path from the authenticated
management request through deterministic Core compilation, atomic PostgreSQL
activation, Node-reduced legacy client projection, and the product-owned `meshd`
packet gate.

The current policy input names stable Device identities. It does not yet accept
Resource or Resource Group destination selectors. Adding those selectors is the
next M2 slice and must resolve them to version- and target-generation-pinned
Device destinations without changing the runtime packet semantics qualified
here.

The client boundary is pinned to `meshd` source
`484cb397cde7d1a9e199035cd1360127189319c2`. No client source change is required
by M2a because that artifact already validates and enforces bounded host-level
TCP/UDP rules fail closed.

## Invariants

- Protocol is exactly one of `tcp`, `udp`, or the fixed v1 `icmp` profile. There
  is no protocol wildcard.
- TCP and UDP require between one and 64 input destination-port intervals per
  rule. Port zero, descending ranges, and values above 65535 are rejected.
- Intervals are sorted, merged when overlapping or adjacent, and copied at the
  domain boundary. Equivalent inputs therefore compile to the same snapshot,
  semantic hash, and client-map bytes.
- An explicitly empty rule set is valid and means deny-all. Missing, malformed,
  stale, or ambiguous policy never means allow-all.
- Peer visibility requires an explicit directional rule in either direction.
  The packet filter sent to one Node contains only rules whose destination is
  that Node; an outbound-only rule never becomes local inbound authority.
- Policy release, compiled rules, Network/policy revisions, audit evidence, and
  outbox evidence commit in one PostgreSQL transaction. A stale `If-Match` or
  database CAS creates no replacement release.
- A policy replacement is complete. Explicit empty `PacketFilter` clears prior
  client authority; restore publishes a new complete revision.
- `meshd` validates the full candidate map before replacing live state. Policy,
  self-address, or peer-address changes clear bounded return-flow state;
  malformed packets, fragments, unsupported protocols, and narrow port rules on
  portless transports fail closed.

## Deterministic compiler and projection

`policy.NewRule` normalizes port intervals. `policy.NewSnapshot` sorts compiled
edges by stable Access Rule ID, source Device, destination Device, protocol, and
canonical ports. The publication semantic hash omits the allocated revision but
binds exact scope, compiler format, stable identities, protocol, and normalized
ports.

The legacy adapter iterates that immutable order and emits protocol numbers 6
and 17 with exact destination ranges. It omits every rule not addressed to the
requesting Node. Tests encode equivalent snapshots built from reversed input
order and require byte-identical map frames.

## Publication lifecycle

The disposable PostgreSQL scenario exercises one ordered lifecycle:

1. Publish TCP 8443 at policy revision 3.
2. Reject a replay of the stale revision-2 candidate without mutation.
3. Publish an explicit empty rule set at revision 4 and observe zero visible
   peers and zero client policy rules.
4. Restore TCP 8443 plus UDP 53 at revision 5 through the authenticated browser
   management boundary.
5. Observe one authorized peer and the exact two transport rules from the
   authoritative map loader.
6. Reject the stale deny-all command after restore and retain the active release.

PostgreSQL remains the authority. Redis is not read to decide or widen packet
access, and the flow requires no sticky session.

## STRIDE review

| Threat | Control |
| --- | --- |
| Spoofing | Stable typed Device IDs, authenticated Account Session, exact Workspace/Network scope, and live `policy.publish` resolution. |
| Tampering/replay | Strong revision precondition, locked Network/policy revisions, immutable release rows, semantic hash, and complete-replacement projection. |
| Repudiation | Revision-bound hash-chained audit and durable outbox evidence commit with the release. |
| Information disclosure | Node-reduced inbound filters and policy-safe errors omit unrelated topology and database diagnostics. |
| Denial of service | 8 MiB request cap, 10,000-rule snapshot cap, 64 input ranges per rule, bounded database waits/retries, and bounded client rule cardinality. |
| Elevation of privilege | No wildcard protocol, no implicit same-group/same-peer allow, empty means deny, and unknown client semantics fail closed. |

## Acceptance and non-claims

The executable acceptance matrix is recorded in
`docs/qualification/phase2-m2a-tcp-udp-policy-publication-2026-09-29.md`.

This slice is engineering evidence, not a production, GA, HA, failover, or SLO
claim. It does not qualify deployed artifacts, Resource/Resource Group policy
inputs, Access Graph semantics, routed Resources, subnet/exit forwarding, or
cross-platform packet enforcement.

## Next order

1. M2b1: compile active Device Resources to the exact same Node-resolved TCP/UDP
   semantics with exact version, target generation, inventory revision, and
   semantic-hash pins (implemented).
2. M2b2: expand immutable Resource Groups with exact definition/member pins.
3. M4: reuse the compiler semantics for Access Graph explanation and simulation.
4. M5: extend enforcement to routed/service Resources and trusted gateways.
