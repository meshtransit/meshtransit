# Host policy

MeshTransit enforces the node-specific policy from the validated network map at
the plaintext TUN boundary. A packet is checked before encryption on egress and
before kernel delivery on ingress. A denied packet is not forwarded and does
not become successful flow evidence.

## Authorization model

Every packet must first pass address ownership checks:

- outbound source addresses must belong to the local signed node and the
  destination must belong to a signed peer in the active map;
- inbound source addresses must belong to a signed peer and the destination
  must belong to the local signed node;
- profile generations are never combined, so an address from another profile
  grants no authority.

The control server supplies a destination-reduced filter to each receiving
node. MeshTransit therefore applies explicit grants on inbound new flows. It
allows replies to locally initiated flows through a separate bounded return
table. Outbound packets are not themselves treated as proof that the remote
node will accept a new flow.

Policy updates are atomic. A new map is fully validated before publication.
Changing local addresses, peer addresses, or policy rules clears all tracked
flows, so a removed grant cannot survive through stale return state.

## Protocol and port contract

The empty protocol list means TCP, UDP, ICMPv4, and ICMPv6. An explicit
protocol list matches only those IP protocol numbers.

- TCP and UDP require a non-zero destination port and match the inclusive
  destination port range in the rule.
- ICMP and every other portless IP protocol require the exact all-port range
  `0-65535`. A narrow range has no meaningful transport interpretation and
  fails closed.
- An explicitly authorized non-TCP/UDP protocol can pass only with that
  all-port destination. Such traffic receives no return-flow state.
- Capability selectors are preserved by map decoding but do not authorize
  host traffic until a product-owned capability resolver is implemented.

IPv4 and IPv6 fragments are rejected because later fragments do not contain
enough transport metadata for consistent host-policy decisions. IPv6 extension
walking is bounded. ICMPv4 inside IPv6, ICMPv6 inside IPv4, malformed echo
messages, truncated headers, zero TCP destination ports, and malformed UDP
lengths fail closed.

## Return-flow state

Return authority is exact and bounded to 4,096 entries per active policy
filter:

| Protocol | Creation | Reply identity | Idle lifetime |
| --- | --- | --- | --- |
| TCP | outbound SYN without ACK | reversed source/destination IP and port tuple | 5 minutes; 10 seconds after FIN; RST removes it |
| UDP | first outbound datagram | reversed source/destination IP and port tuple | 30 seconds |
| ICMPv4/ICMPv6 | outbound echo request | reversed addresses, protocol, and echo identifier; echo reply only | 10 seconds |

An outbound TCP ACK cannot create state. An unsolicited inbound TCP packet, a
UDP packet with a different tuple, an ICMP request, or an ICMP reply with a
different identifier must match an explicit inbound grant or is denied. When
the table is full, expired entries are removed; if it remains full, new state
is not created.

## Linux qualification

`tools/qualification/linux-policy.sh` evaluates one already-active control
policy phase across two installed Linux nodes. It tests new TCP and UDP flows
over both address families plus ICMPv4 and ICMPv6 in both directions, then
compares every observation with an explicit `allow` or `deny` expectation.

The harness creates mode-restricted temporary directories, copies a bounded
TCP/UDP challenge peer, and runs it under the `meshd` service identity. The peer
accepts only a fixed-format 54-byte random challenge and never logs or retains
the payload. Cleanup stops both peers and removes only the exact temporary
files. The harness does not mutate policy, profiles, routes, DNS, packages, or
services.

A control-policy matrix must be operator-staged with compare-and-swap updates
and exact rollback:

1. Record the current policy document and version.
2. Allow A to B for all four supported protocols; expect new B-to-A flows to
   fail while replies to A-to-B traffic succeed.
3. Reverse the grant and expectations.
4. Allow one TCP and UDP destination port; verify that port and deny an
   adjacent port.
5. Apply default deny and expect all new flows to fail. Peers may disappear
   from the reduced map in this phase.
6. Restore the exact original document with its current compare-and-swap
   version, then verify both nodes are online, synchronized, and healthy.

The report schema is `meshtransit.linux-policy-qualification/v1`. Reports
contain labels, artifact identity, map revisions, aggregate rule counts,
expectations, observations, timings, process exit codes, and the `meshd`
service's current and peak memory before and after the phase. The harness also
requires the service PID and systemd restart count to remain stable on both
nodes; otherwise it emits `daemon_restarted` and fails the phase. Reports
exclude SSH destinations, overlay addresses, network identity, policy contents,
daemon status documents, process IDs, and challenge bytes.

If the reduced map removes a peer route during an all-deny phase, the harness
does not leak a probe toward the underlay default route. It records the missing
mesh route and exit code `90` as the observed denial instead.

Unit and race tests remain the primary proof for malformed packets, exact
return tuples, flow expiry, table bounds, and update invalidation. The live
matrix proves control-to-host behavior but is not a substitute for those
adversarial tests.
