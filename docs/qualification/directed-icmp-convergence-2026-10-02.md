# Directed ICMP revocation and restoration — 2026-10-02

## Artifact boundary

This engineering observation used Core commit
`72abbaa005375c98ea038158ba5e2883e8e59eb5`, Console commit
`7079c29b548e1a9c6624f008c7cf12727b97d7ed`, schema 78, and two Linux clients on
`meshd` commit `745db5193def2db0d8a1946eb762e75f898ddef0` (`0.1.0~poc62`).
Both clients initially had one peer, one inbound ICMP rule and a synchronized
control session in one Network. No peer, address, account or deployment
identifier from the environment is included in this public record.

## Observed lifecycle

1. A currently authorized publisher removed only the forward ICMP rule through
   Console preview and publication. The reverse rule remained active.
2. The destination's filter changed from one inbound rule to zero. Its peer
   remained visible because the reverse rule still needed that peer.
3. Continuous IPv4 and IPv6 forward ping traffic stopped, including the ping
   processes already running before publication.
4. The reverse ping processes delivered 747 of 747 packets for each family
   throughout the 150-second observation, including the denial interval.
   Stateful replies did not create permission for forward initiation.
5. The publisher restored the same directed ICMP access through Create rule.
   The destination regained one inbound rule and both forward ping processes
   resumed. No other protocol, port or scope was added.

The durable release transitioned from two rules to one and back to two.
Each publication created one revision outbox event, delivered on its first
attempt. Worker counters recorded two claimed events, two successful deliveries,
two received Redis wakeups, no failed or deferred delivery, and zero ready backlog.

## Measurement limits

Observed Console-click-to-filter changes were approximately 1.26 seconds for
removal and 1.69 seconds for restoration. Filter polling used a 100-millisecond
interval; ping used a 200-millisecond interval. Browser and client clocks were
not calibrated against each other. These are approximate observations from one
cycle, not p95 or fleet qualification.

PostgreSQL commit-timestamp tracking was disabled. The stored activation instant
is not an exact commit timestamp; this record makes no commit-to-apply claim.
Outbox event creation-to-completion intervals were about 0.448 and 0.962 seconds.

Both client registrations later reached their existing expiry. Their subsequent
status was offline with blocked control sessions, no peers and no packet rules.
That expiry occurred after restoration and is separate from the ACL result.

## Remaining qualification

- Repeat with calibrated clocks and publication acknowledgements before
  calculating convergence percentiles.
- Exercise TCP/UDP port narrowing and established-flow revocation separately.
- Verify delivery through both Control replicas and reconciliation after a
  deliberately missed Redis wakeup.
- Qualify explicit sharing and scoped DNS independently; this test establishes
  neither cross-Network connectivity nor DNS delivery.
