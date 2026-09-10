# Encrypted relay path

The relay is a reachability transport, not a second encryption layer or a
policy authority. `meshd` sends the same end-to-end encrypted WireGuard packet
that it would send over UDP. A relay can observe connection metadata, packet
sizes, timing, and public node-key destinations, but it cannot decrypt tunnel
payloads or grant a route that the validated control map and local packet gate
did not already authorize.

## Path lifecycle

For each validated map, the data plane derives a private relay configuration:

1. Keep only signed regions with at least one non-STUN relay node.
2. Use the self node's usable home preference; otherwise select the lowest
   usable region ID deterministically.
3. Bind every authorized peer public key and overlay address to its usable home
   preference. A missing preference uses the local deterministic rendezvous
   region.
4. Configure each WireGuard peer with its relay endpoint as the base path.
5. Promote a direct UDP endpoint only after the session-bound authenticated
   probe protocol proves it.
6. Restore the relay endpoint when that proof expires, the candidate is removed,
   or the direct update is explicitly rolled back.

Changing relay topology, identity, peer-region binding, or overlay identity
changes the public relay fingerprint and recreates the packet engine. Temporary
private-key copies are cleared after configuration and never enter that
fingerprint.

## Transport boundary

`internal/relay` owns authorization, queues, connection workers, retry policy,
and lifecycle. It exposes a small protocol-independent client contract whose
`Close` operation must interrupt a concurrent `Receive`.

`internal/compat/derp` owns the pinned on-wire framing. It deliberately does
not inherit general HTTP-client behavior: relay sessions use raw TCP plus TLS,
do not use environment proxies, do not follow redirects, and require an HTTP
101 protocol upgrade followed by the authenticated server greeting. Certificate
verification accepts only one of these control-authorized modes:

- normal system-root verification for the signed hostname;
- full chain verification for a separately signed certificate name while
  retaining the signed SNI; or
- an exact lowercase `sha256-raw:` certificate pin, with hostname and validity
  checks still enforced.

The adapter answers protocol pings, treats restart notices as reconnect signals,
and ignores informational presence and health frames. It returns only encrypted
peer packets to the product pool.

An authenticated inbound packet may establish a reverse route for its source
peer on that exact active region. This lets a responder answer on the connection
where the initiator was observed when their home regions differ. The route is
never learned from the WireGuard payload or an arbitrary endpoint string, and it
is deleted when that relay connection ends.

## Resource bounds and failure behavior

- encrypted packet size: 2 KiB maximum;
- active relay regions: 16 maximum;
- pending send batches: 32 per region;
- pending send bytes: 1 MiB per region and 4 MiB total;
- received packet queue: 128 entries;
- connection deadline: 10 seconds;
- write deadline: 5 seconds;
- reconnect delay: cryptographically jittered from 250 milliseconds to 5
  seconds.

Queue saturation drops the attempted relay packet instead of growing memory.
Unknown sources and invalid frames are discarded. Cancellation closes active
connections and joins every worker. WireGuard bind reconfiguration stops one
connection generation and can safely open the next; destroying the device
permanently closes the pool and clears its retained private authority. If no
usable signed relay exists, the data plane can still use a control-authorized
direct endpoint, but it never invents a relay, disables TLS verification, or
accepts an unauthorized peer/region combination.

## Follow-up work

The next relay milestones are worker eviction when more than sixteen regions
are touched, relay-connection-aware preference retention, explicit IPv4/IPv6
node dialing with bounded happy-eyeballs behavior, connection health telemetry
without payloads, and adversarial end-to-end tests against malformed or
overloaded relay servers. Latency measurement and atomic publication of the
preferred region are implemented in the discovery/control path; the packet
engine adopts the result only after it is echoed in a validated network map.
