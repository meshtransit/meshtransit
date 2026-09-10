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
4. Retain every usable signed region as connection authority, while opening
   workers lazily and keeping the active set bounded.
5. Configure each WireGuard peer with its relay endpoint as the base path.
6. Promote a direct UDP endpoint only after the session-bound authenticated
   probe protocol proves it.
7. Restore the relay endpoint when that proof expires, the candidate is removed,
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

Each node uses its signed IPv6 and IPv4 fields independently. An empty field
resolves the signed hostname for that family, `none` disables that family, and
a literal must be a valid global-unicast address of the declared family.
IPv6 starts first and IPv4 follows after 200 milliseconds, or immediately when
IPv6 fails. Only the winning TCP socket proceeds to TLS and protocol
authentication; every started losing attempt is canceled, closed, and joined.
The TLS SNI and HTTP authority remain the signed hostname even when the socket
dials a literal address.

The adapter answers protocol pings, treats restart notices and explicit unhealthy
reports as reconnect signals, and translates authenticated keepalive, presence,
and healthy-status frames into a payload-free product activity event. It returns
encrypted peer packets as a separate event kind, so wire-specific message types
never enter relay orchestration.

An authenticated inbound packet may establish a reverse route for its source
peer on that exact active region. This lets a responder answer on the connection
where the initiator was observed when their home regions differ. The route is
never learned from the WireGuard payload or an arbitrary endpoint string, and it
is deleted when that relay connection ends. The route carries the worker
generation, so cleanup from an older connection lifecycle cannot delete newer
authority.

## Health-aware home selection

The pool exposes an internal, non-secret snapshot containing region ID,
authenticated connection state, bounded failure count, and last connection,
receive, send, and failure times. It contains no node keys, packet data, relay
health text, or network identity.

STUN latency remains the source of relative region quality, but no measured
candidate is published immediately. The packet engine first opens that signed
region without routing traffic through it. Selection changes only after the new
connection completes TLS, protocol authentication, and has fresh activity.
Recent authenticated activity on the current home also prevents a partial STUN
round from causing false failover. Control remains authoritative: the running
packet configuration changes home only after the published preference is echoed
in a newly validated map.

## Resource bounds and failure behavior

- encrypted packet size: 2 KiB maximum;
- active relay regions: 16 maximum;
- pending send batches: 32 per region;
- pending send bytes: 1 MiB per region and 4 MiB total;
- received packet queue: 128 entries;
- connection deadline: 10 seconds;
- per-node TCP dial deadline: 1.5 seconds;
- per-node TLS, upgrade, and authenticated-confirmation deadline: 4 seconds;
- address-family fallback delay: 200 milliseconds;
- pre-authentication upgrade response: 32 KiB maximum;
- authenticated server-info frame: 64 KiB maximum;
- authenticated health and peer-state frames: 1 KiB maximum;
- write deadline: 5 seconds;
- reconnect delay: cryptographically jittered from 250 milliseconds to 5
  seconds;
- authenticated receive silence: 2 minutes 10 seconds maximum before reconnect.

Queue saturation drops the attempted relay packet instead of growing memory.
When all sixteen slots are used, the pool waits for the oldest idle non-home
worker to exit before starting a replacement. It never evicts the home worker,
a worker with queued or in-flight sends, or a worker carrying an authenticated
reverse route. If every non-home worker is protected, preparation fails with a
bounded region-limit error rather than exceeding the goroutine cap.

Unknown sources and invalid peer packets are discarded. Invalid adapter event
shapes, unknown or out-of-phase wire frames, unhealthy server reports, receive
silence, and transport failures close the affected connection and enter bounded
reconnect. Cancellation closes active
connections and joins every worker. WireGuard bind reconfiguration stops one
connection generation and can safely open the next; destroying the device
permanently closes the pool and clears its retained private authority. If no
usable signed relay exists, the data plane can still use a control-authorized
direct endpoint, but it never invents a relay, disables TLS verification, or
accepts an unauthorized peer/region combination. A node that authenticates and
immediately disconnects does not reset exponential retry. Reset requires a
connection lifetime of at least thirty seconds.

## Follow-up work

Deterministic adversarial coverage now includes oversized upgrade headers,
stalled TLS and missing greetings, unknown and malformed authenticated frames,
rapid connection churn, and queue byte pressure. Remaining relay release work
is long-duration saturation testing and operator-facing aggregate health
telemetry without keys or payloads.
