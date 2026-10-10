# Direct-path design

## Scope

This document fixes the behavior and security boundaries for automatic endpoint
discovery and direct UDP path selection. It is an internal design record, not a
claim that every phase is implemented.

The compatibility study covered the pinned `tailscale.com v1.102.3` source and
official upstream snapshot `63d1eedf2c90ca4fb1a673c318aa804720052fc9` from
2026-09-08. The reference is used as a behavior oracle; source files are not
copied into this repository.

## Decisions

| Area | Decision | Reason |
| --- | --- | --- |
| UDP ownership | Keep one long-lived UDP socket for encrypted packets, STUN, and authenticated path probes. | A STUN result from another socket describes the wrong NAT mapping. Stable socket ownership also permits seamless peer endpoint changes. |
| Candidate sources | Keep host-interface, server-reflexive, port-mapped, and explicitly configured candidates as distinct product types. | Source metadata is needed for deterministic publication, diagnostics, and compatibility translation. |
| Publication order | Keep the compatibility-friendly order: port mapping, server-reflexive, configured, then host; IPv4 precedes IPv6 within one source. | Older peers may use only the first address. Modern path selection must use authenticated measurements instead of list order. |
| Endpoint history | Keep short-lived non-host candidates to tolerate one failed discovery round. | Immediate withdrawal causes avoidable flapping during NAT rebinding or packet loss. |
| Expiry | Improve history by scheduling removal at its actual deadline. | The reference tracker can retain an expired address until another link or discovery event triggers an update. |
| Path proof | Require an authenticated discovery response before a candidate becomes the preferred data path. | A control-distributed address is a probe target, not proof that the peer currently owns that path. |
| Selection | Admit only fresh authenticated paths, smooth measured latency, require a material improvement to switch, then use deterministic local/IPv6/address preferences for near-equivalent paths. | This avoids random first-packet routing and latency-jitter flapping while remaining testable. |
| Activity | Run bounded periodic health rounds for online peers now; add packet-activity pacing before scale-out. | Fresh proof is required for safe roaming, while idle meshes should eventually avoid unnecessary background traffic. |
| Control requests | Continue rejecting arbitrary control-supplied probe URLs. | Executing them would create an SSRF primitive unrelated to peer path discovery. |
| Isolation | Bind every discovery result and callback to an active-profile generation. | Results from a cancelled profile or old network map must never cross a Network boundary. |
| Observability | Expose candidate counts, source classes, chosen path class, freshness, and failure reason; do not log raw discovery packets. | Operators need an inspectable state machine without secrets, payloads, or unnecessary address history. |

## Component boundaries

```text
signed relay map ──► STUN scheduler ───────────────┐
local interfaces ─► candidate collector           │
configured input ─► candidate collector           ▼
                                            shared UDP transport
                                                   │
candidate set ─────► TS2021 compatibility adapter  ├─► encrypted tunnel packets
peer map ──────────► authenticated path manager ───┘
```

- `internal/pathdiscovery` owns candidate and path state in MeshTransit terms.
- A small RFC 5389 codec will own STUN framing without a product dependency.
- `internal/dataplane` will own the shared socket and the WireGuard `Bind`
  implementation.
- `internal/compat/ts2021` alone will translate candidate sources to protocol
  endpoint types and publish endpoint-only map updates.
- The daemon will own lifecycle, cancellation, and active-profile generation.

## Candidate contract

- A candidate is a canonical `netip.AddrPort` with a non-zero UDP port and a
  known source.
- IPv4-mapped IPv6, zones, unspecified, multicast, loopback, and link-local
  addresses are rejected.
- Private IPv4 and unique-local IPv6 are allowed for host and configured LAN
  paths. Candidate addresses grant no routing or policy authority.
- One publication contains at most 16 unique candidates and at most 64 raw
  observations before deduplication.
- Duplicate addresses retain the highest publication-priority source.
- Collections are sorted deterministically and returned through defensive
  copies so callers cannot mutate published state.

## STUN security contract

- Servers come only from the currently validated, control-signed relay map.
- Literal validated relay IPs are preferred. Hostname resolution, when added,
  must remain bounded and tied to the signed node name.
- Every request uses a cryptographically random transaction ID. A response is
  accepted only when transaction ID, source server, address family, socket
  generation, and active-profile generation all match.
- Pending transactions, packet size, retries, total round duration, and probe
  concurrency are bounded. Cancellation removes pending state immediately.
- A reflected address is only publishable data. It never creates a route,
  policy rule, peer identity, or trusted path by itself.

## Delivery phases

1. Implemented: product-owned candidate validation and deterministic collection.
2. Implemented: shared UDP transport plus bounded STUN discovery on that socket.
3. Implemented: non-streaming endpoint publication through the compatibility
   adapter, randomized 20–26 second refresh while peers exist, immediate refresh
   after a debounced meaningful host-network change, bounded anti-flap history,
   retry/coalescing, and expiry scheduled at the exact candidate deadline. Linux
   uses native route/link/address notifications and falls back to five-second
   polling; other platforms poll until native adapters are implemented and
   qualified. Product-owned data and DNS interfaces are ignored.
4. Implemented in the Linux candidate path: the compatible encrypted Ping/Pong identity and bounded wire
   codec are implemented. One ephemeral identity is now owned by each daemon
   control session and its exact public key is used for map and endpoint
   publication across reconnects. A bounded registry atomically derives peer
   channels from each validated map, binds node and discovery identities,
   authorizes signed probe destinations, translates authenticated messages, and
   destroys replaced or deactivated shared secrets while retaining its
   generation rollback watermark. The product-owned transaction manager
   enforces bounded per-peer/global state, exact peer/map/socket/source binding,
   five-second deadlines, consume-once replay rejection, and generation resets.
   Live shared-socket demultiplexing, bounded asynchronous authentication, Pong
   responses, paced map-triggered scheduling, randomized periodic health
   rounds, failed-send cancellation, and authenticated transaction completion
   are implemented. The bounded
   product-owned selector now enforces authorized candidates, a 6.5-second
   freshness window, smoothed RTT, switch hysteresis, deterministic ties,
   exact expiry/fallback, bounded lease handoff across an otherwise identical
   newer map revision, generation reset, and rollback rejection. One owned
   daemon worker applies selector transitions through peer-scoped WireGuard
   `update_only` requests, guards the installed map revision and signed endpoint
   set, restores the signed base endpoint at exact proof expiry, and closes the
   engine on an ambiguous update. Aggregate process-local status counts relay
   bootstraps, authenticated direct promotions, and relay fallbacks, and records
   last and maximum relay-to-direct promotion duration without retaining peer
   identity or endpoint data. Equivalent map revisions preserve only the
   remaining proof lease without a device write; the lease is not extended.
   A compatible signed home-relay change updates only the fallback metadata,
   keeps the authenticated direct endpoint, and makes expiry restore the newest
   relay base. Any socket, route, peer identity, discovery identity,
   candidate-authority, or relay-topology change restores or recreates the
   signed base path. Activity-aware probe suppression
   remains; periodic authenticated rounds currently keep roaming decisions
   fresh for all online peers.
5. Implemented in the Linux candidate path: end-to-end tests use only automatically
   discovered host and server-reflexive candidates. They cover daemon restart,
   private-path selection, socket rebinding, stale-result cancellation, and a
   live default-deny to restored-policy transition without restarting the
   daemon. Socket generations share one monotonic namespace for the complete
   WireGuard engine lifetime, so recreating a bind cannot make a fresh path
   generation look stale or reuse authority from an earlier socket.
6. Implemented as a bounded qualification: a Linux scenario creates a
   dedicated dummy interface, adds one non-production test address, requires an
   observed network event and completed endpoint refresh within 20 seconds, and
   verifies uninterrupted dual-stack peer traffic before removing the interface.
   This safely proves proactive detection and refresh without modifying the SSH
   uplink or default route. It does not by itself prove failover between two real
   underlays; that requires a separately controlled multi-homed lab.

Port mapping (PCP, NAT-PMP, UPnP IGD) is described in
[port-mapping.md](port-mapping.md); a mapping is published as a
`port_mapping` candidate and still needs authenticated proof. The bounded relay base
path is described in [relay.md](relay.md); it is not a direct candidate and does
not weaken the endpoint authority or freshness rules above.
