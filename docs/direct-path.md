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
| Selection | Prefer a recently authenticated path, then measured latency, with deterministic tie-breaking. | This avoids random first-packet routing and makes behavior testable while still allowing roaming. |
| Activity | Probe and heartbeat only active peer sessions; apply per-peer and global rate limits. | Idle meshes should not create continuous background traffic or unbounded timers. |
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
   adapter, randomized 20–26 second refresh while peers exist, bounded
   anti-flap history, retry/coalescing, and expiry scheduled at the exact
   candidate deadline.
4. Pending: encrypted discovery messages and authenticated path selection/roaming.
5. Pending: Linux end-to-end tests with no manually advertised endpoint, including
   restart, socket rebinding, stale-result cancellation, and default-deny
   policy behavior.

Port mapping and relay transport remain separate follow-up capabilities. They
have candidate types now, but they are not treated as implemented until their
own security and interoperability gates pass.
