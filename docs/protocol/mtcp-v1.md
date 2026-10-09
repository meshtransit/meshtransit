# MTCP v1: MeshTransit Control Protocol (outline)

Outline, 2026-10-09. Full specification in phase P4; this page fixes the
decisions later work builds on. MTCP v1 replaces the TS2021 compatibility
protocol entirely; there is no dual stack.

## Decisions

- **Transport:** HTTPS on 443, upgraded to one bidirectional stream (HTTP
  upgrade, with WebSocket as fallback for proxies). Both have been verified
  through Cloudflare.
- **End-to-end authentication:** inside the stream, `Noise_IK_25519_ChaChaPoly_BLAKE2s`
  with the node's machine key as initiator static and Core's control key as
  responder static. TLS-terminating proxies cannot read or forge control
  messages.
- **Messages:** Protocol Buffers with explicit field numbers, defined under
  `api/mtcp/v1`. Unknown fields are ignored; unknown message types are rejected.
- **Capabilities:** negotiated by name (`relay.udp`, `disco.v2`,
  `portmap`, ...), never by a single global capability number.
- **Map stream:** a full snapshot on every (re)connect, then deltas, each
  carrying the Network revision it brings the node to. A node that sees a gap
  asks for a snapshot.
- **Streams carried:** map, endpoint and NAT reports, relay tickets and the
  signed relay map, lifecycle events (suspend, expiry, revoke), aggregate path
  telemetry.
- **Keys:** MeshTransit key types and text prefixes from [keys.md](keys.md);
  key rotation without downtime.
- **Limits:** every message has a size cap; every stream has bounded buffers and
  backpressure; slow consumers are resynchronised, never allowed to grow memory.

## Open items for P4

- Registration and browser-approval flows over MTCP.
- Exact protobuf schema and test vectors.
- Migration of profile storage in meshd.
