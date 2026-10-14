# MeshTransit protocols

Language-independent specifications for the protocols spoken between
MeshTransit components. Implementations live in `shared/` (Go); every spec
ships test vectors that any implementation must reproduce.

| Document | Status | Scope |
|---|---|---|
| [threat-model.md](threat-model.md) | Draft 1 | Assets, adversaries and required mitigations for the network layer |
| [keys.md](keys.md) | Draft 1 | Key types, text encodings and signing domains |
| [disco-v2.md](disco-v2.md) | Draft 1 | Peer path discovery: ping, pong, call-me-maybe |
| [mtrp-v1.md](mtrp-v1.md) | Draft 1 | MeshTransit Relay Protocol (Interchange) and relay tickets |
| [nat-classification.md](nat-classification.md) | Draft 1 | How a node classifies its NAT and what it reports |
| [mtcp-v1.md](mtcp-v1.md) | Draft 1 | MeshTransit Control Protocol; schema in `api/mtcp/v1` |
| [policy-digest-v1.md](policy-digest-v1.md) | Draft 1 | Semantic digest of a packet filter, for enforcement evidence |
| [device-alias-v1.md](device-alias-v1.md) | Draft 2 | Device alias grants carried by MTCP §7.4, and how nodes apply them |
| [audit-record-v2.md](audit-record-v2.md) | Draft 1 | Audit records, the seal chain and verifiable exports |

## Conventions

- The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be
  interpreted as described in RFC 2119 and RFC 8174.
- All multi-byte integers are unsigned and big-endian (network order) unless a
  field says otherwise.
- `u8`, `u16`, `u32`, `u64` are unsigned integers of that many bits.
  `bytes[n]` is exactly `n` bytes. `||` is concatenation.
- An IP endpoint on the wire is `bytes[16]` (IPv6, or IPv4-mapped IPv6
  `::ffff:a.b.c.d`) followed by a `u16` port: 18 bytes. Port 0 and the
  unspecified address are invalid.
- Times are `u64` milliseconds since the Unix epoch (UTC) unless stated.
- Receivers MUST reject, without side effects, any message that is shorter
  than its fixed part, longer than its stated maximum, uses an unknown version,
  or carries reserved bits set. A rejected message never produces a reply that
  is larger than the message itself.
- Every length is checked before it is used to allocate or slice memory.

## Cryptography

Only standard constructions are used: X25519, Ed25519, ChaCha20-Poly1305 and
XChaCha20-Poly1305, BLAKE2s, HKDF and the Noise Protocol Framework
(revision 34). Inner payloads of the data plane are WireGuard packets, which
are end-to-end encrypted between nodes; relays never hold keys that decrypt
them.

## Versioning

Every message carries a version. A new incompatible version gets a new number
and is negotiated explicitly; implementations never guess. Unknown message
types inside a known version are rejected, not ignored, unless the spec marks a
range as "ignore if unknown".
