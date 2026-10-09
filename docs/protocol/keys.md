# Keys and signing domains

Draft 1, 2026-10-09.

## Key types

Each purpose has its own key. A key of one type is never used for another
purpose.

| Type | Algorithm | Owner | Purpose | Text prefix |
|---|---|---|---|---|
| Node key | X25519 | Node | WireGuard static key; identifies a device in maps | `mtnode:` |
| Disco key | X25519 | Node | Authenticates disco v2 messages and MTRP sessions; rotated with the node session | `mtdisco:` |
| Relay key | X25519 | Interchange node | Noise IK responder static key | `mtrelay:` |
| Signing key | Ed25519 | Core | Signs relay tickets and the relay map | `mtsign:` (public) |
| Machine key | X25519 | Node installation | MTCP Noise initiator static key; identifies the installation | `mtmachine:` |
| Control key | X25519 | Core deployment | MTCP Noise responder static key, pinned by nodes | `mtcontrol:` |

## Text encoding

Public keys are written as the prefix followed by the lowercase hexadecimal
encoding of the 32-byte key, for example
`mtnode:` + 64 hex characters. Parsers MUST accept only lowercase hex of the
exact length and the exact prefix. Private keys are never printed, logged or
put in URLs; their text form (`privkey:` + hex) exists only for configuration
files with restrictive permissions.

The all-zero public key is invalid for every type. X25519 operations that
produce an all-zero shared secret MUST be treated as failures.

## Key IDs

A signing key is identified by an 8-byte key ID: the first 8 bytes of
`BLAKE2s-256("meshtransit/key-id/v1" || 0x00 || public_key)`. Text form:
16 lowercase hex characters.

## Domain separation

Every signature, MAC and KDF input starts with a unique ASCII domain string
followed by a zero byte. Registered domains:

| Domain | Used by |
|---|---|
| `meshtransit/key-id/v1` | Key IDs |
| `meshtransit/disco/v2` | disco v2 key derivation |
| `meshtransit/mtrp-ticket/v1` | Relay ticket signatures |
| `meshtransit/relay-map/v1` | Relay map signatures |
| `MeshTransit MTRP v1` | Noise prologue for MTRP (no zero byte; Noise prologue) |
| `MeshTransit MTCP v1` | Noise prologue for MTCP (no zero byte; Noise prologue) |
| `meshtransit/mtcp-key-proof/v1` | MTCP proof of possession of node and disco keys |
| `meshtransit/mtcp-control-fp/v1` | MTCP control key fingerprint in enrollment links |
| `meshtransit/mtrp-mac1/v1`, `meshtransit/mtrp-cookie/v1` | MTRP handshake DoS MACs |

New uses MUST register a new domain here.
