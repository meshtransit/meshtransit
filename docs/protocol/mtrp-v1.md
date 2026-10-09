# MTRP v1: MeshTransit Relay Protocol (Interchange)

Draft 1, 2026-10-09. Implementation: `shared/mtrp` (codecs, tickets),
`relay/` (server, P2), `client/` (P3).

MTRP lets a node reach a peer through an Interchange relay when no direct path
exists yet or ever. Relays forward opaque payloads (WireGuard packets and disco
v2 messages) between authorised sessions. They cannot decrypt them.

## 1. Transports

| Transport | Default port | Framing | When |
|---|---|---|---|
| UDP | 3479/udp | one frame per datagram | primary |
| TLS 1.3 over TCP | 443/tcp | `u16 length || frame` | UDP blocked |
| WebSocket over TLS | 443/tcp, path `/mtrp/v1` | one frame per binary message | only HTTP(S) allowed, or a proxy is required |

STUN (RFC 8489, with RFC 5780 attributes when the relay has an alternate port
or address) runs on 3478/udp. Ports are advertised in the relay map; the values
above are defaults.

A client tries UDP first and starts TLS after 300 ms without a handshake
response, keeping whichever completes first; WebSocket is used when TLS cannot
connect (for example only an HTTP proxy is reachable). A client keeps at most
one active session per relay node.

TLS and WebSocket share one TCP port. After a TLS 1.3 handshake the relay
dispatches on ALPN: `mtrp/1` selects length-prefixed frames, `http/1.1`
selects HTTP, where `GET /mtrp/v1` with subprotocol `mtrp.v1` upgrades to
WebSocket. TLS is not part of the trust model: the Noise handshake
authenticates the relay, so clients MAY skip certificate verification. Relays
SHOULD still present a publicly trusted certificate (for example via ACME
TLS-ALPN-01 on the same port) so that middleboxes and proxies accept the
connection. Closing a stream ends the sessions bound to it. Relays bound
connections per source address and in total, give the TLS handshake 10 s, and
drop frames for a client whose send queue is full.

## 2. Keys and identities

- Relay key: X25519 static key of each relay node, published in the signed
  relay map (section 8). Nodes MUST NOT accept a relay key from any other
  source.
- Client identity: the node's **disco key** (X25519). The node key appears in
  the ticket; the node proves possession of the disco key in the handshake.
- Core signing key: Ed25519; signs tickets and the relay map.

## 3. Frames

Every frame starts with a 4-byte header:

```
version   u8   = 1
type      u8
reserved  u16  = 0
```

| Type | Name | Body |
|---|---|---|
| 0x01 | INIT | `sender_index u32 || noise_msg1 || mac1 bytes[16] || mac2 bytes[16]` |
| 0x02 | RESPONSE | `sender_index u32 || receiver_index u32 || noise_msg2 || mac1 bytes[16] || mac2 bytes[16]` |
| 0x03 | COOKIE | `receiver_index u32 || nonce bytes[24] || encrypted_cookie bytes[32]` |
| 0x04 | CONTROL | `receiver_index u32 || counter u64 || ciphertext` |
| 0x05 | DATA | `receiver_index u32 || route u32 || payload` |

- Indexes are random non-zero `u32` chosen by each side for its end of a
  session (as in WireGuard); `receiver_index` names the session at the
  recipient.
- Limits: frame ≤ 2048 bytes on UDP and ≤ 4096 bytes on streams; DATA payload
  1..2032 bytes; CONTROL plaintext ≤ 1024 bytes. Larger frames are dropped
  (streams: the connection is closed).

## 4. Handshake

Noise pattern **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** with prologue
`MeshTransit MTRP v1`. Initiator static = client disco key; responder static =
relay key.

```
INIT     -> e, es, s, ss   payload: ClientHello
RESPONSE <- e, ee, se      payload: ServerHello
```

ClientHello (encrypted in INIT):

```
timestamp   u64        ; ms; strictly increasing per disco key (replay guard)
ticket_len  u16        ; 1..1024
ticket      bytes[ticket_len]
caps        u32        ; bit0 WebSocket-capable, others 0
padding     bytes[...] ; zero; INIT MUST be ≥ 256 bytes on UDP
```

ServerHello (encrypted in RESPONSE):

```
keepalive_s     u16    ; client sends a CONTROL KEEPALIVE when idle this long (default 25)
idle_timeout_s  u16    ; relay drops a silent session after this long (default 90)
max_routes      u16
not_after       u64    ; ticket expiry the relay enforces, ms
```

The relay, after decrypting ClientHello, MUST verify in this order and drop the
INIT silently on the first failure: ticket signature and key ID (section 6),
ticket time window, ticket `disco_key` equals the Noise initiator static key,
revocation lists, `timestamp` greater than the last accepted for this disco key,
admission limits. Only then does it allocate session state and reply.

The `timestamp` MUST be within ±60 s of the relay clock and not earlier than
the relay's start: replay state does not survive a restart, so an INIT from
before it cannot be told from a replay. A client whose INIT is refused this
way retries with a fresh timestamp.

### 4.1 DoS protection (mac1/mac2, cookies)

As in WireGuard:

```
mac1_key   = BLAKE2s-256("meshtransit/mtrp-mac1/v1" || 0x00 || relay_pub)
mac1       = BLAKE2s-128(key = mac1_key, frame bytes before mac1)
cookie     = BLAKE2s-128(key = R, source_ip || source_port)     ; R random, rotated every 120 s
cookie_key = BLAKE2s-256("meshtransit/mtrp-cookie/v1" || 0x00 || relay_pub)
COOKIE     = XChaCha20-Poly1305(cookie_key, nonce, cookie, aad = mac1 of the INIT)
mac2       = BLAKE2s-128(key = cookie, frame bytes before mac2)   ; zero if no cookie
```

- The relay drops any INIT with a wrong mac1 before doing any public-key work.
- Under load (configurable handshake rate), the relay requires a valid mac2;
  without it, it answers with a 64-byte COOKIE (smaller than any INIT) and
  keeps no state.
- On streams the TCP/TLS handshake already proves the address; mac2 is zero
  and COOKIE is never sent.
- RESPONSE carries mac1 computed with the same relay mac1 key and a zero
  mac2. The client checks it before any Noise work, so a spoofed RESPONSE is
  dropped cheaply.
- A client that receives a COOKIE stores it and sends a **new** INIT (new
  ephemeral key, new timestamp) with mac2; it never retransmits the old INIT.
- ClientHello padding: on UDP the client pads with zeros so that the INIT
  frame is at least 256 bytes (`MinUDPInit`); a RESPONSE (≈ 114 bytes) is
  therefore always smaller than the INIT it answers.

### 4.2 Session keys

After the handshake, Noise `Split()` gives one key per direction (the first
CipherState protects client→relay traffic on both sides). The Noise handshake
hash is the session's channel binding. CONTROL
frames use ChaCha20-Poly1305 with the Noise nonce encoding (32 zero bits
followed by the 64-bit little-endian `counter`) and
`aad = header || receiver_index || counter`. Each side keeps a sliding
anti-replay window of 2048 counters per session, updated only after a frame
authenticates. Counters start at 0; a session MUST NOT use counter 2^60 or
above and is re-established instead. A session is re-established
by a new handshake at least every 24 h and whenever the ticket changes zones.

## 5. CONTROL messages

Plaintext: `type u8 || body`.

| Type | Name | Body | Sender |
|---|---|---|---|
| 0x01 | KEEPALIVE | — | either |
| 0x02 | ROUTE_OPEN | `request u32 || peer_node bytes[32]` | client |
| 0x03 | ROUTE_OK | `request u32 || route u32` | relay |
| 0x04 | ROUTE_ERROR | `request u32 || code u8` (1 not authorised, 2 peer absent, 3 limit, 4 invalid) | relay |
| 0x05 | ROUTE_INCOMING | `route u32 || peer_node bytes[32]` | relay |
| 0x06 | ROUTE_CLOSE | `route u32 || reason u8` (1 peer left, 2 revoked, 3 expired, 4 by client) | either |
| 0x07 | TICKET_UPDATE | `ticket_len u16 || ticket` | client |
| 0x08 | TICKET_ACK | `not_after u64` | relay |
| 0x09 | SESSION_CLOSE | `reason u8 || retry_after_ms u32` (1 expired, 2 revoked, 3 draining, 4 policy, 5 idle) | relay |
| 0x0A | PATH_CHALLENGE | `nonce u64` (non-zero, random) | relay |
| 0x0B | PATH_RESPONSE | `nonce u64` (echo of the challenge) | client |

### 5.1 Routes

- A client opens a route to a peer by node key. The relay grants it only if
  the peer has an active session on this relay **and** the two sessions'
  tickets share at least one zone (same kind and ID). Otherwise ROUTE_ERROR.
- The relay assigns a route number in each session's own namespace and tells
  the peer with ROUTE_INCOMING, so both sides send DATA with their own route
  number and learn who a DATA frame came from.
- Routes close when either session ends, a ticket expires or is revoked, or a
  zone is withdrawn. Route numbers are random non-zero and not reused within a
  session.
- Limits: `max_routes` per session (from the ticket, default 4096); route opens
  are rate limited per session.

### 5.2 Liveness and roaming (UDP)

- A UDP session is bound to the source address of its INIT. DATA and CONTROL
  from any other address are dropped, except an authenticated CONTROL frame,
  which moves the binding to its source address (roaming).
- **Return routability.** A binding is *unverified* until the relay has proof
  that the client receives at that address. The client MUST send a KEEPALIVE
  immediately after the handshake; the first authenticated CONTROL frame from
  the handshake address verifies it (its keys required the RESPONSE sent
  there). After a roam the relay sends PATH_CHALLENGE to the new address; the
  client MUST answer with PATH_RESPONSE from that address, which verifies it.
  The relay caps traffic towards an unverified binding (default 16 KiB/s), so
  moving a binding to someone else's address cannot make the relay a
  reflector. Stream bindings are always verified.
- The client sends KEEPALIVE after `keepalive_s` without sending anything; the
  relay closes a session after `idle_timeout_s` without a valid frame.

### 5.3 Tickets during a session

The client renews its ticket with TICKET_UPDATE before `not_after`. The relay
verifies it like at handshake time (same node and disco key required) and
answers TICKET_ACK. At `not_after` without renewal the relay sends
SESSION_CLOSE(expired) and erases the session. Revocations from Core close
matching sessions with SESSION_CLOSE(revoked).

## 6. Tickets

A ticket is a canonical binary structure signed by Core with Ed25519.

```
magic       bytes[4]   = "MTT1"
key_id      bytes[8]   ; signing key ID (keys.md)
ticket_id   bytes[16]  ; random
issued_at   u64        ; ms
not_after   u64        ; ms; not_after - issued_at ≤ 15 min
node        bytes[32]  ; node (WireGuard) public key
disco       bytes[32]  ; disco public key used for the MTRP handshake
deployment  bytes[16]  ; deployment public ID
max_bps     u32        ; bytes/s per session; 0 = relay default
max_routes  u16        ; 0 = relay default
zone_count  u8         ; 1..32
zones       zone_count × (kind u8 || id bytes[16])   ; kind 1 Network, 2 Trust Contract
signature   bytes[64]  ; Ed25519 over ("meshtransit/mtrp-ticket/v1" || 0x00 || all preceding bytes)
```

Verification rules:

- Exact length for the declared `zone_count`; unknown magic, zone kind or
  trailing bytes: reject.
- `key_id` MUST be a currently trusted Core signing key; the relay learns
  trusted keys from Core, never from tickets.
- Accept only if `issued_at − 60 s ≤ now < not_after` and the lifetime bound
  holds.
- Zones MUST be sorted by `(kind, id)` without duplicates (canonical form).
- Reject if `ticket_id`, `node` or `disco` is on a revocation list.

## 7. Relay behaviour requirements

- Forwarding decisions use only in-memory state; no I/O on the packet path.
- Per-session token buckets for packets/s and bytes/s (from the ticket, capped
  by relay policy); excess DATA is dropped and counted.
- Global admission: maximum sessions and handshakes/s; above them, cookie mode.
- Metrics carry no keys, addresses, zones or route numbers as labels.
- Logs contain no keys, tickets, endpoints or zones; only aggregate counters and
  error codes.
- Draining: SESSION_CLOSE(draining, retry_after) lets clients move to another
  node before shutdown; the relay keeps forwarding for existing sessions until
  it stops, and admits no new ones.
- Admission before public-key work: per-source handshake rate (IPv6 counted
  per /64), global handshake rate and session capacity; above either global
  limit, UDP INITs need a valid cookie (mac2).
- CONTROL frames are rate limited per session after authentication; route
  numbers are never reused within a session; a TICKET_UPDATE must not be older
  than the ticket it replaces.

## 8. Signed documents and the relay map

Core distributes two signed documents in the same envelope:

```
magic        bytes[4]  = "MTSD"
version      u8        = 1
kind         u8        ; 1 relay map, 2 relay state
key_id       bytes[8]  ; Core signing key (keys.md)
payload_len  u32       ; 1 .. 8 MiB
payload      bytes     ; UTF-8 JSON
signature    bytes[64] ; Ed25519 over (domain || 0x00 || every preceding byte)
```

Domains: `meshtransit/relay-map/v1` (kind 1) and `meshtransit/relay-state/v1`
(kind 2), so a signature over one kind is never valid as the other. Receivers
verify the signature before parsing the payload.

The **relay map** payload:

```json
{"version": 1, "map_version": 3, "expires_at_ms": 1760600000000,
 "regions": [{"id": 1, "code": "sgp", "name": "Singapore",
   "nodes": [{"name": "sgp1", "host_name": "relay-sgp1.meshtransit.net",
     "ipv4": "18.142.253.199", "key": "mtrelay:…",
     "udp_port": 3479, "tls_port": 443, "stun_port": 3478,
     "stun_alt_port": 3480, "weight": 100}]}]}
```

Limits: 1–128 regions with unique non-zero IDs and lowercase codes, 1–16
nodes per region, unique relay keys, at least one address per node, expiry at
most 30 days ahead. A node rejects a map whose `map_version` is not newer than
the one it holds or whose `expires_at_ms` has passed.

## 9. Relay ↔ Core

Core publishes a signed **relay state** at `GET /relay/v1/state` on its control
host. The document is public: it contains no secrets and every revocation
entry is a hash, so relays need no credential to fetch it, and its signature
makes it trustworthy over any transport.

```json
{"version": 1, "sequence": 1760000000123,
 "issued_at_ms": 1760000000123, "expires_at_ms": 1760000600123,
 "signing_keys": [{"key": "mtsign:…", "not_after_ms": 1767000000000}],
 "revoked": {"tickets": ["<32 hex>"], "nodes": ["<32 hex>"], "discos": ["<32 hex>"]},
 "drain": ["mtrelay:…"]}
```

- `sequence` strictly increases; `expires_at_ms − issued_at_ms` ≤ 1 hour
  (Core uses 10 minutes and republishes every 10 seconds).
- `signing_keys` (1–4) are the Core keys whose tickets and documents relays
  accept. A relay bootstraps from configured keys and afterwards replaces its
  trusted set with the list of each newer verified state, keeping keys only
  until their `not_after_ms`. Rotation therefore publishes the next key here
  before Core signs with it.
- A revocation entry is the first 16 bytes of
  `BLAKE2s-256("meshtransit/relay-revocation/v1" || 0x00 || kind || value)`
  with kind 1 ticket ID, 2 node key, 3 disco key. Core lists every revoked
  value whose tickets may still be valid (≤ 15 minutes plus skew); relays close
  matching sessions and refuse matching tickets.
- `drain` lists relay keys that must drain (SESSION_CLOSE draining) and stop
  accepting sessions.
- Relays poll every 10 seconds with `If-None-Match`, accept only a newer
  `sequence` signed by a trusted key, and keep the last good state when Core
  is unreachable, logging when it has expired. Ticket lifetimes (≤ 15 min)
  bound how long a missed update matters.

Health and load reporting from relays to Core (for home-relay steering) needs
relay authentication and is specified with the relay fleet work.

## 10. Test vectors

`shared/mtrp/testdata/vectors.json`: frame encodings for every type, signed
tickets with fixed keys, mac1/mac2 and cookie values, and an `invalid` list
that every implementation MUST reject.
