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
| 0x0C | ZONES | `ticket_id bytes[16] \|\| offset u16 \|\| count u8 \|\| count × zone` (section 5.4) | client |

### 5.1 Routes

- A client opens a route to a peer by node key. The relay grants it only if
  the peer has an active session on this relay **and** the two sessions'
  tickets share at least one zone (same kind and ID) that Core has not
  withdrawn (section 9). Otherwise ROUTE_ERROR.
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
- The relay answers every KEEPALIVE. A client that has received nothing for
  1.2 s probes with a KEEPALIVE every 0.8 s and treats the relay as dead
  after three unanswered probes plus four smoothed round trips (0.4–2 s),
  about 3.2 s on a nearby relay, so it moves to another relay within seconds
  when one fails silently. An idle session therefore exchanges one KEEPALIVE
  pair every 1.2 s; control frames are rate limited per session (section 7),
  well above that.

### 5.3 Tickets during a session

The client renews its ticket with TICKET_UPDATE before `not_after`. The relay
verifies it like at handshake time (same node and disco key required) and
answers TICKET_ACK. At `not_after` without renewal the relay sends
SESSION_CLOSE(expired) and erases the session. Revocations from Core close
matching sessions with SESSION_CLOSE(revoked).

### 5.4 Zone lists of MTT2 tickets

An MTT2 ticket (section 6.1) carries its first zones inline and commits to the
rest. After a handshake or TICKET_UPDATE with an MTT2 ticket whose zones are
not all inline, the client sends the zones from index `min(zone_total, 32)`
onward in ZONES frames: `count` is 1..59, `offset + count ≤ zone_total`, and
the zones of each frame are in canonical order.

- The relay collects the frames of the ticket it is completing (matched by
  `ticket_id`); frames for any other ticket are ignored, as are repeats.
  Frames for the ticket already in force mean the client missed the
  acknowledgement: the relay repeats TICKET_ACK, at most once a second.
- Once every zone has arrived, the relay checks that the whole list is
  canonical, starts with the inline zones and matches `zone_digest`. Only then
  does the ticket come into force, and the relay answers TICKET_ACK with its
  `not_after`. A list that does not match is discarded entirely. The relay
  checks again that the ticket is not revoked and its key still trusted
  before putting it in force, as it may have been staged minutes earlier.
- Until then a new session uses the inline zones, which the signature covers
  directly, and a session that sent TICKET_UPDATE keeps its current ticket.
- A relay may decline to hold more zones than its policy allows (per session,
  and across the relay). It then puts the ticket in force with its inline zones
  only and answers TICKET_ACK at once, so the client stops sending. A renewal
  counts only the zones it adds to those the session already holds. A ticket
  older than the one in force or being assembled is acknowledged and dropped.
- The client sends the frames again, backing off from 1 s to 1 min, until it
  receives that TICKET_ACK. ZONES frames have their own rate limit, which
  allows several complete lists, and do not count against the CONTROL rate.

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
zone_count  u8         ; 1..32 (MTT2: section 6.1)
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
- Reject if `ticket_id`, `node` or `disco` is on a revocation list, or if
  every zone of the ticket is withdrawn.

### 6.1 MTT2: tickets that commit to many zones

An MTT1 ticket fits one handshake datagram, so it carries at most 32 zones. A
node with more (a Device with more than 31 Trust Contracts) receives an MTT2
ticket, but only from a Core that negotiated `relay.zones2` with it (MTCP §13).
MTT2 is MTT1 with these changes:

```
magic        bytes[4]   = "MTT2"
...          (key_id through max_routes as in MTT1)
zone_total   u16        ; 1..16384 zones granted
zone_digest  bytes[32]  ; SHA-256("meshtransit/mtrp-zones/v1" || 0x00 ||
                        ;   ticket_id || zone_total u16 || all zones)
inline_count u8         ; = min(zone_total, 32)
zones        inline_count × zone   ; the first zones of the canonical list
signature    bytes[64]
```

- The whole zone list is canonical (sorted by `(kind, id)`, no duplicates),
  so the Network zone (kind 1) is always inline.
- The signature covers `zone_digest`, and `zone_digest` binds the list to
  `ticket_id`, so a list cannot be reused under another ticket.
- Verification is as for MTT1 (section 6). Until the whole list is known,
  revocation by zones judges the inline zones: a ticket whose inline zones,
  its Network zone among them, are all withdrawn is refused (as a Private
  Interchange relay refuses a Network it does not serve).
- Beside an MTT2 ticket, Core issues an MTT1 fallback for the same keys and
  lifetime that names the inline zones. A relay that does not know MTT2 drops
  the INIT unanswered; the client retries with the fallback and later hands
  the MTT2 ticket over with TICKET_UPDATE, which such a relay ignores.
- Core sends the zone list to the node beside the ticket (`RelayTicket.zones`,
  MTCP §9). The node checks it against the ticket before using either.

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
kind         u8        ; 1 relay map, 2 relay state, 3 relay grant
key_id       bytes[8]  ; Core signing key (keys.md)
payload_len  u32       ; 1 .. 8 MiB
payload      bytes     ; UTF-8 JSON
signature    bytes[64] ; Ed25519 over (domain || 0x00 || every preceding byte)
```

Domains: `meshtransit/relay-map/v1` (kind 1), `meshtransit/relay-state/v1`
(kind 2) and `meshtransit/relay-grant/v1` (kind 3, section 9.2), so a
signature over one kind is never valid as another. Receivers verify the
signature before parsing the payload.

The **relay map** payload:

```json
{"version": 1, "map_version": 3, "expires_at_ms": 1760600000000,
 "regions": [{"id": 1, "code": "sgp", "name": "Singapore",
   "nodes": [{"name": "sgp1", "host_name": "relay-sgp1.meshtransit.net",
     "ipv4": "18.142.253.199", "key": "mtrelay:…",
     "udp_port": 3479, "tls_port": 443, "stun_port": 3478,
     "stun_alt_port": 3480, "weight": 100}]}]}
```

A region MAY carry `"preferred": true`: a Private Interchange region (section
9.2) granted to the node's Network. A node uses a reachable preferred region
as its home relay before shared regions and does not leave it for a faster
shared region; it keeps the shared regions to reach peers outside its
Network. Core sends each Network a map with the shared regions plus the
Private Interchange regions granted to it.

Limits: 1–128 regions with unique non-zero IDs and unique lowercase codes, 1–16
nodes per region, unique relay keys, at least one address per node, expiry at
most 30 days ahead. A node rejects a map whose `expires_at_ms` has passed or
whose `map_version` is older than the one it holds; a map with the same
`map_version` replaces the held one only when its `expires_at_ms` is later.

Core serves the map at `GET /relay/v1/map` on its control host and re-signs
it with every relay state refresh, with `expires_at_ms` 7 days ahead, so an
unchanged map keeps its `map_version` while its expiry moves forward. The
operator maintains the regions and nodes in a file whose SHA-256 is pinned in
Core's configuration; `map_version` is that file's revision.

## 9. Relay ↔ Core

Core publishes a signed **relay state** at `GET /relay/v1/state` on its control
host. The document is public: it contains no secrets and every revocation
entry is a hash, so relays need no credential to fetch it, and its signature
makes it trustworthy over any transport.

```json
{"version": 1, "sequence": 1760000000123,
 "issued_at_ms": 1760000000123, "expires_at_ms": 1760000600123,
 "signing_keys": [{"key": "mtsign:…", "not_after_ms": 1767000000000}],
 "revoked": {"tickets": ["<32 hex>"], "nodes": ["<32 hex>"], "discos": ["<32 hex>"],
             "zones": ["<32 hex>"]},
 "drain": ["mtrelay:…"]}
```

- `sequence` strictly increases; `expires_at_ms − issued_at_ms` ≤ 1 hour
  (Core uses 10 minutes and republishes every 10 seconds). Core signs once
  per 10-second window aligned to Unix time, with `issued_at_ms` and
  `sequence` set to the window start and every other time derived from it,
  so replicas behind one load balancer serve byte-identical documents.
  Between windows Core checks its revocations every second; when they
  change it signs the state at once with `issued_at_ms` and `sequence` set
  to that second (relay maps and grants keep their window). Replicas may
  sign such a state a second apart; relays keep the highest `sequence`.
- `signing_keys` (1–4) are the Core keys whose tickets and documents relays
  accept. A relay bootstraps from configured keys and afterwards replaces its
  trusted set with the list of each newer verified state, keeping keys only
  until their `not_after_ms`. Rotation therefore publishes the next key here
  before Core signs with it.
- A revocation entry is the first 16 bytes of
  `BLAKE2s-256("meshtransit/relay-revocation/v1" || 0x00 || kind || value)`
  with kind 1 ticket ID, 2 node key, 3 disco key, 4 zone (`zone kind u8 ||
  zone ID bytes[16]`). Core lists every revoked value whose tickets may still
  be valid (≤ 15 minutes plus skew); relays close matching sessions and refuse
  matching tickets. `zones` is omitted when empty.
- A withdrawn zone (for example an ended Trust Contract) no longer counts
  when two tickets are compared: relays close the routes whose sessions share
  no other live zone (ROUTE_CLOSE revoked), refuse new ones, and treat a
  ticket left without any live zone as revoked. Zone IDs are never reused, so
  withdrawal needs no record of issued tickets.
- Core derives the lists from durable state: node keys of key epochs that
  ended (rotation, expiry, revocation) and the current key of every Device
  that is not active, both within the window; and Trust Contracts that ended
  or passed their expiry within it. A Device resumed within the window drops
  out of the list, so its new tickets are accepted.
- `drain` lists relay keys that must drain (SESSION_CLOSE draining) and stop
  accepting sessions.
- Both documents are served with an `ETag` and `Cache-Control: no-cache`,
  answer `If-None-Match` with 304, are rate limited per source (an IPv4
  address or an IPv6 /64; when Core's bounded source table is full the
  least recently seen source is evicted, so new sources are never locked
  out), and return 503 until Core has signed its first state.
- A relay holding a state polls `GET /relay/v1/state?wait=N` (N = 1–25
  seconds) with `If-None-Match`. Core holds the request until it signs a
  newer state (200) or N seconds pass (304), and answers at once beyond a
  bound on held polls (in total, and four per source); other query
  parameters are refused (400). After a
  200 or a held 304 the relay polls again at once, so a revocation reaches
  it within about a second of Core signing it. A 304 that comes back early
  means Core does not hold polls: the relay then polls every 10 seconds.
- Relays accept only a newer `sequence` signed by a trusted key (ignoring,
  without error, a state that is not newer, as a replica behind may serve,
  and then waiting a second before asking again), and keep the last good
  state when Core is unreachable, logging when it has expired. A failed
  poll is retried after about a second, doubling to a minute. A starting
  relay reads no session until it has applied a first state, waiting up to
  20 seconds before serving on its bootstrap keys. Ticket lifetimes
  (≤ 15 min) bound how long a missed update matters.

Health and load reporting from relays to Core (for home-relay steering) needs
relay authentication and is specified with the relay fleet work.

### 9.1 Grants to nodes

Core delivers a node's Interchange access over its MTCP session: the signing
keys in `KeyUpdate`, the signed relay map, and the node's `RelayTicket`
([mtcp-v1](mtcp-v1.md) §7.3, §9, §11).

- The control session is authenticated, so the keys need no other signature;
  the node verifies the relay map with them before use and keeps the previous
  map when verification fails.
- Tickets bind the node and disco keys the node last reported and the zones
  of its Network and of every Trust Contract it takes part in (at most 31).
  They live 15 minutes, never past the node's authority deadline, and are
  replaced 5 minutes before expiry, at once when the disco key or zones
  change.
- A node keeps its last ticket until it expires when a later map carries
  none.
- The relay map is the only source of relay regions: Core validates the home
  region a node reports against it.

### 9.2 Private Interchange grants

A Workspace may run its own relays (Private Interchange, the same software)
and grant each to some of its Networks. Core includes a granted relay's
region, marked preferred, in those Networks' relay maps. The relay learns
which Networks it serves from a relay grant:

```json
{"version": 1, "relay": "mtrelay:…", "sequence": 1760000000000,
 "issued_at_ms": 1760000000000, "expires_at_ms": 1760000600000,
 "networks": ["01890f00-0000-7000-8000-000000000201"]}
```

- Core signs it as a kind 3 document, sorted distinct Network IDs, at most
  1024, lifetime at most one hour (Core uses 10 minutes, re-signed with every
  state refresh, `sequence` the signing window).
- `GET /relay/v1/grant?relay=<mtrelay:…>` returns the document sealed to that
  relay key with the Noise `N` pattern (Noise_N_25519_ChaChaPoly_BLAKE2s,
  prologue `meshtransit/relay-grant/v1`): an ephemeral key, then the
  encrypted document. Only the relay can read which Networks it serves;
  anyone may ask. Core answers 404 for a relay key no Workspace registered.
- A relay started as a Private Interchange polls its grant with the state,
  accepts only a newer `sequence` for its own key signed by a trusted key,
  and keeps the last good grant while it is valid. Without a valid grant it
  accepts no session (fail closed).
- With a grant, a relay accepts a session only when its ticket names one of
  the granted Networks, and opens a route only between sessions that share a
  granted Network. Trust Contract zones do not admit sessions to a Private
  Interchange.

## 10. Test vectors

`shared/mtrp/testdata/vectors.json`: frame encodings for every type, signed
tickets with fixed keys, mac1/mac2 and cookie values, and an `invalid` list
that every implementation MUST reject.
