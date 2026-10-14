# MTCP v1: MeshTransit Control Protocol

Draft 1, 2026-10-09. Schema: [`api/mtcp/v1/mtcp.proto`](../../api/mtcp/v1/mtcp.proto).
Implementation: `shared/mtcp` (records, handshake, session, messages,
proofs), generated types in `api/mtcp/v1` (`make proto`); Core `control` role
and meshd (phase P4).

MTCP connects a node (meshd) to Core. Over one long-lived, mutually
authenticated session it registers the node, delivers its network map,
collects endpoint and NAT reports, hands out relay tickets and pushes lifecycle
changes. MTCP v1 replaced the earlier compatibility protocol entirely; there is
no dual stack. Data never flows over MTCP.

## 1. Roles and keys

| Key | Type ([keys.md](keys.md)) | Held by | Use in MTCP |
|---|---|---|---|
| Machine key | X25519, `mtmachine:` | Node installation | Noise initiator static key; identifies the installation |
| Control key | X25519, `mtcontrol:` | Core deployment | Noise responder static key |
| Node key | X25519, `mtnode:` | Node | WireGuard key; registered and rotated over MTCP |
| Disco key | X25519, `mtdisco:` | Node | Reported over MTCP; distributed to peers in the map |

- The machine key is created once per installation and never leaves it. It
  survives node key rotation and re-registration; it is replaced only by
  reinstalling or by an explicit reset.
- A node keeps one machine key per (control host, profile). Each machine key
  is bound to at most one Device, and a Device to exactly one machine key.
  Two profiles on the same control host therefore use two machine keys and
  two independent sessions.
- The node pins the control key at enrollment (section 2.1). A session to any
  other key is refused unless the pinned key announced it (section 11).
- Core's Ed25519 signing keys (tickets, relay map) reach the node only inside
  an authenticated session (section 11).

## 2. Transport

MTCP runs over TLS to `https://<control host>` on port 443. Inside TLS, the
node and Core run their own Noise handshake, so a TLS-terminating proxy, CDN or
middlebox can neither read nor forge control messages. TLS protects the HTTP
exchange and hides the Noise handshake from passive observers; it is not part
of the trust model.

### 2.1 Control key discovery

`GET /mtcp/v1/key` returns, over TLS with Web PKI validation:

```json
{"version": 1, "keys": [{"key": "mtcontrol:<64 hex>", "not_after": "2027-10-09T00:00:00Z",
                          "fingerprint": "<32 hex>"}]}
```

- A node fetches it **only at enrollment**, when it has no pinned key for this
  control host, and pins every listed key. The response is at most 4 KiB.
- After enrollment the node never trusts this endpoint again for that profile.
  Key changes arrive inside an authenticated session (section 11). A node that
  loses every pinned key must be re-enrolled by the user.
- The control key fingerprint is the first 16 bytes of
  `BLAKE2s-256("meshtransit/mtcp-control-fp/v1" || 0x00 || key)`, written as
  32 lowercase hex characters. Enrollment commands and links that Core
  generates (enrollment keys, Console install commands) MUST carry it as
  `ck=<fingerprint>`; the node then refuses a key that does not match, which
  removes the Web PKI from the trust path. The key document lists each key's
  fingerprint so the Console can build install commands; a node never
  trusts that field and computes the fingerprint itself. Only the interactive flow started
  without a link relies on Web PKI; its approval page shows the fingerprint so
  the user can compare it with `meshctl status`.

### 2.2 Upgrade

The node opens TLS (1.3 preferred, 1.2 minimum; ALPN `http/1.1`) and sends:

```
POST /mtcp/v1 HTTP/1.1
Host: <control host>
Upgrade: mtcp/1
Connection: Upgrade
MTCP-Key: <16 hex: key ID of the control key the node chose>
MTCP-Handshake: <base64url, no padding, of the Noise INIT record>
Content-Length: 0
```

`MTCP-Key` tells Core which control private key to use (key IDs as in
[keys.md](keys.md)), so Core never trial-decrypts. A deployment has at most two
active control keys (current and next). The node uses the pinned key with the
latest `not_after` and retries once with the other pinned key when Core
answers `421 Misdirected Request` (unknown key ID).

Core answers `101 Switching Protocols` with `Upgrade: mtcp/1` and
`MTCP-Handshake: <base64url of the RESPONSE record>`. From then on the
connection carries records (section 4) in both directions.

- `MTCP-Handshake` is at most 2048 bytes after decoding. A missing, oversized
  or undecodable header gets `400` with no body.
- Core may answer `503` with `Retry-After` when it sheds load before any
  Noise work, and `426` when the node must update (section 12).
- Nodes MAY use an HTTP proxy with `CONNECT`; the Noise layer makes this safe.

### 2.3 WebSocket fallback

When an intermediary does not pass `Upgrade: mtcp/1` (some corporate proxies),
the node connects to `wss://<control host>/mtcp/v1/ws` with
`Sec-WebSocket-Protocol: mtcp.v1` and the same `MTCP-Key` header. The first binary message from the node is
the INIT record, the first from Core is the RESPONSE record; afterwards every
binary message is exactly one record. Text messages close the connection.

The node tries the upgrade first and falls back to WebSocket only after the
upgrade fails with a non-MTCP response (no `101`, or a `101` without the
expected headers). It remembers a working fallback per network for 24 hours.

## 3. Handshake

Noise pattern **`Noise_IK_25519_ChaChaPoly_BLAKE2s`**, prologue
`MeshTransit MTCP v1`. Initiator static = machine key; responder static =
control key.

```
INIT     -> e, es, s, ss   payload: ClientHello
RESPONSE <- e, ee, se      payload: ServerHello
```

Handshake records have the same framing as transport records (section 4.1),
with record type `0x01` (INIT) and `0x02` (RESPONSE).

**ClientHello** (protobuf `ClientHello`):

| Field | Meaning |
|---|---|
| `protocol_version` | `1` |
| `timestamp_ms` | Node clock; strictly increasing per machine key |
| `client` | Product, version, OS, architecture |
| `capabilities` | Feature names the node supports (section 13) |
| `node_key` | Current node key, or empty before the first registration |
| `profile_hint` | Opaque value from the last `ServerHello.profile_hint`, or empty |

Core processes an upgrade in this order:

1. **Before any cryptography:** per-source-IP rate and connection limits and
   replica load shedding (section 14). Failures get `503` (with `Retry-After`)
   or are dropped; no Noise work is done.
2. Decrypt INIT. Failure: close silently.
3. `timestamp_ms` within ±10 minutes of Core time and greater than the last
   accepted value for this machine key. For a machine key bound to a Device,
   the last accepted value is stored durably with the binding and shared by
   all replicas; for unbound keys a bounded per-replica cache is enough,
   because an unbound key has no session to displace. Failure: close
   silently.
4. Version and policy: unsupported `protocol_version`, a client below the
   deployment's minimum version, or maintenance. Failure: Core completes the
   handshake with `ServerHello.reject` set (`VERSION_UNSUPPORTED`,
   `CLIENT_TOO_OLD`, `MAINTENANCE`) and closes after sending it.

**Establishment.** The node MUST send its first TRANSPORT record (a `Ping`,
or `RegisterRequest`) immediately after receiving RESPONSE. Core treats the
session as established only when it has decrypted that record, which proves
the initiator holds the machine private key *now* and not merely in a
captured INIT. Only an established session can replace another (section 5)
or receive the map.

**ServerHello** (protobuf `ServerHello`):

| Field | Meaning |
|---|---|
| `protocol_version` | `1` |
| `server_time_ms` | Core clock, for skew diagnostics |
| `session_id` | Random 16 bytes; appears in logs on both sides |
| `capabilities` | Intersection of the node's list and Core's |
| `limits` | Keepalive interval, idle timeout, map acknowledgement window |
| `profile_hint` | Opaque, ≤ 64 bytes; lets Core route the next session to the same shard |
| `reject` | Set only when the session is refused (version, maintenance) |

The handshake has a 10 s deadline from TCP connect.

## 4. Records and messages

### 4.1 Records

On the upgraded stream every record is:

```
length      u16        ; length of type + body, 1..65535
type        u8
body        bytes[length - 1]
```

On WebSocket the binary message is `type || body` (no length field).

| Type | Name | Body |
|---|---|---|
| 0x01 | INIT | Noise handshake message 1 |
| 0x02 | RESPONSE | Noise handshake message 2 |
| 0x03 | TRANSPORT | Noise transport message (ciphertext and 16-byte tag) |

Any other type, or a handshake record after the handshake, closes the
connection. Noise transport messages use the Noise nonce counter, so records
cannot be reordered, dropped or replayed without detection; a decryption
failure closes the connection.

### 4.2 Messages

The plaintext of a TRANSPORT record is one fragment:

```
msg_type    u8         ; message type (table below)
flags       u8         ; bit0 MORE: another fragment follows; bit1 ZSTD; others 0
payload     bytes[...]
```

- A message is the concatenation of the payloads of consecutive fragments of
  the same `msg_type`, ending with a fragment without MORE. Fragments of
  different messages never interleave.
- `ZSTD` is set on every fragment of a compressed message or on none. The
  reassembled payload is then one zstd frame; the decompressed size MUST be
  declared in the frame header and MUST NOT exceed the message type's limit.
  Decoders use a window of at most 8 MiB and no dictionaries. Compression is
  optional per message: a sender whose encoder cannot declare the size (some
  encoders omit it for small inputs) sends that message uncompressed.
- The reassembled (and decompressed) payload is the protobuf encoding of the
  message type. Unknown protobuf fields are ignored; unknown `msg_type` values
  close the connection with `ERROR UNSUPPORTED`.
- A receiver enforces the size limit **while** reassembling and decompressing,
  never after.

| Type | Message | Direction | Limit (decoded) |
|---|---|---|---|
| 0x01 | `Error` | both | 4 KiB |
| 0x02 | `Ping` | both | 256 B |
| 0x03 | `Pong` | both | 256 B |
| 0x10 | `RegisterRequest` | N→C | 16 KiB |
| 0x11 | `RegisterResponse` | C→N | 8 KiB |
| 0x12 | `RotateNodeKey` | N→C | 4 KiB |
| 0x13 | `Logout` | N→C | 1 KiB |
| 0x14 | `RotateNodeKeyResponse` | C→N | 1 KiB |
| 0x20 | `MapSnapshot` | C→N | 32 MiB |
| 0x21 | `MapDelta` | C→N | 8 MiB |
| 0x22 | `MapAck` | N→C | 256 B |
| 0x23 | `MapResync` | N→C | 256 B |
| 0x30 | `EndpointReport` | N→C | 8 KiB |
| 0x31 | `HostinfoReport` | N→C | 8 KiB |
| 0x32 | `HealthReport` | N→C | 16 KiB |
| 0x33 | `PathStatsReport` | N→C | 256 KiB |
| 0x34 | `EnforcementReport` | N→C | 1 KiB |
| 0x40 | `RelayTicket` | C→N | 256 KiB (4 KiB without `relay.zones2`) |
| 0x50 | `Lifecycle` | C→N | 4 KiB |
| 0x51 | `KeyUpdate` | C→N | 4 KiB |
| 0x52 | `Notice` | C→N | 8 KiB |

A message in the wrong direction closes the connection.

### 4.3 Rekeying and session lifetime

A session lasts at most 24 hours or 2^32 records per direction, whichever
comes first. Core then sends `Lifecycle{state: RECONNECT}`; the node finishes
in-flight work and reconnects. There is no in-band rekey: a fresh handshake is
simpler and also re-checks admission.

## 5. Session model

- One session per machine key. A newly **established** session (section 3)
  for a machine key replaces the older one: Core sends `Error{code: SESSION_REPLACED}` on the
  old session and closes it.
- Core identifies the node by the authenticated machine key, never by
  anything the node claims later in the session.
- After the handshake the node sends either `RegisterRequest` (no Device, or
  re-registration) or nothing; if the machine key is bound to an authorized
  Device, Core starts the map stream (section 7, after the `KeyUpdate` of section 11) without being asked.
- Liveness: either side sends `Ping` after `keepalive_s` (default 25 s)
  without sending anything; the peer answers `Pong` with the same nonce. A
  side that receives nothing for `idle_timeout_s` (default 75 s) closes.
- Reconnect: the node retries with jittered exponential backoff from 1 s to
  60 s, resetting after a session that lasted 60 s. `Retry-After` and
  `Error.retry_after_ms` set a lower bound.

## 6. Registration

### 6.1 Requests

`RegisterRequest` binds the session's machine key to a Device:

| Field | Meaning |
|---|---|
| `node_key`, `disco_key` | The keys the Device will use |
| `node_key_proof`, `disco_key_proof` | Proofs of possession (6.4) |
| `hostinfo` | Hostname, OS, versions (section 8.2) |
| `auth.enrollment_key` | An enrollment credential `mtc1.<id>.<secret>` |
| `auth.interactive` | Ask for a browser approval URL |
| `auth.resume` | Renew the Device this machine key already owns, before it expires (6.2) |

Core MUST evaluate an enrollment key in constant time with respect to the
secret, count it against the credential's use limit only on success, and never
echo it back or log it.

Core MUST reject (`CONFLICT`) a node key or disco key that belongs to another
Device, or that any Device has used before; retired keys are remembered. Core
MUST reject a request whose proofs do not verify (`INVALID`).

### 6.2 Responses

`RegisterResponse` has exactly one outcome:

- `authorized`: the Device ID, Network, assigned addresses, key expiry. The
  map stream starts immediately on the same session.
- `pending`: an approval URL (`https://<origin>/register/v1/<url token>`, no
  query, ≤ 512 bytes), a separate `resume_handle`, and their expiry
  (≤ 10 minutes). The session stays open; when the user approves, Core sends a
  second `RegisterResponse{authorized}` on it. If the session drops, the node
  reconnects and repeats the request with `auth.interactive.resume_handle`; it
  never polls. The pending approval is bound to the requesting machine key,
  node key and hostname: a resume handle presented by any other machine key,
  or with other keys, is rejected (`EXPIRED`), and knowing the approval URL
  is never enough to obtain the authorization. The handle is opaque to the
  node; Core MAY use the URL token itself, since completing the approval also
  requires the session's machine key and node key. A pending approval that
  expires is answered with `rejected{EXPIRED}`. The approval page shows the hostname and the
  machine key fingerprint so the approver can recognise the device.
- `rejected`: a code (`INVALID`, `CREDENTIAL_INVALID`, `CREDENTIAL_EXHAUSTED`,
  `NOT_PERMITTED`, `CONFLICT`, `EXPIRED`) and a human-readable message that
  reveals nothing about other tenants.

The browser flow lets the user choose the Workspace and Network; Core never
selects one on the user's behalf.

`auth.resume` is accepted only when the Network policy explicitly enables
automatic renewal for the Device, and only while it has not expired;
otherwise Core answers `rejected{EXPIRED}` and the node must use the
interactive flow. A stolen machine key alone therefore cannot keep a Device
alive past the expiry a person approved. (No policy enables renewal yet, so
Core currently always answers `EXPIRED`.)

### 6.3 Node key rotation

`RotateNodeKey{new_node_key, new_disco_key, proofs}` replaces the Device's
node and disco keys. Core accepts it only on a session whose machine key owns
the Device and applies the same uniqueness and proof checks as registration.
It applies the change atomically, answers `RotateNodeKeyResponse`, propagates
the new keys to peers as one map change, issues a new `RelayTicket` and adds
the old disco key to the relay revocation list (MTRP v1 §6).

The node stores the staged keys durably before sending the request and keeps
the old keys until it receives the response or a map whose self entry carries
the new keys. After a crash it reconnects with the old node key in
`ClientHello.node_key` and sends the same `RotateNodeKey` again; Core treats a
request whose keys already are the Device's current keys as a successful
repeat. Rotation does not need a new approval.

Every key change advances the Network revision and resets the WireGuard
sessions of the Device's peers, so a Device may change its node key at most 4
times within one hour (section 14). Core checks it under the Device's lock,
so it holds across replicas. A rotation over the budget is answered
`Error{NOT_PERMITTED, retry_after_ms}`.

A repeat of a committed rotation always succeeds, so `NOT_PERMITTED` (budget
or key conflict) is definitive: Core did not apply the rotation. The node
discards the staged keys, goes on with its current keys and may request a new
rotation after `retry_after_ms`. Any other error (`OVERLOADED`, `INTERNAL`,
a lost connection) leaves the outcome unknown, and the node keeps the staged
keys and repeats the same request. Core therefore sends `NOT_PERMITTED` for
`RotateNodeKey` only after it checked that the rotation is not a repeat.

### 6.4 Proof of possession

For a node key or disco key with private part `k` and public part `K`:

```
secret = X25519(k, control_public)           ; Core computes X25519(control_private, K)
proof  = BLAKE2s-256(key = secret,
                     "meshtransit/mtcp-key-proof/v1" || 0x00 || h || K)
```

`h` is the Noise handshake hash of the current session (channel binding), so a
proof cannot be replayed into another session. An all-zero `secret` is a
failure.

### 6.5 Logout

`Logout{}` asks Core to deauthorize the Device (the node is being removed or
the user signed out). Core revokes the Device and its current keys, removes
it from peers' maps, records `device.logged_out` with the Device's owner as
the actor, sends `Lifecycle{state: LOGGED_OUT}` and closes. Only a session
whose machine key and node key are the Device's current keys can log it
out; otherwise Core answers `Error{code: NOT_AUTHORIZED}`. The Device must
enroll again. A Network policy MAY
forbid self-logout for managed Devices; Core then answers
`Error{code: NOT_PERMITTED}`.

## 7. Map

### 7.1 Stream and revisions

The map is the node's complete view: itself, the peers it may reach or that
may reach it, packet filter, DNS, relay map and settings.

- Every map message carries a `view` (`epoch` u64, `seq` u64). Every
  `MapSnapshot` has an `epoch` strictly greater than any earlier one for this
  Device and `seq = 1`; each following `MapDelta` keeps the epoch and
  increases `seq` by one.
- A `MapSnapshot` replaces the node's entire state.
- A `MapDelta` from another epoch is dropped silently (it predates the latest
  snapshot). A `MapDelta` of the current epoch whose `seq` is not exactly the
  current `seq + 1` is a gap: the node sends `MapResync{epoch, seq}` and
  ignores further deltas of that epoch until a new snapshot arrives. A node
  has at most one resync outstanding and sends at most one per 10 s.
- Core answers a resync with a new snapshot, unless it has already sent a
  snapshot with a newer epoch, in which case it ignores the resync.
- Every map message also lists `network_revisions`: the revisions of the
  Networks the node itself belongs to. Networks of other Workspaces that
  contribute shared peers are never listed. Core records which revisions were delivered (policy
  distribution, R1-65) and the time machine (R1-68) can relate a node's view
  to a historic revision. Nodes treat them as opaque diagnostics.
- A delta is atomic: the node applies all of it or none.

### 7.2 Flow control

The node sends `MapAck{epoch, seq}` after applying a message, at most once per
second (it acknowledges the latest applied `seq`). Core keeps at most 8
unacknowledged map messages per session. When that window is full, Core stops
sending and coalesces pending changes; if they exceed 8 MiB, or the window
stays full for 60 s, it discards them and sends one fresh snapshot (new epoch)
once the node acknowledges. The pending delta budget (8 MiB) and the one
snapshot in flight are exempt from the 16 MiB outbound cap of section 14. A slow node therefore costs bounded memory and gets a
correct (if later) map.

### 7.3 Contents

`MapSnapshot`:

| Field | Meaning |
|---|---|
| `self` | The node's own Device entry |
| `peers` | Peer entries, sorted by `device_id`; at most 10,000 |
| `packet_filter` | Inbound rules for this node |
| `dns` | DNS configuration |
| `relay_map` | Signed relay map bytes (MTRP v1 §8), verified by the node |
| `settings` | Report intervals and the path statistics switch |

`MapDelta` carries only what changed:

| Field | Meaning |
|---|---|
| `self` | Replaces the self entry |
| `peers_upsert` | Full replacements, keyed by `device_id` |
| `peers_remove` | `device_id`s to remove |
| `peer_patches` | Partial updates of volatile fields (endpoints, home relay, online, last seen, disco key) |
| `packet_filter` | Replaces the whole filter when present |
| `dns` | Replaces the whole DNS configuration when present |
| `relay_map` | Replaces the relay map when present |
| `settings` | Replaces settings when present |

A `device_id` appears at most once across `peers_upsert`, `peers_remove` and
`peer_patches` in one delta. A patch for an unknown peer, or an upsert and a
removal of the same ID, makes the delta invalid (the node resyncs).

**Device entry** (`Device`, used for self and peers):

| Field | Meaning |
|---|---|
| `device_id` | Stable public ID (string, ≤ 64 bytes) |
| `name` | Fully qualified DNS name, lowercase, trailing dot |
| `display_name` | For UI only |
| `node_key`, `disco_key` | Current keys |
| `addresses` | Device addresses (one IPv4 /32 and/or one IPv6 /128) |
| `allowed_prefixes` | Prefixes routed to this peer (its addresses plus approved subnet routes) |
| `endpoints` | Candidate UDP endpoints with their kind (disco v2 endpoint kinds) |
| `nat` | The peer's last NAT classification (nat-classification §1) |
| `home_relay` | Relay region ID the peer is reachable through |
| `online`, `last_seen` | Presence, as known to Core; `online` is absent when Core has no connectivity for the Device (unknown, not offline: nodes still probe it) |
| `key_expiry` | When the Device stops being valid without renewal |
| `owner` | Opaque owner reference for display (no personal data beyond a display name) |
| `capabilities` | Feature names the peer supports (section 13) |
| `alias` | Device alias grant, when the peer is reached through a share (7.4) |

A peer from another Workspace (reached through a share or Trust Contract)
carries only what the node needs: its consumer-side name, keys, alias
addresses, endpoints and presence. `display_name`, `owner` and the provider's
own name are omitted.

**Packet filter** (`PacketFilter`): a list of inbound allow rules, default
deny. Each rule has `sources` (prefixes, at most 1024), `destinations`
(prefix plus port ranges) and `protocols` (IANA numbers; empty means TCP, UDP
and ICMP). At most 10,000 rules. Rules are node-reduced: they mention only
traffic this node can receive.

**DNS** (`DnsConfig`): `records` (name, A/AAAA, value) for Device names and
imported shares, `resolvers` (IP and optional DoH/DoT URL), `search_domains`,
`routes` (name suffix → resolvers, for split DNS). At most 50,000 records.

### 7.4 Device alias grants

The `alias` field carries the [device alias v1](device-alias-v1.md) grant as
typed fields: `contract_id`, `endpoint_id`, `generation`,
`grant_revision`, `recovery_epoch`, `role` (consumer or provider),
`expires_at`, `services` (protocol, port range) and the local masquerade
addresses for this peer. All semantics (exact intersection, deadlines,
atomic replacement, no reverse rule) carry over unchanged. A node that does
not advertise `device-alias.v1` never receives alias peers.

### 7.5 Withdrawal

Core never signals revocation with an empty map. It sends `Lifecycle`
(section 10); the node then removes peers, filter and DNS itself.

## 8. Node reports

### 8.1 Endpoints and NAT

`EndpointReport` carries the node's current candidates and NAT classification:
`disco_key`, `endpoints` (address and kind, at most 32), `nat`
(mapping, filtering, allocation, sequential step), `ipv6` (global address
present, STUN over IPv6 succeeded), `preferred_relay` (region ID) and
`observed_at`. With `nat.report1` the node also sends `nat_observed_ms` (when
`nat` was classified) and `port_mapping`: the protocol (1 PCP, 2 NAT-PMP,
3 UPnP IGD), the state (1 off, 2 searching, 3 mapped, 4 double NAT,
5 unavailable, 6 failed) and the expiry of its gateway mapping, never its
address (that is a `PORT_MAPPED` endpoint).

- `nat` is present only while the node holds a current classification
  (nat-classification §4); absent means not classified, not "no NAT".
- The `nat` and `port_mapping` values are numbers: Core reads codes it does
  not know as unknown instead of rejecting the report, so newer nodes can add
  values.
- Core keeps the latest NAT, IPv6 and port mapping state per Device for the
  session and stores it only when it changes; the Console shows it with the
  Device's paths.

- `disco_key` MUST equal the Device's current disco key (the one proved in
  this session's registration or rotation); otherwise Core answers
  `Error{INVALID}` and ignores the report.
- The node sends its first report right after its first map, with an empty
  `endpoints` list when it has no candidates yet: relay tickets bind the
  disco key, so Core issues the relay grant (section 9) only once it has one.
- The node sends it after each change, and again every 5 minutes. Core keeps
  the endpoints while the session lives and drops them about 30 s (the
  presence TTL) after it ends.
- A node sends at most one report per second: it coalesces faster changes
  and sends the latest when the second has passed. Core never drops a
  report: one that arrives less than a second after the last one it stored
  is kept, replacing any kept before, and stored when the second ends.
- **Announce interval.** A Device's peers learn of at most one change of
  its endpoints, disco key or preferred relay per announce interval (5 s by
  default), across its sessions and Core replicas, plus the disco key
  changes announced at once below: every change wakes the map stream of
  each peer, so a Device changing them in a loop would otherwise cost its
  Network one delta per peer per change.
  - The first change after a quiet interval is announced at once.
  - Changes within the interval are stored at once, so a new map stream sees
    them, and the latest one is announced when the interval ends. None is
    lost: if the session or replica ends first, the connectivity resync
    (every 30 s) announces it.
  - A new disco key is announced at once, at most once every 20 s (three
    times a minute): the node's own map waits for it, so a reconnect is not
    held back. Another new disco key within those 20 s waits like any other
    change, at most one interval.
  - A new session generation (a key rotation, section 6.3) starts its own
    interval. So does a Device whose endpoint state expired (about 30 s
    after its last session ended); the session limits (section 14) bound how
    often that happens.
  - Peers keep reaching a Device whose new endpoints wait: a direct path
    still open keeps working, and otherwise the Device's CALL_ME_MAYBE
    through the relay names its current endpoints and a peer learns an
    address the Device pings it from (peer-reflexive, disco-v2 §4.1). A
    new preferred relay is not learned this way: until it is announced, at
    most one interval later, peers keep using the old one.
- Core rejects a malformed endpoint (address not 4 or 16 bytes, port outside
  1–65535) with `Error{INVALID}`, ignores endpoints of unknown kind and
  silently drops well-formed endpoints it does not distribute (unspecified,
  loopback, link-local, multicast or broadcast addresses). It distributes
  only the latest report to peers, in a map delta; Core currently sends the
  whole peer entry in `peers_upsert`.

### 8.2 Hostinfo

`HostinfoReport`: hostname, OS and version, client version, architecture,
optionally the device model, and the routes the node offers
(`advertised_prefixes`: subnets, or `0.0.0.0/0` and `::/0` to offer an exit
node). Offered routes take effect only after approval in Core; approved ones
appear in the node's and its peers' `allowed_prefixes`. Sent after registration and on change. Core uses
the hostname only to propose a Device name; it never trusts it for identity.

### 8.3 Health and path statistics

- `HealthReport`: component states (data plane, DNS, relay sessions, clock
  skew) as enums plus short codes; no free-form logs. On change, at most once
  per 10 s.
- `PathStatsReport`: per peer, for the last interval (default 60 s): bytes and
  packets sent/received direct and relayed, the path technique (direct,
  peer-reflexive, prediction, birthday, relay), the relay region, smoothed RTT
  bucket. At most 10,000 entries. Used for the Console "direct or relayed and
  why" view and capacity planning; retained according to the deployment's
  telemetry policy.

  A relayed peer carries `relay_reason`, the node's own view of why it has no
  direct path:

  | Reason | Meaning |
  |---|---|
  | `BOOTSTRAP` | The peer has been relayed for less than 30 s; direct paths are still being tried |
  | `NO_CANDIDATES` | The peer publishes no endpoint the node could try |
  | `NO_RESPONSE` | Endpoints were tried and none answered (UDP blocked or a strict NAT) |
  | `UNSPECIFIED` | Not relayed, or the node cannot tell |

  The node samples its peers every 10 s and sends one report per interval;
  a report the session has not sent yet is replaced by the next one. Core
  accepts at most one report per 30 s per session, keeps only peers present
  in the node's current map, and drops the rest.
  Peers that belong to another Network (shares) are kept without their
  identity. Core stores only the latest report, at most 256 peers ordered by
  traffic, and discards it when the node starts a new session.

Flow logs keep their separate HTTPS endpoint; they are not part of MTCP v1.

### 8.4 Enforcement

`EnforcementReport{view, digest, grants, applied_ms}`: the
[policy digest](policy-digest-v1.md) of the rules the node's packet filter
enforces after applying the map at `view`, how many grants they cover, and
when it installed them. Sent after each change of the installed rules, once
more 30 s later, and every 5 min while unchanged; at most one per second.
Core compares it with the digest of the filter it sent at that view and shows
the Device as enforced, applying (within 60 s) or mismatch. The report is
evidence from the node, not attestation (policy digest §6).

## 9. Relay access

- `RelayTicket{ticket, not_after, zones}` carries an MTRP v1 ticket (MTRP §6)
  for this node's disco key. With `relay.zones2`, a node in more than 31 Trust
  Contracts receives an MTT2 ticket naming all of them, and `zones` carries the
  list it commits to (MTRP §6.1, 17 bytes per zone) and `fallback_ticket` an
  MTT1 ticket for the same keys naming its inline zones, for relays that do
  not take MTT2. The node rejects a ticket whose list or fallback does not
  match. Without `relay.zones2` the ticket names
  the Network and the 31 oldest Trust Contracts, and `zones` is empty. Core sends one right after authorization, and a fresh one
  at least 2 minutes before the current one expires, and immediately after any
  change of the node's zones (Network or Trust Contract membership).
- The relay map is part of the map (section 7.3); the node verifies its
  signature with a Core signing key received in `KeyUpdate` (section 11)
  before using it, and keeps the previous relay map when verification fails.

## 10. Lifecycle

`Lifecycle{state, reason, retry_after_ms, not_before}`:

| State | Node behaviour |
|---|---|
| `ACTIVE` | Normal (sent after a resume) |
| `SUSPENDED` | Remove peers and routes, keep keys; Core closes the session; reconnect every 30 s and expect a map when resumed |
| `EXPIRED` | Remove peers and routes; re-register with `auth.resume` or interactively |
| `REVOKED` | Remove peers and routes, erase node and disco keys for this profile; enrollment from scratch is required |
| `LOGGED_OUT` | As `REVOKED`, initiated by the node |
| `REAUTH_REQUIRED` | Keep running until `not_before`, then behave as `EXPIRED`; show the user a prompt |
| `RECONNECT` | Reconnect after `retry_after_ms` (session lifetime, Core drain) |

Lifecycle changes caused by admins (suspend, revoke, transfer) reach the node
within seconds while it is connected, and on its next connect otherwise.

## 11. Core keys and their rotation

`KeyUpdate{control_keys, signing_keys, nonce}` carries:

- `control_keys`: the control keys the node MUST pin from now on (at most two),
  each with `not_after`;
- `signing_keys`: the Ed25519 keys that sign relay tickets and the relay map
  (at most four), each with its key ID and `not_after`.

Core sends a `KeyUpdate` on every established session before the first map
message, and again whenever either set changes. It arrives over a session
authenticated with a currently pinned control key, so no extra signature is
needed. The node replaces both sets atomically and durably, then answers
`Pong{nonce}` (`nonce` ≤ 32 bytes). Core keeps accepting an old control key
until every Device has acknowledged a set without it or the key's `not_after`
passes.

## 12. Versioning

Unknown enum values are handled as follows: an unknown `Lifecycle.state`
behaves as `RECONNECT`; an endpoint with an unknown kind is ignored; an
unknown health component or technique is ignored; any other unknown enum
value makes the message `INVALID`.


- `protocol_version` 1 is this document. A future incompatible version gets a
  new number and a new upgrade token (`mtcp/2`); Core MAY serve several.
- Within v1, features are negotiated by capability name only; there is no
  global capability number.
- Core answers `426 Upgrade Required` (before Noise) or
  `ServerHello.reject = CLIENT_TOO_OLD` when a client version is below the
  deployment's minimum; the node shows the user how to update.

## 13. Capabilities

Names are lowercase, dot-separated, with a version suffix. Registered names:

| Name | Meaning |
|---|---|
| `map.zstd` | Node accepts ZSTD-flagged map messages |
| `disco.v2` | Node speaks disco v2 |
| `relay.mtrp1` | Node speaks MTRP v1 (UDP, TLS, WebSocket) |
| `device-alias.v1` | Node implements device alias grants (7.4) |
| `dns.split` | Node applies split DNS routes |
| `stats.path1` | Node sends `PathStatsReport` |
| `nat.report1` | Node sends NAT classification in `EndpointReport` |
| `map.large1` | Node applies maps of up to 10,000 peers |
| `relay.zones2` | Node hands relays MTT2 tickets and their ZONES (MTRP §5.4, §6.1). Core offers it only once every relay accepts them |

Unknown names are ignored. Core sends a feature only when both sides list it.

## 14. Limits and admission

| Item | Limit |
|---|---|
| Handshake record | 2048 bytes |
| Transport record | 65535 bytes |
| Concurrent sessions per Core replica | configurable (default 4096) |
| New handshakes per source (IPv4 address or IPv6 /64) | 10/s burst 50 by default, configurable; before any Noise work |
| Unauthenticated connections per source (IPv4 address or IPv6 /64) | handshakes in progress plus established sessions that have not yet received a map snapshot; by default the handshake burst plus 10 seconds at the handshake rate (150), configurable |
| Node key changes per Device | 4 per hour (6.3); over it `Error{NOT_PERMITTED, retry_after_ms}` |
| Endpoint changes a Device's peers see | 1 per 5 s by default, configurable (8.1); the latest is always delivered |
| New Devices a person adds to one Network by browser sign-in | 20 per 24 hours, revoked ones included; over it `Rejected{NOT_PERMITTED}`. Resuming a Device is not adding one. |
| `RegisterRequest` and `RotateNodeKey` per session | 4 at once, then 1 per second; over it `Error{OVERLOADED, retry_after_ms}` |
| Lifetime of a session that receives no map snapshot | 15 minutes by default, configurable; longer than a browser approval (6.2), then the session closes |
| Buffered outbound bytes per session | 16 MiB plus one snapshot in flight; beyond it the session closes |
| Unacknowledged map messages | 8 (7.2) |
| Reports | per type, section 8 |

Core performs the X25519 operations of a handshake only after the source IP
passed the rate limit, so a flood costs at most the configured handshake rate
of CPU. A session counts as unauthenticated until Core sends it a map
snapshot, which proves it serves an authorized Device. A source therefore
cannot hold more than that many sessions that serve no Device, however long
it keeps them alive with Pings, and none of them lives past the unproven
lifetime. Sessions that received a map do not count, so the limit does not
grow with the number of Devices behind one address. It does count Devices
that are still waiting for their first map: the default leaves room for a
full burst and 10 seconds of handshakes (the default map request timeout), so
a reconnect storm from one NAT is paced by the handshake rate rather than
refused while Core is slow. The upgrade request itself is rejected (400/503) without any
cryptographic work when headers are malformed or the replica is shedding load.

## 15. Errors

`Error{code, message, retry_after_ms, fatal}`. `fatal` errors are followed by
closing the connection. `message` is for logs and support, never contains
secrets or other tenants' data, and is at most 512 bytes.

| Code | Meaning |
|---|---|
| `INVALID` | Malformed message, wrong direction or limit exceeded |
| `UNSUPPORTED` | Unknown message type or capability misuse |
| `NOT_AUTHORIZED` | Message requires an authorized Device |
| `NOT_PERMITTED` | Policy forbids the action |
| `SESSION_REPLACED` | A newer session for this machine key exists |
| `OVERLOADED` | Retry after `retry_after_ms` |
| `INTERNAL` | Retry after `retry_after_ms` |

## 16. Security considerations

| # | Threat | Mitigation |
|---|---|---|
| C1 | TLS interception (corporate proxy, CDN, mis-issued certificate) reads or alters control traffic | Noise IK inside TLS with a pinned control key; TLS is not trusted |
| C2 | Attacker replays a captured INIT | Strictly increasing `timestamp_ms` per machine key, ±10 min window; the replayed session cannot complete without the machine private key anyway |
| C3 | Stolen machine key | Bound to one Device; admins revoke the Device; key never leaves the node's protected store |
| C4 | Handshake flood exhausts Core CPU | Per-IP rate and connection limits before X25519; load shedding with 503 |
| C5 | Compression or reassembly bomb | Limits enforced during reassembly and decompression; declared decompressed size required; 8 MiB window |
| C6 | Slow node exhausts Core memory | Ack window, coalescing, snapshot fallback, 16 MiB outbound cap |
| C7 | Cross-tenant disclosure through the map | The map contains only peers the node may reach or be reached by; error messages carry no foreign data |
| C8 | Malicious node floods reports | Per-type rate limits, latest-wins coalescing, size caps |
| C9 | Downgrade to an older protocol | No in-band version fallback; no older protocol is served |
| C10 | Enrollment key theft from logs | Enrollment keys are never logged or echoed; evaluated in constant time |
| C11 | Map tampering by a compromised relay | Maps never travel through relays; relay map is signed separately |
| C12 | Captured INIT replayed to displace a live node | Sessions count only after the first TRANSPORT record; durable per-Device timestamps shared by replicas |
| C13 | Approval URL leaked or phished | Pending approvals bound to machine key and node key; separate resume handle; fingerprint on the approval page |
| C14 | Registering someone else's public node or disco key | Uniqueness against current and retired keys; proof of possession bound to the handshake hash |
| C15 | Stolen machine key renews an expired Device | `auth.resume` only before expiry unless policy enables auto-renewal |
| C16 | Shared peers reveal another Workspace's data | Foreign peers carry no owner or provider names; foreign Network revisions never listed |
| C17 | One source holds every session slot of a replica with sessions that never register, kept alive by Pings | Such sessions count as unauthenticated for their source until they receive a map, bounded per source, and close after the unproven lifetime (section 14) |
| C18 | One Device churns its whole Network by rotating its node key in a loop, each change advancing the revision and resetting its peers' WireGuard sessions | At most 4 key changes per Device per hour, checked under the Device lock; registration and rotation requests are also rate limited per session (sections 6.3, 14). A refused request still briefly takes the Network's revision lock; the per-source handshake rate bounds how often |
| C19 | One Device floods its Network with endpoint changes, each costing one map delta per peer | At most one announced change per Device per announce interval, gated atomically in Redis across sessions and replicas; the latest change is still delivered (section 8.1) |

## 17. Test vectors

`shared/mtcp/testdata/vectors.json` holds a complete handshake with fixed
machine, control and ephemeral keys (INIT, RESPONSE, handshake hash), three
transport records in both directions, node and disco key proofs bound to that
handshake, the control key ID and the control key fingerprint.
`shared/mtcp/testdata/crosscheck.py` recomputes all of them with an
independent Noise IK implementation (Python, `cryptography` package):
`make mtcp-crosscheck`. Fragmentation, ZSTD limits and the protobuf encoding
of messages are pinned by the Go tests of `shared/mtcp`.
