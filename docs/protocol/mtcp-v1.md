# MTCP v1: MeshTransit Control Protocol

Draft 1, 2026-10-09. Schema: [`api/mtcp/v1/mtcp.proto`](../../api/mtcp/v1/mtcp.proto).
Implementation: `shared/mtcp` (records, handshake, session, messages,
proofs), generated types in `api/mtcp/v1` (`make proto`); Core `control` role
and meshd.

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

- A node takes keys from it **only at enrollment**, when it has no pinned key
  for this control host, and pins every listed key. The response is at most 4 KiB.
- After enrollment the node never takes a key from this endpoint again for
  that profile. It may read the document to check that a pinned key, or a
  next key announced inside a session, is listed; a key the node does not
  already hold is never taken from it. Key changes arrive
  inside an authenticated session (section 11). A node that loses every
  pinned key must be re-enrolled by the user.
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
| 0x35 | `RouteHealthReport` | N→C | 160 KiB |
| 0x36 | `RouteSelectionReport` | N→C | 128 KiB |
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
  contribute shared peers are never listed. Core records which revisions were
  delivered, so the Console can show how far a policy has been distributed
  and relate a node's view to a historic revision. Nodes treat them as opaque
  diagnostics.
- A delta is atomic: the node applies all of it or none.

### 7.2 Flow control

The node sends `MapAck{epoch, seq}` for the latest applied message: at once
for a snapshot, and for deltas once 4 of them are unacknowledged or 1 s after
the first of them, whichever comes first. Core's window below never stalls,
and a node sends fewer acks than map messages. Core does not count acks
against a session's message budget (section 14), so a node that acknowledges
every message still works. Core keeps at most 8
unacknowledged map messages per session. When that window is full, Core stops
sending; changes that commit meanwhile are coalesced into the next delta, or
into a full reread of the node's view. If the window stays full for 60 s, Core
ends the stream; the node reconnects and receives a fresh snapshot (new
epoch). A slow node therefore costs bounded memory and gets a correct (if
later) map.

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
| `routes` | Subnet routes the node may use (7.6); only with `routes.subnet.v1` |
| `served` | Subnets the node forwards to as a router (7.6); only with `router.subnet.v1` |

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
| `routes` | Replaces all routes when present; present and empty removes them |
| `served` | Replaces all served routes when present; present and empty removes them |

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
| `allowed_prefixes` | Exactly the peer's own `addresses`, as /32 and /128 host prefixes; a node refuses a map with anything else. Subnet routes never appear here: the node derives them from `routes` (7.6) |
| `endpoints` | Candidate UDP endpoints with their kind (disco v2 endpoint kinds) |
| `nat` | The peer's last NAT classification (nat-classification §1) |
| `home_relay` | Relay region ID the peer is reachable through |
| `online`, `last_seen` | Presence, as known to Core; `online` is absent when Core has no connectivity for the Device (unknown, not offline: nodes still probe it) |
| `key_expiry` | When the Device stops being valid without renewal |
| `owner` | Opaque owner reference for display (no personal data beyond a display name) |
| `capabilities` | Feature names the peer supports (section 13) |
| `alias` | Device alias grant, when the peer is reached through a share (7.4) |

**Names.** Core names Devices under the deployment's DNS suffix (Core
configuration, `mesh.internal` by default). Self and every peer of the node's
own Network are named `<label>.<workspace code>.<network code>.<suffix>.`,
where the label is the Device's DNS label (one DNS label, unique among the
live Devices of the Network) and the codes are the twelve-digit display codes
of its Workspace and Network; `<workspace code>.<network code>.<suffix>` is
the Network's **zone**. A peer from another Network (reached through a share
or Trust Contract) carries only what the node needs: keys, alias addresses,
endpoints and presence, and as `name` the name the node imports it under
(its share name, `<label>.<provider workspace code>.<provider network code>.shared.<suffix>.`)
or, when the node only exports to it, a placeholder under `invalid.` that
does not resolve. Its hostname, its own name, `display_name` and `owner` are
omitted. Every name is at most 253 bytes with its trailing dot; Core bounds
the suffix accordingly.

**Packet filter** (`PacketFilter`): a list of inbound allow rules, default
deny. Each rule has `sources` (prefixes, at most 1024), `destinations`
(prefix plus port ranges) and `protocols` (IANA numbers; empty means TCP, UDP
and ICMP). At most 10,000 rules. Rules are node-reduced: they mention only
traffic this node can receive. For a router that includes traffic to the
subnets it serves (7.6): their rules name those prefixes as destinations.

**DNS** (`DnsConfig`): `records` (name, A/AAAA, value) for Device names and
imported shares, `resolvers` (IP and optional DoH/DoT URL), `search_domains`,
`routes` (name suffix → resolvers, for split DNS; a route without resolvers is
answered by the node itself). At most 50,000 records. Core sends an A or AAAA
record for each address of self and of each same-Network peer under its name,
and one for each address of each imported share under its share name; one
route for the suffix with no resolvers, so the node answers every name under
it and an unknown one is `NXDOMAIN`; and the Network's zone as the only
search domain. A node ignores a route without resolvers for the root or a
single-label suffix. Core sends no pointer records: the node answers PTR queries
for the addresses of the records under its own zone (the zone its own name is
in). Within a stream, Core sends `dns` in a delta only when it changed.

### 7.4 Device alias grants

The `alias` field (`AliasGrant`) carries the [device alias v1](device-alias-v1.md)
grant: `contract_id`, `endpoint_id`, `generation`, `grant_revision`,
`recovery_epoch`, `role` (consumer or provider), `expires_ms`, `services`
(protocol and port range) and `masquerade_v4` / `masquerade_v6`, the
receiving node's own aliases toward this peer. Device alias v1 defines the
grant's rules: exact intersection, deadlines, atomic replacement, no reverse
rule. A node that does not advertise `device-alias.v1` never receives alias
peers.

### 7.5 Withdrawal

Core never signals revocation with an empty map. It sends `Lifecycle`
(section 10); the node then removes peers, filter, DNS and routes itself
(7.6).

### 7.6 Subnet routes

A **Site** is one address space behind the mesh, such as an office LAN or a
VPC, inside one Network. Routers are Devices that forward traffic from the
mesh into a Site. Core decides which routers serve a Site and which nodes may
use it. Core sends `routes` only to nodes that list `routes.subnet.v1` and
`served` only to nodes that list `router.subnet.v1`; a node that receives a
field it did not list ignores it.

**Order.** Sites are sorted by `site_ref` bytewise. Prefixes are sorted IPv4
before IPv6, then by address bytes, then by prefix length.

**Clearing.** `routes` and `served` are message fields: in a delta, a present
field replaces the whole value and a present, empty one removes everything;
an absent one leaves the value unchanged. Core MUST send a present, empty
message to clear. A snapshot without the field means none.

#### Consumer routes

`routes` (`RouteConfig`) is a list of `SiteRoute`:

| Field | Meaning |
|---|---|
| `site_ref` | Opaque, stable reference of the Site: 1–64 bytes of UTF-8 |
| `prefixes` | The part of the Site this node's rules grant: the intersection of the destinations of its active rules with the Site's prefixes, canonical and sorted. At least 1, at most 1,024 |
| `candidates` | The Site's routers as `device_id`s, in priority order. The order changes only when routers are assigned or reprioritized, never with their health. At most 32 |
| `primary` | The router Core chose, one of `candidates`; empty when none |
| `generation` | Per Site; increases each time `primary` changes and never goes back, also across Core replicas and restarts |
| `status` | `SERVED`: forward through `primary`. `UNSERVED`: no router can serve now. `CONFLICT`: the Site overlaps another Site granted to this node. `CAPACITY`: the routers' maps cannot hold this node |
| `name` | The Site's display name, for status only: 1–64 characters without control characters; empty from an older Core. A node ignores a name it would not show (longer, with control characters, not UTF-8) rather than the map |

Core:

- sends `routes`, and `served`, only to nodes that also list `map.large1`:
  a router's consumers are cut at the large map's peer limit;
- sends a Site to a node only while an active policy rule lets the node
  reach part of it, and never a Site the node serves as a router;
- includes every candidate that is a live Device of the Network as a peer
  of the map (peer limits never remove one); a router keeps room for those,
  so it admits at most its peer limit less 256 (or less half the limit, if
  smaller) consumers, and a consumer beyond them gets `CAPACITY`; at most 256
  distinct routers (or half the peer limit, if smaller) appear across all
  Sites of one map;
- sends two Sites whose prefixes overlap only with both marked `CONFLICT`.

**Local bounds.** Using routes is a local choice: a node installs none until
its user enables them, and its local configuration may narrow them further.
Whatever Core sends, a node never installs a route prefix that:

- is shorter than IPv4 /8 or IPv6 /32 (this excludes a default route split
  into halves);
- overlaps the IPv4 overlay frame (`100.64.0.0/10`, `198.18.0.0/15`),
  `fd00::/48` (which holds the self-test address), the /48 of any mesh
  address or overlay route the node holds, loopback, link-local, multicast
  or unspecified addresses. The rest of `fd00::/8` is unique local space a
  Site may use;
- is a public range, unless the user also enabled public routes. Only
  `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and `fc00::/7` are private;
  every other range, reserved ones included, counts as public;
- overlaps a network the node is directly attached to, or a more specific
  route the node already has.

**Own traffic.** A node's own sockets (control, relays, STUN, port mapping,
disco and WireGuard, DNS upstreams) never use route prefixes: the node binds
them to its physical network with its platform's mechanism, and a node that
cannot do so on its platform does not install routes at all. The system
resolvers the node learned from its physical network are excluded from route
prefixes as single-address routes over that network.

These bounds limit what a compromised Core can redirect; they cannot stop it
from naming any peer as `primary` for a prefix the node accepts. The router's
packet filter, not the consumer, enforces who reaches the Site. A prefix the
node refuses, and a Site that leaves `routes`, follows the node's other
routes: traffic to a revoked Site may then reach a local network that uses
the same addresses. This is accepted: the node treats the prefix as if it
had never been granted.

**Forwarding.** For each prefix it installs, a node:

- routes the prefix toward the mesh, whatever the status, and removes the
  route only when the Site leaves `routes`. Traffic to an installed prefix
  never falls back to the node's other routes. A prefix the node refused is
  not installed and follows the node's other routes, as if never granted;
- sends the Site's traffic to `primary` only while the status is `SERVED`
  and `primary` is a peer of the map (otherwise the Site is handled as
  `UNSERVED`). For any other status it answers with ICMP destination
  unreachable, at most 10 per second per Site in all, and drops the rest;
- routes a prefix to exactly one peer at a time. A route prefix never
  widens what a peer may send: `allowed_prefixes` stays its own addresses.

#### Served routes

`served` (`ServedRoutes`) is a list of `ServedSite`: `site_ref` (as above),
`prefixes` (canonical, sorted, at least 1, at most 1,024), `masquerade`
(translate mesh sources to the router's own address on the way into the
Site) and `probes` (at most 4 addresses inside the Site's prefixes that the
router checks: `ICMP` with port 0, or `TCP` with a port of 1–65535).
A router sends its probes from the first address of the overlay frame,
`100.64.0.0` or `fd00::`, through its own forward path; Core never assigns
either address to a Device (it leases from a prefix's first host), and
peers never carry it.

A router forwards into the intersection of `served` and the prefixes its own
local configuration offers (8.2): for each served prefix inside an offered
prefix, the served prefix; for each offered prefix inside a served prefix,
the offered one. Core cannot make a node a router. It
forwards only traffic its packet filter admits, only into those prefixes,
and lets traffic from the Site into the mesh only as replies to flows its
packet filter admitted. Its route digest (8.4) covers that intersection.

#### Validity and withdrawal

A node refuses a map as malformed when `routes` or `served`:

- lists a `site_ref` twice, out of order, empty, longer than 64 bytes or not
  UTF-8;
- carries a prefix that is not canonical (host bits set, an IPv4-mapped
  IPv6 address, an address of other than 4 or 16 bytes, more bits than the
  family has), a default route, a prefix listed twice or out of order, or
  more prefixes than the limits of section 14;
- in `routes`: has duplicate `candidates`, more than 32, the node itself as
  a candidate, a `primary` outside `candidates`, `SERVED` with an empty
  `primary`, or an unknown status;
- in `served`: has prefixes that overlap within or across Sites, a probe
  outside its Site's prefixes, of unknown kind, with a wrong port, or more
  than 4 probes.

Overlap between Sites in `routes` is not malformed: the node handles those
Sites as `CONFLICT`.

When it receives `Lifecycle` (section 10), a node removes its routes and a
router stops forwarding into every Site. When its session only ends (the
network or Core is unreachable), a node keeps its last `routes` and `served`
as it keeps the rest of its map, until a new map or `Lifecycle` arrives; the
key deadlines it checks on every packet still apply. A Core restart or
rolling update therefore never interrupts a Site.

### 7.7 Exit Pools

An **Exit Pool** is a group of exit nodes: Devices that forward other
Devices' Internet traffic. It is its own entity of the Network, not a kind of
Site. Core decides which exit node is a pool's primary and which nodes may
use the pool. Core sends `exits` only to nodes that list `routes.exit.v1`
and `served_exits` only to nodes that list `router.exit.v1`; a node that
receives a field it did not list ignores it. Both follow the ordering and
clearing rules of 7.6, with `pool_ref` in place of `site_ref`.

**The Internet.** An exit node forwards only to the Internet: IPv4 outside
`0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`,
`168.63.129.16/32`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`,
`192.0.2.0/24`, `192.31.196.0/24`, `192.52.193.0/24`, `192.88.99.0/24`,
`192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`,
`224.0.0.0/4` and `240.0.0.0/4`, and IPv6 inside `2000::/3` outside
`2001::/32`, `2001:2::/48`, `2001:10::/28`, `2001:20::/28`, `2001:db8::/32`,
`2002::/16` and `3fff::/20`. It also leaves out its own addresses, the
subnets it is attached to, its gateway and its public addresses as seen from
outside. Rules never name Internet addresses: Core sends them with the
destinations `0.0.0.0/0` and `::/0`, and the exit node subtracts this set.

#### Consumer pools

`exits` (`ExitConfig`) is a list of at most 64 `ExitPool`:

| Field | Meaning |
|---|---|
| `pool_ref` | Opaque, stable reference of the pool: 1–64 bytes of UTF-8 |
| `name` | The pool's display name: 1–64 characters without control characters |
| `candidates` | The pool's exit nodes in priority order, 1 to 16, each with the `state` and `families` of its last health report and the overlay addresses of its DNS forwarder |
| `primary` | The exit node Core chose, one of `candidates`; empty when none |
| `generation` | Per pool; increases each time `primary` changes and never goes back |
| `status` | `SERVED`: send through `primary`. `UNSERVED`: no exit node can serve now. `CAPACITY`: the exit nodes' maps cannot hold this node |
| `managed` | The administrator asks this node to use the pool. A node follows it only if its own configuration allows managed exits |

Core sends a pool to a node only while an active rule lets the node reach the
Internet through it, never the pool the node is an exit node of, and includes
every candidate that is a live Device of the Network as a peer, as for
routers (7.6).

**Local choice.** Using an exit is the node's user's choice, among the pools
Core sends; Core cannot make a node use one unless the node allows managed
exits. A node keeps using the candidate it chose while that candidate
answers and its `state` is not `FAILED`, even when Core chooses another
`primary`: changing exit node changes the node's public address.

#### Served pool

`served_exits` (`ServedExits`) holds at most one `ServedExit`: the pool this
node is an exit node of, with its `probes` (at most 8 Internet addresses and
TCP ports the exit node connects to through its own forwarding path),
`conntrack_per_consumer`, `smtp_allowed`, `dns_upstreams` (at most 4
Internet addresses, tried in order) and `rules`: the pool's rules as filter
rules whose destinations are `0.0.0.0/0` and `::/0`. An exit node forwards
only when its own configuration offers to be one (`exit_offered`, 8.2) and
only what those rules admit to the Internet; its local limits may lower
`conntrack_per_consumer` and refuse SMTP whatever Core sends.

#### Validity

A node refuses a map as malformed when `exits` or `served_exits`: lists a
`pool_ref` twice, out of order, empty, longer than 64 bytes or not UTF-8;
has more pools than allowed; in `exits`, has no candidate, more than 16,
duplicate candidates, the node itself as a candidate, a `primary` outside
`candidates`, `SERVED` with an empty `primary` or an unknown status or state;
in `served_exits`, has more than one pool, a probe or upstream that is not an
Internet address, a probe port of 0, or a rule whose destination is not
`0.0.0.0/0` or `::/0`.

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
  silently drops well-formed endpoints peers must not probe:
  - unspecified, loopback, link-local, multicast and broadcast addresses;
  - `100.64.0.0/10`, which holds every Network's IPv4 overlay, so a probe
    there would loop through the tunnel; `0.0.0.0/8`, `240.0.0.0/4` and
    `100::/64`;
  - IPv6 forms that embed an IPv4 address and would escape the IPv4 rules:
    IPv4-compatible `::/96`, SIIT `::ffff:0:0:0/96`, 6to4 `2002::/16` and
    Teredo `2001::/32`. A NAT64 address (`64:ff9b::/96`) is kept only when
    the IPv4 address it embeds is global, and every rule below applies to
    that IPv4 address too. Operator-specific NAT64 prefixes are not
    recognised;
  - the Device's own overlay addresses;
  - the addresses of the relays in the relay directory, and the ranges the
    operator denies (`MESHTRANSIT_CONTROL_MTCP_DENIED_ENDPOINT_CIDRS`, for
    Core and its load balancers), so a Device cannot point its peers'
    probes at the infrastructure. A relay listed only by hostname has no
    address to drop; list its addresses in the denied ranges.

  Private ranges, ULA (`fc00::/7`) and the documentation ranges are kept:
  they are LAN paths, or reach no Internet host. Core applies these rules
  when a report arrives and again when it sends a map, so an endpoint
  stored before a relay or a denied range was added, or by an older Core,
  is not sent either. Core distributes only the latest report to peers, in
  a map delta; it currently sends the whole peer entry in `peers_upsert`.
- A node applies the same address rules to its map, dropping an endpoint
  instead of refusing the map, and refuses the overlay address of any node
  in its map and the relays' addresses, also as candidates learned from
  CALL_ME_MAYBE or from a ping's source (disco-v2 §4.1). It does not know
  the operator's denied ranges, so a peer can still name one in a
  CALL_ME_MAYBE; the probe budget (disco-v2 §4.4) bounds what that costs.

### 8.2 Hostinfo

`HostinfoReport`: hostname, OS and version, client version, architecture,
optionally the device model, and the subnets the node's local configuration
offers to forward (`advertised_prefixes`, at most 256 canonical prefixes; a
report with more is refused as invalid).
Offering grants nothing: a Device serves a Site only after an administrator
makes it the Site's router, and only within prefixes it offers (7.6). Core
ignores an entry that is malformed, not canonical, or one no Site could use
(a default route, shorter than IPv4 /8 or IPv6 /32, IPv4-mapped, inside the
overlay frame or a loopback, link-local, multicast or reserved range), and
counts it in a metric; earlier clients that offered `0.0.0.0/0` or `::/0`
for an exit node offer nothing that way any more. Sent after registration
and on change, always with the whole set: Core keeps the latest offer of
each Device, and a report that offers what is already stored writes nothing.
Core uses the hostname only to propose a Device name; it never trusts it for
identity.

`exit_offered`, from a node that lists `router.exit.v1`, says the node's own
configuration offers to be an exit node (7.7). Like prefixes, it grants
nothing: an administrator must make the Device an exit node of a pool, and it
serves only while it offers. Core keeps the latest value of each Device and
ignores it from a node without `router.exit.v1`.

### 8.3 Health and path statistics

- `HealthReport`: component states (data plane, DNS, relay sessions, clock
  skew) as enums plus short codes; no free-form logs. On change, at most once
  per 10 s.
- `RouteHealthReport`: only on a session that negotiated `router.health1`, the
  health of every Site it serves (7.6), as it measures it itself: `site_ref`,
  a state (`OK`, `DEGRADED` as a warning only, `FAILED`) and a code of at most
  64 bytes, such as `forwarding_off`, `nft_rules_missing`, `no_route`,
  `prefix_not_advertised`, `forward_blocked`, `probe_failed` or
  `conntrack_high`. At most 1,024 Sites, sorted by `site_ref`, each once. The
  whole set is sent on change and every 10 s while the node serves any Site,
  and once empty when it serves none. A router whose service stops (not a
  restart its package expects) sends a last set with every Site it served
  `FAILED` as `going_away` before it closes the session, so Core elects
  another router at once. Core keeps the latest set for the
  Device's current session, only for Sites of the `served` it sent, and
  treats a set without a report for 30 s as unknown, not failed. A malformed
  report, or one on a session without `router.health1`, is `INVALID`.
  With `router.exit.v1`, `exit` is the health of the pool the node is an exit
  node of (7.7), measured the same way, with the address `families` it
  reaches the Internet in, and codes such as `exit_not_offered`,
  `egress_failed`, `egress_v6_failed`, `forward_blocked`, `dns_failed` or
  `conntrack_high`; unset when the node serves no pool. Core keeps it only
  for the pool of the `served_exits` it sent. An `exit` on a session without
  `router.exit.v1` is `INVALID`.
- `RouteSelectionReport`: only on a session that negotiated
  `routes.selection1`, the router the node sends each Site's traffic to, for
  the Sites of its `routes`: `site_ref`, `router` (one of the Site's
  `candidates`) and why, `PRIMARY` (the map's primary) or `LOCAL_FAILOVER`
  (another candidate the node chose while the primary does not answer, 7.6),
  or `NONE` with an empty `router` for a Site not served. At most 1,024 Sites,
  sorted by `site_ref`, each once. The whole set is sent on change and every
  60 s while the node reaches any Site, and once empty when it reaches none.
  Core keeps the latest set for the Device's current session, only for Sites
  of the `routes` it sent with a `router` among their `candidates`, and
  treats a Site without a report for 3 minutes as unknown. A malformed
  report, or one on a session without `routes.selection1`, is `INVALID`.
  With `routes.exit.v1`, `exit` is the exit node the node sends its Internet
  traffic to (7.7): `pool_ref`, `exit_node` (one of the pool's `candidates`)
  and why, `PRIMARY`, `LOCAL_FAILOVER`, `STICKY` (the candidate it kept after
  Core chose another primary) or `NONE` with an empty `exit_node`; unset when
  it uses no exit. Core keeps it only for a pool of the `exits` it sent. An
  `exit` on a session without `routes.exit.v1` is `INVALID`.
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
when it installed them. With `router.subnet.v1` it also carries
`route_digest` and `route_entries`: the [route digest](route-digest-v1.md) of
the served routes the node forwards into, and how many entries it covers.
`route_digest` is always 32 bytes, also for an empty set; Core treats any
other length as a malformed report.
Routes a node uses as a consumer are not reported: using them is a local
choice, and the router enforces access.
Sent after each change of the installed rules or routes, once
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

Core sends `REVOKED` only when it knows the session's exact machine and node
keys were the current keys of a Device that was revoked with them. Any other
key without authority (unknown, rotated away) gets `EXPIRED`, and a lookup
that fails gets `RECONNECT`, so a node never erases keys on an ambiguous cause.
A node erases only the keys the revoked session used: keys that a login,
rotation or logout has replaced since are kept. After
`REVOKED` Core does not accept a registration on the same session: those keys
never become a Device again.

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
| `map.large1` | Node applies maps of up to 10,000 peers; without it Core sends at most 256 |
| `routes.subnet.v1` | Node applies `routes` (7.6) |
| `router.subnet.v1` | Node can forward into Sites: it applies `served` (7.6) and reports `route_digest` (8.4) |
| `router.health1` | Node sends `RouteHealthReport` (8.3); only with `router.subnet.v1` (Sites) or `router.exit.v1` (its Exit Pool) |
| `routes.selection1` | Node sends `RouteSelectionReport` (8.3); only with `routes.subnet.v1` (Sites) or `routes.exit.v1` (its exit) |
| `routes.exit.v1` | Node applies `exits` (7.7); with `routes.selection1` it reports its exit in `RouteSelectionReport` |
| `router.exit.v1` | Node can be an exit node: it applies `served_exits` (7.7) and reports `exit_offered` (8.2); with `router.health1` it reports its exit health in `RouteHealthReport` |
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
| Browser approvals issued or resumed per session (6.2) | 2 at once, then 1 per 10 s; over it `Error{OVERLOADED, retry_after_ms}`. A malformed resume handle is refused before it counts |
| `MapResync` per session (7.1) | 2 at once, then 1 per 5 s; over it fatal `Error{OVERLOADED, retry_after_ms}`, and the node gets a fresh snapshot when it reconnects |
| `EnforcementReport` per session (8.4) | 4 at once, then 1 per second; over it the latest report is kept, replacing any kept before, and stored when the budget allows |
| `RouteHealthReport` per session (8.3) | 2 at once, then 1 per 2 s; over it the latest report is kept, replacing any kept before, and stored when the budget allows |
| `RouteSelectionReport` per session (8.3) | 2 at once, then 1 per 5 s; over it the latest report is kept, replacing any kept before, and stored when the budget allows |
| Offers of `HostinfoReport` stored per session (8.2) | 4 at once, then 1 per 10 s; over it the latest offer is kept, replacing any kept before, and stored when the budget allows. An offer sent before the session serves a Device is stored once it does |
| A Device's live presence lease moving to another Core replica | 10 per minute; past it the stream ends with `Lifecycle{RECONNECT, retry_after_ms}` until the minute is over. Two processes sharing one machine key are bounded to that rate, not stopped; a reconnect after a replica ended, a rolling update or a rebalance moves it once. A refused attempt still costs Core the snapshot and relay ticket it prepared, but not their delivery |
| Everything a node sends, per session | 200 messages at once, then 50 per second, and 1 MiB of records at once, then 256 KiB per second; over either, fatal `Error{OVERLOADED, retry_after_ms}`. `MapAck` counts only as bytes: it answers map messages Core chose to send, and nodes that ack every message (7.2) must not reach the limit |
| Lifetime of a session that receives no map snapshot | 15 minutes by default, configurable; longer than a browser approval (6.2), then the session closes |
| Outbound messages per session | No send queue: one message is written at a time. Each record must be written within 10 s, and each whole message within 30 s plus its size at 64 KiB/s, at most 10 minutes; otherwise Core closes the session and the node reconnects |
| Unacknowledged map messages | 8 (7.2) |
| Subnet routes in one map (7.6) | 1,024 Sites in `routes` and in `served`; 1,024 prefixes per Site; 4,096 prefixes in all `routes`, and 4,096 in all `served`; 32 candidates per Site and 256 distinct routers in all; 4 probes per served Site |
| `advertised_prefixes` in `HostinfoReport` (8.2) | 256 |
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
| C6 | Slow node exhausts Core memory | Ack window, coalescing, snapshot fallback, no send queue, per-record and per-message send deadlines |
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
| C20 | A Device announces endpoints that point its peers' probes at a victim: the overlay, a relay, Core | Core drops overlay, special-purpose, relay and operator-denied addresses, also through NAT64, when a report arrives and when it sends a map; nodes refuse overlay and relay addresses as candidates; each node's pings to a peer's unanswered candidates are bounded by a backoff and a per-Device budget: at most 144 at once and 0.4/s in the long run, so a victim named by M Devices receives at most 0.4 × M pings/s from each node that has them in its map (section 8.1, disco-v2 §4.4) |
| C21 | One session makes Core work in a loop with cheap messages: map resyncs that each encode the whole map, enforcement reports that each write Redis, browser approvals that each write the database, or a flood of any message | Per-session budgets for each, and one for all messages and bytes (section 14); a node that follows the protocol stays well inside them, and reconnecting is bounded by the per-source handshake rate |

## 17. Test vectors

`shared/mtcp/testdata/vectors.json` holds a complete handshake with fixed
machine, control and ephemeral keys (INIT, RESPONSE, handshake hash), three
transport records in both directions, node and disco key proofs bound to that
handshake, the control key ID and the control key fingerprint.
`shared/mtcp/testdata/crosscheck.py` recomputes all of them with an
independent Noise IK implementation (Python, `cryptography` package):
`make mtcp-crosscheck`. Fragmentation, ZSTD limits and the protobuf encoding
of messages are pinned by the Go tests of `shared/mtcp`.
