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
| 0x10 | `RegisterRequest` | N→C | 41,215 B (16 KiB, plus a Kubernetes gateway's pod token of 8 KiB, issuer of 255 B and JWKS of 16 KiB) |
| 0x11 | `RegisterResponse` | C→N | 8 KiB |
| 0x12 | `RotateNodeKey` | N→C | 12 KiB (4 KiB plus a pod token of 8 KiB) |
| 0x13 | `Logout` | N→C | 1 KiB |
| 0x14 | `RotateNodeKeyResponse` | C→N | 1 KiB |
| 0x15 | `NodeKeyProof` | N→C | 256 B |
| 0x16 | `RotateMachineKey` | N→C | 8,448 B (256 B plus a pod token of 8 KiB) |
| 0x17 | `RotateMachineKeyResponse` | C→N | 256 B |
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
| 0x37 | `CaptiveWindowReport` | N→C | 4 KiB |
| 0x38 | `DnsHealthReport` | N→C | 4 KiB |
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
| `auth.cluster_join` | Join a Kubernetes cluster as a gateway replica with a join key `mtk1.<id>.<secret>` and what the pod reports about itself (6.6) |

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
repeat. Rotation does not need a new approval. This repeat does not apply to
a Kubernetes gateway, whose former node key is refused at the gate (6.7): it
proves its staged node key on a new session instead.

Every key change advances the Network revision and resets the WireGuard
sessions of the Device's peers, so a Device may change its node key at most 4
times within one hour, a Kubernetes gateway 30 (6.8, section 14). Core checks it under the Device's lock,
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
`Error{code: NOT_PERMITTED}`. A Kubernetes gateway never logs out: Core,
and its database, answer `Error{code: NOT_PERMITTED}`, so a copy of the
gateway's keys cannot remove it; an administrator does (6.7).

### 6.6 Kubernetes cluster join

A Kubernetes gateway replica (meshgw) sends `RegisterRequest` with
`auth.cluster_join`: a join key of one cluster (`mtk1.<id>.<secret>`; Core
never accepts it as `auth.enrollment_key`, nor an enrollment key here) and
`reported`, a JSON object of at most 16 strings (keys up to 64 bytes,
values up to 256, 2 KiB in all) that Core stores for display only.

The key does not authorize a Device. Core opens a request bound to the
session's machine key and node key, which holds no Device, and answers
`pending` with `admin_approval` (the cluster ID, the request ID and a
32-byte nonce Core chose) and no `approval_url`. The node prints the code

```
trust  = SHA-256("meshtransit/kube-sa-trust/v1" || 0x00 || u16 issuer || u32 jwks
                 || u16 namespace || u16 service_account || u16 pod)
digest = SHA-256("meshtransit/kube-join-code/v2" || 0x00 || machine_key(32)
                 || node_key(32) || cluster_id(16) || request_nonce(32) || trust(32))
code   = the first 50 bits of digest, RFC 4648 base32 upper case: "XXXXX-XXXXX"
```

Each length is big-endian before its bytes; `jwks` is the canonical form of
the cluster's keys (`kube-sa-trust/v1`: public members only, sorted by
`kid`, members in lexicographic order, no whitespace, no HTML escaping).
Since K1.1 the join also carries the pod's identity:
`service_account_token` (the pod's projected ServiceAccount token, audience
`meshtransit.net/kubernetes-gateway`; never logged),
`service_account_issuer` and `service_account_jwks` (as the cluster's API
server serves them). Core verifies the token against those keys and takes
the namespace, ServiceAccount and pod from it; the node takes them from its
own token's payload. A join without a valid token or keys is
`rejected{INVALID}`; a cluster whose issuer is not cluster-local (`*.svc`,
`*.cluster.local`) is `rejected{NOT_PERMITTED}` until administrators can
replace a cluster's keys. When the keys hold a request with other signing
material, Core answers `rejected{CONFLICT}` with that request's
`admin_approval`, and the node prints its own code for it, which differs.

(`shared/kubejoin`), and an administrator approves the request by typing
the code read from the replica's log. Core and its database each compute the
code from the keys they received, so a request made with other keys has
another code. Approval consumes one use of the key and gives the replica
15 minutes to complete.

The session stays open while the request waits: `expires_ms` is the earlier
of the key's expiry and 10 minutes ahead. When the request is approved Core
creates the Device and sends `authorized` on the same session; the node
never polls. After the session drops or `expires_ms` passes, the node sends
the same request again (same join key, same keys) and gets the same request
back. Once the request completed the machine key is a gateway's, so such a
session is refused by the gateway gate (6.7, "a Kubernetes gateway must
prove its node key first"): a node that lost the `authorized` answer then
proves its node key on a new session, and a `Pong` tells it the Device
exists. A request rejected or cancelled
(five wrong codes, or the key revoked) is answered `rejected{NOT_PERMITTED}`;
one approved but not completed by its deadline `rejected{EXPIRED}` on the
session that waited (a node asking again afterwards finds the key's use
spent: `rejected{CREDENTIAL_EXHAUSTED}`, or a new request if uses remain); a
completed one whose Device was revoked or deleted `rejected{NOT_PERMITTED}`.
While a request is approved, `expires_ms` is the earlier of its completion
deadline and 10 minutes ahead. A key that is unknown, of another kind or
with a wrong secret is `rejected{CREDENTIAL_INVALID}`; one revoked, expired
or used up `rejected{CREDENTIAL_EXHAUSTED}`, checked before the keys; keys a
Device or another registration holds `rejected{CONFLICT}`; a full queue
(twice the key's uses waiting) `rejected{NOT_PERMITTED}`.

The Device belongs to the Workspace, never expires, keeps the name
`<cluster>-<ordinal>` (or `<cluster>-<ordinal>-<n>` when another Device took
that name while the request was approved, its stem shortened to keep 63
bytes; the database accepts no other)
and holds exactly the keys the code bound. It cannot be transferred,
renamed, suspended or shared. A deployment that has not enabled cluster joins answers
`rejected{NOT_PERMITTED}`.

### 6.7 Node key proof and Kubernetes gateways

When Core offers `session.proof1`, a node MAY send `NodeKeyProof{proof}` as
its first TRANSPORT record, before the message that establishes the session:

```
proof = BLAKE2s-256(key = X25519(node_key, control_key),
                    "meshtransit/mtcp-node-key-session/v1" || 0x00 || h || node_key)
```

where `node_key` is the ClientHello's. A Device of kind Kubernetes gateway
MUST send it, and a gateway node sends it only when `session.proof1` was
negotiated; without it the node stops. Until a gateway's proof checks Core
neither establishes the session, replaces an older one, nor sends anything
but the refusal, and its handshake timestamp is compared but not recorded:
Core records it, durably and in its cache, only after the proof. A gateway's
handshake with a stale timestamp is still answered; Core refuses it after
the proof, which a replayed INIT can never send.

| Machine key | Node key | Gateway | Other node |
|---|---|---|---|
| bound to no Device | — | (not a gateway) | `Error{NOT_AUTHORIZED, "machine key is not bound"}`, session goes on |
| a gateway's former key | — | fatal `Error{NOT_AUTHORIZED, "machine key is retired"}` | — |
| held before, not now (revoked, expired) | — | (a gateway's: above) | `Error{NOT_AUTHORIZED, "node key is not current"}`, not fatal |
| current | not the current key | fatal `Error{NOT_AUTHORIZED, "node key is not current"}` | same, not fatal |
| current | current, wrong proof | fatal `Error{NOT_AUTHORIZED, "invalid node key proof"}` | `Error{INVALID}`, not fatal |
| current | current, proof checks, timestamp more than 5 s ahead of Core | fatal `Error{NOT_AUTHORIZED, "handshake timestamp is ahead of Core"}` | — |
| current | current, proof checks, timestamp taken since | fatal `Error{NOT_AUTHORIZED, "handshake replayed"}`; the key is contested (6.8) | — |
| current | current, proof checks | session goes on, proven | session goes on, proven |

A gateway that sends anything else first gets a fatal
`Error{NOT_AUTHORIZED, "a Kubernetes gateway must prove its node key first"}`;
a `NodeKeyProof` after the first record gets `Error{INVALID}`. A gateway
probing for its keys after a crash tries its staged machine key first.

For a gateway session Core tells its database, in each transaction, which
machine key and node key the session proved, and the database resolves a
session to a gateway only then: an older Core, which never does, cannot
serve, rotate or log out a gateway. An older Core records no timestamp for
a gateway's handshake (its own cache only), and stores a gateway's
enforcement reports, which need no map, outside the database: replicas must
all run a Core that knows gateways before any join is enabled. A gateway session refuses every
`RegisterRequest` with `rejected{NOT_PERMITTED}` and `Logout` with
`Error{NOT_PERMITTED}`. The session that completed a cluster join (6.6)
proved its keys in the `RegisterRequest` and is a gateway session from then
on.

A copy of a gateway's current machine and node keys (its Kubernetes Secret)
can still connect as the gateway and replace the real pod's session until
an administrator removes the Device; a copy of former keys gets nothing.

### 6.8 Gateway machine key rotation

A Kubernetes gateway moves to a new machine key at every start, so a copy of
its former Secret opens no session. On a session that proved its node key
(6.7) it sends `RotateMachineKey{new_machine_key, proof}`:

```
proof = BLAKE2s-256(key = X25519(new_machine_key, control_key),
                    "meshtransit/mtcp-machine-key-rotation/v1" || 0x00 || h || new_machine_key)
```

Since K1.1 both rotations of a gateway (this one and 6.3) carry
`service_account_token`, the pod's token, read again for each rotation.
Core verifies it after the request's own proofs (and, for a node key, after
finding that a repeated rotation already committed, which needs no token)
and before the presence check below, against the cluster's signing trust
(set when the cluster's first replica was approved) and the pod the
Device's join named, and records one use of it per key it replaces, in the
rotation's transaction; without one, or with a token used for that key
already, the rotation is refused with `Error{NOT_PERMITTED}`, not fatal.

Core checks the proof, moves the Device to the new key in one transaction
(the former key's epoch expires and stays in a history; no Device or gateway
ever uses a key again; its handshake timestamp is forgotten), records
`device.machine_key_rotated`, answers `RotateMachineKeyResponse{}` and ends
the session. The node reconnects with the new key and proves its node key
again; peers see the change as one map change. Core commits the rotation
even when the session ends meanwhile.

The node stores the new key as staged before it sends the request and keeps
it until a later rotation's response: after a crash it tries its newest
staged key first, then the former ones. Refusals are `Error`, not fatal:
`NOT_PERMITTED` when the key was used before or the gateway already changed
its machine key 30 times within the hour (then with `retry_after_ms`), which
also tells the node to drop the staged key; `NOT_AUTHORIZED` when the
session's keys are no longer the gateway's; `INVALID` for a bad key or
proof; `NOT_PERMITTED` on any session that is not a gateway's. A gateway
also rotates its node key (6.3) at every start, at most 30 times an hour.

A gateway session rotates its machine key or its node key only while its own
map stream holds the gateway's presence on every Core replica. Since K1.1 a
contested key no longer refuses the rotation: only the pod has the token,
so its rotation retires the keys of a copy that fought it. Every gateway session opened with a Ping streams, so a
rotation sent right after the Ping waits, at most 5 seconds, for the stream
to claim the presence. Core refuses a rotation with `Error{NOT_PERMITTED}`,
not fatal and without `retry_after_ms`, so the node drops the staged key,
keeps the session and starts at once. It refuses when:

- **No valid pod token** (K1.1), checked first.
- **No presence.** The stream has not claimed the presence, another stream
  holds it, or Core cannot tell (Redis failed).
- **Contested** (before K1.1 only; since K1.1 counted, not refused). The
  machine key is contested:
  - **Pushed out on the same replica.** A gateway session pushed out a live
    session of the same machine key on the same replica, within 10 minutes
    (handshake result `gateway_replaced`).
  - **Replayed proof.** A valid node key proof was refused only for its
    timestamp, within 10 minutes. The proof binds the handshake, so a second
    holder of the keys took a newer timestamp.
  - **Presence taken from a live holder.** A gateway stream took the presence
    from another live holder, on any replica or generation, within 10 minutes.
    This is shared through Redis.
- **Replaced while waiting.** The session is no longer its replica's session
  of the machine key.

A rotation also keeps the stream's presence while it commits, so a stream
that claims the presence meanwhile contests the key.

A gateway reconnects within 2 seconds every time, outside the backoff of
section 5, when any of the following happens:

- it is pushed out with `SESSION_REPLACED`;
- its stream loses the presence to another holder, which Core also answers
  with a fatal `SESSION_REPLACED`;
- it is refused with "handshake replayed".

So a copy of its Secret that takes the real pod's place is taken back before
the window ends, and while they contend neither rotates. The third take of a
live holder's presence within five minutes is audited as a session fight.

The checks have these limits:

- **Clock.** A gateway's timestamp may not run more than 5 seconds ahead of
  Core, so a copy cannot shut the real pod out as replays. A pod whose clock
  steps back is counted as a second holder until it catches up.
- **Absent pod.** The checks cannot tell a copy from the pod while the pod
  has no stream at all.
- **Source budget.** A holder of the keys that shares the pod's source
  address can use up that source's handshake budget (section 14) for longer
  than the window, and then rotate.
- **Restart soon after a take.** A pod restarting within 10 minutes after a
  take of its presence skips that start's rotation.

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
| `owner` | Opaque owner reference for display (no personal data beyond a display name); in a Kubernetes gateway's map, set with `kubernetes` (7.8) |
| `capabilities` | Feature names the peer supports (section 13) |
| `alias` | Device alias grant, when the peer is reached through a share (7.4) |
| `kubernetes` | The Kubernetes groups the peer holds in the node's cluster; only in a Kubernetes gateway's own map (7.8) |

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
omitted. A gateway replica of a Kubernetes cluster of the node's own Network
(a peer of any other node) is reached by its cluster's name only: its `name`
is such a placeholder and its `display_name` is omitted; its own map names
it as usual. Every name is at most 253 bytes with its trailing dot; Core
bounds the suffix accordingly.

**Packet filter** (`PacketFilter`): a list of inbound allow rules, default
deny. Each rule has `sources` (prefixes, at most 1024), `destinations`
(prefix plus port ranges) and `protocols` (IANA numbers; empty means TCP, UDP
and ICMP). At most 10,000 rules. Rules are node-reduced: they mention only
traffic this node can receive. For a router that includes traffic to the
subnets it serves (7.6): their rules name those prefixes as destinations.

**DNS** (`DnsConfig`): `records` (name, A/AAAA with `value` or CNAME with `target`) for Device names and
imported shares, `resolvers` (IP and optional DoH/DoT URL), `search_domains`,
`routes` (name suffix → resolvers, for split DNS; a route without resolvers is
answered by the node itself). At most 50,000 records. Core sends an A or AAAA
record for each address of self and of each same-Network peer under its name
(not a gateway replica); one for each address of the replicas of each
Kubernetes cluster the map holds under `<cluster>.kube.<zone>.`, in Device
ID order with IPv4 before IPv6 of each replica, at most 32 per cluster since a
node refuses more addresses for one name; and one for each address of each
imported share under its share name; one
route for the suffix with no resolvers, so the node answers every name under
it and an unknown one is `NXDOMAIN`; and the Network's zone as the first
search domain. A node ignores a route without resolvers for the root or a
single-label suffix, unless it declared `dns.forward1`. Core sends no pointer
records: the node answers PTR queries for the addresses of the records under
its own zone (the zone its own name is in). Within a stream, Core sends `dns`
in a delta only when it changed.

**Forward zones** (`dns.forward1`, sent only to a node that lists
`dns.split`, `dns.forward1` and `map.large1`). After the suffix route, one
route per DNS zone of the Network sent to this Device, sorted by suffix: up
to 256, at most 4 resolvers each, in the order the node asks them. A resolver
is a peer's IPv4 mesh address or an Internet address, with `port` (0 is 53).
Core lists a peer as a resolver only while it may serve (an active,
Workspace-owned Device of the Network, no exit node, live), the active
release has a rule from this node to it over UDP on that port, this node is
among the resolver's first 9,744 consumers in Device order (fewer with a
lower configured peer limit), and this node's map has room for it in the 256
peers it keeps for Site routers, exit nodes and resolvers; the peer is then a
needed peer of both maps. A resolver Device whose own client lacks
`map.large1` keeps only 256 peers, so it should serve no more Devices than
that. A zone is never sent to its own resolver Devices. `unavailable` is set when none of a zone's
resolvers can be used now: the node keeps the route, single-label and all, so
the zone never falls back silently. `fail_open` says what the node does when
the route is unavailable or no resolver answers: ask its own system resolver
(or the exit's DNS forwarder while it uses an exit node), instead of
answering `SERVFAIL`. Zones that are search domains follow the Network's zone
by their position, at most 8 search domains in all. A node without
`dns.forward1` receives none of this.

**Names and zone kinds** (`dns.records1`, sent only to a node that also
lists `dns.split`, `dns.forward1` and `map.large1`). A zone may say what the
names it does not hold get. A zone that answers them `NXDOMAIN` is a route
without resolvers and not `unavailable`, which the node answers itself, as
the suffix route. A zone that leaves them to the host is a route without
resolvers, `unavailable` and `fail_open`. A node needs no route of its own
for a name under any route it answers.

Core also sends the names an administrator set in those zones, after the
names above, in name order:
- A name that points at a Device: its A and AAAA records hold the Device's
  mesh addresses. Core sends it while the active release has a rule from
  this node to that live Device (any protocol, any port; one the other way
  is not enough) and the map holds the Device as a peer, or while the
  Device is this node.
- A name with fixed addresses: A and AAAA records.
- A `CNAME` record (type 5) with `target`, the name without a trailing dot.
  Core leaves it out when its chain through the Network's own names reaches
  a Device name this node may not see.

A name already taken by a record above is left out. So is a whole name past
the 50,000 records, or past 1 MiB of these names encoded. A limited map
keeps the Devices names point at after explicit shares and before other
peers.

**The root zone** (`dns.root1`, sent only to a node that also lists
`dns.split`, `dns.forward1` and `map.large1`). The Network's zone for every
name no other route holds is a route with suffix `.`, with resolvers,
`unavailable` and `fail_open` as a forward zone; it sorts before the other
zones and is never a search domain. The node keeps every name at its own
resolver while it has the route, `unavailable` or not, so a zone that fails
closed never falls back to the host silently; a root zone's resolvers answer
only names no other route holds. A node without `dns.root1` receives no root
zone, and its resolver Devices are no peers of its map for it. With a root
zone, `infrastructure_names` (at most 64) lists the host names of the
deployment's own services (the identity issuer's host, which may be a third
party's, the Console's origin, the Private Interchange host, then the names
the operator protects), each exactly, that the node leaves to its network
like the control host and the relays' hosts; a filtering root zone does not
see them;
it is empty without a root zone, and a name the node cannot read is left
out.

A node without `dns.records1` receives no name and no zone of another kind.
Core holds the wakeups of a Network's DNS changes so they reach maps
together, at most 30 seconds after the first one.

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
| `candidates` | The pool's exit nodes in priority order (`SPREAD`: this node's own order), 1 to 16, each with the `state` and `families` of its last health report, the overlay addresses of its DNS forwarder and `draining` when the administrator is taking it out of the pool |
| `primary` | The exit node Core chose, one of `candidates`; empty when none. `SPREAD`: the exit node Core assigned to this node |
| `generation` | Per pool; increases each time `primary` (`SPREAD`: the pool's serving set) changes and never goes back |
| `status` | `SERVED`: send through `primary`. `UNSERVED`: no exit node can serve now. `CAPACITY`: the exit nodes' maps cannot hold this node |
| `managed` | The administrator asks this node to use the pool. A node follows it only if its own configuration allows managed exits |
| `mode` | `FAILOVER` (or unset): every consumer goes through the elected primary. `SPREAD`: each consumer has its own exit node of the pool's serving set |
| `captive_off` | The administrator turned captive portal windows off for the pool: a node using it opens none, and closes one already open (8.5) |

Core sends a pool to a node only while an active rule lets the node reach the
Internet through it, never the pool the node is an exit node of, and includes
every candidate that is a live Device of the Network as a peer, as for
routers (7.6).

**Local choice.** Using an exit is the node's user's choice, among the pools
Core sends; Core cannot make a node use one unless the node allows managed
exits. A node keeps using the candidate it chose while that candidate
answers and its `state` is not `FAILED`, even when Core chooses another
`primary`: changing exit node changes the node's public address. It may
move back to `primary` once no connection goes through the exit node it
uses: when that node is `draining` or the pool has `mode` `SPREAD`.

**Spread pools.** In a `SPREAD` pool Core assigns each consumer one exit
node of the pool's serving set by rendezvous hashing, so consumers spread
over the exit nodes and each keeps one public address; `candidates` come in
the consumer's own order (priority tier, then the serving set, then its
hash), so consumers of an exit node that stops answering spread over the
others as they fail over locally. Nodes that do not know modes follow
`primary` and the candidate order as in a `FAILOVER` pool.

#### Served pool

`served_exits` (`ServedExits`) holds at most one `ServedExit`: the pool this
node is an exit node of, with its `probes` (at most 8 Internet addresses and
TCP ports the exit node connects to through its own forwarding path),
`conntrack_per_consumer`, `smtp_allowed`, `dns_upstreams` (at most 4
Internet addresses, tried in order), `rules`: the pool's rules as filter
rules whose destinations are `0.0.0.0/0` and `::/0`, and `dns_relay_targets`:
the Internet resolvers (port 53) of the Network's DNS zones sent to every
Device, distinct and in address order, which the exit node's DNS forwarder
relays any consumer's question to, and `dns_relay_scopes`: at most 64, each
the Internet resolvers of zones sent to some Device Groups (`targets`) and the
mesh addresses of the pool's consumers in them (`sources`, host prefixes),
which it relays to for those consumers only; at most 256 resolvers in all
(DNS relay below). An exit node forwards
only when its own configuration offers to be one (`exit_offered`, 8.2) and
only what those rules admit to the Internet; its local limits may lower
`conntrack_per_consumer` and refuse SMTP whatever Core sends.

#### DNS relay

A consumer asks its exit node's DNS forwarder to relay a question to one
resolver of a zone with the EDNS option 65432 (Local/Experimental Use,
RFC 6891): version 1 (1 byte), address family 1 IPv4 or 2 IPv6 (1 byte), port
53 (2 bytes), the address (4 or 16 bytes). A forwarder that relays answers
every question carrying the option with the option too, version 1 and a
status byte, added after the answer is fitted to the UDP size: 0 the
resolver answered (its answer as it is), 1 the resolver did not answer
(SERVFAIL), 2 not relayed (the resolver is not in `dns_relay_targets` nor in a
scope naming the consumer's address, is not
on the Internet or belongs to the exit's own networks, or the question holds
the option twice; REFUSED), 3 the forwarder is busy (SERVFAIL), 4 the exit
node's own way to the Internet is down (SERVFAIL). The forwarder removes the
option before asking the resolver. An answer without the option comes from a
forwarder that does not relay (DNS design D1c). A consumer never answers a
zone's name from another resolver after status 2, even for a zone that fails
open (DNS design D1c.5).

#### Validity

A node refuses a map as malformed when `exits` or `served_exits`: lists a
`pool_ref` twice, out of order, empty, longer than 64 bytes or not UTF-8;
has more pools than allowed; in `exits`, has no candidate, more than 16,
duplicate candidates, the node itself as a candidate, a `primary` outside
`candidates`, `SERVED` with an empty `primary` or an unknown status or state;
in `served_exits`, has more than one pool, a probe, upstream or relay target
that is not an Internet address, more than 256 relay targets in all or a relay
target twice in `dns_relay_targets` or in one scope, more than 64 relay scopes,
a scope without targets or sources or with a source that is not a host
prefix, a probe port of 0, or a rule whose destination is not `0.0.0.0/0` or
`::/0`.

### 7.8 Kubernetes access

A Kubernetes gateway that negotiated `gateway.kube.v1` gets, on each peer of
its own Network that a policy rule naming Kubernetes groups lets reach it,
`kubernetes`: the groups the peer holds in the gateway's cluster and when it
last changed owner, and `owner`. Core offers `gateway.kube.v1` only where it
builds maps from its shared Network view; it ignores it from any node that is
not a gateway. No other map carries either field, and no peer of another
Network ever does.

- **Grants.** `grants` lists the groups, sorted, at least one. Each holds
  until `valid_until_ms`, never 0: the earliest of the selector membership
  the rule matched the peer by, the peer's key expiry, and, for a member's
  Device (tagged or not), the end of its owner's Workspace and Network
  memberships. A group several rules grant holds until the latest of them.
  The gateway stops honouring a grant at its deadline on its own; Core drops
  it at its next rebuild.
- **Exclusions.** A peer that routes for others (a Site router or an exit
  node, in any state), a member's Device whose owner is no longer an active
  member, and a peer Core holds no owner evidence for carry no `kubernetes`.
  Only a rule whose destination group holds nothing but the cluster's
  replicas counts.
- **Owner.** `owner.ref` is the member's public principal ID, `tags:` and the
  Device's tag IDs sorted and joined by commas, or empty for a Device of the
  Workspace; `owner.display_name` is always empty (no person's name reaches
  the cluster). `owner_changed_ms` is when the Device last changed owner; 0:
  never.
- **Replacement.** Every `peers_upsert` to the gateway carries both fields,
  connectivity upserts included: an upsert replaces the peer, so without them
  a peer going offline would lose its groups. A change of the access alone
  between revisions (a membership ending) comes as a full snapshot.
- **Withheld.** When Core could not read the evidence with the policy the
  map's packet filter came from (the gateway was read on its own, or the
  evidence was inconsistent), the map carries no `kubernetes` on any peer.

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

With `dns.root1` it also carries `dns_digest` and `dns_routes`: the
[DNS digest](dns-digest-v1.md) of the DNS routes and search domains the node
applied to its host after validating the map, and how many routes it covers,
or, when it applies none, an empty `dns_digest` and `dns_reason`: `user_off`
(turned off on the Device) or `apply_failed` (the host refused it). Sent
after each DNS apply or failed apply too. Core compares it with the digest
of the DNS it last sent the node. A digest of another length, a digest with
a reason, or an unknown reason is left out; the policy evidence still counts.

### 8.5 Captive portal windows

To sign in to a hotel or airport Wi-Fi while it uses an exit, a node's root
may open a captive portal window: for a few minutes (at most 5) the host's
web traffic leaves straight to the local network instead of the exit node.
No window opens while the node's pool has `captive_off` (7.7); a node
without that field's support ignores it.

With `captive.audit1` (a node lists it with `routes.exit.v1`) the node
reports each window that closed in a `CaptiveWindowReport{windows}`, at most
16, each once per session and at most one report per 15 s: `window_id` (32
lowercase hex digits), `opened_ms` and `closed_ms` (when the node saw it open
and close, at the latest its end) and `end`: `EXPIRED` (its time ran out),
`CLOSED` (root closed it, or the node stopped using the exit) or
`TUNNEL_BACK` (the node closed it once the tunnel was back). Core does not
answer; the node reports a window in up to 3 sessions. Core records each
window once per Device and `window_id`, with a `device.captive_window` audit
event, at most 48 per Device per day. A report never names the portal.

An empty report, more than 16 windows, a `window_id` of another shape, an
unknown `end`, or a report on a session without `captive.audit1` is
`INVALID`. Core leaves out, without ending the session, a `window_id` listed
twice after its first, and a window whose times it cannot take (closed more
than a minute after Core's clock, more than 6 minutes long, or more than 30
days old). It drops a report sooner than 10 s after the last of the session
or before the session has a map; a window it could not record (the daily
budget, another session of the Device recording, a database error) is not
audited unless a later session reports it again.

### 8.6 Resolver health

With `dns.root1` a node sends `DnsHealthReport{resolvers}`: how its resolver
sees each resolver of the zones it applies, at most 64, the root zone's
first. Each is `ip` (4 or 16 bytes, as the map sent it), `port` (0 is 53),
`state` (`OK`; `BROKEN`, its circuit breaker skips it; `STOPPED`, a resolver
Device that stopped answering the node's pings, asked last; `REFUSING`, its
last answer was `SERVFAIL` or `REFUSED`; `IDLE`, not asked since the zones
were applied) and `last_ok_ms` (its last answer, 0 for none). The node sends
the whole set on change, at least 30 s apart, and at least every 5 minutes
while unchanged. Core keeps only resolvers it sent the node, drops a report
sooner than 20 s after the last of the session or before the session has a
map, and keeps the latest per session. More than 64 resolvers, one listed
twice, an address of another length, a port over 65535, an unknown `state`,
or a report on a session without `dns.root1` is `INVALID`. A new `state`
therefore comes with a new capability.

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
| `dns.forward1` | Node applies forward zones (7.3): routes with resolvers and `port`, `unavailable` and `fail_open`; only with `dns.split` and `map.large1` |
| `dns.records1` | Node applies names and zone kinds (7.3): `CNAME` records, routes it answers or leaves to the host, names under a route without a route of their own; only with `dns.forward1` |
| `dns.root1` | Node applies the root zone (7.3), reports the DNS digest it applied (8.4) and sends `DnsHealthReport` (8.6); only with `dns.forward1` |
| `stats.path1` | Node sends `PathStatsReport` |
| `nat.report1` | Node sends NAT classification in `EndpointReport` |
| `map.large1` | Node applies maps of up to 10,000 peers; without it Core sends at most 256 |
| `session.proof1` | Core accepts `NodeKeyProof` as a session's first record (6.7) and `RotateMachineKey` from gateways (6.8); a Kubernetes gateway requires it |
| `routes.subnet.v1` | Node applies `routes` (7.6) |
| `router.subnet.v1` | Node can forward into Sites: it applies `served` (7.6) and reports `route_digest` (8.4) |
| `router.health1` | Node sends `RouteHealthReport` (8.3); only with `router.subnet.v1` (Sites) or `router.exit.v1` (its Exit Pool) |
| `routes.selection1` | Node sends `RouteSelectionReport` (8.3); only with `routes.subnet.v1` (Sites) or `routes.exit.v1` (its exit) |
| `routes.exit.v1` | Node applies `exits` (7.7); with `routes.selection1` it reports its exit in `RouteSelectionReport` |
| `router.exit.v1` | Node can be an exit node: it applies `served_exits` (7.7) and reports `exit_offered` (8.2); with `router.health1` it reports its exit health in `RouteHealthReport` |
| `relay.zones2` | Node hands relays MTT2 tickets and their ZONES (MTRP §5.4, §6.1). Core offers it only once every relay accepts them |
| `captive.audit1` | Node sends `CaptiveWindowReport` (8.5); only with `routes.exit.v1` |
| `gateway.kube.v1` | A Kubernetes gateway applies its peers' `kubernetes` and `owner` (7.8); Core offers it only where maps come from its shared Network view |

Unknown names are ignored. Core sends a feature only when both sides list it.

## 14. Limits and admission

| Item | Limit |
|---|---|
| Handshake record | 2048 bytes |
| Transport record | 65535 bytes |
| Concurrent sessions per Core replica | configurable (default 4096) |
| New handshakes per source (IPv4 address or IPv6 /64) | 10/s burst 50 by default, configurable; before any Noise work |
| Unauthenticated connections per source (IPv4 address or IPv6 /64) | handshakes in progress plus established sessions that have not yet received a map snapshot; by default the handshake burst plus 10 seconds at the handshake rate (150), configurable |
| Node key changes per Device | 4 per hour, 30 for a Kubernetes gateway (6.3); over it `Error{NOT_PERMITTED, retry_after_ms}` |
| Machine key changes per Kubernetes gateway | 30 per hour (6.8); over it `Error{NOT_PERMITTED, retry_after_ms}` |
| Endpoint changes a Device's peers see | 1 per 5 s by default, configurable (8.1); the latest is always delivered |
| New Devices a person adds to one Network by browser sign-in | 20 per 24 hours, revoked ones included; over it `Rejected{NOT_PERMITTED}`. Resuming a Device is not adding one. |
| `RegisterRequest` and `RotateNodeKey` per session | 4 at once, then 1 per second; over it `Error{OVERLOADED, retry_after_ms}` |
| Browser approvals issued or resumed per session (6.2) | 2 at once, then 1 per 10 s; over it `Error{OVERLOADED, retry_after_ms}`. A malformed resume handle is refused before it counts |
| `MapResync` per session (7.1) | 2 at once, then 1 per 5 s; over it fatal `Error{OVERLOADED, retry_after_ms}`, and the node gets a fresh snapshot when it reconnects |
| `EnforcementReport` per session (8.4) | 4 at once, then 1 per second; over it the latest report is kept, replacing any kept before, and stored when the budget allows |
| `RouteHealthReport` per session (8.3) | 2 at once, then 1 per 2 s; over it the latest report is kept, replacing any kept before, and stored when the budget allows |
| `RouteSelectionReport` per session (8.3) | 2 at once, then 1 per 5 s; over it the latest report is kept, replacing any kept before, and stored when the budget allows |
| `DnsHealthReport` per session (8.6) | 1 per 20 s; a sooner one is dropped, the node's next one counts |
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
| `SESSION_REPLACED` | A newer session for this machine key exists, or another stream took a Kubernetes gateway's presence (6.8) |
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
| C18 | One Device churns its whole Network by rotating its node key in a loop, each change advancing the revision and resetting its peers' WireGuard sessions | At most 4 key changes per Device per hour (a Kubernetes gateway, which re-keys at every start: 30 node key and 30 machine key changes, so whoever holds its current Secret can cause about 60 an hour until an administrator removes it), checked under the Device lock; registration and rotation requests are also rate limited per session (sections 6.3, 14). A refused request still briefly takes the Network's revision lock; the per-source handshake rate bounds how often |
| C19 | One Device floods its Network with endpoint changes, each costing one map delta per peer | At most one announced change per Device per announce interval, gated atomically in Redis across sessions and replicas; the latest change is still delivered (section 8.1) |
| C20 | A Device announces endpoints that point its peers' probes at a victim: the overlay, a relay, Core | Core drops overlay, special-purpose, relay and operator-denied addresses, also through NAT64, when a report arrives and when it sends a map; nodes refuse overlay and relay addresses as candidates; each node's pings to a peer's unanswered candidates are bounded by a backoff and a per-Device budget: at most 144 at once and 0.4/s in the long run, so a victim named by M Devices receives at most 0.4 × M pings/s from each node that has them in its map (section 8.1, disco-v2 §4.4) |
| C21 | One session makes Core work in a loop with cheap messages: map resyncs that each encode the whole map, enforcement reports that each write Redis, browser approvals that each write the database, or a flood of any message | Per-session budgets for each, and one for all messages and bytes (section 14); a node that follows the protocol stays well inside them, and reconnecting is bounded by the per-source handshake rate |
| C22 | A leaked cluster join key makes its holder a Kubernetes gateway, which sees who connects and carries kubectl traffic | The key opens only a request with no Device; an administrator approves it by a code bound to the replica's own keys, read from the real pod's log and checked by Core and its database; five wrong codes cancel; at most twice the key's uses wait; the key lives an hour at most (6.6) |
| C23 | A copy of a Kubernetes gateway's Secret, or an older Core, serves, logs out or re-keys the gateway | A gateway proves its node key as its session's first record; until then nothing is established or replaced and its timestamp is not recorded; the database resolves a gateway only for a transaction marked proven, which older Core never marks; gateways cannot log out or register again; former machine keys are kept and refused, and a gateway moves to a new machine key at every start (6.7, 6.8); a gateway session that pushes out a live one on the same replica contests the key, and no session of it rotates for 15 seconds (6.8). A copy of the current Secret remains a gateway until an administrator removes it, and on another replica than the real pod's, or by starving the handshakes of the pod's source address, it can rotate the keys and lock the pod out |

## 17. Test vectors

`shared/mtcp/testdata/vectors.json` holds a complete handshake with fixed
machine, control and ephemeral keys (INIT, RESPONSE, handshake hash), three
transport records in both directions, node and disco key proofs bound to that
handshake, the control key ID and the control key fingerprint.
`shared/mtcp/testdata/crosscheck.py` recomputes all of them with an
independent Noise IK implementation (Python, `cryptography` package):
`make mtcp-crosscheck`. Fragmentation, ZSTD limits and the protobuf encoding
of messages are pinned by the Go tests of `shared/mtcp`.
