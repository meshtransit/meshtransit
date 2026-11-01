# Connection log v1 (flowlog-v1)

Status: draft for phase 1a. Schema: `api/flowlog/v1/flowlog.proto`. Token code:
`shared/flowlog`. Design and decisions: `docs/connection-logs-design.md` and
ADR-054 in the MeshTransit design repository.

## 1. Scope

A node counts the traffic its packet filter allows and denies, aggregates it
per window and sends one batch per window to the connection log receiver
(`meshflow`). The receiver names the endpoints from Core's directory and
writes the records to the customer's S3 or R2 bucket. MeshTransit stores no
connection logs: a node keeps its batches until the receiver reports them
written.

## 2. Roles

| Party | Does |
|---|---|
| Node (meshd, meshgw) | counts at the packet filter, keeps batches until committed, sends them |
| Core | decides whether a node may send (Workspace entitlement, Network setting), signs its token, sends `FlowTicket` over MTCP (mtcp-v1 §9.1) |
| Receiver | checks the token and the Noise key, checks and names records, writes them to the customer's bucket, answers the committed sequence |

## 3. Token

`token = "MFT1" || u16be(len(claims)) || claims || sig`, where `claims` is the
deterministic protobuf encoding of `FlowTokenClaims` and `sig` is Ed25519 over
`"meshtransit/flow-token/v1" || 0x00 || claims` with a key used only for
connection log tokens, named by `kid`. A token is at most 2,048 bytes.

- `version` 1; `kid` 1 to 32 bytes of `[A-Za-z0-9._-]`; `audience`
  `meshflow:<deployment ID>`, at most 80 bytes.
- `workspace_id`, `network_id`, `device_id`, `token_id`: 16 bytes;
  `machine_key`: the 32-byte machine key the node uses as its Noise static key.
- `roles`: one or more of `DEVICE`, `ROUTER`, `EXIT`, `GATEWAY`, each once.
  `site_ids` come with `ROUTER`, `exit_pool_ids` with `EXIT`, `cluster_ids`
  with `GATEWAY`: a role that has IDs carries at least one, IDs never come
  without their role, no ID twice, at most 64 IDs in all.
- `issued_at ≤ not_before < expires_at`, `expires_at - issued_at ≤ 15 min`.
- `window_s` 60 to 300: the window the node aggregates over.
- A verifier allows 2 minutes of clock skew on `not_before` and `expires_at`,
  refuses unknown fields, unknown `kid`s and another audience.

Core rotates the signing key by `kid` with an overlap. A token never appears in
another node's map, the local API, diagnostics or logs. The token's
`expires_at` governs; `FlowTicket.not_after_ms` only tells the node when to
expect a new ticket.

## 4. Transport

One request per window, with jitter: `POST <control origin>/mtflow/v1/batches`
(ADR-054), over the control connection's TLS. TLS is transport only: the token
and the Noise messages authenticate end to end between node and receiver, and
the spec assumes an on-path party.

**Request.**

- Header `MeshTransit-Flow-Token`: the token, base64url without padding.
- Header `MeshTransit-Flow-Network`: the token's `network_id` as a lowercase
  UUID. Ingress routes on it so a Network's batches tend to reach one
  replica, which then writes them in fewer, larger objects; the token
  changes at every renewal, so it cannot be the routing key. Correctness
  never depends on that routing: any replica may take any batch (§5).
- `Content-Type: application/vnd.meshtransit.flowlog.v1`.
- Body: frames, each `u16be(n) || n bytes` with `n ≥ 1`.
  - Frame 0, at most 256 bytes, is the message of
    `Noise_X_25519_ChaChaPoly_BLAKE2s`, prologue
    `"meshtransit flowlog v1" || 0x00 || token`, with the decoded token bytes.
    The initiator's static key is the node's machine key; the responder's
    static key is `FlowTicket.receiver_key`. Its payload is a `FlowRequest`:
    `batch_length` L (1 to 4 MiB), the batch's `boot_id` and `sequence`,
    `held_from` and `lost` (§5).
  - Frames 1 to k are transport messages under the first cipher state of the
    split, each with a plaintext of 65,519 bytes but the last (1 to 65,519).
    Their plaintexts, in order, are exactly L bytes: the gzip-compressed
    `FlowBatch`, one gzip member and nothing after it.

**Receiver order.** Each step runs only when the one before passed.

1. Per source address rate limit.
2. Token from the header: decode, `flowlog.VerifyToken` (signature, `kid`,
   audience, validity). Nothing of the body is read before this. Then
   ownership: a replica that does not write the Network the
   `MeshTransit-Flow-Network` header names answers 421 with `Retry-After`
   (`flowlog.ErrNotOwner`), still without reading the body; the node sends
   again later, and ingress routes it to the owner.
3. Frame 0: read the handshake message, then `Token.Claims` with the
   initiator's static key; another key is refused. Decode the `FlowRequest`,
   unknown fields refused. The `MeshTransit-Flow-Network` header must be the
   claims' `network_id` (`flowlog.CheckNetworkHeader`), or 400.
4. Device revocation or suspension (from Core), then the per-Device and
   per-Network rate limits.
5. The sequence rules of §5 decide only: when the batch is already held or
   out of order the receiver answers now and reads no further; otherwise it
   reads on. Only rule 1 of §5 may change its state here (`held_from` is
   authenticated by frame 0); `held` moves to `s` only when step 7 passes.
6. The transport frames: every one must decrypt, the plaintexts must add up
   to L exactly, nothing may follow the last.
7. Decompress with at most 16 MiB out, decode with unknown fields refused,
   check that `boot_id` and `reporter_sequence` match the request, then the
   rules of §6.

**Answer.** Once step 3 passes the receiver answers with HTTP 200 and the body
`u16be(n) || n bytes`: one message of `Noise_K_25519_ChaChaPoly_BLAKE2s` from
the receiver (initiator, static key the receiver key) to the node (responder,
static key its machine key), prologue
`"meshtransit flowlog v1 answer" || 0x00 || h`, where `h` is the request
handshake's hash after frame 0 (its channel binding). Its payload is a
`FlowBatchResponse`. The receiver's fresh ephemeral key makes every answer's
keys new, so a replayed request never makes the receiver seal twice under one
key; `h` binds the answer to the request it answers, and `ss` to the receiver
key.

Until step 3 passes, and when step 6 fails, the receiver answers in plain
HTTP: 400 (framing, a frame that does not decrypt, a body short of or past L,
a `MeshTransit-Flow-Network` header that is not the token's Network), 401
(token), 403 (another machine key, revoked Device), 413 (size), 421 with
`Retry-After` (another replica writes the Network), 429 or 503
with `Retry-After` (503 also for a fault of the receiver's own). The receiver
reads at most one batch per (Device, `boot_id`) at a time and caps a body at
frame 0 plus L plus 18 bytes per frame. **A node never drops a batch on a plain HTTP answer**,
only on a `FlowBatchResponse` that opened under its machine key; on 401 or
403 it waits for a new `FlowTicket`, on anything else it backs off and sends
again. An on-path party can thus delay batches, never delete them.

The batch has no forward secrecy against the receiver's static key: whoever
later holds that key can read recorded requests. Ingress and receiver never
log the token header, nor the Network header next to a source address. A recorded request can be
replayed while its token is valid; the receiver answers it as a batch it
already has (§5), and only the node can open the answer.

## 5. Batch and sequence

- `boot_id`: 16 random bytes, new whenever the node starts a new spool.
- `reporter_sequence` starts at 1 and increases by one per batch of a
  `boot_id`. The node keeps each batch's compressed bytes and sends them again
  byte for byte; it never re-encodes a batch. What changes between sends goes
  in the `FlowRequest`.
- `window_start`/`window_end` are the node's clock; the receiver records its
  own receipt time too.
- `map_revision` and `policy_digest` name the map and enforced policy the
  counts were taken under.
- `records`: at most 65,536. `overflow` counts traffic the node could not key
  this window (packets and bytes counted, endpoints not).

**Node.** The node sends its batches in order, oldest first. `held_from` is
the lowest sequence it still holds; when the spool is full it drops its oldest
batches, committed or not, and `lost` names the dropped range below
`held_from` until a `committed_sequence` reaches past it. When it has nothing
new to send but holds batches that are not yet committed, it sends the oldest
again after `window_s`, so it learns the committed sequence. It ignores an
answer whose `committed_sequence` is above the highest sequence it sent, and
backs off as for a plain HTTP error; when `next_sequence` is below
`held_from` it sends `held_from` next (rule 1 below then applies).

**Receiver.** Per (Network, Device, `boot_id`) the receiver keeps
`committed`, durable: every sequence at or below it is in the bucket, or
written as lost or invalid. It also keeps `held`: the highest sequence that is
fully read and checked and sits in its writer's buffer, or is committed. `held`
is volatile; `committed ≤ held`, and after a restart `held = committed`. The
receiver takes `next = held + 1`. With no state for the `boot_id` (new, the
receiver lost it, or another replica holds it) it starts with
`held = held_from - 1`, so it never commits a sequence it has not seen, and:

- when the request names no `lost` range, `committed = held_from - 1`;
- when it names one, the receiver buffers one `lost` event for that range,
  with its counts, and starts with `committed = lost.from - 1`: the node keeps
  naming the range until that event is in the bucket and `committed` moves
  past it, so a receiver without state never erases the evidence of a loss.

Several receivers may hold state for the same `boot_id` (replicas, a
restart): each commits only what it wrote, the answers of one may name a
lower `committed` than another's, and the node keeps the highest it was
answered. Their `lost` events may overlap, with different record IDs:
consumers take the union of the ranges, and the counts are informational.
Then, for a request with sequence `s`:

1. When `held_from > next`, the node dropped `next..held_from-1`: the
   receiver buffers one `lost` event for that range (with the counts of
   `lost` when it names exactly that range: counts of a wider or narrower
   range would be wrong for this one) and sets `held = held_from - 1`.
2. `s ≤ held`: **already held**, answered `ACCEPTED` with the current
   `committed`, nothing read or written.
3. `s = next`: the receiver reads the batch (§4 steps 6 and 7). Only when
   both pass does it buffer the batch, or its `invalid` event, and set
   `held = s`; when they fail it answers in plain HTTP and nothing changes, so
   the node sends `s` again. `committed` follows once the buffer is in the
   bucket.
4. `s > next`: **out of order**, answered `OUT_OF_ORDER` with
   `next_sequence = next`; the node sends that sequence first.

A batch that breaks §6 is buffered as one `invalid` event and counts as held,
so the next one is not held up. A truncated or corrupted body leaves `held`
where it was. When the receiver lost state and starts again at `held_from`,
batches the node still holds are written again with the same record IDs; a
`lost` event may name batches that were in fact written before the state was
lost, so consumers match `lost` events against the record IDs they have.

## 6. Records

A record is one aggregate of a window: allowed traffic of one flow key
(`kind FLOW`), or the denials between two endpoints (`kind DENY`).

- **Classes:** `MESH` (Device to Device, a Kubernetes gateway included),
  `SHARE` (a Device shared from another Workspace), `SITE`, `EXIT`. An
  Internet address never leaves the node: `EXIT` records, and any record whose
  far end is neither a mesh nor a private address, carry no IP for that end,
  only pool, protocol and destination port.
- **IDs:** the node fills `source_device_id`/`destination_device_id`,
  `trust_contract_id`, `site_id`, `exit_pool_id`, `cluster_id` only from its
  own map. The receiver checks they belong to the token's Network or contract.
- **primary:** exactly one record of a piece of traffic is primary: the
  receiving node for `MESH`, each Workspace's own side for `SHARE`, the router
  for `SITE`, the exit node for `EXIT`, the deciding node for `DENY`.
- **Deny reasons:** `NOT_IN_MAP` (sender; no rule to a mesh address),
  `PORT_NOT_ALLOWED` (receiver), `SHARE_SERVICE`, `SHARE_EXPIRED`,
  `ROUTE_NOT_INSTALLED` (sender), `PEER_UNUSABLE`, `CAPACITY` (a limit of
  the deciding node: an exit node's consumers, a share's flow table). Multicast, broadcast,
  link-local and addresses outside the Network's mesh ranges are not counted
  as denials. Denials aggregate per (source, destination, protocol) with
  `distinct_ports` and at most 8 `sample_ports`.

**Counts.** What a node reports, as `client/internal/flowcount` counts it:

- A `FLOW` key is (class, direction, protocol, source, destination,
  destination port, peer, share/Site/pool). The flow's source is the side
  that opened it; its ephemeral port is collapsed to 0, so connections from
  one client to one service merge. `packets_out`/`bytes_out` go source to
  destination, `_in` the other way; bytes are IP packet lengths.
- `connections`: TCP SYNs without ACK from the source (a retransmitted SYN
  counts again; a connection open before the window counts 0); a UDP or
  ICMP key counts one per window.
- `tcp_state` follows the packets: `SYN` on a SYN, `ESTABLISHED` on an ACK,
  `CLOSING` on a FIN, `RESET` on a RST; once closing or reset it stays so
  until a new SYN. `ended` when a FIN or RST was seen in the window.
- `flow_id`: a keyed hash of the key, the key secret new each time the node
  starts, so it is stable across windows of one run and reveals nothing.
- `distinct_ports` is an estimate (linear counting over 1,024 slots, hashed
  with a per-run seed): about 3 % off typically, up to about 12 % at 2,000
  ports, and it saturates near 7,100; it is never below the number of
  `sample_ports`. Only TCP and UDP denials have ports.
- A node keys at most 4,096 flows and 1,024 denials per window (a router,
  exit node or gateway 61,440 and 4,096: never more than a batch's 65,536
  records); past that the packet counts in `overflow`, whose `keys` is an
  estimate of the distinct keys refused (it saturates near 34,000).
- Noise is never counted, allowed or denied: multicast, broadcast and
  reserved IPv4, link-local, loopback and unspecified addresses. A record or
  denial for an invalid class, direction or reason is a node bug and is
  dropped before it reaches a batch.
- A window covers its records: its start is no later than any `first_seen`,
  its end no earlier than any `last_seen`, and it ends after it starts. Windows
  of one node may overlap a little.

**Refused requests.** A `FlowRequest` with `batch_length` out of bounds,
`boot_id` not 16 bytes, `sequence` 0, `held_from` 0 or above `sequence`, or a
`lost` sequence range that is reversed or does not end below `held_from`, or
a field the receiver does not know at any depth, gets a plain 400: the node
keeps the batch and reports the error in its diagnostics. `lost.from_ms` and
`to_ms` are what the node saw and are never refused (a clock that stepped
back may reverse them).

**Refused batches.** The receiver answers `INVALID` and writes only an
`invalid` event (§5) when:

- the batch: `boot_id` or `reporter_sequence` other than the request's;
  `window_end ≤ window_start` or a window longer than twice `window_s`;
  a window time, `first_seen` or `last_seen` that is not 0 (unset, for
  `first_seen`/`last_seen`) and not between 1970 and the end of year 9999;
  `policy_digest` neither empty nor 32 bytes; more than 65,536 records;
- a record: `kind`, `class` or `direction` unspecified, or a value no enum
  names; `protocol` over 255; a port over 65,535; an IP that is not empty, 4
  or 16 bytes, or an IPv4 address in 16 bytes; an ID or `flow_id` neither
  empty nor 16 bytes; `last_seen < first_seen`;
- a `FLOW` record with a deny reason, `distinct_ports` or `sample_ports`; a
  `DENY` record without a deny reason; more than 8 `sample_ports`, or more than
  `distinct_ports`.

Only these checks, which need nothing but the batch, make a batch `INVALID`.

**Dropped records.** A well-formed record the reporter may not report (it is
not an end of the flow, not the router of the Site, not in the pool's
candidates, not the cluster's gateway, or an ID outside the token's Network or
contract, or a Device ID that is not the Device holding the address beside
it), or one with an IP that is public (outside the Network's mesh
ranges, the deployment's alias ranges, the routes of its Sites and the
private and unique-local ranges; any IP of an `EXIT` record), is dropped and
counted; the rest of the batch is written. These checks read the Network's
directory, which the receiver learns from Core and which may lag a change:
they never make a batch `INVALID`. When an ID or a role is unknown to the
directory the receiver holds and it knows that directory is older than
Core's revision of the Network, it answers the batch `THROTTLED` instead of
dropping, so a new Device's first traffic is checked against the newer
directory. When the receiver holds no directory fresh
enough to check (its last good read of it, 200 or 304, over 5 minutes old,
or built more than 2 minutes before it was answered, as the answer's
built-at and generated-at headers say), it answers the batch with
`THROTTLED` with `retry_after_ms` instead.

## 7. Answer and record IDs

The node drops every batch at or below `committed_sequence`. `ACCEPTED`
batches stay with the node until committed, so a batch may be sent again:
delivery is at least once.

Each written record and event has `record_id` = the first 16 bytes of
`SHA-256("meshtransit/flow-record/v1" || 0x00 || network_id || device_id || boot_id || u64be(sequence) || u32be(index))`
with the UUID version set to 8 and the variant to RFC 9562.

- A record of a batch: `sequence` is the batch's, `index` its position.
- The batch's `overflow` event: index `len(records)`; an `invalid` event:
  index `0xFFFFFFFE`.
- A `lost` event: `sequence` is the first lost sequence, index `0xFFFFFFFF`,
  and `u64be(last lost sequence)` appended to the hashed bytes, so a wider
  range never shares an ID with a narrower one.

A batch written twice keeps its IDs, and consumers deduplicate on them.

`THROTTLED` and `retry_after_ms` hold the node back; `TOKEN_REJECTED` waits for
a new `FlowTicket`; `DISABLED` drops the spool; `INVALID` drops that batch,
which the receiver has already counted as held.
