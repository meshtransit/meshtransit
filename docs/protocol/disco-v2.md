# disco v2: peer path discovery

Draft 1, 2026-10-09. Implementation: `shared/disco`.

disco v2 lets two nodes find and keep the best UDP path between them. It runs
on the same UDP socket as WireGuard, and through the relay when no direct path
exists yet. It never carries user traffic.

## 1. Keys and message keys

Each node has a disco key pair (X25519, see [keys.md](keys.md)). Peers learn
each other's disco public key from the control plane (MTCP) together with the
node key; a disco key not present in the current map is unknown.

For a pair of disco keys `A` (own) and `B` (peer):

```
shared = X25519(a_private, B)                  ; MUST NOT be all zero
lo, hi = sort(A, B) bytewise
K      = HKDF-SHA256(salt = "meshtransit/disco/v2" || 0x00,
                     ikm  = shared,
                     info = lo || hi,
                     L    = 32)
```

`K` is the same for both directions. Implementations SHOULD cache `K` per peer
and erase it when the peer leaves the map or either disco key changes.

## 2. Envelope

```
magic       bytes[6]   = 4D 54 44 32 C0 DE        ; "MTD2" C0 DE
sender      bytes[32]  ; sender's disco public key
nonce       bytes[24]  ; random per message (crypto/rand)
ciphertext  bytes[n]   ; XChaCha20-Poly1305(K, nonce, plaintext, aad)
aad         = magic || sender
```

- Minimum envelope: 6 + 32 + 24 + 16 (tag) + 2 (version, type) = 80 bytes.
- Maximum envelope: 1472 bytes (fits a 1500-byte IPv4 path without
  fragmentation), so the plaintext is at most 1394 bytes. Larger packets or
  plaintexts MUST be rejected; parsers enforce the plaintext bound themselves.
- The magic cannot be confused with WireGuard (first byte 1–4 followed by three
  zero bytes), STUN (first two bits zero) or MTRP frames (first byte 1).
- A receiver looks up `sender` in the current map. Unknown sender: drop.
  Decryption failure: drop. Neither produces a reply or any state change.

## 3. Plaintext

```
version  u8   = 2
type     u8
body     bytes[...]
```

| Type | Name | Direction | Transport |
|---|---|---|---|
| 0x01 | PING | any | direct UDP or relay |
| 0x02 | PONG | reply to PING | same path as the PING (relay: §3.2.1) |
| 0x03 | CALL_ME_MAYBE | any | relay (or MTCP) |
| 0x10–0x1F | reserved for peer relay and port prediction | | |

Unknown types and versions are rejected.

### 3.1 PING (0x01)

```
txid     bytes[12]   ; random, non-zero
node     bytes[32]   ; sender's node (WireGuard) public key
sent_at  u64         ; sender clock, ms
padding  bytes[...]  ; zero bytes; used for path MTU probes
```

The receiver MUST check that `node` is the node key paired with `sender` in
the current map; otherwise drop. Non-zero padding: drop.

### 3.2 PONG (0x02)

```
txid      bytes[12]   ; copied from the PING
observed  endpoint    ; 18 bytes: source address and port of the PING as seen by the responder
echo      u64         ; the PING's sent_at
```

A PONG is 38 bytes of body, always smaller than the PING that caused it
(52 bytes of body plus padding), so pongs cannot amplify. A PONG is accepted
only if `txid` matches an outstanding PING sent to the endpoint the PONG came
from (or through the relay session the PING used) and that PING has not
expired (5 s).

`observed` tells the receiver how the peer sees it: a per-peer reflexive
address. Implementations SHOULD feed it into their own candidate set and NAT
classification (it reveals endpoint-dependent mappings that STUN cannot see).

A PONG through the relay observes no source: its `observed` is 18 zero bytes,
which the receiver ignores. A PONG that arrives directly with a zero
`observed` is dropped, and so is one through the relay with a non-zero
`observed`.

### 3.2.1 Liveness through the relay

A PING through the relay and its PONG prove only that the peer is up and
reachable through the relay; they never establish or select a direct path,
and never add a candidate. A node MAY send them to a peer it needs to know is
alive while it has no proven direct path to it, such as the routers of a Site
it routes through (subnet router failover), at most once every 2 seconds per
peer. The relay-attested node key MUST be the one paired with the sender's
disco key in the map. A node answers a relayed PING with a relayed PONG at
most once per second per peer; a PONG is accepted only if it matches a PING
sent to that peer through the relay in the last 5 seconds. Nodes that predate
this section drop relayed PINGs, so their peers simply see no answer.

### 3.3 CALL_ME_MAYBE (0x03)

```
seq         u64        ; strictly increasing per sender disco key
sent_at     u64        ; sender clock, ms
nat_map     u8         ; mapping behaviour, see nat-classification.md
nat_filter  u8         ; filtering behaviour
nat_alloc   u8         ; port allocation pattern
flags       u8         ; bit0 port mapped, bit1 IPv6 global, bit2 port prediction allowed; bits 3–7 MUST be 0
count       u8         ; 0..32
endpoints   count × (kind u8 || endpoint 18 bytes)
```

Endpoint kinds: 1 host, 2 server-reflexive (STUN), 3 port mapped
(UPnP/NAT-PMP/PCP), 4 static (configured), 5 peer-reflexive (learned from a
PONG). Other values: reject the message.

A sender sets bit0 when the list contains a port-mapped endpoint and bit1 when
it contains a global (not unique-local) IPv6 endpoint of its own (host,
server-reflexive, port mapped or static). The bits are informational: the
receiver probes every listed endpoint either way.

The receiver MUST reject the message if `seq` is not greater than the last
accepted `seq` from this sender disco key, or if `|now − sent_at| > 60 s`. On
acceptance it merges the endpoints into the peer's candidate set (bounded,
section 4.1), clears per-candidate pacing for that peer and pings every
candidate immediately. This is how two nodes open their NATs at the same time.

## 4. Behaviour

### 4.1 Candidates

- Sources: the peer's endpoints from the control plane, CALL_ME_MAYBE, and
  **peer-reflexive** addresses: the source address of an authenticated PING
  from a peer in the map that is not yet a candidate is added as a candidate
  of that peer (kind 5). Peer-reflexive learning is what makes a path through
  an endpoint-dependent NAT work.
- At most 64 candidates per peer. Each candidate expires 5 min 10 s after it
  was last advertised or observed; the oldest unproven candidate is evicted
  first.
- A node only initiates traffic to candidates of peers in the current map.
- A candidate must be an address the probe policy accepts (mtcp-v1 §8.1),
  and never the overlay address of a node in the map or a relay's address,
  nor a NAT64 address embedding one. A node neither learns such an address
  from CALL_ME_MAYBE or a ping's source nor answers a packet from one, and
  drops candidates a new map refuses.

### 4.2 Probing

- A probe round pings at most 8 candidates of a peer: first those that
  answered within 2 min, then those with the fewest unanswered pings, so a
  peer with many candidates is reached across rounds. Sends are paced at
  least 10 ms apart per node.
- A CALL_ME_MAYBE is answered at most once per 2 s per peer, with at most 8
  pings: the candidates it names first, then the others.
- When it starts probing a peer that has no trusted direct path, it also
  sends CALL_ME_MAYBE through the relay with its current endpoints (refreshing
  its own STUN results first if they are older than 27 s).
- Probe order before any result: host addresses on a shared private network,
  global IPv6, port mapped, server-reflexive, peer-reflexive, static.

### 4.3 Path selection and keepalive

- A PONG makes its path **trusted** for 6.5 s; RTT is smoothed as
  `(3·old + new) / 4`.
- Selection: a direct path always beats the relay. Among direct paths, the
  lowest smoothed RTT wins; a switch needs ≥ 10 % and ≥ 2 ms improvement. Ties
  prefer private, then IPv6, then IPv4.
- Until a direct path is trusted, WireGuard packets are sent both through the
  relay and to the best direct candidate, so the first packets never wait for
  discovery.
- While the peer has traffic (in either direction within 45 s): ping the
  selected path every 3 s; when it is not direct or trust has expired, re-probe
  all candidates and send CALL_ME_MAYBE every 5 s during the first minute, then
  every 15 s.
- Idle peers (no traffic for 45 s) are not probed; the next packet restarts
  probing.
- **Consent freshness:** a candidate with no authenticated PONG for 30 s is no
  longer used for sending.

### 4.4 Limits

- Authenticated PINGs answered: at most 16 per peer and 128 in all per
  second; a PING over the limit is neither answered nor learned from.
- A CALL_ME_MAYBE is answered at most once per 2 s per peer (section 4.2);
  replays are refused.
- **Probe budget.** A peer chooses its candidates, so it chooses where a node
  sends pings; the budget bounds what it can make a node send to addresses
  that never answered:
  - a candidate with no PONG is pinged again after 3 s, then 6, 12, 24 and
    48 s, then every minute; a new map generation cancels pending pings,
    so it ends the wait but keeps the count;
  - pings to all such candidates of one peer spend a bucket of 24, refilled
    one per 5 s, so naming new endpoints does not bypass the backoff;
  - while the peer has no candidate that answered, pings beyond the bucket
    spend a path-setup credit of 120, also refilled one per 5 s;
  - a candidate that answered within 2 min is pinged freely, so a working
    path is kept alive; it reaches only the peer itself;
  - the budget belongs to the peer's Device, not its keys or the current
    map: a new disco key, a new map and the peer leaving and rejoining the
    map all keep it, until it would be full again anyway; a ping that was
    never sent is refunded.

  So a node sends a peer's unanswered candidates at most 144 pings at once
  and 0.4 per second in the long run; a victim named by M Devices receives
  at most 0.4 × M pings per second from each node that has them in its map.
  This bounds the pings a node starts. Its PONGs go to the source of an
  authenticated PING, at most 16 per peer per second, so a peer that can
  forge its source address can aim those at a victim, one for one.
- All counters are kept per peer and per node with bounded memory. A peer's
  candidates are forgotten when it leaves the map; its probe budget is kept,
  for at most twice the map's peer limit of Devices, until it is full again.

## 5. Test vectors

`shared/disco/testdata/vectors.json` contains, for fixed keys and nonces, the
derived `K` and complete envelopes for each message type. An implementation
MUST reproduce them byte for byte and MUST reject every entry in the
`invalid` list.
