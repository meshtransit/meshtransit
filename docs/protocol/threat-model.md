# Network-layer threat model

Draft 1, 2026-10-09. Covers path discovery (disco v2), the relay protocol
(MTRP v1, Interchange), relay tickets and NAT classification. The control
protocol's threats are listed in [mtcp-v1.md §16](mtcp-v1.md#16-security-considerations).

## 1. System and trust boundaries

```
 node A ──disco v2 (UDP, direct or via relay)── node B
   │  \                                        /  │
   │   └──MTRP v1 (UDP | TLS | WebSocket)──Interchange──┘
   │                                         │
   └────────MTCP (TLS + Noise)────────── Core ┘ (tickets, revocations, relay map)
```

- **Core** is trusted for authorization: it issues relay tickets, the signed
  relay map and revocations. Its signing key is the root of trust for relays.
- **Interchange** (relay) is trusted to forward only what tickets allow and to
  stay available. It is **not** trusted with confidentiality: it only sees
  WireGuard ciphertext and encrypted disco messages.
- **Nodes** are trusted for their own traffic only. Another node in the same
  Network may be malicious.
- **The network path** (Wi-Fi, ISP, carrier NAT, cloud NAT, Internet) is
  hostile: it can observe, drop, delay, replay, reorder and spoof packets.

## 2. Assets

| Asset | Why it matters |
|---|---|
| Confidentiality and integrity of node traffic | Core promise; protected end to end by WireGuard |
| Node identity keys (WireGuard node key, disco key) | Impersonation of a device |
| Core ticket-signing key | Forging relay access for any node |
| Relay static key | Impersonating a relay to nodes |
| Authorization boundary (Network, Trust Contract) | A relay must never let an outsider reach a node |
| Relay capacity | Shared by every tenant; abuse affects all |
| Metadata (who talks to whom, when, from where) | Privacy of customers |
| Availability of direct paths | Falls back to relay, costs latency and money |

## 3. Adversaries

| ID | Adversary | Capability |
|---|---|---|
| A1 | Off-path attacker | Sends spoofed UDP from arbitrary source addresses |
| A2 | On-path attacker | Observes, drops, replays and modifies packets on one path |
| A3 | Malicious node in the same Network | Holds valid keys and a valid ticket for that Network |
| A4 | Malicious tenant | Valid account in another Workspace; tries to reach foreign nodes or exhaust relays |
| A5 | Compromised relay | Full control of one Interchange node |
| A6 | Revoked or expired node | Previously valid keys and tickets |

## 4. Threats and required mitigations

STRIDE category in brackets. "MUST" items are acceptance criteria for P2/P3.

### Disco v2

| # | Threat | Mitigation |
|---|---|---|
| D1 | [S] A1 forges pings/pongs to steer a node to a wrong endpoint | Every disco message is authenticated with X25519-derived keys between the two disco keys; unauthenticated packets are dropped before any state change |
| D2 | [S/T] A2 replays an old CallMeMaybe to make a node spray pings at old addresses (reflection) | CallMeMaybe carries a per-sender sequence number and timestamp; receivers MUST reject seq ≤ last accepted and timestamps outside ±60 s |
| D3 | [D] A1 spoofs a victim's address in pings to make nodes send pongs to the victim | A pong is never larger than the ping that caused it; pongs per source address are rate limited (default 10/s, burst 20) |
| D4 | [D] A3 sends huge endpoint lists | At most 32 endpoints per CallMeMaybe, at most 64 candidates kept per peer, each with a lifetime |
| D5 | [I] Observers learn endpoints | Endpoints travel only inside encrypted disco messages or MTCP |
| D6 | [S] Learning a peer-reflexive address from a forged ping | Peer-reflexive candidates come only from authenticated pings of a peer present in the current map |
| D7 | [D] A peer keeps a node sending to an endpoint that no longer answers (consent) | Consent freshness: stop sending to a candidate that has not answered an authenticated ping for 30 s |
| D8 | [D] Port prediction floods a NAT or looks like a scan | Prediction runs only for the matrix case that needs it, ≤ 1,024 probes per attempt at ≤ 100 packets/s, with per-peer and per-node backoff; Workspace can disable it |

### MTRP v1 and Interchange

| # | Threat | Mitigation |
|---|---|---|
| R1 | [S] A1/A4 connects without authorization | Noise IK handshake proves possession of the disco key named in a Core-signed ticket; no forwarding before the handshake completes |
| R2 | [E] A4 relays to nodes outside its Network | A route opens only when both sessions' tickets share a zone (Network or Trust Contract); checked on every route open |
| R3 | [S] A1 injects DATA by spoofing a session's source address | UDP sessions are bound to the source address of the last authenticated packet; DATA from any other address is dropped. Address changes require an authenticated CONTROL packet (roaming) |
| R4 | [D] A1 amplifies traffic through the relay | No reply larger than the request before the handshake completes; handshake initiation is padded to at least the response size; cookie replies (WireGuard-style mac1/mac2) under load |
| R5 | [D] A3/A4 exhausts relay capacity | Per-session, per-node and per-zone limits on routes, packets/s and bytes/s from the ticket; global admission control; idle sessions close after 90 s |
| R6 | [T] Replay of handshake messages | Noise IK with ephemeral keys; a TAI64N-style timestamp in the initiation payload; replays older than the last accepted timestamp per disco key are rejected |
| R7 | [E] A6 keeps using a revoked node | Tickets live ≤ 15 minutes; Core pushes revocations; relays close matching sessions within 5 s (p99) |
| R8 | [S] A1 forges tickets | Tickets are signed with Ed25519 over a domain-separated canonical encoding; relays accept only key IDs announced by Core and reject unknown versions |
| R9 | [I] A5 reads traffic | Payloads are WireGuard ciphertext; relays hold no node traffic keys |
| R10 | [I] A5 or logs leak metadata | Relays log only aggregates; no endpoint, key or route is logged; retention per policy |
| R11 | [S] A2 impersonates a relay | Relay static keys come from the Core-signed relay map; Noise IK authenticates the responder |
| R12 | [D] Parser bugs crash or slow the relay | Fixed-size headers, bounded lengths checked before allocation, fuzzing of every parser, no reflection-based decoding on the hot path |

### Tickets and keys

| # | Threat | Mitigation |
|---|---|---|
| K1 | Signing key compromise | Key stored in a Secret, used only by Core; key IDs allow rotation; rotation runbook |
| K2 | Key confusion across protocols | Distinct key types per purpose (WireGuard node key, disco key, relay key, signing key); every signature and KDF uses a unique domain string |
| K3 | Timing leaks in MAC/signature comparisons | Constant-time comparisons for every MAC; library Ed25519 verification |
| K4 | Weak randomness | All nonces, IDs and keys come from the OS CSPRNG (`crypto/rand`) |

## 5. Residual risks (accepted for now)

- DATA frames on UDP are not authenticated by the relay layer (R3 limits who can
  inject; WireGuard drops garbage). An attacker on the path can inject junk that
  costs relay bandwidth, not confidentiality.
- A compromised relay can drop or delay traffic and see traffic volumes
  between nodes it relays.
- Port prediction may be flagged by carrier IDS; it is opt-out per Workspace.
- No external cryptographic review before production (owner decision
  2026-10-09); compensated by standard constructions, test vectors, fuzzing and
  adversarial tests.
