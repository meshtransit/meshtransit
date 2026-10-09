# NAT classification

Draft 1, 2026-10-09. Implementation: `shared/netcheck`.

A node classifies the NAT in front of its WireGuard socket so that peers pick
the right traversal technique (see the traversal matrix in
`test/natlab`). Terms follow RFC 4787 and RFC 5780.

## 1. Reported values

Carried in disco v2 CALL_ME_MAYBE and in MTCP node status.

| Field | Values |
|---|---|
| `nat_map` (mapping) | 0 unknown, 1 none (address is public), 2 endpoint-independent, 3 address-dependent, 4 address-and-port-dependent |
| `nat_filter` (filtering) | 0 unknown, 1 endpoint-independent, 2 address-dependent, 3 address-and-port-dependent |
| `nat_alloc` (port allocation) | 0 unknown, 1 port-preserving, 2 sequential, 3 random |

"Easy" means mapping ∈ {none, endpoint-independent}. "Hard" means mapping ∈
{address-dependent, address-and-port-dependent}.

## 2. Procedure

All probes are STUN Binding requests sent from the WireGuard socket, so the
results describe the mapping WireGuard and disco actually use.

1. **Mapping.** Query at least two servers with different IP addresses (S1, S2)
   and, when advertised, S1's alternate port (S1′). Let `M(x)` be the mapped
   address returned by server `x`.
   - every `M` equals the local address: **none**;
   - `M(S1) = M(S2) = M(S1′)`: **endpoint-independent**;
   - `M(S1) = M(S1′)` but `M(S1) ≠ M(S2)`: **address-dependent**;
   - `M(S1) ≠ M(S1′)`: **address-and-port-dependent**;
   - fewer than two servers answered: **unknown**.
2. **Port allocation.**
   - Endpoint-independent: mapped port equals the local port → **port-preserving**,
     otherwise **random** (nothing better to learn).
   - Endpoint-dependent: query at least four distinct destinations in sequence
     and take the differences between consecutive mapped ports. All
     differences in 1..8 (allowing wrap-around) → **sequential** with the median
     step recorded; otherwise **random**.
3. **Filtering** (needs a server supporting RFC 5780 CHANGE-REQUEST):
   - ask for a response from the other address and port: received →
     **endpoint-independent**;
   - otherwise ask for a response from the other port only: received →
     **address-dependent**; not received → **address-and-port-dependent**;
   - if the server has no alternate address but has an alternate port, a
     received change-port response proves at most **address-dependent**
     (report 2); a missing one proves **address-and-port-dependent**;
   - no RFC 5780 server reachable: **unknown**.
4. **IPv6.** Report whether the node has a global IPv6 address and whether STUN
   over IPv6 succeeded (CALL_ME_MAYBE flag bit1).

Each probe waits 1 s and is retransmitted once after 200 ms. The whole
procedure is bounded to 3 s.

## 3. Refinement from peers

Every disco v2 PONG carries the address a peer observed. If two peers observe
different ports for the same local socket, the mapping is endpoint-dependent
regardless of what STUN showed; the node updates its classification.

## 4. When to run

At start, after every network change, and every 5 minutes while the node has
peers. Results older than 10 minutes are reported as unknown.

## 5. Privacy

Classification results and endpoints are shared only with the control plane
and with peers in the current map, inside encrypted messages. They are never
logged with addresses.
