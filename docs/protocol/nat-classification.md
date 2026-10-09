# NAT classification

Draft 1, 2026-10-09. Implementation: `shared/netcheck`; meshd runs it on its
encrypted packet socket (`client/internal/pathdiscovery`), shown by
`meshctl netcheck`.

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
   - `M(S1) ≠ M(S2)` and S1′ was not measured: **address-and-port-dependent**
     (the two cannot be told apart; the stricter value keeps peers from
     relying on port reuse that may not exist);
   - fewer than two server addresses answered: **unknown**.
2. **Port allocation.**
   - Endpoint-independent: mapped port equals the local port → **port-preserving**,
     otherwise **random** (nothing better to learn).
   - Endpoint-dependent: contact the destinations one at a time and take the
     differences between consecutive *distinct* mapped ports. At least three
     distinct mappings are needed, otherwise **unknown**. All differences in
     1..8 (modulo 2^16) → **sequential** with the median step recorded;
     otherwise **random**.
3. **Filtering** (needs a server supporting RFC 5780 CHANGE-REQUEST):
   - ask for a response from the other address and port: received →
     **endpoint-independent**;
   - otherwise ask for a response from the other port only: received →
     **address-dependent**; not received → **address-and-port-dependent**;
   - if the server has no alternate address but has an alternate port, a
     received change-port response proves at most **address-dependent**
     (report 2); a missing one proves **address-and-port-dependent**;
   - no RFC 5780 server reachable: **unknown**;
   - contradictory results resolve to the stricter class.

   The filtering probes MUST run before any packet is sent to S1′, which
   shares S1's address and the alternate port: that packet would open the
   filter the change-port probe measures. A response counts only if it comes
   from the address and port the change request asked for; a server that
   ignores CHANGE-REQUEST answers from its primary address, and accepting that
   would report filtering as open.
4. **IPv6.** Report whether the node has a global IPv6 address and whether STUN
   over IPv6 succeeded (CALL_ME_MAYBE flag bit1).

Each probe waits 1 s and is retransmitted once after 200 ms. The whole
procedure is bounded to 3 s and uses at most four servers. Transaction IDs
come from a CSPRNG; responses with an unknown transaction ID are dropped.

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

## 6. Laboratory validation

`test/natlab` simulates the NAT behaviours above (RFC 4787 mapping,
filtering, allocation, timeouts, hairpinning, carrier-grade chains and IPv6
stateful firewalls) with an RFC 5780 STUN server. Tests check that
`shared/netcheck` classifies every profile correctly, and a reference agent
built on disco v2 records which technique connects each pair of profiles in
[`test/natlab/testdata/matrix.md`](../../test/natlab/testdata/matrix.md),
regenerated with `make natlab-matrix`.
