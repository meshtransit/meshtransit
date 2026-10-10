# Port mapping

meshd asks the local Internet gateway to forward its WireGuard UDP port, so a
peer can reach this node directly even when both sides sit behind NATs that
would otherwise force a relay (for example two endpoint-dependent NATs, or a
port-restricted cone facing a symmetric NAT).

The implementation lives in `client/internal/portmap`. It is written from the
protocol specifications; no code is taken from other port mapping libraries.

## Behaviour

- **Protocols.** PCP (RFC 6887, MAP opcode, IPv4), NAT-PMP (RFC 6886) and
  UPnP IGD (`WANIPConnection:2`, `WANIPConnection:1`, `WANPPPConnection:1`),
  tried in that order. Once one works it is tried first from then on.
- **Behind a NAT only.** Requests go to the IPv4 default gateway, found from
  the kernel's route to a documentation address (no packet is sent for that),
  and only when both the gateway and the local address are private, shared
  (100.64.0.0/10) or link-local. A host with a public address, such as a cloud
  server, never sends mapping requests (state `unavailable`, `no_nat`).
  PCP and NAT-PMP replies are accepted only from the gateway's port 5351, SSDP
  replies only from the gateway's address. A UPnP device description and its
  control URL must be plain `http` to the gateway's own address literal: no
  host names, no credentials, no other hosts, no redirects, no HTTP proxy.
  Responses are size-limited (PCP/NAT-PMP 1100 bytes, SSDP 2 KiB, description
  256 KiB, SOAP 64 KiB).
- **What is mapped.** Only the WireGuard UDP port, to this host's address on
  the gateway's link. The external port asked for is the internal port; the
  gateway may grant another.
- **Lifetime.** Two hours are requested and the mapping is renewed at half its
  granted lifetime (PCP reuses the mapping nonce). A UPnP gateway that only
  accepts permanent leases gets one, refreshed hourly. A UPnP renewal that
  lands on another external port removes the old entry, and after each
  discovery meshd removes UDP entries an earlier run left for this host (its
  description and internal address, another external port), so a permanent
  lease left by a crash does not stay forever. A `WANIPConnection:2` service
  without `AddAnyPortMapping` falls back to `AddPortMapping`.
- **Gateway restarts.** Every two minutes, and at once after a network change,
  the mapper checks that the gateway still holds the mapping: the PCP and
  NAT-PMP epoch (RFC 6887 §8.5: backwards, or elapsed times differing by more
  than 1/16 plus two seconds), or `GetSpecificPortMappingEntry` for UPnP. A
  lost mapping is requested again immediately. When a cached UPnP control URL
  stops answering, the service is discovered again.
- **Changes.** A new packet port, a new gateway or a new local address removes
  the old mapping and creates a new one. When the control session ends or
  meshd stops, the mapping is removed from the gateway.
- **Failures.** When no protocol answers, the mapper retries every five
  minutes or after a network change. A refused or failed request is retried
  after 30 seconds, doubling up to five minutes. While renewals fail the
  mapping is no longer offered to peers; after three failures in a row it is
  removed and requested afresh.

## Candidates

A mapping becomes a `port_mapping` endpoint candidate, published to Core and
sent to peers in CALL_ME_MAYBE like any other candidate (see
[direct-path.md](direct-path.md)). It is published only when:

- the external address is public: a private or shared (100.64.0.0/10)
  external address means another NAT sits beyond the gateway (state
  `double_nat`);
- it maps the current packet port and has not expired;
- its external address is one meshd observed itself, through STUN in the same
  discovery round or the NAT classification. NAT-PMP and UPnP replies are not
  authenticated, so this keeps a host on the LAN that spoofs the gateway from
  choosing an endpoint peers would probe.

Unlike server-reflexive candidates, a mapping is not retained after it
disappears. A peer still has to prove the path with authenticated disco pings
before it carries traffic.

## Configuration and status

- `--port-mapping=auto` (default) maps when the data plane runs;
  `--port-mapping=off` never contacts the gateway.
- `meshctl status` shows `Port mapping:` with the state (`off`, `idle`,
  `searching`, `mapped`, `double_nat`, `unavailable`, `failed`), the protocol and
  the expiry. `/v1/status` never includes the external address.
- `meshctl netcheck` also prints the mapped external endpoint.
- Logs carry the protocol, state changes and short error codes only, never
  gateway or external addresses.

## Security

Port mapping opens one inbound UDP port on the gateway to the WireGuard
socket. Everything arriving there is either a WireGuard packet, which fails
authentication unless it comes from a configured peer, or a disco or STUN
datagram, which is authenticated or bound to a transaction meshd started. No
other service is exposed. Turning port mapping off restores the previous
behaviour exactly.

## Tests

- Gateway fakes for each protocol: malformed, foreign and stray replies,
  refusals, version fallback (PCP to NAT-PMP), epoch resets, UPnP conflicts
  (718), permanent-only leases (725), and descriptions or URLs that point away
  from the gateway. Fuzz targets cover every parser.
- The NAT lab supports explicit mappings (`NAT.AddPortMapping`). The real
  mapper obtains a PCP mapping through a symmetric NAT and an Internet host
  reaches it; the mapping is gone after the mapper stops.
- meshd's disco runtime in the lab: symmetric/symmetric,
  symmetric/carrier-grade symmetric and port-restricted/symmetric pairs stay
  relayed without a mapping and go direct when one side's router maps its port.

IPv6 firewall pinholes (PCP with IPv6) are not requested yet.
