# Paths and relays

Two nodes start through a relay and switch to a direct UDP path when they can
prove one works. This document describes how a node finds
its own addresses, how two nodes find a direct path, when they stay relayed,
and how relays are chosen. The wire protocols are
[disco v2](../protocol/disco-v2.md) and [MTRP v1](../protocol/mtrp-v1.md); the
components are in [Client](../architecture/client.md) and
[Relay](../architecture/relay.md).

## A node's own addresses

A node gathers **candidates**, addresses where peers might reach its WireGuard
socket:

| Source | Reported as | When |
|---|---|---|
| Local interfaces (at most 4 IPv6) | `HOST` | Always |
| STUN answers from the relays, on the WireGuard socket | `SERVER_REFLEXIVE` | Always |
| A port mapping on the router (PCP, NAT-PMP or UPnP IGD) | `PORT_MAPPED` | `--port-mapping=auto` (default) |
| The instance's public addresses from cloud metadata | `STATIC` | `--cloud-metadata=auto` (default), on Linux |
| Addresses given with `--advertise-endpoint` | `STATIC` | When set |

A candidate must be a global unicast address with a port. A node keeps at most
16, preferring port mappings, then STUN, then configured, then local
addresses, IPv4 before IPv6. A STUN candidate survives a failed round for
5 minutes; the others follow the latest observation. On Linux, IPv6 local
candidates skip tentative, duplicate and deprecated addresses, use a privacy
address only when no stable one exists, and put ULA addresses last.

**Port mapping** is attempted only toward the IPv4 default gateway, and only
when both the node's address and the gateway's are private, shared
(`100.64.0.0/10`) or link-local.

- A mapping lives 2 hours and is renewed at half its life (a permanent UPnP
  lease is refreshed hourly). The node checks a held mapping every 2 minutes
  and withdraws it after 3 failed renewals. When no protocol answers it tries
  again after 5 minutes; after a refusal, after 30 seconds doubling to
  5 minutes.
- An external address that is itself private or shared (a second NAT) is never
  offered.
- The external address is offered only if the node observed it itself
  (through STUN or its NAT check). NAT-PMP and UPnP answers are not
  authenticated, so this keeps another LAN host that pretends to be the
  gateway from choosing an address peers will probe.
- No IPv6 pinholes are requested. `meshctl status` shows the mapping's state,
  never its external address.

**Cloud metadata** is read on AWS (IMDSv2), Google Cloud, Azure and
DigitalOcean, which the node recognises from its DMI data (Linux only). It
asks `169.254.169.254` at start, hourly and after network changes (at most
once a minute), with a 2-second timeout, retrying after 1 minute doubling to
10; it uses at most 8 addresses. These addresses are taken as given, not
checked with STUN.

**NAT check.** The node also classifies its NAT (mapping and filtering
behaviour) from STUN answers of several relays, every 5 minutes and after
network changes; see [NAT classification](../protocol/nat-classification.md).
`meshctl netcheck` shows the result, the Console shows it with the Device's
paths ("No NAT", "Easy NAT", "Hard NAT").

The node gathers candidates every 20 to 26 seconds while it has peers, and
after a network change or a relay failure (such rounds at most every 5
seconds). It reports them to Core in an `EndpointReport` when they change, and
again every 5 minutes.

## What peers learn

Core filters each report before passing it on. It drops:

- addresses no peer may be told to probe
  ([endpoint policy](../../shared/endpointpolicy/endpoint.go)): `0.0.0.0/8`,
  `100.64.0.0/10`, `240.0.0.0/4`, the IPv4-compatible and IPv4-mapped IPv6
  ranges, `100::/64`, Teredo and 6to4, and NAT64 addresses whose embedded IPv4
  is not public;
- the reporting Device's own overlay addresses and the address of every relay
  listed by IP (a relay listed only by hostname is not matched);
- the ranges the operator denies with
  `MESHTRANSIT_CONTROL_MTCP_DENIED_ENDPOINT_CIDRS`, for example Core's own load
  balancers.

Private and IPv6 ULA addresses are kept, so two nodes on the same LAN find each
other. A peer learns of a change at most once every 5 seconds by default
(`MESHTRANSIT_CONTROL_MAP_ENDPOINT_ANNOUNCE_INTERVAL`). Nodes apply the same
policy to the endpoints they receive, and drop overlay and relay addresses
too.

## Finding a direct path

1. **Relay first.** A peer with a home relay starts on the relay: WireGuard
   traffic flows through it at once.
2. **Probe.** About every 3 seconds, the node sends authenticated disco pings
   to up to 8 candidates of each online peer (at most 512 pings a round, so
   large maps take several rounds). A peer without a working path also gets a
   `CALL_ME_MAYBE` through the relay (every 5 seconds in its first minute,
   then every 15), asking it to ping back; both sides pinging at the same
   moment opens both NATs. A ping received from a peer without a proven path
   is answered at once with probes of its own (from an address already known,
   at most every 6.5 seconds per peer), and a new source address becomes a
   candidate too (peer-reflexive).
3. **Select.** A candidate that answers becomes the peer's WireGuard endpoint.
   Another replaces it only if it is faster by at least 10% and 2 ms; among
   equally fast ones, a private address wins over a public one, IPv6 over IPv4.
4. **Fall back.** A path is trusted for 6.5 seconds after each answer. Without
   fresh answers the peer goes back to the relay.

Pings to candidates that never answered are limited per peer: each such
candidate backs off from 3 seconds to a minute, and all of them share a budget
of 24 pings plus 120 more while the peer has no working path, refilled one per
5 seconds. A Device that lists false endpoints can therefore make each of its
peers send at most 144 pings at once and about 0.4 a second after that to
them (disco v2 §4.4).

**When a direct path is impossible**, traffic stays on the relay: UDP blocked
on either side, or a NAT that changes the port for every destination
(symmetric) facing another symmetric or port-restricted NAT, unless one side
has a port mapping. There is no port prediction yet.

A node reports, every minute, how much traffic each peer used and whether it
went direct or through which relay, with the reason when relayed (relayed for
less than 30 seconds, no candidates, no answer). The Console shows it as, for
example, "2 direct · 1 via ams".

## Relays

The **relay map** lists the relay regions, each with its nodes; Core signs it
and sends it in every map. The shared map is set by the operator. A node:

- keeps a session with its **home relay** region, where its peers reach it;
- sends to a peer through the **peer's** home region, keeping up to 16
  regions open;
- picks its home: a region its Network prefers (Private Interchange) if one is
  usable; otherwise the home Core last recorded for it, if usable; otherwise
  the lowest usable region. It then moves only to a region at least 10 ms and
  20% faster by STUN latency. It leaves at once if the home's session fails,
  and after two missed latency rounds if the home just stops answering;
- tries a region's nodes in order and uses the first that answers. Relay nodes
  of one region do not forward to each other, so in practice a region has one
  node.

A node reaches a relay over UDP, TLS 1.3 or WebSocket on the relay's TLS
port: it starts with UDP and races TLS after 300 ms, so it still connects
where UDP is blocked. A relay session that falls silent is declared
dead after three missed keepalive probes, a few seconds; the node then uses
another region.

Relays cap traffic per Network (500 Mbit/s per relay node by default) and per
session (1 Gbit/s); see [Relay](../architecture/relay.md#limits).

### Private Interchange

A Workspace can run its own relays and offer them to some of its Networks
(`interchange.manage`, up to 16 per Workspace and 256 Networks each):

- `GET /api/v1/workspaces/{workspace}/interchanges`,
  `POST …/interchanges/actions/create`,
  `POST …/interchanges/{id}/actions/update`, `…/delete`.
- Core gives each one a region ID and adds it to the granted Networks' relay
  maps as a preferred region; those nodes use it as home whenever it works.
- The Workspace's operator runs `meshrelay --private-interchange` on the
  relay host and registers its relay key, address and ports in Core; the
  Console shows the start command. The relay serves only the granted
  Networks.

## Not yet

- Port prediction for hard NATs; IPv6 pinholes through PCP.
- HTTP/3 (MASQUE) for networks that allow only 443 over QUIC.
- Several cooperating nodes in one relay region.
- Cloud metadata on Windows and macOS; port mapping and cloud metadata on
  Android and iOS.
- Using a peer's NAT type to choose how to traverse it.
