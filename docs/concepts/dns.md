# MeshTransit DNS

`meshd` runs a small DNS resolver that answers the names of the mesh and
leaves every other name to the host's own resolvers (split DNS). This
document describes what it answers today, how it is wired into each
platform, and what is not done yet.

## What resolves today

Every Device has a DNS name in its Network:

```
<label>.<Workspace code>.<Network code>.<suffix>
```

- The **label** is derived from the hostname by Core: its first label,
  lowercased, each run of other characters replaced by one hyphen (so a label
  never starts with an IDNA `xn--` prefix), at most 63 bytes. Nothing left
  gives `device`; an all-digit label, or a name hosts look up on their own
  (`wpad`, `isatap`, `localhost`, `gateway`, `dns`, `www`, `mail`, `proxy`,
  ...), is prefixed with `device-`, so no Device can answer it through the
  search domain. It is
  unique among the live Devices of the Network: a Device whose hostname gives
  a label another Device holds gets the first free numbered variant
  (`laptop-1`, `laptop-2`, ...). A revoked Device releases its label at once.
  Renaming a Device to a hostname whose label another Device holds is refused,
  as a taken hostname is. See [devices](devices.md#addresses-and-names).
- The **Workspace and Network codes** are their twelve-digit display codes.
- The **suffix** is deployment configuration, `MESHTRANSIT_DNS_SUFFIX`, by
  default `mesh.internal` ([configuration](../operations/configuration.md)).
  It has at least two labels and is never a special-use zone (`local`,
  `localhost`, `arpa`, `invalid`, `test`, `onion`, `example` and names under
  them): the node answers every name under it. A node also ignores a
  locally answered route for the root or a single label from Core.

Names never stop a map: a Device without a label is listed without a name,
and a record whose name another record took, or past the record limit, is
left out (the control role counts both in
`meshtransit_mtcp_map_names_degraded_total`).

A node resolves its own name and the names of the peers its map lists, which
are the Devices of its Network that policy pairs it with. Its resolver also
answers reverse (PTR) queries for those addresses, and short names resolve: the
Network's zone `<Workspace code>.<Network code>.<suffix>` is its search
domain (on Windows, see [Not yet](#not-yet)).

Shared Devices resolve on the consumer side only, by their share name:

```
<label>.<provider Workspace code>.<provider Network code>.shared.<suffix>
```

The name points to the shared Device's Resource Alias (IPv4 and/or IPv6), as
described in [sharing](sharing.md#accepting); on a deployment without Device
aliases, to the provider Device's own overlay address. The label is chosen by
the provider in the offer and frozen there; Core builds the name from it when
the consumer accepts. (Offers created before labels existed carry a name the
consumer typed instead; such a name is published as typed.) A Device of
another Network is never known by its hostname or its own name: a provider's
map shows a consumer Device only under a placeholder that does not resolve.

Core sends the names in each map (MTCP §7.3): an address record per name and
address, the suffix as a route the node answers itself, and the Network's
zone as search domain. The node replaces its whole DNS configuration with
every map and derives the reverse records itself. With DNS zones, Core also
sends forward zones (below).

## Forward zones

A Network admin can send a domain to chosen resolvers: a DNS zone, created
through the management API with `dns.manage` when the deployment sets
`MESHTRANSIT_DNS_ZONES_ENABLED`. Its resolvers are, in order, Devices of the
Network (port 53 or 1024-65535) or addresses on the Internet (port 53); it
goes to every Device or to Device Groups. A node on Linux, macOS or Windows
with DNS on applies zones (MTCP `dns.forward1`); Android and iOS do not yet.

- The host routes the zone's domain to the node's resolver, which asks the
  zone's resolvers in order (1.5 s each). A resolver Device is listed only
  while the active policy has a rule from this Device to it over UDP on its
  port; add TCP too for large answers.
- A zone none of whose resolvers can be used now still has its route, so
  its names never fall to the host's DNS by accident; a single-label domain
  (`corp`) is routed too.
- **Failure mode.** When no resolver answers, or none can be used, a zone
  that fails `closed` answers `SERVFAIL`; one that fails `open` asks the
  host's network resolvers from the node's own sockets (the exit node's
  DNS forwarder while one is in use), with its own 2 seconds after 3 seconds
  for the zone's resolvers.
- A resolver that fails 3 times in a row (no answer, a broken answer) is
  skipped for 30 seconds; then the next question tries it again. `SERVFAIL`
  and `REFUSED` are about the name and never count. A truncated answer from
  a resolver the node cannot reach over TCP is passed on truncated.
- A zone that fails `closed` never reaches the host's network, not even in a
  captive portal window.
- A resolver Device may listen on port 53 or 1024-65535; the node asks no
  other address on a port other than 53.
- While the node uses an exit node, Device resolvers keep their place and an
  Internet resolver is replaced by the exit node's DNS forwarder: no question
  leaves through the host's own network.
- Zones with a search position are search domains after the Network's zone,
  at most 8 in all.
- Zones apply only while the node is connected to Core: when the control
  session ends the node removes its DNS from the host, `closed` included.

## How the resolver answers

| Query | Answer |
|---|---|
| A known name, type A, AAAA or ANY | Authoritative answer with its addresses |
| A known name, any other type or a missing family | `NODATA` with an SOA |
| An unknown name under a name the resolver owns | `NXDOMAIN` with an SOA |
| A name under a forward zone | The zone's resolvers' answer, or its failure mode |
| Any other name | Not asked: the host sends it to its own resolvers |

- Answers live 5 seconds, negative answers 10 seconds.
- A query must have exactly one question of class IN and at most one
  additional record, an EDNS0 OPT; anything else gets `FORMERR`, another EDNS
  version `BADVERS`. EDNS0 is answered with a 4096-byte buffer.
- At most 256 UDP queries and 64 TCP connections at once; a query is at most
  4096 bytes. Query names are never logged.
- The resolver forwards a forward zone's names to its resolvers, trying them
  in order (1.5 s each, 5 s in all, 3 s when the zone fails open), with a
  random transaction ID, accepting only an answer to the same question, and
  retrying a truncated UDP answer over TCP. Encrypted upstreams (DoH, DoT)
  are not supported: a resolver given as a URL is ignored, and a zone left
  without resolvers is unavailable.
- A UDP answer larger than 512 bytes, or than the size the client announced
  with EDNS0, is truncated and marked so.

## Wiring into the host

The resolver listens on a fixed local address, and only the mesh names are
routed to it:

| Platform | Resolver at | Host integration |
|---|---|---|
| Linux | `192.0.2.53:1053` on the link `meshdns0`, created by `meshnetd` | `systemd-resolved`, per link: the mesh names as route domains, LLMNR and mDNS off |
| macOS | `192.0.2.53:1053`, an address on `lo0` | A supplemental resolver in `scutil` for the mesh names |
| Windows | `127.53.53.53:53`, in the service | One NRPT rule for the mesh names; the DNS cache is flushed |
| Android, iOS | not yet | — |

On Linux, DNS needs `systemd-resolved`: with `--enable-dns`, `meshnetd`
refuses to start unless `/usr/bin/resolvectl` is a root-owned file that only
root can change.

`meshd` applies DNS in one step: the resolver gets its new configuration
first, then the host; if the host step fails, the resolver is rolled back.
Turning DNS off, a profile change and shutdown undo both, host first. On
macOS and Windows, stale entries left by a crash are removed at the next
start.

`meshctl status` shows the DNS state: `inactive`, `configured`, `failed` or
`not_implemented`. A failure to apply DNS sets DNS to `failed` and turns the
mesh names off on the host, so no name keeps pointing at an address from an
earlier map; the control session and data plane stay up, and the next map
from Core tries again. Names then go to the host's own resolvers. Only if
turning DNS off fails as well does the node leave the mesh and reconnect.

The packages enable DNS (`--enable-dns`).

## Limits

| Limit | Value |
|---|---|
| Records in a map, one per address | 50,000 |
| Addresses per name | 32 |
| Domains routed to the resolver | 256, and 16 KiB of names, on Linux and macOS (the helper); 256 NRPT namespaces on Windows |

The suffix is routed to the resolver as one domain, so neither the number of
Devices nor the number of shares counts against the host's limit. The
resolver owns that zone: a name under the suffix that is not a Device or
share of the map gets `NXDOMAIN` and never reaches the host's own resolvers.
A Core that predates the suffix names shares under `shared.mesh`; the node
then routes `shared.mesh` as one domain the same way (unless Core configures
that route itself).

## Not yet

- Names set in zones on clients: Core stores them (an address name to a
  Device or fixed addresses, a CNAME, in zones whose other names are
  forwarded, answered `NXDOMAIN` or left to the host) and sends them to
  clients that declare `dns.records1`, but no client applies them yet. A
  zone for every other name (the root).
- Internet resolvers of a zone asked through the exit node itself (today the
  exit node's DNS forwarder answers instead).
- The search domain on Windows: the NRPT routes the zone to the resolver, but
  short names are not completed.
- Reverse lookups through the host's resolver: the node's resolver answers
  PTR queries sent to it, but reverse zones are not routed to it.
- Encrypted upstream resolvers.
- "DNS for all names" on macOS and Windows.
- DNS on Android and iOS.
