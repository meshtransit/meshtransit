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
goes to every Device or to Device Groups. A node on Linux, macOS, Windows or
Android with DNS on applies zones (MTCP `dns.forward1`); iOS does not yet.

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

## Names and zone kinds

A zone may also hold names an admin sets: a name to a Device (its mesh
addresses), to fixed addresses, to a share the Network imports (its alias,
so a provider's web app opens under its real name), or a CNAME. A zone also
says what the names it does not hold get:
- `forward`: the zone's resolvers, as above;
- `nxdomain`: `NXDOMAIN`, answered by the node;
- `host`: the host's own DNS.

A node on Linux, macOS or Windows with DNS on applies them (MTCP
`dns.records1`).

- **Who sees a name.** Core sends a name to a Device only while a rule of
  the active policy lets that Device reach the target Device. A rule the
  other way is not enough, and a Device always sees its own names. Changes
  of zones and names reach Devices together, at most 30 seconds after the
  first.
- **Names of a share.** A name that points at a share answers the share's
  alias, and only on a consumer Device whose map holds the share: a rule
  reaches it, the contract runs, and the peer limit kept it. Anywhere else
  the name, and any CNAME whose chain reaches it, is left out. Revoking the
  share or changing the rule takes the name away at once, without the
  30-second window. The provider's Devices never get the consumer's names.
- **Service names.** A provider can suggest up to 8 names on a share offer,
  and change them while the share runs; the consumer approves each one when
  it accepts, or uses one later from the share's page. Using a name makes it
  a name of the consumer Network that points at the share. A changed
  suggestion never removes a name the consumer already uses, and the
  provider never sees which names the consumer uses.
- **Routing.** The host routes an `nxdomain` or `forward` zone's domain to
  the node, a single label (`lan`) included but never the root or a suffix
  of the Internet (`com`, `co.uk`). A `host` zone is not routed as a whole:
  each of its names is routed to the node, and the host's own DNS, per link,
  answers the rest. A `forward` zone that fails open with no resolver it can
  use is left to the host the same way. A `host` zone whose only name is its
  own domain (the zone a service name gets) is not sent to a Device that
  receives another zone holding it: the name is answered in that zone.
- **Types the node answers.** For a name it holds, the node answers A, AAAA,
  ANY and CNAME itself. HTTPS and SVCB get no data, so a browser takes no
  hint past the name. Any other type (MX, TXT…) of a name in a `host` or
  `forward` zone goes on to the zone's resolvers or the host's DNS; in an
  `nxdomain` zone it gets no data. A name that only holds other names gets
  no data, not `NXDOMAIN`.
- **CNAMEs.** The node follows a CNAME, at most 8 steps, and answers the
  whole chain. A chain that leaves the node's names is asked of the
  resolvers that name would go to:
  - a zone's resolvers;
  - the exit node's forwarder while one is in use;
  - the Network's resolvers;
  - otherwise the host's network resolvers.

  The chase uses one 5-second budget.
- **No answer from outside speaks for a name the node holds.** From every
  answer it forwards, the node keeps only the chain the question asked for.
  - It drops records and CNAMEs that would answer for names it holds, and
    answers those names itself.
  - It turns `NXDOMAIN` for a name it holds into no data.
  - It drops authority and additional records and the authenticated flag,
    and keeps every TTL at 5 seconds at most.
- On Linux the node turns DNSSEC validation off on its link: the names it
  answers, of domains on the Internet too, are unsigned. While the node uses
  an exit node or the Network's resolvers, its link is the host's default
  route, so systemd-resolved then validates no name at all.
- A zone that leaves its other names to the host keeps a route of its own,
  unavailable and failing open, when it is a search domain, lies under
  another route, or holds more names than the host can route one by one
  (200 domains in all): the node then answers its names and asks the host's
  network resolvers for the rest. A name set at the zone's own domain (`@`)
  routes the whole zone through the node.

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
| Android | `192.0.2.53:53`, inside the app: questions to it are taken out of the VPN interface's packets | The VPN interface's only DNS server, with a route to it and the search domains. Android has no split DNS, so every name comes to it: the mesh's are answered as above, any other is asked of the DNS servers of the phone's networks, each over its own network |
| iOS | not yet | — |

On Android the interface takes this DNS only once the app has reported its
networks' DNS servers, and loses it when the map has no DNS or the person
turns "Use MeshTransit DNS" off. While the Internet goes through an exit
node it always has it, and no name leaves outside the mesh: the Internet's
names go to the exit node, or are answered `SERVFAIL` until its resolvers
are known. A zone's resolver at a private address is asked only when the
phone routes to it through a Site or is on its network. Answers over UDP
stay within the interface MTU (1,252 bytes, then truncated); DNS over TCP to
the resolver is reset, as is Android's Private DNS probe on port 853. With
Private DNS set to a hostname ("strict"), Android sends no name to the
resolver, and the mesh names do not resolve.

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

Core keeps each map within 248 domains and 15.5 KiB of them, counted the
way the node routes them, which leaves room for the routes the node adds
itself. The node routes a `host` zone whole when another route or a search
domain covers it, or when its names would pass 200 routed domains;
otherwise each of its names gets a route. Core keeps, in order: the mesh
suffix and the Network's zone, the zones routed as a whole by domain, the
other search domains, then the names that need a route of their own by
name, and last the `host` zones. A zone past the budget is left out with its
search domain and names, a name past it whole;
`meshtransit_mtcp_map_names_degraded_total{reason="route_budget"}` counts
them.

The suffix is routed to the resolver as one domain, so neither the number of
Devices nor the number of shares counts against the host's limit. The
resolver owns that zone: a name under the suffix that is not a Device or
share of the map gets `NXDOMAIN` and never reaches the host's own resolvers.
A Core that predates the suffix names shares under `shared.mesh`; the node
then routes `shared.mesh` as one domain the same way (unless Core configures
that route itself).

## Not yet

- Names and zone kinds on iOS. A zone for every other name (the root).
- Internet resolvers of a zone asked through the exit node itself (today the
  exit node's DNS forwarder answers instead).
- The search domain on Windows: the NRPT routes the zone to the resolver, but
  short names are not completed.
- Reverse lookups through the host's resolver: the node's resolver answers
  PTR queries sent to it, but reverse zones are not routed to it.
- Encrypted upstream resolvers.
- "DNS for all names" on macOS and Windows.
- DNS on iOS.
- DNS over TCP and encrypted upstreams on Android.
