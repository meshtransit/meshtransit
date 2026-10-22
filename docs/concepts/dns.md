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
every map and derives the reverse records itself. Core does not yet send
upstream resolvers, and there is no API to configure DNS for a Network.

## How the resolver answers

| Query | Answer |
|---|---|
| A known name, type A, AAAA or ANY | Authoritative answer with its addresses |
| A known name, any other type or a missing family | `NODATA` with an SOA |
| An unknown name under a name the resolver owns | `NXDOMAIN` with an SOA |
| Any other name | Not asked: the host sends it to its own resolvers |

- Answers live 5 seconds, negative answers 10 seconds.
- A query must have exactly one question of class IN and at most one
  additional record, an EDNS0 OPT; anything else gets `FORMERR`, another EDNS
  version `BADVERS`. EDNS0 is answered with a 4096-byte buffer.
- At most 256 UDP queries and 64 TCP connections at once; a query is at most
  4096 bytes. Query names are never logged.
- The resolver can also forward a domain to upstream resolvers, trying them
  in order (1.5 s each, 5 s in all), with a random transaction ID, accepting
  only an answer to the same question, and retrying a truncated UDP answer
  over TCP. Core does not configure forwarding yet. Encrypted upstreams (DoH,
  DoT) are not supported: a resolver given as a URL is ignored.
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

- Custom records. Resolvers and routes configured in Core: DNS zones (a
  domain and up to four resolvers, a Device of the Network or an address on
  the Internet, sent to all Devices or to Device Groups) can be created and
  changed through the management API with `dns.manage` when the deployment
  sets `MESHTRANSIT_DNS_ZONES_ENABLED`, but maps do not carry them yet.
- The search domain on Windows: the NRPT routes the zone to the resolver, but
  short names are not completed.
- Reverse lookups through the host's resolver: the node's resolver answers
  PTR queries sent to it, but reverse zones are not routed to it.
- Encrypted upstream resolvers.
- "DNS for all names" on macOS and Windows.
- DNS on Android and iOS.
