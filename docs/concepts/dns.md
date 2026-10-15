# MeshTransit DNS

`meshd` runs a small DNS resolver that answers the names of the mesh and
leaves every other name to the host's own resolvers (split DNS). This
document describes what it answers today, how it is wired into each
platform, and what is not done yet.

## What resolves today

Only the names of **shared Devices** resolve, on the consumer side:

```
<label>.<provider Workspace code>.<provider Network code>.shared.mesh
```

The name points to the shared Device's Resource Alias (IPv4 and/or IPv6), as
described in [sharing](sharing.md#accepting); on a deployment without Device
aliases, to the provider Device's own overlay address. The label is chosen by
the provider in the offer and frozen there; Core builds the name from it when
the consumer accepts. (Offers created before labels existed carry a name the
consumer typed instead.)

**Device names do not resolve yet.** A Device has a hostname, unique in its
Network ([devices](devices.md#addresses-and-names)), and its peers know it,
but Core does not publish it in DNS and `meshd` does not answer it; reach
Devices of your own Network by address. There is no reverse (PTR) lookup
either.

Core sends the names in each map (MTCP §7.3) and the node replaces its whole
DNS configuration with every map. Core does not yet send upstream resolvers,
search domains or routes, and there is no API to configure DNS for a Network.

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
| Records in a map, one per address | 32,768 (accepted by the node) |
| Addresses per name | 32 |
| Domains routed to the resolver | 256, and 16 KiB of names, on Linux and macOS (the helper); 256 NRPT namespaces on Windows |

All shared names are routed to the resolver by one route, `shared.mesh`, so
the number of shares does not count against the host's limit. (If Core ever
configures a route for `shared.mesh` itself, that route is kept and each
shared name is routed on its own again.) The resolver
owns that zone: a name under `shared.mesh` that is not a share the Device
imported gets `NXDOMAIN` and never reaches the host's own resolvers.

## Not yet

- Names and reverse lookups for Devices.
- A DNS domain per Network, custom records, and resolvers, routes and search
  domains configured in Core (`dns.manage` has no operation yet).
- Encrypted upstream resolvers.
- "DNS for all names" on macOS and Windows.
- DNS on Android and iOS.
