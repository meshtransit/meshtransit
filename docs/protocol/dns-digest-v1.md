# DNS digest v1

Draft 1. Implementation: `shared/dnsdigest`.

The DNS digest is one SHA-256 value over the DNS routes and search domains of
a node. Core computes it over the `DnsConfig` it sends a node (mtcp-v1 §7.3);
a node that declared `dns.root1` computes it over the configuration it
applied to its host and reports it in `EnforcementReport` (mtcp-v1 §8.4).
Equal digests mean the node applies exactly the zones, resolvers, failure
modes and search domains Core intended. Records (names and addresses) are
not covered: they change often and do not decide where a name goes.

## 1. Model

A configuration is a list of routes and a list of search domains. A route
has:

- `suffix`: `.` (every name no other route holds) or a domain in lower case,
  without a trailing dot, of labels of 1–63 letters, digits, hyphens or
  underscores, at most 253 bytes;
- `resolvers`: 0–4 resolvers in the order the node asks them, each an IPv4
  or IPv6 address (IPv4-mapped IPv6 is the IPv4 address) and a port, 0
  meaning 53;
- `unavailable` and `fail_open` as in `DnsRoute`; an unavailable route has
  no resolver.

Suffixes are unique. Search domains are domains as above, never `.`, in the
order sent. The node digests the routes it kept after validating the map,
before it turns them into host configuration: a route it dropped shows as a
different digest.

## 2. Canonical route

```
route    = u16(len(suffix)) || suffix || u8(flags) || u8(count(resolvers))
           || for each resolver, in order: family || address || u16(port)
flags    = 1 if unavailable, + 2 if fail_open
family   = u8(4) followed by bytes[4], or u8(6) followed by bytes[16]
port     = the port, 53 for 0
```

Integers are big-endian. An implementation MUST refuse a configuration that
breaks section 1, more than 1,024 routes, or more than 16 search domains,
instead of hashing it partially.

## 3. Digest

```
routes = sort bytewise
digest = SHA-256( "meshtransit dns digest v1" || 0x00
                  || u64(count(routes))
                  || for each route: u32(len(route)) || route
                  || u64(count(search_domains))
                  || for each search domain, in order: u16(len(domain)) || domain )
```

The text form is `sha256:` followed by 64 lowercase hex digits, as for the
policy digest. In `EnforcementReport` the digest is the 32 raw bytes, also
for the empty configuration, and `dns_routes` is `count(routes)`.

## 4. Test vector

Routes:

| suffix | resolvers | unavailable | fail_open |
|---|---|---|---|
| `073438549244.296056403058.mesh.internal` | none | no | no |
| `corp.internal` | `100.64.0.21` port 5335, `192.0.2.53` port 0 | no | yes |
| `.` | none | yes | no |

Search domains: `073438549244.296056403058.mesh.internal`, `corp.internal`.

Digest:
`sha256:e0ade8e76caf31f2f615616fa198aeb45a96511e0161cb2d055923f995c63504`
