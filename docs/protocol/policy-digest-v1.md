# Policy digest v1

Draft 1, 2026-10-09. Implementation: `shared/policydigest`.

The policy digest is one SHA-256 value over the packet filter a node
enforces. Core computes it over the filter it sends a node; the node computes
it over the rules actually installed in its packet filter and reports it
(enforcement evidence). Equal digests mean the node enforces exactly the
grants Core intended for it. Unequal digests after a grace period mean the
node runs something else: an older filter, a filter it refused, or a
deliberate or accidental change.

The digest is **semantic**. It covers the set of single grants a filter
allows, not how the filter is written. How rules are grouped, split (for
example a source list cut at 1,024 entries), ordered or duplicated does not
change it.

## 1. Model

A filter is a list of allow rules. Each rule has:

- `sources`: selectors;
- `destinations`: selectors, each with an inclusive port range
  `port_from..port_to` (`port_from <= port_to`);
- `protocols`: IP protocol numbers (0–255). An empty list means "TCP, UDP and
  ICMP" and is kept distinct from any explicit list.

A selector is one of:

| Kind | Code | Meaning |
|---|---|---|
| any | 1 | every address |
| prefix | 2 | an IPv4 or IPv6 prefix |
| range | 3 | an inclusive address range of one family |
| capability | 4 | a named capability (sources only) |

A rule without destinations grants nothing and is ignored.

## 2. Canonical selectors

Addresses are unmapped first (`::ffff:a.b.c.d` becomes `a.b.c.d`).

```
any        = u8(1)
prefix     = u8(2) || family || address || u8(bits)      ; host bits cleared
range      = u8(3) || family || start || end              ; start <= end, same family
capability = u8(4) || u16(len) || name                    ; 1 <= len <= 1024 bytes
family     = u8(4) followed by bytes[4], or u8(6) followed by bytes[16]
```

A single address is a prefix of full length (/32 or /128). A range is never
rewritten into prefixes; both sides read the same wire form.

## 3. Grants

Each rule expands into one grant per (protocol token, source, destination):

```
token = u16(protocol)      for each listed protocol (duplicates removed)
      = u16(0x0100)        when the protocol list is empty
grant = token || source || destination_selector || u16(port_from) || u16(port_to)
```

An implementation MUST refuse a filter that expands into more than
1,048,576 grants (2^20) instead of hashing it partially.

## 4. Digest

```
grants  = sort bytewise, then remove duplicates
digest  = SHA-256( "meshtransit policy digest v1" || 0x00
                   || u64(count(grants))
                   || for each grant: u32(len(grant)) || grant )
```

The text form is `sha256:` followed by 64 lowercase hex digits. Parsers accept
only that exact form. The empty filter has a well-defined digest; no filter
produces the all-zero value.

## 5. Test vector

`shared/policydigest/testdata/packet-filter-v1.json` holds this filter in the
TS2021 `PacketFilter` wire form, which both Core and meshd parse in their
tests:

| Rule | Sources | Destinations | Protocols |
|---|---|---|---|
| 1 | `100.64.0.2`, `fd7a:115c:a1e0::2` | `100.64.0.1` port 22, `fd7a:115c:a1e0::1` port 22 | 6 |
| 2 | `100.64.0.3` | `100.64.0.1` ports 0–65535 | 1 |

It expands into 5 grants and its digest is

```
sha256:65c3166a6062804e3b2a55acd157d70ce0ebf6fdd91130eecd280654a714251a
```

The vector was cross-checked with an independent Python implementation of
sections 2–4.

## 6. Security considerations

- The digest is evidence the node gives about itself, sent inside its
  authenticated control session. It detects stale, refused or altered filters
  on an honest node. A node whose operating system is compromised can report
  the digest Core expects while enforcing something else; the digest is not
  remote attestation.
- The digest reveals nothing beyond what the node already holds: anyone able
  to compute it already knows the filter.
- Version 1 covers the packet filter only. Device alias grants and future
  capability grants are outside it until a later version includes them.
