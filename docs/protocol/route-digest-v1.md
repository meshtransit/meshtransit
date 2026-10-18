# Route digest v1

Draft 1. Implementation: `shared/routedigest`.

The route digest is one SHA-256 value over the subnets a router forwards
into. Core computes it over the `served` routes it sends a router
(mtcp-v1 §7.6); the router computes it over the routes it actually serves
and reports it in `EnforcementReport` (mtcp-v1 §8.4). Equal digests mean the
router forwards into exactly the Sites and prefixes Core intended, with the
intended source translation. Unequal digests after a grace period mean the
router serves something else: an older set, a prefix its local configuration
does not offer, or a set it could not install.

Routes a node uses as a consumer are not covered. Using them is a local
choice of the node, and the router enforces who reaches the Site through its
packet filter, which the [policy digest](policy-digest-v1.md) covers.

## 1. Model

A served route set is a list of entries. Each entry has:

- `site_ref`: the Site reference from `ServedSite`, 1–64 bytes of UTF-8;
- `prefix`: one canonical prefix of that Site (host bits cleared, not the
  default route, IPv4 never written as IPv4-mapped IPv6);
- `masquerade`: whether the router translates mesh sources to its own
  address on the way into the Site.

A `ServedSite` with several prefixes is several entries. The router digests
the routes it actually forwards into: the intersection of `served` with the
prefixes its local configuration offers (mtcp-v1 §7.6). The digest covers
the set of entries: their order and duplicates do not change it; the same
Site and prefix with both masquerade values is invalid.

## 2. Canonical entry

```
entry  = u16(len(site_ref)) || site_ref
         || family || address || u8(bits)
         || u8(masquerade)                       ; 1 or 0
family = u8(4) followed by bytes[4], or u8(6) followed by bytes[16]
```

Integers are big-endian. An implementation MUST refuse an entry that breaks
section 1 and a list of more than 4,096 entries (mtcp-v1 §14 bounds a
router's served prefixes to that), instead of hashing it partially.

## 3. Digest

```
entries = sort bytewise, then remove duplicates
digest  = SHA-256( "meshtransit route digest v1" || 0x00
                   || u64(count(entries))
                   || for each entry: u32(len(entry)) || entry )
```

The text form is `sha256:` followed by 64 lowercase hex digits, as for the
policy digest. In `EnforcementReport` the digest is always the 32 raw bytes,
also for the empty set, and `route_entries` is `count(entries)`.

## 4. Test vectors

`shared/routedigest` `TestComputeMatchesTheVector`:

| `site_ref` | Prefix | Masquerade |
|---|---|---|
| `site-hq` | `10.20.0.0/16` | yes |
| `site-hq` | `fd10:20::/48` | yes |
| `site-lab` | `192.168.50.0/24` | no |
| `site-hq` | `10.20.0.0/16` | yes (duplicate) |

It covers 3 entries and its digest is

```
sha256:3b577c0036777a664548ccd90580209560832faa9b06fc08d70adb047db0adbb
```

The empty set has the digest

```
sha256:76486304a2b5099aec5f5731de6baaa2dc2231046e5ea3b5c9ba964994f5e6e1
```

Both were cross-checked with an independent Python implementation of
sections 2–3.

## 5. Security considerations

- Like the policy digest, it is evidence the router gives about itself, not
  remote attestation: a router whose operating system is compromised can
  report the expected value while forwarding elsewhere.
- It reveals nothing beyond what the router already holds.
- It says what the router installed, not that the Site answers: Site health
  is reported separately.
