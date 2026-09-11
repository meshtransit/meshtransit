# Linux relay-fallback matrix alpha15 — sample 1

These reports cover one bounded direct-path impairment on each node in the
current two-node Linux alpha topology while the peer remained online.

- Runtime: `0.1.0~alpha15`
- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256: `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Scenarios: 2
- Result: 2 pass, 0 fail
- Slowest observed relay fallback: 5,809 ms
- Slowest observed direct-path restoration: 2,771 ms

Each run blocked UDP only to all three IPv4 underlay candidates advertised by
the peer. Packet counters proved that the fault was exercised. Both overlay
address families carried traffic over relay before the dedicated nftables
table was removed and the authenticated direct path returned.

Independent post-run checks confirmed table removal, preservation of each
default route, synchronized direct-path operation, exact MagicDNS answers,
dual-stack traffic, and no warning-level service log entries.

The report schema stores candidate counts rather than addresses and omits SSH
destinations, overlay addresses, DNS names and answers, network identifiers,
control fingerprints, and raw traffic output. `SHA256SUMS` records the exact
report bytes committed here.

This is one bounded sample per node. It does not establish p95 recovery,
IPv6-only underlay behavior, multiple-peer behavior, or relay-region failure.
