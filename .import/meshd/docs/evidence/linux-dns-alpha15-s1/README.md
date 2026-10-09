# Linux DNS lifecycle matrix alpha15 — sample 1

These reports cover one graceful `meshd.service` stop/start DNS lifecycle on
each node in the current two-node Linux alpha topology while the peer remained
online.

- Runtime: `0.1.0~alpha15`
- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256: `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Scenarios: 2
- Result: 2 pass, 0 fail
- Slowest dedicated-link and listener cleanup: 94 ms
- Slowest complete DNS recovery: 4,789 ms

Each run proved authoritative A, AAAA, IPv4/IPv6 PTR, NODATA, and NXDOMAIN
behavior, direct UDP and TCP service, short-name search, FQDN host resolution,
split-only routing, and continued non-mesh DNS while `meshd` was stopped.

Independent post-run checks confirmed both services active, the dedicated DNS
link and listeners restored, no default-DNS takeover, external resolution on
the non-mesh resolver path, direct dual-stack peer traffic, and no
warning-level service log entries.

The report schema omits DNS names and answers, peer and resolver addresses,
network identifiers, control fingerprints, raw daemon status, and raw query
output. `SHA256SUMS` records the exact report bytes committed here.

This is one bounded sample per node. It does not establish p95 recovery or
revalidate control-configured upstream split/default forwarding on alpha15.
