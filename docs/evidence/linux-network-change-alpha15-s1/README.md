# Linux network-change matrix alpha15 — sample 1

These reports cover one controlled interface-address change on each node in
the current two-node Linux alpha topology while the peer remained online.

- Runtime: `0.1.0~alpha15`
- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256: `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Scenarios: 2
- Result: 2 pass, 0 fail
- Recovery deadline: 20 seconds
- Slowest observed endpoint refresh: 881 ms
- Slowest observed stable dual-stack traffic: 117 ms

The controlled action used only the dedicated `meshqchg0` dummy interface.
Independent post-run checks confirmed its removal, preservation of each
default route, synchronized direct-path operation, exact MagicDNS answers,
dual-stack traffic, and no warning-level service log entries.

The report schema omits SSH destinations, overlay addresses, DNS names and
answers, network identifiers, control fingerprints, and raw traffic output.
`SHA256SUMS` records the exact report bytes committed here.

This is one bounded sample per node. It verifies proactive endpoint refresh
and no-regression behavior in this topology but does not establish p95
recovery or real migration between multiple uplinks.
