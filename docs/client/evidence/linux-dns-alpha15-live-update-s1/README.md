# Linux DNS live-update matrix alpha15 — sample 1

This aggregate report covers one sequential control-plane DNS transition across
the current two-node Linux alpha topology:

1. MeshTransit DNS-only baseline to one split route with one classic IPv4 resolver.
2. Split route to one explicit-default classic IPv4 resolver.
3. Explicit default back to the exact MeshTransit DNS-only baseline.

- Runtime: `0.1.0~alpha15`
- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256: `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Control updates: 3
- Nodes: 2
- Result: pass

Both clients applied every phase without a daemon restart. The split phase
routed only the selected suffix through `meshdns0`; the explicit-default phase
installed `+DefaultRoute` and `~.`; rollback removed both temporary routes and
disabled public forwarding through the mesh resolver. MeshTransit DNS, direct
dual-stack traffic, and control synchronization remained healthy.

The aggregate schema records outcomes and counts rather than DNS names,
resolver or peer addresses, process IDs, query answers, network identifiers,
control fingerprints, or raw status. `SHA256SUMS` records the exact report
bytes committed here.

This is one bounded operator-driven sample. It does not establish p95 update
latency or cover upstream failure, multiple resolvers, or encrypted DNS.
