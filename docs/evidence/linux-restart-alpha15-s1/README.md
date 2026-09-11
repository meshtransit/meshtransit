# Linux restart matrix alpha15 — sample 1

These reports cover controlled restart of both MeshTransit services on each
node in the current two-node Linux alpha topology.

- Runtime: `0.1.0~alpha15`
- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256: `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Scenarios: 4
- Result: 4 pass, 0 fail
- Readiness deadline: 15 seconds
- Slowest observed full readiness: 5,079 ms

The report schema omits peer addresses, DNS answers, network identifiers,
control fingerprints, and raw traffic output. `SHA256SUMS` records the exact
report bytes committed here.

This is one bounded sample per node and service. It proves the four scenarios
under this topology but does not establish p95 recovery or long-duration
reliability.
