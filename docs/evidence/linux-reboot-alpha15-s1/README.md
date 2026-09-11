# Linux reboot matrix alpha15 — sample 1

These reports cover one controlled reboot of each node in the current two-node
Linux alpha topology while the other node remained online as the observer.

- Runtime: `0.1.0~alpha15`
- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256: `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Scenarios: 2
- Result: 2 pass, 0 fail
- Recovery deadline: 60 seconds
- Slowest observed outbound dual-stack readiness: 50,014 ms

The report schema omits SSH destinations, overlay addresses, DNS answers, boot
IDs, profile IDs, control fingerprints, and raw traffic output. `SHA256SUMS`
records the exact report bytes committed here.

This is one bounded reboot sample per node. It verifies the two scenarios under
this topology but does not establish p95 recovery or long-duration reliability.
