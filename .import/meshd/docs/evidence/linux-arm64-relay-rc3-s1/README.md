# Linux ARM64 relay fallback rc3 — sample 1

These reports record bounded direct-path loss from each side of the registered
Ubuntu 24.04 ARM64 and Ubuntu 26.04 AMD64 topology.

- Runtime: `0.1.0~rc3+69e5e2f`
- Runtime commit: `69e5e2f00f0fead79e5baf4848725ee3aa6590b6`
- Result: both directional scenarios passed
- Relay traffic: IPv4 and IPv6 passed from both initiating nodes
- Restoration: the qualification nftables table was removed and direct paths
  recovered without a service restart

The harness dropped only UDP to one explicitly validated peer-underlay address
at a time. It did not change SSH, control or relay destinations, default routes,
MeshTransit interfaces, DNS, profiles, packages, or policy.

The reports omit SSH destinations, peer underlay addresses, overlay addresses,
DNS names and answers, endpoint candidates, profile identifiers, account
identifiers, control fingerprints, packet payloads, and process identifiers.
