# Linux ARM64 network-change rc3 — sample 1

These reports record a bounded interface-address change from each side of the
registered Ubuntu 24.04 ARM64 and Ubuntu 26.04 AMD64 topology.

- Runtime: `0.1.0~rc3+69e5e2f`
- Runtime commit: `69e5e2f00f0fead79e5baf4848725ee3aa6590b6`
- Result: both directional scenarios passed
- Traffic: 502 of 502 IPv4 and IPv6 probes succeeded
- Cleanup: the dedicated dummy interface was absent after both runs

Each harness run created one dedicated dummy interface, added one benchmark
address, waited for the native network monitor and endpoint refresh, and then
removed the interface. Existing uplinks, default routes, MeshTransit interfaces,
DNS, profiles, packages, policy, and services were not changed.

The reports omit SSH destinations, underlay and overlay addresses, DNS names and
answers, endpoint candidates, profile identifiers, account identifiers, control
fingerprints, packet payloads, and process identifiers.
