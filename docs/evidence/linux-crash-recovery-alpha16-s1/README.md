# Linux crash-recovery matrix alpha16 — sample 1

These reports cover abrupt `SIGKILL` termination of both MeshTransit services
on each node in the current two-node Linux alpha topology.

- Runtime: `0.1.0~alpha16`
- Runtime commit: `fa246a10468b831b9cb83d29b1f46497a54ac20b`
- Artifact SHA-256:
  `51b32b18380122522e980812288fdedaa6efbf3f6d39823ece29be13b25ec159`
- Harness commit: `12a7c28`
- Harness SHA-256:
  `9f3f42784a830f2c3abec2f29d462634468e5a95c1c61a7dbf1906cf3e8c00b1`
- Scenarios: 4
- Result: 4 pass, 0 fail
- Readiness deadline: 20 seconds
- Slowest observed full readiness: 6,791 ms
- Slowest observed stable traffic recovery: 6,885 ms

Killing `meshd` removed its non-persistent DNS link, UDP/TCP listeners, and
per-link `systemd-resolved` state before systemd restarted it. Cleanup was
observed in 31–60 milliseconds. Killing `meshnetd` triggered a coordinated
restart: both the helper PID and daemon PID changed, preventing a new helper
generation from serving stale TUN ownership state.

Every stream finished with 82–86 consecutive IPv4 and IPv6 replies. Post-matrix
checks found both services active, synchronized direct paths, configured DNS,
one data link, one DNS link, one UDP and one TCP resolver listener owned by the
current daemon, unchanged identity and configuration bytes, and no error-level
service logs.

The report schema omits peer addresses, DNS names and answers, process IDs,
network identifiers, control fingerprints, and raw traffic output.
`SHA256SUMS` records the exact report bytes committed here.

This is one bounded sample per node and service. It does not establish p95
recovery or long-duration reliability, and it does not simulate kernel panic,
power loss, or storage corruption.
