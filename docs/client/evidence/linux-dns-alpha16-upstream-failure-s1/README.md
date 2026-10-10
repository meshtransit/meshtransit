# Linux DNS upstream-failure matrix alpha16 — sample 1

This aggregate report covers one sequential, fault-injected split-DNS scenario
on the current two-node Linux alpha topology:

1. A non-responsive resolver was placed before a reachable resolver.
2. The reachable resolver was removed, leaving only the non-responsive
   resolver.
3. The temporary split route was removed and the exact MeshTransit DNS-only baseline
   was restored.

- Runtime: `0.1.0~alpha16`
- Runtime commit: `fa246a10468b831b9cb83d29b1f46497a54ac20b`
- Artifact SHA-256:
  `51b32b18380122522e980812288fdedaa6efbf3f6d39823ece29be13b25ec159`
- Independently built, byte-identical artifacts: 2
- Control updates: 3
- Nodes: 2
- Result: pass

All six ordered-failover queries succeeded after one bounded upstream attempt,
with observed durations from 1,526 to 1,554 milliseconds. All six
blackhole-only direct queries returned `SERVFAIL` in 1,531 to 1,543
milliseconds. Host-resolver queries also failed in the blackhole-only phase.
Packet capture observed twelve upstream DNS packets, all sent only to the
selected non-responsive resolver, with zero packets sent to an unexpected DNS
destination.

The split route remained suffix-scoped in both failure phases. Unrelated public
queries stayed on the host resolver path, while MeshTransit DNS, bidirectional
dual-stack peer traffic, synchronized control, and the encrypted data plane
remained healthy. Neither daemon restarted. Rollback removed the temporary
route, disabled public forwarding through the MeshTransit resolver, and
preserved both identity files and host configuration byte-for-byte.

The aggregate schema intentionally omits resolver, peer, node-management, and
overlay addresses; DNS names and answers; process IDs; network identifiers;
control fingerprints; raw packet captures; and raw daemon status.
`SHA256SUMS` records the exact report bytes committed here.

This is one bounded classic-IPv4 upstream sample. It does not establish p95
latency, exercise an IPv6 upstream or encrypted DNS, or replace repeated
release-candidate qualification. Unit tests separately cover retry after
upstream `SERVFAIL` and `REFUSED`, terminal `NXDOMAIN`, and aggregate
`SERVFAIL` when every selected upstream fails.
