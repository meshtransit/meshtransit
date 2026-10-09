# Linux repeated crash-recovery matrix alpha16 — sample 1

These reports cover three serial `SIGKILL` samples for each MeshTransit service
on each node in the current two-node Linux alpha topology.

- Runtime: `0.1.0~alpha16`
- Runtime commit: `fa246a10468b831b9cb83d29b1f46497a54ac20b`
- Artifact SHA-256:
  `51b32b18380122522e980812288fdedaa6efbf3f6d39823ece29be13b25ec159`
- Repeat-runner commit: `a04838a`
- Repeat-runner SHA-256:
  `32b8d80b2c3b64dfa01dc1275e54e9aece8b42a8e557654869fd19f254452e42`
- Single-run harness SHA-256:
  `9f3f42784a830f2c3abec2f29d462634468e5a95c1c61a7dbf1906cf3e8c00b1`
- Scenarios: 4
- SIGKILL samples: 12
- Result: 12 pass, 0 fail
- Readiness deadline: 20 seconds per sample
- Slowest per-scenario nearest-rank p95 full readiness: 7,575 ms
- Slowest per-scenario nearest-rank p95 stable traffic recovery: 7,346 ms
- Slowest per-scenario nearest-rank p95 DNS cleanup: 52 ms

Every post-sample resource check found both services active, exactly one daemon
and helper process, one data link, one DNS link, one UDP listener, and one TCP
listener. Persisted identity/profile/env bytes and modes, the complete data-link
route set, and semantic per-link resolver state remained equal to their
scenario baselines. The only descriptor increase was one additional daemon
descriptor in one scenario, within the documented four-descriptor timing
headroom. No error-level service log entry was observed.

All six helper-termination samples changed both the selected helper PID and the
daemon PID. All six daemon-termination samples observed the dedicated DNS
runtime disappear before the new daemon became ready. Both nodes ended online,
control-synchronized, direct-path ready, and DNS configured.

The reports omit peer addresses, DNS names and answers, process IDs, route and
resolver contents, persisted-state hashes, network identifiers, control
fingerprints, and raw traffic output. `SHA256SUMS` records the exact aggregate
report bytes committed here.

With three samples per scenario, nearest-rank p95 equals that scenario's maximum
sample. This evidence establishes short repeated-crash behavior for the current
artifact and topology; it does not establish release-candidate p95, a crash
storm beyond the configured systemd rate boundary, or 72-hour reliability.
