# Alpha17 Linux soak smoke evidence

This directory contains the first accepted redacted fixed-topology soak reports
for `meshd` alpha17.

- `meshd` artifact SHA-256:
  `ecc46e8f6c7e3d02e22499324caa9789e82bf4cd83f999de831a1e9ee6d9d145`
- Harness schema: `meshtransit.linux-soak-qualification/v1`
- `ubuntu-b-soak.json`: canary, 7/7 samples, pass
- `ubuntu-a-soak.json`: second node, 7/7 samples, pass

Both reports are development smoke evidence. Their 90-second duration is
deliberately below the 72-hour release gate, so
`scenario.release_candidate_eligible` is false.

The reports omit SSH destinations, overlay addresses, DNS names and answers,
raw service PIDs, persisted-state digests, profile and network identifiers,
control fingerprints, endpoint data, and packet contents.

See
[`linux-soak-qualification-2026-09-12.md`](../../linux-soak-qualification-2026-09-12.md)
for rollout order, results, rejected pre-evidence execution, independent final
checks, and scope limits.
