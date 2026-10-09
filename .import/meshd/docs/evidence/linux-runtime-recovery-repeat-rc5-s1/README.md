# Linux repeated runtime recovery rc5 sample 1

- Runtime: `0.1.0~rc5+35a452b`
- Runtime commit: `35a452b639cef650e11a24aaba3f668da6b33233`
- Repeat harness commit: `71d17c0`
- Scenario: five serial helper-socket permission faults with bounded recovery
- Targets: Ubuntu 26.04 x86_64 and aarch64
- Outcome: both passed 5/5 with unchanged systemd restart counts

Reports:

- `ubuntu26-amd64.json`
- `ubuntu26-arm64.json`

The reports contain aggregate platform, artifact, timing, generation, topology,
and resource-invariant evidence only. They omit process IDs, addresses, route
values, socket paths, network names, fingerprints, identity material, and error
text.
