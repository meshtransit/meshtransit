# Linux network-change qualification — 2026-09-11

This report records the first repeatability check for proactive endpoint refresh
after an ordinary Linux network change. It is evidence for the Linux alpha POC,
not a release-candidate percentile claim.

## Artifacts

- `meshd`: `0.1.0~alpha9`
- `meshd` commit: `e84a2925da78db9a67d4d3f619bcb24a6c417ad5`
- Debian package SHA-256:
  `bb1218898e5ef21bc21c26117b66cd62cee91b29c442d4bb75fb4f2f8e4cc20b`
- `meshctl`: `0.1.0~alpha5`
- `meshctl` commit: `9e0db1f763d6ca1cdb56fa419821af682e39c54c`
- Debian package SHA-256:
  `1d3356a14a9e13e6bbd3f6df28215b850daf0f71f2dbc73917907a0b932d189a`

Both repository CI runs passed Linux quality and security checks, five target
cross-builds, and amd64/arm64 Debian package verification before deployment.
The traceable runs are `meshd` CI #21 (`34606746952`) and `meshctl` CI #9
(`34608111890`).

## Topology and method

- Two x86-64 nodes running Ubuntu 24.04.4 LTS and Linux 6.8.0-139-generic.
- One authenticated direct peer path was available in each direction.
- IPv4, IPv6, and MeshTransit DNS were healthy before every sample.
- Each sample used `linux-network-change.sh` with its default 20-second recovery
  bound and 0.2-second continuous dual-stack probes.
- The action created only the dedicated `meshqchg0` dummy interface and assigned
  `198.18.255.254/32`. It did not modify an existing uplink, default route,
  `mesh0`, or `meshdns0`.
- The harness removed `meshqchg0` through its normal path or exit trap. A final
  independent check confirmed that the interface was absent on both nodes.

## Results

| Node | Sample | Event observed | Endpoint refresh | Path usable | IPv4 loss | IPv6 loss | Cleanup | Outcome |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| ubuntu-b | 1 | 785 ms | 785 ms | 51 ms | 0% | 0% | pass | pass |
| ubuntu-b | 2 | 895 ms | 895 ms | 42 ms | 0% | 0% | pass | pass |
| ubuntu-b | 3 | 892 ms | 892 ms | 35 ms | 0% | 0% | pass | pass |
| ubuntu-a | 1 | 829 ms | 829 ms | 70 ms | 0% | 0% | pass | pass |
| ubuntu-a | 2 | 805 ms | 805 ms | 46 ms | 0% | 0% | pass | pass |
| ubuntu-a | 3 | 816 ms | 816 ms | 53 ms | 0% | 0% | pass | pass |

All six samples passed. Endpoint refresh ranged from 785 to 895 milliseconds,
with a maximum of 895 milliseconds against the 20-second bound. Neither address
family lost a probe, and no service warning was recorded during the test window.
After the final sample, both nodes remained online and synchronized with DNS
configured, one direct peer path, and matching observed/refresh counters.

## Alpha15 validation sample

After the packet-path, TUN lifecycle, and live-update fixes were combined in
`0.1.0~alpha15`, the controlled scenario was repeated once on each node using
the same immutable Debian package as the alpha15 policy, restart, and reboot
matrices.

- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256:
  `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Harness schema: `meshtransit.linux-network-change-qualification/v1`
- Recovery deadline: 20 seconds

| Node | Event observed | Endpoint refresh | Path usable | IPv4 stable | IPv6 stable | Loss | Cleanup | Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| `ubuntu-b` | 881 ms | 881 ms | 48 ms | 117 ms | 116 ms | 0% | pass | pass |
| `ubuntu-a` | 849 ms | 849 ms | 54 ms | 88 ms | 93 ms | 0% | pass | pass |

Both status counters advanced for interface creation and advanced again after
the interface was removed. Independent post-run inspection confirmed that
`meshqchg0` was absent, the original default route and uplink were unchanged,
peer routes still used `mesh0`, both services remained active, MeshTransit DNS and
dual-stack traffic remained healthy, and the bounded warning-level journal
query returned no entries.

The redacted reports and checksum manifest are retained in
[`docs/evidence/linux-network-change-alpha15-s1`](evidence/linux-network-change-alpha15-s1).

## Scope limit

This scenario proves that the daemon detects a bounded interface/address change,
refreshes endpoint discovery promptly, keeps the existing mesh path usable, and
rolls back the test interface. It does not prove real multi-uplink path migration
because the production uplink and default route were deliberately left untouched.
A separately controlled multi-homed lab and a larger sample set are still
required to close the release-candidate p95 target.
