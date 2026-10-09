# Linux relay-fallback qualification — 2026-09-11

Status: Linux alpha POC evidence, not release-candidate qualification.

## Result

All six sequential runs passed. Each node moved its single peer from direct to
relay within the 10-second gate, exchanged IPv4 and IPv6 traffic while the
direct fault remained active, removed the fault, and returned to direct within
the 15-second recovery gate.

| Node | Sample | Relay observed (ms) | Direct restored (ms) | First reply after fault (ms) | Max consecutive loss | Total loss per family | Dropped UDP packets (out/in) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ubuntu-a | 1 | 4,800 | 1,997 | 4,956 | 4 | 7.1429% | 17 / 4 |
| ubuntu-a | 2 | 5,838 | 1,902 | 6,218 | 5 | 9.0909% | 19 / 6 |
| ubuntu-a | 3 | 6,042 | 1,916 | 6,188 | 5 | 8.7719% | 19 / 6 |
| ubuntu-b | 1 | 4,489 | 3,032 | 5,066 | 4 | 7.0175% | 17 / 6 |
| ubuntu-b | 2 | 4,046 | 3,020 | 5,058 | 4 | 7.2727% | 17 / 6 |
| ubuntu-b | 3 | 4,036 | 3,130 | 5,071 | 4 | 7.1429% | 17 / 4 |

With the documented nearest-rank calculation, the six-sample p95 is the
maximum: 6,042 ms for relay observation and 3,130 ms for direct restoration.
These values are comfortably inside the harness gates, but six samples do not
establish the release-candidate p95 target.

## Topology and artifact

- Two Ubuntu 24.04 amd64 nodes, both running kernel `6.8.0-139-generic`.
- One peer per node with dual-stack MeshTransit overlay traffic.
- Three IPv4 underlay candidates per peer: public, shared private, and VPC
  private. Endpoint values are intentionally omitted from this report.
- `meshd` version `0.1.0~alpha9`, commit
  `e84a2925da78db9a67d4d3f619bcb24a6c417ad5`.
- Debian artifact SHA-256:
  `bb1218898e5ef21bc21c26117b66cd62cee91b29c442d4bb75fb4f2f8e4cc20b`.
- Default harness timings: two-second lead, 10-second fallback deadline,
  two-second relay hold, 15-second direct-recovery deadline, five-second tail,
  200-millisecond traffic pacing, and 100-millisecond status polling.

## Evidence checks

- Every run began with exactly one direct peer and at least one connected relay
  region.
- Both IPv4 and IPv6 probes succeeded while aggregate status reported one relay
  peer and the UDP fault was still installed.
- Every nftables output counter increased, proving the direct fault was
  exercised. Input counters also increased in all runs.
- Every run removed the dedicated nftables table and ended online,
  synchronized, direct, MagicDNS-configured, and dual-stack stable.
- A separate signal-interruption check terminated the harness while the fault
  was active; its trap removed the table and the node returned to direct.
- The longest observed disruption was five 200-millisecond probe sequences.
  Total loss includes the intentional direct-path failure interval.

## Alpha15 validation sample

After the packet-path, TUN lifecycle, and live-update fixes were combined in
`0.1.0~alpha15`, the scenario was repeated once on each node using the same
immutable Debian package as the other alpha15 qualification matrices.

- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256:
  `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Harness schema: `meshtransit.linux-relay-fallback-qualification/v1`
- Relay-fallback deadline: 10 seconds
- Direct-recovery deadline: 15 seconds

| Node | Relay observed | Direct restored | First IPv4/IPv6 reply | Maximum consecutive loss | Total loss per family | Dropped UDP (out/in) | Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `ubuntu-b` | 5,809 ms | 2,771 ms | 6,346 / 6,348 ms | 5 | 8.7719% | 19 / 6 | pass |
| `ubuntu-a` | 4,871 ms | 2,585 ms | 5,021 / 5,020 ms | 4 | 6.7797% | 17 / 6 | pass |

Both address families exchanged traffic while aggregate status selected relay.
After rollback, the continuous streams stabilized within 71 milliseconds and
ended with at least 33 consecutive replies. Independent post-run inspection
confirmed that `meshd_relay_qual` was absent, the original default route was
unchanged, peer routes still used `mesh0`, both services remained active,
MagicDNS and dual-stack traffic were healthy, and the bounded warning-level
journal query returned no entries.

The redacted reports and checksum manifest are retained in
[`docs/evidence/linux-relay-fallback-alpha15-s1`](evidence/linux-relay-fallback-alpha15-s1).

## Limitations and next evidence

The nodes share a cloud environment and the fault blocks an explicit set of
IPv4 underlay candidates. This does not qualify IPv6-only underlay behavior,
multiple simultaneous peers, relay-region failure, cross-provider NAT, adverse
latency/loss, or sustained operation. Release-candidate evidence needs a larger
sample set attached to the exact candidate artifact and the remaining native
Linux matrix.
