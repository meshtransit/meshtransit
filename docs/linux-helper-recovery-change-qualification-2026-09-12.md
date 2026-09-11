# Linux helper-recovery/network-change qualification — 2026-09-12

This report records the first two-node qualification in which an abrupt
`meshnetd` termination and coordinated service recovery are immediately
followed by a controlled host-network event. It is bounded alpha evidence, not
a release-candidate percentile claim.

## Artifact and topology

- `meshd`: `0.1.0~alpha16`
- Runtime commit: `fa246a10468b831b9cb83d29b1f46497a54ac20b`
- Debian package SHA-256:
  `51b32b18380122522e980812288fdedaa6efbf3f6d39823ece29be13b25ec159`
- Two x86-64 Ubuntu 24.04 nodes with one authenticated direct peer path.
- IPv4, IPv6, MagicDNS, and control-map synchronization were healthy before
  each run.
- Ubuntu B was the canary. Ubuntu A ran only after B passed and an independent
  cleanup check completed.

The chained harness sent `SIGKILL` only to the main `meshnetd.service` process.
The existing recovery harness required systemd to replace the helper, replace
`meshd`, and restore online, synchronized, DNS-configured dual-stack service.
The next qualification action created the dedicated `meshqchg0` dummy
interface with the fixed RFC 2544 test address and then removed it. Existing
uplinks, default routes, `mesh0`, and `meshdns0` were not modified directly.

## Results

| Node | Full recovery ready | Recovery traffic stable | Chain launch gap | Network event | Endpoint refresh | Path usable | Network traffic stable | Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `ubuntu-b` | 6,986 ms | 6,868 ms | 77 ms | 836 ms | 836 ms | 39 ms | 185 ms | pass |
| `ubuntu-a` | 6,235 ms | 5,969 ms | 54 ms | 787 ms | 787 ms | 29 ms | 137 ms | pass |

Both child reports passed and matched on topology, platform, and immutable
artifact metadata. On both nodes, the network-change and endpoint-refresh
counters advanced. The recovered `meshd` and `meshnetd` PIDs and both systemd
restart counters remained unchanged for the complete network-change phase.
Raw PIDs are deliberately omitted from the retained reports.

## Independent post-run checks

After each chain completed, the node had exactly one `meshd` process, one
`meshnetd` process, one `mesh0` interface, one `meshdns0` interface, one UDP DNS
listener, and one TCP DNS listener. `meshqchg0` was absent. IPv4 and IPv6 peer
routes still used `mesh0`; MagicDNS returned both expected addresses; direct
dual-stack traffic passed; and status remained online with one direct path and
DNS configured.

Each journal contained the two expected systemd warning records for the
injected `SIGKILL`. Neither node recorded an error-level `meshd` or `meshnetd`
entry during its qualification window.

The redacted machine-readable reports and checksum manifest are retained in
[`docs/evidence/linux-helper-recovery-change-alpha16-s1`](evidence/linux-helper-recovery-change-alpha16-s1).

## Scope limit

This sample proves that one freshly recovered service generation on each node
processed its first controlled network event without another restart, refreshed
endpoints, and retained the existing healthy mesh. It does not establish p95,
long-duration reliability, or real multi-uplink path migration because the
production uplink and default route were deliberately unchanged.
