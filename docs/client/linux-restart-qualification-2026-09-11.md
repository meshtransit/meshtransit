# Linux restart qualification — 2026-09-11 UTC

Status: bounded Linux alpha restart and crash-recovery evidence, not p95 or
release-candidate evidence.

## Scope

The same immutable `0.1.0~alpha15` Debian package was tested on both nodes in
the current two-node Ubuntu topology. Each node independently restarted
`meshd.service` and `meshnetd.service` while its peer stayed online.

- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256:
  `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Harness schema: `meshtransit.linux-restart-qualification/v1`
- Readiness deadline: 15 seconds
- Traffic: concurrent IPv4 and IPv6 ICMP at 200-millisecond pacing
- Stability tail: five seconds with at least three consecutive replies

Every run required both services to be active, the data interface and dual-stack
peer routes to exist, the control session to be synchronized, and MeshTransit DNS to
return the exact peer addresses before the selected service was restarted.

## Results

| Node | Restarted service | Action | TUN ready | Daemon and DNS ready | IPv4 stable | IPv6 stable | Result |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `ubuntu-b` | `meshd.service` | 130 ms | 4,720 ms | 5,079 ms | 4,805 ms | 4,875 ms | pass |
| `ubuntu-b` | `meshnetd.service` | 138 ms | 3,993 ms | 4,472 ms | 4,270 ms | 4,194 ms | pass |
| `ubuntu-a` | `meshd.service` | 117 ms | 4,575 ms | 4,909 ms | 4,866 ms | 4,629 ms | pass |
| `ubuntu-a` | `meshnetd.service` | 110 ms | 4,278 ms | 4,702 ms | 4,631 ms | 4,449 ms | pass |

All four restart commands returned success and changed the selected service
PID. Every readiness and stable-traffic measurement was below the 15-second
deadline. The slowest full readiness observation was 5,079 milliseconds, and
the slowest stable traffic recovery was 4,875 milliseconds.

Packet loss in these reports measures the intentional interruption window, not
steady-state loss. Each stream ended with 68–74 consecutive replies after
recovery. The post-matrix check returned both nodes to synchronized direct-path
operation with configured DNS, exact A/AAAA answers, dual-stack peer routes,
and three successful packets per address family. No warning-level service log
entry or harness temporary directory remained.

## Evidence and limits

The redacted machine-readable reports and checksum manifest are retained in
[`docs/evidence/linux-restart-alpha15-s1`](evidence/linux-restart-alpha15-s1).
They omit peer addresses, DNS names and answers, network identifiers, control
fingerprints, and raw traffic output.

This matrix establishes one passing bounded sample for every node/service
combination in the current topology. It does not establish the release target's
p95 latency or 72-hour reliability requirement. Repeated restart samples,
reboot recovery, fault injection, and the remaining native Linux matrix are
separate gates.

## Alpha16 abrupt-termination matrix

The immutable `0.1.0~alpha16` Debian package was then tested with `SIGKILL`
instead of a graceful service restart. The same action was applied separately
to `meshd.service` and `meshnetd.service` on each node while the peer stayed
healthy.

- Runtime commit: `fa246a10468b831b9cb83d29b1f46497a54ac20b`
- Artifact SHA-256:
  `51b32b18380122522e980812288fdedaa6efbf3f6d39823ece29be13b25ec159`
- Harness schema: `meshtransit.linux-crash-recovery-qualification/v1`
- Readiness deadline: 20 seconds
- Traffic: concurrent IPv4 and IPv6 ICMP at 200-millisecond pacing
- Stability tail: five seconds with at least three consecutive replies

| Node | Killed service | DNS cleanup | Full readiness | IPv4 stable | IPv6 stable | Result |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `ubuntu-b` | `meshd.service` | 31 ms | 6,791 ms | 6,513 ms | 6,513 ms | pass |
| `ubuntu-b` | `meshnetd.service` | not required | 6,715 ms | 6,885 ms | 6,808 ms | pass |
| `ubuntu-a` | `meshd.service` | 60 ms | 6,282 ms | 6,002 ms | 6,005 ms | pass |
| `ubuntu-a` | `meshnetd.service` | not required | 6,771 ms | 6,519 ms | 6,575 ms | pass |

Every selected service acquired a new PID and increased its systemd automatic
restart counter. Direct `meshd` termination removed the non-persistent DNS
link, UDP/TCP listeners, and per-link `systemd-resolved` state before the new
daemon became ready. Terminating `meshnetd` caused systemd to stop and recreate
`meshd` as part of the dependency restart; the harness requires both PIDs to
change so the daemon cannot continue against stale helper-generation TUN state.

All eight probe streams stabilized within 6,885 milliseconds and ended with
82–86 consecutive replies per address family. Post-matrix inspection found one
data link, one DNS link, one UDP and one TCP resolver listener owned by the
current daemon, synchronized direct paths, configured MeshTransit DNS, unchanged
identity/profile/env bytes, and no error-level service log entries on either
node.

The redacted reports and checksum manifest are retained in
[`docs/evidence/linux-crash-recovery-alpha16-s1`](evidence/linux-crash-recovery-alpha16-s1).
This remains one bounded sample per node and service. It does not establish p95
recovery, long-duration reliability, kernel-panic behavior, power-loss safety,
or storage-corruption recovery.

## Alpha16 repeated abrupt-termination matrix

The crash scenarios were then repeated three times per service and node with
the same immutable alpha16 artifact. A resource snapshot after every sample
required one process per service, one data link, one DNS link, one UDP resolver
listener, one TCP resolver listener, unchanged persisted state, unchanged data
routes, unchanged semantic resolved policy, and bounded descriptor counts.

| Node | Killed service | Samples | Full readiness p95 | Stable traffic p95 | DNS cleanup p95 | Result |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `ubuntu-b` | `meshd.service` | 3 | 7,575 ms | 7,346 ms | 36 ms | pass |
| `ubuntu-b` | `meshnetd.service` | 3 | 7,192 ms | 7,151 ms | not applicable | pass |
| `ubuntu-a` | `meshd.service` | 3 | 7,027 ms | 6,783 ms | 52 ms | pass |
| `ubuntu-a` | `meshnetd.service` | 3 | 6,852 ms | 6,735 ms | not applicable | pass |

All 12 samples passed. All six helper terminations recreated both helper and
daemon generations, and all six direct daemon terminations observed DNS runtime
cleanup. Every persisted, route, resolver, process, link, and listener invariant
remained intact. The maximum descriptor drift was one daemon descriptor in one
scenario, and no error-level service log was recorded.

The aggregate reports and checksums are retained in
[`docs/evidence/linux-crash-repeat-alpha16-s1`](evidence/linux-crash-repeat-alpha16-s1).
Each scenario has only three samples, so its nearest-rank p95 is its maximum.
This is repeatability evidence for the alpha topology, not the larger sample set
or long-duration soak required for a release candidate.
