# Linux restart qualification — 2026-09-11 UTC

Status: bounded Linux alpha evidence, not p95 or release-candidate evidence.

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
peer routes to exist, the control session to be synchronized, and MagicDNS to
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
