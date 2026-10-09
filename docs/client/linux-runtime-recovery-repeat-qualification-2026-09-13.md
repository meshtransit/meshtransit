# Linux repeated local runtime recovery qualification — 2026-09-13

## Result

The exact `35a452b639cef650e11a24aaba3f668da6b33233` rc5 runtime
passed five consecutive local-runtime fault/recovery samples on native Ubuntu
26.04 amd64 and arm64. The repeat harness implementation was finalized at
`71d17c0`.

| Target | Samples | Failure observed p95 | Fully synchronized p95 | Resources stable p95 | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| Ubuntu 26.04, x86_64 | 5/5 | 1,472 ms | 3,796 ms | 414 ms | pass |
| Ubuntu 26.04, aarch64 | 5/5 | 1,696 ms | 4,022 ms | 238 ms | pass |

Every sample observed the intentional helper-socket failure, exposed
`runtime_recovery.pending=true`, restored access, and returned to synchronized
control with DNS configured. The same daemon and helper generation survived
within each sample, both systemd restart counters stayed unchanged, and the
final runtime counters were `failures=1`, `recoveries=1`, `pending=false`.

## Repeatability and resource contract

The serial gate stopped on the first failure and independently validated every
child report. After every successful recovery it also required:

- exactly one `meshd` and one `meshnetd` process;
- exactly one data interface and one DNS interface;
- exactly one UDP and one TCP DNS listener;
- the helper socket contract to remain `0660 root:meshd`;
- persisted profile, identity, and configuration bytes to remain unchanged;
- the exact global self-address set and explicit peer-route set to remain
  unchanged;
- resolver state and systemd restart counters to remain unchanged;
- descriptor growth to remain within the four-descriptor bound; and
- synchronized, DNS-configured status with no pending runtime recovery.

The report separates explicit peer routes from address-derived `proto kernel`
routes. IPv6 DAD may change the timing of the latter, while the exact global
self-address set is checked independently. Resource convergence has a bounded
five-second window and its time is included in the p95 summary.

## Topology isolation found during qualification

One initial amd64 attempt was deliberately rejected at sample four when the
control map changed from zero to one visible peer and installed two explicit
host routes. The new gate classified both `peer_count_changed` and
`route_state_changed`; all recovery, service, DNS, address, socket, descriptor,
and restart invariants remained healthy. After the external topology returned
to the zero-peer baseline, the complete amd64 5/5 run passed. This invalidated
attempt is not counted as recovery evidence.

## Artifact and evidence scope

| Target | Debian package SHA-256 |
| --- | --- |
| x86_64 | `6537fd7a5e1b05b97208b459abacb0a842ad64d6f80086688a7d4671cd0cbea3` |
| aarch64 | `fcaf252d402177de030a2d761055b371f90d3f4bff21a80d650214b74f38a93d` |

The two passing redacted reports are retained under
[`docs/evidence/linux-runtime-recovery-repeat-rc5-s1`](evidence/linux-runtime-recovery-repeat-rc5-s1/README.md).
Post-run checks found both services active, `NRestarts=0`, the helper socket at
`0660 root:meshd`, synchronized control, configured DNS, and no pending
recovery on both nodes.

This gate proves repeatable in-process recovery on registered peerless nodes.
It does not replace a traffic-bearing two-node fault test, relay or policy
qualification, reboot/crash gates, or the 72-hour soak.
