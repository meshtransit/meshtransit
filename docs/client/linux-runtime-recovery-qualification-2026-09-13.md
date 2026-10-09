# Linux local runtime recovery qualification — 2026-09-13

## Result

The exact `35a452b639cef650e11a24aaba3f668da6b33233` candidate passed
the bounded local-runtime recovery gate on native Ubuntu 26.04 amd64 and arm64.
Both nodes were already registered and synchronized before the test.

| Target | Package SHA-256 | Failure observed | Fully synchronized | Result |
| --- | --- | ---: | ---: | --- |
| Ubuntu 26.04, x86_64 | `6537fd7a5e1b05b97208b459abacb0a842ad64d6f80086688a7d4671cd0cbea3` | 1,510 ms | 3,800 ms | pass |
| Ubuntu 26.04, aarch64 | `fcaf252d402177de030a2d761055b371f90d3f4bff21a80d650214b74f38a93d` | 1,364 ms | 3,705 ms | pass |

## Fault and acceptance boundary

Each run deliberately stopped the baseline daemon, kept the packaged helper
running, temporarily changed only `/run/meshnetd/meshnetd.sock` from mode
`0660` to `000`, and started a fresh daemon generation. This made the first
privileged TUN request fail with `permission denied` while the local API stayed
available. The harness observed `runtime_recovery.pending=true`, restored the
socket to its exact package mode, and waited for a fresh full-map application.

Both architectures finished with:

- `runtime_recovery.failures=1`;
- `runtime_recovery.recoveries=1`;
- `runtime_recovery.pending=false`;
- control synchronized and DNS configured;
- data and DNS interfaces present;
- unchanged daemon and helper PIDs during the fault/recovery window;
- unchanged systemd restart counters; and
- the helper socket restored to `0660 root:meshd`.

The post-run journal on each node independently confirmed the injected
`permission denied` helper connection failure. Both services remained active
and `meshd.service` retained `NRestarts=0`. The candidate therefore recovered
inside the original daemon process; systemd did not mask the result by starting
a replacement process.

## Evidence scope

The source archive used on both machines had SHA-256
`399e554c78903cbd837c80d7864af16ba92bc24994735783e32169dc0f2855c7`.
The complete native race suite and package verifier passed independently on
both architectures before installation. The machine-readable reports are in
[`docs/evidence/linux-runtime-recovery-rc5-s1`](evidence/linux-runtime-recovery-rc5-s1/README.md).

This sample proves bounded recovery from one temporary privileged-helper
availability failure on a peerless but registered network. It does not replace
the two-node traffic, relay, policy, reboot, crash-repeat, or 72-hour soak gates.
