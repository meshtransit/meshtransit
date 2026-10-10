# Linux traffic-bearing local runtime recovery qualification — 2026-09-13

## Result

The exact `35a452b639cef650e11a24aaba3f668da6b33233` RC5 runtime
passed three consecutive traffic-bearing helper-socket fault samples on native
Ubuntu 26.04 AMD64 and ARM64. The reusable qualification harness was introduced
at `826ad90`.

| Target | Samples | Runtime synchronized p95 | IPv4 stable p95 | IPv6 stable p95 | MeshTransit DNS stable p95 | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Ubuntu 26.04, x86_64 | 3/3 | 4,104 ms | 5,239 ms | 5,217 ms | 5,217 ms | pass |
| Ubuntu 26.04, aarch64 | 3/3 | 4,089 ms | 6,978 ms | 6,927 ms | 4,625 ms | pass |

Every sample intentionally stopped the active daemon, removed access to the
privileged helper socket for the new startup, and restored access only after
the daemon exposed the pending runtime failure. The same replacement daemon
generation then rebuilt the data and DNS runtimes without another service
restart.

## Traffic proof

Independent probe loops began before fault injection and continued through the
complete recovery and stability tail. Each loop was bounded and sampled:

- IPv4 ICMP through the product-owned data interface;
- IPv6 ICMP through the same interface; and
- an uncached MeshTransit DNS lookup that required the exact peer A and AAAA answers.

A sample was rejected unless all three probe classes observed at least one
missed attempt after the action began, returned a reply, and ended with at
least three consecutive successful attempts. This prevents an always-healthy
cached result or an unexercised fault from being accepted as recovery evidence.

The AMD64 samples observed 13–15 missing IPv4 attempts, 21–24 missing IPv6
attempts, and 16–18 missing MeshTransit DNS attempts. The ARM64 samples observed 13–15,
21–23, and 11–12 respectively. Every final success tail contained at least 125
consecutive successful attempts.

## Runtime and resource proof

Each traffic sample nested one complete single-sample repeated runtime gate.
That gate required the helper failure and pending state to be observed, the
runtime failure and recovery counters to advance, and the final status to be
synchronized with DNS configured and no recovery pending. It also required:

- one daemon and helper process, one data and DNS interface, and one UDP/TCP
  DNS listener;
- unchanged persisted profiles, identities, configuration, self addresses,
  explicit peer routes, and resolver policy;
- the helper socket to remain `0660 root:meshd`;
- unchanged systemd restart counters; and
- descriptor growth within the documented four-descriptor bound.

Post-run checks on both nodes found both services active, `NRestarts=0`, one
process per service, the expected helper-socket contract, synchronized control,
configured DNS, and an available encrypted peer path.

## Artifact and evidence scope

| Target | Debian package SHA-256 |
| --- | --- |
| x86_64 | `6537fd7a5e1b05b97208b459abacb0a842ad64d6f80086688a7d4671cd0cbea3` |
| aarch64 | `fcaf252d402177de030a2d761055b371f90d3f4bff21a80d650214b74f38a93d` |

The two validated redacted reports are retained under
[`docs/evidence/linux-runtime-recovery-traffic-rc5-s1`](evidence/linux-runtime-recovery-traffic-rc5-s1/README.md).
The two separate 72-hour soak nodes were not accessed or changed.

This result closes the final traffic-bearing runtime-recovery implementation
gate used for the Linux feature freeze. It is not evidence that the 72-hour
soak, artifact signing, or every remaining release-candidate acceptance item
has passed.
