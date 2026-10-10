# Linux RC5 traffic-bearing runtime-recovery evidence

This directory retains the redacted reports from the final bounded Linux
feature-freeze gate on 2026-09-13. The exact RC5 runtime was exercised on one
native Ubuntu 26.04 AMD64 node and one native Ubuntu 26.04 ARM64 node in the
same fixed Network.

Each node ran three helper-socket permission faults while independent probe
loops continuously exercised IPv4, IPv6, and uncached MeshTransit DNS against the
other node. Every sample observed loss in all three probe classes and ended
with a long consecutive-success tail. The nested runtime gate also passed its
process, interface, listener, route, address, resolver, persisted-state,
descriptor, socket-permission, and systemd restart-count invariants.

| Report | Architecture | Samples | IPv4 stable p95 | IPv6 stable p95 | MeshTransit DNS stable p95 | Result |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `ubuntu26-amd64.json` | x86_64 | 3/3 | 5,239 ms | 5,217 ms | 5,217 ms | pass |
| `ubuntu26-arm64.json` | aarch64 | 3/3 | 6,978 ms | 6,927 ms | 4,625 ms | pass |

The reports identify the artifact with these Debian package digests:

- AMD64: `6537fd7a5e1b05b97208b459abacb0a842ad64d6f80086688a7d4671cd0cbea3`
- ARM64: `fcaf252d402177de030a2d761055b371f90d3f4bff21a80d650214b74f38a93d`

They contain operator labels and aggregate measurements only. Peer addresses,
DNS names and answers, process IDs, control identity, endpoint data, packet
contents, and raw probe logs were not retained.

This evidence closes the traffic-bearing in-process runtime-recovery gate. It
does not substitute for the independent 72-hour fixed-topology soak or release
artifact signing.
