# Linux host-policy qualification evidence — 2026-09-11 UTC

## Result

The first bounded live two-node host-policy matrix passed on the Linux alpha
POC. All 60 probes matched their expected result, with no policy mismatch or
infrastructure error in the accepted reports. The original control policy was
restored after the matrix and verified from both the console and the nodes.

This is implementation evidence for one topology and one runtime artifact. It
does not promote the artifact to a release candidate and does not replace the
repeatability, long-duration, signed-artifact, IPv6-only underlay, Windows, or
macOS release gates.

## Qualified artifact

- Runtime version: `0.1.0~alpha10`
- Runtime commit: `d9a38cd3853602512047888624773fc6a335dff2`
- Debian artifact SHA-256:
  `30af618c5d8e4174e05a97441e5193749eea2d57fd20e25a52b260339d0ffe80`
- Topology: two registered amd64 Ubuntu nodes, reported only as `ubuntu-a` and
  `ubuntu-b`
- Address families: IPv4 and IPv6
- Qualification schema: `meshtransit.linux-policy-qualification/v1`

The two installed binaries reported the same version and commit in every
accepted phase. The artifact was built twice independently with identical
bytes before installation. A root-only alpha9 rollback package remained cached
on each node with SHA-256
`bb1218898e5ef21bc21c26117b66cd62cee91b29c442d4bb75fb4f2f8e4cc20b`.

## Matrix

Each phase contained twelve new-flow probes: TCP and UDP over both address
families plus ICMPv4 and ICMPv6, in both directions. TCP and UDP used a bounded
fixed-format random challenge and required an exact response. Distinct ICMP
identifiers prevented reply state from one direction authorizing the reverse
direction.

| Phase | Expected and observed contract | Result | Per-probe duration |
| --- | --- | --- | --- |
| `asymmetric-a-to-b` | A→B TCP, UDP, and ICMP allowed; every B→A new flow denied | 12/12 pass | 3,085–5,776 ms; mean 4,396 ms |
| `asymmetric-b-to-a` | B→A TCP, UDP, and ICMP allowed; every A→B new flow denied | 12/12 pass | 2,962–5,691 ms; mean 4,478 ms |
| `port-narrowing-allowed` | Only the designated A→B TCP/UDP ports allowed; ICMP and all reverse new flows denied | 12/12 pass | 3,131–5,793 ms; mean 4,663 ms |
| `adjacent-ports-default-deny` | Adjacent ungranted TCP/UDP ports, ICMP, and both directions denied | 12/12 pass | 5,149–6,584 ms; mean 5,673 ms |
| `explicit-default-deny` | Empty grants denied TCP, UDP, and ICMP for both families and directions | 12/12 pass | 3,428–6,162 ms; mean 5,036 ms |

The asymmetric phases also demonstrated bounded reply handling: an exact reply
to an allowed locally initiated TCP or UDP flow succeeded while an independent
new flow in the reverse direction remained denied. The port phases proved that
authorization did not widen to a neighboring port or to ICMP. The final
default-deny report exercised actual mesh routes and observed deny for every
packet class.

## Harness hardening during qualification

Several pre-acceptance runs were rejected as invalid evidence before the final
matrix was accepted:

1. Status returned self addresses as host prefixes, while the harness compared
   bare addresses.
2. A deny-only reduced map could legitimately close `mesh0` and transition the
   data plane to `idle`.
3. A source address could be removed between route inspection and socket bind.
4. A listener could become unnecessary after its inbound routes disappeared
   during startup.

The harness was changed to compare canonical host prefixes, accept
`offline`/`idle` only for deny-only phases, avoid listeners when no mesh route
exists, classify removal of a local mesh address as a blocked probe, and
re-check inbound routes before accepting a missing listener. It still fails if
a listener is unavailable while a route into that listener remains. Regression
tests, Python compilation, and ShellCheck passed for the accepted harness.

Relevant harness commits are:

- `8c5d2c5` — match status address prefixes
- `6109bd3` — handle idle nodes in deny-only phases
- `ae2eb3b` — qualify deny-only phases without mesh routes
- `7290a3c` — classify a removed mesh source address as denied
- `7821662` — re-check routes when a policy listener stops

## Restoration and post-checks

The policy was validated and saved through the server-authoritative console
with its strong ETag guard. After the accepted matrix, the exact original
policy text was restored. The console reported four explicit allow rules.

Both nodes then reported:

- `online`, `registered`, and control session `synchronized`;
- one peer and two reduced inbound policy rules;
- `encrypted_relay_ready` with one authenticated direct path;
- DNS `configured`;
- the expected alpha10 version and runtime commit.

IPv4 and IPv6 ping passed in both directions after restoration. No package,
profile, identity, DNS configuration, or service definition was changed by the
policy harness. Temporary peer helpers and listeners were removed by its exit
trap.

## Supporting quality gates

The runtime implementation passed the full race-enabled Go test suite, `go
vet`, `golangci-lint`, `govulncheck`, cross-platform compile jobs, and Linux
amd64/arm64 package jobs. The corresponding runtime CI evidence is
[GitHub Actions run 34621187171](https://github.com/meshtransit/meshd/actions/runs/34621187171).

Before using this evidence for Linux-alpha promotion, repeat the complete five
phase matrix from the next immutable candidate artifact and retain multiple
reports to demonstrate repeatability rather than a single successful sample.
