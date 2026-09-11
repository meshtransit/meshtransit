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

## Alpha12 churn-remediation baseline

Before repeating the mutable policy matrix, a bounded baseline phase was run
against `0.1.0~alpha12` on both nodes. The candidate was built independently
twice from commit `9c3f0fe2d360755ecd381204338b3e43527a28b0`; both builds produced the
same amd64 Debian artifact with SHA-256
`52a9d3360605a3e45a18235710e14e41440462f727c086f752d4362b1af40a36`.
The candidate was deployed to one node first, passed mixed-version dual-stack
traffic checks, and was then deployed to the second node.

The active baseline policy allowed ICMPv4 and ICMPv6 while denying new TCP and
UDP flows in both directions. All twelve observations matched that contract,
with zero policy mismatches and zero infrastructure errors. Both `meshd`
process IDs remained stable and both systemd restart counters remained zero.

Service memory evidence for the phase was:

| Node | Current before | Current after | Peak before | Peak after |
| --- | ---: | ---: | ---: | ---: |
| `ubuntu-a` | 11,763,712 B | 12,603,392 B | 12,013,568 B | 12,857,344 B |
| `ubuntu-b` | 12,345,344 B | 12,439,552 B | 12,607,488 B | 12,701,696 B |

Post-phase inspection confirmed that the temporary listeners, ports, helpers,
and directories were removed. This baseline qualifies the immutable artifact
and the runtime-health reporting path; it does not yet qualify control-map
churn. A controlled default-deny transition followed by exact policy
restoration remains required for that claim.

The alpha12 source passed the race-enabled quality job, all five cross-build
targets, and both Linux package jobs in
[GitHub Actions run 34632024073](https://github.com/meshtransit/meshd/actions/runs/34632024073).

## Rejected alpha12 churn transition

The first controlled default-deny transition on alpha12 was rejected and the
baseline policy was restored immediately. During a 24-second observation, both
nodes alternated between a one-peer encrypted state and a zero-peer idle state.
Map revisions advanced from 23 to 33 on `ubuntu-a` and from 29 to 39 on
`ubuntu-b`. The service processes did not restart, but current memory rose from
approximately 12 MiB to 53.5 MiB and 84.2 MiB respectively.

Exact baseline restoration stopped the revision oscillation and restored one
direct dual-stack peer on both nodes, but the transition had already raised
current memory to approximately 122.4 MiB and 114.7 MiB. IPv4 and IPv6 traffic
passed in both directions after restoration. The services were then restarted
one node at a time; each returned to approximately 10 MiB with the same
installed artifact, synchronized control, configured DNS, and a direct path.

Source inspection identified a client-side feedback path: a peerless reduced
map closed the shared UDP transport and published a transient endpoint
withdrawal; the resulting control update could make the peer visible again,
recreate the tunnel, and repeat the cycle. Alpha12 is therefore not qualified
for policy churn. The next candidate must retain fail-closed peerless presence,
replace endpoints atomically across socket generations, bound idle discovery,
and repeat this exact live transition before promotion.

## Rejected alpha13 repeated-transition gate

`0.1.0~alpha13` fixed the endpoint-withdrawal feedback loop. It was built twice
from commit `deb43cb361eee138577c4e576e7c9bf242377e1a`; both builds produced the
same amd64 Debian artifact with SHA-256
`707051e34936fb380d5a01e8ee472787351af0faffa831b5c6e8f378d4df1bf3`.
Mixed-version canary traffic and the first all-alpha13 dual-stack baseline
passed in both directions.

During a default-deny transition, both nodes stayed synchronized and stable at
one new revision, retained their process IDs with zero restarts, exposed zero
peers and zero peer routes, and reported the idle data-plane state. The bounded
policy harness matched all twelve deny expectations with no infrastructure
errors. Memory stayed flat during that deny phase, at approximately 11.7 MiB
on `ubuntu-a` and 14.5 MiB on `ubuntu-b`.

The complete repeated-transition gate nevertheless failed. Restoring the exact
baseline policy increased current memory to approximately 45.5 MiB and 47.6
MiB. A second default-deny transition increased it again to 68.4 MiB and 65.0
MiB, and the second restoration ended at approximately 70.0 MiB and 67.4 MiB.
Control revisions did not oscillate and traffic remained correct, so this was
not the alpha12 feedback bug. Inspection showed that each legitimate peer-route
and relay-authority change still closed and recreated the complete userspace
WireGuard/TUN device. Alpha13 is therefore not qualified for repeated policy
churn.

The exact baseline policy was restored, IPv4 and IPv6 passed in both
directions, and the services were restarted one node at a time. Current memory
returned to approximately 8.8 MiB on each node with the same alpha13 artifact,
synchronized control, configured DNS, and one authenticated direct peer path.
The next candidate must update compatible peer, relay-peer, and host-route
authority in place, then pass multiple deny/restore cycles with bounded memory
before promotion.

## Rejected alpha14 pre-gate

`0.1.0~alpha14` was built independently twice from commit
`672f3f5dfba28bdd38137b50e44993acdfe33ea6`; both builds were byte-identical
with SHA-256
`dc0f769596ed406dbd278805001ddebf1dcf8930733359d2151ce483ac85b952`.
The canary upgrade, mixed-version dual-stack traffic, second-node rollout, and
all-alpha14 baseline passed. The first default-deny transition retained both
service process IDs, removed all peer routes, reported zero peers and idle, and
kept current memory near the pre-transition values.

The candidate was rejected before the repeated-transition gate because both
relay `last_connected` timestamps reset at the policy transition. The TUN was
not recreated, but source inspection confirmed that the live full-peer UAPI
configuration resent the unchanged `listen_port`. The official userspace
WireGuard engine handles every listen-port assignment with an unconditional
bind update, which closed and reopened the shared UDP and relay transport. The
exact baseline policy was restored immediately. The next candidate must use a
peer-only live configuration that cannot carry the private key or listen port,
then prove stable socket and relay generations through repeated transitions.

## Accepted alpha15 in-place churn gate

`0.1.0~alpha15` was built independently twice from commit
`3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`. Both amd64 Debian packages were
byte-identical, passed package verification, and had SHA-256
`1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`.
The source passed the complete Linux race suite, `go vet`, `golangci-lint`,
reachable-vulnerability scanning, and all five release-target builds.
The node-B canary and mixed alpha14/alpha15 dual-stack traffic passed before the
same artifact was installed on node A.

Three complete default-deny and exact-baseline-restoration cycles then passed.
Every deny state was synchronized with zero peers, zero policy rules, idle data
plane, configured DNS, retained self addresses, and no peer host routes. Every
restored state returned to one peer, two reduced inbound rules, and one
authenticated direct path. Map revisions advanced once per expected control
transition without the alpha12 oscillation.

The following lifecycle identities remained unchanged through all six policy
transitions:

| Evidence | `ubuntu-a` | `ubuntu-b` |
| --- | --- | --- |
| `meshd` PID | `42846` | `38776` |
| systemd restarts | `0` | `0` |
| `mesh0` ifindex | `141` | `142` |
| IPv4 UDP socket inode | `155580` | `148826` |
| IPv6 UDP socket inode | `155581` | `148827` |
| Home relay connected at | `2026-09-11T20:02:26.004878848Z` | `2026-09-11T20:01:27.001961529Z` |

This proves that compatible peer/policy changes replaced packet-filter state,
relay peer authority, WireGuard peers, and host routes without recreating the
TUN, rebinding the UDP sockets, or reconnecting the home relay.

Memory showed a bounded initial warm-up rather than per-cycle device retention:

| Observation | `ubuntu-a` current | `ubuntu-b` current |
| --- | ---: | ---: |
| Initial baseline | 10,174,464 B | 13,774,848 B |
| Restore after cycle 1 | 14,282,752 B | 16,809,984 B |
| Restore after cycle 2 | 14,974,976 B | 16,875,520 B |
| Deny cycle 3 | 15,060,992 B | 16,875,520 B |
| Final restore | 15,114,240 B | 14,266,368 B |

During the third deny cycle, the official policy harness matched all twelve
TCP, UDP, ICMPv4, and ICMPv6 deny observations with zero policy mismatches and
zero infrastructure errors. Both process IDs and memory readings were exactly
stable across that bounded phase. The final exact policy restoration reinstated
both IPv4 and IPv6 peer routes; three packets per family passed in both
directions. Both services remained active, DNS remained configured, and the
ten-minute warning-level journal query returned no entries on either node.

Alpha15 therefore passes the repeated peerless policy-churn gate that rejected
alpha12, alpha13, and alpha14. This result qualifies compatible host-route and
peer-authority replacement; it does not broaden the current subnet/exit-route
scope or complete the remaining Linux v0.1 qualification matrix.

## Supporting quality gates

The runtime implementation passed the full race-enabled Go test suite, `go
vet`, `golangci-lint`, `govulncheck`, cross-platform compile jobs, and Linux
amd64/arm64 package jobs. The corresponding runtime CI evidence is
[GitHub Actions run 34621187171](https://github.com/meshtransit/meshd/actions/runs/34621187171).

Before using this evidence for Linux-alpha promotion, repeat the complete five
phase matrix from the next immutable candidate artifact and retain multiple
reports to demonstrate repeatability rather than a single successful sample.
