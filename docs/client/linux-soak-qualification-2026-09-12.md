# Linux soak qualification — 2026-09-12

## Scope

This document records the first native two-node smoke of the read-only Linux
fixed-topology soak gate. It validates the harness and its runtime telemetry on
the current Ubuntu test topology. It is not the 72-hour release-candidate run.

## Artifacts

- `meshd` `0.1.0~alpha17`, commit
  `8313c5a938d3b83157bedaafe28579082fd3e215`
- `meshd` Debian SHA-256:
  `ecc46e8f6c7e3d02e22499324caa9789e82bf4cd83f999de831a1e9ee6d9d145`
- `meshctl` `0.1.0~alpha6`, commit
  `12d7a09e48af51e9c675113c6cc43ec078ca1452`
- `meshctl` Debian SHA-256:
  `f2389ef86a1b847cf20541fccbe0591cab0dfac468ee7d2e9671efc89f39ceee`
- Accepted harness fix: commit `3d99bbe`, source SHA-256
  `d1f2b43e302102b316ba8f9e1383afe78a148c4b7f24ac562b7cb61d8a2b961a`

Both new Debian packages were built independently twice with byte-identical
outputs. Before each rollout, the prior alpha16/alpha5 package was present and
its extracted binaries matched the installed binaries byte for byte.

## Rollout and rejected pre-evidence execution

Ubuntu B was upgraded first. The raw authenticated daemon API exposed valid
runtime data, but the installed alpha5 CLI discarded the newly added field
while decoding and re-encoding status. `meshctl` was updated to preserve the
optional runtime model, retain compatibility with older daemons, and show a
bounded human-readable summary. Race tests, vet, and golangci-lint passed
before alpha6 was installed.

The first 90-second harness invocation completed its samples but produced no
report. The cause was jq assignment precedence: `unique` received the report
object and failure array instead of only the failure array. This execution was
rejected as evidence. Commit `3d99bbe` moved report finalization into a tested
function; its contract now covers passing reports plus flattened, sorted, and
deduplicated failure aggregation. A 20-second native diagnostic then passed
before the accepted canary smoke began.

After Ubuntu B passed, Ubuntu A was upgraded. Both upgrades preserved the
identity tree, profile file, daemon configuration, online synchronized state,
one authenticated direct path, MeshTransit DNS, and IPv4/IPv6 peer traffic.

## Accepted results

Both nodes used a 90-second duration, 15-second sampling, and a 30-second
warmup. Every sample checked service generations and restart counters,
process/interface/listener cardinality, persisted state, routes, resolver
policy, artifact identity, network-change counters, MeshTransit DNS, and one IPv4 and
IPv6 peer probe.

| Node | Samples | Journal warning/error | meshd maximum RSS growth | meshnetd maximum RSS growth | Goroutine/thread/descriptor growth | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Ubuntu B canary | 7/7 | 0/0 | 0.02% | 0% | 0/0/0 | Pass |
| Ubuntu A | 7/7 | 0/0 | 3.23% | 0% | 0/0/0 | Pass |

After both smokes, an independent simultaneous final gate on each node verified
the exact alpha17/alpha6 versions, active services, online synchronized state,
one direct path, runtime counters, unchanged persisted state, exact MeshTransit DNS,
and five successful probes for each address family.

The retained report SHA-256 values are:

- Ubuntu B:
  `cf3bf736c7d373190314274111ea3354b73d5d823c8c28e641ae100143d457b0`
- Ubuntu A:
  `4c41e80492edb4addd26ccae0a54d788a8eb6f88ee5d2e03f761edf99cdc7acf`

The machine-readable reports are in
[`docs/evidence/linux-soak-alpha17-smoke-s1`](evidence/linux-soak-alpha17-smoke-s1).

## Security and limits

Runtime health remains available only through the authenticated local Unix
socket. No profiling or network listener was enabled. Reports contain only
operator labels, artifact/platform metadata, aggregate counters, booleans, and
traffic outcomes; a separate redaction check rejected forbidden field names.

These passing smokes validate instrumentation and harness behavior, not
long-duration stability. Both reports correctly set
`scenario.release_candidate_eligible` to false. The remaining release gate is
a 72-hour run with at least a one-hour warmup and the default strict resource
limits. This sample also covers only one fixed direct-path, dual-stack Ubuntu
topology; relay transitions, network changes, IPv6-only underlay, and
multi-uplink migration remain separate qualifications.
