# Linux RC4 upstream DNS failure matrix — sample 1

This evidence records the release-candidate upstream DNS failover,
fail-closed, and rollback matrix on native Ubuntu 26.04 AMD64 and ARM64. The
two hosts were dedicated qualification nodes; the long-running soak nodes were
not modified.

## Candidate and topology

- `meshd`: `0.1.0~rc4+e427252`
- commit: `e427252f4f4fc13c247d9db7e5c8d31ed62d7911`
- AMD64 package SHA-256: `8c195ac3825159ddd46e954d77f7c8c5e599a8c6889edafcc8cfe43180a7b4e3`
- ARM64 package SHA-256: `abe72bc1a71d62f2fae81c7c3e9d1cc37324f384957268a795a5dad1a4a4f6e8`
- sample count: five UDP and five TCP queries per phase and architecture
- query deadline: 4,500 ms

The temporary policy allowed traffic only between the two devices owned by the
qualification user in this isolated Network. The baseline was MagicDNS enabled,
no global resolver, local-DNS override disabled, no split route, no search
domain, no custom record, and zero allow rules.

## Results

| Architecture | Phase | Expected result | UDP | TCP | Blocked packets | Fallback packets | Unexpected packets |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| AMD64 | failover | `NOERROR` | 5/5 | 5/5 | 7 UDP / 10 TCP | 7 UDP / 30 TCP | 0 |
| AMD64 | fail-closed | `SERVFAIL` | 5/5 | 5/5 | 11 UDP / 10 TCP | 0 | 0 |
| AMD64 | rollback | `SERVFAIL` from direct MeshTransit resolver; host bypass | 5/5 | 5/5 | 0 | 0 | 0 |
| ARM64 | failover | `NOERROR` | 5/5 | 5/5 | 7 UDP / 10 TCP | 7 UDP / 30 TCP | 0 |
| ARM64 | fail-closed | `SERVFAIL` | 5/5 | 5/5 | 11 UDP / 10 TCP | 0 | 0 |
| ARM64 | rollback | `SERVFAIL` from direct MeshTransit resolver; host bypass | 5/5 | 5/5 | 0 | 0 | 0 |

All retained reports passed the resolver-destination gate. MagicDNS, IPv4 and
IPv6 peer traffic, daemon readiness, service generation, and restart count
remained healthy in every phase. The temporary nftables table was removed by
the harness after each run.

The first AMD64 fail-closed attempt was intentionally rejected and is not a
retained passing report: four UDP packets reached the resolver removed by the
immediately preceding control update. The query outcome itself was correct.
After the previous revision's DNS work drained, the unchanged gate passed with
zero unexpected packets. This matrix therefore qualifies steady-state behavior
after revision convergence; it does not claim that no resolver work can remain
in flight across a configuration transition.

## Rollback and final state

After both architecture runs, the split route and temporary policy rule were
removed through the authenticated Console. Both nodes then reported `online`,
`synchronized`, `dns=configured`, `peer_count=0`, `policy_rule_count=0`, and
`data_plane=idle`. `meshd.service` was active with `NRestarts=0`; the resolver
link contained only the Network MagicDNS and reverse-routing domains, and the
qualification nftables table was absent.

## Reports

- [`ubuntu26-amd64-failover.json`](ubuntu26-amd64-failover.json)
- [`ubuntu26-amd64-fail-closed.json`](ubuntu26-amd64-fail-closed.json)
- [`ubuntu26-amd64-rollback.json`](ubuntu26-amd64-rollback.json)
- [`ubuntu26-arm64-failover.json`](ubuntu26-arm64-failover.json)
- [`ubuntu26-arm64-fail-closed.json`](ubuntu26-arm64-fail-closed.json)
- [`ubuntu26-arm64-rollback.json`](ubuntu26-arm64-rollback.json)

The JSON reports omit SSH destinations, profile identifiers, device names,
DNS names and answers, resolver addresses, control fingerprints, credentials,
process identifiers, and raw daemon status.
