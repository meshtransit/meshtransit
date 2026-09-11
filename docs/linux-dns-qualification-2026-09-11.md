# Linux DNS qualification — 2026-09-11

Status: Linux alpha POC evidence, not release-candidate qualification.

## Scope

The same installed `0.1.0~alpha9` artifact was exercised sequentially on two
Ubuntu nodes. Each node resolved the other through the deployed split-only DNS
plan, then performed one graceful `meshd.service` stop/start lifecycle. The peer
remained online throughout each run.

Artifact SHA-256:
`bb1218898e5ef21bc21c26117b66cd62cee91b29c442d4bb75fb4f2f8e4cc20b`.
Daemon commit: `e84a2925da78db9a67d4d3f619bcb24a6c417ad5`.

The report contract intentionally omits node addresses, DNS names, network
identifiers, resolver responses, endpoint addresses, and control fingerprints.

## Results

Both node runs passed every gate:

| Gate | ubuntu-a | ubuntu-b |
| --- | ---: | ---: |
| Graceful stop exit code | 0 | 0 |
| DNS link/listener removal | 80 ms | 101 ms |
| Non-mesh DNS available while stopped | pass | pass |
| Graceful start exit code | 0 | 0 |
| DNS ready after start | 4,276 ms | 4,592 ms |
| UDP authoritative A and AAAA | pass | pass |
| TCP authoritative A | pass | pass |
| Authoritative NODATA and NXDOMAIN with SOA | pass | pass |
| IPv4 and IPv6 PTR | pass | pass |
| Short-name search and FQDN host resolution | pass | pass |
| Split route restored without default-DNS takeover | pass | pass |

Two temporary control-plane configurations were then applied sequentially:

1. A split route for a public test domain used one classic-IP upstream. Both
   nodes installed the exact route on `meshdns0`; direct resolver queries and
   host resolver queries returned upstream answers with recursion available.
2. The split route was removed and the same upstream was configured as an
   explicit default. Both nodes installed `+DefaultRoute` and `~.`, forwarded an
   unrelated public domain through `meshdns0`, and continued to answer MagicDNS.

The original configuration was restored after those checks: MagicDNS enabled,
no global resolvers, no split rules, and override-local-DNS disabled. Both nodes
then showed `-DefaultRoute`, external queries returned to the physical uplink,
MagicDNS remained on `meshdns0`, and direct encrypted peer paths remained healthy.

The first harness attempt on `ubuntu-a` reported a false cleanup timeout because
`resolvectl status` returned exit code zero for an absent interface while writing
an error message. Direct inspection proved that the kernel link and sockets were
already absent. The harness was corrected to inspect the returned link record;
the passing result above is from the corrected run.

## Interpretation and release-candidate limits

This evidence demonstrates installed-host authoritative resolution, UDP/TCP
service, `systemd-resolved` search integration, split and explicit-default
upstream forwarding, non-mesh DNS isolation, clean graceful removal, bounded
restoration, and control-plane rollback on the two-node Linux POC topology.
Isolated resolver tests additionally cover most-specific-route selection,
fallback-resolver isolation, transaction-ID validation, and UDP truncation retry
over TCP. A release candidate still needs the larger repeated sample set and
fault-injected upstream failure scenarios defined by the release plan.
