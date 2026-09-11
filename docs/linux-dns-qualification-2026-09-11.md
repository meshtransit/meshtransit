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

## Alpha15 lifecycle validation

After the packet-path, TUN lifecycle, and live-update fixes were combined in
`0.1.0~alpha15`, the host-local split-only lifecycle scenario was repeated once
on each node using the same immutable Debian package as the other alpha15
qualification matrices.

- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256:
  `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Harness schema: `meshtransit.linux-dns-qualification/v1`
- Cleanup and recovery deadline: 20 seconds

| Node | Stop duration | Link/listener removal | External DNS during stop | Complete DNS recovery | Query suite | Result |
| --- | ---: | ---: | --- | ---: | --- | --- |
| `ubuntu-b` | 73 ms | 94 ms | pass | 4,789 ms | pass | pass |
| `ubuntu-a` | 56 ms | 67 ms | pass | 3,945 ms | pass | pass |

Both runs passed authoritative A/AAAA, IPv4/IPv6 PTR, NODATA, NXDOMAIN, direct
UDP and TCP, short-name search, and FQDN host-resolution checks before and
after the lifecycle action. Independent inspection confirmed split-only
routing without `~.`, external queries on the non-mesh resolver path, direct
dual-stack peer traffic, both services active, and no warning-level journal
entries.

The redacted reports and checksum manifest are retained in
[`docs/evidence/linux-dns-alpha15-s1`](evidence/linux-dns-alpha15-s1). This
host-local lifecycle sample did not mutate the control-plane resolver
configuration. The separate alpha15 live-update matrix below covers those
upstream modes.

## Alpha15 live-update validation

A second alpha15 matrix exercised three control-plane updates sequentially
without restarting either client. The initial state was captured before the
first change and used as the exact rollback target.

1. One public test suffix was routed to one reachable classic IPv4 resolver.
   Both clients installed only that route, forwarded direct and host-resolver
   queries with recursion available, and kept an unrelated public query on the
   non-mesh resolver path.
2. The split route was replaced by the same resolver as an explicit default.
   Both clients installed `+DefaultRoute` and `~.`, forwarded unrelated public
   queries through `meshdns0`, and continued to answer MagicDNS.
3. The global resolver and override were removed. Both clients returned to
   `-DefaultRoute`, removed `~.` and the temporary split route, sent public
   queries back to the host resolver, and stopped forwarding public names from
   the local MeshTransit resolver.

Every phase completed on both nodes with synchronized control, configured DNS,
direct IPv4/IPv6 traffic, and MagicDNS resolution. The original daemon process
IDs remained unchanged and both systemd restart counters remained zero,
demonstrating live application rather than restart recovery. The final bounded
warning-level journal query returned no entries.

The redacted aggregate report and checksum manifest are retained in
[`docs/evidence/linux-dns-alpha15-live-update-s1`](evidence/linux-dns-alpha15-live-update-s1).
Resolver addresses, test names, answers, process IDs, and network identifiers
are intentionally omitted. This sample used one classic IPv4 resolver and does
not cover upstream failure, multiple-resolver failover, or encrypted DNS.

## Interpretation and release-candidate limits

This evidence demonstrates installed-host authoritative resolution, UDP/TCP
service, `systemd-resolved` search integration, split and explicit-default
upstream forwarding, non-mesh DNS isolation, clean graceful removal, bounded
restoration, and control-plane rollback on the two-node Linux POC topology.
Isolated resolver tests additionally cover most-specific-route selection,
fallback-resolver isolation, transaction-ID validation, and UDP truncation retry
over TCP. A release candidate still needs the larger repeated sample set and
fault-injected upstream failure scenarios defined by the release plan.
