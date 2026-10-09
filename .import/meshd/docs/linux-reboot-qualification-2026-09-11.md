# Linux reboot qualification — 2026-09-11 UTC

Status: bounded Linux alpha evidence, not p95 or release-candidate evidence.

## Scope

The same immutable `0.1.0~alpha15` Debian package was exercised through one
controlled reboot of each node in the current two-node Ubuntu topology. The
other node stayed online and recorded continuous IPv4 and IPv6 traffic.

- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256:
  `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Harness schema: `meshtransit.linux-reboot-qualification/v1`
- Recovery deadline: 60 seconds
- Observation window: 75 seconds
- Traffic pacing: 200 milliseconds

Preflight required both nodes to be registered, synchronized, dual-stack
reachable, and resolvable through MagicDNS. Reboot confirmation was bound to
the exact target label, and the two nodes were never rebooted concurrently.

## Results

| Target | SSH and boot ID | Services | TUN and routes | Daemon online | MagicDNS | Outbound dual stack | Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `ubuntu-b` | 23,339 ms | 32,745 ms | 35,782 ms | 38,957 ms | 42,894 ms | 50,014 ms | pass |
| `ubuntu-a` | 18,890 ms | 27,614 ms | 31,200 ms | 34,185 ms | 37,279 ms | 44,310 ms | pass |

Both runs observed an actual SSH outage and a changed kernel boot ID. The
active profile, profile count, self addresses, runtime version, runtime commit,
and artifact digest were preserved. Every readiness signal completed below the
60-second deadline.

Observer traffic on `ubuntu-a` became continuously stable 34,402 milliseconds
after the node-B reboot command for IPv4 and 34,450 milliseconds for IPv6.
Observer traffic on `ubuntu-b` became stable 29,027 milliseconds after the
node-A reboot command for IPv4 and 29,091 milliseconds for IPv6. Packet loss in
the reports covers the intentional reboot interval; both streams ended with
189–217 consecutive replies.

Final inspection found both nodes online and synchronized with one direct peer,
configured DNS, exact MagicDNS A/AAAA answers, and dual-stack host routes.
Three IPv4 and three IPv6 packets passed in each direction, service restart
counters were zero, and the bounded warning-level journal query returned no
entries.

## Evidence and limits

The redacted machine-readable reports and checksum manifest are retained in
[`docs/evidence/linux-reboot-alpha15-s1`](evidence/linux-reboot-alpha15-s1).
They omit SSH destinations, overlay addresses, DNS answers, boot IDs, profile
IDs, control fingerprints, and raw traffic output.

This is one passing reboot sample per node in the current topology. It does not
establish p95 reboot recovery, IPv6-only underlay behavior, multi-uplink
recovery, or the 72-hour reliability target. Those remain separate gates.
