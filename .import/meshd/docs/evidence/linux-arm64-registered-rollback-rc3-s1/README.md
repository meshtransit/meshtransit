# Linux ARM64 registered rollback rc3 — sample 1

This report records a registered rollback and re-upgrade on the Ubuntu 24.04
ARM64 node while its Ubuntu 26.04 AMD64 peer remained online on rc3.

- Candidate: `0.1.0~rc3+69e5e2f`
- Rollback: `0.1.0~rc1+2e3fe8f`
- Result: rollback, mixed-version traffic, DNS, and re-upgrade passed
- Traffic: 40 of 40 post-transition IPv4 and IPv6 probes succeeded
- Final state: both nodes online on the expected topology; ARM restored to rc3

Profile selection, self addresses, network identity, and pinned control trust
were compared in memory before and after both transitions. The report exposes
only equality results. It omits SSH destinations, profile identifiers, overlay
and underlay addresses, DNS names and answers, control fingerprints, endpoint
candidates, credentials, package logs, packet payloads, and process identifiers.
