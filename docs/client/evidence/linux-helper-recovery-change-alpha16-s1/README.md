# Alpha16 helper-recovery/network-change evidence

This directory contains the first redacted `alpha16` reports for the chained
`meshnetd SIGKILL` recovery and controlled network-change qualification.

- Artifact SHA-256:
  `51b32b18380122522e980812288fdedaa6efbf3f6d39823ece29be13b25ec159`
- Harness schema:
  `meshtransit.linux-helper-recovery-change-qualification/v1`
- `ubuntu-b-helper-recovery-change.json`: canary, pass
- `ubuntu-a-helper-recovery-change.json`: second node, pass

The reports include both redacted child phase reports. They do not include SSH
destinations, overlay addresses, DNS names, raw service PIDs, raw endpoint
addresses, profile identifiers, network names, control fingerprints, policy
contents, or packet contents.

See
[`linux-helper-recovery-change-qualification-2026-09-12.md`](../../linux-helper-recovery-change-qualification-2026-09-12.md)
for method, results, independent post-run checks, and scope limits.
