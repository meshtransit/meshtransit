# Linux policy matrix alpha15 — sample 1

These reports were produced by `tools/qualification/linux-policy.sh` against
the same two-node Linux topology and immutable Debian artifact.

- Runtime: `0.1.0~alpha15`
- Runtime commit: `3e6ed3aaadf228e248a5158f2a8cb87d85f80e23`
- Artifact SHA-256: `1766c157059c6b70918c49a4878767f3b38418316be3f762bf45e82b8ae0ac82`
- Result: five phases passed, 60 of 60 observations matched
- Policy mismatches: 0
- Infrastructure errors: 0

The report schema deliberately omits SSH destinations, overlay addresses,
policy source, raw status, and probe payloads. `SHA256SUMS` records the exact
report bytes committed here.

This directory contains one complete alpha15 sample. It is qualification
evidence, not a release-stage promotion by itself.
