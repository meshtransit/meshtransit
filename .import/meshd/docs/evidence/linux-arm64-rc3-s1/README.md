# Linux ARM64 rc3 evidence sample 1

This directory retains the minimal redacted evidence for the native ARM64
qualification described in
[`linux-arm64-qualification-2026-09-12.md`](../../linux-arm64-qualification-2026-09-12.md).

- `ubuntu-24.04-summary.json` records the native build, package, lifecycle,
  authorization, and final-state gates.
- `ubuntu-24.04-readiness.json` is the direct output of the bounded five-sample
  service-readiness harness.
- `amazon-linux-2023-portability.txt` records the deliberately limited
  cross-builder portability result and its unsupported-platform boundaries.
- `SHA256SUMS` binds this evidence set.

The files intentionally exclude IP addresses, hostnames, process IDs, socket
paths, control-plane state, peer endpoints, credentials, and identity data.
The Amazon Linux result is not compatibility certification and does not add an
RPM-based supported platform.
