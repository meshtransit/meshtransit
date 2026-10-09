# Linux v0.1 feature freeze — 2026-09-13

Status: **feature frozen; release acceptance still in progress**.

## Freeze decision

Linux v0.1 feature development is frozen after the native AMD64/ARM64
traffic-bearing runtime-recovery gate passed. The frozen runtime source anchor
is `35a452b639cef650e11a24aaba3f668da6b33233`; the deployed CLI source anchor
is `e53acf5d9ae3a2d5382c5b3992d540cbbb5c1e73`. The final reusable qualification
harness was added at `826ad90`.

The exact runtime packages used for the closing gate were:

- AMD64: `6537fd7a5e1b05b97208b459abacb0a842ad64d6f80086688a7d4671cd0cbea3`
- ARM64: `fcaf252d402177de030a2d761055b371f90d3f4bff21a80d650214b74f38a93d`

## Frozen scope

The Linux implementation boundary now includes browser login with bounded
wait-for-approval, profile isolation, pinned control trust, synchronized map
streaming, encrypted relay and authenticated direct paths, IPv4/IPv6 host
traffic, policy enforcement, MagicDNS and classic split DNS, privilege-separated
TUN management, host-protected identity storage and rotation, package/service
lifecycle, network-change handling, and bounded in-process recovery from local
runtime failure.

No new Linux v0.1 feature is accepted after this point. Changes are limited to:

- a confirmed release-blocking correctness or interoperability defect;
- a security vulnerability or fail-open behavior;
- a packaging, signing, documentation, or qualification correction that does
  not change runtime behavior; or
- an explicit unfreeze decision recorded in the release contract.

Any runtime behavior change invalidates the RC5 exact-artifact evidence. It
must produce a new candidate, repeat the affected native matrix on AMD64 and
ARM64, and restart any exact-artifact long-duration gate.

## Evidence that supports the freeze

- native package lifecycle and readiness on Ubuntu 26.04 AMD64, Debian 13, and
  Ubuntu 24.04/26.04 ARM64;
- direct, forced-relay, DNS, policy, network-change, reboot, rollback, and
  repeated crash recovery on registered mixed-architecture peers;
- secret-storage tamper, migration, rotation, rollback, and credential boundary
  gates;
- reproducible package/SBOM work and release-surface scans;
- five consecutive peerless in-process runtime-recovery samples per
  architecture; and
- three consecutive traffic-bearing in-process runtime-recovery samples per
  architecture, including observed IPv4, IPv6, and uncached MagicDNS outages
  followed by stable recovery.

The closing native result is documented in
[linux-runtime-recovery-traffic-qualification-2026-09-13.md](linux-runtime-recovery-traffic-qualification-2026-09-13.md).

## What the freeze does not claim

Feature freeze is not Linux beta, GA, or a stable release declaration. The
following acceptance work remains and may uncover a release-blocking fix:

- complete and accept the protected 72-hour fixed-topology soak;
- finish the exact-candidate native target matrix, including IPv6-only
  underlay evidence and any still-claimed Ubuntu target not covered by the
  retained candidate reports;
- finish signed artifact and provenance publication;
- resolve or explicitly defer the documented TPM binding, forced power-loss
  rotation, and encrypted off-host backup policy gaps; and
- perform the final release-commit vulnerability, secret, license, SBOM,
  rollback, and documentation audit.

Windows implementation is the next feature-development priority. Linux remains
available as the reference peer and may receive only the freeze exceptions
above until its remaining acceptance evidence is complete.
