# Linux service readiness qualification — 2026-09-12

## Scope

This qualification closes the gap between a systemd unit being reported as
started and its owned Unix listener being available. It covers package upgrade,
bounded coordinated restart, rollback, and re-upgrade on the dedicated Ubuntu
26.04 and Debian 13 amd64 hosts. It does not use or modify the two registered
72-hour soak nodes.

The hosts in this sample were intentionally not registered. The result proves
the service-manager and local-health contract; it does not replace encrypted
peer traffic, DNS, policy, relay, or long-duration evidence.

## Candidate

| Field | Value |
| --- | --- |
| Feature commit | `2212425a3ca53adfa45ab4fe4d36dad341e6645d` |
| Package lifecycle fix | `03c417de00a600ceddc7ad620509182abe4902b9` |
| Package version | `0.1.0~rc2+03c417d` |
| Build date | `2026-09-12T11:04:23Z` |
| Package SHA-256 | `d8a0ff209041d4a07bbab76adc89e72c37a5f6da7d4b496f2a424408f884a22f` |
| Rollback version | `0.1.0~rc1+2e3fe8f` |
| Rollback SHA-256 | `30b13f00532e6974de2872f52d0f4fb1b531c4f0368769855e42b1bc84057798` |

`rc2` is used deliberately so Debian version ordering remains monotonic across
commit hashes. A version suffix based only on the leading hexadecimal commit
characters is not an ordering scheme.

## Contract implemented

- `meshd` and `meshnetd` validate and remove `NOTIFY_SOCKET` before opening
  their product listeners.
- Each process sends `READY=1` only after its listener is bound. An expected
  notification that cannot be delivered fails startup within one second.
- Orderly shutdown makes a bounded best-effort `STOPPING=1` report.
- Both packaged units require `Type=notify`, `NotifyAccess=main`, and
  `TimeoutStartSec=30s`.
- The implementation sends the stable Unix-datagram protocol directly and adds
  no `libsystemd`, CGO, or third-party dependency.
- The Debian maintainer script detects a unit still transitioning after
  `deb-systemd-invoke` and joins only that existing job. A unit that was stopped
  by the administrator is not started by an upgrade.
- Package inspection and CI self-tests enforce the emitted unit and maintainer
  lifecycle properties.

## Failure found during rollout

The first feature artifact, `0.1.0~rc1+2212425`, proved that the daemon-level
notification worked, but exposed a separate packaging race on Ubuntu.
`deb-systemd-invoke try-restart` returned after `meshnetd` was active while
`meshd` was still `activating`; the immediate local health call consequently
failed. The package lifecycle fix at `03c417d` joins a transitioning job using
systemd itself, so the package operation now returns only after the same
`READY=1` result or startup failure.

The intermediate artifact was not rolled out to Debian and is not the retained
candidate.

## Results

| Platform | Upgrade returned ready | Restart samples | Restart duration | Immediate health | Automatic restarts | Rollback/re-upgrade |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Ubuntu 26.04 / kernel 7.0.0-31 | pass | 5/5 | 677–1,028 ms | 44–83 ms | 0 | pass/pass |
| Debian 13 / kernel 6.12.107 | pass | 5/5 | 891–1,560 ms | 36–60 ms | 0 | pass/pass |

Every sample changed both intended process generations, found both sockets,
found both services active, and made one health attempt with no readiness
retry. After rollback to the retained rc1 package, each host recovered local
health through a bounded compatibility wait. Re-upgrade to rc2 then passed the
immediate, no-retry health assertion. Both hosts finished on rc2 with both
services active and `NRestarts=0`.

The machine-readable reports are in
[`docs/evidence/linux-service-readiness-rc2-s1`](evidence/linux-service-readiness-rc2-s1/README.md).

## Build and security gates

- Go 1.26.8 Linux native race tests and vet passed.
- Pinned `govulncheck` reported zero reachable vulnerabilities and pinned
  `golangci-lint` completed with zero issues from a clean cache.
- macOS-hosted race tests, vet, and CGO-disabled cross-builds passed for Linux
  amd64/arm64, Windows amd64, and macOS amd64/arm64.
- Dash syntax, ShellCheck, systemd unit verification, package verification, and
  release-binary auditing passed.
- The exact package produced a digest-bound CycloneDX SBOM. Grype reported no
  vulnerabilities, and all package/SBOM/report checksums verified.
- All qualification harness self-tests passed. The new readiness harness caps
  restart iterations, validates its confirmation label and artifact digest,
  restores services after interruption, and emits only redacted aggregate
  evidence.

## Remaining release gates

- Native ARM64 package, peer-credential, service-readiness, and rollback
  qualification subsequently passed on Ubuntu 24.04; see
  [linux-arm64-qualification-2026-09-12.md](linux-arm64-qualification-2026-09-12.md).
  Registered ARM64 traffic, DNS, policy, relay, and Ubuntu 26.04 ARM64 evidence
  remain.
- The active 72-hour registered-node soak and its final immutable report remain
  independent gates.
- Signed release artifacts and repository publication remain required before a
  stable Linux release.
