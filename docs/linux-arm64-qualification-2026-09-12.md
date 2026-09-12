# Linux ARM64 native qualification — 2026-09-12

## Scope

This qualification records the first native ARM64 candidate build and package
lifecycle on Ubuntu 24.04. A second ARM64 host running Amazon Linux 2023 was
used only as an independent build and portability environment. Neither host is
one of the registered 72-hour soak nodes.

The Ubuntu host was intentionally left unregistered. This result proves native
compilation, package lifecycle, systemd readiness, local socket authorization,
and cross-builder reproducibility. It does not prove encrypted peer traffic,
TUN activation, DNS application, policy enforcement, relay fallback, or
long-duration behavior on ARM64.

## Candidate

| Field | Value |
| --- | --- |
| Source commit | `69e5e2f00f0fead79e5baf4848725ee3aa6590b6` |
| Source archive SHA-256 | `157a416096962f60ea35920eddb422c82754bd8fe30d9e0a0505b518677717ca` |
| Package version | `0.1.0~rc3+69e5e2f` |
| Build date | `2026-09-12T11:31:54Z` |
| ARM64 package SHA-256 | `8ea1a650b82ba911bb6033af1b80947a1ff81d983800a49b6919cde33908cff1` |
| Rollback commit | `2e3fe8f41315cbeaccbb2e2e194cfe9731510ae3` |
| Rollback version | `0.1.0~rc1+2e3fe8f` |
| Rollback package SHA-256 | `c92f2251b2f2459dfae626512e515fba69d84893946e91d921ff8b119849113f` |

The candidate version advances to `rc3` so Debian version ordering remains
monotonic after the retained `rc2` amd64 candidate.

## Ubuntu 24.04 ARM64 result

The native host ran Ubuntu 24.04.4, kernel `6.17.0-1017-aws`, systemd 255,
and Go 1.26.8 on ARM64.

- Full `go test -race -shuffle=on -p=2 ./...` passed in 82 seconds, including
  the Linux abstract notification-socket test.
- `go vet ./...` passed in 40 seconds. Module verification, tidy consistency,
  formatting, ShellCheck, qualification self-tests, packaging self-tests,
  binary auditing, package verification, and systemd unit verification passed.
- A second isolated package build produced the same package bytes and SHA-256.
- A clean rollback-package install became ready in 287 ms after a 1,057 ms
  package operation.
- Candidate upgrade returned in 1,588 ms and its single immediate health
  request passed in 10 ms without a readiness retry.
- Five coordinated candidate restarts passed. Restart duration was 930–993 ms;
  each single immediate health request completed in 30–32 ms. Both process
  generations changed and automatic restart counters remained zero.
- Downgrade to the retained rollback build, bounded compatibility readiness,
  and re-upgrade to the candidate passed. The re-upgrade immediate health
  request completed in 10 ms.
- The encrypted host credential was preserved across downgrade and re-upgrade
  without reading its content.
- Runtime directory and socket ownership matched the package contract. The
  unprivileged `nobody` identity received `EACCES` from both the local API and
  privileged-helper sockets.

The host finished with `0.1.0~rc3+69e5e2f` installed, both services
active/running as `Type=notify`, `NotifyAccess=main`, a 30-second startup
deadline, and zero automatic restarts.

## Cross-builder reproducibility

The exact source archive, Go 1.26.8 toolchain, target, build flags, version,
commit, and build date were used independently on Ubuntu 24.04 and Amazon Linux
2023. The resulting release binaries were byte-identical:

| Binary | SHA-256 |
| --- | --- |
| `meshd` | `f5087b50feab1f3c95c248422b74b7bf9682301503db2eaebdc72c629b9761b1` |
| `meshnetd` | `2839f5dcee7aea18f594a01821ab53b3a1bdcf1ba95da6bc950a34e2ef8e17b1` |
| `meshcred` | `de8ef11a78099e5b4281185abb49456750716900af7f391470bfb7b2b94d1796` |

On Amazon Linux the full native race suite, vet, eleven qualification
self-tests, portable shell gates, and release-binary audit passed. All three
binaries were static ELF64 AArch64 executables without a dynamic interpreter.

Amazon Linux remains outside the supported matrix. Its systemd 252 is below
the package contract of systemd 255 or later, no RPM lifecycle exists, and the
host was not tested with SELinux enforcing. Unit syntax verification passed
against staged binaries, but services were not installed or started and no
route, DNS, or TUN state was changed.

## Evidence

The redacted machine-readable reports are retained under
[`docs/evidence/linux-arm64-rc3-s1`](evidence/linux-arm64-rc3-s1/README.md).
Candidate and rollback packages, detailed logs, and integrity manifests remain
mode `0600` on the disposable qualification hosts. They are not committed
because raw host evidence has a broader disclosure surface than the aggregate
release contract requires.

## Remaining release gates

- Run the same package lifecycle on Ubuntu 26.04 ARM64.
- Register an ARM64 Ubuntu candidate and run the two-node IPv4/IPv6 direct,
  forced-relay, DNS, policy, restart, network-change, and rollback matrices
  against a dedicated non-soak peer.
- Complete the larger crash sample set and sustained candidate validation.
- Produce and verify the exact candidate SBOM, signature, and provenance before
  publication.

Docker and Podman were absent on the Ubuntu ARM64 host, so the disposable
Debian-container wrapper was not repeated there. Direct mocked maintainer tests,
package verification, and the actual native clean install, upgrade, downgrade,
and re-upgrade lifecycle all passed.
