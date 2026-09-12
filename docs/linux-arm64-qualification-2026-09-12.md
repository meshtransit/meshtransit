# Linux ARM64 native qualification — 2026-09-12

## Scope

This qualification records native ARM64 candidate builds and package
lifecycles on Ubuntu 24.04 and Ubuntu 26.04. A third ARM64 host running Amazon
Linux 2023 was used only as an independent build and portability environment.
None of these hosts is one of the registered 72-hour soak nodes.

The Ubuntu host was intentionally left unregistered during the package-lifecycle
phase. A follow-on qualification registered that same immutable candidate and
paired it with a dedicated Ubuntu 26.04 AMD64 node. Direct encrypted traffic,
TUN activation, DNS application and lifecycle, and host-policy enforcement are
now proven for this mixed-architecture topology. Bounded forced-relay fallback
and direct-path recovery subsequently passed from both initiating nodes. Native
network-change observation and endpoint refresh also passed on both nodes with
zero packet loss. Registered rollback and re-upgrade subsequently preserved the
active identity, control trust, DNS, and mixed-version direct traffic. Ubuntu
26.04 ARM64 then passed the same candidate lifecycle and complete registered
functional matrix against the dedicated AMD64 peer. Only the remaining Linux
release gates, including sustained behavior, remain open.

## Candidate

| Field | Value |
| --- | --- |
| Source commit | `69e5e2f00f0fead79e5baf4848725ee3aa6590b6` |
| Source archive SHA-256 | `157a416096962f60ea35920eddb422c82754bd8fe30d9e0a0505b518677717ca` |
| Package version | `0.1.0~rc3+69e5e2f` |
| Build date | `2026-09-12T11:31:54Z` |
| Ubuntu 24.04 ARM64 package SHA-256 | `8ea1a650b82ba911bb6033af1b80947a1ff81d983800a49b6919cde33908cff1` |
| Ubuntu 26.04 ARM64 package SHA-256 | `c3ac50a269cbf90605f4123834072630d985f9db9ab8f4ec44d2653d6621a0fd` |
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

## Ubuntu 26.04 ARM64 result

The second native host ran Ubuntu 26.04, kernel `7.0.0-1006-aws`, systemd 259,
and Go 1.26.8 on ARM64. It used the same immutable source archive, commit,
build date, and release flags as the earlier ARM64 qualification.

- The native race suite, vet, module, formatting, ShellCheck, qualification,
  packaging, emitted-binary, and systemd unit gates passed. Two isolated
  package builds were byte-identical on the host. The three release binaries
  also matched the independent Ubuntu 24.04 and Amazon Linux builds exactly.
- Clean installation, candidate upgrade, reinstall, downgrade, re-upgrade,
  socket authorization, and encrypted-credential preservation passed. Five
  coordinated candidate restarts took 895–1,011 ms; every single immediate
  health request passed in 26–31 ms and automatic restart counters stayed zero.
- Browser registration produced one authenticated direct peer. Bidirectional
  IPv4 and IPv6 direct traffic passed with 40 of 40 packets delivered. DNS
  authoritative UDP/TCP, negative-answer, reverse, short-name, FQDN, cleanup,
  recovery, and non-mesh preservation checks passed.
- Four policy phases produced 48 of 48 matching observations. The phases
  covered ICMP baseline behavior, directional TCP/UDP port narrowing, adjacent
  port default denial, and explicit default denial. The original baseline was
  restored after the matrix.
- A bounded direct-path fault selected relay in 4,787 ms for both address
  families, recovered direct in 2,231 ms, and removed its temporary nftables
  table. A controlled dummy-interface change was observed and refreshed in
  802 ms while all 244 dual-stack probes succeeded; the interface was removed.
- Registered rc3→rc1→rc3 rollback delivered 40 of 40 mixed-version probes and
  preserved the active profile projection, self addresses, network identity,
  control pin, DNS, policy, and encrypted credential. Both services finished
  active on rc3 with zero automatic restarts.

The Debian archives built on Ubuntu 24.04 and 26.04 have different container
bytes because the hosts use different `dpkg` implementations. Their installed
release binaries are byte-identical. Reproducibility claims therefore remain
scoped to same-environment package bytes and cross-builder binary payloads.

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

The registered functional result is retained separately under
[`docs/evidence/linux-arm64-functional-rc3-s1`](evidence/linux-arm64-functional-rc3-s1/README.md).
Both nodes synchronized through independently pinned control trust, established
one authenticated direct path, and passed bidirectional IPv4 and IPv6 traffic.
The DNS lifecycle passed on both nodes, including authoritative UDP/TCP queries,
PTR, negative answers, split routing, cleanup, recovery, and preservation of
non-mesh DNS. Four policy phases produced 48 matching observations with no
mismatch or infrastructure error, and the original ICMP-only baseline was
restored successfully.

The directional forced-relay reports are retained under
[`docs/evidence/linux-arm64-relay-rc3-s1`](evidence/linux-arm64-relay-rc3-s1/README.md).
Each side independently lost its direct UDP path, selected the authorized relay,
carried IPv4 and IPv6 traffic, removed its bounded fault table, and recovered the
direct path. Both nodes finished online with DNS and policy intact and zero
automatic service restarts.

The controlled interface-change reports are retained under
[`docs/evidence/linux-arm64-network-change-rc3-s1`](evidence/linux-arm64-network-change-rc3-s1/README.md).
Both native network monitors observed the bounded interface creation, completed
endpoint refresh in less than 900 ms, kept the direct path usable, and carried
502 of 502 dual-stack probes. The dedicated interfaces were removed and both
nodes observed the removal without a service restart.

The registered rollback result is retained under
[`docs/evidence/linux-arm64-registered-rollback-rc3-s1`](evidence/linux-arm64-registered-rollback-rc3-s1/README.md).
The ARM64 node downgraded to rc1 while its AMD64 peer remained on rc3, passed
dual-stack traffic in both directions and DNS resolution, and then returned to
rc3. Both transitions preserved the active profile projection, self addresses,
network identity, and pinned control trust. The final services were active with
zero automatic restarts.

The complete Ubuntu 26.04 ARM64 aggregate is retained under
[`docs/evidence/linux-ubuntu26-arm64-rc3-s1`](evidence/linux-ubuntu26-arm64-rc3-s1/README.md).
It records the native build and package gates, five-sample readiness result,
socket and credential boundaries, complete registered functional matrix,
forced relay, controlled network change, and registered rollback without
publishing host or mesh identifiers.

## Remaining release gates

- Complete the larger crash sample set and sustained candidate validation.
- Produce and verify the exact candidate SBOM, signature, and provenance before
  publication.

Docker and Podman were absent on the Ubuntu ARM64 host, so the disposable
Debian-container wrapper was not repeated there. Direct mocked maintainer tests,
package verification, and the actual native clean install, upgrade, downgrade,
and re-upgrade lifecycle all passed.
