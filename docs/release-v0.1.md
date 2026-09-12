# MeshTransit v0.1 release contract

Status: draft, pre-release.

This document defines the minimum product contract for the first stable
MeshTransit desktop release. It is an acceptance plan, not a statement that the
current implementation is production-ready.

## Release objective

Version 0.1 must provide a secure, recoverable host-to-host mesh client on the
three supported desktop operating systems. Platform work proceeds in this
order:

1. Linux is the reference implementation and reaches its native release gates
   first.
2. Windows implements the same product contracts and is tested on native hosts.
3. macOS implements the same product contracts after the Windows boundary is
   stable.

The common control, policy, DNS planning, relay, discovery, and encrypted
packet-path code must remain operating-system independent. Each platform owns
only local IPC, privilege, tunnel, DNS, secret-storage, network-change, service,
and packaging adapters.

## Supported capability scope

The v0.1 release includes:

- browser SSO and transient authentication-key registration;
- explicit control-key pinning and fail-closed key-change handling;
- multiple saved profiles with exactly one active profile;
- long-lived network-map synchronization and bounded reconnect;
- encrypted host-to-host IPv4 and IPv6 traffic;
- an authenticated relay base path and authenticated direct-path promotion;
- host, protocol, TCP/UDP port, and ICMP policy enforcement;
- MagicDNS records, search domains, split DNS, and an explicit default DNS
  route;
- local status and profile management through `meshctl`;
- native installation, service lifecycle, upgrade, rollback, and uninstall;
- recovery after daemon restart and ordinary host network changes.

The following are intentionally outside v0.1:

- more than one simultaneously active network;
- subnet routers and exit nodes;
- mobile clients and a desktop graphical interface;
- encrypted upstream DNS transports;
- fragmented-packet forwarding and narrow port semantics for transports other
  than TCP and UDP;
- production flow-log storage and query infrastructure.

Unsupported input and features must fail closed. They must not be silently
widened to a less restrictive behavior.

## Target platform matrix

The versions below are the initial validation targets. A target becomes
supported only after it passes its native release gates and is listed in the
published compatibility matrix.

| Priority | Platform | Architectures | Native validation targets | Current status |
| --- | --- | --- | --- | --- |
| 1 | Linux | amd64, arm64 | Ubuntu 24.04 and 26.04 LTS with `systemd-resolved` | amd64 lifecycle passed on Ubuntu 26.04 and Debian 13; arm64 lifecycle plus registered mixed-architecture direct traffic, DNS, policy, forced relay, network-change recovery, and rollback passed on Ubuntu 24.04 and 26.04; sustained validation and remaining release security gates remain |
| 2 | Windows | amd64 | Windows 11 25H2 and Windows Server 2025 | cross-build only; tunnel, DNS, IPC, and service adapters remain |
| 3 | macOS | arm64, amd64 | macOS 26 on arm64 and macOS 15 on amd64 | cross-build only; tunnel, DNS, IPC, entitlement, and service adapters remain |

Adding a platform or older OS version requires its own native test evidence. A
cross-build is a build gate, not compatibility evidence.

The target versions were reviewed on 2026-09-10 against the official
[Ubuntu release cycle](https://ubuntu.com/about/release-cycle),
[Windows 11 lifecycle](https://learn.microsoft.com/lifecycle/products/windows-11-home-and-pro),
[Windows Server 2025 lifecycle](https://learn.microsoft.com/lifecycle/products/windows-server-2025),
and [macOS compatibility list](https://support.apple.com/109033). They must be
reviewed again when cutting the release candidate.

## Current implementation baseline

The current `main` branch already contains the common profile, identity,
control, validated map, policy, DNS-planning, relay, endpoint-discovery,
authenticated direct-path, local API, and flow-observation components. Linux
has opt-in TUN, userspace WireGuard, `SO_PEERCRED`, privileged `meshnetd`, and
`systemd-resolved` adapters. It also has native route/link/address monitoring,
immediate endpoint refresh after meaningful changes, and a polling fallback.

The Linux packet and DNS paths now use release-facing flags and contain no
unverified-local-peer bypass. They remain release-ineligible until every native
candidate gate passes. Linux has a
reproducible Debian package, lifecycle contract, and bounded restart, reboot,
controlled interface-change, relay-fallback, split-DNS, and host-policy
qualification harnesses. Both packaged daemons now bind their owned Unix
listener before reporting `READY=1` through a bounded, fail-closed systemd
notification adapter; the dedicated registration-independent harness requires
one immediate health attempt after every completed restart. The Debian
maintainer lifecycle also joins an in-progress notification job before an
install or upgrade returns. The two-host Linux alpha topology has repeatable
direct-loss fallback and split-DNS cleanup/recovery evidence plus complete live
bidirectional host-policy matrices on alpha10 and two repeatable alpha15
samples. Alpha15 also has one bounded passing restart scenario for each service
on each node, one passing reboot sample per node, and one passing controlled
network-change sample per node with no packet loss. Its direct-loss matrix also
has one passing relay-fallback and direct-restoration sample per node, and its
split-only DNS lifecycle has one passing sample per node. Alpha15 split and
explicit-default upstream DNS modes also applied live on both nodes and rolled
back to the exact baseline without a daemon restart. Alpha16 adds one bounded
two-node ordered-upstream timeout, failover, fail-closed, DNS-destination
isolation, and rollback sample. Alpha16 also has one passing `SIGKILL` recovery
sample for each service on each node, including observed daemon DNS cleanup and
coordinated daemon/helper generation replacement, followed by three passing
samples for every node/service combination with state and resource invariants.
Each node also has one passing chained sample proving that the newly recovered
helper/daemon generation handles its first controlled network change, refreshes
endpoints, and remains stable without an additional restart.
The authenticated local status contract and read-only Linux soak harness now
expose the bounded aggregate runtime and operating-system resource measurements
needed for the long-duration gate. The first two-node alpha17 native smoke
passed with 14/14 healthy samples and unchanged resource cardinality; the
72-hour release-candidate evidence remains. The release-candidate harness is
now guarded by a restart-intolerant systemd launcher that prevents the observed
Ubuntu `needrestart` maintenance path from silently replacing the observer and
resetting its evidence window. Native Ubuntu 26.04 lifecycle protection passed
at commit `618d851`; see
[linux-soak-observer-resilience-qualification-2026-09-12.md](linux-soak-observer-resilience-qualification-2026-09-12.md).
The Linux secret-storage migration stage now writes profile-bound,
authenticated identity envelopes and supplies their key through a
host-encrypted systemd credential. New identity state is never plaintext. The
alpha18 compatibility artifact retained legacy bytes during read-only startup
and passed alpha17 downgrade; with alpha18 retained as the rollback target,
legacy state is now atomically protected on first read. Native Debian 13 and
Ubuntu 26.04 package, credential, tamper, restart, removal, purge, and staged
rollback evidence passed in the bounded alpha19 qualification. TPM binding,
encrypted off-host backup policy, forced power-loss rotation samples, and
signed release artifacts remain before this gate is production-complete. The
bounded alpha21 matrix passed two-key staging, eager identity rewrap,
active-only finalization, recovery, explicit fallback deletion, and rollback to
a reader-compatible artifact while rotation was pending on Ubuntu 26.04;
systemd 257 staging/finalization/commit also passed on Debian 13. See
[linux-secret-storage-qualification-2026-09-12.md](linux-secret-storage-qualification-2026-09-12.md)
and
[linux-identity-key-rotation-qualification-2026-09-12.md](linux-identity-key-rotation-qualification-2026-09-12.md).
Linux package CI now emits a digest-bound CycloneDX SBOM, verifies it against
the modules embedded in all packaged binaries, and applies a symbol-aware
High/Critical vulnerability gate. Exact-commit alpha20 packages and SBOMs were
byte-reproducible for amd64 and arm64 across two runs and passed independent
artifact inspection on Debian 13; this does not yet establish cross-builder
reproducibility. See
[linux-supply-chain-qualification-2026-09-12.md](linux-supply-chain-qualification-2026-09-12.md).
The release-facing runtime surface now has an emitted-binary gate that rejects
removed development flags and unverified-peer bypass markers. Exact candidate
package upgrade passed on Ubuntu 26.04 and Debian 13; Ubuntu also passed an
exact-artifact rollback and re-upgrade. See
[linux-production-surface-qualification-2026-09-12.md](linux-production-surface-qualification-2026-09-12.md).
The subsequent rc2 readiness candidate passed immediate post-upgrade health,
five no-retry restart samples per host, rollback, and immediate re-upgrade
health on the same dedicated platforms. See
[linux-service-readiness-qualification-2026-09-12.md](linux-service-readiness-qualification-2026-09-12.md).
The rc3 ARM64 candidate then passed native race/vet and package verification,
Ubuntu 24.04 clean install, upgrade, five-sample service readiness, socket
authorization, downgrade, and re-upgrade. Its three release binaries were
byte-identical across independent Ubuntu and Amazon Linux ARM64 builders. The
Amazon host remains a build-only portability result, not a supported RPM
target. See
[linux-arm64-qualification-2026-09-12.md](linux-arm64-qualification-2026-09-12.md).
The same rc3 candidate subsequently passed the complete native package and
registered functional matrix on Ubuntu 26.04 ARM64, including direct traffic,
DNS, policy, forced relay, controlled network change, mixed-version rollback,
credential preservation, and final cleanup. See
[linux-ubuntu26-arm64-rc3-s1](evidence/linux-ubuntu26-arm64-rc3-s1/README.md).
It then passed 20 of 20 bounded `SIGKILL` recovery samples across `meshd` and
`meshnetd` on Ubuntu 26.04 ARM64 and AMD64. All service-generation, state,
route, DNS, process, interface, listener, descriptor, dual-stack traffic, and
journal-error gates passed. See
[linux-crash-repeat-rc3-s1](evidence/linux-crash-repeat-rc3-s1/README.md).
Both architectures then passed a controlled host reboot while the other node
remained online as a dual-stack observer. Complete target readiness recovered
within 29,969 ms, and registered profiles, addresses, and runtime artifacts were
preserved. See
[linux-reboot-rc3-s1](evidence/linux-reboot-rc3-s1/README.md).
The RC4 candidate then separated control presence from peer-path readiness:
registered peerless nodes report online while their synchronized control
session is healthy, with data-plane and DNS state still reported independently.
The same candidate passed an end-to-end browser login in which one bounded
`meshctl login` invocation waited for approval and completed without a separate
`login complete` command. See
[linux-rc4-control-login-s1](evidence/linux-rc4-control-login-s1/README.md).
RC4 also passed the release-candidate upstream DNS failover, fail-closed, and
rollback matrix on Ubuntu 26.04 AMD64 and ARM64, with five UDP and five TCP
samples per phase, no unexpected resolver destinations in any retained report,
and exact baseline restoration. See
[linux-dns-rc4-upstream-failure-s1](evidence/linux-dns-rc4-upstream-failure-s1/README.md).
It does not yet have a signed artifact and provenance pipeline, IPv6-only
underlay evidence, real multi-uplink migration qualification, or a long-duration
qualification suite.
See [linux-qualification.md](linux-qualification.md) for the bounded alpha
evidence and its limitations.
Windows and macOS deny local API access, contain no unverified-peer override,
and do not have native tunnel, DNS, or installer activation.

## Definition of done

Every supported platform must satisfy all common gates and its native gates.
Failures must preserve the previous working configuration or leave the host in
a documented clean state.

### Common functional gates

- A fresh install can register through both supported login modes and reconnect
  without recreating identity.
- A previously registered client becomes ready after a daemon restart without
  user interaction.
- IPv4 and IPv6 host traffic work through both relay and authenticated direct
  paths.
- Direct-path loss returns traffic to relay; later authenticated proof can
  promote the path to direct again.
- DNS applies atomically, answers authoritative records, forwards split routes,
  and restores the prior host configuration on disable, failure, and uninstall.
- Policy tests cover allowed and denied TCP, UDP, and ICMP traffic in both
  directions, including bounded return flows.
- Profile changes cannot merge identities, routes, policy, DNS state, endpoints,
  or telemetry credentials across networks.
- `meshctl` reports actionable, redacted health and path status without exposing
  secrets, raw endpoint addresses, packet contents, or policy contents.

### Reliability acceptance targets

These are controlled-lab targets for the release candidate, not measurements of
the current candidate implementation:

- after registration, service-start to mesh-ready latency is at most 15 seconds
  at p95 when the control plane is reachable;
- loss of a selected direct path restores an available relay path within 10
  seconds at p95;
- an ordinary network change restores a usable path within 20 seconds at p95;
- a 72-hour fixed-topology soak has no daemon crash, deadlock, goroutine leak,
  descriptor leak, or unbounded queue growth;
- after the first steady-state hour of that soak, resident memory growth is at
  most 10 percent under a fixed peer and traffic load;
- daemon or helper termination does not leave a permissive route, resolver
  policy, interface, or credential file behind.

The qualification report must record topology, traffic load, network
impairments, sample count, percentiles, memory baseline, and exact artifact
digests so results are reproducible.

### Security gates

- Production artifacts contain no unsafe development override and reject
  unknown or unverifiable local peers.
- Long-lived private identity material is sealed by the platform secret-storage
  adapter; plaintext fallback is development-only and release-ineligible.
- Privileged components receive no control credential or node private key and
  accept only a fixed, bounded operation schema.
- Local IPC authorizes an operating-system identity, uses least-privilege ACLs,
  and is tested against an unprivileged local attacker.
- Control, relay, and telemetry transports verify their intended identity,
  refuse redirects where required, and enforce bounded reads, writes, and
  timeouts.
- Logs and diagnostics contain no authentication material, private key, packet
  payload, DNS query name, or unredacted peer endpoint.
- `go test -race`, `go vet`, the configured linter, vulnerability scanning,
  packet/parser fuzz targets, and adversarial protocol tests pass for the
  release commit.
- The complete Git history and release working tree pass the pinned Gitleaks
  scan with no untriaged baseline or allowlisted production credential.
- Release artifacts are reproducible where practical, carry checksums and an
  SBOM, are signed with protected release credentials, and can be traced to one
  reviewed commit.
- Required dependency notices are complete and the project license is selected
  before publishing v0.1 artifacts. Public source availability alone is not a
  software license.

### Native platform gates

Linux must additionally pass:

- clean `.deb` installation, service enable/start, in-place upgrade, downgrade
  rollback, and uninstall on every target Ubuntu version and architecture;
- dedicated service identities and socket-group authorization;
- abrupt `meshd` and `meshnetd` restart, boot recovery, interface cleanup, route
  cleanup, and `systemd-resolved` rollback;
- direct, forced-relay, DNS, and policy matrices across two disposable hosts,
  including IPv6-only underlay validation.

Windows must additionally pass:

- native local IPC authorization without the unsafe override;
- tunnel, DNS, network-change, and Windows Service adapters under their intended
  least-privilege identities;
- signed MSI install, repair, upgrade, rollback, and uninstall;
- sleep/resume, interface changes, firewall-profile changes, and service crash
  recovery on Windows 11 and Windows Server 2025.

macOS must additionally pass:

- native local IPC authorization without the unsafe override;
- entitled tunnel and DNS activation with the smallest viable privilege set;
- signed and notarized package install, upgrade, rollback, and uninstall;
- sleep/wake, Wi-Fi changes, interface changes, and daemon or extension crash
  recovery on both target architectures.

## Release stages

| Stage | Exit condition |
| --- | --- |
| Linux alpha | Linux package and service lifecycle work; two-host direct, relay, DNS, and policy tests are repeatable |
| Linux beta | Linux native matrix, security gates, restart tests, and 72-hour soak pass |
| Windows alpha | Windows adapters and installer pass one native two-host mesh test |
| Windows beta | Windows native matrix, recovery tests, and 72-hour soak pass |
| macOS alpha | macOS adapters and package pass one native two-host mesh test |
| Cross-platform RC | Linux, Windows, and macOS interoperate pairwise; all common and native gates pass from signed candidate artifacts |
| v0.1 stable | RC has no open release-blocking defect, documentation and compatibility matrix match evidence, and rollback artifacts are available |

No stage is promoted solely because it compiles. Release evidence is attached to
the exact candidate commit and artifact digest.

## Artifact plan

- Linux: signed amd64 and arm64 `.deb` packages plus checksums and SBOMs.
- Windows: signed amd64 MSI plus checksum and SBOM.
- macOS: signed and notarized arm64 and amd64 package plus checksums and SBOMs.
- Container images are not a substitute for native client packages because the
  host tunnel, DNS, IPC, and service boundaries require native qualification.

The first implementation milestone after this contract is repository and CI
baseline work, followed by Linux packaging and native qualification. A Windows
host is first required when its local IPC/tunnel skeleton is ready for native
execution; it is not required for the initial Linux milestone.
