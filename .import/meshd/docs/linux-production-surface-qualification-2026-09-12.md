# Linux production runtime surface qualification — 2026-09-12

## Scope

This report records the first exact-commit qualification of the Linux
release-facing runtime surface. The change replaces the development data-plane
and DNS flags with `--enable-data-plane` and `--enable-dns`, removes the public
TUN-only mode, and removes the unverified-local-peer authorization bypass from
source and emitted binaries. Package verification now scans all installed
executables and systemd units for removed development markers.

This is bounded candidate evidence. It proves source gates, emitted-artifact
gates, native package lifecycle, rollback, service startup, and local API
recovery. The dedicated hosts were not registered, so it does not replace the
registered two-node traffic, DNS, policy, relay, restart, or soak gates.

## Candidate and rollback

- Candidate: `0.1.0~rc1+2e3fe8f`, commit
  `2e3fe8f41315cbeaccbb2e2e194cfe9731510ae3`, built at
  `2026-09-12T10:07:31Z`.
- Candidate amd64 package SHA-256:
  `30b13f00532e6974de2872f52d0f4fb1b531c4f0368769855e42b1bc84057798`.
- Rollback: `0.1.0~alpha21`, commit
  `95922588f94807a967e561bd5e8164948ef371d2`, rebuilt from the exact commit
  timestamp with SHA-256
  `983574ba3c352526e131402c15e1a96713531cf176accb2671efd116ed6a33f2`.

The candidate was built only after the implementation commit existed. Package
metadata embeds the complete commit and commit-derived build timestamp. The
same checked package bytes were transferred to both native hosts.

## Source and artifact gates

The clean candidate source passed `go test ./...`, `go vet ./...`,
`go test -race ./...`, golangci-lint `v2.12.2`, ShellCheck, and the binary-audit
self-test on Ubuntu 26.04 amd64. Gitleaks `v8.30.1` found no leak in the exported
candidate tree. `govulncheck v1.8.0` found zero reachable vulnerabilities; it
reported one advisory in the required module graph whose affected symbols are
not called by this program.

Package verification checked its checksum, control metadata, maintainer
scripts, permissions, systemd units, and all three installed executables. The
byte-level scan found none of the removed data-plane, DNS, TUN-only, or
unverified-peer markers. A symbol-aware Syft `1.51.1` and Grype `0.116.1` scan
generated a CycloneDX SBOM and reported zero vulnerability matches.

The installed `meshd` and `meshnetd` binaries independently rejected every
removed flag tested. There are no compatibility aliases: a host retaining an
old flag fails startup instead of silently changing its security meaning.

## Native lifecycle results

Ubuntu 26.04 first booted its already installed `7.0.0-31-generic` kernel from
`7.0.0-27-generic`. The existing alpha21 services recovered before any package
change. The host then passed candidate upgrade, rollback to the exact alpha21
artifact, and re-upgrade to the candidate. Its existing unregistered profile
count and pinned control trust were preserved. All three units remained active,
both long-running services reported zero automatic restarts and successful exit
status, and the bounded warning-or-higher journal query returned zero records.

Debian 13 first booted `6.12.107+deb13-amd64` from
`6.12.94+deb13-amd64`, recovered the alpha21 services, and upgraded the same
candidate bytes. The exact rollback package was staged and checksum-verified.
All three units were active, both long-running services reported zero automatic
restarts and successful exit status, and the same bounded journal query returned
zero records.

A controlled helper/daemon restart on each host recovered the authenticated
local health endpoint. An immediate zero-wait request raced the Unix socket on
both hosts even though systemd already reported `active`; retrying the health
probe succeeded without an automatic service restart. Until readiness signaling
is implemented or qualified, automation must treat the local health endpoint,
not only systemd `ActiveState`, as the readiness contract.

The redacted result is retained in
[`docs/evidence/linux-production-surface-rc1-s1`](evidence/linux-production-surface-rc1-s1).

## Remaining limits

Neither dedicated host had an active registration, so no candidate TUN, DNS
link, peer route, encrypted direct/relay path, or dual-stack traffic was expected
or claimed. The candidate still requires a registered two-node native matrix,
readiness timing samples, the complete restart/crash/network/DNS/policy suite,
long-duration soak, arm64 native validation, signed artifacts, and provenance
before the first stable Linux release.
