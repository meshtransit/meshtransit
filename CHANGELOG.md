# Changelog

All notable user-visible changes will be documented in this file.

## Unreleased

### Added

- v0.1 release contract, platform priority, native validation matrix, and
  operating-system adapter boundaries.
- Linux quality, vulnerability, opt-in CodeQL, and cross-platform build
  workflows with pinned action and tool versions.
- Go 1.26.8 toolchain baseline.
- Reproducible amd64/arm64 Debian package builder with hardened split-privilege
  systemd services and package lifecycle scripts.
- Debian service-state preservation across upgrade, removal, and reinstall,
  alternate-root-safe purge behavior, and disposable package lifecycle tests.
- Bounded Linux restart qualification for service, TUN, MagicDNS, and dual-stack
  traffic recovery, with redacted machine-readable reports and parser fixtures.
- Bounded two-node Linux reboot qualification for service, route, identity,
  MagicDNS, and dual-stack traffic recovery with explicit target confirmation.
- Linux route/link/address monitoring with bounded netlink event coalescing,
  polling fallback, immediate endpoint refresh, redacted status counters, and a
  reversible network-change qualification harness.
- Bounded Linux direct-path loss qualification with UDP-only peer isolation,
  measured relay fallback, dual-stack relay traffic proof, direct recovery, and
  automatic nftables cleanup.
- Linux host-policy qualification now records bounded `meshd` memory evidence
  and fails a phase if the service restarts on either node.
- WireGuard peer sessions now survive control-map endpoint-authority refreshes;
  stale direct selections return to the relay path without replacing the peer.
- Separate owner-writable runtime directories for the operator API and
  privileged-helper sockets.
- Initial daemon composition root.
- Atomic profile store with one-active-profile enforcement.
- Versioned local Unix-socket API for health, status, profile creation, listing, and selection.
- Initial architecture and security model.
- Pinned capability-142 adapter for bounded HTTPS control-key and authenticated Noise-handshake probes.
- BSD 3-Clause attribution for the compatibility dependency.
- Fail-closed Linux local API authorization based on kernel `SO_PEERCRED` credentials.
- Optional Linux socket-group authorization for kernel-verified local callers,
  plus service-account resolution for the privileged helper.
- Per-profile persistent machine/node identities with confined, atomic `0600` storage.
- Explicit control-key fingerprint pinning with Noise possession verification and no implicit rotation.
- Pinned Noise HTTP/2 registration, transient auth-key login, and persisted same-origin browser follow-up.
- Local API status fields and endpoints for control trust and registration.
- Pinned capability-142 network-map streaming with frame bounds, watchdog deadlines, and bounded jittered reconnect.
- Upstream-independent validated network snapshots with atomic delta updates and deny-by-default policy state.
- Control-session, netmap-revision, and peer-count status fields.

### Changed

- Successful network-triggered endpoint refreshes are counted before their
  resulting endpoint update becomes observable.
- Semantically unchanged control-map deltas are revalidated without publishing
  a new local generation, avoiding unnecessary probe, data-plane, and DNS
  reconfiguration while preserving expiry enforcement and reconnect isolation.
