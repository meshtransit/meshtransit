# Changelog

Notable changes to MeshTransit. Component histories from before the monorepo
merge (2026-10-09) are kept below.

## Unreleased

- Merged Core, meshd and meshctl into one repository with per-directory
  licensing (core/ AGPL-3.0, client/ Apache-2.0).

## meshd (before the merge)

### Unreleased

### Added

- v0.1 release contract, platform priority, native validation matrix, and
  operating-system adapter boundaries.
- Linux quality, vulnerability, opt-in CodeQL, and cross-platform build
  workflows with pinned action and tool versions.
- Digest-bound CycloneDX SBOMs and symbol-aware Grype reports for Linux
  packages, with checksum-pinned tooling and a High/Critical CI gate.
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
- Process-local aggregate runtime-recovery status for native fault qualification.
- Bounded, reversible Linux helper-socket fault qualification that requires
  in-process TUN and DNS recovery without a service restart.
- Fail-fast repeated Linux local-runtime recovery qualification with per-sample
  resource invariants, bounded kernel-resource convergence, and redacted
  nearest-rank p95 recovery timings; explicit peer routes and global self
  addresses are checked independently from address-derived kernel routes, and
  aggregate peer-count changes are classified as topology changes.
- Traffic-bearing Linux local-runtime recovery qualification with continuous
  IPv4, IPv6, and uncached MagicDNS probes, mandatory outage observation,
  stable-recovery timing, and nested per-sample runtime/resource validation.

### Changed

- Authenticated direct paths now keep only their remaining proof lease across
  otherwise identical control-map revisions. Routine endpoint publications no
  longer force a relay fallback and immediate re-promotion, while lease expiry,
  socket changes, and peer or endpoint-authority changes still fail closed to
  the signed base path.
- Signed peer home-relay changes now replace the retained fallback metadata
  without overwriting a compatible authenticated direct endpoint. The existing
  proof deadline is unchanged, and expiry restores the newest signed relay
  base while identity, route, authority, socket, and topology changes retain
  fail-closed behavior.
- A temporary local map-application failure now tears down TUN, routes, DNS,
  path probes, and session secrets before the daemon retries from a fresh full
  snapshot. Recovery uses interruptible jittered exponential backoff capped at
  thirty seconds; a profile or registration change bypasses the wait, while
  permanent control trust and protocol failures remain blocked. An ambiguous
  cleanup exits the supervisor instead of reusing uncertain local state.
- Control-map reconnect backoff now resets only after a validated stream stays
  established for thirty seconds, preventing rapid map-then-disconnect loops
  from holding retries at the minimum delay. The watchdog and reconnect policy
  now have deterministic transport-fault coverage.
- Browser-login completion treats bounded transport timeouts, truncated
  exchanges, HTTP 408/425/429, and HTTP 5xx as temporary. Pending state is
  retained, both pending responses and temporary failures consume the
  three-second completion window to throttle retries, and caller cancellation
  still wins immediately. A verified response that races the poll deadline is
  persisted under the caller context instead of being discarded, temporary
  key copies are cleared after registration, and trust or protocol failures
  remain terminal.
- Control supervision now enforces one active runner per daemon service, and
  browser/auth-key registration transitions are serialized with cancellable
  waiting so concurrent local clients cannot create duplicate control sessions
  or reuse the same pending authorization concurrently.
- Linux host-credential provisioning and staged key rotation now tolerate an
  ambiguous return after directory synchronization: retries verify and accept
  the completed state without generating another key or deleting recovery
  material early.
- Top-level online status now reflects a synchronized control session even for
  a peerless Network; data-plane and DNS readiness remain separate fields.
- Compatible peer and policy changes now replace WireGuard peers, relay peer
  authority, and helper-confined host routes without recreating the TUN or UDP
  transport. The privileged route operation is bound to an interface opened by
  the same helper generation, requires unchanged self addresses, and rolls
  completed netlink changes back on failure. Live peer updates omit the private
  key and listen port so the userspace engine cannot rebind its socket.
- Peerless reduced maps now install an empty peer and route configuration while
  retaining the encrypted UDP presence transport. Socket-generation changes
  replace endpoint advertisements only after current-socket discovery, and
  periodic discovery pauses while no peers are visible. This prevents
  transient endpoint withdrawal from driving control-map and tunnel churn.
- Successful network-triggered endpoint refreshes are counted before their
  resulting endpoint update becomes observable.
- Semantically unchanged control-map deltas are revalidated without publishing
  a new local generation, avoiding unnecessary probe, data-plane, and DNS
  reconfiguration while preserving expiry enforcement and reconnect isolation.

## meshctl (before the merge)

### Unreleased

### Added

- `meshctl up`: one idempotent command that finds or creates the profile,
  activates it, pins the control key (built-in for MeshTransit Cloud) and
  registers, waiting for browser approval.
- Linux quality, vulnerability, opt-in CodeQL, and cross-platform build
  workflows with pinned action and tool versions.
- Go 1.26.8 toolchain baseline.
- Reproducible amd64/arm64 Debian package builder and package inspection gate.
- Initial `status`, `version`, and profile commands.
- Versioned Unix-socket client with bounded JSON responses.
- Human-readable and JSON output modes.
- Stable usage and runtime exit-code separation.
- `doctor control` command for capability and control-key fingerprint checks.
- Explicit control-key trust with an operator-supplied SHA-256 fingerprint.
- Browser and standard-input auth-key login workflows.
- Bounded browser-login waiting with automatic completion, cancellation, and
  resumable timeout behavior.
- Control-trust, registration, and pinned-key status fields.
- Control-session, validated netmap-revision, and peer-count status output.
- Aggregate direct/relay path counts and redacted relay-region health.
- Aggregate host-network-change and completed endpoint-refresh status counters.
- Aggregate daemon runtime health in human-readable and JSON status output.
- Process-local runtime failure, completed recovery, and pending status with
  backward-compatible handling of older v1 daemons.
