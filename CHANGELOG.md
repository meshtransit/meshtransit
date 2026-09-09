# Changelog

All notable user-visible changes will be documented in this file.

## Unreleased

### Added

- Initial daemon composition root.
- Atomic profile store with one-active-profile enforcement.
- Versioned local Unix-socket API for health, status, profile creation, listing, and selection.
- Initial architecture and security model.
- Pinned capability-142 adapter for bounded HTTPS control-key and authenticated Noise-handshake probes.
- BSD 3-Clause attribution for the compatibility dependency.
- Fail-closed Linux local API authorization based on kernel `SO_PEERCRED` credentials.
- Per-profile persistent machine/node identities with confined, atomic `0600` storage.
- Explicit control-key fingerprint pinning with Noise possession verification and no implicit rotation.
- Pinned Noise HTTP/2 registration, transient auth-key login, and persisted same-origin browser follow-up.
- Local API status fields and endpoints for control trust and registration.
- Pinned capability-142 network-map streaming with frame bounds, watchdog deadlines, and bounded jittered reconnect.
- Upstream-independent validated network snapshots with atomic delta updates and deny-by-default policy state.
- Control-session, netmap-revision, and peer-count status fields.
