# Changelog

All notable user-visible changes will be documented in this file.

## Unreleased

### Added

- Linux quality, vulnerability, CodeQL, and cross-platform build workflows with
  pinned action and tool versions.
- Go 1.26.8 toolchain baseline.
- Initial `status`, `version`, and profile commands.
- Versioned Unix-socket client with bounded JSON responses.
- Human-readable and JSON output modes.
- Stable usage and runtime exit-code separation.
- `doctor control` command for capability and control-key fingerprint checks.
- Explicit control-key trust with an operator-supplied SHA-256 fingerprint.
- Browser and standard-input auth-key login workflows.
- Control-trust, registration, and pinned-key status fields.
- Control-session, validated netmap-revision, and peer-count status output.
- Aggregate direct/relay path counts and redacted relay-region health.
