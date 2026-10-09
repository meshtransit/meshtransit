# Security policy

`meshd` is pre-release software and does not yet provide a production tunnel. Do not treat the current data-plane status as a security boundary.

Report suspected vulnerabilities privately to the repository maintainers. Do not include private keys, authentication keys, packet payloads, access tokens, or production state files in an issue. A private GitHub security-advisory channel must be enabled before public release.

Supported versions will be listed here after the first release. The `main` branch currently receives security fixes.

The CodeQL workflow requires a repository variable named `ENABLE_CODEQL` with
the value `true`. Keep it unset while this private repository lacks GitHub
Advanced Security; enable it before public release or immediately after GitHub
Advanced Security is activated. Race detection, `go vet`, `golangci-lint`,
`gosec`, and `govulncheck` remain mandatory in CI independently of CodeQL.

See `docs/security-model.md` for trust boundaries, implemented controls, and known gaps.
