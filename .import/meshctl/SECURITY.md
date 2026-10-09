# Security policy

`meshctl` is pre-release software. Report suspected vulnerabilities privately to the repository maintainers and do not include credentials, private keys, packet data, or production profile output in an issue. A private GitHub security-advisory channel must be enabled before public release.

The CLI is designed to remain unprivileged. A change that reads daemon state directly, handles node private keys, configures the host network, or bypasses the local API is security-sensitive and requires an architecture review.

Supported versions will be listed here after the first release. The `main` branch currently receives security fixes.

The CodeQL workflow requires a repository variable named `ENABLE_CODEQL` with
the value `true`. Keep it unset while this private repository lacks GitHub
Advanced Security; enable it before public release or immediately after GitHub
Advanced Security is activated. Race detection, `go vet`, `golangci-lint`,
`gosec`, and `govulncheck` remain mandatory in CI independently of CodeQL.
