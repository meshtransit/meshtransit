# Security policy

MeshTransit is pre-release software. Do not rely on it as a production security
boundary until the first stable release.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub security advisories
for this repository ("Report a vulnerability" on the Security tab). Do not open
a public issue.

Never include private keys, authentication or enrollment keys, access tokens,
cookies, packet payloads, production state files or production topology in a
report. Describe the class of problem and the minimal steps to reproduce it.

We aim to acknowledge reports within three working days and to agree on a
disclosure timeline with the reporter.

## Supported versions

Supported versions will be listed here after the first release. The `main`
branch currently receives security fixes.

## Security tooling

CI runs race detection, `go vet`, `golangci-lint` (including `gosec`),
`govulncheck`, secret scanning, import-boundary checks and, when enabled,
CodeQL. The CodeQL workflow requires the repository variable `ENABLE_CODEQL`
set to `true`.

Threat models: `docs/protocol/threat-model.md` (network protocols), the trust
boundaries in `docs/architecture/overview.md`, and the client's
`docs/clients/security-model.md`.
