# Contributing to MeshTransit

Thank you for helping. This guide covers the whole repository; component
specifics are in `core/README.md` and `client/README.md`.

## Before you start

- Open an issue to discuss significant changes before writing code.
- Security issues: follow [SECURITY.md](SECURITY.md), not the issue tracker.
- By contributing you agree that your contribution is licensed under the
  license of the directory you change (see [LICENSE](LICENSE)).

## Prerequisites

- Go version declared in `go.mod`
- Docker, for Core integration tests and container builds
- `golangci-lint` v2 (run through `make lint` / `make lint-client`)
- Gitleaks v8.30.1 for `make scan-secrets`
- Syft and Grype for Linux package audits (`hack/security/install-supply-chain-tools.sh`)

## Local workflow

```bash
go mod verify
make test test-race vet
make lint lint-client
make check-boundaries
make scan-secrets
make integration-platform-container   # Core changes touching storage or control
```

On Linux, build and audit packages with the pinned supply-chain tools:

```bash
./hack/security/install-supply-chain-tools.sh /tmp/mesh-tools
PATH="/tmp/mesh-tools:${PATH}" make package-deb VERSION=0.1.0~dev ARCH=amd64
```

## Pull requests

- Keep changes small and focused; one concern per pull request.
- Test observable behaviour. Every parser of network input needs a fuzz test.
- Security-sensitive changes update the relevant threat model and security
  documents.
- Do not add a dependency without explaining why the standard library is not
  enough, checking its license and pinning its version.
- Use conventional commit messages (`feat:`, `fix:`, `refactor:`, `docs:`,
  `test:`, `chore:`, `perf:`, `ci:`).
- CI must pass: Core, Client, boundaries and CodeQL workflows.
