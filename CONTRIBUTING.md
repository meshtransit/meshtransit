# Contributing to meshd

## Prerequisites

- Go version declared by `go.mod`
- `golangci-lint` v2 for the lint target
- Gitleaks v8.30.1 for the secret-scanning target
- Syft v1.51.1 and Grype v0.116.1 for Linux package auditing

## Local workflow

```bash
go mod verify
make test
make race
make vet
make lint
make scan-secrets
```

On Linux, create and audit a package with the exact pinned supply-chain tools:

```bash
./tools/security/install-supply-chain-tools.sh /tmp/mesh-tools
PATH="/tmp/mesh-tools:${PATH}" make package-deb VERSION=0.1.0~dev ARCH=amd64
PATH="/tmp/mesh-tools:${PATH}" make audit-deb VERSION=0.1.0~dev ARCH=amd64
```

Keep changes small and test observable behavior. Protocol implementations belong in isolated internal adapters. Do not add a dependency before documenting why the standard library is insufficient, checking its license, pinning its version, and receiving maintainer approval.

Security-sensitive changes must update `docs/security-model.md`. Changes to profile or API behavior must preserve the one-active-profile and server-resolved-network invariants.
