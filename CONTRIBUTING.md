# Contributing to meshd

## Prerequisites

- Go 1.24 or newer
- `golangci-lint` v2 for the lint target

## Local workflow

```bash
go mod verify
make test
make race
make vet
make lint
```

Keep changes small and test observable behavior. Protocol implementations belong in isolated internal adapters. Do not add a dependency before documenting why the standard library is insufficient, checking its license, pinning its version, and receiving maintainer approval.

Security-sensitive changes must update `docs/security-model.md`. Changes to profile or API behavior must preserve the one-active-profile and server-resolved-network invariants.
