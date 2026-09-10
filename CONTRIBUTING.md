# Contributing to meshctl

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

Keep CLI output stable and test exit codes. The CLI must stay unprivileged and communicate through the local API. Do not duplicate daemon policy decisions in commands, and do not introduce a network-selection field into profile creation.

Before adding an external module, document why the standard library is insufficient, check its license, pin its version, and receive maintainer approval.
