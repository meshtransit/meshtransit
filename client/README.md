# MeshTransit client

The node side of MeshTransit: `meshd`, the daemon that registers a Device with
Core, keeps its map, runs WireGuard to its peers over direct paths and relays,
enforces the packet filter and answers MeshTransit DNS; `meshnetd`, its network
helper; `meshcred`, which provisions the key that encrypts its identity at
rest; and `meshctl`, the command-line client. `client/mobile` embeds the same
daemon in the Android and iOS apps.

| Directory | What |
|---|---|
| `cmd/meshd`, `cmd/meshnetd`, `cmd/meshcred`, `cmd/meshctl` | The binaries |
| `internal/` | Daemon, control session, map, data plane, paths, relays, DNS, platform adapters |
| `mobile/` | The gomobile API for the apps |
| `tools/` | Qualification scripts |

How it works: [Client](../docs/architecture/client.md). Installing it:
[Linux](../docs/clients/linux.md), [macOS](../docs/clients/macos.md),
[Windows](../docs/clients/windows.md), [Android](../docs/clients/android.md).
Commands: [meshctl](cmd/meshctl/README.md). Flags:
[configuration](../docs/operations/configuration.md).

## Build and test

From the repository root, with Go 1.26.9 or newer:

```bash
make build-client        # bin/meshd, bin/meshnetd, bin/meshcred, bin/meshctl
make test                # all tests
make test-linux-client   # the Linux-only client tests in a container
make lint-client
go test ./test/natlab    # registration, maps and NAT traversal in an in-process lab
```

`make natlab-matrix` regenerates the traversal matrix in
`test/natlab/testdata/matrix.md`; review its diff before committing.

Packages: `make package-deb` (on Linux), `make package-darwin` and
`make package-windows` (on macOS; the latter downloads Wintun); mobile
libraries: `make mobile-android` (needs the Android NDK), `make mobile-ios`.

## Running it by hand

For development, `meshd` runs without packages if you give it its own socket,
state directory and an owner-only 32-byte identity key. The socket's directory
must be a real directory that only its owner can write (not `/tmp` itself),
and its path short (a Unix socket path is limited to about 100 bytes):

```bash
umask 077
mkdir -p /tmp/meshd-dev
head -c 32 /dev/urandom > /tmp/meshd-dev/identity-key
./bin/meshd --socket /tmp/meshd-dev/meshd.sock --state-dir /tmp/meshd-dev/state \
  --identity-key-file /tmp/meshd-dev/identity-key &
export MESHCTL_SOCKET=/tmp/meshd-dev/meshd.sock
./bin/meshctl profile create --name dev --control-url https://control.example.com
./bin/meshctl doctor control    # probes the active profile's server
```

Without `--enable-data-plane` it stays control-only: it registers and keeps
its map but opens no tunnel. The data plane needs `meshnetd` running as root
(`meshnetd --allow-user USER`, with `--enable-dns` for DNS) on Linux or macOS;
the packages set this up, with the flags in
[configuration](../docs/operations/configuration.md).

## Security

Read the [security model](../docs/clients/security-model.md) and the
[platform contracts](../docs/clients/platform-contracts.md) before changing the
local API, identity storage, the helper protocol or the data plane.

## License

Except for third-party components identified in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), the client is licensed under
the [Apache License 2.0](../LICENSES/Apache-2.0.txt). The required attributions
are recorded in [NOTICE](../NOTICE). Contributing:
[CONTRIBUTING.md](../CONTRIBUTING.md).
