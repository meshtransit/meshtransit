# meshctl

`meshctl` is the unprivileged command-line client for the local MeshTransit daemon. It controls profiles and reads status only through the versioned `meshd` Unix API.

## Demo

```console
$ meshctl status
Daemon: dev
State: offline
Data plane: not_implemented
DNS: not_implemented
Network changes: unavailable
Runtime recovery: unavailable
Runtime: unavailable
Active profile: none
Profiles: 0
Control trust: unconfigured
Registration: unregistered
Control session: inactive
Netmap revision: 0
Network: none
Self addresses: none
Peers: 0
Peer paths: unavailable
Relay: unavailable
Policy rules: 0
Control key: none
Note: control synchronization is available; encrypted tunnel is not active
```

## Getting started

Requirements: Go 1.26.8 or newer and a running `meshd` from the matching API generation.

```bash
make test
make build
./bin/meshctl --socket /tmp/meshd.sock status
./bin/meshctl --socket /tmp/meshd.sock profile create \
  --name production \
  --control-url https://transit.example.com
./bin/meshctl --socket /tmp/meshd.sock profile list
./bin/meshctl --socket /tmp/meshd.sock doctor control
./bin/meshctl --socket /tmp/meshd.sock profile trust \
  --fingerprint sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
./bin/meshctl --socket /tmp/meshd.sock login
```

Linux amd64/arm64 Debian package build and installation are documented in
[docs/linux-packaging.md](docs/linux-packaging.md).

Global flags must appear before the command. `MESHCTL_SOCKET` and `MESHCTL_TIMEOUT` provide environment defaults; explicit flags take precedence.

## Commands

- `meshctl status`
- `meshctl profile list`
- `meshctl profile create --name NAME --control-url HTTPS_URL`
- `meshctl profile use PROFILE_ID`
- `meshctl profile trust --fingerprint sha256:...`
- `meshctl login`
- `meshctl login --wait-timeout 10m`
- `meshctl login --no-wait`
- `meshctl login --auth-key-stdin`
- `meshctl login complete`
- `meshctl version`
- `meshctl doctor control`
- `meshctl --json ...` for machine-readable output

`doctor control` verifies the TLS certificate, reads the capability-142 server key, completes a short-lived Noise IK handshake, and prints only the public-key fingerprint. It does not register or modify a node.

Before `profile trust`, compare that fingerprint with a value delivered through an independent trusted channel. Reusing the value printed over the same connection is only trust on first use.

`login` starts browser enrollment, prints the authorization URL, and waits up to
five minutes for approval. `--wait-timeout` changes that bounded wait and
`--no-wait` returns immediately after printing the URL. Re-running `login`
resumes a pending flow; `login complete` remains available as a recovery command.
In JSON mode, a waiting browser flow emits the pending and registered responses
as successive JSON documents. For a pre-auth key, pipe it to
`login --auth-key-stdin`. Auth keys are deliberately unavailable as flags or
environment variables and are not persisted by either process.

Creating a profile does not accept a network ID. The control plane derives and authorizes network membership from the registration or session credential.

After registration, `meshd` automatically maintains the active profile's control-map stream. `meshctl status` reports synchronization, the latest validated revision, aggregate direct/relay path counts, redacted relay health, aggregate host-network-change/endpoint-refresh counters, process-local runtime-recovery state, and bounded process-wide runtime health. Older v1 daemons that do not expose recovery state remain compatible and are shown as `unavailable`. Status does not expose stack traces, allocation profiles, peer public keys, endpoint addresses, host interface addresses, raw route topology, raw policy, or registration handles.

## Security boundary

`meshctl` does not read `/var/lib/meshd`, access private keys, or manipulate network devices. On Linux, `meshd` additionally checks kernel `SO_PEERCRED` identity for every accepted Unix-socket connection.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributors

MeshTransit contributors.

## License

No project license has been selected yet. Do not publish or redistribute this repository until the maintainers add a `LICENSE` file.
