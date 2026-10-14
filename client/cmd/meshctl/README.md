# meshctl

`meshctl` is the unprivileged command-line client for the local MeshTransit daemon. It controls profiles and reads status only through `meshd`'s versioned local API: a Unix socket on Linux and macOS, a named pipe on Windows.

## Demo

A daemon started without `--enable-data-plane` and not yet registered:

```console
$ meshctl status
Daemon: dev
State: offline
Data plane: not_implemented
DNS: inactive
Network changes: unavailable
Runtime recovery: idle (failures: 0, recoveries: 0)
Runtime: 8 goroutines, 0.6 MiB heap allocated, 12.3 MiB system, 0 GC cycles
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
Path transitions: unavailable
Path probes: unavailable
Relay: unavailable
NAT: unavailable
Port mapping: off
Cloud: off
Policy rules: 0
Control key: none
Note: control synchronization is available; encrypted tunnel is not active
```

## Getting started

On a machine with `meshd` running, one command connects it to MeshTransit
Cloud and waits for you to approve it in the browser:

```bash
meshctl up
```

`meshctl up` finds or creates the profile for the server, makes it active,
pins the control key and registers. Cloud packages carry the Cloud control key
fingerprint, so nothing needs to be compared by hand. For a self-hosted server
pass the URL and the fingerprint your administrator gives you:

```bash
meshctl up --server https://mesh.example.com --fingerprint sha256:...
```

Running `meshctl up` again on a connected machine changes nothing.

### Building from source

Requirements: Go 1.26.9 or newer and a running `meshd` from the matching API
generation (see [running it by hand](../../README.md#running-it-by-hand)).

```bash
make test
make build
./bin/meshctl --socket /tmp/meshd-dev/meshd.sock status
./bin/meshctl --socket /tmp/meshd-dev/meshd.sock profile create \
  --name production \
  --control-url https://transit.example.com
./bin/meshctl --socket /tmp/meshd-dev/meshd.sock profile list
./bin/meshctl --socket /tmp/meshd-dev/meshd.sock doctor control
./bin/meshctl --socket /tmp/meshd-dev/meshd.sock profile trust \
  --fingerprint sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
./bin/meshctl --socket /tmp/meshd-dev/meshd.sock login
./bin/meshctl --socket /tmp/meshd-dev/meshd.sock identity rotate-node-key
```

Installing the packages: [Linux](../../../docs/clients/linux.md),
[macOS](../../../docs/clients/macos.md), [Windows](../../../docs/clients/windows.md).

Global flags must appear before the command. `MESHCTL_SOCKET` and `MESHCTL_TIMEOUT` provide environment defaults; explicit flags take precedence.

## Commands

- `meshctl up`
- `meshctl up --server HTTPS_URL --fingerprint sha256:... [--name NAME] [--no-wait]`
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
- `meshctl identity rotate-node-key`
- `meshctl down`
- `meshctl logout`
- `meshctl netcheck`
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

`identity rotate-node-key` asks `meshd` to perform an authenticated, crash-safe
rotation for the active registered profile. `meshctl` sends no key or login
credential and never receives private key material. A temporary failure can be
retried safely; `meshd` retains and reuses the exact staged transition.

`down` takes the machine off the network: `meshd` stops the control session,
the data plane and MeshTransit DNS, and stays off across restarts until
`meshctl up`. The Device stays registered.

`logout` removes the machine from its Network: `meshd` stops the control
session, asks Core to revoke the Device (its address then goes through
quarantine before reuse), and gives the profile new machine and node keys,
because Core never accepts revoked keys again. `meshctl up` then enrolls the
machine as a new Device. If Core no longer knows the Device, for example
because an administrator removed it, only the local keys are reset. A failed
logout changes nothing and can be retried.

`netcheck` asks `meshd` to classify the NAT in front of its encrypted packet
socket now, using the relay map's STUN servers on that same socket, and prints
the mapping, filtering and port allocation behaviour, whether the network is
easy or hard for direct connections, and the public endpoint
([nat-classification](../../../docs/protocol/nat-classification.md)). `meshd`
also classifies on its own at session start, after network changes and every
five minutes; `meshctl status` shows that result without the public endpoint.
Filtering is reported as `unknown` until the relays offer RFC 5780 STUN.

Creating a profile does not accept a network ID. The control plane derives and authorizes network membership from the registration or session credential.

After registration, `meshd` automatically maintains the active profile's control-map stream. `meshctl status` reports synchronization, the latest validated revision, aggregate direct/relay path counts, redacted relay health, aggregate host-network-change/endpoint-refresh counters, process-local runtime-recovery state, and bounded process-wide runtime health. Older v1 daemons that do not expose recovery state remain compatible and are shown as `unavailable`. Status does not expose stack traces, allocation profiles, peer public keys, endpoint addresses, host interface addresses, raw route topology, raw policy, or registration handles.

## Security boundary

`meshctl` does not read `meshd`'s state, access private keys, or manipulate network devices. `meshd` checks the caller of every connection (`SO_PEERCRED` or `LOCAL_PEERCRED` and the socket's permissions, or the Windows caller's access token); see the [security model](../../../docs/clients/security-model.md#local-api).

## Contributing

See [CONTRIBUTING.md](../../../CONTRIBUTING.md).

## Contributors

MeshTransit contributors.

## License

`meshctl` is licensed under the [Apache License 2.0](../../../LICENSES/Apache-2.0.txt). See
[NOTICE](../../../NOTICE) for attribution.
