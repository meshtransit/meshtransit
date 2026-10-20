# Linux

The Linux client ships as two Debian packages, `meshd` and `meshctl`, for
amd64 and arm64. It needs systemd 255 or later with `systemd-resolved`.
How the parts work is in [Client](../architecture/client.md).

## Build

```bash
make package-deb VERSION=0.1.0 ARCH=amd64   # or ARCH=arm64; Linux only
```

The build injects the Git commit, uses `SOURCE_DATE_EPOCH` for reproducible
timestamps, writes a `.sha256` next to each package, and verifies the package
(`packaging/linux/meshd/verify-deb.sh`): installed files, modes, units, and that
no removed pre-release flag remains. `hack/security/audit-linux-package.sh PACKAGE`
adds an SBOM and a vulnerability report (it needs the `syft` and `grype`
versions that `hack/security/install-supply-chain-tools.sh` installs).

## What the packages install

| Path | What |
|---|---|
| `/usr/bin/meshd` | The daemon (package `meshd`) |
| `/usr/libexec/meshtransit/meshnetd` | Network helper |
| `/usr/libexec/meshtransit/meshcred` | Identity key provisioning |
| `/usr/lib/systemd/system/{meshd,meshnetd,meshcred}.service` | Units |
| `/etc/meshd/meshd.env` | Extra flags (`MESHD_FLAGS=`), root-owned 0640 |
| `/etc/credstore.encrypted/meshd.identity-key` | The host-encrypted identity key, created at first start |
| `/var/lib/meshd` | State, mode 0700 |
| `/run/meshd/meshd.sock` | Local API, mode 0660 in `/run/meshd` (`meshd:meshtransit`, 0750) |
| `/usr/bin/meshctl` | The CLI (package `meshctl`) |

Service identities:

- `meshd` runs as the system user `meshd` with group `meshtransit` (which
  owns the local API socket; the account's own group is `meshd`) and no capabilities. It receives the TUN
  descriptor from the helper and never sends it keys.
- `meshnetd` runs as root with group `meshd`, only `CAP_CHOWN` and
  `CAP_NET_ADMIN`, and only `/dev/net/tun`. It serves only `meshd`
  (`--allow-user=meshd`) and only addresses and routes inside `100.64.0.0/10`,
  `198.18.0.0/15` and `fd00::/8`.
- `meshcred.service` is a root oneshot that `meshd.service` requires, with no
  capabilities or network. It runs when `meshd` starts while it is inactive,
  normally once per boot, and then stays active. On the first run it creates a 256-bit key and stores
  it only as a credential encrypted with systemd's host key
  (`systemd-creds --with-key=host`); later runs reuse it. systemd decrypts it
  into `meshd`'s private credential mount; `meshnetd` cannot read it.

`meshd` starts with `--allow-socket-peers --enable-data-plane
--wireguard-listen-port=41641 --enable-dns --enable-device-aliases
--enable-subnet-routes --enable-exits`, plus
`MESHD_FLAGS` from `/etc/meshd/meshd.env` (for example `--log-level=debug`,
`--port-mapping=off`, `--cloud-metadata=off`). Both long-running units are
`Type=notify`: `systemctl start` returns once each has bound its socket, and
fails if it cannot.

## Subnet routes

A Linux machine reaches the Sites its rules grant once root accepts subnet
routes; nothing is installed until then:

```bash
sudo /usr/libexec/meshtransit/meshnetd routes accept on
```

The setting lives in `/etc/meshtransit/routes.json` and applies within
seconds; `routes accept off` removes the routes. To forward into a subnet as
a router, add `--enable-subnet-router` to `MESHD_FLAGS` and, as root, run
`meshnetd routes router-mode on` and `meshnetd routes advertise PREFIX`. How
the routes are kept safe is in [Client](../architecture/client.md).

## Exit node

A Linux machine forwards other Devices' Internet traffic for the Exit Pool
Core assigns it to only when both the deployment and root allow it: add
`--enable-exit-node` to `MESHD_FLAGS`, and as root run
`meshnetd routes exit-mode on`. Core's limits only narrow the machine's own:

```bash
sudo /usr/libexec/meshtransit/meshnetd routes exit-mode on
sudo /usr/libexec/meshtransit/meshnetd routes exit-conntrack-max 8192   # connections per consumer
sudo /usr/libexec/meshtransit/meshnetd routes exit-max-consumers 64
sudo /usr/libexec/meshtransit/meshnetd routes exit-smtp on              # TCP 25, off by default
```

The exit node forwards only to the Internet: never to private, shared,
link-local (cloud metadata) or other special ranges, the mesh, its own
addresses, the subnets it is attached to or its gateways, whatever Core
sends. Every source is translated to the machine's own address. `routes
exit-mode off` stops forwarding within seconds.

## Use an exit node

A Linux machine sends its Internet traffic through an Exit Pool its rules
grant only once root chooses one; nothing changes until then:

```bash
sudo /usr/libexec/meshtransit/meshnetd routes exit-use POOL   # a pool's reference or name
sudo /usr/libexec/meshtransit/meshnetd routes exit-use auto   # the first pool Core serves, kept
sudo /usr/libexec/meshtransit/meshnetd routes exit-use off
```

`meshctl status` shows the exit node used on its `Exit` line. While a pool
is chosen the machine fails closed: traffic to the Internet goes into the
mesh or nowhere, also while no exit node of the pool can carry it, the pool
is not granted, or `meshd` is down. Mesh Devices and Sites keep their own
routes. What still leaves by the machine's own networks:

- `meshd`'s own connections to Core, relays and peers;
- replies to connections opened from outside (a server keeps its SSH);
- DHCP, IPv6 neighbour discovery, and local bridges without a physical port
  (Docker, libvirt);
- the attached private subnets, only after `routes exit-allow-lan on`.

DNS does not go through the exit node yet: names resolve only when the
machine's resolver is in an allowed LAN (`exit-allow-lan on`). Containers
and VMs on the machine also go through the exit node. IPv6 goes
through it only when the exit node has IPv6; otherwise it is refused at once.
`routes exit-allow-managed on` lets an administrator choose the pool (one
Core marks managed) while `exit-use` is off.

The kill switch is held by `meshnetd` from root's `exit-use` alone: neither
`meshd` nor Core can lift it, and it stays while `meshd` or `meshnetd` are
stopped, restarted or upgraded, and before the first map. `routes exit-use
off` removes it within seconds; removing the package removes it too. If the
machine stays offline with no helper running, root removes it with
`sudo /usr/libexec/meshtransit/meshnetd --release-exit`. A pool chosen by the
administrator (`exit-allow-managed`) is the exception: Core decides when it
applies.

## Install, upgrade, roll back

```bash
sudo apt install ./meshctl_0.1.0_amd64.deb ./meshd_0.1.0_amd64.deb
sudo usermod -aG meshtransit "$USER"     # then log out and in again
```

A fresh install enables and starts the services. An upgrade uses the same
command with newer packages; it keeps the administrator's enabled and running
choices and restarts only services that were running. To roll back, install
the previous pair with `sudo apt install --allow-downgrades ./meshctl_….deb
./meshd_….deb` (or `sudo dpkg -i` on the two files).

After an identity key rotation (below) has begun, a build that knows only the
single-key credential is no longer a valid rollback target.

## Join a Network

**With the browser:**

```bash
meshctl up --server https://control.example.com --fingerprint sha256:…
```

`up` creates and activates a profile, pins Core's control key after checking
the fingerprint, prints an approval link and waits for it (5 minutes by
default; `--no-wait` to return at once). Open the link, sign in, and choose the
Workspace and Network. Without `--server`, `up` uses the Cloud service and its
built-in fingerprint. Get the fingerprint from the deployment's operator
(`meshctl doctor control` on a trusted network shows what a server presents);
the 32-character `ck=` value of an enrollment link is accepted too.

**With an enrollment key:**

```bash
meshctl profile create --name example --control-url https://control.example.com
meshctl profile trust --fingerprint sha256:…
printf %s "$KEY" | meshctl login --auth-key-stdin
```

`profile create` activates the new profile only if none is active; otherwise
run `meshctl profile use PROFILE_ID` before `trust`. The key is read from
standard input only, never from an argument. Once
registered, `meshd` keeps its control session by itself, across restarts.

## Check and troubleshoot

| Command | Shows |
|---|---|
| `meshctl status` | State, control session, registration, addresses, when the Device expires, peers and paths, DNS, NAT, relays |
| `meshctl netcheck` | NAT type and public address; exits 1 unless the classification is ready |
| `meshctl doctor control` | Core's control key fingerprint and transport, without registering |
| `journalctl -u meshd -u meshnetd -u meshcred` | Logs (JSON) |

Put `--json` before the command for JSON output: `meshctl --json status`. Common problems:

- **`meshctl: localapi: calling daemon: …` (permission):** the user is not in
  `meshtransit` yet, or has not logged in again since being added.
- **`meshnetd` does not start:** with DNS on, it requires
  `/usr/bin/resolvectl` as a root-owned file only root can change, which means
  `systemd-resolved` must be installed.
- **The node goes offline after a DNS error:** a failed DNS apply also stops
  the control session today; see [DNS](../concepts/dns.md#wiring-into-the-host).
- **`meshcred: provision failed` or "loading identity envelope key failed":**
  the encrypted credential cannot be created or decrypted on this host, for
  example after copying it from another machine. `meshcred` prints no cause;
  run `systemd-creds` by hand to see it.
- **"migrating identity records failed":** the identity records were sealed
  with another key, for example after copying only `/var/lib/meshd` from
  another machine.
- **Startup fails after an upgrade:** remove pre-release flags such as
  `--enable-tun-poc` or `--control-protocol=legacy` from `MESHD_FLAGS`.

## Leave, reset, remove

- `meshctl down` disconnects and stays disconnected across restarts;
  `meshctl up` reconnects.
- `meshctl logout` removes the Device in Core and replaces the local keys; the
  next `meshctl up` registers a new Device.
- `sudo apt-get remove meshd meshctl` stops the services and keeps the identity,
  the encrypted credential and `/etc/meshd`; reinstalling reconnects the same
  Device.
- `sudo apt-get purge meshd meshctl` also deletes `/var/lib/meshd`, the
  encrypted credential (and its recovery copy) and `/etc/meshd`. It does not
  remove systemd's host key, which other services may use.

Removing the package does not remove the Device from its Network: run
`meshctl logout` first, or revoke it in the Console. Maintainer scripts honor
`DPKG_ROOT`. To keep a node's identity across a purge, back up `/var/lib/meshd`
with the matching credential to secret storage; the credential only decrypts
on the same host, and one state directory must never run on two machines.

## Rotating the identity key

The envelope key that encrypts the identity records can be replaced in a
staged, recoverable transaction. None of these commands prints key material.

```bash
sudo /usr/libexec/meshtransit/meshcred rotate      # stage a new key and a recovery copy
sudo systemctl restart meshd.service               # meshd rewraps every record with the new key
# check that the node is registered and healthy
sudo systemctl stop meshd.service
sudo /usr/libexec/meshtransit/meshcred finalize    # refuses unless the new key alone reads everything
sudo systemctl start meshd.service
# check again
sudo systemctl stop meshd.service
sudo /usr/libexec/meshtransit/meshcred commit      # delete the old key
sudo systemctl start meshd.service
```

Before `commit`, `meshcred recover` (with `meshd` stopped) restores the
two-key credential. `finalize`, `commit` and `recover` refuse to run while
`meshd` is active. An interrupted step can be repeated. Never delete the
`.recovery` file by hand.
