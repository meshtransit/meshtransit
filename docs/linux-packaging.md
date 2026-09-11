# Linux packaging and service lifecycle

Linux is the first native release target. The `meshd` Debian package contains
the unprivileged daemon, the minimal root helper, hardened systemd units,
sysusers/tmpfiles declarations, and a root-only environment file. `meshctl` is
built and packaged independently from its own repository because the versioned
local API permits independent upgrades.

## Service identities

- `meshd` runs as the `meshd` system user. Its primary service group is
  `meshtransit`, which owns the `0660` local API socket. Operators must be added
  to that group explicitly.
- `meshnetd` runs as root with primary group `meshd`. Its capability bounding
  set contains only `CAP_CHOWN` and `CAP_NET_ADMIN`; `/dev/net/tun` is the only
  allowed device.
- The local API and privileged-helper sockets use separate runtime directories:
  `/run/meshd` is owned by `meshd:meshtransit`, while `/run/meshnetd` is owned
  by `root:meshd`. Neither operator group receives directory write access.
- The main daemon has no Linux capabilities. It receives non-persistent TUN
  descriptors over the helper socket and never sends keys or control
  credentials to the helper.
- `/var/lib/meshd` is mode `0700`. `/etc/meshd/meshd.env` is a root-owned mode
  `0640` conffile and must not contain enrollment credentials.

The package enables encrypted host networking and MagicDNS. Flow logging stays
disabled. The privileged helper fixes the overlay pools to `100.64.0.0/10` and
`fd7a:115c:a1e0::/48`; supporting different control-plane pools requires an
explicit root-owned unit override and must remain within the server's assigned
address space.

## Build and verify

The package builder runs only on Linux and requires Go, `dpkg`, and
`dpkg-deb`. It injects the exact Git commit, uses `SOURCE_DATE_EPOCH` for
reproducible timestamps, and writes a sibling SHA-256 checksum file.

```bash
./packaging/linux/build-deb.sh 0.1.0~alpha1 amd64 dist
./packaging/linux/verify-deb.sh dist/meshd_0.1.0~alpha1_amd64.deb amd64
```

## Install, upgrade, rollback, and uninstall

Install `meshctl` first, then `meshd`. A fresh install enables and starts the
services through Debian's service-policy helpers. An upgrade preserves an
administrator's enabled/disabled and running/stopped choices; only services
that are already running are restarted. Unit dependency ordering starts
`meshnetd` before `meshd`.

```bash
sudo dpkg -i meshctl_0.1.0~alpha1_amd64.deb
sudo dpkg -i meshd_0.1.0~alpha1_amd64.deb
sudo usermod -aG meshtransit "$USER"
```

Log out and back in after changing group membership. An upgrade uses the same
commands with a newer package. Rollback installs the previously retained pair
of packages; package artifacts and checksums are retained per release candidate.

```bash
sudo dpkg -i meshctl_PREVIOUS_amd64.deb meshd_PREVIOUS_amd64.deb
```

Normal removal stops both services, removes their volatile sockets, and
preserves identity state plus the root-owned conffile. Reinstalling reconnects
the same node identity when it was running before removal; an intentionally
stopped service stays stopped. Purge additionally removes `/var/lib/meshd`
permanently. Maintainer scripts honor `DPKG_ROOT`, so image-building and
alternate-root operations cannot delete state from the host root.

```bash
sudo apt-get remove meshd meshctl
sudo apt-get purge meshd meshctl
```

Before purge, copy `/var/lib/meshd` only to secret storage if retaining node
identity is intentional. Do not restore one state directory onto two machines.
