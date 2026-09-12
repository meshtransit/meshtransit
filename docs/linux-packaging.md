# Linux packaging and service lifecycle

Linux is the first native release target. The `meshd` Debian package contains
the unprivileged daemon, the minimal root network helper, the root-only
`meshcred` credential provisioner, hardened systemd units, sysusers/tmpfiles
declarations, and a root-only environment file. `meshctl` is built and packaged
independently from its own repository because the versioned local API permits
independent upgrades.

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
- `meshcred.service` runs once as root before `meshd.service`, with no
  capabilities or network address family. It generates a 256-bit identity
  envelope key and persists only a host-encrypted systemd credential at
  `/etc/credstore.encrypted/meshd.identity-key`. The service verifies decryption
  before create-only installation and safely reuses an existing credential.
  During explicit rotation it also maintains a verified host-encrypted
  `.recovery` copy; ordinary package removal preserves both files and purge
  removes both.
- systemd decrypts that credential into
  `/run/credentials/meshd.service/meshd.identity-key`, visible inside the
  daemon's private credential mount. `meshnetd` cannot access the decrypted key.
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
reproducible timestamps, records the commit and build date in package control
metadata, and writes a sibling SHA-256 checksum file. The
control metadata becomes authenticated only after the package-signing stage.

```bash
./packaging/linux/build-deb.sh 0.1.0~alpha1 amd64 dist
./packaging/linux/verify-deb.sh dist/meshd_0.1.0~alpha1_amd64.deb amd64
```

## SBOM and vulnerability gate

Every candidate `.deb` is extracted and scanned as the filesystem that will be
installed. Scanning the archive as one opaque file is deliberately avoided
because that omits the Go modules embedded in `meshd`, `meshnetd`, and
`meshcred`.

The audit writes a CycloneDX 1.7 SBOM and a full Grype JSON report next to the
package, with SHA-256 sidecars for both. The CycloneDX root component includes
the exact `.deb` digest, architecture, build date, and Git commit. Temporary
extraction paths are removed, every reported location must resolve inside the
package, and the validator compares the SBOM with the module build information
in all three binaries.

Grype consumes a separate temporary Syft-native SBOM containing Go function
symbols. This keeps the published CycloneDX document portable while allowing
reachability-aware matching. The temporary native document is deleted after
the scan because it includes local tool configuration. Any High or Critical
finding fails the package job; the complete report is retained even when the
gate fails. `govulncheck` remains an independent source-level reachability gate.

Syft v1.51.1 and Grype v0.116.1 are installed from their immutable release
archives after locally verifying hard-coded SHA-256 values. Tool self-update
checks are disabled during generation and scanning.

```bash
./tools/security/install-supply-chain-tools.sh /tmp/mesh-tools
PATH="/tmp/mesh-tools:${PATH}" \
    ./tools/security/audit-linux-package.sh \
    dist/meshd_0.1.0~alpha1_amd64.deb
```

CI retains the `.deb`, its checksum, the CycloneDX SBOM, the vulnerability
report, and both report checksums for 14 days. Release publication will attach
the same SBOM contract to signed candidate artifacts.

The first exact-commit amd64/arm64 result is recorded in
[linux-supply-chain-qualification-2026-09-12.md](linux-supply-chain-qualification-2026-09-12.md).

## Install, upgrade, rollback, and uninstall

Install `meshctl` first, then `meshd`. A fresh install enables and starts the
services through Debian's service-policy helpers. An upgrade preserves an
administrator's enabled/disabled and running/stopped choices; only services
that are already running are restarted. Unit dependency ordering provisions
the credential and starts `meshnetd` before `meshd`.

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

## Identity envelope-key rotation

Rotation is an explicit, staged transaction. Deploy and retain a build that
understands the bounded two-key credential before beginning; after `rotate`, a
build that accepts only the original 32-byte credential is not a valid rollback
target. None of these commands prints key material.

1. Stage a new active key and a durable host-encrypted recovery copy. The
   running daemon keeps its already mounted old key until restart.
2. Restart `meshd`. Before reopening its local API, the daemon verifies and
   atomically rewraps every canonical identity record with the new active key.
3. Stop `meshd` and finalize. Finalization refuses to proceed unless every
   identity is readable using the active key alone; the recovery copy remains.
4. Start and qualify `meshd` with the single active key. Only after that
   succeeds, stop it once more and commit the rotation to delete fallback key
   material.

```bash
sudo /usr/libexec/meshtransit/meshcred rotate
sudo systemctl restart meshd.service
# Verify registration continuity and daemon health here.
sudo systemctl stop meshd.service
sudo /usr/libexec/meshtransit/meshcred finalize
sudo systemctl start meshd.service
# Verify the finalized credential here before committing.
sudo systemctl stop meshd.service
sudo /usr/libexec/meshtransit/meshcred commit
sudo systemctl start meshd.service
```

`finalize`, `commit`, and `recover` fail closed unless systemd reports
`meshd.service` as stopped or failed. Before `commit`, recovery restores the
verified two-key credential atomically and keeps its source copy:

```bash
sudo systemctl stop meshd.service
sudo /usr/libexec/meshtransit/meshcred recover
sudo systemctl start meshd.service
```

An interrupted `rotate` is resumable: the recovery copy is made durable before
the primary credential is replaced, and rerunning `rotate` activates that exact
copy instead of generating another key. An interrupted `finalize` leaves either
the verified two-key credential or the verified active key as the complete
primary file. Never delete the `.recovery` file manually.

Normal removal stops the services, removes their volatile sockets, and
preserves identity state, the encrypted credential, and the root-owned
conffile. Reinstalling reconnects the same node identity when it was running
before removal; an intentionally stopped service stays stopped. Purge
additionally removes `/var/lib/meshd` and the package-owned encrypted credential
permanently. It does not remove systemd's machine-wide host credential key,
which may protect credentials belonging to other services. Maintainer scripts
honor `DPKG_ROOT`, so image-building and alternate-root operations cannot
delete state from the host root.

```bash
sudo apt-get remove meshd meshctl
sudo apt-get purge meshd meshctl
```

Before purge, back up `/var/lib/meshd` together with the matching encrypted
credential only to secret storage if retaining node identity is intentional.
The host-key-encrypted credential is not portable by itself. Do not restore one
state directory onto two machines.
