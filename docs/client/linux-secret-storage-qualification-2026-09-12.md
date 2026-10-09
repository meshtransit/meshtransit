# Linux secret-storage qualification — 2026-09-12

## Scope

This report records the first native qualification of encrypted identity state,
host-bound systemd credential provisioning, staged migration, and package
lifecycle on the two dedicated Linux security-test hosts. The separate
alpha17 72-hour soak nodes were neither accessed nor changed.

This is bounded alpha evidence. It does not claim resistance to a root attacker,
TPM-backed sealing, encrypted backup recovery, key rotation, or release-artifact
signing.

## Artifacts and platforms

- Migration artifact: `meshd` `0.1.0~alpha19`, commit
  `48ae468aa593a9eb65847e2cc3a05f7a6e3095ec`, Debian SHA-256
  `3ad0c59b364f36bdb160521860622449cfb9777036b2315465cd705e2243f3fa`.
- Compatibility rollback artifact: `meshd` `0.1.0~alpha18`, commit
  `2ad02889c0e526307d6f986da391253e27251b31`, Debian SHA-256
  `c6a1b99c32b0f6942e1f8d0876362d96a70c34fecfbb105126da6265ec5a2fac`.
- Legacy rollback artifact: `meshd` `0.1.0~alpha17`, commit
  `ea5813418fbe682c6b1ff0af9e7064901ef1deba`, Debian SHA-256
  `701a6ab49b8854c0b221714379ae89635d41d929267eb3fe15e6b4c1c05afd6e`.
- Debian 13 x86-64 with systemd `257.13-1~deb13u1`.
- Ubuntu 26.04 x86-64 with systemd `259.5-0ubuntu3`.

The alpha18 and alpha19 packages were each built twice from their exact commit,
commit timestamp, and version. Each pair was byte-identical. Local gates passed:
full shuffled race tests, `go vet`, golangci-lint including gosec, ShellCheck,
the new identity and protector fuzz targets, Linux amd64/arm64 plus Windows
amd64 and macOS arm64 compilation, `govulncheck`, package verification,
maintainer lifecycle tests, and Gitleaks scans of both history and the working
tree.

## Rejected diagnostic executions

Two early Debian executions were rejected as evidence and fixed before the
accepted artifacts were built:

1. The first provisioner encrypted a temporary file with the embedded service
   name but tried to decrypt it under the random temporary basename. systemd
   correctly rejected that name mismatch. Commit `5355a86` binds temporary
   verification explicitly to `meshd.identity-key`.
2. The first daemon policy treated systemd's root-owned mode `0440` private
   credential as an ordinary owner-only file. Native inspection confirmed the
   service view is a 32-byte regular file with mode `0440` and ownership
   `root:root`. Commit `2ad0288` added a separate, Linux-only policy that accepts
   only mode `0400` or `0440`, root ownership, and a two-component path beneath
   `/run/credentials/*.service/`; arbitrary key-file overrides still require
   owner-only permissions.

No rejected package was installed on the Ubuntu host. Debian was stopped after
each failed attempt and later passed a fresh purge/reinstall with the accepted
alpha18 artifact.

## Native results

| Gate | Debian 13 | Ubuntu 26.04 |
| --- | --- | --- |
| Fresh alpha18 install | Pass | Pass |
| `meshcred`, `meshnetd`, `meshd` active | Pass | Pass |
| Encrypted credential regular, root-owned, mode `0600` | Pass | Pass |
| Decrypted service credential exactly 32 bytes, content not emitted | Pass | Pass |
| New identity contains only envelope metadata and ciphertext | Pass | Pass |
| Identity restart continuity | Pass | Pass |
| Identity ciphertext tamper fails closed | Pass | Covered on Debian |
| Encrypted credential tamper fails closed | Pass | Covered on Debian |
| Remove preserves identity and matching credential | Pass | Covered on Debian |
| Purge removes owned state and credential but preserves systemd host key | Pass | Covered on Debian |
| Fresh reinstall after purge | Pass | Pass |
| Host reboot preserves credential and service health | Pass | Pass |
| Alpha19 exact artifact active after reboot | Pass | Pass |

On Debian, changing one authenticated payload character caused `meshd` to stop
with `identity envelope authentication`; restoring the exact backup returned the
service to health with the original identity hash. Changing one byte of the
encrypted systemd credential prevented `meshd` from starting; restoring the
blob recovered both the provisioner and daemon. Neither test emitted decrypted
key material.

Normal package removal preserved both the identity record and its matching
encrypted credential byte-for-byte. Reinstall reopened the same identity.
Purge removed `/var/lib/meshd` and
`/etc/credstore.encrypted/meshd.identity-key`, while deliberately preserving
the machine-wide `/var/lib/systemd/credential.secret`; a later fresh install
created new package state successfully.

## Staged migration and rollback

Ubuntu exercised the complete compatibility sequence:

1. Alpha17 created a legacy plaintext identity.
2. Alpha18 started, read the same identity without changing its hash, and
   verified the existing control pin.
3. Downgrade to alpha17 retained the exact identity and remained healthy.
4. Alpha18 was installed again as the retained compatibility rollback target.
5. Alpha19 started and atomically replaced the legacy record with a versioned
   AES-256-GCM envelope; private-key field names were absent afterward.
6. Downgrade to alpha18 read the encrypted identity without changing it and
   verified the existing control pin.
7. Alpha19 was restored and survived a host reboot with identical identity and
   credential hashes.

This proves the two-step rollback contract for the exercised record. Alpha17 is
not a valid rollback target after alpha19 migrates a record; alpha18 is.

## Hardening and remaining limits

`systemd-analyze security` rated `meshcred`, `meshd`, and `meshnetd` as `OK` on
Ubuntu, with exposure scores `3.1`, `3.3`, and `3.7`. The root provisioner has
an empty capability bounding set, no network address family, and write access
only to the encrypted credential directory and systemd's host-key directory.
The privileged network helper receives no identity credential.

Neither VPS exposed a usable firmware TPM. `systemd-creds` therefore used its
host key and warned that the host secret was not on encrypted media. This
backend protects copied identity state or backups that do not also include the
host key, but it does not protect a running host after root compromise or a
disk image containing both files. TPM binding, key rotation and recovery,
encrypted backup policy, repeated power-loss fault injection, signed artifacts,
SBOM publication, and longer native sampling remain release work.

The redacted machine-readable summary is retained in
[`docs/evidence/linux-secret-storage-alpha19-s1`](evidence/linux-secret-storage-alpha19-s1).
