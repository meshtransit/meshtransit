# Linux identity-key rotation qualification — 2026-09-12

## Scope

This report records the first native qualification of the staged Linux
identity envelope-key transaction. It covers a durable two-key credential,
eager identity rewrap, active-key-only finalization, recovery, fallback-key
deletion, and rollback to a reader-compatible build while rotation is pending.

The dedicated Ubuntu 26.04 and Debian 13 security-test hosts were used. The
separate 72-hour soak hosts were not accessed or changed.

## Artifacts and platforms

- Rotation artifact: `meshd` `0.1.0~alpha21`, commit
  `95922588f94807a967e561bd5e8164948ef371d2`, Debian SHA-256
  `983574ba3c352526e131402c15e1a96713531cf176accb2671efd116ed6a33f2`.
- Reader-compatible rollback artifact: `meshd`
  `0.1.0~alpha20compat1`, commit
  `20ea87a47bde317f36ed0d4fe18579ee2b3c8f97`, Debian SHA-256
  `f4910f73b454a92207e23fe9fa6f6cb5e75d10bd350d47b02d14bbc19a768378`.
- Ubuntu 26.04 x86-64 with systemd `259.5-0ubuntu3.4`.
- Debian 13 x86-64 with systemd `257.13-1~deb13u1`.

Both packages were built from source archives of the exact commits without Git
history. Commit and timestamp metadata were supplied explicitly to the
reproducible package builder. Package structure and systemd units passed
`verify-deb.sh`; all changed shell files passed ShellCheck on Ubuntu.

Before native installation, the rotation implementation passed 696 shuffled
race tests across 27 packages, `go vet`, golangci-lint including gosec, the
identity and protector fuzz targets, `govulncheck`, maintainer lifecycle tests,
and Linux amd64/arm64, Windows amd64, and macOS amd64/arm64 compilation.

## Transaction contract

The exercised transaction was:

1. `rotate` generated a fresh active key, retained the old key as the single
   read-only fallback, encrypted the bounded key set with `systemd-creds`,
   verified its round trip, made the recovery link durable, and atomically
   replaced the primary credential.
2. Restarting `meshd` loaded the key set and rewrote every canonical identity
   with the active key before opening the local API.
3. `finalize`, while the daemon was stopped, verified every identity using the
   active key alone and replaced the primary credential with that single key.
   The two-key recovery copy remained.
4. A later `commit`, again while the daemon was stopped, repeated active-key
   verification and then deleted the recovery copy and fallback key.

`finalize`, `commit`, and `recover` were also checked to require a stopped or
failed `meshd.service`. Decrypted credential bytes were never displayed or
stored as evidence; only their bounded byte counts were observed.

## Native results

| Gate | Ubuntu 26.04 | Debian 13 |
| --- | --- | --- |
| Alpha19 to alpha21 package upgrade | Pass | Pass |
| Original single-key credential accepted | Pass | Pass |
| `rotate` creates equal primary/recovery encrypted blobs | Pass | Pass |
| Rotating credential decrypts to exactly 85 bytes | Pass | Pass |
| Existing daemon remains active until requested restart | Pass | Pass |
| Second `rotate` fails closed while pending | Pass | Covered by unit gate |
| Restart accepts rotating credential | Pass | Pass |
| Startup rewraps existing identity before service readiness | Pass | No identity present |
| `finalize` is refused while daemon is active | Pass | Pass |
| Offline `finalize` produces 32-byte primary and retains 85-byte recovery | Pass | Pass |
| Restart with finalized active key | Pass | Pass |
| Offline `recover` restores exact two-key primary | Pass | Covered on Ubuntu |
| Restart after recovery preserves identity readability | Pass | Covered on Ubuntu |
| Reader-compatible downgrade while rotation is pending | Pass | Covered on Ubuntu |
| Restore rotation artifact after pending downgrade | Pass | Covered on Ubuntu |
| Offline `commit` removes recovery only after verification | Pass | Pass |
| Final services active with `NRestarts=0` | Pass | Pass |

Ubuntu started with one existing encrypted identity. Its ciphertext hash was
unchanged by the package upgrade and by `rotate` before restart, changed when
startup rewrapped it with the new active key, and then remained stable through
finalize, restart, recovery, reader-compatible downgrade, alpha21 restoration,
and commit. This distinguishes expected randomized re-encryption from identity
loss. The final Ubuntu and Debian states both use one 32-byte credential, have
no recovery file, and run `meshcred`, `meshnetd`, and `meshd` successfully.

The pending-rotation rollback installed commit `20ea87a` over alpha21 while the
primary and recovery credentials still contained two keys. The compatibility
daemon restarted successfully, retained the exact identity ciphertext, and had
`NRestarts=0`. Alpha21 was then restored and the same transaction was finalized
and committed. A build older than the two-key reader remains an invalid
rollback target while rotation is pending.

## Crash and recovery evidence

Native execution proved the durable recovery and restore paths, including a
real recovery after successful finalization. Deterministic unit tests also
cover an interrupted rotation resumed from the already-durable recovery copy,
active-key verification failure preserving the rotating primary, a mismatched
recovery copy, a single-key recovery copy, duplicate generated key material,
and create-only provisioning refusing to orphan a recovery copy.

The file transaction uses same-directory temporary files, file `fsync`, a
directory `fsync` after the recovery link, atomic rename of the primary, and a
second directory `fsync`. The state machine is designed so each boundary leaves
a complete old primary, complete rotating primary, or complete finalized
primary with a verified recovery copy where required; abrupt power-loss testing
of those boundaries remains outstanding.

## Remaining limits

This is bounded release-candidate evidence, not a claim against root compromise
or physical disk attacks. It does not yet include forced host power loss at
every filesystem boundary, firmware TPM binding, an encrypted off-host backup
and restore policy, concurrent operator fault injection, or repeated rotation
over the long-duration two-node topology. Debian had no registered identity, so
its result qualifies systemd 257 credential and package behavior; identity
continuity and pending-build rollback were exercised on Ubuntu.

Before the first stable Linux release, run repeated power-loss/fault-injection
samples, add the signed artifact/provenance gate, and perform one post-rotation
network continuity sample on a registered two-node candidate topology without
disturbing the active 72-hour soak.
