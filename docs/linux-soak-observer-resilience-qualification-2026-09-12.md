# Linux soak observer resilience qualification — 2026-09-12

## Scope

This report qualifies the lifecycle protection added to the Linux fixed-topology
soak observer at commit
`618d851c599e63c484ca8138a36c3c91f7af3158`. It proves that ordinary systemd
service-maintenance requests cannot replace the observer and silently reset its
measurement window. It is not a 72-hour mesh stability result.

## Trigger and root cause

An earlier alpha17 observer changed generation during a nominally uninterrupted
run. The host did not reboot, and neither `meshd` nor `meshnetd` restarted. The
observer's new start timestamp coincided with an unattended `libc6` update;
`needrestart` explicitly selected the old transient observer unit for restart.
The mesh remained healthy, but the stitched observation was invalid as release
evidence because its first measurement window had been lost.

Ubuntu `needrestart` 3.11 checks a unit's `RefuseManualStop` property before
selecting it for a service restart. The fix therefore protects only the
observer unit instead of disabling unattended security updates or installing a
global `needrestart` exclusion.

## Implemented contract

Release-candidate runs now start through `linux-soak-systemd.sh`. The launcher:

- accepts only a bounded lowercase run ID and one of two fixed root-owned state
  roots;
- rejects symlinked, pre-existing, non-root-owned, or non-private output paths;
- pins a root-owned mode-`0500` harness copy and its SHA-256 before execution;
- starts one transient service with `RefuseManualStop=yes` and `Restart=no`;
- applies read-only filesystem, home, kernel, privilege, namespace, and address
  family restrictions compatible with the read-only harness;
- verifies that the unit is active and that both lifecycle properties were
  applied before reporting success;
- leaves a failed or interrupted run non-resumable, requiring a fresh run ID.

The harness schema is now `meshtransit.linux-soak-qualification/v2`. A strict
72-hour invocation fails before sampling unless its own cgroup proves that it is
inside a correctly named, restart-protected observer unit. The redacted report
records only the two protection booleans; it omits the unit name, PID, and
invocation identifier.

## Validation

The exact candidate scripts passed local Bash syntax checks and both self-test
suites. The repository also passed `make test` and `make race` with isolated Go
build caches.

Native validation used an x86-64 Ubuntu 26.04 LTS host with kernel
`7.0.0-27-generic`, systemd `259 (259.5-0ubuntu3.4)`, Bash `5.3.9`, ShellCheck
`0.11.0`, and `needrestart` `3.11`. The exact four scripts from the candidate
commit passed Bash syntax, ShellCheck, the soak self-test, and the launcher
self-test on that host.

A systemd compatibility probe exposed and rejected one pre-evidence defect:
systemd 259 returns success from `systemctl show` for a missing unit while
reporting `LoadState=not-found`. The launcher was changed to inspect the value
explicitly and fail closed on an empty or unreadable state. Its regression test
and a native missing-unit check then passed.

Finally, the exact candidate launcher started a five-minute inert test harness.
The active unit reported `RefuseManualStop=yes`, `Restart=no`,
`ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges=yes`, and zero
restarts. A manual `systemctl restart` was refused. The main PID and invocation
identifier remained unchanged and the restart count remained zero afterward.
The unit was then terminated through the documented explicit kill path; it
became inactive and unloaded, and its private output and test directories were
removed. This probe did not start, stop, or restart `meshd` or `meshnetd`.

The redacted machine-readable result and checksum are retained in
[`docs/evidence/linux-soak-observer-resilience-s1`](evidence/linux-soak-observer-resilience-s1).

## Security and limits

This change protects against the observed maintenance restart and against
ordinary manual stop/restart requests. It intentionally does not resume after a
host reboot, observer crash, administrative kill, or kernel termination; any of
those events invalidates the run so that an incomplete window cannot be
mistaken for continuous evidence. Root can still terminate or replace the
observer, which is an explicit administrative trust boundary.

The existing alpha17 schema-v1 smoke is historical and remains valid only as a
short harness smoke. A new exact-artifact, protected, two-node 72-hour run is
still required before the Linux release-candidate soak gate can pass.
