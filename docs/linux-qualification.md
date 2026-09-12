# Linux qualification

The Linux qualification tools measure recovery of one installed MeshTransit
node against one healthy peer. They cover explicit restart or abrupt `SIGKILL`
of either `meshd.service` or `meshnetd.service`, a full host reboot, and a
controlled interface-address change. They also exercise direct-path loss,
relay fallback, later direct recovery, and split-DNS cleanup and restoration.
The helper-recovery/change chain verifies that the newly coordinated service
generation can process the first subsequent host-network event without another
restart.
Package upgrade, real multi-uplink migration, and soak scenarios remain
separate gates.

The first exact-commit release-facing runtime-surface, native upgrade,
rollback, and controlled-restart results are recorded in
[linux-production-surface-qualification-2026-09-12.md](linux-production-surface-qualification-2026-09-12.md).
Those dedicated hosts were not registered, so this evidence does not replace
the two-node packet, DNS, policy, relay, or soak matrices.

The service-manager readiness gate is intentionally independent of
registration. On an installed candidate, run:

```bash
sudo tools/qualification/linux-service-readiness.sh \
  --node-label ubuntu-readiness \
  --artifact-sha256 PACKAGE_SHA256 \
  --confirm-restarts ubuntu-readiness
```

Preflight requires both packaged units to expose `Type=notify`,
`NotifyAccess=main`, and the 30-second startup deadline. Each bounded iteration
restarts both units, proves that both process generations changed without an
automatic failure restart, checks both Unix sockets, and issues exactly one
immediate `/v1/health` request after `systemctl restart` returns. There is no
readiness polling between the restart and that request. The report excludes
process IDs, socket paths, hostnames, profile state, and control data.
The first passing exact-candidate sample is recorded in
[linux-service-readiness-qualification-2026-09-12.md](linux-service-readiness-qualification-2026-09-12.md).

The bounded Linux secret-storage, staged migration, package lifecycle, and boot
recovery results are recorded in
[linux-secret-storage-qualification-2026-09-12.md](linux-secret-storage-qualification-2026-09-12.md).
The staged key-rotation, active-only finalization, recovery, and pending-build
rollback results are recorded in
[linux-identity-key-rotation-qualification-2026-09-12.md](linux-identity-key-rotation-qualification-2026-09-12.md).

## Service-action safety boundary

The harness runs on the node being tested and requires root only for the selected
`systemctl restart` or `systemctl kill`. It accepts exactly `restart` or
`sigkill` as the action and exactly `meshd` or `meshnetd` as the service. It does
not remove packages, purge state, change profiles or policy, write identity
files, or change routes and resolver configuration directly. An exit trap
starts both services if an action or the harness is interrupted.

Preflight must prove all of the following before the service action is attempted:

- both services are active and have live process IDs;
- the data and DNS interfaces exist;
- both peer host routes use the MeshTransit data interface;
- the daemon is online, synchronized, and has an encrypted peer path;
- MagicDNS returns the exact expected IPv4 and IPv6 peer addresses;
- baseline IPv4 and IPv6 ICMP traffic succeeds.

Raw ping output, peer addresses, DNS responses, the network name, and the control
fingerprint stay in a mode-`0700` temporary directory and are deleted on exit.
The JSON report contains only operator-selected topology labels, platform and
artifact metadata, aggregate timing, and packet counters.

## Service-action prerequisites

Run the harness on a supported Ubuntu host with the packaged services already
registered. It requires Bash, `iproute2`, `iputils-ping`, `jq`, `meshctl`,
`systemd`, `systemd-resolved`, and GNU `timeout`. A direct daemon-crash run also
uses `ss` to prove that its dedicated resolver listeners disappear. The peer
must stay healthy for the complete observation window. Current policy must
allow ICMP and IPv6 ICMP between the two test nodes.

Use the SHA-256 of the exact `.deb` under test. The harness accepts a run without
it for development, but marks `artifact.evidence_complete` false; such a report
is not release-candidate evidence.

## Run a restart scenario

Copy the harness to the node or run it from a source checkout. The JSON document
is the only stdout output, so it can be redirected without mixing in progress
messages.

```bash
sudo tools/qualification/linux-restart.sh \
  --node-label ubuntu-a \
  --peer-label ubuntu-b \
  --peer-v4 100.64.0.6 \
  --peer-v6 fd7a:115c:a1e0::d \
  --peer-name ubuntu-b \
  --service meshd \
  --artifact-sha256 SHA256_OF_DEB \
  >meshd-restart.json
```

Repeat with `--service meshnetd`. Reverse the node and peer arguments and run
both scenarios on the second host. Defaults provide a two-second healthy lead,
a 15-second readiness deadline, a five-second stability tail, and parallel
IPv4/IPv6 probe loops with 200-millisecond pacing and per-attempt timeouts. Each
loop starts a bounded probe attempt so deletion and recreation of the data
interface cannot terminate the rest of the observation window. Timing
parameters are available for controlled experiments, but release-candidate
runs use the documented defaults.

For abrupt-termination qualification, add `--action sigkill` and use the
documented 20-second crash-recovery deadline. Direct daemon termination must
expose a cleanup window in which `meshdns0`, both resolver listeners, and its
per-link `systemd-resolved` record are absent. Helper termination must also
produce a new daemon PID, proving that systemd recreated the unprivileged
consumer against the new helper generation instead of retaining stale TUN
ownership state.

## Restart report contract

The schema identifier is `meshtransit.linux-restart-qualification/v1`.

- `action.duration_ms` measures the blocking service restart. The selected
  service PID must change.
- `readiness_ms` measures both services active, the data interface present, the
  daemon online and synchronized, and MagicDNS configured with correct A/AAAA
  answers. Every value is measured from restart start.
- `traffic.ipv4` and `traffic.ipv6` include total transmitted/received packets,
  total loss, first reply after the restart command, the longest missing
  sequence, post-action reply count, and the start of the final consecutive
  success run (`stable_recovery_ms`).
- `failures` contains stable machine-readable reason codes. `outcome` is `pass`
  only when the restart succeeds, the target PID changes, every readiness check
  meets the deadline, and both traffic families end with at least three
  consecutive replies whose stable run began within the deadline.

`--action sigkill` changes the schema identifier to
`meshtransit.linux-crash-recovery-qualification/v1`. Its report additionally
records the selected unit's restart counter, whether the `meshd` generation
changed, and the observed DNS cleanup time when the daemon itself was killed.
A pass requires systemd to record an automatic restart, the selected PID to
change, a new daemon generation to become ready, and the same final readiness
and stable dual-stack traffic gates as a controlled restart.

A passing single run proves only that scenario. It does not establish p95
latency or the 72-hour reliability target. Aggregate candidate reports must also
record sample count, topology/load definition, artifact digest, and percentile
calculations as required by [release-v0.1.md](release-v0.1.md).

## Run repeated crash qualification

The repeat runner invokes only the bounded single-run harness and stops at the
first failed sample or resource invariant. Runs are serial; it never terminates
both nodes or both local services concurrently. The default is three samples,
with a maximum of 20 per invocation.

```bash
sudo tools/qualification/linux-crash-repeat.sh \
  --node-label ubuntu-a \
  --peer-label ubuntu-b \
  --peer-v4 100.64.0.6 \
  --peer-v6 fd7a:115c:a1e0::d \
  --peer-name ubuntu-b \
  --service meshd \
  --iterations 3 \
  --ready-timeout-seconds 20 \
  --artifact-sha256 SHA256_OF_DEB \
  >ubuntu-a-meshd-crash-repeat.json
```

After every sample the runner requires exactly one daemon process, one helper
process, one data interface, one DNS interface, one UDP resolver listener, and
one TCP resolver listener. It hashes but does not emit the identity/profile/env
contents, route set, or per-link resolver configuration, and requires all three
to equal the baseline. Only the kernel-assigned DNS link index is normalized
before comparison because it must change when the non-persistent link is
recreated. Descriptor counts may exceed the initial steady-state count by at
most four to accommodate connection timing; a new process with zero observable
descriptors is always a failure.

The aggregate schema is
`meshtransit.linux-crash-repeat-qualification/v1`. It retains redacted
single-run measurements, per-sample resource checks, nearest-rank p95 full
readiness and stable-traffic timings, and the count of error-level service log
entries. The outer trap starts both services after interruption or failure and
deletes all temporary reports.

The first complete two-node alpha15 restart matrix is recorded in
[linux-restart-qualification-2026-09-11.md](linux-restart-qualification-2026-09-11.md),
with its redacted machine-readable reports retained under `docs/evidence`. The
same document records the first alpha16 abrupt-termination matrix; those reports
are retained under
[`docs/evidence/linux-crash-recovery-alpha16-s1`](evidence/linux-crash-recovery-alpha16-s1).
The first three-sample matrix for every node/service combination is retained
under
[`docs/evidence/linux-crash-repeat-alpha16-s1`](evidence/linux-crash-repeat-alpha16-s1).
The release-candidate matrix expands this to five samples for both services on
Ubuntu 26.04 ARM64 and AMD64. Its runner latches transient `NRestarts` peaks but
uses the installed restart policy, durable systemd `InvocationID` transition,
and process-generation transition as the automatic-recovery boundary. All 20
samples passed; the reports are retained under
[`docs/evidence/linux-crash-repeat-rc3-s1`](evidence/linux-crash-repeat-rc3-s1/README.md).

## Chain helper recovery and network change

The chained harness invokes the existing single-run tools serially. It first
qualifies `meshnetd SIGKILL`, including the mandatory coordinated `meshd`
generation change, and then launches the controlled dummy-interface scenario
as its first post-recovery action. The confirmation label must exactly match
the node label.

```bash
sudo tools/qualification/linux-helper-recovery-change.sh \
  --node-label ubuntu-a \
  --peer-label ubuntu-b \
  --peer-v4 100.64.0.6 \
  --peer-v6 fd7a:115c:a1e0::d \
  --peer-name ubuntu-b \
  --artifact-sha256 SHA256_OF_DEB \
  --confirm-recovery-change ubuntu-a \
  >ubuntu-a-helper-recovery-change.json
```

The aggregate schema is
`meshtransit.linux-helper-recovery-change-qualification/v1`. A pass requires
both child reports to pass and match exactly on topology, platform, and
artifact metadata. The network-change counters must advance, and the recovered
`meshd` and `meshnetd` PIDs and restart counters must remain stable throughout
the network-change phase. Raw PIDs are compared in memory but omitted from the
report. Both child reports retain their existing redaction contract.

The chain shortens only the healthy stability tail after crash recovery and the
healthy lead before the dummy-interface action to one second each. It retains
the 20-second readiness and endpoint-refresh deadlines and the full five-second
network-change stability tail. Failure or interruption starts both services;
the child network-change trap owns removal of its dedicated interface.

The first passing two-node alpha16 chain is recorded in
[linux-helper-recovery-change-qualification-2026-09-12.md](linux-helper-recovery-change-qualification-2026-09-12.md),
with its redacted reports retained under `docs/evidence`.

## Run local runtime-recovery qualification

The runtime-recovery harness proves a different boundary from a systemd crash
test. It intentionally starts a fresh `meshd` generation while the fixed
`meshnetd` socket temporarily has mode `000`. The unprivileged daemon must stay
alive, expose a pending local-runtime failure, and retry from a fresh full map.
After the harness restores the package mode `0660`, that exact daemon and helper
generation must synchronize TUN and DNS without an automatic service restart.

```bash
sudo tools/qualification/linux-runtime-recovery.sh \
  --node-label ubuntu-amd64 \
  --artifact-sha256 SHA256_OF_DEB \
  --confirm-helper-socket-fault ubuntu-amd64 \
  >ubuntu-amd64-runtime-recovery.json
```

The explicit confirmation must exactly match the node label. Preflight requires
an online registered node, both packaged services, the package-owned `0660`
helper socket, and active data and DNS interfaces. The test does not require a
peer and does not modify profile, identity, policy, control, or default-route
state. An exit trap restores the socket mode and starts both services after any
failure or interruption.

The report schema is
`meshtransit.linux-runtime-recovery-qualification/v1`. It contains only the
operator label, kernel/architecture, artifact identity, aggregate timing and
recovery counters, service-generation comparisons, and final readiness. It
omits process IDs, socket paths, network names, addresses, fingerprints, error
text, and control or identity data. A pass requires the pending state to be
observed, both counters to advance, final `pending=false`, synchronized control,
configured DNS, both interfaces, restored socket mode, and unchanged daemon and
helper generations/restart counters throughout recovery.

For repeatability and resource-stability evidence, run the serial aggregate
gate. It stops at the first failed sample and uses the same explicit fault
confirmation as the single-run harness.

```bash
sudo tools/qualification/linux-runtime-recovery-repeat.sh \
  --node-label ubuntu-amd64 \
  --iterations 5 \
  --artifact-sha256 SHA256_OF_DEB \
  --confirm-helper-socket-fault ubuntu-amd64 \
  >ubuntu-amd64-runtime-recovery-repeat.json
```

The aggregate schema is
`meshtransit.linux-runtime-recovery-repeat-qualification/v1`. Every sample must
pass the single-run report validator and retain the same platform and artifact
identity. After each sample the gate requires one process per service, one data
and DNS interface, one UDP and TCP DNS listener, unchanged persisted bytes,
explicit peer routes, self addresses and resolver state, stable systemd restart
counters, the packaged helper socket contract, bounded descriptor growth, ready
status, and no pending recovery. Transient kernel route or link convergence is given a bounded
five-second window; the report retains both the initial failure codes and the
time until all invariants become stable. Its report contains the redacted child
evidence and nearest-rank p95 times for observing the failure and returning to
synchronized service. The route digest covers explicit peer routes but excludes
address-derived `proto kernel` routes, whose IPv6 DAD timing is not controlled
by MeshTransit; an independent digest requires the exact global self-address
set to remain unchanged.
The baseline peer count is pinned for the run, and each resource check reports
only that aggregate count plus the explicit route count. A topology change is
classified as `peer_count_changed` instead of being mistaken for a recovery
regression; no peer identity or route value is emitted.

The first native rc5 5/5 result on Ubuntu 26.04 amd64 and arm64 is recorded in
[linux-runtime-recovery-repeat-qualification-2026-09-13.md](linux-runtime-recovery-repeat-qualification-2026-09-13.md),
with the two redacted aggregate reports retained under `docs/evidence`.

For the final traffic-bearing gate, run the aggregate wrapper on each node in a
fixed two-peer topology. It continuously probes IPv4, IPv6, and uncached
MagicDNS while each nested sample executes the complete runtime and resource
gate:

```bash
sudo tools/qualification/linux-runtime-recovery-traffic.sh \
  --node-label ubuntu-amd64 \
  --peer-label ubuntu-arm64 \
  --peer-v4 PEER_OVERLAY_V4 \
  --peer-v6 PEER_OVERLAY_V6 \
  --peer-name PEER_MAGICDNS_NAME \
  --iterations 3 \
  --artifact-sha256 SHA256_OF_DEB \
  --confirm-helper-socket-fault ubuntu-amd64 \
  >ubuntu-amd64-runtime-recovery-traffic.json
```

The schema is
`meshtransit.linux-runtime-recovery-traffic-qualification/v1`. Every traffic
class must observe an outage after the action begins, recover before the
deadline, and finish with at least three consecutive successful attempts. DNS
queries bypass the host cache and must contain the exact peer A and AAAA
answers. The retained report contains only labels, artifact/platform identity,
aggregate probe counters, timings, and the redacted nested runtime summary.

The first native RC5 3/3 result in both directions on Ubuntu 26.04 AMD64 and
ARM64 is recorded in
[linux-runtime-recovery-traffic-qualification-2026-09-13.md](linux-runtime-recovery-traffic-qualification-2026-09-13.md).

## Run a fixed-topology soak

The soak harness is read-only and runs on the node under test. It samples the
authenticated local status API and `/proc`, checks service generations and
restart counters, and verifies process/interface/listener cardinality,
persisted identity/configuration bytes, routes, resolver policy, MagicDNS, and
one IPv4 plus one IPv6 peer probe at every interval.

```bash
sudo tools/qualification/linux-soak-systemd.sh start \
  --run-id linux-rc1-a \
  -- \
  --node-label ubuntu-a \
  --peer-label ubuntu-b \
  --peer-v4 100.64.0.6 \
  --peer-v6 fd7a:115c:a1e0::d \
  --peer-name ubuntu-b \
  --artifact-sha256 SHA256_OF_DEB
```

The launcher creates a new root-owned mode-`0700` directory at
`/root/meshtransit-qualification/linux-rc1-a`, installs a private, pinned,
read-only copy of the harness, and starts
`meshtransit-soak-linux-rc1-a.service`. Its report and stderr paths are printed
after the unit is verified active. The report remains empty until the harness
finishes; this is expected and must not be treated as a stalled run.

Release-candidate execution is deliberately restart-intolerant. The transient
unit sets `RefuseManualStop=yes`, which Ubuntu `needrestart` checks before
selecting a service after library upgrades, and `Restart=no`, so a crash cannot
silently begin a new evidence window. It does not disable unattended security
updates or globally exclude any service. A host reboot, observer termination,
or missing unit therefore fails the run and requires a new run ID. To abort a
known unit deliberately, independently verify its exact name and then use
`systemctl kill`; `systemctl restart` and `systemctl stop` are intentionally
refused while the gate is active.

Release-candidate defaults run for 72 hours, sample every 30 seconds, and use
the first sample at or after one hour as the steady-state memory baseline. A
pass requires every sample to remain healthy, unchanged service generations,
no warning-level service journal entries, maximum post-warmup RSS growth of at
most ten percent for either process, and no more than eight goroutines or four
threads/descriptors above the steady-state baseline. Shorter runs may validate
the harness but are marked `scenario.release_candidate_eligible: false`.

The current schema is `meshtransit.linux-soak-qualification/v2`. It records
only whether the observer was systemd-bound and restart-protected; it does not
emit the unit name or invocation identifier. Historical alpha17 smoke evidence
uses schema v1. Reports retain only
operator labels, artifact/platform metadata, booleans, aggregate status,
resource counters, and traffic success. They omit raw PIDs, state digests,
addresses, DNS names and answers, profile/network identity, control
fingerprints, endpoint data, and packet contents. The static data-plane queue
caps prevent unbounded allocation; runtime goroutine, heap/object, system
memory, RSS, thread, and descriptor trends detect retained work without
exposing a profiling endpoint.

The first accepted native two-node alpha17 smoke is recorded in
[linux-soak-qualification-2026-09-12.md](linux-soak-qualification-2026-09-12.md),
with both redacted seven-sample reports retained under `docs/evidence`. The
90-second smokes validate the instrumentation and harness but are not
release-candidate evidence; the 72-hour gate remains.

## Run a reboot scenario

Run the reboot harness from an operator host that can reach two registered
Linux nodes over SSH. The target is the only node rebooted. The observer stays
online and records IPv4 and IPv6 traffic for the complete bounded window.

The harness rejects SSH option and shell metacharacter injection, uses strict
host-key checking, and requires `--confirm-reboot` to exactly match the target
label. A changed kernel boot ID is mandatory evidence; observing an SSH outage
is recorded but is not mandatory because a short outage can fall between
polls. Raw traffic, SSH destinations, overlay addresses, DNS answers, boot IDs,
profile IDs, and control fingerprints are not included in the JSON report.

```bash
tools/qualification/linux-reboot.sh \
  --target-ssh root@TARGET_HOST \
  --observer-ssh root@OBSERVER_HOST \
  --target-label ubuntu-a \
  --observer-label ubuntu-b \
  --target-v4 100.64.0.5 \
  --target-v6 fd7a:115c:a1e0::6 \
  --target-name ubuntu-a \
  --observer-v4 100.64.0.6 \
  --observer-v6 fd7a:115c:a1e0::d \
  --observer-name ubuntu-b \
  --artifact-sha256 SHA256_OF_DEB \
  --confirm-reboot ubuntu-a \
  >ubuntu-a-reboot.json
```

Use `--ssh-driver rtk` when the operator environment routes SSH through RTK.
The selected driver is used consistently for preflight, reboot, readiness
polling, and both long-running traffic streams.

Preflight requires both nodes to be online, synchronized, registered, and able
to exchange dual-stack traffic. After the reboot, the target must recover both
services, the data interface and peer routes, daemon readiness, exact MagicDNS
answers, and outbound dual-stack traffic. The active profile, profile count,
self addresses, daemon version, and daemon commit must remain unchanged.

Defaults provide a three-second healthy lead, a 60-second recovery deadline, a
five-second stability tail, and a 75-second observation window. The operator
host clock must remain stable during the run. Reverse target and observer and
repeat the scenario on the second node; never reboot both nodes concurrently.

The reboot schema identifier is
`meshtransit.linux-reboot-qualification/v1`. A passing report requires a changed
boot ID, all readiness and persistence gates, parseable IPv4 and IPv6 traffic,
and a final stable traffic run that begins within the recovery deadline.

The first complete two-node alpha15 reboot matrix is recorded in
[linux-reboot-qualification-2026-09-11.md](linux-reboot-qualification-2026-09-11.md),
with its redacted machine-readable reports retained under `docs/evidence`.
The release-candidate matrix adds native Ubuntu 26.04 ARM64 and AMD64 coverage;
both controlled reboot scenarios passed and their reports are retained under
[`docs/evidence/linux-reboot-rc3-s1`](evidence/linux-reboot-rc3-s1/README.md).

## Run a network-change scenario

The network-change harness runs on the node under test. It requires an exact
`--confirm-network-change` match, refuses to reuse an existing interface, and
creates only a dedicated dummy interface with one fixed RFC 2544 benchmarking
address. It does not change the real uplink, default route, `mesh0`, or
`meshdns0`. A trap removes the test interface if the run is interrupted.

```bash
sudo tools/qualification/linux-network-change.sh \
  --node-label ubuntu-a \
  --peer-label ubuntu-b \
  --peer-v4 100.64.0.6 \
  --peer-v6 fd7a:115c:a1e0::d \
  --peer-name ubuntu-b \
  --artifact-sha256 SHA256_OF_DEB \
  --confirm-network-change ubuntu-a \
  >ubuntu-a-network-change.json
```

The schema identifier is
`meshtransit.linux-network-change-qualification/v1`. Preflight requires both
services, MagicDNS, a direct peer path, dual-stack traffic, and the
`network_changes` status counters. A pass requires meshd to observe the change,
complete endpoint discovery within 20 seconds, retain a usable direct path and
stable dual-stack traffic, and remove the dedicated interface. Reports contain
only labels, artifact/platform metadata, aggregate counters, and timings.

This controlled scenario qualifies notification, coalescing, daemon handoff,
endpoint refresh, and no-regression behavior without risking SSH access. It is
not evidence for migration between two real underlays. That stronger test needs
a multi-homed lab with an independent management path and scheduled rollback.

The initial repeatability matrix and the later two-node alpha15 validation are
recorded in
[linux-network-change-qualification-2026-09-11.md](linux-network-change-qualification-2026-09-11.md),
with redacted alpha15 reports retained under `docs/evidence`. They are Linux
alpha POC evidence and do not replace the larger real multi-uplink sample set
required for release-candidate p95 qualification.

## Run a relay-fallback scenario

The relay-fallback harness runs on a node with exactly one installed peer. It
requires every current underlay address advertised by that peer, including
public, private, and IPv6 candidates where present. Omitting a usable candidate
leaves the path direct and causes the run to fail instead of producing false
relay evidence.

Preflight requires an online synchronized daemon, one direct peer, at least one
connected relay region, exact MagicDNS answers, dual-stack traffic, and routes
that separate overlay from underlay addresses. The harness refuses to reuse its
fixed `meshd_relay_qual` nftables table. It then atomically creates two hooks
which drop only UDP whose source or destination is one of the explicit peer
underlay addresses. It never changes SSH, routes, interfaces, DNS, control or
relay destinations. A trap deletes the dedicated table after failure, signal,
or successful completion.

```bash
sudo tools/qualification/linux-relay-fallback.sh \
  --node-label ubuntu-a \
  --peer-label ubuntu-b \
  --peer-v4 100.64.0.6 \
  --peer-v6 fd7a:115c:a1e0::d \
  --peer-name ubuntu-b \
  --peer-underlay-v4 PEER_PUBLIC_IPV4 \
  --peer-underlay-v4 PEER_PRIVATE_IPV4 \
  --artifact-sha256 SHA256_OF_DEB \
  --confirm-direct-loss ubuntu-a \
  >ubuntu-a-relay-fallback.json
```

The schema identifier is
`meshtransit.linux-relay-fallback-qualification/v1`. A pass requires nftables
drop counters to prove that direct traffic hit the fault, aggregate status to
change from one direct peer to one relay peer within 10 seconds, successful
IPv4 and IPv6 traffic while the fault remains active, complete table removal,
and return to a stable direct path within 15 seconds. Reports contain only
operator labels, candidate counts, artifact/platform metadata, aggregate
counters, and timings. Raw endpoint and overlay addresses are never emitted;
temporary probe logs are deleted with the mode-`0700` directory.

Reverse node and peer inputs and repeat the scenario on the second host. Never
run it concurrently on both ends of the same peer relationship. The initial
repeatability matrix and the later two-node alpha15 validation are recorded in
[linux-relay-fallback-qualification-2026-09-11.md](linux-relay-fallback-qualification-2026-09-11.md),
with redacted alpha15 reports retained under `docs/evidence`. They are Linux
alpha evidence and do not qualify an IPv6-only underlay or the release-candidate
p95 target.

## Run a DNS lifecycle scenario

The DNS harness runs on the node under test and requires `--confirm-dns-lifecycle`
to exactly match its operator label. Preflight verifies the installed split-only
configuration, dedicated UDP/TCP listeners, authoritative A/AAAA/PTR/NODATA/
NXDOMAIN behavior, short-name search, FQDN resolution, and isolation of the
host's non-mesh DNS path.

It then stops only `meshd.service`, verifies that the dedicated link, listeners,
and per-link resolved state disappear while external DNS remains available, and
starts the daemon again. A trap starts the service after interruption or failure.
It does not stop `meshnetd`, edit resolver files, change the default route, or
modify control-plane DNS configuration.

```bash
sudo tools/qualification/linux-dns.sh \
  --node-label ubuntu-a \
  --peer-label ubuntu-b \
  --peer-v4 100.64.0.6 \
  --peer-v6 fd7a:115c:a1e0::d \
  --peer-name ubuntu-b \
  --dns-domain NETWORK_DNS_DOMAIN \
  --artifact-sha256 SHA256_OF_DEB \
  --confirm-dns-lifecycle ubuntu-a \
  >ubuntu-a-dns.json
```

The schema identifier is `meshtransit.linux-dns-qualification/v1`. Reports do
not include DNS names, DNS answers, addresses, network identifiers, resolver
responses, control fingerprints, or raw daemon status. A pass requires cleanup
and restoration within 20 seconds, continued non-mesh DNS during the stop, and
all authoritative and host-integration checks after recovery.

Reverse the node and peer arguments and repeat on the second host. The initial
matrix and the later two-node alpha15 lifecycle validation are recorded in
[linux-dns-qualification-2026-09-11.md](linux-dns-qualification-2026-09-11.md),
with redacted alpha15 reports retained under `docs/evidence`. The initial run
also staged control-configured upstream split and explicit-default resolvers,
verified both nodes, and restored the original split-only configuration. That
mutation is deliberately operator-driven rather than part of the host-local
lifecycle harness. The same three-phase update and rollback matrix has now been
repeated on alpha15 without restarting either daemon, with redacted aggregate
evidence retained under `docs/evidence`.

Alpha16 additionally has one bounded two-node upstream-failure matrix. An
ordered non-responsive/responsive resolver pair failed over after one bounded
attempt on every query; the non-responsive-only phase returned `SERVFAIL` and
packet capture found no query to an unexpected DNS destination. The temporary
split route was then removed and both clients returned to their exact
MagicDNS-only baseline without restart. Redacted aggregate evidence is retained
under
[`docs/evidence/linux-dns-alpha16-upstream-failure-s1`](evidence/linux-dns-alpha16-upstream-failure-s1).

For release-candidate repetition, use a dedicated Network that does not contain
soak or production nodes. Commit the ordered split route through the authenticated
control API, wait for the route on both clients, and run the node-local gate on
each architecture:

```bash
sudo tools/qualification/linux-dns-upstream.sh \
  --node-label ubuntu-arm64 \
  --peer-label ubuntu-amd64 \
  --peer-v4 PEER_OVERLAY_V4 \
  --peer-v6 PEER_OVERLAY_V6 \
  --peer-name PEER_MAGICDNS_NAME \
  --magic-domain NETWORK_MAGICDNS_DOMAIN \
  --test-domain example.com \
  --test-query example.com \
  --phase failover \
  --blocked-resolver FIRST_RESOLVER_IPV4 \
  --fallback-resolver SECOND_RESOLVER_IPV4 \
  --samples 5 \
  --artifact-sha256 SHA256_OF_DEB \
  --confirm-dns-upstream ubuntu-arm64 \
  >ubuntu-arm64-failover.json
```

Both declared resolvers must answer UDP and TCP before fault injection. The
harness then installs one temporary nftables output chain scoped to the
non-root `meshd` UID, drops only port 53 traffic to the declared first resolver,
and counts blocked, fallback, and unexpected destinations. Each UDP and TCP
query must return the phase-specific outcome inside the bounded query window.
The harness does not require a minimum delay: resolver racing can select the
fallback immediately, while cached health or a circuit breaker can produce an
immediate fail-closed result. Resolver counters prove that the injected fault
was exercised. MagicDNS, dual-stack peer traffic, daemon generation, and
restart count must remain stable. A trap removes the exact qualification table.

For `fail-closed`, publish only the first resolver, omit
`--fallback-resolver`, and require bounded `SERVFAIL` through both direct and
host-resolver paths. Finally restore the exact control snapshot and run
`--phase rollback` without either resolver argument. Rollback requires the
temporary split route to be absent, public resolution to avoid the MeshTransit
link, local forwarding to fail closed, and all continuity gates to remain
healthy. The harness deliberately does not hold browser credentials or mutate
control state; configuration changes remain authenticated, versioned CAS
operations with an operator-visible rollback.

Use a distinct, previously uncached query name for each phase and wait for the
new control revision and split-route state before collecting a retained sample.
Do not weaken the destination gate to accommodate traffic left in flight from a
prior revision; discard that transition sample and repeat only after the old
resolver work has drained.

The RC4 candidate passed the three-phase matrix with five UDP and five TCP
samples per phase on Ubuntu 26.04 AMD64 and ARM64. Every retained report had
zero unexpected resolver packets, preserved daemon generations and restart
counters, and passed MagicDNS and dual-stack peer continuity. DNS and policy
were restored to the exact MagicDNS-only/default-deny baseline afterward. See
[`docs/evidence/linux-dns-rc4-upstream-failure-s1`](evidence/linux-dns-rc4-upstream-failure-s1/README.md).

## Run a host-policy phase

Run the policy harness from an operator host that can reach both installed
nodes over SSH. The control policy must already be active and converged before
each invocation. The harness does not edit policy itself; all eight directional
protocol expectations are mandatory so an untested direction cannot be
mistaken for a pass.

```bash
tools/qualification/linux-policy.sh \
  --node-a-ssh root@NODE_A_HOST \
  --node-b-ssh root@NODE_B_HOST \
  --node-a-label ubuntu-a \
  --node-b-label ubuntu-b \
  --node-a-v4 NODE_A_OVERLAY_V4 \
  --node-a-v6 NODE_A_OVERLAY_V6 \
  --node-b-v4 NODE_B_OVERLAY_V4 \
  --node-b-v6 NODE_B_OVERLAY_V6 \
  --phase-label asymmetric-a-to-b \
  --expect-a-to-b-tcp allow \
  --expect-a-to-b-udp allow \
  --expect-a-to-b-icmp4 allow \
  --expect-a-to-b-icmp6 allow \
  --expect-b-to-a-tcp deny \
  --expect-b-to-a-udp deny \
  --expect-b-to-a-icmp4 deny \
  --expect-b-to-a-icmp6 deny \
  --artifact-sha256 SHA256_OF_DEB \
  --confirm-policy-test asymmetric-a-to-b \
  --ssh-driver rtk \
  >asymmetric-a-to-b.json
```

Any expected allow requires a visible encrypted peer path and exact host routes
on both nodes. An all-deny phase accepts a reduced map with no visible peer so
default deny remains testable. Both services, registered identity, synchronized
control session, exact self addresses, and a valid policy revision remain
mandatory in every phase. A phase with an expected allow additionally requires
the data interface and encrypted peer path. A deny-only phase permits the
healthy `offline`/`idle` state when the reduced map removes every authorized
peer path. Current artifacts may retain a peerless data interface for endpoint
presence, but it must contain no peer routes; older artifacts may remove the
interface entirely.

TCP and UDP run over IPv4 and IPv6 with a fixed-format random challenge served
under the unprivileged `meshd` identity. ICMP probes use distinct echo
identifiers for each direction, preventing a reply tracked for one direction
from authorizing the reverse test. If an all-deny reduced map has no mesh route,
the corresponding probes are not sent through the underlay default route; the
report records that route absence and exit code `90` as the denial mechanism.
If a deny-only map removes a source address or inbound route during listener
startup, the harness re-checks the affected route before accepting the
transition as denial evidence. A missing listener while its inbound route
remains is still an infrastructure failure.
The report schema is `meshtransit.linux-policy-qualification/v1`. Reports omit
SSH destinations, overlay addresses, policy contents, raw status, and payloads.
See [policy.md](policy.md) for the complete enforcement and staged rollback
contract.

The bounded two-node matrix history is recorded in
[linux-policy-qualification-2026-09-11.md](linux-policy-qualification-2026-09-11.md).
It includes the first complete alpha15 sample and its redacted machine-readable
reports plus an independent second sample. The two samples complete the bounded
policy-matrix repeatability gate for the current Linux alpha topology; they do
not replace the remaining release-candidate qualification.

## Local validation

The restart parser has deterministic recovery and no-recovery fixtures. The
reboot validation tests cover SSH destination filtering, explicit target
confirmation, clock progression, and help output.

```bash
bash -n tools/qualification/linux-restart.sh \
  tools/qualification/test-linux-restart.sh \
  tools/qualification/linux-crash-repeat.sh \
  tools/qualification/test-linux-crash-repeat.sh \
  tools/qualification/linux-reboot.sh \
  tools/qualification/test-linux-reboot.sh \
  tools/qualification/linux-network-change.sh \
  tools/qualification/test-linux-network-change.sh \
  tools/qualification/linux-helper-recovery-change.sh \
  tools/qualification/test-linux-helper-recovery-change.sh \
  tools/qualification/linux-runtime-recovery.sh \
  tools/qualification/test-linux-runtime-recovery.sh \
  tools/qualification/linux-runtime-recovery-repeat.sh \
  tools/qualification/test-linux-runtime-recovery-repeat.sh \
  tools/qualification/linux-soak.sh \
  tools/qualification/linux-soak-systemd.sh \
  tools/qualification/test-linux-soak.sh \
  tools/qualification/test-linux-soak-systemd.sh \
  tools/qualification/linux-relay-fallback.sh \
  tools/qualification/test-linux-relay-fallback.sh \
  tools/qualification/linux-dns.sh \
  tools/qualification/test-linux-dns.sh \
  tools/qualification/linux-dns-upstream.sh \
  tools/qualification/test-linux-dns-upstream.sh \
  tools/qualification/linux-policy.sh \
  tools/qualification/test-linux-policy.sh \
  tools/qualification/testdata/ping
shellcheck tools/qualification/linux-restart.sh \
  tools/qualification/test-linux-restart.sh \
  tools/qualification/linux-crash-repeat.sh \
  tools/qualification/test-linux-crash-repeat.sh \
  tools/qualification/linux-reboot.sh \
  tools/qualification/test-linux-reboot.sh \
  tools/qualification/linux-network-change.sh \
  tools/qualification/test-linux-network-change.sh \
  tools/qualification/linux-helper-recovery-change.sh \
  tools/qualification/test-linux-helper-recovery-change.sh \
  tools/qualification/linux-runtime-recovery.sh \
  tools/qualification/test-linux-runtime-recovery.sh \
  tools/qualification/linux-runtime-recovery-repeat.sh \
  tools/qualification/test-linux-runtime-recovery-repeat.sh \
  tools/qualification/linux-soak.sh \
  tools/qualification/linux-soak-systemd.sh \
  tools/qualification/test-linux-soak.sh \
  tools/qualification/test-linux-soak-systemd.sh \
  tools/qualification/linux-relay-fallback.sh \
  tools/qualification/test-linux-relay-fallback.sh \
  tools/qualification/linux-dns.sh \
  tools/qualification/test-linux-dns.sh \
  tools/qualification/linux-dns-upstream.sh \
  tools/qualification/test-linux-dns-upstream.sh \
  tools/qualification/linux-policy.sh \
  tools/qualification/test-linux-policy.sh \
  tools/qualification/testdata/ping
PYTHONPYCACHEPREFIX=/tmp/meshd-pycache \
  python3 -m py_compile tools/qualification/testdata/policy_peer.py
bash tools/qualification/test-linux-restart.sh
bash tools/qualification/test-linux-crash-repeat.sh
bash tools/qualification/test-linux-reboot.sh
bash tools/qualification/test-linux-network-change.sh
bash tools/qualification/test-linux-helper-recovery-change.sh
bash tools/qualification/test-linux-runtime-recovery.sh
bash tools/qualification/test-linux-runtime-recovery-repeat.sh
bash tools/qualification/test-linux-soak.sh
bash tools/qualification/test-linux-soak-systemd.sh
bash tools/qualification/test-linux-relay-fallback.sh
bash tools/qualification/test-linux-dns.sh
bash tools/qualification/test-linux-dns-upstream.sh
bash tools/qualification/test-linux-policy.sh
```
