# Linux qualification

The Linux qualification tools measure recovery of one installed MeshTransit
node against one healthy peer. They cover explicit restart of either
`meshd.service` or `meshnetd.service`, a full host reboot, and a controlled
interface-address change. They also exercise direct-path loss, relay fallback,
and later direct recovery. Package upgrade, real multi-uplink migration, and
soak scenarios remain separate gates.

## Restart safety boundary

The harness runs on the node being tested and requires root only for the selected
`systemctl restart`. It accepts exactly `meshd` or `meshnetd` as the service. It
does not remove packages, purge state, change profiles or policy, write identity
files, or change routes and resolver configuration directly.

Preflight must prove all of the following before the restart is attempted:

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

## Restart prerequisites

Run the harness on a supported Ubuntu host with the packaged services already
registered. It requires Bash, `iproute2`, `iputils-ping`, `jq`, `meshctl`,
`systemd`, `systemd-resolved`, and GNU `timeout`. The peer must stay healthy for
the complete observation window. Current policy must allow ICMP and IPv6 ICMP
between the two test nodes.

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

A passing single run proves only that scenario. It does not establish p95
latency or the 72-hour reliability target. Aggregate candidate reports must also
record sample count, topology/load definition, artifact digest, and percentile
calculations as required by [release-v0.1.md](release-v0.1.md).

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
The harness still uses plain `ssh` for the two long-running traffic streams so
the wrapper cannot outlive or truncate their observation window.

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

The first two-node repeatability evidence is recorded in
[linux-network-change-qualification-2026-09-11.md](linux-network-change-qualification-2026-09-11.md).
It is Linux alpha POC evidence and does not replace the larger real multi-uplink
sample set required for release-candidate p95 qualification.

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
run it concurrently on both ends of the same peer relationship. The first
two-node repeatability evidence is recorded in
[linux-relay-fallback-qualification-2026-09-11.md](linux-relay-fallback-qualification-2026-09-11.md).
It is Linux alpha evidence and does not qualify an IPv6-only underlay or the
release-candidate p95 target.

## Local validation

The restart parser has deterministic recovery and no-recovery fixtures. The
reboot validation tests cover SSH destination filtering, explicit target
confirmation, clock progression, and help output.

```bash
bash -n tools/qualification/linux-restart.sh \
  tools/qualification/test-linux-restart.sh \
  tools/qualification/linux-reboot.sh \
  tools/qualification/test-linux-reboot.sh \
  tools/qualification/linux-network-change.sh \
  tools/qualification/test-linux-network-change.sh \
  tools/qualification/linux-relay-fallback.sh \
  tools/qualification/test-linux-relay-fallback.sh \
  tools/qualification/testdata/ping
shellcheck tools/qualification/linux-restart.sh \
  tools/qualification/test-linux-restart.sh \
  tools/qualification/linux-reboot.sh \
  tools/qualification/test-linux-reboot.sh \
  tools/qualification/linux-network-change.sh \
  tools/qualification/test-linux-network-change.sh \
  tools/qualification/linux-relay-fallback.sh \
  tools/qualification/test-linux-relay-fallback.sh \
  tools/qualification/testdata/ping
bash tools/qualification/test-linux-restart.sh
bash tools/qualification/test-linux-reboot.sh
bash tools/qualification/test-linux-network-change.sh
bash tools/qualification/test-linux-relay-fallback.sh
```
