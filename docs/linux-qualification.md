# Linux restart qualification

The Linux restart harness measures recovery of one installed MeshTransit node
against one healthy peer. It is the first native reliability tool for the v0.1
release contract. The current scenario covers an explicit restart of either
`meshd.service` or `meshnetd.service`; package upgrade, boot recovery, network
change, and soak scenarios remain separate gates.

## Safety boundary

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

## Prerequisites

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
IPv4/IPv6 probes every 200 milliseconds. Timing parameters are available for
controlled experiments, but release-candidate runs use the documented defaults.

## Report contract

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

## Local validation

The ping parser has deterministic recovery and no-recovery fixtures:

```bash
bash -n tools/qualification/linux-restart.sh \
  tools/qualification/test-linux-restart.sh
shellcheck tools/qualification/linux-restart.sh \
  tools/qualification/test-linux-restart.sh
bash tools/qualification/test-linux-restart.sh
```
