# Linux repeated crash-recovery rc3 — sample 1

These reports cover five serial `SIGKILL` samples for each MeshTransit service
on Ubuntu 26.04 ARM64 and AMD64. The two dedicated qualification nodes acted as
healthy peers for one another; the long-running soak nodes were not used.

- Runtime: `0.1.0~rc3+69e5e2f`
- Runtime commit: `69e5e2f00f0fead79e5baf4848725ee3aa6590b6`
- ARM64 package SHA-256:
  `c3ac50a269cbf90605f4123834072630d985f9db9ab8f4ec44d2653d6621a0fd`
- AMD64 package SHA-256:
  `2eade02dbbe869b3bbbe9fe393e7622d57f78b6976f193b6f26e67e6b9fe1cb4`
- Qualification runner commit: `98478a76fa1708ecf7edf71661c2e2145a78f8ce`
- Single-run harness SHA-256:
  `b0e39b5c19b6bd94e341588f3684ab5112d5762097e8e75cbaf9fb1493108d50`
- Repeat-runner SHA-256:
  `32b8d80b2c3b64dfa01dc1275e54e9aece8b42a8e557654869fd19f254452e42`
- Scenarios: 4
- SIGKILL samples: 20
- Result: 20 pass, 0 fail
- Readiness deadline: 20 seconds per sample
- Slowest per-scenario nearest-rank p95 full readiness: 4,257 ms
- Slowest per-scenario nearest-rank p95 stable traffic recovery: 4,425 ms
- Slowest per-scenario nearest-rank p95 DNS cleanup: 88 ms

The qualification runner records both the peak `NRestarts` value and a durable
systemd `InvocationID` generation change. This avoids a timing race on systemd
259, where a successful activation can reset `NRestarts` before the new PID is
visible, while still requiring an installed restart policy that covers
`SIGKILL`, a new service invocation, and a new process generation. Every
`meshnetd` sample additionally required a new `meshd` generation.

Every post-sample resource check found both services active, exactly one daemon
and helper process, one data link, one DNS link, one UDP listener, and one TCP
listener. Persisted identity/profile/configuration bytes and modes, the complete
data-link route set, and semantic per-link resolver state remained equal to the
scenario baselines. Descriptor growth stayed within the four-descriptor timing
headroom, and no error-level service log entry was observed.

The reports omit peer addresses, DNS names and answers, process and invocation
identifiers, route and resolver contents, persisted-state hashes, network
identifiers, control fingerprints, and raw traffic output. With five samples
per scenario, nearest-rank p95 equals that scenario's maximum sample. This is a
bounded repeated-crash result; it does not establish crash-storm behavior past
the configured systemd rate boundary or replace the 72-hour reliability gate.
