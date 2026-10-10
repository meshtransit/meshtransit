# Linux reboot recovery rc3 — sample 1

These reports cover one controlled reboot of each dedicated Ubuntu 26.04
qualification node while the other architecture remained online and observed
continuous IPv4 and IPv6 mesh traffic. The long-running soak nodes were not
used or modified.

- Runtime: `0.1.0~rc3+69e5e2f`
- Runtime commit: `69e5e2f00f0fead79e5baf4848725ee3aa6590b6`
- ARM64 package SHA-256:
  `c3ac50a269cbf90605f4123834072630d985f9db9ab8f4ec44d2653d6621a0fd`
- AMD64 package SHA-256:
  `2eade02dbbe869b3bbbe9fe393e7622d57f78b6976f193b6f26e67e6b9fe1cb4`
- Qualification runner commit: `d39f865a90c4ceea529d48b32393b529c3116b15`
- Reboot harness SHA-256:
  `a45c4fb5d69f33de2d9e67f052a5ff732c74cb554a3ce243ba9d852aea5db1de`
- Traffic parser SHA-256:
  `5cf4062ee43080c6e2584417414c0d49c7e06c65cf6e3f29197ed2a0f3dfa690`
- Scenarios: 2
- Result: 2 pass, 0 fail
- Recovery deadline: 60 seconds per node
- Slowest SSH and changed-boot-ID observation: 18,371 ms
- Slowest stable dual-stack traffic recovery: 25,694 ms
- Slowest complete readiness: 29,969 ms

Both runs observed a real SSH outage and a changed kernel boot ID. After boot,
both services, the data interface and routes, daemon control synchronization,
MeshTransit DNS, and outbound dual-stack traffic recovered before the deadline. The
active profile, profile count, self addresses, runtime version, and runtime
commit remained unchanged. Each observer then recorded more than 200
consecutive replies per address family after stable recovery.

The selected SSH driver is used for every remote operation, including the two
long-running observer streams. The traffic parser permits at most one terminal
request counted by `iputils ping` before its reply can arrive at the observation
deadline; that request remains recorded as loss and does not hide an earlier
gap or waive the required consecutive-reply run.

The reports omit SSH destinations, overlay addresses, DNS names and answers,
boot IDs, profile IDs, control fingerprints, and raw traffic output.
`SHA256SUMS` records the exact report bytes committed here. This is one bounded
reboot sample per architecture. It does not establish reboot p95, power-loss
recovery, IPv6-only underlay behavior, multi-uplink migration, or long-duration
reliability.
