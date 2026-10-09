# Linux Ubuntu 26.04 ARM64 rc3 — sample 1

This evidence records native build, package, service, security, and registered
mesh qualification for the immutable rc3 candidate on Ubuntu 26.04 ARM64. A
dedicated Ubuntu 26.04 AMD64 peer remained on rc3 except while explicitly
validating the ARM node's rc1 rollback compatibility.

- Candidate: `0.1.0~rc3+69e5e2f`
- Candidate package SHA-256:
  `c3ac50a269cbf90605f4123834072630d985f9db9ab8f4ec44d2653d6621a0fd`
- Result: all recorded gates passed
- Direct policy traffic: 48 of 48 observations matched
- Network-change traffic: 244 of 244 probes succeeded
- Registered rollback traffic: 40 of 40 probes succeeded
- Final state: candidate restored, both services active, direct path selected,
  DNS configured, policy baseline restored, and zero automatic restarts

The forced-relay loss in the report occurred only during the deliberate,
bounded direct-path fault. Its nftables table and the network-change dummy
interface were both removed before the final checks.

The report omits SSH destinations, profile identifiers, overlay and underlay
addresses, internal DNS names and answers, control fingerprints, endpoint
candidates, credentials and their hashes, package logs, packet payloads, and
process identifiers. Raw reports and packages remain owner-only on the
disposable qualification host.
