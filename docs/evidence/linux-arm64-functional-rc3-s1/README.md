# Linux ARM64 functional qualification rc3 — sample 1

This directory records the first registered two-node functional qualification
of the rc3 client across Ubuntu 24.04 ARM64 and Ubuntu 26.04 AMD64.

- Runtime: `0.1.0~rc3+69e5e2f`
- Runtime commit: `69e5e2f00f0fead79e5baf4848725ee3aa6590b6`
- Result: direct dual-stack traffic, DNS lifecycle, and host-policy gates passed
- Policy observations: 48 of 48 matched, with no infrastructure errors
- Final state: both nodes online with one authenticated direct peer path

The report excludes SSH destinations, overlay addresses, DNS names and answers,
profile identifiers, account identifiers, control fingerprints, raw status,
endpoint candidates, packet payloads, and process identifiers. Package and
source digests remain so the result can be tied to immutable inputs.

This sample does not qualify forced relay, network-change recovery, registered
rollback, sustained operation, or an IPv6-only underlay.
