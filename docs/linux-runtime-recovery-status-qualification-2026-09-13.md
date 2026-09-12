# Linux runtime recovery status qualification — 2026-09-13

## Result

The exact `e53acf5d9ae3a2d5382c5b3992d540cbbb5c1e73` meshctl candidate
passed local and native status-contract qualification against registered
`meshd` rc5 nodes on Ubuntu 26.04 amd64 and arm64.

| Target | Package SHA-256 | Human output | JSON output | Result |
| --- | --- | --- | --- | --- |
| Ubuntu 26.04, x86_64 | `3649375392da2f9407207dbd320c8a3332985e30006a0bb3a0910ef5aa51b38b` | recovery idle, 1 failure/1 recovery | exact counter match | pass |
| Ubuntu 26.04, aarch64 | `352b3f88a68cbeb85c7aceb22babce7aaa2954c23606c6ecb3f08176ebf1fd40` | recovery idle, 1 failure/1 recovery | exact counter match | pass |

The source archive SHA-256 was
`a81d258c738d56798e341275220b65d0d0cc80fbe1a709773bddeec154de28c7`.
Both native package verifiers and complete native race suites passed before the
final check.

## Contract verified

- The v1 local API client decodes `runtime_recovery.failures`, `recoveries`,
  and `pending` without changing their values.
- Human output reports the state as `idle` or `pending` and uses stable
  label-first counters.
- JSON mode preserves the structured recovery object for automation.
- A v1 daemon that omits this newer additive field remains accepted and human
  output reports `unavailable` rather than a misleading zero value.
- Neither status mode adds peer identity, endpoint, route, DNS-name, key,
  packet, error-text, or payload data.

Installing the unprivileged CLI package did not restart `meshd` or `meshnetd`.
Both services remained active with no automatic daemon restart, and the final
control, data-plane, and DNS states remained healthy.
