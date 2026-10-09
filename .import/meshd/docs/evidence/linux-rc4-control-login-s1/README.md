# Linux RC4 control presence and login wait — sample 1

This evidence records the native Ubuntu 26.04 AMD64 and ARM64 validation of
the RC4 control-presence status contract and the blocking browser-login flow.
The two hosts are dedicated qualification nodes; the long-running soak nodes
were not modified.

## Candidate

- `meshd`: `0.1.0~rc4+e427252`
- `meshd` commit: `e427252f4f4fc13c247d9db7e5c8d31ed62d7911`
- `meshctl`: `0.1.0~rc4+0b8f710`
- `meshctl` commit: `0b8f7108c7193240a6d8b96ef8f4d61f8d4de41c`

Package SHA-256 values:

| Package | AMD64 | ARM64 |
| --- | --- | --- |
| `meshd` | `8c195ac3825159ddd46e954d77f7c8c5e599a8c6889edafcc8cfe43180a7b4e3` | `abe72bc1a71d62f2fae81c7c3e9d1cc37324f384957268a795a5dad1a4a4f6e8` |
| `meshctl` | `5c51e0b9df7a2e741ea20d747f2398bec9a559b68981acfac90472808af9a3c5` | `c7b3ba2d6e497f4477632da10aa702b8a724c2b14a9b2f1e1a20f1a4c9fa4a2e` |

All four package sidecars passed SHA-256 verification before installation.

## Control-presence result

Before the upgrade, both registered nodes reported `offline` even though the
control session was `synchronized` and DNS was configured. After installing
the exact RC4 packages, both architectures reported:

| Gate | AMD64 | ARM64 |
| --- | --- | --- |
| Top-level state | `online` | `online` |
| Control session | `synchronized` | `synchronized` |
| Registration | `registered` | `registered` |
| DNS | `configured` | `configured` |
| Data plane | `idle` | `idle` |
| Peer count | `0` | `0` |
| `meshd` / `meshnetd` | active / active | active / active |
| Automatic restarts | `0` / `0` | `0` / `0` |

This verifies that online presence is no longer incorrectly coupled to an
authorized peer path. Data-plane and DNS state remain independently visible.

## Browser-login result

The AMD64 node used a new, isolated qualification profile. The command was
started once as:

```text
meshctl login --wait-timeout 5m
```

The same process printed the authorization URL, printed the bounded waiting
message, detected browser approval, reported the active profile as registered,
and exited with code zero. `meshctl login complete` was not invoked. A shell
cleanup trap restored the original qualification profile, which immediately
returned to `online`, `synchronized`, and `configured`; the ARM64 observer also
remained healthy.

The exact source passed `go test -race ./...` natively on Ubuntu 26.04 AMD64
after packaging.

## Redaction and limits

This record omits SSH destinations, profile identifiers, registration URLs and
handles, control fingerprints, overlay and underlay addresses, credentials,
and process identifiers. It validates client and daemon behavior. A separate
Console observation confirmed that both registered qualification devices were
reported online without adding another peer. The temporary login device was
then removed from the Console. The release-candidate DNS upstream fault matrix
is recorded separately in
[`linux-dns-rc4-upstream-failure-s1`](../linux-dns-rc4-upstream-failure-s1/README.md).
