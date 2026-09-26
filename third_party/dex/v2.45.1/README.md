# Dex v2.45.1 compatibility inputs

This directory contains only the MeshTransit-owned compatibility inputs needed
to build and qualify the pinned Dex dependency. Dex source is not vendored and
MeshTransit does not maintain a Dex fork.

## Upstream identity

- repository: `https://github.com/dexidp/dex.git`
- release: `v2.45.1`
- tag commit: `11d2eeb52b42e1980e14cb91e69dd9e3faab2076`
- Go module: `github.com/dexidp/dex`
- Go module version: `v0.0.0-20260303133905-11d2eeb52b42`

## Ordered patch set

1. `patches/0001-rfc9207-authorization-response-issuer.patch`
   - SHA-256: `77652df0db7176e1fb752f4a81e9403b26d16a8517a3a48aab291676e736332c`
   - advertises `authorization_response_iss_parameter_supported=true`;
   - returns exactly one configured `iss` in successful query and fragment
     authorization responses;
   - returns exactly one configured `iss` in redirected authorization errors;
   - replaces conflicting reserved response parameters already present in a
   registered callback query; and
   - includes upstream-style tests for issuer paths and untrusted request
     headers.
2. `patches/0002-signed-authentication-time.patch`
   - SHA-256: `f661957c38772b7bc733eee46a16177fdff47695b478e37786413db5e299cdfd`
   - records the end-user authentication instant once and carries it through
     authorization requests, authorization codes, and refresh tokens;
   - signs a valid NumericDate `auth_time` into ID tokens while keeping it out
     of access tokens;
   - preserves the original value across refreshes instead of substituting the
     refresh time or token issue time;
   - rejects negative and future values, while legacy zero values remain
     unsigned and therefore cannot pass the MeshTransit qualification gate;
   - persists the value through memory, legacy SQL, Ent SQL, etcd, and
   Kubernetes storage backends; and
   - includes signing, refresh, discovery, persistence, and race coverage.
3. `patches/0003-security-dependency-updates.patch`
   - SHA-256: `43912a1c989c540c7d1a73e301205b0e18d8f1306ad0d14bafa3b8bc0c4fda7f`;
   - raises the minimum Go language version to 1.26 and pins the qualified
     build to the fully patched Go 1.26.8 toolchain;
   - upgrades only existing dependencies needed to remove reachable binary
     findings reported on 2026-09-25; and
   - contains two format-call compatibility fixes required by Go 1.26 vet.
4. `patches/0004-background-worker-join.patch`
   - SHA-256: `d93d2d2f3325b45d720bc5cc70c4e1164a3e7422faa8f324bc13ddb005d66a57`;
   - makes signer rotation and garbage collection return completion channels;
   - exposes one `server.Server.Done` channel that closes only after every
     started background worker has exited; and
   - includes cancellation and delayed-worker tests that prove storage cannot
     be released while either worker is still running.
5. `patches/0005-connector-lifecycle-join.patch`
   - SHA-256: `694e23190a100eeabf354d5dbf31348b938f48c1ac536cad88ccb742b324dde5`;
   - closes every opened connector when the server context is cancelled or
     construction fails;
   - extends `server.Server.Done` so storage release cannot race a connector
   background worker; and
   - rejects connector opens after shutdown starts and tests delayed close,
     exactly-once close, and the late-open fence under the race detector.
6. `patches/0006-prepared-postgres-runtime-open.patch`
   - SHA-256: `72d767a1efcd5d67b6c489bfabf2238e967c6d804aff3f754dcd8bb0125d4702`;
   - adds a PostgreSQL runtime open path that never runs migrations;
   - accepts only the exact migration level required by the current build and
     fails closed when the migration table is missing, behind, or ahead;
   - closes the opened database handle when schema verification fails; and
   - preserves the existing migration-capable open path for the dedicated
     one-shot migrator.
7. `patches/0007-context-bounded-prepared-postgres-check.patch`
   - SHA-256: `db9c5f2549df7d096f115f4facad875b512e72331c1143e125a688fb1a26585b`;
   - makes prepared-schema open accept the caller's cancellation and deadline;
   - exposes a narrow prepared PostgreSQL storage contract whose periodic check
     performs `PingContext` plus exact migration-level verification; and
   - proves cancellation reaches the SQL driver instead of leaving readiness
     work behind after a timeout.
8. `patches/0008-inject-connector-http-client.patch`
   - SHA-256: `524158992232a39496c976fa712a58405d52cc6abfd1eb01104232efdaf9b257`;
   - adds a caller-owned HTTP client map keyed by immutable connector ID;
   - lets generic OIDC use that client for discovery, token exchange, and
     remote-key retrieval without changing the default Dex path;
   - preserves the injected client when provider endpoints are overridden;
   - fails closed when a configured connector cannot accept injection; and
   - includes connector and server tests, including nil-client rejection.

The ordered patch set applies only to the exact tag commit above. It passed the
complete Dex `./server` and `./server/signer` package and race suites before
being stored here. With `CGO_ENABLED=1`, the only failure in the complete Dex
`./...` suite is an unchanged upstream SAML certificate fixture that is no
longer valid at the current date; the same test fails without these patches.

## Qualified artifact evidence

`manifest.darwin-arm64.json` binds the eight ordered patches, canonical patched
source tree, build inputs, exact binary, and four evidence files. The
qualification binary is `v2.45.1+compat.8`, built with Go 1.26.8 and
`CGO_ENABLED=0` for `darwin/arm64`.

- source tree SHA-256:
  `31e9f91bd3761028f838e7f00635cded92bbd661a4264b8b58ba391546422bae`;
- binary SHA-256:
  `dfaf9cb0afd9b6c07790c55daae6e8eee5a59dbac86faffe366767def8a1165a`;
- two clean independent builds produced the same binary digest;
- the CycloneDX 1.7 SBOM contains 107 components and is normalized to remove
  scan timestamps, random identifiers, and temporary paths;
- the technical license inventory covers all 106 library components, detects
  no strong copyleft, and records 11 MPL-2.0 components plus ten unclassified
  auxiliary license-text hashes for legal review;
- the pinned govulncheck binary scan reports zero reachable symbol and zero
  imported-package vulnerabilities; one module-only `x/crypto/openpgp`
  advisory is retained with a not-imported disposition; and
- `SSO-BROKER-000`, module checksum verification, the eight-way compile
  contract, server/signer tests, worker and connector lifecycle join tests,
  prepared-schema storage tests, OIDC HTTP-client injection tests, and race
  tests pass.

The artifact verifier reproduced the declared source-tree and binary digests
from a local checkout whose `origin`, tag, and commit match the upstream
identity above. This artifact is qualification evidence for the recorded host
platform. It is not a Linux production artifact and legal approval remains a
separate `SSO-BROKER-001` decision.

`make prepare-dex-source` can materialize this exact patched tree into the
`source` child of an existing empty private directory. The operation verifies
the complete manifest, binary, evidence, patch order, tag commit, and canonical
source digest before preserving any source. The result is an ephemeral build
input without Git metadata; it is never checked into MeshCore.

`make qualification-dex-compile` then compares that `source` tree with the
unmodified checkout. The base server/configuration/storage contract must compile
for upstream, the same contract with only `storage.Claims.AuthTime` must fail
there for that missing field, and independent upstream checks must reject both
`server.Server.Done`, the signer join-channel signature, and the PostgreSQL
prepared-schema runtime open. Two further upstream checks must reject the
connector-ID HTTP-client map and generic-OIDC client-injection method. The
complete authentication-time, worker-join, prepared-schema, and outbound-client
contract must compile for the prepared tree. This keeps every removable patch
surface and adapter API drift visible without executing Dex or enabling the
broker runtime.

`make prepare-dex-workspace` performs source preparation and binds the same
manifest module version to MeshCore's direct dependency. It rejects checked-in
Dex replacements and creates a temporary workspace containing MeshCore, the
verified Dex module, and its `api/v2` module. `make
qualification-dex-workspace` successfully compiles the real build-tagged
`internal/adapter/dexbroker` contract through that workspace. The ordinary
MeshCore build does not select the tag, and no source or workspace is committed.

## Upgrade rule

For every Dex version change:

1. pin the new tag and exact tag commit;
2. run the unchanged black-box gate against the unmodified upstream binary;
3. remove each compatibility patch independently when upstream passes its
   corresponding qualification checks;
4. otherwise port the required patches as new version-scoped files and run
   upstream package, storage conformance, and race tests; and
5. generate a new platform-specific immutable artifact manifest, SBOM, license
   inventory, vulnerability report, qualification report, and digests. Never
   reuse this patch set or its evidence for another Dex version.

The signed `auth_time` compatibility change is intentionally a separate patch
so either requirement can be dropped independently when upstream implements it.
The security dependency patch is also independent and must be recalculated from
the vulnerability database and toolchain applicable at upgrade time. The
background-worker and connector lifecycle patches remain independent and must
be removed separately when an upstream stable release exposes each equivalent
complete lifecycle fence. The two prepared-schema PostgreSQL patches must be
removed independently when upstream provides an equivalent no-DDL runtime open
and a context-bounded exact-schema readiness contract.
The connector HTTP-client patch must be removed when upstream exposes an
equivalent caller-owned transport boundary for generic OIDC. MeshCore continues
to own endpoint allowlisting, DNS/IP validation, TLS policy, limits, timeouts,
and client lifecycle outside Dex.
