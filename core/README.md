# MeshTransit Core

MeshTransit Core is the control plane: it holds Workspaces, Networks, Devices,
policy and sharing in PostgreSQL, serves the management API and the Console's
backend, and speaks [MTCP v1](../docs/protocol/mtcp-v1.md) to clients. One
binary, `meshcore`, runs one role per process (`api`, `control`, `identity` or
`worker`), or every role with `all`. (Its `relay` role serves only health and
metrics; the relay is `meshrelay`, in `relay/`.)
The protocol specifications are listed in
[docs/protocol](../docs/protocol/README.md).

## Running Core

```bash
make build-core                 # bin/meshcore
bin/meshcore version            # build, revision and configuration schema
bin/meshcore config validate    # check the configuration of the selected role
bin/meshcore migrate status     # schema state, with the migrator's settings
bin/meshcore migrate up         # apply pending migrations
bin/meshcore serve              # run the role in MESHTRANSIT_ROLE (the default command)
```

Core is configured with environment variables; `serve` never migrates or
repairs the database. A role uses the identity broker only in a build with
the `dexbroker` tag.

## Documentation

- [Architecture: Core](../docs/architecture/core.md): roles, storage, maps,
  relay authority, API, worker.
- [Configuration](../docs/operations/configuration.md): every environment
  variable.
- [Deployment](../docs/operations/deployment.md),
  [upgrades](../docs/operations/upgrades.md),
  [key rotation](../docs/operations/key-rotation.md),
  [monitoring](../docs/operations/monitoring.md),
  [limits](../docs/operations/limits.md).
- Product behaviour: [identity and access](../docs/concepts/identity-and-access.md),
  [Devices](../docs/concepts/devices.md), [policy](../docs/concepts/policy.md),
  [sharing](../docs/concepts/sharing.md), [audit](../docs/concepts/audit.md).
- APIs: `api/openapi/management_v1.json`; the client protocol is
  [MTCP v1](../docs/protocol/mtcp-v1.md).

## Development gates

Run individual gates with `make fmt-check`, `make tidy-check`, `make vet`,
`make test`, `make test-race`, `make lint`, `make lint-integration`, and
`make vuln`. `make quality` runs the complete bootstrap set. The integration
lint target compiles and analyzes the build-tagged test harness without dialing
dependencies. The lint and vulnerability commands pin tool versions for
reproducible execution with the module's Go 1.26.9 baseline.

`make qualification-dex DEX_QUALIFICATION_BINARY=/absolute/path/to/dex`
runs `SSO-BROKER-000` against the default pinned release. Override
`DEX_QUALIFICATION_RELEASE` only when qualifying an exact replacement artifact.
The suite treats Dex as a black-box OIDC server and does not import Dex packages,
so an upgrade reruns the same discovery, successful/error callback, signature,
and `auth_time` contracts. The target fails while any hard requirement is absent.

`make qualification-dex-boundary` enforces the adapter-only portion of
`SSO-BROKER-001`. `internal/adapter/dexbroker` is the only MeshCore package that
may import `github.com/dexidp/dex` or any of its subpackages. The contract test
parses every Go source file, including files excluded by current build tags, and
fails closed on malformed or symlinked Go source. The package now exposes a
product-owned lifecycle shell whose public surface is only `http.Handler`,
`Ready`, `Shutdown`, and `Done`; Dex configuration and runtime types remain
private to the adapter. It does not enable a listener, route, or public login.

ADR-049 permits only temporary upstream-oriented compatibility patches. RFC 9207
response issuer support and persisted signed authentication time remain separate
patches so each can be removed when an upstream stable release supplies that
behavior. A third independent patch pins the Go toolchain floor and dependency
versions needed to clear reachable vulnerability findings. A fourth independent
patch adds a completion fence for signer rotation and garbage collection so
storage teardown can join every Dex-owned background worker. The ordered
version-scoped inputs, platform manifest, CycloneDX SBOM, license inventory,
vulnerability report, and qualification report are stored under
[`third_party/dex/v2.45.1`](third_party/dex/v2.45.1/README.md); Dex source is not
vendored and no Dex fork is maintained. Compatibility inputs live outside
MeshCore domain code, record the exact upstream commit and patch digests,
preserve original authentication time across refresh, and cannot derive claims
from token issue time or request headers. The unchanged black-box gate, not
patch presence, decides whether an artifact is eligible for the embedded broker
adapter.

`make verify-dex-artifact DEX_ARTIFACT_MANIFEST=/absolute/path/manifest.json
DEX_UPSTREAM_SOURCE=/absolute/path/dex
DEX_ARTIFACT_BINARY=/absolute/path/dex-binary` verifies ADR-049 artifact identity
before the black-box gate runs. It operates offline, applies ordered patch copies
to a temporary detached checkout, verifies all declared SHA-256 evidence, and
leaves the supplied source checkout unchanged. The manifest schema and operator
contract are in
[`tools/qualification/dexartifact`](tools/qualification/dexartifact/README.md).

`make prepare-dex-source` accepts the same three verified inputs plus
`DEX_PREPARED_ROOT`, which must identify an existing empty private directory.
Only after every manifest check passes does it preserve the exact patched tree
under `DEX_PREPARED_ROOT/source`, without Git metadata. It refuses a non-empty
root and never writes Dex source into the MeshCore repository. This produces the
ephemeral dependency input for the compile gate; it does not enable the broker
runtime or public login.

`make qualification-dex-compile DEX_UPSTREAM_SOURCE=/absolute/path/dex
DEX_PREPARED_ROOT=/absolute/path/prepared` runs the adapter compile contract
against both trees. It first proves the base Dex server/configuration/storage
API compiles against unmodified upstream, then proves that adding only the
required `storage.Claims.AuthTime` field fails there with the expected compiler
diagnostic. Two further negative checks independently prove that unmodified
upstream lacks `server.Server.Done` and the signer join-channel signature. A
fifth negative check proves the prepared PostgreSQL runtime/readiness contract
is also absent upstream. The sixth and seventh independently prove upstream
lacks the connector HTTP-client map and generic-OIDC client-injection API; the
eighth compiles the complete contract against the verified prepared source. The
generated package also locks `server.NewServer` and `http.Handler`
compatibility. It builds but never
executes the temporary test binary, stores no Dex source in MeshCore, and
enables no runtime or route.
The exact contract and upgrade behavior are documented in
[`tools/qualification/dexcompile`](tools/qualification/dexcompile/README.md).

`make prepare-dex-workspace` accepts the artifact inputs used by
`prepare-dex-source`, verifies them again, and additionally requires the
MeshCore `go.mod` to pin the manifest's exact Go module coordinate. It rejects
any checked-in Dex `replace`, then writes an ephemeral `go.work` beside the
prepared source. The workspace contains MeshCore, the verified Dex root module,
and Dex's `api/v2` module; no workspace file or Dex source is written into the
repository. `make qualification-dex-workspace DEX_PREPARED_ROOT=/absolute/path`
then compiles the real build-tagged adapter and process composition in
`internal/adapter/dexbroker` and `cmd/meshcore`.
The current pin is
`github.com/dexidp/dex@v0.0.0-20260303133905-11d2eeb52b42`, derived from the
manifest commit and its UTC timestamp. The direct dependency and workspace are
build wiring only: the ordinary image excludes the `dexbroker` tag, and no Dex
component, listener, route, or login is enabled.

The adapter lifecycle shell fences new requests before shutdown, drains every
already-admitted handler, calls component stop exactly once, and closes `Done`
only after the component reports that all owned background work has joined.
Concurrent and repeated shutdown calls share one stable result; a caller
deadline does not abandon cleanup. Unexpected component completion immediately
removes readiness and subsequent requests fail with a generic no-store 503.
The runtime graph is redacted from formatting and structured logging and refuses
JSON serialization. Unit and race tests cover typed-nil construction, admission
fencing, drain order, timeout continuation, concurrent shutdown, unexpected
completion, and fail-closed zero values. The verified `compat.9` input supplies
the worker/connector join fences, no-DDL prepared-schema open, a context-bounded
exact-schema readiness check, and caller-owned per-connector HTTP clients.
Upstream-negative compile checks, candidate compilation, full
storage/server/signer/OIDC tests, black-box
`SSO-BROKER-000`, and race tests pass.

The exact component bridge now constructs the pinned server and signer lazily
from product-owned scalar options but borrows storage; it never closes the
shared handle. A private PostgreSQL resource opens only the prepared-schema path
with
TLS `verify-full`, file-backed password/CA references, explicit per-replica
max-open/max-idle limits, bounded connect/lifetime values, redacted outward
errors, and context-bounded connectivity/schema checks. Shutdown stops new uses,
joins both admitted checks and the long-lived service borrow, preserves the
handle after a caller timeout, and closes exactly once on retry. `role=identity`
now maps this resource into readiness, registers it under `resourceOwner`, and
owns the lazy broker service followed by its private HTTPS listener. Reverse
shutdown stops and drains the listener before broker workers release their
long-lived PostgreSQL borrow. Only discovery, authorization, the configured
connector hop, callback, token, and keys are admitted with exact Host/path/method
checks; userinfo, introspection, device flow, health, root, static UI, and every
unconfigured route fail closed. Forwarded assertions are stripped, request and
body/query/header sizes are bounded, plaintext and HTTP/2 are disabled, and
security headers are reasserted at write time. Public ingress and Core BFF
callback remain explicit deployment concerns; aggregate `role=all` composition
is enabled only in the manifest-verified tagged binary.

`make integration-deps` runs the build-tagged TLS/auth dependency test when
`MESHTRANSIT_INTEGRATION=1` and the required file-backed settings above are
present. It performs health round trips only and never creates application
schema or data.

`make integration-migrations` runs the build-tagged migration test when
`MESHTRANSIT_MIGRATION_INTEGRATION=1` and the separate migration settings above
point to an empty disposable database. It starts two concurrent migration
runners, proves exactly one application wins, checks clean compatibility, and
verifies that a repeat run is a no-op. It also exercises RLS isolation and the
audit/outbox commit, rollback, UUID reuse, immutability, sequence, and hash-chain
invariants, plus real worker claim/reconciliation/delivered/retry behavior.
Never point this test at a shared or production database.
`make integration-platform-container` provisions the same isolated PostgreSQL
18.6 TLS/SCRAM and Redis 8.8.0 TLS/ACL fixtures used by CI. It additionally
proves end-to-end Network-revision wakeup delivery, transactional retry, and
lease-expiry replay after a post-publish/pre-completion process failure. The
gate launches the ordinary binary in separated `control` and `worker` roles,
performs bounded SIGTERM shutdowns, and proves restarted processes reach
readiness against the same durable state. A negative process case proves
invalid control configuration exits with redacted diagnostics
before starting the operator listener. The same gate also discovers the
control key over validated TLS, establishes an MTCP v1 session, registers a
synthetic one-off credential, and verifies the committed Node, key epochs,
primary address, revision, audit, and outbox evidence. Repeating that exchange
after process restart must replay the canonical result without consuming or
creating any additional authority. Both containers are removed when the test
exits.

## Container image

`make container-build` creates `meshtransit/mesh-core:dev` by default.
Override `CONTAINER_IMAGE`, `CONTAINER_TAG`, or `CONTAINER_PLATFORM` without
editing repository files. `make container-inspect` verifies the numeric
non-root identity and fixed entrypoint, `make container-smoke` exercises the
relay health surface under a read-only filesystem with all Linux capabilities
dropped, and `make container-scan` rejects High or Critical findings. An
explicitly authorized release can use
`make container-push-multiarch` to publish both platforms with BuildKit SBOM
and provenance attestations.

The embedded identity-broker image is an explicit release path, not an implicit
dependency of the ordinary image. First create a verified ephemeral workspace
with `make prepare-dex-workspace`; then pass that directory as
`DEX_PREPARED_ROOT` to `make container-push-dexbroker-multiarch`. The dedicated
`Dockerfile.dexbroker` receives the prepared Dex tree as a named BuildKit context,
creates a temporary Go workspace inside the builder, and selects only the
`dexbroker` build tag. No Dex source, workspace path, or Git metadata enters the
MeshCore repository. A future Dex release must produce its own verified prepared
workspace before it can use the unchanged image target.

The image uses a digest-pinned Go 1.26.9 builder and a `scratch` runtime. It has
no shell or package manager, contains only the static binary, public CA bundle,
and third-party notices, and runs as UID/GID `65532:65532`. The health listener
remains bound to loopback unless `MESHTRANSIT_HEALTH_ADDRESS` is explicitly
changed. Storage roles must receive credential and private CA files through
read-only mounts;
credentials must not be baked into the image or supplied as environment
values.

The CI workflow (currently disabled, see `.github/workflows-disabled/`) builds,
inspects, smoke-tests, and scans the image but never pushes it. Publishing is a separate, explicitly authorized release
operation and should use an immutable version tag plus the resulting digest.
Release automation should pass the source commit through `CONTAINER_REVISION`;
the workflow already records its Git commit in the OCI image metadata.

## License

Except for third-party components identified in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), the community distribution of
MeshTransit Core is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE).

The same MeshTransit-owned code may also be licensed under a separate written
commercial agreement. See
[COMMERCIAL-LICENSING.md](../COMMERCIAL-LICENSING.md) for the licensing boundary;
that document does not itself grant a commercial license.
