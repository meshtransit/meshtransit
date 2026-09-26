# Dex compile contract

`dexcompile` verifies the narrow compile-time API that the MeshCore Dex adapter
is allowed to depend on. It compiles generated temporary source only; it does
not run Dex package initialization, start a listener, or enable login.

The gate performs eight checks in order:

1. the adapter's base `server.Config`, `server.NewServer`, `server.Server`,
   `storage.Storage`, and `http.Handler` contract compiles against the exact
   unmodified upstream checkout;
2. adding only the required `storage.Claims.AuthTime` field is rejected by that
   upstream checkout with the expected compiler diagnostic; and
3. requiring `server.Server.Done` is rejected by that upstream checkout with
   the expected missing-method diagnostic;
4. requiring the signer `Start` join-channel signature is rejected by that
   upstream checkout with the expected method-signature diagnostic; and
5. requiring the context-bounded PostgreSQL prepared-schema runtime/readiness
   contract is rejected by that upstream checkout with the expected
   missing-method diagnostic; and
6. requiring the connector-ID HTTP-client map is rejected by that upstream
   checkout with the expected missing-field diagnostic;
7. requiring the generic-OIDC caller-owned HTTP-client open method is rejected
   by that upstream checkout with the expected missing-method diagnostic; and
8. the complete authentication-time, worker-join, context-bounded
   prepared-schema, and outbound HTTP-client contract compiles against the
   verified patched source.

The negative checks prove that a passing candidate actually supplies all
required compatibility surfaces instead of passing because the base API was
already broken. The candidate must be the Git-metadata-free `source`
directory produced by `dexartifact -prepared-root`; the command rejects a
candidate that still contains `.git` metadata. Artifact identity and source
digests remain the responsibility of `dexartifact`.

Run after source preparation:

```sh
go run ./tools/qualification/dexcompile \
  -upstream-source /absolute/path/to/unmodified/dex \
  -candidate-source /absolute/path/to/prepared/source
```

The tool resolves the local Go executable, disables workspace and user Go
configuration, uses the installed toolchain without automatic switching, and
builds a temporary test binary without executing it. Temporary modules and
compiled outputs are removed on handled exit. Output is a bounded JSON result;
errors are generic and do not expose source paths or compiler diagnostics.

For a Dex upgrade, run this unchanged gate first. If unmodified upstream now
accepts the full contract, the negative assertion deliberately fails and the
compatibility patch must be reevaluated or removed before a new version-scoped
artifact is qualified.
