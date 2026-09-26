# Dex artifact verifier

`dexartifact` verifies the complete identity of one patched Dex candidate before
the OIDC black-box gate is allowed to evaluate it. It does not download source,
build a binary, or trust a mutable branch.

The manifest format is defined by
[`manifest.schema.json`](manifest.schema.json). The Go verifier is authoritative
for security-sensitive validation and additionally rejects unknown JSON fields,
duplicate JSON names, duplicate patch IDs or paths, non-canonical paths,
symlinked manifest files, and oversized inputs.

Verification performs these operations offline:

1. validates the exact upstream HTTPS repository, semantic version, tag commit,
   Go module path and pseudo-version, ordered patch list, toolchain, build flags,
   and evidence references;
2. verifies SHA-256 for every patch, the binary, license inventory, SBOM,
   vulnerability report, and qualification report;
3. clones the local upstream checkout into a private temporary directory at the
   exact tag commit without using its working tree;
4. applies the ordered patch copies with `git apply --check` and
   `git apply --index`, rejecting whitespace errors and rejected hunks;
5. hashes a canonical stream of every indexed mode, path, size, and file byte;
   and
6. optionally materializes the verified patched source without Git metadata
   under an existing empty private directory;
7. optionally verifies MeshCore's exact direct module pin, rejects Dex replace
   directives, and writes a private temporary Go workspace; and
8. emits one bounded JSON report only when every expected digest matches.

Patch and evidence paths are relative to the manifest directory. They cannot
escape it. The source checkout and binary paths are absolute CLI inputs. The
source checkout must have an `origin` URL and an annotated or lightweight tag
that resolve exactly to the manifest values. The module pseudo-version timestamp
and revision suffix must also match that commit's Git timestamp and hash.

Run:

```sh
go run ./tools/qualification/dexartifact \
  -manifest /absolute/path/to/artifact/manifest.json \
  -source /absolute/path/to/local/dex-checkout \
  -binary /absolute/path/to/dex
```

To prepare the exact patched source for a later compile gate, create a private
empty directory and add `-prepared-root /absolute/path/to/empty-directory`.
The verified source is written to its previously absent `source` child. The
command refuses a non-empty root and never overwrites an existing source tree.

To prepare build wiring in the same verified operation, also pass
`-workspace-module /absolute/path/to/meshcore`. The command requires MeshCore's
`go.mod` module and Go versions to match the manifest, requires exactly one
direct Dex requirement at the manifest module version, and rejects root or
`api/v2` replacements. It writes `go.work` under the prepared root with the
MeshCore, prepared Dex, and prepared Dex API modules. The workspace is temporary
and must not be committed.

The command writes only the verified version, commit, module version, patch
count, source-tree digest, binary digest, and preparation status to stdout.
Diagnostics are generic and go to stderr; paths, patch contents, Git output,
and evidence contents are not printed.

The tool uses a local `git` executable with system/global configuration,
interactive prompts, and repository hooks disabled. It never modifies the
provided checkout. Temporary patch copies and unrequested verification clones
are removed on every handled exit. A requested prepared tree is preserved only
after its digest matches the manifest and its Git metadata has been removed.

This verifier establishes artifact identity. It does not replace
`SSO-BROKER-000`, license review, vulnerability analysis, signature validation,
or release approval.
