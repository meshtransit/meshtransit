# Linux package supply-chain qualification — 2026-09-12

## Scope

This report records the first exact-commit qualification of the Linux package
SBOM and vulnerability gate. It covers checksum-pinned scanner installation,
reproducible amd64 and arm64 Debian packages, reproducible CycloneDX documents,
symbol-aware vulnerability scans, fail-closed checksum handling, and independent
artifact inspection on a second Linux distribution.

This is bounded alpha evidence. The artifacts are not signed, the build does
not yet emit SLSA provenance, and the result is not a production release.

## Candidate and tools

- Version: `0.1.0~alpha20`.
- Git commit: `33feb2e6136bfc2d545e015797b86f3121d365b7`.
- Build date: `2026-09-12T04:33:58Z`, derived from the commit timestamp through
  `SOURCE_DATE_EPOCH=1789187638`.
- Source archive SHA-256:
  `295dfd2252ec1cae79bcb9ba5ae0736c981662de185e941fd7146ebcf17da467`.
- Syft `1.51.1`, installed from its pinned release archive after SHA-256
  verification.
- Grype `0.116.1`, installed by the same policy. The scan used schema `v6.1.9`
  vulnerability data built at `2026-09-11T06:29:40Z`.

The build host was Ubuntu 26.04 LTS x86-64 with Go `1.26.0`, `dpkg-deb`
`1.23.7`, and `jq` `1.8.1`. The independent verifier was Debian 13 x86-64.
The dedicated alpha17 72-hour soak nodes were neither accessed nor changed.

## Artifact identity

| Architecture | Debian package SHA-256 | CycloneDX SHA-256 | Grype report SHA-256 |
| --- | --- | --- | --- |
| amd64 | `b2873d555b74a9c31f29e18606911a517051d0241bbe2395a488e6d651a24c38` | `12a2b789bfec1706874d91e67a7ebc777587740f68d6f1b2e14b8abcd203c894` | `50b5f08d7a97c8caba10c2b7a2775795cfd54489d90e6fa210fce7a05171fff1` |
| arm64 | `7586519c176979af8359ccc4eb0e7038fe0e864bb71dc036d12da04a57d0b47d` | `c0f60a094730cc25f5957a10db17c984dca636a1298c5bc23f627148070b7fa1` | `c8a3dc5fb074db32b9e62913ab4e4631865853262ed9f5943558ed2ca69720c1` |

The transfer bundle containing the two packages, their two SBOMs, their two
Grype reports, and all six checksum sidecars had SHA-256
`632a7f86959931cc6d885e02e6be3b194a56935d8943da10e8b8279dfd308a9d`
before and after transfer to the independent verifier.

## Method and results

The source was exported directly from the candidate commit with `git archive`.
The archive contained no Git metadata, previous build output, or macOS
AppleDouble files. Both architectures were built twice from that archive with
the same commit, version, timestamp, and constrained build parallelism. Each
pair of `.deb` files was byte-identical.

Each package was extracted and scanned twice. The normalized CycloneDX 1.7
documents were byte-identical between runs. Each document contained 23
components, including 20 Go components, and accounted for the installed
`meshd`, `meshnetd`, and `meshcred` binaries. Its root component was bound to
the exact package digest, architecture, version, build date, and Git commit.

The symbol-aware Grype scan reported zero matches for both architectures with
the database snapshot listed above. A zero-match result is point-in-time
evidence, not a claim that the artifacts cannot acquire a future advisory.

On Debian 13, all six sidecars were verified again before parsing the package,
SBOM, or report. Both package control records matched the expected name,
version, architecture, commit, and build date. An independent standard-library
JSON validator recomputed each package digest, checked its binding to the SBOM,
counted the components, checked the Grype tool version and zero-match result,
and rejected any leaked builder staging path.

Two isolated negative tests exercised the fail-closed boundary:

1. Removing one byte from a copied package was rejected as a package checksum
   mismatch before extraction.
2. Replacing the checksum sidecar filename with `../../etc/shadow` while
   retaining a valid digest was rejected as an unexpected file reference.

The machine-readable, redacted result is retained in
[`docs/evidence/linux-supply-chain-alpha20-s1`](evidence/linux-supply-chain-alpha20-s1).

## Remaining limits

The two reproducibility runs used one builder; a second independent rebuild is
still required before claiming cross-builder reproducibility. Debian performed
an independent artifact inspection but did not install these packages because
runtime and package-lifecycle behavior is covered by separate qualification.
Scanner archive checksums establish downloaded-tool integrity against values
reviewed in source, not publisher identity. Release signing, isolated builders,
attested provenance, trusted timestamping, long-term evidence retention, and a
documented vulnerability-response SLA remain release gates.
