#!/usr/bin/env bash
# Rebuilds the Dex qualification binary whose SHA-256 the artifact manifest
# records, so `make prepare-dex-workspace` can verify it.
#
# Usage: build-dex-qualification-binary.sh <upstream Dex checkout> <new output file>
#
# The binary is a standalone build of the verified patched Dex tree (no
# go.work, the tree's own go.mod/go.sum), with the toolchain, platform and flags
# the manifest records. Everything happens in a private temporary directory;
# the checkout and the repository are not written. A result that differs from
# the manifest's binary_sha256 is refused.

set -euo pipefail

upstream="${1:-}"
output="${2:-}"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
dex_dir="${repo_root}/core/third_party/dex/v2.45.1"
manifest="${dex_dir}/manifest.darwin-arm64.json"

[[ -d "${upstream}/.git" && -n "${output}" && ! -e "${output}" ]] || {
	printf '%s\n' 'usage: build-dex-qualification-binary.sh <Dex checkout> <new output file>' >&2
	exit 2
}

field() { sed -n "s/.*\"$1\": \"\\([^\"]*\\)\".*/\\1/p" "${manifest}" | head -n 1; }
commit="$(field commit)"
version="$(field version)"
go_version="$(field go_version)"
expected="$(field binary_sha256)"
ldflags="$(sed -n 's/.*"-ldflags=\(.*\)".*/\1/p' "${manifest}" | head -n 1)"
[[ "${commit}" =~ ^[0-9a-f]{40}$ && "${expected}" =~ ^[0-9a-f]{64}$ && "${go_version}" =~ ^go1\.[0-9]+\.[0-9]+$ && -n "${ldflags}" ]] || {
	printf '%s\n' 'Manifest is missing a build input.' >&2
	exit 1
}
[[ "$(git -C "${upstream}" rev-parse --verify "refs/tags/${version}^{commit}")" = "${commit}" ]] || {
	printf '%s\n' 'Upstream tag does not point at the manifest commit.' >&2
	exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "${work:?}"' EXIT

git clone --quiet --no-checkout --no-hardlinks --local "${upstream}" "${work}/src"
git -C "${work}/src" checkout --quiet --detach "${commit}"
for patch in "${dex_dir}"/patches/*.patch; do
	git -C "${work}/src" apply --index --whitespace=error-all "${patch}"
done
rm -rf "${work}/src/.git"

(
	cd "${work}/src"
	env GOWORK=off GOTOOLCHAIN="${go_version}" GOOS=darwin GOARCH=arm64 GOARM64=v8.0 \
		CGO_ENABLED=0 GOFLAGS= \
		go build -buildvcs=false -trimpath "-ldflags=${ldflags}" -o "${work}/dex" ./cmd/dex
)

actual="$(shasum -a 256 "${work}/dex" | awk '{print $1}')"
[[ "${actual}" = "${expected}" ]] || {
	printf 'Built digest %s does not match the manifest.\n' "${actual}" >&2
	exit 1
}
cp "${work}/dex" "${output}"
printf '%s\n' "${actual}"
