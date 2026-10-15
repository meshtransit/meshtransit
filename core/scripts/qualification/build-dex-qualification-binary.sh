#!/usr/bin/env bash
# Rebuilds the Dex qualification binary whose SHA-256 the artifact manifest
# records, so `make prepare-dex-workspace` can verify it.
#
# Usage: build-dex-qualification-binary.sh <upstream Dex checkout> <output binary>
#
# The recorded digest is not that of a standalone Dex build. The binary is built
# inside a go.work together with a module whose go.mod/go.sum are frozen in
# qualification-workspace.go.{mod,sum}; minimal version selection therefore
# takes its dependency versions from that file and not from the current
# repository go.mod, which moves with every Go or dependency upgrade. Building
# with the current go.mod yields a different, equally valid, digest that the
# verifier refuses.
#
# Everything happens in a private temporary directory; nothing in the checkout
# or the repository is written. The result must equal binary_sha256.

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
expected="$(field binary_sha256)"
[[ "${commit}" =~ ^[0-9a-f]{40}$ && "${expected}" =~ ^[0-9a-f]{64}$ ]] || {
	printf '%s\n' 'Manifest is missing the upstream commit or binary digest.' >&2
	exit 1
}
[[ "$(git -C "${upstream}" rev-parse --verify "refs/tags/${version}^{commit}")" = "${commit}" ]] || {
	printf '%s\n' 'Upstream tag does not point at the manifest commit.' >&2
	exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

git clone --quiet --no-checkout --no-hardlinks --local "${upstream}" "${work}/patched"
git -C "${work}/patched" checkout --quiet --detach "${commit}"
for patch in "${dex_dir}"/patches/*.patch; do
	git -C "${work}/patched" apply --index --whitespace=error-all "${patch}"
done
rm -rf "${work}/patched/.git"

mkdir "${work}/frozen"
cp "${dex_dir}/qualification-workspace.go.mod" "${work}/frozen/go.mod"
cp "${dex_dir}/qualification-workspace.go.sum" "${work}/frozen/go.sum"
frozen_go="$(awk '$1 == "go" {print $2}' "${work}/frozen/go.mod")"
printf 'go %s\n\nuse (\n\t%s\n\t%s\n\t%s\n)\n' "${frozen_go}" \
	"${work}/frozen" "${work}/patched" "${work}/patched/api/v2" > "${work}/go.work"

# Flags, platform and toolchain are the manifest's build.flags.
(
	cd "${work}"
	env GOWORK="${work}/go.work" GOTOOLCHAIN="go${frozen_go}" GOOS=darwin GOARCH=arm64 \
		GOARM64=v8.0 CGO_ENABLED=0 GOFLAGS= \
		go build -buildvcs=false -trimpath \
		'-ldflags=-w -X main.version=v2.45.1+compat.8' \
		-o "${work}/dex" github.com/dexidp/dex/cmd/dex
)

actual="$(shasum -a 256 "${work}/dex" | awk '{print $1}')"
[[ "${actual}" = "${expected}" ]] || {
	printf 'Built digest %s does not match the manifest.\n' "${actual}" >&2
	exit 1
}
cp "${work}/dex" "${output}"
printf '%s\n' "${actual}"
