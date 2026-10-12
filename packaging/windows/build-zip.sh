#!/bin/bash
# Builds the MeshTransit client for Windows as a zip: meshd.exe (the
# MeshTransit service), meshctl.exe, wintun.dll and the install scripts.
# Usage: packaging/windows/build-zip.sh VERSION {amd64|arm64} [OUTPUT_DIR]
#
# wintun.dll is the signed prebuilt driver DLL from wintun.net, pinned by the
# archive's SHA-256 and redistributed unmodified with its licence.
set -euo pipefail

version=${1:-}
architecture=${2:-}
output_dir=${3:-dist}
if [[ -z "$version" || ( "$architecture" != amd64 && "$architecture" != arm64 ) ]]; then
	printf 'usage: %s VERSION {amd64|arm64} [OUTPUT_DIR]\n' "$0" >&2
	exit 2
fi
[[ "$version" =~ ^[0-9A-Za-z.+-]+$ ]] || {
	printf 'VERSION contains unsupported characters\n' >&2
	exit 1
}

readonly wintun_version=0.14.1
readonly wintun_sha256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
readonly wintun_url="https://www.wintun.net/builds/wintun-$wintun_version.zip"

script_dir=$(cd "$(dirname "$0")" && pwd -P)
repository_dir=$(cd "$script_dir/../.." && pwd -P)
commit=${MESH_COMMIT:-$(git -C "$repository_dir" rev-parse --verify HEAD)}
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || {
	printf 'MESH_COMMIT must be a full lowercase Git commit\n' >&2
	exit 1
}
source_date_epoch=${SOURCE_DATE_EPOCH:-$(git -C "$repository_dir" show -s --format=%ct HEAD)}
build_date=$(date -u -r "$source_date_epoch" '+%Y-%m-%dT%H:%M:%SZ')

cache_dir="$repository_dir/dist/cache"
mkdir -p "$cache_dir" "$output_dir"
output_dir=$(cd "$output_dir" && pwd -P)
wintun_zip="$cache_dir/wintun-$wintun_version.zip"
if [[ ! -f "$wintun_zip" ]]; then
	curl -fsSL -o "$wintun_zip.partial" "$wintun_url"
	mv "$wintun_zip.partial" "$wintun_zip"
fi
printf '%s  %s\n' "$wintun_sha256" "$wintun_zip" | shasum -a 256 -c --quiet - || {
	printf 'wintun archive checksum mismatch\n' >&2
	exit 1
}

readonly name="meshtransit-windows-$architecture-$version"
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
stage="$work_dir/$name"
mkdir -p "$stage"

version_package=meshtransit.net/client/internal/version
ldflags="-s -w -X $version_package.Version=$version -X $version_package.Commit=$commit -X $version_package.Date=$build_date"
for binary in meshd meshctl; do
	(cd "$repository_dir" && CGO_ENABLED=0 GOOS=windows GOARCH="$architecture" \
		go build -buildvcs=false -trimpath -ldflags="$ldflags" -o "$stage/$binary.exe" "./client/cmd/$binary")
done
unzip -p "$wintun_zip" "wintun/bin/$architecture/wintun.dll" > "$stage/wintun.dll"
unzip -p "$wintun_zip" "wintun/LICENSE.txt" > "$stage/wintun-LICENSE.txt"
cp "$script_dir/install.ps1" "$script_dir/uninstall.ps1" "$stage/"
(cd "$stage" && shasum -a 256 meshd.exe meshctl.exe wintun.dll > SHA256SUMS)

zip_path="$output_dir/$name.zip"
rm -f "$zip_path"
(cd "$work_dir" && zip -qrX "$zip_path" "$name")
(cd "$output_dir" && shasum -a 256 "$name.zip" > "$name.zip.sha256")
printf '%s\n' "$zip_path"
