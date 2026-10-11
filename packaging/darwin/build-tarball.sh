#!/bin/bash
# Builds the macOS client tarball: meshd, meshnetd, meshcred, meshctl, the
# launchd plists and the install scripts. Unsigned until a Developer ID exists;
# a curl download carries no quarantine flag, so Gatekeeper does not block it.
#
# Usage: packaging/darwin/build-tarball.sh VERSION {amd64|arm64} [OUTPUT_DIR]
set -euo pipefail

usage() {
	printf 'usage: %s VERSION {amd64|arm64} [OUTPUT_DIR]\n' "$0" >&2
	exit 2
}
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage
readonly version=$1 architecture=$2
output_dir=${3:-dist}
case "$architecture" in amd64 | arm64) ;; *) usage ;; esac
[[ "$version" =~ ^[0-9][0-9A-Za-z.+~-]*$ ]] || {
	printf 'VERSION contains unsupported characters\n' >&2
	exit 2
}

script_dir=$(cd "$(dirname "$0")" && pwd -P)
repository_dir=$(cd "$script_dir/../.." && pwd -P)
commit=${MESH_COMMIT:-$(git -C "$repository_dir" rev-parse --verify HEAD)}
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || {
	printf 'MESH_COMMIT must be a full lowercase Git commit\n' >&2
	exit 1
}
source_date_epoch=${SOURCE_DATE_EPOCH:-$(git -C "$repository_dir" show -s --format=%ct HEAD)}
build_date=$(date -u -r "$source_date_epoch" '+%Y-%m-%dT%H:%M:%SZ')

readonly name="meshtransit-darwin-$architecture-$version"
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
stage="$work_dir/$name"
mkdir -p "$stage/launchd" "$output_dir"
output_dir=$(cd "$output_dir" && pwd -P)

version_package=meshtransit.net/client/internal/version
ldflags="-s -w -X $version_package.Version=$version -X $version_package.Commit=$commit -X $version_package.Date=$build_date"
for binary in meshd meshnetd meshcred meshctl; do
	(cd "$repository_dir" && CGO_ENABLED=0 GOOS=darwin GOARCH="$architecture" \
		go build -buildvcs=false -trimpath -ldflags="$ldflags" -o "$stage/$binary" "./client/cmd/$binary")
done
install -m 0755 "$script_dir/install.sh" "$script_dir/uninstall.sh" "$stage/"
install -m 0644 "$script_dir/newsyslog-meshtransit.conf" "$stage/"
install -m 0644 "$script_dir/launchd/"*.plist "$stage/launchd/"
(cd "$stage" && shasum -a 256 meshd meshnetd meshcred meshctl > SHA256SUMS)

tarball="$output_dir/$name.tar.gz"
tar -C "$work_dir" --uid 0 --gid 0 -czf "$tarball" "$name"
(cd "$output_dir" && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256")
printf '%s\n' "$tarball"
