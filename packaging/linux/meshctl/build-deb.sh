#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    printf 'usage: %s VERSION {amd64|arm64} [OUTPUT_DIR]\n' "$0" >&2
    exit 2
}

[[ $# -ge 2 && $# -le 3 ]] || usage

readonly version="$1"
readonly architecture="$2"
readonly output_dir="${3:-dist}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_dir="$(cd "${script_dir}/../../.." && pwd)"
readonly repository_dir

case "${architecture}" in
    amd64|arm64) ;;
    *) usage ;;
esac
[[ "${version}" =~ ^[0-9][0-9A-Za-z.+:~-]*$ ]] || {
    printf 'VERSION contains unsupported characters\n' >&2
    exit 2
}

for tool in awk basename date dpkg dpkg-deb du find git go install mktemp sha256sum touch; do
    command -v "${tool}" >/dev/null || {
        printf 'required tool is unavailable: %s\n' "${tool}" >&2
        exit 1
    }
done
dpkg --validate-version "${version}" >/dev/null

commit="${MESH_COMMIT:-$(git -C "${repository_dir}" rev-parse --verify HEAD)}"
readonly commit
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || {
    printf 'MESH_COMMIT must be a full lowercase Git commit\n' >&2
    exit 1
}

source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "${repository_dir}" show -s --format=%ct HEAD)}"
readonly source_date_epoch
[[ "${source_date_epoch}" =~ ^[0-9]+$ ]] || {
    printf 'SOURCE_DATE_EPOCH must be a non-negative integer\n' >&2
    exit 1
}
build_date="$(date -u --date="@${source_date_epoch}" '+%Y-%m-%dT%H:%M:%SZ')"
readonly build_date

work_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

readonly package_root="${work_dir}/root"
readonly binary_dir="${work_dir}/bin"
mkdir -p "${package_root}/DEBIAN" "${binary_dir}" "${output_dir}"

readonly version_package='github.com/meshtransit/meshtransit/client/internal/version'
readonly ldflags="-s -w -X ${version_package}.Version=${version} -X ${version_package}.Commit=${commit} -X ${version_package}.Date=${build_date}"

(
    cd "${repository_dir}"
    CGO_ENABLED=0 GOOS=linux GOARCH="${architecture}" \
        go build -buildvcs=false -trimpath -ldflags="${ldflags}" \
        -o "${binary_dir}/meshctl" ./client/cmd/meshctl
)

install -D -m 0755 "${binary_dir}/meshctl" "${package_root}/usr/bin/meshctl"
install -D -m 0644 "${repository_dir}/client/cmd/meshctl/README.md" \
    "${package_root}/usr/share/doc/meshctl/README.md"
install -D -m 0644 "${repository_dir}/client/LICENSE" \
    "${package_root}/usr/share/doc/meshctl/LICENSE"
install -D -m 0644 "${repository_dir}/NOTICE" \
    "${package_root}/usr/share/doc/meshctl/NOTICE"

installed_size="$(du -sk "${package_root}" | awk '{print $1}')"
readonly installed_size
cat >"${package_root}/DEBIAN/control" <<EOF
Package: meshctl
Version: ${version}
Architecture: ${architecture}
Maintainer: MeshTransit maintainers
Installed-Size: ${installed_size}
Section: net
Priority: optional
Recommends: meshd
Homepage: https://github.com/meshtransit/meshtransit
Description: MeshTransit command-line client
 Unprivileged command-line access to the versioned local MeshTransit daemon API.
EOF

while IFS= read -r -d '' path; do
    touch --no-dereference --date="@${source_date_epoch}" "${path}"
done < <(find "${package_root}" -print0)

readonly package_path="${output_dir}/meshctl_${version}_${architecture}.deb"
SOURCE_DATE_EPOCH="${source_date_epoch}" \
    dpkg-deb --root-owner-group --build "${package_root}" "${package_path}"
(
    cd "${output_dir}"
    sha256sum "$(basename "${package_path}")" >"$(basename "${package_path}").sha256"
)
printf '%s\n' "${package_path}"
