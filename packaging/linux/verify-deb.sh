#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# -eq 2 ]] || {
    printf 'usage: %s PACKAGE ARCHITECTURE\n' "$0" >&2
    exit 2
}

readonly package_path="$1"
readonly expected_architecture="$2"
[[ -f "${package_path}" ]] || {
    printf 'package does not exist: %s\n' "${package_path}" >&2
    exit 1
}

(
    cd "$(dirname "${package_path}")"
    sha256sum --check "$(basename "${package_path}").sha256"
)

[[ "$(dpkg-deb --field "${package_path}" Package)" == 'meshctl' ]]
[[ "$(dpkg-deb --field "${package_path}" Architecture)" == "${expected_architecture}" ]]

work_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

dpkg-deb --extract "${package_path}" "${work_dir}/root"
[[ -x "${work_dir}/root/usr/bin/meshctl" ]]
[[ -f "${work_dir}/root/usr/share/doc/meshctl/README.md" ]]
[[ -f "${work_dir}/root/usr/share/doc/meshctl/LICENSE" ]]
[[ -f "${work_dir}/root/usr/share/doc/meshctl/NOTICE" ]]

printf 'verified %s\n' "${package_path}"
