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

[[ "$(dpkg-deb --field "${package_path}" Package)" == 'meshd' ]]
[[ "$(dpkg-deb --field "${package_path}" Architecture)" == "${expected_architecture}" ]]

work_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

dpkg-deb --extract "${package_path}" "${work_dir}/root"
dpkg-deb --control "${package_path}" "${work_dir}/control"

[[ -x "${work_dir}/root/usr/bin/meshd" ]]
[[ -x "${work_dir}/root/usr/libexec/meshtransit/meshnetd" ]]
[[ "$(stat -c '%a' "${work_dir}/root/etc/meshd/meshd.env")" == '640' ]]
[[ "$(cat "${work_dir}/control/conffiles")" == '/etc/meshd/meshd.env' ]]

grep -Fq -- '--allow-socket-peers' \
    "${work_dir}/root/usr/lib/systemd/system/meshd.service"
grep -Fq -- '--allow-user=meshd' \
    "${work_dir}/root/usr/lib/systemd/system/meshnetd.service"
grep -Fq 'CapabilityBoundingSet=CAP_CHOWN CAP_NET_ADMIN' \
    "${work_dir}/root/usr/lib/systemd/system/meshnetd.service"

if command -v systemd-analyze >/dev/null; then
    cp "${work_dir}/root/usr/lib/systemd/system/meshd.service" \
        "${work_dir}/meshd.service"
    cp "${work_dir}/root/usr/lib/systemd/system/meshnetd.service" \
        "${work_dir}/meshnetd.service"
    sed -i "s@/usr/bin/meshd@${work_dir}/root/usr/bin/meshd@" \
        "${work_dir}/meshd.service"
    sed -i "s@/usr/libexec/meshtransit/meshnetd@${work_dir}/root/usr/libexec/meshtransit/meshnetd@" \
        "${work_dir}/meshnetd.service"
    systemd-analyze verify \
        "${work_dir}/meshd.service" \
        "${work_dir}/meshnetd.service"
fi

printf 'verified %s\n' "${package_path}"
