#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir

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
[[ "$(dpkg-deb --field "${package_path}" X-MeshTransit-Commit)" =~ ^[0-9a-f]{40}$ ]]
[[ "$(dpkg-deb --field "${package_path}" X-MeshTransit-Build-Date)" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]

work_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

dpkg-deb --extract "${package_path}" "${work_dir}/root"
dpkg-deb --control "${package_path}" "${work_dir}/control"

for script in postinst prerm postrm; do
    dash -n "${work_dir}/control/${script}"
done

[[ -x "${work_dir}/root/usr/bin/meshd" ]]
[[ -x "${work_dir}/root/usr/libexec/meshtransit/meshnetd" ]]
[[ -x "${work_dir}/root/usr/libexec/meshtransit/meshcred" ]]
"${script_dir}/../../tools/security/audit-release-binary.sh" \
    "${work_dir}/root/usr/bin/meshd" \
    "${work_dir}/root/usr/libexec/meshtransit/meshnetd" \
    "${work_dir}/root/usr/libexec/meshtransit/meshcred"
[[ "$(stat -c '%a' "${work_dir}/root/etc/meshd/meshd.env")" == '640' ]]
[[ "$(stat -c '%a' "${work_dir}/root/etc/credstore.encrypted")" == '700' ]]
[[ "$(cat "${work_dir}/control/conffiles")" == '/etc/meshd/meshd.env' ]]
grep -Fq 'init-system-helpers (>= 1.54~)' "${work_dir}/control/control"
grep -Fq 'systemd (>= 255)' "${work_dir}/control/control"

grep -Fq "deb-systemd-helper enable \"\${unit}\"" \
    "${work_dir}/control/postinst"
grep -Fq "deb-systemd-invoke \"\${action}\" meshnetd.service meshd.service" \
    "${work_dir}/control/postinst"
grep -Fq 'deb-systemd-invoke stop meshd.service meshnetd.service meshcred.service' \
    "${work_dir}/control/prerm"
grep -Fq 'systemctl --system is-active --quiet meshd.service' \
    "${work_dir}/control/prerm"
grep -Fq ": >\"\${reinstall_marker}\"" "${work_dir}/control/prerm"
grep -Fq 'remove_reinstall_marker=true' "${work_dir}/control/postinst"
grep -Fq 'deb-systemd-helper purge meshcred.service meshnetd.service meshd.service' \
    "${work_dir}/control/postrm"
grep -Fq "root_prefix=\"\${DPKG_ROOT%/}\"" "${work_dir}/control/postrm"
grep -Fq 'meshd.identity-key.recovery' "${work_dir}/control/postrm"
if grep -Fq 'systemctl enable' "${work_dir}/control/postinst"; then
    printf 'postinst must preserve administrator enablement state\n' >&2
    exit 1
fi
if grep -Fq 'systemctl disable' "${work_dir}/control/prerm"; then
    printf 'prerm must preserve administrator enablement state\n' >&2
    exit 1
fi

grep -Fq -- '--allow-socket-peers' \
    "${work_dir}/root/usr/lib/systemd/system/meshd.service"
grep -Fq -- '--enable-data-plane' \
    "${work_dir}/root/usr/lib/systemd/system/meshd.service"
grep -Fq -- '--enable-dns' \
    "${work_dir}/root/usr/lib/systemd/system/meshd.service"
for unit in meshd.service meshnetd.service; do
    grep -Fqx 'Type=notify' \
        "${work_dir}/root/usr/lib/systemd/system/${unit}"
    grep -Fqx 'NotifyAccess=main' \
        "${work_dir}/root/usr/lib/systemd/system/${unit}"
    grep -Fqx 'TimeoutStartSec=30s' \
        "${work_dir}/root/usr/lib/systemd/system/${unit}"
done
grep -Fq 'Requires=meshcred.service meshnetd.service' \
    "${work_dir}/root/usr/lib/systemd/system/meshd.service"
grep -Fq 'LoadCredentialEncrypted=meshd.identity-key:/etc/credstore.encrypted/meshd.identity-key' \
    "${work_dir}/root/usr/lib/systemd/system/meshd.service"
grep -Fq 'ExecStart=/usr/libexec/meshtransit/meshcred' \
    "${work_dir}/root/usr/lib/systemd/system/meshcred.service"
grep -Fq 'ReadWritePaths=/etc/credstore.encrypted /var/lib/systemd' \
    "${work_dir}/root/usr/lib/systemd/system/meshcred.service"
grep -Fq -- '--allow-user=meshd' \
    "${work_dir}/root/usr/lib/systemd/system/meshnetd.service"
grep -Fq -- '--enable-dns' \
    "${work_dir}/root/usr/lib/systemd/system/meshnetd.service"
for forbidden_flag in \
    --enable-tun-poc \
    --enable-wireguard-poc \
    --enable-dns-poc \
    --unsafe-allow-unverified-local-peer; do
    if grep -Fq -- "${forbidden_flag}" \
        "${work_dir}/root/usr/lib/systemd/system/meshd.service" \
        "${work_dir}/root/usr/lib/systemd/system/meshnetd.service"; then
        printf 'packaged unit contains removed flag: %s\n' "${forbidden_flag}" >&2
        exit 1
    fi
done
grep -Fq 'CapabilityBoundingSet=CAP_CHOWN CAP_NET_ADMIN' \
    "${work_dir}/root/usr/lib/systemd/system/meshnetd.service"
grep -Fq 'ReadWritePaths=/run/meshnetd' \
    "${work_dir}/root/usr/lib/systemd/system/meshnetd.service"
grep -Fq 'RestrictAddressFamilies=AF_UNIX AF_NETLINK' \
    "${work_dir}/root/usr/lib/systemd/system/meshnetd.service"
grep -Fq 'd /run/meshd 0750 meshd meshtransit -' \
    "${work_dir}/root/usr/lib/tmpfiles.d/meshd.conf"
grep -Fq 'd /run/meshnetd 0750 root meshd -' \
    "${work_dir}/root/usr/lib/tmpfiles.d/meshd.conf"

if command -v systemd-analyze >/dev/null; then
    cp "${work_dir}/root/usr/lib/systemd/system/meshd.service" \
        "${work_dir}/meshd.service"
    cp "${work_dir}/root/usr/lib/systemd/system/meshnetd.service" \
        "${work_dir}/meshnetd.service"
    cp "${work_dir}/root/usr/lib/systemd/system/meshcred.service" \
        "${work_dir}/meshcred.service"
    sed -i "s@/usr/bin/meshd@${work_dir}/root/usr/bin/meshd@" \
        "${work_dir}/meshd.service"
    sed -i "s@/usr/libexec/meshtransit/meshnetd@${work_dir}/root/usr/libexec/meshtransit/meshnetd@" \
        "${work_dir}/meshnetd.service"
    sed -i "s@/usr/libexec/meshtransit/meshcred@${work_dir}/root/usr/libexec/meshtransit/meshcred@" \
        "${work_dir}/meshcred.service"
    systemd-analyze verify \
        "${work_dir}/meshcred.service" \
        "${work_dir}/meshd.service" \
        "${work_dir}/meshnetd.service"
fi

printf 'verified %s\n' "${package_path}"
