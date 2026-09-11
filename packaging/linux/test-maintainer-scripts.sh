#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
work_dir="$(mktemp -d)"
readonly work_dir
cleanup() {
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

readonly mock_bin="${work_dir}/bin"
readonly calls="${work_dir}/calls"
readonly package_root="${work_dir}/root"
mkdir -p \
    "${mock_bin}" \
    "${package_root}/etc/meshd" \
    "${package_root}/run/meshd" \
    "${package_root}/run/meshnetd" \
    "${package_root}/var/lib/meshd/identities"
touch \
    "${package_root}/etc/meshd/meshd.env" \
    "${package_root}/run/meshd/meshd.sock" \
    "${package_root}/run/meshnetd/meshnetd.sock" \
    "${package_root}/var/lib/meshd/profiles.json" \
    "${package_root}/var/lib/meshd/identities/node.json"

cat >"${mock_bin}/record-command" <<'EOF'
#!/bin/sh
printf '%s' "${0##*/}" >>"${MESHD_TEST_CALLS}"
for argument in "$@"; do
    printf ' <%s>' "${argument}" >>"${MESHD_TEST_CALLS}"
done
printf '\n' >>"${MESHD_TEST_CALLS}"
EOF
chmod 0755 "${mock_bin}/record-command"
ln -s record-command "${mock_bin}/systemd-sysusers"
ln -s record-command "${mock_bin}/systemd-tmpfiles"
ln -s record-command "${mock_bin}/deb-systemd-invoke"

cat >"${mock_bin}/systemctl" <<'EOF'
#!/bin/sh
printf '%s' "${0##*/}" >>"${MESHD_TEST_CALLS}"
for argument in "$@"; do
    printf ' <%s>' "${argument}" >>"${MESHD_TEST_CALLS}"
done
printf '\n' >>"${MESHD_TEST_CALLS}"

case " $* " in
    *" is-enabled "*)
        exit "${MESHD_TEST_SYSTEMCTL_IS_ENABLED:-0}"
        ;;
esac
EOF
chmod 0755 "${mock_bin}/systemctl"

cat >"${mock_bin}/deb-systemd-helper" <<'EOF'
#!/bin/sh
printf '%s' "${0##*/}" >>"${MESHD_TEST_CALLS}"
for argument in "$@"; do
    printf ' <%s>' "${argument}" >>"${MESHD_TEST_CALLS}"
done
printf '\n' >>"${MESHD_TEST_CALLS}"

if [ "${1:-}" = debian-installed ]; then
    exit "${MESHD_TEST_DEBIAN_INSTALLED:-1}"
fi
if [ "${1:-}" = --quiet ] && [ "${2:-}" = was-enabled ]; then
    exit "${MESHD_TEST_WAS_ENABLED:-0}"
fi
EOF
chmod 0755 "${mock_bin}/deb-systemd-helper"

run_script() {
    env \
        DPKG_ROOT="${package_root}" \
        MESHD_TEST_CALLS="${calls}" \
        PATH="${mock_bin}:${PATH}" \
        "$@"
}

run_script "${script_dir}/deb/postinst" configure
grep -Fqx "systemd-sysusers <--root=${package_root}> <meshd.conf>" "${calls}"
grep -Fqx "systemd-tmpfiles <--root=${package_root}> <--create> <meshd.conf>" "${calls}"
grep -Fqx 'deb-systemd-helper <enable> <meshnetd.service>' "${calls}"
grep -Fqx 'deb-systemd-helper <enable> <meshd.service>' "${calls}"
if grep -Fq 'deb-systemd-invoke' "${calls}"; then
    printf 'postinst invoked a live service for an alternate root\n' >&2
    exit 1
fi

: >"${calls}"
MESHD_TEST_WAS_ENABLED=1 run_script "${script_dir}/deb/postinst" configure
grep -Fqx 'deb-systemd-helper <update-state> <meshnetd.service>' "${calls}"
grep -Fqx 'deb-systemd-helper <update-state> <meshd.service>' "${calls}"
if grep -Fq 'deb-systemd-helper <enable>' "${calls}"; then
    printf 'postinst re-enabled an administrator-disabled service\n' >&2
    exit 1
fi

: >"${calls}"
MESHD_TEST_SYSTEMCTL_IS_ENABLED=1 run_script \
    "${script_dir}/deb/postinst" configure 0.1.0~alpha5
grep -Fqx 'deb-systemd-helper <update-state> <meshnetd.service>' "${calls}"
grep -Fqx 'deb-systemd-helper <update-state> <meshd.service>' "${calls}"
if grep -Fq 'deb-systemd-helper <enable>' "${calls}"; then
    printf 'postinst re-enabled a disabled unit from a legacy package\n' >&2
    exit 1
fi

: >"${calls}"
run_script "${script_dir}/deb/prerm" remove
[[ ! -s "${calls}" ]]
[[ -f "${package_root}/var/lib/meshd/profiles.json" ]]

run_script "${script_dir}/deb/postrm" remove
[[ ! -e "${package_root}/run/meshd/meshd.sock" ]]
[[ ! -e "${package_root}/run/meshnetd/meshnetd.sock" ]]
[[ -f "${package_root}/var/lib/meshd/profiles.json" ]]
[[ -f "${package_root}/etc/meshd/meshd.env" ]]

mkdir -p "${package_root}/run/meshd" "${package_root}/run/meshnetd"
touch "${package_root}/run/meshd/stale" "${package_root}/run/meshnetd/stale"
: >"${calls}"
run_script "${script_dir}/deb/postrm" purge
grep -Fqx 'deb-systemd-helper <purge> <meshnetd.service> <meshd.service>' "${calls}"
[[ ! -e "${package_root}/var/lib/meshd" ]]
[[ ! -e "${package_root}/run/meshd" ]]
[[ ! -e "${package_root}/run/meshnetd" ]]
[[ -f "${package_root}/etc/meshd/meshd.env" ]]

if env \
    DPKG_ROOT=relative \
    MESHD_TEST_CALLS="${calls}" \
    PATH="${mock_bin}:${PATH}" \
    "${script_dir}/deb/postrm" purge >/dev/null 2>&1; then
    printf 'postrm accepted a relative DPKG_ROOT\n' >&2
    exit 1
fi

printf 'maintainer lifecycle scripts verified\n'
