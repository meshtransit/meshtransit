#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly audit_script="${script_dir}/audit-release-binary.sh"

test_dir=""
cleanup() {
    if [[ -n "${test_dir}" ]]; then
        rm -f -- \
            "${test_dir}/safe" \
            "${test_dir}/forbidden" \
            "${test_dir}/symlink" \
            "${test_dir}/bin/grep"
        rmdir -- "${test_dir}/bin" 2>/dev/null || true
        rmdir -- "${test_dir}"
    fi
}
trap cleanup EXIT

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-release-binary-audit.XXXXXXXX")"
printf '#!/bin/sh\nexit 0\n' >"${test_dir}/safe"
chmod 0755 "${test_dir}/safe"
"${audit_script}" "${test_dir}/safe" >/dev/null

readonly -a forbidden_markers=(
    '--enable-tun-poc'
    '--enable-wireguard-poc'
    '--enable-dns-poc'
    '--unsafe-allow-unverified-local-peer'
    'UnsafeAllowUnverifiedLocalPeer'
    'unsafeAllowUnverifiedPeer'
)

for marker in "${forbidden_markers[@]}"; do
    printf '#!/bin/sh\n%s\n' "${marker}" >"${test_dir}/forbidden"
    chmod 0755 "${test_dir}/forbidden"
    if "${audit_script}" "${test_dir}/forbidden" >/dev/null 2>&1; then
        printf 'forbidden marker unexpectedly passed: %s\n' "${marker}" >&2
        exit 1
    fi
done

ln -s -- "${test_dir}/safe" "${test_dir}/symlink"
if "${audit_script}" "${test_dir}/symlink" >/dev/null 2>&1; then
    printf 'symlink unexpectedly passed release binary audit\n' >&2
    exit 1
fi

mkdir -- "${test_dir}/bin"
printf '#!/bin/sh\nexit 2\n' >"${test_dir}/bin/grep"
chmod 0755 "${test_dir}/bin/grep"
if PATH="${test_dir}/bin:${PATH}" \
    "${audit_script}" "${test_dir}/safe" >/dev/null 2>&1; then
    printf 'binary scan error unexpectedly passed release audit\n' >&2
    exit 1
fi

printf 'release binary audit validation passed\n'
