#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

fail() {
    printf 'audit-release-binary: %s\n' "$*" >&2
    exit 1
}

(( $# > 0 )) || fail "usage: $0 BINARY..."

readonly -a forbidden_markers=(
    '--enable-tun-poc'
    '--enable-wireguard-poc'
    '--enable-dns-poc'
    '--unsafe-allow-unverified-local-peer'
    'UnsafeAllowUnverifiedLocalPeer'
    'unsafeAllowUnverifiedPeer'
)

for binary in "$@"; do
    [[ -f "${binary}" && ! -L "${binary}" && -x "${binary}" ]] ||
        fail "binary must be an executable regular file: ${binary}"

    for marker in "${forbidden_markers[@]}"; do
        if grep -aFq -- "${marker}" "${binary}"; then
            fail "forbidden development marker found in ${binary}: ${marker}"
        else
            scan_status=$?
            (( scan_status == 1 )) || fail "unable to scan binary: ${binary}"
        fi
    done
done

printf 'release binary audit passed for %d file(s)\n' "$#"
