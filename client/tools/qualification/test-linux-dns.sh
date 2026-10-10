#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-dns.sh"

assert_rejected() {
  if "$@"; then
    printf 'command unexpectedly succeeded: %q' "$1" >&2
    printf ' %q' "${@:2}" >&2
    printf '\n' >&2
    exit 1
  fi
}

help_output="$("${harness}" --help)"
grep -Fq -- 'bounded Linux split-DNS qualification' <<<"${help_output}"
grep -Fq -- 'A/AAAA/PTR/NODATA/NXDOMAIN' <<<"${help_output}"
grep -Fq -- 'trap restores the service' <<<"${help_output}"

"${harness}" __validate-label ubuntu-a
assert_rejected "${harness}" __validate-label 'ubuntu a'
"${harness}" __validate-dns-label poc1-1
assert_rejected "${harness}" __validate-dns-label '-poc1'
"${harness}" __validate-dns-name n-123.mesh.example
assert_rejected "${harness}" __validate-dns-name 'bad..example'
"${harness}" __validate-ipv4 100.64.0.6
assert_rejected "${harness}" __validate-ipv4 100.64.0.999
"${harness}" __validate-ipv6 fd07:d4de:9d87::d
assert_rejected "${harness}" __validate-ipv6 'fd7a::1%eth0'

printf 'linux DNS qualification validation passed\n'
