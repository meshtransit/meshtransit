#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-restart.sh"

assert_equal() {
  local label="$1"
  local actual="$2"
  local expected="$3"

  if [[ "${actual}" != "${expected}" ]]; then
    printf '%s: got %q, want %q\n' "${label}" "${actual}" "${expected}" >&2
    exit 1
  fi
}

recovery_metrics="$(
  "${harness}" __parse-ping-log \
    "${script_dir}/testdata/ping-recovery.log" \
    1789123000400000000 \
    1789123000800000000
)"
assert_equal recovery "${recovery_metrics}" $'10\t8\t20\t600\t2\t2\t5\t600\t5'

no_recovery_metrics="$(
  "${harness}" __parse-ping-log \
    "${script_dir}/testdata/ping-no-recovery.log" \
    1789123000200000000 \
    1789123000400000000
)"
assert_equal no-recovery "${no_recovery_metrics}" $'5\t1\t80\tnull\t4\t4\t0\tnull\t0'

"${harness}" --help >/dev/null

printf 'linux restart qualification parser tests passed\n'
