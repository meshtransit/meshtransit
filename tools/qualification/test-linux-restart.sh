#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-restart.sh"
test_dir=""

cleanup() {
  if [[ -n "${test_dir}" ]]; then
    rm -f -- "${test_dir}/ping.log" "${test_dir}/ping-state"
    rmdir -- "${test_dir}"
  fi
}

trap cleanup EXIT

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

probe_recovery_metrics="$(
  "${harness}" __parse-ping-log \
    "${script_dir}/testdata/probe-recovery.log" \
    1789123000400000000 \
    1789123000800000000
)"
assert_equal probe-recovery "${probe_recovery_metrics}" $'10\t8\t20.0000\t600\t2\t2\t5\t600\t5'

no_recovery_metrics="$(
  "${harness}" __parse-ping-log \
    "${script_dir}/testdata/ping-no-recovery.log" \
    1789123000200000000 \
    1789123000400000000
)"
assert_equal no-recovery "${no_recovery_metrics}" $'5\t1\t80\tnull\t4\t4\t0\tnull\t0'

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-probe-test.XXXXXXXX")"
PATH="${script_dir}/testdata:${PATH}" \
FAKE_PING_STATE="${test_dir}/ping-state" \
  "${harness}" __run-ping 4 0.1 1 192.0.2.1 "${test_dir}/ping.log"
probe_calls="$(<"${test_dir}/ping-state")"
if (( probe_calls < 3 )); then
  printf 'probe loop stopped after %d attempts, want at least 3\n' "${probe_calls}" >&2
  exit 1
fi
grep -Eq '^[0-9]+ packets transmitted, [0-9]+ received, [0-9.]+% packet loss$' \
  "${test_dir}/ping.log"

"${harness}" --help >/dev/null

printf 'linux restart qualification parser tests passed\n'
