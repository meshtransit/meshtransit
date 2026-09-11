#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-policy.sh"
readonly peer_helper="${script_dir}/testdata/policy_peer.py"

assert_rejected() {
  if "$@" >/dev/null 2>&1; then
    printf 'command unexpectedly succeeded: %q' "$1" >&2
    printf ' %q' "${@:2}" >&2
    printf '\n' >&2
    exit 1
  fi
}

help_output="$("${harness}" --help)"
grep -Fq -- 'bounded dual-stack host-policy phase' <<<"${help_output}"
grep -Fq -- 'does not change control policy' <<<"${help_output}"
grep -Fq -- 'excludes SSH destinations, overlay addresses, and payloads' <<<"${help_output}"

"${harness}" __validate-ssh-destination root@192.0.2.10
assert_rejected "${harness}" __validate-ssh-destination 'root@host;shutdown'
assert_rejected "${harness}" __validate-ssh-destination '-oProxyCommand=unsafe'

"${harness}" __validate-expectation allow
"${harness}" __validate-expectation deny
assert_rejected "${harness}" __validate-expectation pass

"${harness}" __validate-port 1024
"${harness}" __validate-port 65535
assert_rejected "${harness}" __validate-port 0
assert_rejected "${harness}" __validate-port 65536

[[ "$("${harness}" __classify-helper-probe 0)" == allow ]]
[[ "$("${harness}" __classify-helper-probe 10)" == deny ]]
[[ "$("${harness}" __classify-helper-probe 20)" == error ]]
[[ "$("${harness}" __classify-ping-probe 0)" == allow ]]
[[ "$("${harness}" __classify-ping-probe 1)" == deny ]]
[[ "$("${harness}" __classify-ping-probe 2)" == deny ]]
[[ "$("${harness}" __classify-ping-probe 255)" == error ]]

common_arguments=(
  --node-a-ssh root@192.0.2.10
  --node-b-ssh root@192.0.2.11
  --node-a-label ubuntu-a
  --node-b-label ubuntu-b
  --node-a-v4 100.64.0.5
  --node-a-v6 fd7a:115c:a1e0::6
  --node-b-v4 100.64.0.6
  --node-b-v6 fd7a:115c:a1e0::d
  --phase-label asymmetric-a-to-b
  --expect-a-to-b-tcp allow
  --expect-a-to-b-udp allow
  --expect-a-to-b-icmp4 allow
  --expect-a-to-b-icmp6 allow
  --expect-b-to-a-tcp deny
  --expect-b-to-a-udp deny
  --expect-b-to-a-icmp4 deny
  --expect-b-to-a-icmp6 deny
  --artifact-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
)
assert_rejected "${harness}" "${common_arguments[@]}" \
  --confirm-policy-test another-phase
assert_rejected "${harness}" "${common_arguments[@]}" \
  --confirm-policy-test asymmetric-a-to-b \
  --expect-b-to-a-icmp6 maybe

python3 "${peer_helper}" self-test

printf 'linux policy qualification validation passed\n'
