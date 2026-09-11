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
grep -Fq -- 'fails if meshd restarts on either node' <<<"${help_output}"
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

status_with_prefixes='{"self_addresses":["100.64.0.5/32","fd7a:115c:a1e0::6/128"]}'
"${harness}" __status-has-addresses \
  "${status_with_prefixes}" 100.64.0.5 fd7a:115c:a1e0::6
assert_rejected "${harness}" __status-has-addresses \
  "${status_with_prefixes}" 100.64.0.6 fd7a:115c:a1e0::6
assert_rejected "${harness}" __status-has-addresses \
  '{"self_addresses":["100.64.0.5","fd7a:115c:a1e0::6"]}' \
  100.64.0.5 fd7a:115c:a1e0::6

online_status='{"state":"online","control_session":"synchronized","registration":"registered","data_plane":"encrypted_relay_ready","policy_rule_count":0,"netmap_revision":1,"self_addresses":[]}'
idle_status='{"state":"offline","control_session":"synchronized","registration":"registered","data_plane":"idle","policy_rule_count":0,"netmap_revision":1,"self_addresses":[]}'
failed_status='{"state":"offline","control_session":"synchronized","registration":"registered","data_plane":"failed","policy_rule_count":0,"netmap_revision":1,"self_addresses":[]}'
"${harness}" __status-is-ready "${online_status}" true
"${harness}" __status-is-ready "${online_status}" false
"${harness}" __status-is-ready "${idle_status}" false
assert_rejected "${harness}" __status-is-ready "${idle_status}" true
assert_rejected "${harness}" __status-is-ready "${failed_status}" false

assert_rejected "${harness}" __any-mesh-route false false false false
"${harness}" __any-mesh-route true false false false
"${harness}" __any-mesh-route false false false true

service_metrics=$'MainPID=123\nNRestarts=2\nMemoryCurrent=1048576\nMemoryPeak=2097152'
parsed_metrics="$("${harness}" __parse-service-metrics "${service_metrics}")"
jq -e '
  .main_pid == 123 and .restarts == 2 and
  .memory_current_bytes == 1048576 and .memory_peak_bytes == 2097152
' >/dev/null <<<"${parsed_metrics}"
assert_rejected "${harness}" __parse-service-metrics \
  $'MainPID=0\nNRestarts=0\nMemoryCurrent=1\nMemoryPeak=1'
assert_rejected "${harness}" __parse-service-metrics \
  $'MainPID=123\nNRestarts=0\nMemoryCurrent=[not set]\nMemoryPeak=1'

stable_runtime="$("${harness}" __compare-service-metrics \
  "${parsed_metrics}" \
  '{"main_pid":123,"restarts":2,"memory_current_bytes":1572864,"memory_peak_bytes":2621440}')"
jq -e '
  .service_pid_stable == true and .restarts == {before:2,after:2} and
  .memory_current_bytes == {before:1048576,after:1572864} and
  .memory_peak_bytes == {before:2097152,after:2621440}
' >/dev/null <<<"${stable_runtime}"
restarted_runtime="$("${harness}" __compare-service-metrics \
  "${parsed_metrics}" \
  '{"main_pid":456,"restarts":3,"memory_current_bytes":524288,"memory_peak_bytes":786432}')"
jq -e '
  .service_pid_stable == false and .restarts == {before:2,after:3}
' >/dev/null <<<"${restarted_runtime}"

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
