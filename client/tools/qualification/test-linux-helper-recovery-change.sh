#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-helper-recovery-change.sh"
test_dir=""

cleanup() {
  if [[ -n "${test_dir}" ]]; then
    rm -f -- "${test_dir}/recovery.json" "${test_dir}/change.json" \
      "${test_dir}/wrong-topology.json" "${test_dir}/stale-counter.json"
    rmdir -- "${test_dir}"
  fi
}

trap cleanup EXIT

help_output="$("${harness}" --help)"
grep -Fq -- 'Runs a bounded meshnetd SIGKILL recovery' <<<"${help_output}"
grep -Fq -- 'stable service generations' <<<"${help_output}"

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-helper-recovery-change-test.XXXXXXXX")"

jq -n '
  {
    schema: "meshtransit.linux-crash-recovery-qualification/v1",
    topology: {node_label: "node-a", peer_label: "node-b", address_families: ["ipv4", "ipv6"]},
    platform: {kernel_release: "test", architecture: "amd64"},
    artifact: {version: "test", commit: "0123456", sha256: null, evidence_complete: false},
    scenario: {action: "sigkill", service: "meshnetd.service"},
    action: {
      target_pid_changed: true,
      meshd_pid_changed: true,
      restart_count_increased: true
    },
    readiness_ms: {
      services_active: 10,
      data_interface: 20,
      daemon_online: 30,
      magic_dns: 40
    },
    failures: [],
    outcome: "pass"
  }
' >"${test_dir}/recovery.json"

jq -n '
  {
    schema: "meshtransit.linux-network-change-qualification/v1",
    topology: {node_label: "node-a", peer_label: "node-b", address_families: ["ipv4", "ipv6"]},
    platform: {kernel_release: "test", architecture: "amd64"},
    artifact: {version: "test", commit: "0123456", sha256: null, evidence_complete: false},
    scenario: {action: "controlled_interface_address_change"},
    baseline: {network_changes_observed: 4, endpoint_refreshes: 4},
    action: {cleanup_ok: true},
    recovery_ms: {event_observed: 10, endpoint_refresh: 20, path_usable: 30},
    final: {network_changes_observed: 5, endpoint_refreshes: 5},
    failures: [],
    outcome: "pass"
  }
' >"${test_dir}/change.json"

"${harness}" __validate-report-pair \
  "${test_dir}/recovery.json" "${test_dir}/change.json"

jq '.topology.node_label = "node-c"' \
  "${test_dir}/change.json" >"${test_dir}/wrong-topology.json"
if "${harness}" __validate-report-pair \
  "${test_dir}/recovery.json" "${test_dir}/wrong-topology.json"; then
  printf 'mismatched topology was accepted\n' >&2
  exit 1
fi

jq '.final.endpoint_refreshes = .baseline.endpoint_refreshes' \
  "${test_dir}/change.json" >"${test_dir}/stale-counter.json"
if "${harness}" __validate-report-pair \
  "${test_dir}/recovery.json" "${test_dir}/stale-counter.json"; then
  printf 'unchanged endpoint-refresh counter was accepted\n' >&2
  exit 1
fi

printf 'linux helper recovery/change qualification validation passed\n'
