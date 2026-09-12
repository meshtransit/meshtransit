#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-runtime-recovery.sh"
test_dir=""

cleanup() {
  if [[ -n "${test_dir}" ]]; then
    rm -f -- "${test_dir}/valid.json" "${test_dir}/pending.json" \
      "${test_dir}/restarted.json"
    rmdir -- "${test_dir}"
  fi
}

trap cleanup EXIT

help_output="$("${harness}" --help)"
grep -Fq -- 'Runs a bounded, reversible local-runtime recovery fault.' <<<"${help_output}"
grep -Fq -- 'It does not change profile, identity, policy, control' <<<"${help_output}"

"${harness}" __validate-label ubuntu-amd64
if "${harness}" __validate-label 'unsafe;label' >/dev/null 2>&1; then
  printf 'unsafe node label was accepted\n' >&2
  exit 1
fi

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-runtime-recovery-test.XXXXXXXX")"
jq -n '
  {
    schema: "meshtransit.linux-runtime-recovery-qualification/v1",
    topology: {node_label: "ubuntu-amd64"},
    platform: {kernel_release: "test", architecture: "x86_64"},
    artifact: {
      version: "test",
      commit: "0123456",
      sha256: null,
      evidence_complete: false
    },
    scenario: {action: "helper_socket_permission_fault_at_startup"},
    fault: {
      helper_socket_mode_removed: true,
      service_start_exit_code: 0,
      runtime_failure_observed: true,
      pending_observed: true
    },
    recovery_ms: {failure_observed: 20, synchronized: 1200},
    generation: {
      meshd_pid_stable: true,
      meshnetd_pid_stable: true,
      meshd_restart_count_stable: true,
      meshnetd_restart_count_stable: true
    },
    final: {
      services_active: true,
      helper_socket_mode_restored: true,
      data_interface_present: true,
      dns_interface_present: true,
      control_session: "synchronized",
      data_plane: "idle",
      dns: "configured",
      runtime_recovery: {failures: 1, recoveries: 1, pending: false}
    },
    failures: [],
    outcome: "pass"
  }
' >"${test_dir}/valid.json"

"${harness}" __validate-report "${test_dir}/valid.json"

jq '.final.runtime_recovery.pending = true' \
  "${test_dir}/valid.json" >"${test_dir}/pending.json"
if "${harness}" __validate-report "${test_dir}/pending.json"; then
  printf 'pending runtime recovery was accepted\n' >&2
  exit 1
fi

jq '.generation.meshd_restart_count_stable = false' \
  "${test_dir}/valid.json" >"${test_dir}/restarted.json"
if "${harness}" __validate-report "${test_dir}/restarted.json"; then
  printf 'automatic daemon restart was accepted\n' >&2
  exit 1
fi

printf 'linux runtime recovery qualification validation passed\n'
