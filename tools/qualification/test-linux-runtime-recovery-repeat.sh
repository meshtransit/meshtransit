#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-runtime-recovery-repeat.sh"

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-runtime-recovery-repeat-test.XXXXXXXX")"
sample_path="${temp_dir}/sample.json"
report_path="${temp_dir}/report.json"

cleanup() {
  rm -f -- "${sample_path}" "${report_path}"
  rmdir -- "${temp_dir}" 2>/dev/null || true
}
trap cleanup EXIT

help_output="$("${harness}" --help)"
grep -Fq -- 'stops at the first failed' <<<"${help_output}"
grep -Fq -- 'nearest-rank p95 timing' <<<"${help_output}"
grep -Fq -- '--resource-timeout-seconds N' <<<"${help_output}"

"${harness}" __validate-label ubuntu26-amd64
"${harness}" __validate-positive-integer iterations 1 20
"${harness}" __validate-positive-integer iterations 20 20
if "${harness}" __validate-label '../unsafe' 2>/dev/null; then
  printf 'unsafe node label was accepted\n' >&2
  exit 1
fi
if "${harness}" __validate-positive-integer iterations 0 20 2>/dev/null; then
  printf 'zero iterations were accepted\n' >&2
  exit 1
fi
if "${harness}" __validate-positive-integer iterations 21 20 2>/dev/null; then
  printf 'excessive iterations were accepted\n' >&2
  exit 1
fi
if "${harness}" __validate-positive-integer iterations invalid 20 2>/dev/null; then
  printf 'non-numeric iterations were accepted\n' >&2
  exit 1
fi

normalized_routes="$(printf '%s\n' \
  '100.64.0.2/32 scope link' \
  '100.64.0.3/32 proto static scope link' \
  'fd7a:115c:a1e0::2 proto kernel metric 256 pref medium' \
  'fe80::/64 proto kernel metric 256 pref medium' |
  "${harness}" __normalize-routes)"
grep -Fq -- '100.64.0.2/32 scope link' <<<"${normalized_routes}"
grep -Fq -- '100.64.0.3/32 proto static scope link' \
  <<<"${normalized_routes}"
if grep -Fq -- 'proto kernel' <<<"${normalized_routes}"; then
  printf 'address-derived kernel route was not normalized\n' >&2
  exit 1
fi

jq -n '
  {
    schema: "meshtransit.linux-runtime-recovery-qualification/v1",
    topology: {node_label: "ubuntu26-amd64"},
    platform: {kernel_release: "fixture-kernel", architecture: "x86_64"},
    artifact: {version: "0.1.0-rc5", commit: "fixture-commit", sha256: null}
  }
' >"${sample_path}"
"${harness}" __validate-sample-identity \
  "${sample_path}" ubuntu26-amd64 0.1.0-rc5 fixture-commit null \
  fixture-kernel x86_64
if "${harness}" __validate-sample-identity \
  "${sample_path}" ubuntu26-arm64 0.1.0-rc5 fixture-commit null \
  fixture-kernel x86_64 2>/dev/null; then
  printf 'changed sample identity was accepted\n' >&2
  exit 1
fi

jq -n '
  def resource:
    {
      outcome: "pass",
      failures: [],
      services_active: true,
      helper_socket_contract: true,
      status_ready: true,
      runtime_recovery_idle: true,
      settle_ms: 17
    };
  def sample(i; failure_ms; synchronized_ms):
    {
      iteration: i,
      harness_exit_code: 0,
      report_valid: true,
      identity_consistent: true,
      recovery_ms: {
        failure_observed: failure_ms,
        synchronized: synchronized_ms
      },
      resource_check: resource,
      failures: [],
      outcome: "pass"
    };
  {
    schema: "meshtransit.linux-runtime-recovery-repeat-qualification/v1",
    scenario: {
      action: "helper_socket_permission_fault_at_startup",
      iterations_requested: 5,
      iterations_completed: 5
    },
    samples: [
      sample(1; 11; 101),
      sample(2; 14; 104),
      sample(3; 12; 102),
      sample(4; 15; 105),
      sample(5; 13; 103)
    ],
    summary: {
      failure_observed_p95_ms: 15,
      synchronized_p95_ms: 105,
      resource_stable_p95_ms: 17
    },
    failures: [],
    outcome: "pass"
  }
' >"${report_path}"
"${harness}" __validate-report "${report_path}"

jq '.samples[2].resource_check.outcome = "fail"' \
  "${report_path}" >"${sample_path}"
if "${harness}" __validate-report "${sample_path}" 2>/dev/null; then
  printf 'failed resource sample was accepted\n' >&2
  exit 1
fi

printf 'linux repeated runtime-recovery validation passed\n'
