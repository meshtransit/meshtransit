#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-soak.sh"
test_dir=""

cleanup() {
  if [[ -n "${test_dir}" ]]; then
    rm -f -- \
      "${test_dir}/passing.ndjson" \
      "${test_dir}/growth.ndjson" \
      "${test_dir}/cgroup-v1" \
      "${test_dir}/cgroup-v2" \
      "${test_dir}/cgroup-invalid" \
      "${test_dir}/bin/systemctl"
    rmdir -- "${test_dir}/bin" 2>/dev/null || true
    rmdir -- "${test_dir}"
  fi
}

trap cleanup EXIT

append_sample() {
  local path="$1"
  local index="$2"
  local elapsed="$3"
  local meshd_rss="$4"
  local meshnetd_rss="$5"
  local goroutines="$6"

  jq -nc \
    --argjson index "${index}" \
    --argjson elapsed "${elapsed}" \
    --argjson meshd_rss "${meshd_rss}" \
    --argjson meshnetd_rss "${meshnetd_rss}" \
    --argjson goroutines "${goroutines}" '
      {
        index: $index,
        elapsed_seconds: $elapsed,
        process: {
          meshd: {rss_kib: $meshd_rss, threads: 10, descriptors: 20},
          meshnetd: {rss_kib: $meshnetd_rss, threads: 2, descriptors: 5}
        },
        runtime: {
          goroutines: $goroutines,
          heap_alloc_bytes: 100000,
          heap_in_use_bytes: 120000,
          heap_objects: 1000,
          stack_in_use_bytes: 20000,
          sys_bytes: 200000,
          gc_cycles: $index
        },
        failures: [],
        outcome: "pass"
      }
    ' >>"${path}"
}

help_output="$("${harness}" --help)"
grep -Fq -- 'Runs a read-only fixed-topology Linux soak.' <<<"${help_output}"
grep -Fq -- 'Release-candidate defaults are 72 hours' <<<"${help_output}"
grep -Fq -- 'Release-candidate runs must use linux-soak-systemd.sh' <<<"${help_output}"

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-linux-soak-test.XXXXXXXX")"
printf '0::/system.slice/meshtransit-soak-linux-rc1-a.service\n' >"${test_dir}/cgroup-v2"
printf '1:name=systemd:/system.slice/meshtransit-soak-linux-rc1-b.service\n' >"${test_dir}/cgroup-v1"
printf '0::/system.slice/unrelated.service\n' >"${test_dir}/cgroup-invalid"

[[ "$("${harness}" __systemd-unit-from-cgroup "${test_dir}/cgroup-v2")" == "meshtransit-soak-linux-rc1-a.service" ]]
[[ "$("${harness}" __systemd-unit-from-cgroup "${test_dir}/cgroup-v1")" == "meshtransit-soak-linux-rc1-b.service" ]]
if "${harness}" __systemd-unit-from-cgroup "${test_dir}/cgroup-invalid" >/dev/null 2>&1; then
  printf 'invalid cgroup unexpectedly produced a soak unit\n' >&2
  exit 1
fi

mkdir -- "${test_dir}/bin"
cat >"${test_dir}/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *RefuseManualStop*) printf 'yes\n' ;;
  *Restart*) printf 'no\n' ;;
  *) exit 1 ;;
esac
EOF
chmod 0755 "${test_dir}/bin/systemctl"
PATH="${test_dir}/bin:${PATH}" \
  "${harness}" __observer-has-restart-protection \
  meshtransit-soak-linux-rc1-a.service
if PATH="${test_dir}/bin:${PATH}" \
  "${harness}" __observer-has-restart-protection unrelated.service >/dev/null 2>&1; then
  printf 'invalid observer unit unexpectedly passed restart protection\n' >&2
  exit 1
fi

append_sample "${test_dir}/passing.ndjson" 0 0 900 450 90
append_sample "${test_dir}/passing.ndjson" 1 30 1000 500 100
append_sample "${test_dir}/passing.ndjson" 2 60 1080 540 107

passing_summary="$("${harness}" __summarize-samples \
  "${test_dir}/passing.ndjson" 30 10 8 4 4)"
jq -e '
  .outcome == "pass" and
  .sample_count == 2 and
  .baseline_sample_index == 1 and
  .increase_from_baseline.process.meshd.rss_percent == 8 and
  .increase_from_baseline.process.meshnetd.rss_percent == 8 and
  .increase_from_baseline.runtime.goroutines == 7
' >/dev/null <<<"${passing_summary}"

append_sample "${test_dir}/growth.ndjson" 0 0 900 450 90
append_sample "${test_dir}/growth.ndjson" 1 30 1000 500 100
append_sample "${test_dir}/growth.ndjson" 2 60 1200 540 110

growth_summary="$("${harness}" __summarize-samples \
  "${test_dir}/growth.ndjson" 30 10 8 4 4)"
jq -e '
  .outcome == "fail" and
  (.failures | index("meshd_rss_growth_exceeded")) != null and
  (.failures | index("goroutine_growth_exceeded")) != null
' >/dev/null <<<"${growth_summary}"

passing_report="$(jq -nc '
  {
    scenario: {
      requested_duration_seconds: 60,
      actual_duration_seconds: 60,
      samples_expected: 2,
      samples_completed: 2
    },
    journal: {
      available: true,
      warning_or_higher_entries: 0,
      error_or_higher_entries: 0
    },
    steady_state: {failures: []},
    samples: [{failures: []}, {failures: []}]
  }
')"
passing_report="$("${harness}" __finalize-report <<<"${passing_report}")"
jq -e '.outcome == "pass" and .failures == []' >/dev/null <<<"${passing_report}"

failing_report="$(jq -nc '
  {
    scenario: {
      requested_duration_seconds: 60,
      actual_duration_seconds: 45,
      samples_expected: 3,
      samples_completed: 2
    },
    journal: {
      available: true,
      warning_or_higher_entries: 1,
      error_or_higher_entries: 0
    },
    steady_state: {failures: ["goroutine_growth_exceeded"]},
    samples: [
      {failures: []},
      {failures: ["daemon_status_not_ready", "daemon_status_not_ready"]}
    ]
  }
')"
failing_report="$("${harness}" __finalize-report <<<"${failing_report}")"
jq -e '
  .outcome == "fail" and
  .failures == [
    "daemon_status_not_ready",
    "duration_incomplete",
    "goroutine_growth_exceeded",
    "sample_count_incomplete",
    "service_warning_entries_present"
  ]
' >/dev/null <<<"${failing_report}"

printf 'linux soak qualification validation passed\n'
