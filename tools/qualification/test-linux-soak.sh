#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-soak.sh"
test_dir=""

cleanup() {
  if [[ -n "${test_dir}" ]]; then
    rm -f -- "${test_dir}/passing.ndjson" "${test_dir}/growth.ndjson"
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

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-linux-soak-test.XXXXXXXX")"
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

printf 'linux soak qualification validation passed\n'
