#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-runtime-recovery-traffic.sh"

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-runtime-recovery-traffic-test.XXXXXXXX")"
report_path="${temp_dir}/report.json"

cleanup() {
  rm -f -- "${report_path}"
  rmdir -- "${temp_dir}" 2>/dev/null || true
}
trap cleanup EXIT

help_output="$("${harness}" --help)"
grep -Fq -- 'fixed peer over IPv4' <<<"${help_output}"
grep -Fq -- 'uncached MagicDNS' <<<"${help_output}"
grep -Fq -- 'peer addresses and DNS names are never retained' <<<"${help_output}"

"${harness}" __validate-label ubuntu26-amd64
"${harness}" __validate-dns-name peer.mesh.example
if "${harness}" __validate-label '../unsafe' 2>/dev/null; then
  printf 'unsafe node label was accepted\n' >&2
  exit 1
fi
if "${harness}" __validate-dns-name '-invalid.mesh.example' 2>/dev/null; then
  printf 'unsafe DNS name was accepted\n' >&2
  exit 1
fi

jq -n '
  def probe(stable): {
    parser_ok: true,
    transmitted: 20,
    received: 15,
    loss_percent: 25,
    first_reply_after_action_ms: stable,
    maximum_consecutive_loss: 5,
    missing_after_action: 5,
    replies_after_action: 14,
    stable_recovery_ms: stable,
    consecutive_replies_at_end: 8
  };
  def sample(i): {
    iteration: i,
    child_harness_exit_code: 0,
    child_report_valid: true,
    runtime: {outcome: "pass"},
    traffic: {
      ipv4: probe(2100 + i),
      ipv6: probe(2200 + i),
      magic_dns: probe(2300 + i)
    },
    failures: [],
    outcome: "pass"
  };
  {
    schema: "meshtransit.linux-runtime-recovery-traffic-qualification/v1",
    scenario: {iterations_requested: 3, iterations_completed: 3},
    samples: [sample(1), sample(2), sample(3)],
    failures: [],
    outcome: "pass"
  }
' >"${report_path}"
"${harness}" __validate-report "${report_path}"

jq '.samples[1].traffic.magic_dns.missing_after_action = 0' \
  "${report_path}" >"${temp_dir}/invalid.json"
if "${harness}" __validate-report "${temp_dir}/invalid.json" 2>/dev/null; then
  printf 'sample without an observed DNS outage was accepted\n' >&2
  exit 1
fi
rm -f -- "${temp_dir}/invalid.json"

jq '.samples[2].runtime.outcome = "fail"' \
  "${report_path}" >"${temp_dir}/invalid.json"
if "${harness}" __validate-report "${temp_dir}/invalid.json" 2>/dev/null; then
  printf 'failed child runtime report was accepted\n' >&2
  exit 1
fi
rm -f -- "${temp_dir}/invalid.json"

printf 'linux traffic-bearing runtime-recovery validation passed\n'
