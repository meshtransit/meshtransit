#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-runtime-recovery-traffic-qualification/v1"
readonly repeat_schema_version="meshtransit.linux-runtime-recovery-repeat-qualification/v1"

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly repeat_harness="${script_dir}/linux-runtime-recovery-repeat.sh"
readonly restart_harness="${script_dir}/linux-restart.sh"

temp_dir=""
ping4_probe_pid=""
ping6_probe_pid=""
dns_probe_pid=""

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-runtime-recovery-traffic.sh \
    --node-label LABEL \
    --peer-label LABEL \
    --peer-v4 ADDRESS \
    --peer-v6 ADDRESS \
    --peer-name MESH_DNS_NAME \
    --confirm-helper-socket-fault LABEL \
    [--artifact-sha256 HEX] \
    [--iterations N] \
    [--inter-run-seconds N] \
    [--recovery-timeout-seconds N] \
    [--resource-timeout-seconds N] \
    [--lead-seconds N] \
    [--tail-seconds N] \
    [--probe-interval SECONDS] \
    [--poll-interval SECONDS] \
    [--data-interface NAME] \
    [--dns-interface NAME]

Runs the in-process helper-socket recovery gate while continuously probing a
fixed peer over IPv4, IPv6, and uncached MeshTransit DNS. Every sample must observe a
real outage in all three probes, recover a stable trailing run, and pass the
single-sample runtime/resource invariants. Output is one redacted aggregate
JSON document; peer addresses and DNS names are never retained.
EOF
}

fail() {
  printf 'linux-runtime-recovery-traffic: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-runtime-recovery-traffic: %s\n' "$*" >&2
}

cleanup() {
  local path
  local pid

  set +e
  for pid in "${ping4_probe_pid}" "${ping6_probe_pid}" "${dns_probe_pid}"; do
    if [[ -n "${pid}" ]]; then
      kill "${pid}" 2>/dev/null
      wait "${pid}" 2>/dev/null
    fi
  done
  if [[ -n "${temp_dir}" && -d "${temp_dir}" ]]; then
    while IFS= read -r -d '' path; do
      rm -f -- "${path}"
    done < <(find "${temp_dir}" -maxdepth 1 -type f -print0 2>/dev/null)
    rmdir -- "${temp_dir}" 2>/dev/null
  fi
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

require_command() {
  local command_name="$1"

  command -v "${command_name}" >/dev/null 2>&1 ||
    fail "required command not found: ${command_name}"
}

validate_label() {
  local label="$1"
  local value="$2"

  if [[ ! "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]; then
    fail "${label} must be 1-64 safe label characters"
  fi
}

validate_positive_integer() {
  local label="$1"
  local value="$2"
  local maximum="$3"

  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]] || (( value > maximum )); then
    fail "${label} must be an integer between 1 and ${maximum}"
  fi
}

validate_interval() {
  local label="$1"
  local value="$2"

  if ! awk -v value="${value}" 'BEGIN {
    if (value !~ /^[0-9]+([.][0-9]+)?$/ || value < 0.05 || value > 2) {
      exit 1
    }
  }'; then
    fail "${label} must be between 0.05 and 2 seconds"
  fi
}

validate_interface() {
  local label="$1"
  local value="$2"

  if [[ ! "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ ]]; then
    fail "${label} is not a valid bounded Linux interface name"
  fi
}

validate_dns_name() {
  local value="$1"
  local trimmed="${value%.}"
  local dns_label
  local -a dns_labels

  if (( ${#trimmed} == 0 || ${#trimmed} > 253 )) ||
    [[ "${trimmed}" == *..* || "${trimmed}" == .* ]]; then
    fail "peer-name must be a bounded DNS name"
  fi
  IFS='.' read -r -a dns_labels <<<"${trimmed}"
  for dns_label in "${dns_labels[@]}"; do
    if (( ${#dns_label} == 0 || ${#dns_label} > 63 )) ||
      [[ ! "${dns_label}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]; then
      fail "peer-name contains an invalid DNS label"
    fi
  done
}

now_ns() {
  local value

  value="$(date +%s%N)"
  [[ "${value}" =~ ^[0-9]{19}$ ]] ||
    fail "date does not provide nanosecond epoch timestamps"
  printf '%s\n' "${value}"
}

epoch_ns_to_seconds() {
  local value="$1"

  printf '%s.%09d\n' "$(( value / 1000000000 ))" "$(( value % 1000000000 ))"
}

run_dns_probe() {
  local interval="$1"
  local duration="$2"
  local peer_name="$3"
  local peer_v4="$4"
  local peer_v6="$5"
  local log_path="$6"
  local started_ns
  local deadline_ns
  local current_ns
  local timestamp_ns
  local output
  local transmitted=0
  local received=0
  local loss

  started_ns="$(now_ns)"
  deadline_ns=$(( started_ns + duration * 1000000000 ))
  current_ns="${started_ns}"
  : >"${log_path}"

  while (( current_ns < deadline_ns )); do
    transmitted=$((transmitted + 1))
    output="$(timeout 1s resolvectl query --cache=no "${peer_name}" 2>/dev/null || true)"
    timestamp_ns="$(now_ns)"
    if grep -Fq -- "${peer_v4}" <<<"${output}" &&
      grep -Fq -- "${peer_v6}" <<<"${output}"; then
      received=$((received + 1))
      printf '[%s] probe_seq=%d reply\n' \
        "$(epoch_ns_to_seconds "${timestamp_ns}")" \
        "${transmitted}" >>"${log_path}"
    else
      printf '[%s] probe_seq=%d timeout\n' \
        "$(epoch_ns_to_seconds "${timestamp_ns}")" \
        "${transmitted}" >>"${log_path}"
    fi
    sleep "${interval}"
    current_ns="$(now_ns)"
  done

  loss="$(awk -v transmitted="${transmitted}" -v received="${received}" 'BEGIN {
    if (transmitted == 0) {
      print 100
    } else {
      printf "%.4f", ((transmitted - received) * 100) / transmitted
    }
  }')"
  printf '%d packets transmitted, %d received, %s%% packet loss\n' \
    "${transmitted}" "${received}" "${loss}" >>"${log_path}"
}

probe_json() {
  local log_path="$1"
  local action_start_ns="$2"
  local metrics
  local transmitted=0
  local received=0
  local loss=100
  local first_reply_ms=null
  local maximum_loss=0
  local missing_after=0
  local replies_after=0
  local stable_ms=null
  local trailing_run=0
  local parser_ok=false

  if metrics="$("${restart_harness}" __parse-ping-log \
    "${log_path}" "${action_start_ns}" "${action_start_ns}")"; then
    IFS=$'\t' read -r transmitted received loss first_reply_ms maximum_loss \
      missing_after replies_after stable_ms trailing_run <<<"${metrics}"
    parser_ok=true
  fi

  jq -n \
    --argjson parser_ok "${parser_ok}" \
    --argjson transmitted "${transmitted}" \
    --argjson received "${received}" \
    --argjson loss "${loss}" \
    --argjson first_reply_ms "${first_reply_ms}" \
    --argjson maximum_loss "${maximum_loss}" \
    --argjson missing_after "${missing_after}" \
    --argjson replies_after "${replies_after}" \
    --argjson stable_ms "${stable_ms}" \
    --argjson trailing_run "${trailing_run}" '
      {
        parser_ok: $parser_ok,
        transmitted: $transmitted,
        received: $received,
        loss_percent: $loss,
        first_reply_after_action_ms: $first_reply_ms,
        maximum_consecutive_loss: $maximum_loss,
        missing_after_action: $missing_after,
        replies_after_action: $replies_after,
        stable_recovery_ms: $stable_ms,
        consecutive_replies_at_end: $trailing_run
      }
    '
}

valid_child_report() {
  local report_path="$1"

  jq -e --arg schema "${repeat_schema_version}" '
    type == "object" and
    .schema == $schema and
    .scenario.iterations_requested == 1 and
    .scenario.iterations_completed == 1 and
    .samples[0].fault.runtime_failure_observed == true and
    .samples[0].fault.pending_observed == true and
    .samples[0].resource_check.outcome == "pass" and
    .outcome == "pass" and
    (.failures | type == "array" and length == 0)
  ' "${report_path}" >/dev/null 2>&1
}

validate_report() {
  local report_path="$1"

  jq -e --arg schema "${schema_version}" '
    type == "object" and
    .schema == $schema and
    .scenario.iterations_completed == .scenario.iterations_requested and
    .scenario.iterations_requested > 0 and
    (.samples | length) == .scenario.iterations_requested and
    all(.samples[];
      .child_harness_exit_code == 0 and
      .child_report_valid == true and
      .runtime.outcome == "pass" and
      all(.traffic[];
        .parser_ok == true and
        .missing_after_action > 0 and
        .first_reply_after_action_ms != null and
        .stable_recovery_ms != null and
        .consecutive_replies_at_end >= 3
      ) and
      .outcome == "pass" and
      (.failures | length) == 0
    ) and
    .outcome == "pass" and
    (.failures | type == "array" and length == 0)
  ' "${report_path}" >/dev/null 2>&1
}

main() {
  local node_label=""
  local peer_label=""
  local peer_v4=""
  local peer_v6=""
  local peer_name=""
  local confirmation=""
  local artifact_sha256=""
  local iterations=3
  local inter_run_seconds=1
  local recovery_timeout_seconds=30
  local resource_timeout_seconds=5
  local lead_seconds=2
  local tail_seconds=5
  local probe_interval=0.2
  local poll_interval=0.1
  local data_interface=mesh0
  local dns_interface=meshdns0
  local observation_seconds
  local baseline_status
  local started_at
  local runs_path
  local run_path
  local child_exit_code
  local child_valid
  local action_start_ns
  local ping4_path
  local ping6_path
  local dns_path
  local ping4_pid
  local ping6_pid
  local dns_pid
  local ping4
  local ping6
  local dns
  local sample
  local failures
  local report
  local outcome
  local iteration
  local completed_iterations=0
  local runner_failure=""

  while (( $# > 0 )); do
    case "$1" in
      --node-label) [[ $# -ge 2 ]] || fail "--node-label requires a value"; node_label="$2"; shift 2 ;;
      --peer-label) [[ $# -ge 2 ]] || fail "--peer-label requires a value"; peer_label="$2"; shift 2 ;;
      --peer-v4) [[ $# -ge 2 ]] || fail "--peer-v4 requires a value"; peer_v4="$2"; shift 2 ;;
      --peer-v6) [[ $# -ge 2 ]] || fail "--peer-v6 requires a value"; peer_v6="$2"; shift 2 ;;
      --peer-name) [[ $# -ge 2 ]] || fail "--peer-name requires a value"; peer_name="$2"; shift 2 ;;
      --confirm-helper-socket-fault) [[ $# -ge 2 ]] || fail "--confirm-helper-socket-fault requires a value"; confirmation="$2"; shift 2 ;;
      --artifact-sha256) [[ $# -ge 2 ]] || fail "--artifact-sha256 requires a value"; artifact_sha256="$2"; shift 2 ;;
      --iterations) [[ $# -ge 2 ]] || fail "--iterations requires a value"; iterations="$2"; shift 2 ;;
      --inter-run-seconds) [[ $# -ge 2 ]] || fail "--inter-run-seconds requires a value"; inter_run_seconds="$2"; shift 2 ;;
      --recovery-timeout-seconds) [[ $# -ge 2 ]] || fail "--recovery-timeout-seconds requires a value"; recovery_timeout_seconds="$2"; shift 2 ;;
      --resource-timeout-seconds) [[ $# -ge 2 ]] || fail "--resource-timeout-seconds requires a value"; resource_timeout_seconds="$2"; shift 2 ;;
      --lead-seconds) [[ $# -ge 2 ]] || fail "--lead-seconds requires a value"; lead_seconds="$2"; shift 2 ;;
      --tail-seconds) [[ $# -ge 2 ]] || fail "--tail-seconds requires a value"; tail_seconds="$2"; shift 2 ;;
      --probe-interval) [[ $# -ge 2 ]] || fail "--probe-interval requires a value"; probe_interval="$2"; shift 2 ;;
      --poll-interval) [[ $# -ge 2 ]] || fail "--poll-interval requires a value"; poll_interval="$2"; shift 2 ;;
      --data-interface) [[ $# -ge 2 ]] || fail "--data-interface requires a value"; data_interface="$2"; shift 2 ;;
      --dns-interface) [[ $# -ge 2 ]] || fail "--dns-interface requires a value"; dns_interface="$2"; shift 2 ;;
      -h|--help) usage; return ;;
      *) fail "unknown argument: $1" ;;
    esac
  done

  [[ "${EUID}" -eq 0 ]] || fail "must run as root"
  [[ "$(uname -s)" == Linux ]] || fail "this qualification only runs on Linux"
  [[ -n "${node_label}" ]] || fail "--node-label is required"
  [[ -n "${peer_label}" ]] || fail "--peer-label is required"
  [[ -n "${peer_v4}" ]] || fail "--peer-v4 is required"
  [[ -n "${peer_v6}" ]] || fail "--peer-v6 is required"
  [[ -n "${peer_name}" ]] || fail "--peer-name is required"
  validate_label node-label "${node_label}"
  validate_label peer-label "${peer_label}"
  [[ "${confirmation}" == "${node_label}" ]] ||
    fail "confirmation must exactly match node-label"
  validate_dns_name "${peer_name}"
  validate_positive_integer iterations "${iterations}" 10
  validate_positive_integer inter-run-seconds "${inter_run_seconds}" 60
  validate_positive_integer recovery-timeout-seconds "${recovery_timeout_seconds}" 120
  validate_positive_integer resource-timeout-seconds "${resource_timeout_seconds}" 30
  validate_positive_integer lead-seconds "${lead_seconds}" 10
  validate_positive_integer tail-seconds "${tail_seconds}" 30
  validate_interval probe-interval "${probe_interval}"
  validate_interval poll-interval "${poll_interval}"
  validate_interface data-interface "${data_interface}"
  validate_interface dns-interface "${dns_interface}"
  if [[ -n "${artifact_sha256}" && ! "${artifact_sha256}" =~ ^[A-Fa-f0-9]{64}$ ]]; then
    fail "artifact-sha256 must be exactly 64 hexadecimal characters"
  fi
  if [[ ! "${peer_v4}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    fail "peer-v4 must be an IPv4 address"
  fi
  if [[ "${peer_v6}" != *:* || "${peer_v6}" == *%* ]]; then
    fail "peer-v6 must be an IPv6 address without a zone identifier"
  fi

  [[ -x "${repeat_harness}" ]] || fail "repeat runtime harness is not executable"
  [[ -x "${restart_harness}" ]] || fail "restart harness is not executable"
  for command_name in awk date find grep ip jq meshctl mktemp ping resolvectl sleep systemctl timeout uname; do
    require_command "${command_name}"
  done
  systemctl is-active --quiet meshd.service meshnetd.service ||
    fail "both services must be active"
  ip -4 route get "${peer_v4}" 2>/dev/null | grep -Fq -- "dev ${data_interface}" ||
    fail "peer-v4 does not route through ${data_interface}"
  ip -6 route get "${peer_v6}" 2>/dev/null | grep -Fq -- "dev ${data_interface}" ||
    fail "peer-v6 does not route through ${data_interface}"
  baseline_status="$(meshctl --timeout 5s --json status 2>/dev/null)" ||
    fail "meshctl could not read baseline daemon status"
  jq -e '
    .control_session == "synchronized" and
    .dns == "configured" and
    .paths.available == true and
    .paths.peer_count >= 1 and
    (.data_plane | startswith("encrypted_"))
  ' >/dev/null <<<"${baseline_status}" ||
    fail "baseline status is not traffic-ready"
  ping -4 -n -c 3 -W 1 "${peer_v4}" >/dev/null 2>&1 ||
    fail "baseline IPv4 peer traffic is unavailable"
  ping -6 -n -c 3 -W 1 "${peer_v6}" >/dev/null 2>&1 ||
    fail "baseline IPv6 peer traffic is unavailable"
  baseline_status="$(timeout 2s resolvectl query --cache=no "${peer_name}" 2>/dev/null)" ||
    fail "baseline uncached MeshTransit DNS query failed"
  grep -Fq -- "${peer_v4}" <<<"${baseline_status}" ||
    fail "baseline MeshTransit DNS query omitted peer IPv4"
  grep -Fq -- "${peer_v6}" <<<"${baseline_status}" ||
    fail "baseline MeshTransit DNS query omitted peer IPv6"

  observation_seconds=$((
    lead_seconds + recovery_timeout_seconds + resource_timeout_seconds + tail_seconds + 5
  ))
  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-runtime-recovery-traffic.XXXXXXXX")"
  runs_path="${temp_dir}/runs.ndjson"
  : >"${runs_path}"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  for (( iteration = 1; iteration <= iterations; iteration++ )); do
    run_path="${temp_dir}/runtime-${iteration}.json"
    ping4_path="${temp_dir}/ping4-${iteration}.log"
    ping6_path="${temp_dir}/ping6-${iteration}.log"
    dns_path="${temp_dir}/dns-${iteration}.log"
    child_valid=false
    progress "running traffic-bearing runtime recovery sample ${iteration}/${iterations}"

    "${restart_harness}" __run-ping 4 "${probe_interval}" \
      "${observation_seconds}" "${peer_v4}" "${ping4_path}" &
    ping4_pid=$!
    "${restart_harness}" __run-ping 6 "${probe_interval}" \
      "${observation_seconds}" "${peer_v6}" "${ping6_path}" &
    ping6_pid=$!
    run_dns_probe "${probe_interval}" "${observation_seconds}" \
      "${peer_name}" "${peer_v4}" "${peer_v6}" "${dns_path}" &
    dns_pid=$!
    ping4_probe_pid="${ping4_pid}"
    ping6_probe_pid="${ping6_pid}"
    dns_probe_pid="${dns_pid}"

    sleep "${lead_seconds}"
    action_start_ns="$(now_ns)"
    if "${repeat_harness}" \
      --node-label "${node_label}" \
      --confirm-helper-socket-fault "${node_label}" \
      --artifact-sha256 "${artifact_sha256}" \
      --iterations 1 \
      --inter-run-seconds 1 \
      --recovery-timeout-seconds "${recovery_timeout_seconds}" \
      --resource-timeout-seconds "${resource_timeout_seconds}" \
      --poll-interval "${poll_interval}" \
      --data-interface "${data_interface}" \
      --dns-interface "${dns_interface}" >"${run_path}"; then
      child_exit_code=0
    else
      child_exit_code=$?
    fi

    wait "${ping4_pid}" || true
    wait "${ping6_pid}" || true
    wait "${dns_pid}" || true
    ping4_probe_pid=""
    ping6_probe_pid=""
    dns_probe_pid=""

    if [[ -s "${run_path}" ]] && valid_child_report "${run_path}"; then
      child_valid=true
    fi
    ping4="$(probe_json "${ping4_path}" "${action_start_ns}")"
    ping6="$(probe_json "${ping6_path}" "${action_start_ns}")"
    dns="$(probe_json "${dns_path}" "${action_start_ns}")"
    failures="$(jq -n \
      --argjson child_exit_code "${child_exit_code}" \
      --argjson child_valid "${child_valid}" \
      --argjson timeout_ms "$(( recovery_timeout_seconds * 1000 ))" \
      --argjson ipv4 "${ping4}" \
      --argjson ipv6 "${ping6}" \
      --argjson magic_dns "${dns}" '
        def probe_failures(name; probe): [
          if probe.parser_ok != true then "\(name)_probe_unparseable" else empty end,
          if probe.missing_after_action <= 0 then "\(name)_outage_not_observed" else empty end,
          if probe.first_reply_after_action_ms == null then "\(name)_did_not_recover" else empty end,
          if probe.stable_recovery_ms == null then "\(name)_did_not_stabilize" else empty end,
          if probe.stable_recovery_ms != null and probe.stable_recovery_ms > $timeout_ms then "\(name)_stable_recovery_timeout" else empty end,
          if probe.consecutive_replies_at_end < 3 then "\(name)_unstable_at_end" else empty end
        ];
        ([
          if $child_exit_code != 0 then "runtime_harness_failed" else empty end,
          if $child_valid != true then "runtime_report_rejected" else empty end
        ] +
        probe_failures("ipv4"; $ipv4) +
        probe_failures("ipv6"; $ipv6) +
        probe_failures("magic_dns"; $magic_dns)) | unique
      ')"

    sample="$(jq -n \
      --argjson iteration "${iteration}" \
      --argjson child_exit_code "${child_exit_code}" \
      --argjson child_valid "${child_valid}" \
      --argjson runtime "$(if [[ -s "${run_path}" ]]; then jq -c '{artifact,platform,scenario,summary,outcome}' "${run_path}" 2>/dev/null || printf 'null'; else printf 'null'; fi)" \
      --argjson ipv4 "${ping4}" \
      --argjson ipv6 "${ping6}" \
      --argjson magic_dns "${dns}" \
      --argjson failures "${failures}" '
        {
          iteration: $iteration,
          child_harness_exit_code: $child_exit_code,
          child_report_valid: $child_valid,
          runtime: $runtime,
          traffic: {
            ipv4: $ipv4,
            ipv6: $ipv6,
            magic_dns: $magic_dns
          },
          failures: $failures,
          outcome: (if ($failures | length) == 0 then "pass" else "fail" end)
        }
      ')"
    printf '%s\n' "${sample}" >>"${runs_path}"
    completed_iterations="${iteration}"
    if ! jq -e '.outcome == "pass"' >/dev/null <<<"${sample}"; then
      progress "sample ${iteration} failed; stopping the qualification"
      break
    fi
    if (( iteration < iterations )); then
      sleep "${inter_run_seconds}"
    fi
  done

  report="$(jq -n \
    --arg schema "${schema_version}" \
    --arg started_at "${started_at}" \
    --arg node_label "${node_label}" \
    --arg peer_label "${peer_label}" \
    --arg runner_failure "${runner_failure}" \
    --argjson iterations_requested "${iterations}" \
    --argjson iterations_completed "${completed_iterations}" \
    --argjson inter_run_seconds "${inter_run_seconds}" \
    --argjson recovery_timeout_seconds "${recovery_timeout_seconds}" \
    --argjson resource_timeout_seconds "${resource_timeout_seconds}" \
    --argjson lead_seconds "${lead_seconds}" \
    --argjson tail_seconds "${tail_seconds}" \
    --argjson probe_interval "${probe_interval}" \
    --argjson runs "$(jq -s '.' "${runs_path}")" '
      def p95(values):
        (values | map(select(type == "number")) | sort) as $sorted
        | if ($sorted | length) == 0 then null
          else $sorted[((($sorted | length) * 0.95 | ceil) - 1)]
          end;
      {
        schema: $schema,
        started_at: $started_at,
        topology: {
          node_label: $node_label,
          peer_label: $peer_label,
          address_families: ["ipv4", "ipv6"],
          magic_dns: true
        },
        artifact: ($runs[0].runtime.artifact // null),
        platform: ($runs[0].runtime.platform // null),
        scenario: {
          action: "helper_socket_permission_fault_at_startup_with_live_traffic",
          iterations_requested: $iterations_requested,
          iterations_completed: $iterations_completed,
          inter_run_seconds: $inter_run_seconds,
          recovery_timeout_seconds: $recovery_timeout_seconds,
          resource_timeout_seconds: $resource_timeout_seconds,
          lead_seconds: $lead_seconds,
          tail_seconds: $tail_seconds,
          probe_interval_seconds: $probe_interval
        },
        samples: $runs,
        summary: {
          runtime_synchronized_p95_ms: p95($runs | map(.runtime.summary.synchronized_p95_ms)),
          ipv4_stable_recovery_p95_ms: p95($runs | map(.traffic.ipv4.stable_recovery_ms)),
          ipv6_stable_recovery_p95_ms: p95($runs | map(.traffic.ipv6.stable_recovery_ms)),
          magic_dns_stable_recovery_p95_ms: p95($runs | map(.traffic.magic_dns.stable_recovery_ms))
        }
      }
      | .failures = ([
          if $runner_failure != "" then $runner_failure else empty end,
          if .scenario.iterations_completed != .scenario.iterations_requested then "iterations_incomplete" else empty end,
          (.samples[].failures[])
        ] | unique)
      | .outcome = if (.failures | length) == 0 then "pass" else "fail" end
    ')"

  printf '%s\n' "${report}"
  outcome="$(jq -r '.outcome' <<<"${report}")"
  if [[ "${outcome}" != pass ]]; then
    progress "qualification failed; inspect the JSON failure codes"
    return 2
  fi
  progress "qualification passed"
}

case "${1:-}" in
  __validate-label)
    [[ $# -eq 2 ]] || fail "__validate-label requires one value"
    validate_label label "$2"
    ;;
  __validate-dns-name)
    [[ $# -eq 2 ]] || fail "__validate-dns-name requires one value"
    validate_dns_name "$2"
    ;;
  __validate-report)
    [[ $# -eq 2 ]] || fail "__validate-report requires REPORT"
    validate_report "$2"
    ;;
  -h|--help)
    usage
    ;;
  *)
    main "$@"
    ;;
esac
