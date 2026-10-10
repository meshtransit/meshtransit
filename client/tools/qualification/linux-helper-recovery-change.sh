#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-helper-recovery-change-qualification/v1"
readonly recovery_schema="meshtransit.linux-crash-recovery-qualification/v1"
readonly change_schema="meshtransit.linux-network-change-qualification/v1"

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly recovery_harness="${script_dir}/linux-restart.sh"
readonly change_harness="${script_dir}/linux-network-change.sh"

temp_dir=""
restore_services=false

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-helper-recovery-change.sh \
    --node-label LABEL \
    --peer-label LABEL \
    --peer-v4 ADDRESS \
    --peer-v6 ADDRESS \
    --peer-name MESH_DNS_NAME \
    --confirm-recovery-change LABEL \
    [--artifact-sha256 HEX] \
    [--ready-timeout-seconds N] \
    [--network-timeout-seconds N] \
    [--data-interface NAME] \
    [--dns-interface NAME] \
    [--change-interface NAME]

Runs a bounded meshnetd SIGKILL recovery followed by the first controlled
interface-address change on the recovered service generation. A pass requires
coordinated helper/daemon recovery, endpoint refresh, synchronized dual-stack
traffic and DNS, stable service generations, and no additional service restart
during the network-change phase. The aggregate redacted JSON is written to
stdout.
EOF
}

fail() {
  printf 'linux-helper-recovery-change: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-helper-recovery-change: %s\n' "$*" >&2
}

cleanup() {
  set +e
  if [[ "${restore_services}" == true ]]; then
    systemctl start meshnetd.service meshd.service >/dev/null 2>&1
  fi
  if [[ -n "${temp_dir}" ]]; then
    rm -f -- "${temp_dir}/recovery.json" "${temp_dir}/network-change.json"
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

validate_positive_integer() {
  local label="$1"
  local value="$2"
  local maximum="$3"

  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]] || (( value > maximum )); then
    fail "${label} must be an integer between 1 and ${maximum}"
  fi
}

validate_interface() {
  local label="$1"
  local value="$2"

  if (( ${#value} > 15 )) || [[ ! "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
    fail "${label} is not a valid bounded Linux interface name"
  fi
}

unit_pid() {
  local unit="$1"
  local pid

  pid="$(systemctl show --property=MainPID --value "${unit}" 2>/dev/null || true)"
  if [[ "${pid}" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s\n' "${pid}"
    return
  fi
  printf '0\n'
}

unit_restart_count() {
  local unit="$1"
  local count

  count="$(systemctl show --property=NRestarts --value "${unit}" 2>/dev/null || true)"
  if [[ "${count}" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "${count}"
    return
  fi
  printf '0\n'
}

now_ns() {
  date +%s%N
}

elapsed_ms() {
  local start_ns="$1"
  local end_ns="$2"

  printf '%d\n' "$(( (end_ns - start_ns) / 1000000 ))"
}

valid_recovery_report() {
  local report_path="$1"

  jq -e \
    --arg schema "${recovery_schema}" '
      type == "object" and
      .schema == $schema and
      .scenario.action == "sigkill" and
      .scenario.service == "meshnetd.service" and
      .action.target_pid_changed == true and
      .action.meshd_pid_changed == true and
      .action.restart_count_increased == true and
      .readiness_ms.services_active != null and
      .readiness_ms.data_interface != null and
      .readiness_ms.daemon_online != null and
      .readiness_ms.magic_dns != null and
      .outcome == "pass" and
      (.failures | type == "array" and length == 0)
    ' "${report_path}" >/dev/null 2>&1
}

valid_change_report() {
  local report_path="$1"

  jq -e \
    --arg schema "${change_schema}" '
      type == "object" and
      .schema == $schema and
      .scenario.action == "controlled_interface_address_change" and
      .action.cleanup_ok == true and
      .recovery_ms.event_observed != null and
      .recovery_ms.endpoint_refresh != null and
      .recovery_ms.path_usable != null and
      .final.network_changes_observed > .baseline.network_changes_observed and
      .final.endpoint_refreshes > .baseline.endpoint_refreshes and
      .outcome == "pass" and
      (.failures | type == "array" and length == 0)
    ' "${report_path}" >/dev/null 2>&1
}

valid_report_pair() {
  local recovery_path="$1"
  local change_path="$2"

  valid_recovery_report "${recovery_path}" &&
    valid_change_report "${change_path}" &&
    jq -e -s '
      length == 2 and
      .[0].topology == .[1].topology and
      .[0].platform == .[1].platform and
      .[0].artifact == .[1].artifact
    ' "${recovery_path}" "${change_path}" >/dev/null 2>&1
}

main() {
  local node_label=""
  local peer_label=""
  local peer_v4=""
  local peer_v6=""
  local peer_name=""
  local confirmation=""
  local artifact_sha256=""
  local ready_timeout_seconds=20
  local network_timeout_seconds=20
  local data_interface=mesh0
  local dns_interface=meshdns0
  local change_interface=meshqchg0
  local command_name
  local started_at
  local recovery_path
  local change_path
  local recovery_exit_code=125
  local change_exit_code=125
  local recovery_report=null
  local change_report=null
  local recovery_report_valid=false
  local change_report_valid=false
  local report_pair_valid=false
  local recovery_end_ns=0
  local change_launch_ns=0
  local recovery_to_change_ms=null
  local recovered_meshd_pid=0
  local recovered_meshnetd_pid=0
  local final_meshd_pid=0
  local final_meshnetd_pid=0
  local recovered_meshd_restarts=0
  local recovered_meshnetd_restarts=0
  local final_meshd_restarts=0
  local final_meshnetd_restarts=0
  local meshd_generation_stable=false
  local meshnetd_generation_stable=false
  local meshd_restart_count_stable=false
  local meshnetd_restart_count_stable=false
  local network_change_executed=false
  local report
  local outcome

  while (( $# > 0 )); do
    case "$1" in
      --node-label)
        [[ $# -ge 2 ]] || fail "--node-label requires a value"
        node_label="$2"
        shift 2
        ;;
      --peer-label)
        [[ $# -ge 2 ]] || fail "--peer-label requires a value"
        peer_label="$2"
        shift 2
        ;;
      --peer-v4)
        [[ $# -ge 2 ]] || fail "--peer-v4 requires a value"
        peer_v4="$2"
        shift 2
        ;;
      --peer-v6)
        [[ $# -ge 2 ]] || fail "--peer-v6 requires a value"
        peer_v6="$2"
        shift 2
        ;;
      --peer-name)
        [[ $# -ge 2 ]] || fail "--peer-name requires a value"
        peer_name="$2"
        shift 2
        ;;
      --confirm-recovery-change)
        [[ $# -ge 2 ]] || fail "--confirm-recovery-change requires a value"
        confirmation="$2"
        shift 2
        ;;
      --artifact-sha256)
        [[ $# -ge 2 ]] || fail "--artifact-sha256 requires a value"
        artifact_sha256="$2"
        shift 2
        ;;
      --ready-timeout-seconds)
        [[ $# -ge 2 ]] || fail "--ready-timeout-seconds requires a value"
        ready_timeout_seconds="$2"
        shift 2
        ;;
      --network-timeout-seconds)
        [[ $# -ge 2 ]] || fail "--network-timeout-seconds requires a value"
        network_timeout_seconds="$2"
        shift 2
        ;;
      --data-interface)
        [[ $# -ge 2 ]] || fail "--data-interface requires a value"
        data_interface="$2"
        shift 2
        ;;
      --dns-interface)
        [[ $# -ge 2 ]] || fail "--dns-interface requires a value"
        dns_interface="$2"
        shift 2
        ;;
      --change-interface)
        [[ $# -ge 2 ]] || fail "--change-interface requires a value"
        change_interface="$2"
        shift 2
        ;;
      --help|-h)
        usage
        return 0
        ;;
      *) fail "unknown argument: $1" ;;
    esac
  done

  [[ "$(uname -s)" == Linux ]] || fail "this harness requires Linux"
  (( EUID == 0 )) || fail "run as root so helper recovery can be qualified"
  [[ -x "${recovery_harness}" ]] || fail "linux-restart.sh must be executable beside this harness"
  [[ -x "${change_harness}" ]] || fail "linux-network-change.sh must be executable beside this harness"
  [[ -n "${node_label}" ]] || fail "--node-label is required"
  [[ -n "${peer_label}" ]] || fail "--peer-label is required"
  [[ -n "${peer_v4}" ]] || fail "--peer-v4 is required"
  [[ -n "${peer_v6}" ]] || fail "--peer-v6 is required"
  [[ -n "${peer_name}" ]] || fail "--peer-name is required"
  [[ "${confirmation}" == "${node_label}" ]] ||
    fail "--confirm-recovery-change must exactly match --node-label"
  validate_positive_integer ready-timeout-seconds "${ready_timeout_seconds}" 300
  validate_positive_integer network-timeout-seconds "${network_timeout_seconds}" 60
  validate_interface data-interface "${data_interface}"
  validate_interface dns-interface "${dns_interface}"
  validate_interface change-interface "${change_interface}"
  [[ "${change_interface}" != "${data_interface}" ]] ||
    fail "change-interface must not be the data interface"
  [[ "${change_interface}" != "${dns_interface}" ]] ||
    fail "change-interface must not be the DNS interface"
  if [[ -n "${artifact_sha256}" && ! "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    fail "artifact-sha256 must contain exactly 64 hexadecimal characters"
  fi

  for command_name in date jq mktemp systemctl; do
    require_command "${command_name}"
  done

  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-helper-recovery-change.XXXXXXXX")"
  recovery_path="${temp_dir}/recovery.json"
  change_path="${temp_dir}/network-change.json"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  restore_services=true

  progress "running coordinated meshnetd SIGKILL recovery"
  if "${recovery_harness}" \
    --node-label "${node_label}" \
    --peer-label "${peer_label}" \
    --peer-v4 "${peer_v4}" \
    --peer-v6 "${peer_v6}" \
    --peer-name "${peer_name}" \
    --service meshnetd \
    --action sigkill \
    --artifact-sha256 "${artifact_sha256}" \
    --ready-timeout-seconds "${ready_timeout_seconds}" \
    --tail-seconds 1 \
    --data-interface "${data_interface}" \
    --dns-interface "${dns_interface}" >"${recovery_path}"; then
    recovery_exit_code=0
  else
    recovery_exit_code=$?
  fi
  recovery_end_ns="$(now_ns)"

  if valid_recovery_report "${recovery_path}"; then
    recovery_report_valid=true
    recovery_report="$(jq -c . "${recovery_path}")"
  elif jq -e 'type == "object"' "${recovery_path}" >/dev/null 2>&1; then
    recovery_report="$(jq -c . "${recovery_path}")"
  fi

  if (( recovery_exit_code == 0 )) && [[ "${recovery_report_valid}" == true ]]; then
    recovered_meshd_pid="$(unit_pid meshd.service)"
    recovered_meshnetd_pid="$(unit_pid meshnetd.service)"
    recovered_meshd_restarts="$(unit_restart_count meshd.service)"
    recovered_meshnetd_restarts="$(unit_restart_count meshnetd.service)"

    if [[ "${recovered_meshd_pid}" != 0 && "${recovered_meshnetd_pid}" != 0 ]]; then
      change_launch_ns="$(now_ns)"
      recovery_to_change_ms="$(elapsed_ms "${recovery_end_ns}" "${change_launch_ns}")"
      network_change_executed=true
      progress "recovery passed; launching the first controlled network change"
      if "${change_harness}" \
        --node-label "${node_label}" \
        --peer-label "${peer_label}" \
        --peer-v4 "${peer_v4}" \
        --peer-v6 "${peer_v6}" \
        --peer-name "${peer_name}" \
        --confirm-network-change "${node_label}" \
        --artifact-sha256 "${artifact_sha256}" \
        --lead-seconds 1 \
        --recovery-timeout-seconds "${network_timeout_seconds}" \
        --data-interface "${data_interface}" \
        --dns-interface "${dns_interface}" \
        --change-interface "${change_interface}" >"${change_path}"; then
        change_exit_code=0
      else
        change_exit_code=$?
      fi

      final_meshd_pid="$(unit_pid meshd.service)"
      final_meshnetd_pid="$(unit_pid meshnetd.service)"
      final_meshd_restarts="$(unit_restart_count meshd.service)"
      final_meshnetd_restarts="$(unit_restart_count meshnetd.service)"
      [[ "${recovered_meshd_pid}" == "${final_meshd_pid}" && "${final_meshd_pid}" != 0 ]] &&
        meshd_generation_stable=true
      [[ "${recovered_meshnetd_pid}" == "${final_meshnetd_pid}" && "${final_meshnetd_pid}" != 0 ]] &&
        meshnetd_generation_stable=true
      [[ "${recovered_meshd_restarts}" == "${final_meshd_restarts}" ]] &&
        meshd_restart_count_stable=true
      [[ "${recovered_meshnetd_restarts}" == "${final_meshnetd_restarts}" ]] &&
        meshnetd_restart_count_stable=true

      if valid_change_report "${change_path}"; then
        change_report_valid=true
        change_report="$(jq -c . "${change_path}")"
      elif jq -e 'type == "object"' "${change_path}" >/dev/null 2>&1; then
        change_report="$(jq -c . "${change_path}")"
      fi
      if valid_report_pair "${recovery_path}" "${change_path}"; then
        report_pair_valid=true
      fi
    fi
  fi

  report="$(jq -n \
    --arg schema "${schema_version}" \
    --arg started_at "${started_at}" \
    --arg node_label "${node_label}" \
    --arg peer_label "${peer_label}" \
    --argjson recovery_exit_code "${recovery_exit_code}" \
    --argjson change_exit_code "${change_exit_code}" \
    --argjson recovery_report_valid "${recovery_report_valid}" \
    --argjson change_report_valid "${change_report_valid}" \
    --argjson report_pair_valid "${report_pair_valid}" \
    --argjson network_change_executed "${network_change_executed}" \
    --argjson recovery_to_change_ms "${recovery_to_change_ms}" \
    --argjson meshd_generation_stable "${meshd_generation_stable}" \
    --argjson meshnetd_generation_stable "${meshnetd_generation_stable}" \
    --argjson meshd_restart_count_stable "${meshd_restart_count_stable}" \
    --argjson meshnetd_restart_count_stable "${meshnetd_restart_count_stable}" \
    --argjson recovery_report "${recovery_report}" \
    --argjson change_report "${change_report}" '
      {
        schema: $schema,
        started_at: $started_at,
        topology: {
          node_label: $node_label,
          peer_label: $peer_label,
          address_families: ["ipv4", "ipv6"]
        },
        artifact: ($recovery_report.artifact // $change_report.artifact // null),
        scenario: {
          first_action: "meshnetd_sigkill",
          first_post_recovery_action: "controlled_interface_address_change"
        },
        sequence: {
          recovery_harness_exit_code: $recovery_exit_code,
          recovery_report_valid: $recovery_report_valid,
          recovery_to_network_harness_ms: $recovery_to_change_ms,
          network_change_executed: $network_change_executed,
          network_change_harness_exit_code: $change_exit_code,
          network_change_report_valid: $change_report_valid,
          report_contract_match: $report_pair_valid
        },
        generation: {
          meshd_stable_during_network_change: $meshd_generation_stable,
          meshnetd_stable_during_network_change: $meshnetd_generation_stable,
          meshd_restart_count_stable: $meshd_restart_count_stable,
          meshnetd_restart_count_stable: $meshnetd_restart_count_stable
        },
        phases: {
          helper_recovery: $recovery_report,
          network_change: $change_report
        }
      }
      | .failures = [
          if .sequence.recovery_harness_exit_code != 0 then "helper_recovery_harness_failed" else empty end,
          if .sequence.recovery_report_valid != true then "helper_recovery_report_invalid" else empty end,
          if .sequence.network_change_executed != true then "network_change_not_executed" else empty end,
          if .sequence.network_change_harness_exit_code != 0 then "network_change_harness_failed" else empty end,
          if .sequence.network_change_report_valid != true then "network_change_report_invalid" else empty end,
          if .sequence.report_contract_match != true then "phase_report_contract_mismatch" else empty end,
          if .generation.meshd_stable_during_network_change != true then "meshd_generation_changed_during_network_change" else empty end,
          if .generation.meshnetd_stable_during_network_change != true then "meshnetd_generation_changed_during_network_change" else empty end,
          if .generation.meshd_restart_count_stable != true then "meshd_restart_count_increased_during_network_change" else empty end,
          if .generation.meshnetd_restart_count_stable != true then "meshnetd_restart_count_increased_during_network_change" else empty end
        ]
      | .outcome = if (.failures | length) == 0 then "pass" else "fail" end
    ')"

  printf '%s\n' "${report}"
  outcome="$(jq -r '.outcome' <<<"${report}")"
  if [[ "${outcome}" != pass ]]; then
    progress "qualification failed; inspect the JSON failure codes"
    return 2
  fi
  restore_services=false
  progress "qualification passed"
}

if [[ "${1:-}" == __validate-report-pair ]]; then
  [[ $# -eq 3 ]] || fail "__validate-report-pair requires two report paths"
  valid_report_pair "$2" "$3"
  exit
fi

main "$@"
