#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-runtime-recovery-qualification/v1"
readonly helper_socket="/run/meshnetd/meshnetd.sock"
readonly api_socket="/run/meshd/meshd.sock"

original_helper_mode=""
restore_helper_mode=false
restore_services=false

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-runtime-recovery.sh \
    --node-label LABEL \
    --confirm-helper-socket-fault LABEL \
    [--artifact-sha256 HEX] \
    [--recovery-timeout-seconds N] \
    [--poll-interval SECONDS] \
    [--data-interface NAME] \
    [--dns-interface NAME]

Runs a bounded, reversible local-runtime recovery fault. The harness starts a
fresh meshd generation while its fixed privileged-helper socket temporarily
has mode 000, proves that the daemon reports a pending runtime failure, restores
the package mode, and requires the same process generation to synchronize TUN
and DNS successfully. It does not change profile, identity, policy, control, or
default-route state. Aggregate redacted JSON is written to stdout.
EOF
}

fail() {
  printf 'linux-runtime-recovery: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-runtime-recovery: %s\n' "$*" >&2
}

cleanup() {
  set +e
  if [[ "${restore_services}" == true ]]; then
    systemctl start meshnetd.service >/dev/null 2>&1
  fi
  if [[ "${restore_helper_mode}" == true && -S "${helper_socket}" &&
    -n "${original_helper_mode}" ]]; then
    chmod "${original_helper_mode}" "${helper_socket}" >/dev/null 2>&1
  fi
  if [[ "${restore_services}" == true ]]; then
    systemctl start meshd.service >/dev/null 2>&1
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

validate_interface() {
  local label="$1"
  local value="$2"

  if [[ ! "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ ]]; then
    fail "${label} is not a valid bounded Linux interface name"
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

now_ns() {
  local value

  value="$(date +%s%N)"
  [[ "${value}" =~ ^[0-9]{19}$ ]] ||
    fail "date does not provide nanosecond epoch timestamps"
  printf '%s\n' "${value}"
}

elapsed_ms() {
  local start_ns="$1"
  local end_ns="$2"

  printf '%d\n' "$(( (end_ns - start_ns + 500000) / 1000000 ))"
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

read_status() {
  curl --fail --silent --show-error --max-time 2 \
    --unix-socket "${api_socket}" http://localhost/v1/status 2>/dev/null || true
}

status_has_recovery_contract() {
  local status="$1"

  jq -e '
    .api_version == "v1" and
    (.runtime_recovery.failures | type) == "number" and
    (.runtime_recovery.recoveries | type) == "number" and
    (.runtime_recovery.pending | type) == "boolean"
  ' >/dev/null 2>&1 <<<"${status}"
}

status_is_baseline_ready() {
  local status="$1"

  jq -e '
    .state == "online" and
    .control_session == "synchronized" and
    .dns == "configured" and
    (.data_plane | type) == "string" and
    .data_plane != "failed"
  ' >/dev/null 2>&1 <<<"${status}"
}

status_has_pending_failure() {
  local status="$1"

  jq -e '
    .control_session == "connecting" and
    .runtime_recovery.failures >= 1 and
    .runtime_recovery.recoveries == 0 and
    .runtime_recovery.pending == true
  ' >/dev/null 2>&1 <<<"${status}"
}

status_is_recovered() {
  local status="$1"

  jq -e '
    .state == "online" and
    .control_session == "synchronized" and
    .dns == "configured" and
    (.data_plane | type) == "string" and
    .data_plane != "failed" and
    .runtime_recovery.failures >= 1 and
    .runtime_recovery.recoveries >= 1 and
    .runtime_recovery.pending == false
  ' >/dev/null 2>&1 <<<"${status}"
}

valid_report() {
  local report_path="$1"

  jq -e --arg schema "${schema_version}" '
    type == "object" and
    .schema == $schema and
    .scenario.action == "helper_socket_permission_fault_at_startup" and
    .fault.helper_socket_mode_removed == true and
    .fault.runtime_failure_observed == true and
    .fault.pending_observed == true and
    .fault.service_start_exit_code == 0 and
    .recovery_ms.failure_observed != null and
    .recovery_ms.synchronized != null and
    .generation.meshd_pid_stable == true and
    .generation.meshnetd_pid_stable == true and
    .generation.meshd_restart_count_stable == true and
    .generation.meshnetd_restart_count_stable == true and
    .final.services_active == true and
    .final.helper_socket_mode_restored == true and
    .final.data_interface_present == true and
    .final.dns_interface_present == true and
    .final.control_session == "synchronized" and
    .final.dns == "configured" and
    .final.runtime_recovery.failures >= 1 and
    .final.runtime_recovery.recoveries >= 1 and
    .final.runtime_recovery.pending == false and
    .outcome == "pass" and
    (.failures | type == "array" and length == 0)
  ' "${report_path}" >/dev/null 2>&1
}

main() {
  local node_label=""
  local confirmation=""
  local artifact_sha256=""
  local recovery_timeout_seconds=30
  local poll_interval=0.1
  local data_interface=mesh0
  local dns_interface=meshdns0
  local command_name
  local baseline_status
  local daemon_version
  local daemon_commit
  local started_at
  local kernel_release
  local machine_arch
  local initial_meshd_pid
  local action_start_ns
  local action_exit_code=0
  local deadline_ns
  local current_ns
  local current_status=""
  local failure_observed_ns=""
  local recovered_ns=""
  local failure_observed_ms=null
  local synchronized_ms=null
  local fault_meshd_pid=0
  local fault_meshnetd_pid=0
  local fault_meshd_restarts=0
  local fault_meshnetd_restarts=0
  local final_meshd_pid=0
  local final_meshnetd_pid=0
  local final_meshd_restarts=0
  local final_meshnetd_restarts=0
  local meshd_pid_stable=false
  local meshnetd_pid_stable=false
  local meshd_restarts_stable=false
  local meshnetd_restarts_stable=false
  local helper_mode_restored=false
  local services_active=false
  local data_interface_present=false
  local dns_interface_present=false
  local runtime_failure_observed=false
  local pending_observed=false
  local final_failures=0
  local final_recoveries=0
  local final_pending=true
  local final_control_session="unavailable"
  local final_data_plane="unavailable"
  local final_dns="unavailable"
  local artifact_digest_json=null
  local report
  local outcome

  while (( $# > 0 )); do
    case "$1" in
      --node-label)
        [[ $# -ge 2 ]] || fail "--node-label requires a value"
        node_label="$2"
        shift 2
        ;;
      --confirm-helper-socket-fault)
        [[ $# -ge 2 ]] || fail "--confirm-helper-socket-fault requires a value"
        confirmation="$2"
        shift 2
        ;;
      --artifact-sha256)
        [[ $# -ge 2 ]] || fail "--artifact-sha256 requires a value"
        artifact_sha256="$2"
        shift 2
        ;;
      --recovery-timeout-seconds)
        [[ $# -ge 2 ]] || fail "--recovery-timeout-seconds requires a value"
        recovery_timeout_seconds="$2"
        shift 2
        ;;
      --poll-interval)
        [[ $# -ge 2 ]] || fail "--poll-interval requires a value"
        poll_interval="$2"
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
      --help|-h)
        usage
        return 0
        ;;
      *)
        fail "unknown argument: $1"
        ;;
    esac
  done

  [[ "$(uname -s)" == Linux ]] || fail "this harness requires Linux"
  (( EUID == 0 )) || fail "run as root so the helper socket mode can be restored"
  [[ -n "${node_label}" ]] || fail "--node-label is required"
  [[ "${confirmation}" == "${node_label}" ]] ||
    fail "--confirm-helper-socket-fault must exactly match --node-label"
  validate_label node-label "${node_label}"
  validate_interface data-interface "${data_interface}"
  validate_interface dns-interface "${dns_interface}"
  validate_positive_integer recovery-timeout-seconds "${recovery_timeout_seconds}" 120
  validate_interval poll-interval "${poll_interval}"
  if [[ -n "${artifact_sha256}" && ! "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    fail "artifact-sha256 must contain exactly 64 hexadecimal characters"
  fi

  for command_name in awk chmod curl date ip jq sleep stat systemctl uname; do
    require_command "${command_name}"
  done
  systemctl is-active --quiet meshd.service meshnetd.service ||
    fail "meshd.service and meshnetd.service must both be active"
  [[ -S "${helper_socket}" ]] || fail "packaged helper socket is not present"
  [[ "$(stat -c %U "${helper_socket}")" == root ]] ||
    fail "helper socket owner is not root"
  [[ "$(stat -c %G "${helper_socket}")" == meshd ]] ||
    fail "helper socket group is not meshd"
  original_helper_mode="$(stat -c %a "${helper_socket}")"
  [[ "${original_helper_mode}" == 660 ]] ||
    fail "helper socket mode is not the packaged 660 baseline"
  ip link show dev "${data_interface}" >/dev/null 2>&1 ||
    fail "data interface ${data_interface} is not present"
  ip link show dev "${dns_interface}" >/dev/null 2>&1 ||
    fail "DNS interface ${dns_interface} is not present"

  baseline_status="$(read_status)"
  status_has_recovery_contract "${baseline_status}" ||
    fail "daemon status does not expose the runtime recovery contract"
  status_is_baseline_ready "${baseline_status}" ||
    fail "baseline daemon status is not synchronized with DNS configured"
  daemon_version="$(jq -r '.daemon.version' <<<"${baseline_status}")"
  daemon_commit="$(jq -r '.daemon.commit' <<<"${baseline_status}")"
  initial_meshd_pid="$(unit_pid meshd.service)"
  [[ "${initial_meshd_pid}" != 0 ]] || fail "baseline meshd PID is unavailable"

  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  kernel_release="$(uname -r)"
  machine_arch="$(uname -m)"
  if [[ -n "${artifact_sha256}" ]]; then
    artifact_digest_json="$(jq -Rn --arg value "${artifact_sha256}" '$value')"
  fi

  restore_services=true
  progress "stopping the baseline daemon generation"
  systemctl stop meshd.service
  systemctl start meshnetd.service
  [[ -S "${helper_socket}" ]] || fail "helper socket was not recreated"
  original_helper_mode="$(stat -c %a "${helper_socket}")"
  [[ "${original_helper_mode}" == 660 ]] ||
    fail "recreated helper socket mode is not 660"

  chmod 000 "${helper_socket}"
  restore_helper_mode=true
  [[ "$(stat -c %a "${helper_socket}")" == 0 ]] ||
    fail "helper socket mode fault was not installed"
  action_start_ns="$(now_ns)"
  progress "starting meshd with the bounded helper socket permission fault"
  if systemctl start meshd.service; then
    action_exit_code=0
  else
    action_exit_code=$?
  fi
  fault_meshd_pid="$(unit_pid meshd.service)"
  fault_meshnetd_pid="$(unit_pid meshnetd.service)"
  fault_meshd_restarts="$(unit_restart_count meshd.service)"
  fault_meshnetd_restarts="$(unit_restart_count meshnetd.service)"
  deadline_ns=$(( action_start_ns + recovery_timeout_seconds * 1000000000 ))

  while true; do
    current_ns="$(now_ns)"
    current_status="$(read_status)"
    if [[ -n "${current_status}" ]] && status_has_pending_failure "${current_status}"; then
      failure_observed_ns="${current_ns}"
      runtime_failure_observed=true
      pending_observed=true
      break
    fi
    if (( current_ns >= deadline_ns )); then
      break
    fi
    sleep "${poll_interval}"
  done
  if [[ -n "${failure_observed_ns}" ]]; then
    failure_observed_ms="$(elapsed_ms "${action_start_ns}" "${failure_observed_ns}")"
  fi

  progress "restoring helper socket mode"
  if chmod "${original_helper_mode}" "${helper_socket}" &&
    [[ "$(stat -c %a "${helper_socket}")" == "${original_helper_mode}" ]]; then
    restore_helper_mode=false
    helper_mode_restored=true
  fi

  while true; do
    current_ns="$(now_ns)"
    current_status="$(read_status)"
    if [[ -n "${current_status}" ]] && status_is_recovered "${current_status}" &&
      ip link show dev "${data_interface}" >/dev/null 2>&1 &&
      ip link show dev "${dns_interface}" >/dev/null 2>&1; then
      recovered_ns="${current_ns}"
      break
    fi
    if (( current_ns >= deadline_ns )); then
      break
    fi
    sleep "${poll_interval}"
  done
  if [[ -n "${recovered_ns}" ]]; then
    synchronized_ms="$(elapsed_ms "${action_start_ns}" "${recovered_ns}")"
  fi

  final_meshd_pid="$(unit_pid meshd.service)"
  final_meshnetd_pid="$(unit_pid meshnetd.service)"
  final_meshd_restarts="$(unit_restart_count meshd.service)"
  final_meshnetd_restarts="$(unit_restart_count meshnetd.service)"
  [[ "${fault_meshd_pid}" != 0 && "${final_meshd_pid}" == "${fault_meshd_pid}" ]] &&
    meshd_pid_stable=true
  [[ "${fault_meshnetd_pid}" != 0 && "${final_meshnetd_pid}" == "${fault_meshnetd_pid}" ]] &&
    meshnetd_pid_stable=true
  [[ "${final_meshd_restarts}" == "${fault_meshd_restarts}" ]] &&
    meshd_restarts_stable=true
  [[ "${final_meshnetd_restarts}" == "${fault_meshnetd_restarts}" ]] &&
    meshnetd_restarts_stable=true
  if systemctl is-active --quiet meshd.service meshnetd.service; then
    services_active=true
  fi
  if ip link show dev "${data_interface}" >/dev/null 2>&1; then
    data_interface_present=true
  fi
  if ip link show dev "${dns_interface}" >/dev/null 2>&1; then
    dns_interface_present=true
  fi
  if [[ -n "${current_status}" ]] && status_has_recovery_contract "${current_status}"; then
    final_failures="$(jq -r '.runtime_recovery.failures' <<<"${current_status}")"
    final_recoveries="$(jq -r '.runtime_recovery.recoveries' <<<"${current_status}")"
    final_pending="$(jq -r '.runtime_recovery.pending' <<<"${current_status}")"
    final_control_session="$(jq -r '.control_session' <<<"${current_status}")"
    final_data_plane="$(jq -r '.data_plane' <<<"${current_status}")"
    final_dns="$(jq -r '.dns' <<<"${current_status}")"
  fi

  report="$(jq -n \
    --arg schema "${schema_version}" \
    --arg started_at "${started_at}" \
    --arg node_label "${node_label}" \
    --arg kernel_release "${kernel_release}" \
    --arg architecture "${machine_arch}" \
    --arg version "${daemon_version}" \
    --arg commit "${daemon_commit}" \
    --argjson sha256 "${artifact_digest_json}" \
    --argjson evidence_complete "$([[ -n "${artifact_sha256}" ]] && printf true || printf false)" \
    --argjson service_start_exit_code "${action_exit_code}" \
    --argjson runtime_failure_observed "${runtime_failure_observed}" \
    --argjson pending_observed "${pending_observed}" \
    --argjson failure_observed_ms "${failure_observed_ms}" \
    --argjson synchronized_ms "${synchronized_ms}" \
    --argjson meshd_pid_stable "${meshd_pid_stable}" \
    --argjson meshnetd_pid_stable "${meshnetd_pid_stable}" \
    --argjson meshd_restarts_stable "${meshd_restarts_stable}" \
    --argjson meshnetd_restarts_stable "${meshnetd_restarts_stable}" \
    --argjson services_active "${services_active}" \
    --argjson helper_mode_restored "${helper_mode_restored}" \
    --argjson data_interface_present "${data_interface_present}" \
    --argjson dns_interface_present "${dns_interface_present}" \
    --arg control_session "${final_control_session}" \
    --arg data_plane "${final_data_plane}" \
    --arg dns "${final_dns}" \
    --argjson runtime_failures "${final_failures}" \
    --argjson runtime_recoveries "${final_recoveries}" \
    --argjson runtime_pending "${final_pending}" '
      {
        schema: $schema,
        started_at: $started_at,
        topology: {node_label: $node_label},
        platform: {
          kernel_release: $kernel_release,
          architecture: $architecture
        },
        artifact: {
          version: $version,
          commit: $commit,
          sha256: $sha256,
          evidence_complete: $evidence_complete
        },
        scenario: {action: "helper_socket_permission_fault_at_startup"},
        fault: {
          helper_socket_mode_removed: true,
          service_start_exit_code: $service_start_exit_code,
          runtime_failure_observed: $runtime_failure_observed,
          pending_observed: $pending_observed
        },
        recovery_ms: {
          failure_observed: $failure_observed_ms,
          synchronized: $synchronized_ms
        },
        generation: {
          meshd_pid_stable: $meshd_pid_stable,
          meshnetd_pid_stable: $meshnetd_pid_stable,
          meshd_restart_count_stable: $meshd_restarts_stable,
          meshnetd_restart_count_stable: $meshnetd_restarts_stable
        },
        final: {
          services_active: $services_active,
          helper_socket_mode_restored: $helper_mode_restored,
          data_interface_present: $data_interface_present,
          dns_interface_present: $dns_interface_present,
          control_session: $control_session,
          data_plane: $data_plane,
          dns: $dns,
          runtime_recovery: {
            failures: $runtime_failures,
            recoveries: $runtime_recoveries,
            pending: $runtime_pending
          }
        }
      }
      | .failures = [
          if .fault.service_start_exit_code != 0 then "meshd_start_failed" else empty end,
          if .fault.runtime_failure_observed != true then "runtime_failure_not_observed" else empty end,
          if .fault.pending_observed != true then "runtime_pending_state_not_observed" else empty end,
          if .recovery_ms.synchronized == null then "runtime_recovery_timed_out" else empty end,
          if .generation.meshd_pid_stable != true then "meshd_generation_changed" else empty end,
          if .generation.meshnetd_pid_stable != true then "meshnetd_generation_changed" else empty end,
          if .generation.meshd_restart_count_stable != true then "meshd_restart_count_increased" else empty end,
          if .generation.meshnetd_restart_count_stable != true then "meshnetd_restart_count_increased" else empty end,
          if .final.services_active != true then "services_not_active" else empty end,
          if .final.helper_socket_mode_restored != true then "helper_socket_mode_not_restored" else empty end,
          if .final.data_interface_present != true then "data_interface_not_restored" else empty end,
          if .final.dns_interface_present != true then "dns_interface_not_restored" else empty end,
          if .final.control_session != "synchronized" then "control_not_synchronized" else empty end,
          if .final.dns != "configured" then "dns_not_configured" else empty end,
          if .final.runtime_recovery.failures < 1 then "runtime_failure_counter_not_advanced" else empty end,
          if .final.runtime_recovery.recoveries < 1 then "runtime_recovery_counter_not_advanced" else empty end,
          if .final.runtime_recovery.pending != false then "runtime_recovery_still_pending" else empty end
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

case "${1:-}" in
  __validate-label)
    [[ $# -eq 2 ]] || fail "__validate-label requires one value"
    validate_label label "$2"
    ;;
  __validate-report)
    [[ $# -eq 2 ]] || fail "__validate-report requires one report path"
    valid_report "$2"
    ;;
  *)
    main "$@"
    ;;
esac
