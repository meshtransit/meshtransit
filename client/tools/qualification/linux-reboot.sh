#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-reboot-qualification/v1"

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly ping_parser="${script_dir}/linux-restart.sh"

temp_dir=""
ping4_pid=""
ping6_pid=""
ssh_command=()

usage() {
  cat <<'EOF'
Usage:
  tools/qualification/linux-reboot.sh \
    --target-ssh USER@HOST \
    --observer-ssh USER@HOST \
    --target-label LABEL \
    --observer-label LABEL \
    --target-v4 ADDRESS \
    --target-v6 ADDRESS \
    --target-name MESH_DNS_NAME \
    --observer-v4 ADDRESS \
    --observer-v6 ADDRESS \
    --observer-name MESH_DNS_NAME \
    --artifact-sha256 HEX \
    --confirm-reboot TARGET_LABEL \
    [--ssh-driver ssh|rtk] \
    [--lead-seconds N] \
    [--recovery-timeout-seconds N] \
    [--tail-seconds N] \
    [--observation-seconds N] \
    [--ping-interval SECONDS] \
    [--poll-interval SECONDS] \
    [--ssh-connect-timeout-seconds N]

Runs from an operator host. It reboots exactly one Linux target while a second
healthy mesh node observes IPv4 and IPv6 traffic. The JSON report is written to
stdout; progress and errors are written to stderr. SSH destinations, overlay
addresses, DNS answers, boot IDs, profile IDs, control fingerprints, and raw
ping output are excluded from the report.
EOF
}

fail() {
  printf 'linux-reboot: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-reboot: %s\n' "$*" >&2
}

cleanup() {
  local path

  set +e
  if [[ -n "${ping4_pid}" ]]; then
    kill "${ping4_pid}" 2>/dev/null
    wait "${ping4_pid}" 2>/dev/null
  fi
  if [[ -n "${ping6_pid}" ]]; then
    kill "${ping6_pid}" 2>/dev/null
    wait "${ping6_pid}" 2>/dev/null
  fi
  if [[ -n "${temp_dir}" ]]; then
    for path in "${temp_dir}/ping-v4.log" "${temp_dir}/ping-v6.log"; do
      rm -f -- "${path}"
    done
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

configure_ssh_command() {
  local driver="$1"

  case "${driver}" in
    ssh)
      ssh_command=(ssh)
      ;;
    rtk)
      ssh_command=(rtk proxy ssh)
      ;;
    *)
      fail "ssh-driver must be ssh or rtk"
      ;;
  esac
}

validate_label() {
  local label="$1"
  local value="$2"

  if [[ ! "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]; then
    fail "${label} must be 1-64 safe label characters"
  fi
}

validate_ssh_destination() {
  local value="$1"

  if [[ ! "${value}" =~ ^[A-Za-z0-9_.-]+@[A-Za-z0-9_.:-]+$ ]]; then
    fail "SSH destinations must use USER@HOST without shell metacharacters"
  fi
}

validate_dns_name() {
  local value="$1"
  local dns_label
  local -a dns_labels

  if (( ${#value} > 253 )) || [[ "${value}" == *. ]]; then
    fail "MeshTransit DNS names must be bounded and must not end with a dot"
  fi
  IFS=. read -r -a dns_labels <<<"${value}"
  for dns_label in "${dns_labels[@]}"; do
    if (( ${#dns_label} == 0 || ${#dns_label} > 63 )) ||
      [[ ! "${dns_label}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]; then
      fail "MeshTransit DNS name contains an invalid label"
    fi
  done
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
    if (value !~ /^[0-9]+([.][0-9]+)?$/ || value < 0.2 || value > 5) {
      exit 1
    }
  }'; then
    fail "${label} must be between 0.2 and 5 seconds"
  fi
}

validate_overlay_addresses() {
  local ipv4="$1"
  local ipv6="$2"

  [[ "${ipv4}" =~ ^[0-9.]+$ ]] || fail "IPv4 values must contain only digits and dots"
  [[ "${ipv6}" =~ ^[0-9A-Fa-f:]+$ ]] ||
    fail "IPv6 values must not contain a zone or shell metacharacters"
}

now_ms() {
  python3 -c 'import time; print(time.time_ns() // 1000000)'
}

elapsed_ms() {
  local start_ms="$1"
  local end_ms="$2"

  printf '%d\n' $((end_ms - start_ms))
}

status_is_ready() {
  local status="$1"

  jq -e '
    .state == "online" and
    .control_session == "synchronized" and
    .dns == "configured" and
    .registration == "registered" and
    (.data_plane | type) == "string" and
    (.data_plane | startswith("encrypted_")) and
    .paths.available == true
  ' >/dev/null <<<"${status}"
}

main() {
  local target_ssh=""
  local observer_ssh=""
  local target_label=""
  local observer_label=""
  local target_v4=""
  local target_v6=""
  local target_name=""
  local observer_v4=""
  local observer_v6=""
  local observer_name=""
  local artifact_sha256=""
  local reboot_confirmation=""
  local ssh_driver=ssh
  local lead_seconds=3
  local recovery_timeout_seconds=60
  local tail_seconds=5
  local observation_seconds=75
  local ping_interval=0.2
  local poll_interval=1
  local ssh_connect_timeout_seconds=3
  local command_name
  local target_status
  local observer_status
  local post_status=""
  local previous_boot_id
  local current_boot_id=""
  local daemon_version
  local daemon_commit
  local baseline_profile_id
  local baseline_addresses
  local baseline_profile_count
  local baseline_direct_count
  local baseline_relay_count
  local post_profile_id=""
  local post_addresses=""
  local post_profile_count=""
  local profile_preserved=false
  local addresses_preserved=false
  local profile_count_preserved=false
  local runtime_preserved=false
  local kernel_release
  local machine_arch
  local started_at
  local action_start_ns
  local action_end_ns
  local action_start_ms
  local action_end_ms
  local action_duration_ms
  local reboot_exit_code=0
  local current_ms
  local deadline_ms
  local ssh_unreachable_observed=false
  local ssh_unreachable_ms=null
  local ssh_ready_ms=null
  local boot_id_changed_ms=null
  local service_ready_ms=null
  local tun_ready_ms=null
  local online_ready_ms=null
  local dns_ready_ms=null
  local outbound_ready_ms=null
  local ping4_exit_code=0
  local ping6_exit_code=0
  local ping4_parser_ok=true
  local ping6_parser_ok=true
  local ping4_metrics
  local ping6_metrics
  local ping4_transmitted=0
  local ping4_received=0
  local ping4_loss=100
  local ping4_first_ms=null
  local ping4_max_gap=0
  local ping4_missing_after=0
  local ping4_replies_after=0
  local ping4_stable_ms=null
  local ping4_trailing_run=0
  local ping6_transmitted=0
  local ping6_received=0
  local ping6_loss=100
  local ping6_first_ms=null
  local ping6_max_gap=0
  local ping6_missing_after=0
  local ping6_replies_after=0
  local ping6_stable_ms=null
  local ping6_trailing_run=0
  local report
  local outcome

  while (( $# > 0 )); do
    case "$1" in
      --target-ssh)
        [[ $# -ge 2 ]] || fail "--target-ssh requires a value"
        target_ssh="$2"
        shift 2
        ;;
      --observer-ssh)
        [[ $# -ge 2 ]] || fail "--observer-ssh requires a value"
        observer_ssh="$2"
        shift 2
        ;;
      --target-label)
        [[ $# -ge 2 ]] || fail "--target-label requires a value"
        target_label="$2"
        shift 2
        ;;
      --observer-label)
        [[ $# -ge 2 ]] || fail "--observer-label requires a value"
        observer_label="$2"
        shift 2
        ;;
      --target-v4)
        [[ $# -ge 2 ]] || fail "--target-v4 requires a value"
        target_v4="$2"
        shift 2
        ;;
      --target-v6)
        [[ $# -ge 2 ]] || fail "--target-v6 requires a value"
        target_v6="$2"
        shift 2
        ;;
      --target-name)
        [[ $# -ge 2 ]] || fail "--target-name requires a value"
        target_name="$2"
        shift 2
        ;;
      --observer-v4)
        [[ $# -ge 2 ]] || fail "--observer-v4 requires a value"
        observer_v4="$2"
        shift 2
        ;;
      --observer-v6)
        [[ $# -ge 2 ]] || fail "--observer-v6 requires a value"
        observer_v6="$2"
        shift 2
        ;;
      --observer-name)
        [[ $# -ge 2 ]] || fail "--observer-name requires a value"
        observer_name="$2"
        shift 2
        ;;
      --artifact-sha256)
        [[ $# -ge 2 ]] || fail "--artifact-sha256 requires a value"
        artifact_sha256="$2"
        shift 2
        ;;
      --confirm-reboot)
        [[ $# -ge 2 ]] || fail "--confirm-reboot requires a value"
        reboot_confirmation="$2"
        shift 2
        ;;
      --ssh-driver)
        [[ $# -ge 2 ]] || fail "--ssh-driver requires a value"
        ssh_driver="$2"
        shift 2
        ;;
      --lead-seconds)
        [[ $# -ge 2 ]] || fail "--lead-seconds requires a value"
        lead_seconds="$2"
        shift 2
        ;;
      --recovery-timeout-seconds)
        [[ $# -ge 2 ]] || fail "--recovery-timeout-seconds requires a value"
        recovery_timeout_seconds="$2"
        shift 2
        ;;
      --tail-seconds)
        [[ $# -ge 2 ]] || fail "--tail-seconds requires a value"
        tail_seconds="$2"
        shift 2
        ;;
      --observation-seconds)
        [[ $# -ge 2 ]] || fail "--observation-seconds requires a value"
        observation_seconds="$2"
        shift 2
        ;;
      --ping-interval)
        [[ $# -ge 2 ]] || fail "--ping-interval requires a value"
        ping_interval="$2"
        shift 2
        ;;
      --poll-interval)
        [[ $# -ge 2 ]] || fail "--poll-interval requires a value"
        poll_interval="$2"
        shift 2
        ;;
      --ssh-connect-timeout-seconds)
        [[ $# -ge 2 ]] || fail "--ssh-connect-timeout-seconds requires a value"
        ssh_connect_timeout_seconds="$2"
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

  [[ -n "${target_ssh}" ]] || fail "--target-ssh is required"
  [[ -n "${observer_ssh}" ]] || fail "--observer-ssh is required"
  [[ -n "${target_label}" ]] || fail "--target-label is required"
  [[ -n "${observer_label}" ]] || fail "--observer-label is required"
  [[ -n "${target_v4}" && -n "${target_v6}" ]] ||
    fail "--target-v4 and --target-v6 are required"
  [[ -n "${observer_v4}" && -n "${observer_v6}" ]] ||
    fail "--observer-v4 and --observer-v6 are required"
  [[ -n "${target_name}" && -n "${observer_name}" ]] ||
    fail "--target-name and --observer-name are required"
  [[ -n "${artifact_sha256}" ]] || fail "--artifact-sha256 is required"

  validate_ssh_destination "${target_ssh}"
  validate_ssh_destination "${observer_ssh}"
  [[ "${target_ssh}" != "${observer_ssh}" ]] || fail "target and observer must differ"
  validate_label target-label "${target_label}"
  validate_label observer-label "${observer_label}"
  [[ "${reboot_confirmation}" == "${target_label}" ]] ||
    fail "--confirm-reboot must exactly match --target-label"
  validate_overlay_addresses "${target_v4}" "${target_v6}"
  validate_overlay_addresses "${observer_v4}" "${observer_v6}"
  validate_dns_name "${target_name}"
  validate_dns_name "${observer_name}"
  [[ "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]] ||
    fail "artifact-sha256 must contain exactly 64 hexadecimal characters"
  validate_positive_integer lead-seconds "${lead_seconds}" 30
  validate_positive_integer recovery-timeout-seconds "${recovery_timeout_seconds}" 300
  validate_positive_integer tail-seconds "${tail_seconds}" 60
  validate_positive_integer observation-seconds "${observation_seconds}" 600
  validate_positive_integer ssh-connect-timeout-seconds "${ssh_connect_timeout_seconds}" 30
  validate_interval ping-interval "${ping_interval}"
  validate_interval poll-interval "${poll_interval}"
  if (( observation_seconds < lead_seconds + recovery_timeout_seconds + tail_seconds )); then
    fail "observation-seconds must cover lead, recovery timeout, and stability tail"
  fi

  for command_name in awk date grep jq mktemp python3 sleep uname; do
    require_command "${command_name}"
  done
  [[ -x "${ping_parser}" ]] || fail "linux restart parser is unavailable"

  configure_ssh_command "${ssh_driver}"
  require_command "${ssh_command[0]}"

  remote() {
    local destination="$1"
    local remote_command="$2"

    "${ssh_command[@]}" \
      -o BatchMode=yes \
      -o ConnectTimeout="${ssh_connect_timeout_seconds}" \
      -o ServerAliveInterval=2 \
      -o ServerAliveCountMax=2 \
      -o StrictHostKeyChecking=yes \
      "${destination}" \
      "${remote_command}"
  }

  remote_services_ready() {
    remote "$1" "systemctl is-active --quiet meshd.service meshnetd.service"
  }

  remote_routes_ready() {
    local destination="$1"
    local peer_v4="$2"
    local peer_v6="$3"

    remote "${destination}" \
      "ip link show dev mesh0 >/dev/null 2>&1 && ip -4 route get ${peer_v4} | grep -Fq ' dev mesh0 ' && ip -6 route get ${peer_v6} | grep -Fq ' dev mesh0 '"
  }

  remote_dns_ready() {
    local destination="$1"
    local peer_name="$2"
    local peer_v4="$3"
    local peer_v6="$4"

    remote "${destination}" \
      "ip link show dev meshdns0 >/dev/null 2>&1 && resolvectl query ${peer_name} | grep -Fq '${peer_v4}' && resolvectl query ${peer_name} | grep -Fq '${peer_v6}'"
  }

  remote_outbound_ready() {
    local destination="$1"
    local peer_v4="$2"
    local peer_v6="$3"

    remote "${destination}" \
      "ping -4 -n -c 3 -W 1 ${peer_v4} >/dev/null 2>&1 && ping -6 -n -c 3 -W 1 ${peer_v6} >/dev/null 2>&1"
  }

  progress "checking target and observer preflight"
  remote_services_ready "${target_ssh}" || fail "target services are not active"
  remote_services_ready "${observer_ssh}" || fail "observer services are not active"
  remote_routes_ready "${target_ssh}" "${observer_v4}" "${observer_v6}" ||
    fail "target mesh routes are not ready"
  remote_routes_ready "${observer_ssh}" "${target_v4}" "${target_v6}" ||
    fail "observer mesh routes are not ready"
  target_status="$(remote "${target_ssh}" "meshctl --timeout 3s --json status")" ||
    fail "target status is unavailable"
  observer_status="$(remote "${observer_ssh}" "meshctl --timeout 3s --json status")" ||
    fail "observer status is unavailable"
  status_is_ready "${target_status}" || fail "target is not ready before reboot"
  status_is_ready "${observer_status}" || fail "observer is not ready before reboot"
  remote_dns_ready "${target_ssh}" "${observer_name}" "${observer_v4}" "${observer_v6}" ||
    fail "target MeshTransit DNS preflight failed"
  remote_dns_ready "${observer_ssh}" "${target_name}" "${target_v4}" "${target_v6}" ||
    fail "observer MeshTransit DNS preflight failed"
  remote_outbound_ready "${target_ssh}" "${observer_v4}" "${observer_v6}" ||
    fail "target outbound traffic preflight failed"
  remote_outbound_ready "${observer_ssh}" "${target_v4}" "${target_v6}" ||
    fail "observer outbound traffic preflight failed"

  previous_boot_id="$(remote "${target_ssh}" "cat /proc/sys/kernel/random/boot_id")" ||
    fail "target boot ID is unavailable"
  [[ "${previous_boot_id}" =~ ^[0-9a-f-]{36}$ ]] || fail "target returned an invalid boot ID"
  daemon_version="$(jq -r '.daemon.version' <<<"${target_status}")"
  daemon_commit="$(jq -r '.daemon.commit' <<<"${target_status}")"
  baseline_profile_id="$(jq -r '.active_profile_id' <<<"${target_status}")"
  baseline_addresses="$(jq -c '.self_addresses | sort' <<<"${target_status}")"
  baseline_profile_count="$(jq -r '.profile_count' <<<"${target_status}")"
  baseline_direct_count="$(jq -r '.paths.direct_count // 0' <<<"${target_status}")"
  baseline_relay_count="$(jq -r '.paths.relay_count // 0' <<<"${target_status}")"
  kernel_release="$(remote "${target_ssh}" "uname -r")"
  machine_arch="$(remote "${target_ssh}" "uname -m")"

  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-linux-reboot.XXXXXXXX")"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  progress "preflight passed; starting observer traffic"
  remote "${observer_ssh}" \
    "ping -4 -D -O -n -i ${ping_interval} -W 1 -w ${observation_seconds} ${target_v4}" \
    >"${temp_dir}/ping-v4.log" 2>&1 &
  ping4_pid=$!
  remote "${observer_ssh}" \
    "ping -6 -D -O -n -i ${ping_interval} -W 1 -w ${observation_seconds} ${target_v6}" \
    >"${temp_dir}/ping-v6.log" 2>&1 &
  ping6_pid=$!

  sleep "${lead_seconds}"
  kill -0 "${ping4_pid}" 2>/dev/null || fail "IPv4 observer probe exited during lead"
  kill -0 "${ping6_pid}" 2>/dev/null || fail "IPv6 observer probe exited during lead"

  action_start_ns="$(remote "${observer_ssh}" "date +%s%N")" ||
    fail "observer timestamp is unavailable"
  [[ "${action_start_ns}" =~ ^[0-9]{19}$ ]] || fail "observer timestamp is invalid"
  action_start_ms="$(now_ms)"
  progress "rebooting ${target_label}"
  set +e
  remote "${target_ssh}" "systemctl reboot"
  reboot_exit_code=$?
  set -e
  action_end_ms="$(now_ms)"
  action_duration_ms="$(elapsed_ms "${action_start_ms}" "${action_end_ms}")"
  action_end_ns="$(remote "${observer_ssh}" "date +%s%N")" ||
    fail "observer end timestamp is unavailable"
  [[ "${action_end_ns}" =~ ^[0-9]{19}$ ]] || fail "observer end timestamp is invalid"
  deadline_ms=$((action_start_ms + recovery_timeout_seconds * 1000))

  while true; do
    current_ms="$(now_ms)"
    if (( current_ms > deadline_ms )); then
      break
    fi

    if current_boot_id="$(remote "${target_ssh}" "cat /proc/sys/kernel/random/boot_id" 2>/dev/null)"; then
      if [[ "${current_boot_id}" =~ ^[0-9a-f-]{36}$ &&
        "${current_boot_id}" != "${previous_boot_id}" ]]; then
        if [[ "${ssh_ready_ms}" == null ]]; then
          ssh_ready_ms="$(elapsed_ms "${action_start_ms}" "${current_ms}")"
        fi
        if [[ "${boot_id_changed_ms}" == null ]]; then
          boot_id_changed_ms="$(elapsed_ms "${action_start_ms}" "${current_ms}")"
        fi
      fi
    else
      if [[ "${ssh_unreachable_observed}" == false ]]; then
        ssh_unreachable_observed=true
        ssh_unreachable_ms="$(elapsed_ms "${action_start_ms}" "${current_ms}")"
      fi
    fi

    if [[ "${boot_id_changed_ms}" != null ]]; then
      if [[ "${service_ready_ms}" == null ]] && remote_services_ready "${target_ssh}"; then
        service_ready_ms="$(elapsed_ms "${action_start_ms}" "$(now_ms)")"
      fi
      if [[ "${tun_ready_ms}" == null ]] &&
        remote_routes_ready "${target_ssh}" "${observer_v4}" "${observer_v6}"; then
        tun_ready_ms="$(elapsed_ms "${action_start_ms}" "$(now_ms)")"
      fi
      if [[ "${online_ready_ms}" == null ]]; then
        post_status="$(remote "${target_ssh}" "meshctl --timeout 3s --json status" 2>/dev/null || true)"
        if [[ -n "${post_status}" ]] && status_is_ready "${post_status}"; then
          online_ready_ms="$(elapsed_ms "${action_start_ms}" "$(now_ms)")"
        fi
      fi
      if [[ "${dns_ready_ms}" == null ]] &&
        remote_dns_ready "${target_ssh}" "${observer_name}" "${observer_v4}" "${observer_v6}"; then
        dns_ready_ms="$(elapsed_ms "${action_start_ms}" "$(now_ms)")"
      fi
      if [[ "${outbound_ready_ms}" == null ]] &&
        remote_outbound_ready "${target_ssh}" "${observer_v4}" "${observer_v6}"; then
        outbound_ready_ms="$(elapsed_ms "${action_start_ms}" "$(now_ms)")"
      fi
    fi

    if [[ "${boot_id_changed_ms}" != null && "${service_ready_ms}" != null &&
      "${tun_ready_ms}" != null && "${online_ready_ms}" != null &&
      "${dns_ready_ms}" != null && "${outbound_ready_ms}" != null ]]; then
      break
    fi
    sleep "${poll_interval}"
  done

  if [[ -z "${post_status}" || "${online_ready_ms}" == null ]]; then
    post_status="$(remote "${target_ssh}" "meshctl --timeout 3s --json status" 2>/dev/null || true)"
  fi
  if [[ -n "${post_status}" ]] && status_is_ready "${post_status}"; then
    post_profile_id="$(jq -r '.active_profile_id' <<<"${post_status}")"
    post_addresses="$(jq -c '.self_addresses | sort' <<<"${post_status}")"
    post_profile_count="$(jq -r '.profile_count' <<<"${post_status}")"
    [[ "${post_profile_id}" == "${baseline_profile_id}" ]] && profile_preserved=true
    [[ "${post_addresses}" == "${baseline_addresses}" ]] && addresses_preserved=true
    [[ "${post_profile_count}" == "${baseline_profile_count}" ]] && profile_count_preserved=true
    if [[ "$(jq -r '.daemon.version' <<<"${post_status}")" == "${daemon_version}" &&
      "$(jq -r '.daemon.commit' <<<"${post_status}")" == "${daemon_commit}" ]]; then
      runtime_preserved=true
    fi
  fi

  progress "waiting for the bounded observer window"
  if wait "${ping4_pid}"; then
    ping4_exit_code=0
  else
    ping4_exit_code=$?
  fi
  ping4_pid=""
  if wait "${ping6_pid}"; then
    ping6_exit_code=0
  else
    ping6_exit_code=$?
  fi
  ping6_pid=""

  if ping4_metrics="$(
    "${ping_parser}" __parse-ping-log \
      "${temp_dir}/ping-v4.log" \
      "${action_start_ns}" \
      "${action_end_ns}"
  )"; then
    IFS=$'\t' read -r ping4_transmitted ping4_received ping4_loss ping4_first_ms \
      ping4_max_gap ping4_missing_after ping4_replies_after ping4_stable_ms \
      ping4_trailing_run <<<"${ping4_metrics}"
  else
    ping4_parser_ok=false
  fi
  if ping6_metrics="$(
    "${ping_parser}" __parse-ping-log \
      "${temp_dir}/ping-v6.log" \
      "${action_start_ns}" \
      "${action_end_ns}"
  )"; then
    IFS=$'\t' read -r ping6_transmitted ping6_received ping6_loss ping6_first_ms \
      ping6_max_gap ping6_missing_after ping6_replies_after ping6_stable_ms \
      ping6_trailing_run <<<"${ping6_metrics}"
  else
    ping6_parser_ok=false
  fi

  report="$(jq -n \
    --arg schema "${schema_version}" \
    --arg started_at "${started_at}" \
    --arg target_label "${target_label}" \
    --arg observer_label "${observer_label}" \
    --arg kernel_release "${kernel_release}" \
    --arg arch "${machine_arch}" \
    --arg daemon_version "${daemon_version}" \
    --arg daemon_commit "${daemon_commit}" \
    --arg artifact_sha256 "${artifact_sha256}" \
    --argjson lead_seconds "${lead_seconds}" \
    --argjson recovery_timeout_seconds "${recovery_timeout_seconds}" \
    --argjson tail_seconds "${tail_seconds}" \
    --argjson observation_seconds "${observation_seconds}" \
    --argjson ping_interval "${ping_interval}" \
    --argjson poll_interval "${poll_interval}" \
    --argjson baseline_direct_count "${baseline_direct_count}" \
    --argjson baseline_relay_count "${baseline_relay_count}" \
    --argjson reboot_exit_code "${reboot_exit_code}" \
    --argjson action_duration_ms "${action_duration_ms}" \
    --argjson ssh_unreachable_observed "${ssh_unreachable_observed}" \
    --argjson ssh_unreachable_ms "${ssh_unreachable_ms}" \
    --argjson ssh_ready_ms "${ssh_ready_ms}" \
    --argjson boot_id_changed_ms "${boot_id_changed_ms}" \
    --argjson service_ready_ms "${service_ready_ms}" \
    --argjson tun_ready_ms "${tun_ready_ms}" \
    --argjson online_ready_ms "${online_ready_ms}" \
    --argjson dns_ready_ms "${dns_ready_ms}" \
    --argjson outbound_ready_ms "${outbound_ready_ms}" \
    --argjson profile_preserved "${profile_preserved}" \
    --argjson addresses_preserved "${addresses_preserved}" \
    --argjson profile_count_preserved "${profile_count_preserved}" \
    --argjson runtime_preserved "${runtime_preserved}" \
    --argjson ping4_exit_code "${ping4_exit_code}" \
    --argjson ping4_parser_ok "${ping4_parser_ok}" \
    --argjson ping4_transmitted "${ping4_transmitted}" \
    --argjson ping4_received "${ping4_received}" \
    --argjson ping4_loss "${ping4_loss}" \
    --argjson ping4_first_ms "${ping4_first_ms}" \
    --argjson ping4_max_gap "${ping4_max_gap}" \
    --argjson ping4_missing_after "${ping4_missing_after}" \
    --argjson ping4_replies_after "${ping4_replies_after}" \
    --argjson ping4_stable_ms "${ping4_stable_ms}" \
    --argjson ping4_trailing_run "${ping4_trailing_run}" \
    --argjson ping6_exit_code "${ping6_exit_code}" \
    --argjson ping6_parser_ok "${ping6_parser_ok}" \
    --argjson ping6_transmitted "${ping6_transmitted}" \
    --argjson ping6_received "${ping6_received}" \
    --argjson ping6_loss "${ping6_loss}" \
    --argjson ping6_first_ms "${ping6_first_ms}" \
    --argjson ping6_max_gap "${ping6_max_gap}" \
    --argjson ping6_missing_after "${ping6_missing_after}" \
    --argjson ping6_replies_after "${ping6_replies_after}" \
    --argjson ping6_stable_ms "${ping6_stable_ms}" \
    --argjson ping6_trailing_run "${ping6_trailing_run}" '
      {
        schema: $schema,
        started_at: $started_at,
        topology: {
          target_label: $target_label,
          observer_label: $observer_label,
          address_families: ["ipv4", "ipv6"]
        },
        platform: {
          kernel_release: $kernel_release,
          architecture: $arch
        },
        artifact: {
          version: $daemon_version,
          commit: $daemon_commit,
          sha256: $artifact_sha256,
          evidence_complete: true
        },
        scenario: {
          action: "reboot",
          reboot_command_exit_code: $reboot_exit_code,
          reboot_command_duration_ms: $action_duration_ms
        },
        baseline: {
          direct_peer_count: $baseline_direct_count,
          relay_peer_count: $baseline_relay_count
        },
        observation: {
          lead_seconds: $lead_seconds,
          recovery_timeout_seconds: $recovery_timeout_seconds,
          tail_seconds: $tail_seconds,
          total_seconds: $observation_seconds,
          ping_interval_seconds: $ping_interval,
          readiness_poll_interval_seconds: $poll_interval
        },
        reboot_evidence: {
          ssh_unreachable_observed: $ssh_unreachable_observed,
          ssh_unreachable_ms: $ssh_unreachable_ms,
          ssh_ready_ms: $ssh_ready_ms,
          boot_id_changed: ($boot_id_changed_ms != null),
          boot_id_changed_ms: $boot_id_changed_ms
        },
        readiness_ms: {
          services_active: $service_ready_ms,
          data_interface_and_routes: $tun_ready_ms,
          daemon_online: $online_ready_ms,
          magic_dns: $dns_ready_ms,
          outbound_dual_stack: $outbound_ready_ms
        },
        persistence: {
          active_profile_preserved: $profile_preserved,
          profile_count_preserved: $profile_count_preserved,
          self_addresses_preserved: $addresses_preserved,
          runtime_artifact_preserved: $runtime_preserved
        },
        traffic: {
          ipv4: {
            command_exit_code: $ping4_exit_code,
            parser_ok: $ping4_parser_ok,
            transmitted: $ping4_transmitted,
            received: $ping4_received,
            loss_percent: $ping4_loss,
            first_reply_after_reboot_command_ms: $ping4_first_ms,
            maximum_consecutive_loss: $ping4_max_gap,
            missing_after_action: $ping4_missing_after,
            replies_after_action: $ping4_replies_after,
            stable_recovery_ms: $ping4_stable_ms,
            consecutive_replies_at_end: $ping4_trailing_run
          },
          ipv6: {
            command_exit_code: $ping6_exit_code,
            parser_ok: $ping6_parser_ok,
            transmitted: $ping6_transmitted,
            received: $ping6_received,
            loss_percent: $ping6_loss,
            first_reply_after_reboot_command_ms: $ping6_first_ms,
            maximum_consecutive_loss: $ping6_max_gap,
            missing_after_action: $ping6_missing_after,
            replies_after_action: $ping6_replies_after,
            stable_recovery_ms: $ping6_stable_ms,
            consecutive_replies_at_end: $ping6_trailing_run
          }
        }
      }
      | .failures = [
          if (.scenario.reboot_command_exit_code != 0 and .scenario.reboot_command_exit_code != 255) then "reboot_command_failed" else empty end,
          if .reboot_evidence.boot_id_changed != true then "boot_id_did_not_change" else empty end,
          if .readiness_ms.services_active == null then "services_not_ready" else empty end,
          if .readiness_ms.data_interface_and_routes == null then "data_interface_not_ready" else empty end,
          if .readiness_ms.daemon_online == null then "daemon_not_ready" else empty end,
          if .readiness_ms.magic_dns == null then "magic_dns_not_ready" else empty end,
          if .readiness_ms.outbound_dual_stack == null then "outbound_traffic_not_ready" else empty end,
          if .persistence.active_profile_preserved != true then "active_profile_changed" else empty end,
          if .persistence.profile_count_preserved != true then "profile_count_changed" else empty end,
          if .persistence.self_addresses_preserved != true then "self_addresses_changed" else empty end,
          if .persistence.runtime_artifact_preserved != true then "runtime_artifact_changed" else empty end,
          if .traffic.ipv4.parser_ok != true then "ipv4_probe_unparseable" else empty end,
          if .traffic.ipv6.parser_ok != true then "ipv6_probe_unparseable" else empty end,
          if .traffic.ipv4.stable_recovery_ms == null then "ipv4_did_not_stabilize" else empty end,
          if .traffic.ipv6.stable_recovery_ms == null then "ipv6_did_not_stabilize" else empty end,
          if .traffic.ipv4.stable_recovery_ms != null and .traffic.ipv4.stable_recovery_ms > (.observation.recovery_timeout_seconds * 1000) then "ipv4_stable_recovery_timeout" else empty end,
          if .traffic.ipv6.stable_recovery_ms != null and .traffic.ipv6.stable_recovery_ms > (.observation.recovery_timeout_seconds * 1000) then "ipv6_stable_recovery_timeout" else empty end
        ]
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

if [[ "${1:-}" == __validate-ssh-destination ]]; then
  [[ $# -eq 2 ]] || fail "__validate-ssh-destination requires one value"
  validate_ssh_destination "$2"
  exit
fi

if [[ "${1:-}" == __now-ms ]]; then
  [[ $# -eq 1 ]] || fail "__now-ms does not accept arguments"
  now_ms
  exit
fi

if [[ "${1:-}" == __ssh-driver-command ]]; then
  [[ $# -eq 2 ]] || fail "__ssh-driver-command requires one value"
  configure_ssh_command "$2"
  printf '%s\n' "${ssh_command[*]}"
  exit
fi

main "$@"
