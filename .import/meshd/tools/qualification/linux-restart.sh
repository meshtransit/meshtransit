#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly restart_schema_version="meshtransit.linux-restart-qualification/v1"
readonly crash_schema_version="meshtransit.linux-crash-recovery-qualification/v1"
readonly minimum_post_action_replies=3
readonly dns_resolver_address="192.0.2.53"
readonly dns_resolver_port="1053"

temp_dir=""
ping4_pid=""
ping6_pid=""
restore_services=false

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-restart.sh \
    --node-label LABEL \
    --peer-label LABEL \
    --peer-v4 ADDRESS \
    --peer-v6 ADDRESS \
    --peer-name MAGICDNS_NAME \
    --service meshd|meshnetd \
    [--action restart|sigkill] \
    [--artifact-sha256 HEX] \
    [--lead-seconds N] \
    [--ready-timeout-seconds N] \
    [--tail-seconds N] \
    [--ping-interval SECONDS] \
    [--poll-interval SECONDS] \
    [--data-interface NAME] \
    [--dns-interface NAME]

Runs a bounded restart or SIGKILL recovery qualification on the current Linux
node. SIGKILL of meshd additionally requires observation of the non-persistent
DNS link, listeners, and systemd-resolved state being removed before recovery.
The JSON report is written to stdout; progress and errors are written to stderr.
Peer addresses, DNS answers, control fingerprints, and raw ping output are not
included in the report.
EOF
}

fail() {
  printf 'linux-restart: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-restart: %s\n' "$*" >&2
}

cleanup() {
  local path

  set +e
  if [[ "${restore_services}" == true ]]; then
    systemctl start meshnetd.service meshd.service >/dev/null 2>&1
  fi
  if [[ -n "${ping4_pid}" ]]; then
    kill "${ping4_pid}" 2>/dev/null
    wait "${ping4_pid}" 2>/dev/null
  fi
  if [[ -n "${ping6_pid}" ]]; then
    kill "${ping6_pid}" 2>/dev/null
    wait "${ping6_pid}" 2>/dev/null
  fi
  if [[ -n "${temp_dir}" ]]; then
    for path in \
      "${temp_dir}/ping-v4.log" \
      "${temp_dir}/ping-v6.log"; do
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

validate_label() {
  local label="$1"
  local value="$2"

  if [[ ! "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]; then
    fail "${label} must be 1-64 safe label characters"
  fi
}

validate_dns_name() {
  local value="$1"
  local dns_label
  local -a dns_labels

  if (( ${#value} > 253 )) || [[ "${value}" == *. ]]; then
    fail "peer-name must be a bounded DNS name"
  fi
  IFS=. read -r -a dns_labels <<<"${value}"
  for dns_label in "${dns_labels[@]}"; do
    if (( ${#dns_label} == 0 || ${#dns_label} > 63 )) ||
      [[ ! "${dns_label}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]; then
      fail "peer-name contains an invalid DNS label"
    fi
  done
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
    if (value !~ /^[0-9]+([.][0-9]+)?$/ || value < 0.1 || value > 2) {
      exit 1
    }
  }'; then
    fail "${label} must be between 0.1 and 2 seconds"
  fi
}

validate_action_mode() {
  case "$1" in
    restart|sigkill) return 0 ;;
    *) return 1 ;;
  esac
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
  local delta_ns

  delta_ns=$(( end_ns - start_ns ))
  printf '%d\n' $(( (delta_ns + 500000) / 1000000 ))
}

epoch_ns_to_seconds() {
  local value="$1"
  local whole_length

  whole_length=$(( ${#value} - 9 ))
  printf '%s.%s\n' "${value:0:whole_length}" "${value:whole_length:9}"
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

unit_invocation_id() {
  local unit="$1"
  local invocation_id

  invocation_id="$(systemctl show --property=InvocationID --value "${unit}" 2>/dev/null || true)"
  if [[ "${invocation_id}" =~ ^[0-9A-Fa-f]{32}$ ]]; then
    printf '%s\n' "${invocation_id}"
  fi
}

unit_restart_policy() {
  local unit="$1"

  systemctl show --property=Restart --value "${unit}" 2>/dev/null || true
}

restart_policy_supports_sigkill() {
  case "$1" in
    always|on-abnormal|on-abort|on-failure) return 0 ;;
    *) return 1 ;;
  esac
}

invocation_changed() {
  local before="$1"
  local after="$2"

  [[ "${before}" =~ ^[0-9A-Fa-f]{32}$ ]] || return 1
  [[ "${after}" =~ ^[0-9A-Fa-f]{32}$ ]] || return 1
  [[ "${before}" != "${after}" ]]
}

restart_count_evidence() {
  local baseline="$1"
  local sample
  local peak
  local increased=false

  shift
  [[ "${baseline}" =~ ^[0-9]+$ ]] || return 1
  peak="${baseline}"
  for sample in "$@"; do
    [[ "${sample}" =~ ^[0-9]+$ ]] || return 1
    if (( sample > peak )); then
      peak="${sample}"
    fi
  done
  if (( peak > baseline )); then
    increased=true
  fi
  printf '%s\t%s\n' "${peak}" "${increased}"
}

dns_runtime_removed() {
  local dns_interface="$1"
  local resolved_state

  ip link show dev "${dns_interface}" >/dev/null 2>&1 && return 1
  ss -H -lnu "sport = :${dns_resolver_port}" 2>/dev/null |
    grep -Fq -- "${dns_resolver_address}:${dns_resolver_port}" && return 1
  ss -H -lnt "sport = :${dns_resolver_port}" 2>/dev/null |
    grep -Fq -- "${dns_resolver_address}:${dns_resolver_port}" && return 1
  resolved_state="$(resolvectl status "${dns_interface}" --no-pager 2>&1 || true)"
  ! awk -v expected="(${dns_interface})" '
    $1 == "Link" && $3 == expected { found = 1 }
    END { exit found ? 0 : 1 }
  ' <<<"${resolved_state}"
}

route_uses_interface() {
  local family="$1"
  local address="$2"
  local interface_name="$3"
  local route

  route="$(ip "-${family}" route get "${address}" 2>/dev/null)" || return 1
  awk -v expected="${interface_name}" '{
    for (field_index = 1; field_index < NF; field_index++) {
      if ($field_index == "dev" && $(field_index + 1) == expected) {
        found = 1
      }
    }
    exit found ? 0 : 1
  }' <<<"${route}"
}

status_is_ready() {
  local status="$1"

  jq -e '
    .state == "online" and
    .control_session == "synchronized" and
    (.data_plane | type) == "string" and
    (.data_plane | startswith("encrypted_")) and
    .paths.available == true
  ' >/dev/null <<<"${status}"
}

dns_is_ready() {
  local peer_name="$1"
  local peer_v4="$2"
  local peer_v6="$3"
  local dns_output

  dns_output="$(timeout 2s resolvectl query "${peer_name}" 2>/dev/null)" || return 1
  grep -Fq -- "${peer_v4}" <<<"${dns_output}" || return 1
  grep -Fq -- "${peer_v6}" <<<"${dns_output}"
}

parse_ping_log() {
  local log_path="$1"
  local action_start_ns="$2"
  local action_end_ns="$3"
  local action_start_seconds
  local action_end_seconds

  action_start_seconds="$(epoch_ns_to_seconds "${action_start_ns}")"
  action_end_seconds="$(epoch_ns_to_seconds "${action_end_ns}")"

  awk \
    -v action_start="${action_start_seconds}" \
    -v action_end="${action_end_seconds}" \
    -v minimum_stable="${minimum_post_action_replies}" '
    BEGIN {
      first_after = -1
      maximum_gap = 0
      missing_after = 0
      replies_after = 0
      post_run = 0
      post_run_start = -1
    }
    /^\[[0-9]+[.][0-9]+\]/ &&
      ((/ bytes from / && /icmp_seq=[0-9]+/) ||
      (/ probe_seq=[0-9]+ / && / reply$/)) {
      timestamp = $1
      gsub(/^\[/, "", timestamp)
      gsub(/\]$/, "", timestamp)

      sequence = -1
      for (field_index = 1; field_index <= NF; field_index++) {
        if ($field_index ~ /^(icmp|probe)_seq=[0-9]+$/) {
          sequence = $field_index
          sub(/^(icmp|probe)_seq=/, "", sequence)
          sequence += 0
          break
        }
      }
      if (sequence < 0) {
        next
      }

      if (timestamp >= action_start && have_previous && sequence > previous_sequence) {
        gap = sequence - previous_sequence - 1
        missing_after += gap
        if (gap > maximum_gap) {
          maximum_gap = gap
        }
      }
      if (!have_previous || sequence > previous_sequence) {
        previous_sequence = sequence
        have_previous = 1
      }

      if (timestamp >= action_end) {
        if (!have_post_previous || sequence > post_previous_sequence) {
          replies_after++
          if (first_after < 0) {
            first_after = timestamp
          }
          if (have_post_previous && sequence == post_previous_sequence + 1) {
            post_run++
          } else {
            post_run = 1
            post_run_start = timestamp
          }
          post_previous_sequence = sequence
          have_post_previous = 1
        }
      }
    }
    /packets transmitted/ {
      transmitted = $1
      for (field_index = 1; field_index <= NF; field_index++) {
        field = $field_index
        gsub(/,/, "", field)
        if ($field_index ~ /^received,?$/ && field_index > 1) {
          received = $(field_index - 1)
          gsub(/,/, "", received)
        }
        if ($field_index == "packet" && $(field_index + 1) ~ /^loss,?$/ && field_index > 1) {
          loss = $(field_index - 1)
          gsub(/%/, "", loss)
        }
      }
      have_summary = 1
    }
    END {
      if (!have_summary || transmitted !~ /^[0-9]+$/ || received !~ /^[0-9]+$/ || loss !~ /^[0-9]+([.][0-9]+)?$/) {
        exit 2
      }
      if (have_previous && transmitted > previous_sequence) {
        gap = transmitted - previous_sequence
        missing_after += gap
        if (gap > maximum_gap) {
          maximum_gap = gap
        }
      }

      first_ms = "null"
      if (first_after >= 0) {
        first_ms = sprintf("%.0f", (first_after - action_start) * 1000)
      }
      stable_ms = "null"
      trailing_run = 0
      # iputils may include one final echo request in the transmitted count
      # before its reply can arrive at the observation deadline.
      if (have_post_previous &&
          post_previous_sequence >= transmitted - 1) {
        trailing_run = post_run
        if (post_run >= minimum_stable) {
          stable_ms = sprintf("%.0f", (post_run_start - action_start) * 1000)
        }
      }
      printf "%d\t%d\t%s\t%s\t%d\t%d\t%d\t%s\t%d\n", transmitted, received, loss, first_ms, maximum_gap, missing_after, replies_after, stable_ms, trailing_run
    }
  ' "${log_path}"
}

run_ping() {
  local family="$1"
  local interval="$2"
  local duration="$3"
  local target="$4"
  local log_path="$5"
  local started_ns
  local deadline_ns
  local current_ns
  local timestamp_ns
  local transmitted=0
  local received=0
  local loss

  started_ns="$(now_ns)"
  deadline_ns=$(( started_ns + duration * 1000000000 ))
  current_ns="${started_ns}"
  : >"${log_path}"

  while (( current_ns < deadline_ns )); do
    transmitted=$((transmitted + 1))
    if ping "-${family}" -n -c 1 -W "${interval}" "${target}" >/dev/null 2>&1; then
      received=$((received + 1))
      timestamp_ns="$(now_ns)"
      printf '[%s] probe_seq=%d reply\n' \
        "$(epoch_ns_to_seconds "${timestamp_ns}")" \
        "${transmitted}" >>"${log_path}"
    else
      timestamp_ns="$(now_ns)"
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

main() {
  local node_label=""
  local peer_label=""
  local peer_v4=""
  local peer_v6=""
  local peer_name=""
  local service_name=""
  local action_mode=restart
  local selected_schema_version="${restart_schema_version}"
  local artifact_sha256=""
  local lead_seconds=2
  local ready_timeout_seconds=15
  local tail_seconds=5
  local ping_interval=0.2
  local poll_interval=0.1
  local data_interface=mesh0
  local dns_interface=meshdns0
  local unit
  local command_name
  local baseline_status
  local daemon_version
  local daemon_commit
  local baseline_direct_count
  local baseline_relay_count
  local meshd_pid_before
  local meshnetd_pid_before
  local meshd_pid_after
  local meshnetd_pid_after
  local target_pid_changed=false
  local meshd_pid_changed=false
  local target_restart_count_before
  local target_restart_count_after
  local target_restart_count_peak
  local target_restart_count_increased=false
  local target_restart_policy
  local target_restart_policy_supports_sigkill=false
  local target_invocation_before
  local target_invocation_after
  local target_invocation_changed=false
  local target_restarted=false
  local meshd_restarted=false
  local recovery_generation_ready=false
  local target_pid_before
  local current_target_pid
  local current_meshd_pid
  local current_target_restart_count
  local current_target_invocation
  local observation_seconds
  local started_at
  local action_start_ns
  local action_end_ns
  local action_duration_ms
  local action_exit_code=0
  local deadline_ns
  local current_ns
  local service_ready_ns=""
  local tun_ready_ns=""
  local online_ready_ns=""
  local dns_ready_ns=""
  local dns_cleanup_required=false
  local dns_cleanup_observed=false
  local dns_cleanup_ns=""
  local service_ready_ms=null
  local tun_ready_ms=null
  local online_ready_ms=null
  local dns_ready_ms=null
  local dns_cleanup_ms=null
  local current_status=""
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
  local kernel_release
  local machine_arch
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
      --service)
        [[ $# -ge 2 ]] || fail "--service requires a value"
        service_name="$2"
        shift 2
        ;;
      --action)
        [[ $# -ge 2 ]] || fail "--action requires a value"
        action_mode="$2"
        shift 2
        ;;
      --artifact-sha256)
        [[ $# -ge 2 ]] || fail "--artifact-sha256 requires a value"
        artifact_sha256="$2"
        shift 2
        ;;
      --lead-seconds)
        [[ $# -ge 2 ]] || fail "--lead-seconds requires a value"
        lead_seconds="$2"
        shift 2
        ;;
      --ready-timeout-seconds)
        [[ $# -ge 2 ]] || fail "--ready-timeout-seconds requires a value"
        ready_timeout_seconds="$2"
        shift 2
        ;;
      --tail-seconds)
        [[ $# -ge 2 ]] || fail "--tail-seconds requires a value"
        tail_seconds="$2"
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
  (( EUID == 0 )) || fail "run as root so the selected service state can be changed"

  [[ -n "${node_label}" ]] || fail "--node-label is required"
  [[ -n "${peer_label}" ]] || fail "--peer-label is required"
  [[ -n "${peer_v4}" ]] || fail "--peer-v4 is required"
  [[ -n "${peer_v6}" ]] || fail "--peer-v6 is required"
  [[ -n "${peer_name}" ]] || fail "--peer-name is required"
  [[ -n "${service_name}" ]] || fail "--service is required"
  validate_action_mode "${action_mode}" || fail "action must be restart or sigkill"
  if [[ "${action_mode}" == sigkill ]]; then
    selected_schema_version="${crash_schema_version}"
  fi

  validate_label node-label "${node_label}"
  validate_label peer-label "${peer_label}"
  validate_dns_name "${peer_name}"
  validate_interface data-interface "${data_interface}"
  validate_interface dns-interface "${dns_interface}"
  validate_positive_integer lead-seconds "${lead_seconds}" 30
  validate_positive_integer ready-timeout-seconds "${ready_timeout_seconds}" 300
  validate_positive_integer tail-seconds "${tail_seconds}" 60
  validate_interval ping-interval "${ping_interval}"
  validate_interval poll-interval "${poll_interval}"

  if [[ ! "${peer_v4}" =~ ^[0-9.]+$ ]]; then
    fail "peer-v4 must be an IPv4 address"
  fi
  if [[ ! "${peer_v6}" =~ ^[0-9A-Fa-f:]+$ ]]; then
    fail "peer-v6 must be an IPv6 address without a zone identifier"
  fi
  if [[ -n "${artifact_sha256}" && ! "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    fail "artifact-sha256 must contain exactly 64 hexadecimal characters"
  fi

  case "${service_name}" in
    meshd|meshnetd)
      unit="${service_name}.service"
      ;;
    *)
      fail "service must be meshd or meshnetd"
      ;;
  esac

  if [[ "${action_mode}" == sigkill && "${service_name}" == meshd ]]; then
    dns_cleanup_required=true
  fi

  for command_name in awk date grep ip jq meshctl mktemp ping resolvectl sleep systemctl timeout uname; do
    require_command "${command_name}"
  done
  if [[ "${dns_cleanup_required}" == true ]]; then
    require_command ss
  fi

  route_uses_interface 4 "${peer_v4}" "${data_interface}" ||
    fail "peer-v4 does not resolve through ${data_interface}"
  route_uses_interface 6 "${peer_v6}" "${data_interface}" ||
    fail "peer-v6 does not resolve through ${data_interface}"

  systemctl is-active --quiet meshd.service meshnetd.service ||
    fail "meshd.service and meshnetd.service must both be active"
  ip link show dev "${data_interface}" >/dev/null 2>&1 ||
    fail "data interface ${data_interface} is not present"
  ip link show dev "${dns_interface}" >/dev/null 2>&1 ||
    fail "DNS interface ${dns_interface} is not present"

  baseline_status="$(meshctl --timeout 2s --json status 2>/dev/null)" ||
    fail "meshctl could not read baseline daemon status"
  status_is_ready "${baseline_status}" ||
    fail "baseline daemon status is not online and synchronized"
  jq -e '.dns == "configured"' >/dev/null <<<"${baseline_status}" ||
    fail "baseline daemon status does not report configured DNS"
  dns_is_ready "${peer_name}" "${peer_v4}" "${peer_v6}" ||
    fail "MagicDNS does not currently return both expected peer addresses"
  ping -4 -n -c 3 -W 1 "${peer_v4}" >/dev/null 2>&1 ||
    fail "baseline IPv4 peer traffic is unavailable"
  ping -6 -n -c 3 -W 1 "${peer_v6}" >/dev/null 2>&1 ||
    fail "baseline IPv6 peer traffic is unavailable"

  daemon_version="$(jq -r '.daemon.version' <<<"${baseline_status}")"
  daemon_commit="$(jq -r '.daemon.commit' <<<"${baseline_status}")"
  baseline_direct_count="$(jq -r '.paths.direct_count // 0' <<<"${baseline_status}")"
  baseline_relay_count="$(jq -r '.paths.relay_count // 0' <<<"${baseline_status}")"
  meshd_pid_before="$(unit_pid meshd.service)"
  meshnetd_pid_before="$(unit_pid meshnetd.service)"
  [[ "${meshd_pid_before}" != 0 && "${meshnetd_pid_before}" != 0 ]] ||
    fail "could not resolve both baseline service PIDs"
  case "${service_name}" in
    meshd) target_pid_before="${meshd_pid_before}" ;;
    meshnetd) target_pid_before="${meshnetd_pid_before}" ;;
  esac
  target_restart_count_before="$(unit_restart_count "${unit}")"
  target_restart_count_peak="${target_restart_count_before}"
  target_restart_policy="$(unit_restart_policy "${unit}")"
  if restart_policy_supports_sigkill "${target_restart_policy}"; then
    target_restart_policy_supports_sigkill=true
  fi
  target_invocation_before="$(unit_invocation_id "${unit}")"
  [[ -n "${target_invocation_before}" ]] ||
    fail "could not resolve the baseline service invocation ID"
  if [[ "${action_mode}" == sigkill &&
    "${target_restart_policy_supports_sigkill}" != true ]]; then
    fail "selected service restart policy does not recover SIGKILL"
  fi

  observation_seconds=$(( lead_seconds + ready_timeout_seconds + tail_seconds ))
  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-linux-restart.XXXXXXXX")"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  kernel_release="$(uname -r)"
  machine_arch="$(uname -m)"

  progress "preflight passed; observing ${service_name} ${action_mode} recovery"
  run_ping 4 "${ping_interval}" "${observation_seconds}" "${peer_v4}" \
    "${temp_dir}/ping-v4.log" &
  ping4_pid=$!
  run_ping 6 "${ping_interval}" "${observation_seconds}" "${peer_v6}" \
    "${temp_dir}/ping-v6.log" &
  ping6_pid=$!

  sleep "${lead_seconds}"
  action_start_ns="$(now_ns)"
  restore_services=true
  case "${action_mode}" in
    restart)
      if timeout --signal=TERM --kill-after=2s "${ready_timeout_seconds}s" \
        systemctl restart "${unit}"; then
        action_exit_code=0
      else
        action_exit_code=$?
      fi
      ;;
    sigkill)
      if systemctl kill --kill-whom=main --signal=KILL "${unit}"; then
        action_exit_code=0
      else
        action_exit_code=$?
      fi
      ;;
  esac
  action_end_ns="$(now_ns)"
  action_duration_ms="$(elapsed_ms "${action_start_ns}" "${action_end_ns}")"
  deadline_ns=$(( action_start_ns + ready_timeout_seconds * 1000000000 ))

  while true; do
    current_ns="$(now_ns)"
    if [[ "${dns_cleanup_required}" == true &&
      "${dns_cleanup_observed}" == false ]] &&
      dns_runtime_removed "${dns_interface}"; then
      dns_cleanup_ns="${current_ns}"
      dns_cleanup_observed=true
    fi

    current_target_pid="$(unit_pid "${unit}")"
    current_meshd_pid="$(unit_pid meshd.service)"
    current_target_restart_count="$(unit_restart_count "${unit}")"
    current_target_invocation="$(unit_invocation_id "${unit}")"
    # A fast successful activation can reset NRestarts before the new PID is
    # visible. Keep the transient counter peak for diagnostics and use the
    # persistent InvocationID transition as the generation boundary.
    if invocation_changed \
      "${target_invocation_before}" \
      "${current_target_invocation}"; then
      target_invocation_changed=true
    fi
    IFS=$'\t' read -r target_restart_count_peak target_restart_count_increased < <(
      restart_count_evidence \
        "${target_restart_count_before}" \
        "${target_restart_count_peak}" \
        "${current_target_restart_count}"
    )
    if [[ "${current_target_pid}" != 0 &&
      "${current_target_pid}" != "${target_pid_before}" ]]; then
      if [[ "${action_mode}" == restart ||
        "${target_invocation_changed}" == true ]]; then
        target_restarted=true
      fi
    fi
    if [[ "${current_meshd_pid}" != 0 &&
      "${current_meshd_pid}" != "${meshd_pid_before}" ]]; then
      meshd_restarted=true
    fi
    if [[ "${target_restarted}" == true && "${meshd_restarted}" == true ]]; then
      recovery_generation_ready=true
    fi

    if [[ "${recovery_generation_ready}" == true && -z "${service_ready_ns}" ]] &&
      systemctl is-active --quiet meshd.service meshnetd.service; then
      service_ready_ns="${current_ns}"
    fi
    if [[ "${recovery_generation_ready}" == true && -z "${tun_ready_ns}" ]] &&
      ip link show dev "${data_interface}" >/dev/null 2>&1; then
      tun_ready_ns="${current_ns}"
    fi

    current_status="$(meshctl --timeout 1s --json status 2>/dev/null || true)"
    if [[ "${recovery_generation_ready}" == true && -z "${online_ready_ns}" &&
      -n "${current_status}" ]] &&
      status_is_ready "${current_status}"; then
      online_ready_ns="${current_ns}"
    fi
    if [[ "${recovery_generation_ready}" == true && -z "${dns_ready_ns}" &&
      -n "${current_status}" ]] &&
      jq -e '.dns == "configured"' >/dev/null <<<"${current_status}" &&
      ip link show dev "${dns_interface}" >/dev/null 2>&1 &&
      dns_is_ready "${peer_name}" "${peer_v4}" "${peer_v6}"; then
      dns_ready_ns="${current_ns}"
    fi

    if [[ -n "${service_ready_ns}" && -n "${tun_ready_ns}" &&
      -n "${online_ready_ns}" && -n "${dns_ready_ns}" ]] &&
      [[ "${dns_cleanup_required}" == false ||
        "${dns_cleanup_observed}" == true ]]; then
      break
    fi
    if (( current_ns >= deadline_ns )); then
      break
    fi
    sleep "${poll_interval}"
  done

  [[ -z "${service_ready_ns}" ]] || service_ready_ms="$(elapsed_ms "${action_start_ns}" "${service_ready_ns}")"
  [[ -z "${tun_ready_ns}" ]] || tun_ready_ms="$(elapsed_ms "${action_start_ns}" "${tun_ready_ns}")"
  [[ -z "${online_ready_ns}" ]] || online_ready_ms="$(elapsed_ms "${action_start_ns}" "${online_ready_ns}")"
  [[ -z "${dns_ready_ns}" ]] || dns_ready_ms="$(elapsed_ms "${action_start_ns}" "${dns_ready_ns}")"
  [[ -z "${dns_cleanup_ns}" ]] || dns_cleanup_ms="$(elapsed_ms "${action_start_ns}" "${dns_cleanup_ns}")"

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

  if ping4_metrics="$(parse_ping_log "${temp_dir}/ping-v4.log" "${action_start_ns}" "${action_end_ns}")"; then
    IFS=$'\t' read -r ping4_transmitted ping4_received ping4_loss ping4_first_ms \
      ping4_max_gap ping4_missing_after ping4_replies_after ping4_stable_ms \
      ping4_trailing_run <<<"${ping4_metrics}"
  else
    ping4_parser_ok=false
  fi
  if ping6_metrics="$(parse_ping_log "${temp_dir}/ping-v6.log" "${action_start_ns}" "${action_end_ns}")"; then
    IFS=$'\t' read -r ping6_transmitted ping6_received ping6_loss ping6_first_ms \
      ping6_max_gap ping6_missing_after ping6_replies_after ping6_stable_ms \
      ping6_trailing_run <<<"${ping6_metrics}"
  else
    ping6_parser_ok=false
  fi

  meshd_pid_after="$(unit_pid meshd.service)"
  meshnetd_pid_after="$(unit_pid meshnetd.service)"
  if [[ "${meshd_pid_before}" != "${meshd_pid_after}" &&
    "${meshd_pid_after}" != 0 ]]; then
    meshd_pid_changed=true
  fi
  target_restart_count_after="$(unit_restart_count "${unit}")"
  target_invocation_after="$(unit_invocation_id "${unit}")"
  if invocation_changed \
    "${target_invocation_before}" \
    "${target_invocation_after}"; then
    target_invocation_changed=true
  fi
  IFS=$'\t' read -r target_restart_count_peak target_restart_count_increased < <(
    restart_count_evidence \
      "${target_restart_count_before}" \
      "${target_restart_count_peak}" \
      "${target_restart_count_after}"
  )
  if [[ "${service_name}" == meshd && "${meshd_pid_before}" != "${meshd_pid_after}" &&
    "${meshd_pid_after}" != 0 ]]; then
    target_pid_changed=true
  fi
  if [[ "${service_name}" == meshnetd && "${meshnetd_pid_before}" != "${meshnetd_pid_after}" &&
    "${meshnetd_pid_after}" != 0 ]]; then
    target_pid_changed=true
  fi

  if [[ -n "${artifact_sha256}" ]]; then
    artifact_digest_json="\"${artifact_sha256,,}\""
  fi

  report="$(jq -n \
    --arg schema "${selected_schema_version}" \
    --arg started_at "${started_at}" \
    --arg node_label "${node_label}" \
    --arg peer_label "${peer_label}" \
    --arg kernel_release "${kernel_release}" \
    --arg arch "${machine_arch}" \
    --arg service "${unit}" \
    --arg action_mode "${action_mode}" \
    --arg daemon_version "${daemon_version}" \
    --arg daemon_commit "${daemon_commit}" \
    --argjson artifact_sha256 "${artifact_digest_json}" \
    --argjson baseline_direct_count "${baseline_direct_count}" \
    --argjson baseline_relay_count "${baseline_relay_count}" \
    --argjson action_exit_code "${action_exit_code}" \
    --argjson action_duration_ms "${action_duration_ms}" \
    --argjson target_pid_changed "${target_pid_changed}" \
    --argjson meshd_pid_changed "${meshd_pid_changed}" \
    --argjson target_restart_count_before "${target_restart_count_before}" \
    --argjson target_restart_count_after "${target_restart_count_after}" \
    --argjson target_restart_count_peak "${target_restart_count_peak}" \
    --argjson target_restart_count_increased "${target_restart_count_increased}" \
    --arg target_restart_policy "${target_restart_policy}" \
    --argjson target_restart_policy_supports_sigkill "${target_restart_policy_supports_sigkill}" \
    --argjson target_invocation_changed "${target_invocation_changed}" \
    --argjson dns_cleanup_required "${dns_cleanup_required}" \
    --argjson dns_cleanup_observed "${dns_cleanup_observed}" \
    --argjson dns_cleanup_ms "${dns_cleanup_ms}" \
    --argjson service_ready_ms "${service_ready_ms}" \
    --argjson tun_ready_ms "${tun_ready_ms}" \
    --argjson online_ready_ms "${online_ready_ms}" \
    --argjson dns_ready_ms "${dns_ready_ms}" \
    --argjson lead_seconds "${lead_seconds}" \
    --argjson ready_timeout_seconds "${ready_timeout_seconds}" \
    --argjson tail_seconds "${tail_seconds}" \
    --argjson ping_interval "${ping_interval}" \
    --argjson poll_interval "${poll_interval}" \
    --argjson minimum_replies "${minimum_post_action_replies}" \
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
          node_label: $node_label,
          peer_label: $peer_label,
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
          evidence_complete: ($artifact_sha256 != null)
        },
        scenario: {
          action: $action_mode,
          service: $service
        },
        baseline: {
          direct_peer_count: $baseline_direct_count,
          relay_peer_count: $baseline_relay_count
        },
        observation: {
          lead_seconds: $lead_seconds,
          ready_timeout_seconds: $ready_timeout_seconds,
          tail_seconds: $tail_seconds,
          ping_interval_seconds: $ping_interval,
          readiness_poll_interval_seconds: $poll_interval,
          minimum_stable_replies: $minimum_replies
        },
        action: {
          exit_code: $action_exit_code,
          duration_ms: $action_duration_ms,
          target_pid_changed: $target_pid_changed,
          meshd_pid_changed: $meshd_pid_changed,
          restart_count_before: $target_restart_count_before,
          restart_count_after: $target_restart_count_after,
          restart_count_peak: $target_restart_count_peak,
          restart_count_increased: $target_restart_count_increased,
          restart_policy: $target_restart_policy,
          restart_policy_supports_sigkill: $target_restart_policy_supports_sigkill,
          invocation_changed: $target_invocation_changed
        },
        dns_cleanup: {
          required: $dns_cleanup_required,
          observed: $dns_cleanup_observed,
          observed_ms: $dns_cleanup_ms
        },
        readiness_ms: {
          services_active: $service_ready_ms,
          data_interface: $tun_ready_ms,
          daemon_online: $online_ready_ms,
          magic_dns: $dns_ready_ms
        },
        traffic: {
          ipv4: {
            command_exit_code: $ping4_exit_code,
            parser_ok: $ping4_parser_ok,
            transmitted: $ping4_transmitted,
            received: $ping4_received,
            loss_percent: $ping4_loss,
            first_reply_after_action_ms: $ping4_first_ms,
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
            first_reply_after_action_ms: $ping6_first_ms,
            maximum_consecutive_loss: $ping6_max_gap,
            missing_after_action: $ping6_missing_after,
            replies_after_action: $ping6_replies_after,
            stable_recovery_ms: $ping6_stable_ms,
            consecutive_replies_at_end: $ping6_trailing_run
          }
        }
      }
      | .failures = [
          if .action.exit_code != 0 and .scenario.action == "restart" then "restart_command_failed" else empty end,
          if .action.exit_code != 0 and .scenario.action == "sigkill" then "sigkill_command_failed" else empty end,
          if .action.target_pid_changed != true then "target_pid_did_not_change" else empty end,
          if .scenario.service == "meshnetd.service" and .action.meshd_pid_changed != true then "meshd_generation_did_not_change" else empty end,
          if .scenario.action == "sigkill" and .action.restart_policy_supports_sigkill != true then "restart_policy_does_not_recover_sigkill" else empty end,
          if .scenario.action == "sigkill" and .action.invocation_changed != true then "service_invocation_did_not_change" else empty end,
          if .dns_cleanup.required == true and .dns_cleanup.observed != true then "dns_cleanup_not_observed" else empty end,
          if .readiness_ms.services_active == null then "services_not_ready" else empty end,
          if .readiness_ms.data_interface == null then "data_interface_not_ready" else empty end,
          if .readiness_ms.daemon_online == null then "daemon_not_ready" else empty end,
          if .readiness_ms.magic_dns == null then "magic_dns_not_ready" else empty end,
          if .traffic.ipv4.parser_ok != true then "ipv4_probe_unparseable" else empty end,
          if .traffic.ipv6.parser_ok != true then "ipv6_probe_unparseable" else empty end,
          if .traffic.ipv4.first_reply_after_action_ms == null then "ipv4_did_not_recover" else empty end,
          if .traffic.ipv6.first_reply_after_action_ms == null then "ipv6_did_not_recover" else empty end,
          if .traffic.ipv4.stable_recovery_ms == null then "ipv4_did_not_stabilize" else empty end,
          if .traffic.ipv6.stable_recovery_ms == null then "ipv6_did_not_stabilize" else empty end,
          if .traffic.ipv4.stable_recovery_ms != null and .traffic.ipv4.stable_recovery_ms > (.observation.ready_timeout_seconds * 1000) then "ipv4_stable_recovery_timeout" else empty end,
          if .traffic.ipv6.stable_recovery_ms != null and .traffic.ipv6.stable_recovery_ms > (.observation.ready_timeout_seconds * 1000) then "ipv6_stable_recovery_timeout" else empty end
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

if [[ "${1:-}" == __parse-ping-log ]]; then
  [[ $# -eq 4 ]] || fail "__parse-ping-log requires LOG START_NS END_NS"
  parse_ping_log "$2" "$3" "$4"
  exit
fi

if [[ "${1:-}" == __run-ping ]]; then
  [[ $# -eq 6 ]] || fail "__run-ping requires FAMILY INTERVAL DURATION TARGET LOG"
  run_ping "$2" "$3" "$4" "$5" "$6"
  exit
fi

if [[ "${1:-}" == __validate-action-mode ]]; then
  [[ $# -eq 2 ]] || fail "__validate-action-mode requires ACTION"
  validate_action_mode "$2"
  exit
fi

if [[ "${1:-}" == __restart-count-evidence ]]; then
  [[ $# -ge 2 ]] || fail "__restart-count-evidence requires BASELINE [SAMPLE ...]"
  restart_count_evidence "${@:2}"
  exit
fi

if [[ "${1:-}" == __restart-policy-supports-sigkill ]]; then
  [[ $# -eq 2 ]] || fail "__restart-policy-supports-sigkill requires POLICY"
  restart_policy_supports_sigkill "$2"
  exit
fi

if [[ "${1:-}" == __invocation-changed ]]; then
  [[ $# -eq 3 ]] || fail "__invocation-changed requires BEFORE AFTER"
  invocation_changed "$2" "$3"
  exit
fi

main "$@"
