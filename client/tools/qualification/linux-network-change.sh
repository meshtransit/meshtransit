#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-network-change-qualification/v1"
readonly test_address="198.18.255.254/32"
readonly minimum_post_action_replies=3

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly restart_harness="${script_dir}/linux-restart.sh"

temp_dir=""
ping4_pid=""
ping6_pid=""
change_interface="meshqchg0"
change_interface_created=false

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-network-change.sh \
    --node-label LABEL \
    --peer-label LABEL \
    --peer-v4 ADDRESS \
    --peer-v6 ADDRESS \
    --peer-name MESH_DNS_NAME \
    --confirm-network-change LABEL \
    [--artifact-sha256 HEX] \
    [--lead-seconds N] \
    [--recovery-timeout-seconds N] \
    [--tail-seconds N] \
    [--ping-interval SECONDS] \
    [--poll-interval SECONDS] \
    [--data-interface NAME] \
    [--dns-interface NAME] \
    [--change-interface NAME]

Runs a bounded, reversible Linux interface-address change. The harness creates
one dedicated dummy interface, verifies that meshd observes the change and
completes endpoint discovery, then removes the interface. It never changes the
existing uplink, default route, MeshTransit interface, or DNS interface.
EOF
}

fail() {
  printf 'linux-network-change: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-network-change: %s\n' "$*" >&2
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
  if [[ "${change_interface_created}" == true ]]; then
    ip link delete dev "${change_interface}" 2>/dev/null
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
  local minimum_direct_count="$2"

  jq -e --argjson minimum_direct_count "${minimum_direct_count}" '
    .state == "online" and
    .control_session == "synchronized" and
    (.data_plane | type) == "string" and
    (.data_plane | startswith("encrypted_")) and
    .paths.available == true and
    .paths.direct_count >= $minimum_direct_count
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

main() {
  local node_label=""
  local peer_label=""
  local peer_v4=""
  local peer_v6=""
  local peer_name=""
  local confirmation=""
  local artifact_sha256=""
  local lead_seconds=2
  local recovery_timeout_seconds=20
  local tail_seconds=5
  local ping_interval=0.2
  local poll_interval=0.1
  local data_interface=mesh0
  local dns_interface=meshdns0
  local command_name
  local baseline_status
  local daemon_version
  local daemon_commit
  local baseline_direct_count
  local baseline_relay_count
  local baseline_observed
  local baseline_refreshes
  local final_observed
  local final_refreshes
  local observation_seconds
  local started_at
  local action_start_ns
  local action_end_ns
  local action_duration_ms
  local action_exit_code=0
  local deadline_ns
  local current_ns
  local observed_ns=""
  local refresh_ns=""
  local usable_ns=""
  local observed_ms=null
  local refresh_ms=null
  local usable_ms=null
  local current_status=""
  local current_observed=0
  local current_refreshes=0
  local cleanup_ok=false
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
      --confirm-network-change)
        [[ $# -ge 2 ]] || fail "--confirm-network-change requires a value"
        confirmation="$2"
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
      --change-interface)
        [[ $# -ge 2 ]] || fail "--change-interface requires a value"
        change_interface="$2"
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
  (( EUID == 0 )) || fail "run as root so a dedicated test interface can be created"
  [[ -x "${restart_harness}" ]] || fail "linux-restart.sh must be executable beside this harness"

  [[ -n "${node_label}" ]] || fail "--node-label is required"
  [[ -n "${peer_label}" ]] || fail "--peer-label is required"
  [[ -n "${peer_v4}" ]] || fail "--peer-v4 is required"
  [[ -n "${peer_v6}" ]] || fail "--peer-v6 is required"
  [[ -n "${peer_name}" ]] || fail "--peer-name is required"
  [[ "${confirmation}" == "${node_label}" ]] ||
    fail "--confirm-network-change must exactly match --node-label"

  validate_label node-label "${node_label}"
  validate_label peer-label "${peer_label}"
  validate_dns_name "${peer_name}"
  validate_interface data-interface "${data_interface}"
  validate_interface dns-interface "${dns_interface}"
  validate_interface change-interface "${change_interface}"
  [[ "${change_interface}" != "${data_interface}" ]] ||
    fail "change-interface must not be the data interface"
  [[ "${change_interface}" != "${dns_interface}" ]] ||
    fail "change-interface must not be the DNS interface"
  validate_positive_integer lead-seconds "${lead_seconds}" 30
  validate_positive_integer recovery-timeout-seconds "${recovery_timeout_seconds}" 60
  validate_positive_integer tail-seconds "${tail_seconds}" 60
  validate_interval ping-interval "${ping_interval}"
  validate_interval poll-interval "${poll_interval}"

  [[ "${peer_v4}" =~ ^[0-9.]+$ ]] || fail "peer-v4 must be an IPv4 address"
  [[ "${peer_v6}" =~ ^[0-9A-Fa-f:]+$ ]] ||
    fail "peer-v6 must be an IPv6 address without a zone identifier"
  if [[ -n "${artifact_sha256}" && ! "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    fail "artifact-sha256 must contain exactly 64 hexadecimal characters"
  fi

  for command_name in awk date grep ip jq meshctl mktemp ping resolvectl sleep systemctl timeout uname; do
    require_command "${command_name}"
  done
  ip link show dev "${change_interface}" >/dev/null 2>&1 &&
    fail "change interface already exists; refusing to modify it"
  systemctl is-active --quiet meshd.service meshnetd.service ||
    fail "meshd.service and meshnetd.service must both be active"
  ip link show dev "${data_interface}" >/dev/null 2>&1 ||
    fail "data interface ${data_interface} is not present"
  ip link show dev "${dns_interface}" >/dev/null 2>&1 ||
    fail "DNS interface ${dns_interface} is not present"
  route_uses_interface 4 "${peer_v4}" "${data_interface}" ||
    fail "peer-v4 does not resolve through ${data_interface}"
  route_uses_interface 6 "${peer_v6}" "${data_interface}" ||
    fail "peer-v6 does not resolve through ${data_interface}"

  baseline_status="$(meshctl --timeout 2s --json status 2>/dev/null)" ||
    fail "meshctl could not read baseline daemon status"
  baseline_direct_count="$(jq -er '.paths.direct_count' <<<"${baseline_status}")" ||
    fail "baseline direct path count is unavailable"
  baseline_relay_count="$(jq -er '.paths.relay_count' <<<"${baseline_status}")" ||
    fail "baseline relay path count is unavailable"
  status_is_ready "${baseline_status}" "${baseline_direct_count}" ||
    fail "baseline daemon status is not online with a direct path"
  (( baseline_direct_count > 0 )) || fail "baseline requires at least one direct peer path"
  jq -e '
    .dns == "configured" and
    .network_changes.available == true and
    (.network_changes.observed | type) == "number" and
    (.network_changes.endpoint_refreshes | type) == "number"
  ' >/dev/null <<<"${baseline_status}" ||
    fail "network-change monitoring or DNS is unavailable"
  baseline_observed="$(jq -r '.network_changes.observed' <<<"${baseline_status}")"
  baseline_refreshes="$(jq -r '.network_changes.endpoint_refreshes' <<<"${baseline_status}")"
  dns_is_ready "${peer_name}" "${peer_v4}" "${peer_v6}" ||
    fail "MeshTransit DNS does not currently return both expected peer addresses"
  ping -4 -n -c 3 -W 1 "${peer_v4}" >/dev/null 2>&1 ||
    fail "baseline IPv4 peer traffic is unavailable"
  ping -6 -n -c 3 -W 1 "${peer_v6}" >/dev/null 2>&1 ||
    fail "baseline IPv6 peer traffic is unavailable"

  daemon_version="$(jq -r '.daemon.version' <<<"${baseline_status}")"
  daemon_commit="$(jq -r '.daemon.commit' <<<"${baseline_status}")"
  observation_seconds=$(( lead_seconds + recovery_timeout_seconds + tail_seconds ))
  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-linux-network-change.XXXXXXXX")"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  kernel_release="$(uname -r)"
  machine_arch="$(uname -m)"

  progress "preflight passed; observing controlled interface-address change"
  "${restart_harness}" __run-ping 4 "${ping_interval}" "${observation_seconds}" \
    "${peer_v4}" "${temp_dir}/ping-v4.log" &
  ping4_pid=$!
  "${restart_harness}" __run-ping 6 "${ping_interval}" "${observation_seconds}" \
    "${peer_v6}" "${temp_dir}/ping-v6.log" &
  ping6_pid=$!

  sleep "${lead_seconds}"
  action_start_ns="$(now_ns)"
  if ip link add dev "${change_interface}" type dummy; then
    change_interface_created=true
    if ip address add "${test_address}" dev "${change_interface}" &&
      ip link set dev "${change_interface}" up; then
      action_exit_code=0
    else
      action_exit_code=$?
    fi
  else
    action_exit_code=$?
  fi
  action_end_ns="$(now_ns)"
  action_duration_ms="$(elapsed_ms "${action_start_ns}" "${action_end_ns}")"
  deadline_ns=$(( action_start_ns + recovery_timeout_seconds * 1000000000 ))

  while true; do
    current_ns="$(now_ns)"
    current_status="$(meshctl --timeout 1s --json status 2>/dev/null || true)"
    if [[ -n "${current_status}" ]]; then
      current_observed="$(jq -r '.network_changes.observed // 0' <<<"${current_status}" 2>/dev/null || printf '0')"
      current_refreshes="$(jq -r '.network_changes.endpoint_refreshes // 0' <<<"${current_status}" 2>/dev/null || printf '0')"
      if [[ -z "${observed_ns}" && "${current_observed}" =~ ^[0-9]+$ ]] &&
        (( current_observed > baseline_observed )); then
        observed_ns="${current_ns}"
      fi
      if [[ -z "${refresh_ns}" && "${current_refreshes}" =~ ^[0-9]+$ ]] &&
        (( current_refreshes > baseline_refreshes )); then
        refresh_ns="${current_ns}"
      fi
      if [[ -z "${usable_ns}" ]] &&
        status_is_ready "${current_status}" "${baseline_direct_count}"; then
        usable_ns="${current_ns}"
      fi
    fi
    if [[ -n "${observed_ns}" && -n "${refresh_ns}" && -n "${usable_ns}" ]]; then
      break
    fi
    if (( current_ns >= deadline_ns )); then
      break
    fi
    sleep "${poll_interval}"
  done

  [[ -z "${observed_ns}" ]] || observed_ms="$(elapsed_ms "${action_start_ns}" "${observed_ns}")"
  [[ -z "${refresh_ns}" ]] || refresh_ms="$(elapsed_ms "${action_start_ns}" "${refresh_ns}")"
  [[ -z "${usable_ns}" ]] || usable_ms="$(elapsed_ms "${action_start_ns}" "${usable_ns}")"

  if [[ "${change_interface_created}" == true ]] &&
    ip link delete dev "${change_interface}"; then
    change_interface_created=false
    cleanup_ok=true
  fi
  final_observed="${current_observed}"
  final_refreshes="${current_refreshes}"

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

  if ping4_metrics="$("${restart_harness}" __parse-ping-log \
    "${temp_dir}/ping-v4.log" "${action_start_ns}" "${action_end_ns}")"; then
    IFS=$'\t' read -r ping4_transmitted ping4_received ping4_loss ping4_first_ms \
      ping4_max_gap ping4_missing_after ping4_replies_after ping4_stable_ms \
      ping4_trailing_run <<<"${ping4_metrics}"
  else
    ping4_parser_ok=false
  fi
  if ping6_metrics="$("${restart_harness}" __parse-ping-log \
    "${temp_dir}/ping-v6.log" "${action_start_ns}" "${action_end_ns}")"; then
    IFS=$'\t' read -r ping6_transmitted ping6_received ping6_loss ping6_first_ms \
      ping6_max_gap ping6_missing_after ping6_replies_after ping6_stable_ms \
      ping6_trailing_run <<<"${ping6_metrics}"
  else
    ping6_parser_ok=false
  fi

  if [[ -n "${artifact_sha256}" ]]; then
    artifact_digest_json="\"${artifact_sha256,,}\""
  fi

  report="$(jq -n \
    --arg schema "${schema_version}" \
    --arg started_at "${started_at}" \
    --arg node_label "${node_label}" \
    --arg peer_label "${peer_label}" \
    --arg kernel_release "${kernel_release}" \
    --arg arch "${machine_arch}" \
    --arg daemon_version "${daemon_version}" \
    --arg daemon_commit "${daemon_commit}" \
    --arg change_interface "${change_interface}" \
    --argjson artifact_sha256 "${artifact_digest_json}" \
    --argjson baseline_direct_count "${baseline_direct_count}" \
    --argjson baseline_relay_count "${baseline_relay_count}" \
    --argjson baseline_observed "${baseline_observed}" \
    --argjson baseline_refreshes "${baseline_refreshes}" \
    --argjson final_observed "${final_observed}" \
    --argjson final_refreshes "${final_refreshes}" \
    --argjson action_exit_code "${action_exit_code}" \
    --argjson action_duration_ms "${action_duration_ms}" \
    --argjson cleanup_ok "${cleanup_ok}" \
    --argjson observed_ms "${observed_ms}" \
    --argjson refresh_ms "${refresh_ms}" \
    --argjson usable_ms "${usable_ms}" \
    --argjson lead_seconds "${lead_seconds}" \
    --argjson recovery_timeout_seconds "${recovery_timeout_seconds}" \
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
          action: "controlled_interface_address_change",
          interface: $change_interface,
          changes_existing_uplink: false,
          changes_default_route: false
        },
        baseline: {
          direct_peer_count: $baseline_direct_count,
          relay_peer_count: $baseline_relay_count,
          network_changes_observed: $baseline_observed,
          endpoint_refreshes: $baseline_refreshes
        },
        observation: {
          lead_seconds: $lead_seconds,
          recovery_timeout_seconds: $recovery_timeout_seconds,
          tail_seconds: $tail_seconds,
          ping_interval_seconds: $ping_interval,
          status_poll_interval_seconds: $poll_interval,
          minimum_stable_replies: $minimum_replies
        },
        action: {
          exit_code: $action_exit_code,
          duration_ms: $action_duration_ms,
          cleanup_ok: $cleanup_ok
        },
        recovery_ms: {
          event_observed: $observed_ms,
          endpoint_refresh: $refresh_ms,
          path_usable: $usable_ms
        },
        final: {
          network_changes_observed: $final_observed,
          endpoint_refreshes: $final_refreshes
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
          if .action.exit_code != 0 then "network_change_command_failed" else empty end,
          if .action.cleanup_ok != true then "test_interface_cleanup_failed" else empty end,
          if .recovery_ms.event_observed == null then "network_change_not_observed" else empty end,
          if .recovery_ms.endpoint_refresh == null then "endpoint_refresh_not_completed" else empty end,
          if .recovery_ms.path_usable == null then "direct_path_not_usable" else empty end,
          if .recovery_ms.endpoint_refresh != null and .recovery_ms.endpoint_refresh > (.observation.recovery_timeout_seconds * 1000) then "endpoint_refresh_timeout" else empty end,
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

main "$@"
