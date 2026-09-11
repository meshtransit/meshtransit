#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-relay-fallback-qualification/v1"
readonly nft_family="inet"
readonly nft_table="meshd_relay_qual"

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly restart_harness="${script_dir}/linux-restart.sh"

temp_dir=""
stop_file=""
ping4_pid=""
ping6_pid=""
firewall_active=false

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-relay-fallback.sh \
    --node-label LABEL \
    --peer-label LABEL \
    --peer-v4 ADDRESS \
    --peer-v6 ADDRESS \
    --peer-name MAGICDNS_NAME \
    --peer-underlay-v4 ADDRESS [--peer-underlay-v4 ADDRESS ...] \
    [--peer-underlay-v6 ADDRESS ...] \
    --confirm-direct-loss LABEL \
    [--artifact-sha256 HEX] \
    [--lead-seconds N] \
    [--fallback-timeout-seconds N] \
    [--relay-hold-seconds N] \
    [--recovery-timeout-seconds N] \
    [--tail-seconds N] \
    [--ping-interval SECONDS] \
    [--poll-interval SECONDS] \
    [--data-interface NAME] \
    [--dns-interface NAME]

Runs a bounded, reversible direct-path loss scenario on a single-peer Linux
node. A dedicated nftables table drops only UDP to the explicitly listed peer
underlay addresses. SSH, the default route, MeshTransit interfaces, DNS, the
control connection, and relay connections are not modified. A trap removes
the table if the run is interrupted.
EOF
}

fail() {
  printf 'linux-relay-fallback: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-relay-fallback: %s\n' "$*" >&2
}

cleanup() {
  local path

  set +e
  if [[ "${firewall_active}" == true ]]; then
    if nft delete table "${nft_family}" "${nft_table}" 2>/dev/null; then
      firewall_active=false
    fi
  fi
  if [[ -n "${stop_file}" ]]; then
    : >"${stop_file}"
  fi
  if [[ -n "${ping4_pid}" ]]; then
    wait "${ping4_pid}" 2>/dev/null
  fi
  if [[ -n "${ping6_pid}" ]]; then
    wait "${ping6_pid}" 2>/dev/null
  fi
  if [[ "${firewall_active}" == true ]]; then
    nft delete table "${nft_family}" "${nft_table}" 2>/dev/null
  fi
  if [[ -n "${temp_dir}" ]]; then
    for path in "${temp_dir}/ping-v4.log" "${temp_dir}/ping-v6.log" \
      "${temp_dir}/stop"; do
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

validate_ipv4() {
  local value="$1"
  local octet
  local -a octets

  [[ "${value}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a octets <<<"${value}"
  (( ${#octets[@]} == 4 )) || return 1
  for octet in "${octets[@]}"; do
    [[ "${octet}" =~ ^0$|^[1-9][0-9]{0,2}$ ]] || return 1
    (( 10#${octet} <= 255 )) || return 1
  done
}

validate_ipv6() {
  local value="$1"

  [[ "${value}" =~ ^[0-9A-Fa-f:]+$ && "${value}" == *:* ]]
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

route_avoids_interface() {
  local family="$1"
  local address="$2"
  local forbidden_interface="$3"
  local route

  route="$(ip "-${family}" route get "${address}" 2>/dev/null)" || return 1
  awk -v forbidden="${forbidden_interface}" '
  $1 == "local" || $1 == "blackhole" || $1 == "unreachable" || $1 == "prohibit" {
    exit 1
  }
  {
    for (field_index = 1; field_index < NF; field_index++) {
      if ($field_index == "dev" && $(field_index + 1) == forbidden) {
        exit 1
      }
    }
    exit 0
  }' <<<"${route}"
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
        exit 0
      }
    }
    exit 1
  }' <<<"${route}"
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

baseline_status_is_ready() {
  local status="$1"

  jq -e '
    .state == "online" and
    .control_session == "synchronized" and
    (.data_plane | type) == "string" and
    (.data_plane | startswith("encrypted_")) and
    .dns == "configured" and
    .relay.available == true and
    .relay.connected_regions >= 1 and
    .paths.available == true and
    .paths.peer_count == 1 and
    .paths.direct_count == 1 and
    .paths.relay_count == 0 and
    .paths.pending_count == 0
  ' >/dev/null <<<"${status}"
}

relay_status_is_ready() {
  local status="$1"

  jq -e '
    .state == "online" and
    .control_session == "synchronized" and
    .relay.available == true and
    .relay.connected_regions >= 1 and
    .paths.available == true and
    .paths.peer_count == 1 and
    .paths.direct_count == 0 and
    .paths.relay_count == 1 and
    .paths.pending_count == 0
  ' >/dev/null <<<"${status}"
}

direct_status_is_ready() {
  local status="$1"

  baseline_status_is_ready "${status}"
}

render_nft_batch() {
  local address
  local -a underlay_v4=("${!1}")
  local -a underlay_v6=("${!2}")

  printf 'add table %s %s\n' "${nft_family}" "${nft_table}"
  printf 'add chain %s %s direct_out { type filter hook output priority 0; policy accept; }\n' \
    "${nft_family}" "${nft_table}"
  printf 'add chain %s %s direct_in { type filter hook input priority 0; policy accept; }\n' \
    "${nft_family}" "${nft_table}"
  for address in "${underlay_v4[@]}"; do
    printf 'add rule %s %s direct_out ip daddr %s meta l4proto udp counter drop comment "mesh-direct-loss"\n' \
      "${nft_family}" "${nft_table}" "${address}"
    printf 'add rule %s %s direct_in ip saddr %s meta l4proto udp counter drop comment "mesh-direct-loss"\n' \
      "${nft_family}" "${nft_table}" "${address}"
  done
  for address in "${underlay_v6[@]}"; do
    printf 'add rule %s %s direct_out ip6 daddr %s meta l4proto udp counter drop comment "mesh-direct-loss"\n' \
      "${nft_family}" "${nft_table}" "${address}"
    printf 'add rule %s %s direct_in ip6 saddr %s meta l4proto udp counter drop comment "mesh-direct-loss"\n' \
      "${nft_family}" "${nft_table}" "${address}"
  done
}

chain_packet_count() {
  local chain="$1"

  nft -j list chain "${nft_family}" "${nft_table}" "${chain}" |
    jq -er '[
      .nftables[]?.rule?.expr[]?
      | select(.counter != null)
      | .counter.packets
    ] | add // 0'
}

run_ping_until_stopped() {
  local family="$1"
  local interval="$2"
  local maximum_seconds="$3"
  local target="$4"
  local log_path="$5"
  local marker="$6"
  local started_ns
  local deadline_ns
  local current_ns
  local timestamp_ns
  local transmitted=0
  local received=0
  local loss

  started_ns="$(now_ns)"
  deadline_ns=$(( started_ns + maximum_seconds * 1000000000 ))
  current_ns="${started_ns}"
  : >"${log_path}"

  while [[ ! -e "${marker}" ]] && (( current_ns < deadline_ns )); do
    transmitted=$((transmitted + 1))
    if ping "-${family}" -n -c 1 -W 1 "${target}" >/dev/null 2>&1; then
      received=$((received + 1))
      timestamp_ns="$(now_ns)"
      printf '[%s] probe_seq=%d reply\n' \
        "$(awk -v value="${timestamp_ns}" 'BEGIN { printf "%.9f", value / 1000000000 }')" \
        "${transmitted}" >>"${log_path}"
    else
      timestamp_ns="$(now_ns)"
      printf '[%s] probe_seq=%d timeout\n' \
        "$(awk -v value="${timestamp_ns}" 'BEGIN { printf "%.9f", value / 1000000000 }')" \
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
  local confirmation=""
  local artifact_sha256=""
  local lead_seconds=2
  local fallback_timeout_seconds=10
  local relay_hold_seconds=2
  local recovery_timeout_seconds=15
  local tail_seconds=5
  local ping_interval=0.2
  local poll_interval=0.1
  local data_interface=mesh0
  local dns_interface=meshdns0
  local -a peer_underlay_v4=()
  local -a peer_underlay_v6=()
  local command_name
  local address
  local baseline_status
  local daemon_version
  local daemon_commit
  local started_at
  local kernel_release
  local machine_arch
  local maximum_observation_seconds
  local fault_start_ns
  local fault_end_ns
  local fallback_deadline_ns
  local fallback_observed_ns=""
  local fallback_ms=null
  local current_ns
  local current_status=""
  local relay_ipv4_ok=false
  local relay_ipv6_ok=false
  local output_dropped_packets=0
  local input_dropped_packets=0
  local unblock_start_ns
  local unblock_end_ns
  local impairment_duration_ms=0
  local cleanup_ok=false
  local recovery_deadline_ns
  local direct_observed_ns=""
  local direct_recovery_ms=null
  local final_status=""
  local final_ready=false
  local ping4_exit_code=0
  local ping6_exit_code=0
  local ping4_parser_ok=true
  local ping6_parser_ok=true
  local fallback4_metrics
  local fallback6_metrics
  local recovery4_metrics
  local recovery6_metrics
  local ping4_transmitted=0
  local ping4_received=0
  local ping4_loss=100
  local ping4_first_after_fault_ms=null
  local ping4_max_gap=0
  local ping4_missing_after_fault=0
  local ping4_replies_after_fault=0
  local ping4_stable_after_unblock_ms=null
  local ping4_trailing_run=0
  local ping6_transmitted=0
  local ping6_received=0
  local ping6_loss=100
  local ping6_first_after_fault_ms=null
  local ping6_max_gap=0
  local ping6_missing_after_fault=0
  local ping6_replies_after_fault=0
  local ping6_stable_after_unblock_ms=null
  local ping6_trailing_run=0
  local -a fallback_fields=()
  local -a recovery_fields=()
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
      --peer-underlay-v4)
        [[ $# -ge 2 ]] || fail "--peer-underlay-v4 requires a value"
        peer_underlay_v4+=("$2")
        shift 2
        ;;
      --peer-underlay-v6)
        [[ $# -ge 2 ]] || fail "--peer-underlay-v6 requires a value"
        peer_underlay_v6+=("$2")
        shift 2
        ;;
      --confirm-direct-loss)
        [[ $# -ge 2 ]] || fail "--confirm-direct-loss requires a value"
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
      --fallback-timeout-seconds)
        [[ $# -ge 2 ]] || fail "--fallback-timeout-seconds requires a value"
        fallback_timeout_seconds="$2"
        shift 2
        ;;
      --relay-hold-seconds)
        [[ $# -ge 2 ]] || fail "--relay-hold-seconds requires a value"
        relay_hold_seconds="$2"
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
  (( EUID == 0 )) || fail "run as root so a dedicated nftables table can be created"
  [[ -x "${restart_harness}" ]] || fail "linux-restart.sh must be executable beside this harness"

  [[ -n "${node_label}" ]] || fail "--node-label is required"
  [[ -n "${peer_label}" ]] || fail "--peer-label is required"
  [[ -n "${peer_v4}" ]] || fail "--peer-v4 is required"
  [[ -n "${peer_v6}" ]] || fail "--peer-v6 is required"
  [[ -n "${peer_name}" ]] || fail "--peer-name is required"
  (( ${#peer_underlay_v4[@]} + ${#peer_underlay_v6[@]} > 0 )) ||
    fail "at least one peer underlay address is required"
  [[ "${confirmation}" == "${node_label}" ]] ||
    fail "--confirm-direct-loss must exactly match --node-label"

  validate_label node-label "${node_label}"
  validate_label peer-label "${peer_label}"
  validate_dns_name "${peer_name}"
  validate_interface data-interface "${data_interface}"
  validate_interface dns-interface "${dns_interface}"
  validate_positive_integer lead-seconds "${lead_seconds}" 30
  validate_positive_integer fallback-timeout-seconds "${fallback_timeout_seconds}" 30
  validate_positive_integer relay-hold-seconds "${relay_hold_seconds}" 30
  validate_positive_integer recovery-timeout-seconds "${recovery_timeout_seconds}" 60
  validate_positive_integer tail-seconds "${tail_seconds}" 60
  validate_interval ping-interval "${ping_interval}"
  validate_interval poll-interval "${poll_interval}"

  validate_ipv4 "${peer_v4}" || fail "peer-v4 must be a canonical IPv4 address"
  validate_ipv6 "${peer_v6}" ||
    fail "peer-v6 must be an IPv6 address without a zone identifier"
  for address in "${peer_underlay_v4[@]}"; do
    validate_ipv4 "${address}" ||
      fail "peer-underlay-v4 must be a canonical IPv4 address"
    [[ "${address}" != "${peer_v4}" ]] ||
      fail "peer-underlay-v4 must not be the overlay peer address"
  done
  for address in "${peer_underlay_v6[@]}"; do
    validate_ipv6 "${address}" ||
      fail "peer-underlay-v6 must be an IPv6 address without a zone identifier"
    [[ "${address,,}" != "${peer_v6,,}" ]] ||
      fail "peer-underlay-v6 must not be the overlay peer address"
  done
  if [[ -n "${artifact_sha256}" && ! "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    fail "artifact-sha256 must contain exactly 64 hexadecimal characters"
  fi

  for command_name in awk date grep ip jq meshctl mktemp nft ping resolvectl sleep \
    systemctl timeout touch uname; do
    require_command "${command_name}"
  done
  nft list table "${nft_family}" "${nft_table}" >/dev/null 2>&1 &&
    fail "qualification nftables table already exists; refusing to modify it"
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
  for address in "${peer_underlay_v4[@]}"; do
    route_avoids_interface 4 "${address}" "${data_interface}" ||
      fail "peer-underlay-v4 is unavailable or resolves through the data interface"
  done
  for address in "${peer_underlay_v6[@]}"; do
    route_avoids_interface 6 "${address}" "${data_interface}" ||
      fail "peer-underlay-v6 is unavailable or resolves through the data interface"
  done

  baseline_status="$(meshctl --timeout 2s --json status 2>/dev/null)" ||
    fail "meshctl could not read baseline daemon status"
  baseline_status_is_ready "${baseline_status}" ||
    fail "baseline requires exactly one direct peer and an available relay"
  dns_is_ready "${peer_name}" "${peer_v4}" "${peer_v6}" ||
    fail "MagicDNS does not currently return both expected peer addresses"
  ping -4 -n -c 3 -W 1 "${peer_v4}" >/dev/null 2>&1 ||
    fail "baseline IPv4 peer traffic is unavailable"
  ping -6 -n -c 3 -W 1 "${peer_v6}" >/dev/null 2>&1 ||
    fail "baseline IPv6 peer traffic is unavailable"

  daemon_version="$(jq -r '.daemon.version' <<<"${baseline_status}")"
  daemon_commit="$(jq -r '.daemon.commit' <<<"${baseline_status}")"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  kernel_release="$(uname -r)"
  machine_arch="$(uname -m)"
  maximum_observation_seconds=$((
    lead_seconds + fallback_timeout_seconds + relay_hold_seconds +
      recovery_timeout_seconds + tail_seconds + 10
  ))
  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-linux-relay.XXXXXXXX")"
  stop_file="${temp_dir}/stop"

  progress "preflight passed; starting bounded direct-path impairment"
  run_ping_until_stopped 4 "${ping_interval}" "${maximum_observation_seconds}" \
    "${peer_v4}" "${temp_dir}/ping-v4.log" "${stop_file}" &
  ping4_pid=$!
  run_ping_until_stopped 6 "${ping_interval}" "${maximum_observation_seconds}" \
    "${peer_v6}" "${temp_dir}/ping-v6.log" "${stop_file}" &
  ping6_pid=$!

  sleep "${lead_seconds}"
  fault_start_ns="$(now_ns)"
  firewall_active=true
  if ! render_nft_batch peer_underlay_v4[@] peer_underlay_v6[@] | nft -f -; then
    if ! nft list table "${nft_family}" "${nft_table}" >/dev/null 2>&1; then
      firewall_active=false
    fi
  fi
  fault_end_ns="$(now_ns)"
  [[ "${firewall_active}" == true ]] || fail "could not install the qualification nftables table"
  fallback_deadline_ns=$(( fault_start_ns + fallback_timeout_seconds * 1000000000 ))

  while true; do
    current_ns="$(now_ns)"
    current_status="$(meshctl --timeout 1s --json status 2>/dev/null || true)"
    if [[ -n "${current_status}" ]] && relay_status_is_ready "${current_status}"; then
      fallback_observed_ns="${current_ns}"
      break
    fi
    if (( current_ns >= fallback_deadline_ns )); then
      break
    fi
    sleep "${poll_interval}"
  done
  [[ -z "${fallback_observed_ns}" ]] ||
    fallback_ms="$(elapsed_ms "${fault_start_ns}" "${fallback_observed_ns}")"

  if [[ -n "${fallback_observed_ns}" ]]; then
    if ping -4 -n -c 3 -i 0.2 -W 1 "${peer_v4}" >/dev/null 2>&1; then
      relay_ipv4_ok=true
    fi
    if ping -6 -n -c 3 -i 0.2 -W 1 "${peer_v6}" >/dev/null 2>&1; then
      relay_ipv6_ok=true
    fi
    sleep "${relay_hold_seconds}"
  fi

  output_dropped_packets="$(chain_packet_count direct_out 2>/dev/null || printf '0')"
  input_dropped_packets="$(chain_packet_count direct_in 2>/dev/null || printf '0')"
  unblock_start_ns="$(now_ns)"
  if nft delete table "${nft_family}" "${nft_table}" &&
    ! nft list table "${nft_family}" "${nft_table}" >/dev/null 2>&1; then
    firewall_active=false
    cleanup_ok=true
  fi
  unblock_end_ns="$(now_ns)"
  impairment_duration_ms="$(elapsed_ms "${fault_start_ns}" "${unblock_start_ns}")"

  recovery_deadline_ns=$(( unblock_start_ns + recovery_timeout_seconds * 1000000000 ))
  while true; do
    current_ns="$(now_ns)"
    current_status="$(meshctl --timeout 1s --json status 2>/dev/null || true)"
    if [[ -n "${current_status}" ]] && direct_status_is_ready "${current_status}"; then
      direct_observed_ns="${current_ns}"
      break
    fi
    if (( current_ns >= recovery_deadline_ns )); then
      break
    fi
    sleep "${poll_interval}"
  done
  [[ -z "${direct_observed_ns}" ]] ||
    direct_recovery_ms="$(elapsed_ms "${unblock_start_ns}" "${direct_observed_ns}")"

  sleep "${tail_seconds}"
  : >"${stop_file}"
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

  final_status="$(meshctl --timeout 2s --json status 2>/dev/null || true)"
  if [[ -n "${final_status}" ]] && direct_status_is_ready "${final_status}" &&
    dns_is_ready "${peer_name}" "${peer_v4}" "${peer_v6}"; then
    final_ready=true
  fi

  if fallback4_metrics="$("${restart_harness}" __parse-ping-log \
    "${temp_dir}/ping-v4.log" "${fault_start_ns}" "${fault_end_ns}")" &&
    recovery4_metrics="$("${restart_harness}" __parse-ping-log \
      "${temp_dir}/ping-v4.log" "${unblock_start_ns}" "${unblock_end_ns}")"; then
    IFS=$'\t' read -r -a fallback_fields <<<"${fallback4_metrics}"
    IFS=$'\t' read -r -a recovery_fields <<<"${recovery4_metrics}"
    ping4_transmitted="${fallback_fields[0]}"
    ping4_received="${fallback_fields[1]}"
    ping4_loss="${fallback_fields[2]}"
    ping4_first_after_fault_ms="${fallback_fields[3]}"
    ping4_max_gap="${fallback_fields[4]}"
    ping4_missing_after_fault="${fallback_fields[5]}"
    ping4_replies_after_fault="${fallback_fields[6]}"
    ping4_stable_after_unblock_ms="${recovery_fields[7]}"
    ping4_trailing_run="${recovery_fields[8]}"
  else
    ping4_parser_ok=false
  fi
  if fallback6_metrics="$("${restart_harness}" __parse-ping-log \
    "${temp_dir}/ping-v6.log" "${fault_start_ns}" "${fault_end_ns}")" &&
    recovery6_metrics="$("${restart_harness}" __parse-ping-log \
      "${temp_dir}/ping-v6.log" "${unblock_start_ns}" "${unblock_end_ns}")"; then
    IFS=$'\t' read -r -a fallback_fields <<<"${fallback6_metrics}"
    IFS=$'\t' read -r -a recovery_fields <<<"${recovery6_metrics}"
    ping6_transmitted="${fallback_fields[0]}"
    ping6_received="${fallback_fields[1]}"
    ping6_loss="${fallback_fields[2]}"
    ping6_first_after_fault_ms="${fallback_fields[3]}"
    ping6_max_gap="${fallback_fields[4]}"
    ping6_missing_after_fault="${fallback_fields[5]}"
    ping6_replies_after_fault="${fallback_fields[6]}"
    ping6_stable_after_unblock_ms="${recovery_fields[7]}"
    ping6_trailing_run="${recovery_fields[8]}"
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
    --argjson artifact_sha256 "${artifact_digest_json}" \
    --argjson underlay_v4_count "${#peer_underlay_v4[@]}" \
    --argjson underlay_v6_count "${#peer_underlay_v6[@]}" \
    --argjson fallback_timeout_seconds "${fallback_timeout_seconds}" \
    --argjson recovery_timeout_seconds "${recovery_timeout_seconds}" \
    --argjson lead_seconds "${lead_seconds}" \
    --argjson relay_hold_seconds "${relay_hold_seconds}" \
    --argjson tail_seconds "${tail_seconds}" \
    --argjson ping_interval "${ping_interval}" \
    --argjson poll_interval "${poll_interval}" \
    --argjson fallback_ms "${fallback_ms}" \
    --argjson direct_recovery_ms "${direct_recovery_ms}" \
    --argjson impairment_duration_ms "${impairment_duration_ms}" \
    --argjson output_dropped_packets "${output_dropped_packets}" \
    --argjson input_dropped_packets "${input_dropped_packets}" \
    --argjson cleanup_ok "${cleanup_ok}" \
    --argjson relay_ipv4_ok "${relay_ipv4_ok}" \
    --argjson relay_ipv6_ok "${relay_ipv6_ok}" \
    --argjson final_ready "${final_ready}" \
    --argjson ping4_exit_code "${ping4_exit_code}" \
    --argjson ping4_parser_ok "${ping4_parser_ok}" \
    --argjson ping4_transmitted "${ping4_transmitted}" \
    --argjson ping4_received "${ping4_received}" \
    --argjson ping4_loss "${ping4_loss}" \
    --argjson ping4_first_after_fault_ms "${ping4_first_after_fault_ms}" \
    --argjson ping4_max_gap "${ping4_max_gap}" \
    --argjson ping4_missing_after_fault "${ping4_missing_after_fault}" \
    --argjson ping4_replies_after_fault "${ping4_replies_after_fault}" \
    --argjson ping4_stable_after_unblock_ms "${ping4_stable_after_unblock_ms}" \
    --argjson ping4_trailing_run "${ping4_trailing_run}" \
    --argjson ping6_parser_ok "${ping6_parser_ok}" \
    --argjson ping6_exit_code "${ping6_exit_code}" \
    --argjson ping6_transmitted "${ping6_transmitted}" \
    --argjson ping6_received "${ping6_received}" \
    --argjson ping6_loss "${ping6_loss}" \
    --argjson ping6_first_after_fault_ms "${ping6_first_after_fault_ms}" \
    --argjson ping6_max_gap "${ping6_max_gap}" \
    --argjson ping6_missing_after_fault "${ping6_missing_after_fault}" \
    --argjson ping6_replies_after_fault "${ping6_replies_after_fault}" \
    --argjson ping6_stable_after_unblock_ms "${ping6_stable_after_unblock_ms}" \
    --argjson ping6_trailing_run "${ping6_trailing_run}" '
      {
        schema: $schema,
        started_at: $started_at,
        topology: {
          node_label: $node_label,
          peer_label: $peer_label,
          peer_count: 1,
          address_families: ["ipv4", "ipv6"],
          underlay_candidate_counts: {
            ipv4: $underlay_v4_count,
            ipv6: $underlay_v6_count
          }
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
          action: "drop_udp_to_explicit_peer_underlay_addresses",
          nftables_table: "meshd_relay_qual",
          changes_ssh: false,
          changes_control_or_relay_destinations: false,
          changes_default_route: false,
          changes_mesh_interfaces: false
        },
        observation: {
          lead_seconds: $lead_seconds,
          fallback_timeout_seconds: $fallback_timeout_seconds,
          relay_hold_seconds: $relay_hold_seconds,
          recovery_timeout_seconds: $recovery_timeout_seconds,
          tail_seconds: $tail_seconds,
          ping_interval_seconds: $ping_interval,
          status_poll_interval_seconds: $poll_interval,
          minimum_stable_replies: 3
        },
        impairment: {
          duration_ms: $impairment_duration_ms,
          output_dropped_packets: $output_dropped_packets,
          input_dropped_packets: $input_dropped_packets,
          cleanup_ok: $cleanup_ok
        },
        fallback: {
          relay_observed_ms: $fallback_ms,
          ipv4_traffic_over_relay: $relay_ipv4_ok,
          ipv6_traffic_over_relay: $relay_ipv6_ok
        },
        recovery: {
          direct_observed_ms: $direct_recovery_ms,
          final_ready: $final_ready
        },
        traffic: {
          ipv4: {
            command_exit_code: $ping4_exit_code,
            parser_ok: $ping4_parser_ok,
            transmitted: $ping4_transmitted,
            received: $ping4_received,
            loss_percent: $ping4_loss,
            first_reply_after_fault_ms: $ping4_first_after_fault_ms,
            maximum_consecutive_loss: $ping4_max_gap,
            missing_after_fault: $ping4_missing_after_fault,
            replies_after_fault: $ping4_replies_after_fault,
            stable_after_unblock_ms: $ping4_stable_after_unblock_ms,
            consecutive_replies_at_end: $ping4_trailing_run
          },
          ipv6: {
            command_exit_code: $ping6_exit_code,
            parser_ok: $ping6_parser_ok,
            transmitted: $ping6_transmitted,
            received: $ping6_received,
            loss_percent: $ping6_loss,
            first_reply_after_fault_ms: $ping6_first_after_fault_ms,
            maximum_consecutive_loss: $ping6_max_gap,
            missing_after_fault: $ping6_missing_after_fault,
            replies_after_fault: $ping6_replies_after_fault,
            stable_after_unblock_ms: $ping6_stable_after_unblock_ms,
            consecutive_replies_at_end: $ping6_trailing_run
          }
        }
      }
      | .failures = [
          if .impairment.output_dropped_packets < 1 then "direct_fault_not_exercised" else empty end,
          if .fallback.relay_observed_ms == null then "relay_fallback_not_observed" else empty end,
          if .fallback.relay_observed_ms != null and .fallback.relay_observed_ms > (.observation.fallback_timeout_seconds * 1000) then "relay_fallback_timeout" else empty end,
          if .fallback.ipv4_traffic_over_relay != true then "ipv4_relay_traffic_failed" else empty end,
          if .fallback.ipv6_traffic_over_relay != true then "ipv6_relay_traffic_failed" else empty end,
          if .impairment.cleanup_ok != true then "nftables_cleanup_failed" else empty end,
          if .recovery.direct_observed_ms == null then "direct_recovery_not_observed" else empty end,
          if .recovery.direct_observed_ms != null and .recovery.direct_observed_ms > (.observation.recovery_timeout_seconds * 1000) then "direct_recovery_timeout" else empty end,
          if .recovery.final_ready != true then "final_readiness_failed" else empty end,
          if .traffic.ipv4.parser_ok != true then "ipv4_probe_unparseable" else empty end,
          if .traffic.ipv6.parser_ok != true then "ipv6_probe_unparseable" else empty end,
          if .traffic.ipv4.command_exit_code != 0 then "ipv4_probe_failed" else empty end,
          if .traffic.ipv6.command_exit_code != 0 then "ipv6_probe_failed" else empty end,
          if .traffic.ipv4.stable_after_unblock_ms == null then "ipv4_did_not_stabilize" else empty end,
          if .traffic.ipv6.stable_after_unblock_ms == null then "ipv6_did_not_stabilize" else empty end,
          if .traffic.ipv4.stable_after_unblock_ms != null and .traffic.ipv4.stable_after_unblock_ms > (.observation.recovery_timeout_seconds * 1000) then "ipv4_stable_recovery_timeout" else empty end,
          if .traffic.ipv6.stable_after_unblock_ms != null and .traffic.ipv6.stable_after_unblock_ms > (.observation.recovery_timeout_seconds * 1000) then "ipv6_stable_recovery_timeout" else empty end
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

if [[ "${1:-}" == __validate-ipv4 ]]; then
  [[ $# -eq 2 ]] || fail "__validate-ipv4 requires ADDRESS"
  validate_ipv4 "$2"
  exit $?
fi
if [[ "${1:-}" == __validate-ipv6 ]]; then
  [[ $# -eq 2 ]] || fail "__validate-ipv6 requires ADDRESS"
  validate_ipv6 "$2"
  exit $?
fi
if [[ "${1:-}" == __render-nft-batch ]]; then
  shift
  test_v4=()
  test_v6=()
  while (( $# > 0 )); do
    case "$1" in
      --v4)
        [[ $# -ge 2 ]] || fail "--v4 requires ADDRESS"
        validate_ipv4 "$2" || fail "invalid IPv4 address"
        test_v4+=("$2")
        shift 2
        ;;
      --v6)
        [[ $# -ge 2 ]] || fail "--v6 requires ADDRESS"
        validate_ipv6 "$2" || fail "invalid IPv6 address"
        test_v6+=("$2")
        shift 2
        ;;
      *)
        fail "unknown render argument: $1"
        ;;
    esac
  done
  (( ${#test_v4[@]} + ${#test_v6[@]} > 0 )) || fail "an address is required"
  render_nft_batch test_v4[@] test_v6[@]
  exit 0
fi

main "$@"
