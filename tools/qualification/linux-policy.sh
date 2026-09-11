#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-policy-qualification/v1"

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly peer_helper="${script_dir}/testdata/policy_peer.py"

node_a_ssh=""
node_b_ssh=""
node_a_remote_dir=""
node_b_remote_dir=""
ssh_connect_timeout_seconds=3
declare -a ssh_command=(ssh)
declare -a copy_command=(scp)

usage() {
  cat <<'EOF'
Usage:
  tools/qualification/linux-policy.sh \
    --node-a-ssh USER@HOST \
    --node-b-ssh USER@HOST \
    --node-a-label LABEL \
    --node-b-label LABEL \
    --node-a-v4 ADDRESS \
    --node-a-v6 ADDRESS \
    --node-b-v4 ADDRESS \
    --node-b-v6 ADDRESS \
    --phase-label LABEL \
    --expect-a-to-b-tcp allow|deny \
    --expect-a-to-b-udp allow|deny \
    --expect-a-to-b-icmp4 allow|deny \
    --expect-a-to-b-icmp6 allow|deny \
    --expect-b-to-a-tcp allow|deny \
    --expect-b-to-a-udp allow|deny \
    --expect-b-to-a-icmp4 allow|deny \
    --expect-b-to-a-icmp6 allow|deny \
    --artifact-sha256 HEX \
    --confirm-policy-test PHASE_LABEL \
    [--tcp-port PORT] \
    [--udp-port PORT] \
    [--probe-timeout-seconds N] \
    [--ssh-connect-timeout-seconds N] \
    [--ssh-driver ssh|rtk]

Runs a bounded dual-stack host-policy phase from an operator host. It creates
temporary TCP and UDP challenge listeners on both registered Linux nodes and
checks new TCP, UDP, ICMPv4, and ICMPv6 flows in both directions. The harness
does not change control policy, profiles, routes, DNS, packages, or services.
It fails if meshd restarts on either node and records bounded service-memory evidence.
The JSON report excludes SSH destinations, overlay addresses, and payloads.
EOF
}

fail() {
  printf 'linux-policy: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-policy: %s\n' "$*" >&2
}

require_command() {
  local command_name="$1"

  command -v "${command_name}" >/dev/null 2>&1 ||
    fail "required command not found: ${command_name}"
}

validate_label() {
  local label="$1"
  local value="$2"

  [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] ||
    fail "${label} must be 1-64 safe label characters"
}

validate_ssh_destination() {
  local value="$1"

  [[ "${value}" =~ ^[A-Za-z0-9_.-]+@[A-Za-z0-9_.:-]+$ ]] ||
    fail "SSH destinations must use USER@HOST without shell metacharacters"
}

validate_overlay_addresses() {
  local ipv4="$1"
  local ipv6="$2"

  [[ "${ipv4}" =~ ^[0-9.]+$ ]] ||
    fail "IPv4 values must contain only digits and dots"
  [[ "${ipv6}" =~ ^[0-9A-Fa-f:]+$ ]] ||
    fail "IPv6 values must not contain a zone or shell metacharacters"
}

validate_expectation() {
  local value="$1"

  [[ "${value}" == allow || "${value}" == deny ]] ||
    fail "policy expectations must be allow or deny"
}

validate_port() {
  local label="$1"
  local value="$2"

  if [[ ! "${value}" =~ ^[0-9]+$ ]] || ((value < 1024 || value > 65535)); then
    fail "${label} must be an integer between 1024 and 65535"
  fi
}

validate_positive_integer() {
  local label="$1"
  local value="$2"
  local maximum="$3"

  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]] || ((value > maximum)); then
    fail "${label} must be an integer between 1 and ${maximum}"
  fi
}

validate_remote_dir() {
  local value="$1"

  [[ "${value}" =~ ^/tmp/meshd-policy\.[A-Za-z0-9]{8,16}$ ]] ||
    fail "remote host returned an unsafe temporary directory"
}

now_ms() {
  python3 -c 'import time; print(time.time_ns() // 1000000)'
}

remote_exec() {
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

parse_service_metrics() {
  local raw="$1"
  local main_pid=""
  local restarts=""
  local memory_current=""
  local memory_peak=""
  local key
  local value

  while IFS='=' read -r key value; do
    case "${key}" in
      MainPID) main_pid="${value}" ;;
      NRestarts) restarts="${value}" ;;
      MemoryCurrent) memory_current="${value}" ;;
      MemoryPeak) memory_peak="${value}" ;;
    esac
  done <<<"${raw}"
  for value in "${main_pid}" "${restarts}" "${memory_current}" "${memory_peak}"; do
    [[ "${value}" =~ ^[0-9]+$ ]] || return 1
  done
  ((10#${main_pid} > 0)) || return 1

  jq -cn \
    --argjson main_pid "${main_pid}" \
    --argjson restarts "${restarts}" \
    --argjson memory_current "${memory_current}" \
    --argjson memory_peak "${memory_peak}" \
    '{main_pid:$main_pid,restarts:$restarts,memory_current_bytes:$memory_current,memory_peak_bytes:$memory_peak}'
}

collect_service_metrics() {
  local destination="$1"
  local raw

  raw="$(remote_exec "${destination}" \
    "systemctl show meshd.service -p MainPID -p NRestarts -p MemoryCurrent -p MemoryPeak --no-pager")" ||
    return 1
  parse_service_metrics "${raw}"
}

compare_service_metrics() {
  local before="$1"
  local after="$2"

  jq -cn \
    --argjson before "${before}" \
    --argjson after "${after}" '
      {
        service_pid_stable: ($before.main_pid == $after.main_pid),
        restarts: {before:$before.restarts, after:$after.restarts},
        memory_current_bytes: {
          before:$before.memory_current_bytes,
          after:$after.memory_current_bytes
        },
        memory_peak_bytes: {
          before:$before.memory_peak_bytes,
          after:$after.memory_peak_bytes
        }
      }
    '
}

copy_helper() {
  local destination="$1"
  local remote_dir="$2"

  "${copy_command[@]}" \
    -q \
    -o BatchMode=yes \
    -o ConnectTimeout="${ssh_connect_timeout_seconds}" \
    -o StrictHostKeyChecking=yes \
    "${peer_helper}" \
    "${destination}:${remote_dir}/policy_peer.py"
  remote_exec "${destination}" \
    "chown meshd:meshd ${remote_dir}/policy_peer.py && chmod 0500 ${remote_dir}/policy_peer.py"
}

cleanup_remote() {
  local destination="$1"
  local remote_dir="$2"
  local command

  [[ -n "${destination}" && -n "${remote_dir}" ]] || return
  command="pid=''; if test -f ${remote_dir}/server.pid; then pid=\$(cat ${remote_dir}/server.pid 2>/dev/null || true); fi; case \"\${pid}\" in ''|*[!0-9]*) ;; *) kill \"\${pid}\" >/dev/null 2>&1 || true ;; esac; rm -f -- ${remote_dir}/server.pid ${remote_dir}/ready ${remote_dir}/policy_peer.py; rmdir -- ${remote_dir} >/dev/null 2>&1 || true"
  remote_exec "${destination}" "${command}" >/dev/null 2>&1 || true
}

cleanup() {
  set +e
  cleanup_remote "${node_a_ssh}" "${node_a_remote_dir}"
  cleanup_remote "${node_b_ssh}" "${node_b_remote_dir}"
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

status_is_ready() {
  local status="$1"
  local require_online="$2"

  jq -e --argjson require_online "${require_online}" '
    (
      .state == "online" or
      ($require_online == false and .state == "offline" and .data_plane == "idle")
    ) and
    .control_session == "synchronized" and
    .registration == "registered" and
    (.data_plane | type) == "string" and
    .data_plane != "failed" and
    .data_plane != "not_implemented" and
    (.policy_rule_count | type) == "number" and
    (.netmap_revision | type) == "number" and
    (.self_addresses | type) == "array"
  ' >/dev/null <<<"${status}"
}

status_has_addresses() {
  local status="$1"
  local ipv4="$2"
  local ipv6="$3"

  jq -e --arg ipv4 "${ipv4}/32" --arg ipv6 "${ipv6}/128" '
    (.self_addresses | index($ipv4)) != null and
    (.self_addresses | index($ipv6)) != null
  ' >/dev/null <<<"${status}"
}

status_has_peer_path() {
  local status="$1"

  jq -e '
    .peer_count >= 1 and
    .paths.available == true and
    .paths.peer_count >= 1 and
    (.data_plane | startswith("encrypted_"))
  ' >/dev/null <<<"${status}"
}

any_mesh_route() {
  [[ "$1" == true || "$2" == true || "$3" == true || "$4" == true ]]
}

mesh_route_present() {
  local source_ssh="$1"
  local family="$2"
  local destination="$3"

  remote_exec "${source_ssh}" \
    "ip -${family} route get ${destination} | grep -Fq ' dev mesh0 '" >/dev/null 2>&1
}

policy_peer_is_ready() {
  local destination="$1"
  local remote_dir="$2"

  remote_exec "${destination}" \
    "test -f ${remote_dir}/ready && kill -0 \$(cat ${remote_dir}/server.pid)" \
    >/dev/null 2>&1
}

classify_helper_probe() {
  local exit_code="$1"

  case "${exit_code}" in
    0) printf 'allow\n' ;;
    10) printf 'deny\n' ;;
    *) printf 'error\n' ;;
  esac
}

classify_ping_probe() {
  local exit_code="$1"

  case "${exit_code}" in
    0) printf 'allow\n' ;;
    1|2) printf 'deny\n' ;;
    *) printf 'error\n' ;;
  esac
}

main() {
  local node_a_label=""
  local node_b_label=""
  local node_a_v4=""
  local node_a_v6=""
  local node_b_v4=""
  local node_b_v6=""
  local phase_label=""
  local artifact_sha256=""
  local confirmation=""
  local ssh_driver=ssh
  local tcp_port=31870
  local udp_port=31871
  local probe_timeout_seconds=2
  local node_a_status
  local node_b_status
  local node_a_metrics_before
  local node_b_metrics_before
  local node_a_metrics_after
  local node_b_metrics_after
  local node_a_runtime
  local node_b_runtime
  local started_at
  local any_allow=false
  local evidence_complete=true
  local helper_exit
  local actual
  local direction
  local protocol
  local source_ssh
  local source_dir
  local source_address
  local destination_address
  local destination_port
  local family_flag
  local icmp_identifier
  local route_present
  local node_a_route4=false
  local node_a_route6=false
  local node_b_route4=false
  local node_b_route6=false
  local node_a_listener_ready=false
  local node_b_listener_ready=false
  local start_ms
  local end_ms
  local mismatch_count=0
  local infrastructure_error_count=0
  local expected_json
  local observed_json
  local durations_json
  local exit_codes_json
  local report
  local outcome
  local command_name
  local expect_a_to_b_tcp=""
  local expect_a_to_b_udp=""
  local expect_a_to_b_icmp4=""
  local expect_a_to_b_icmp6=""
  local expect_b_to_a_tcp=""
  local expect_b_to_a_udp=""
  local expect_b_to_a_icmp4=""
  local expect_b_to_a_icmp6=""
  local probe_index=0
  local index
  declare -a expected=()
  declare -a observed=()
  declare -a durations=()
  declare -a exit_codes=()

  while (($# > 0)); do
    case "$1" in
      --node-a-ssh) node_a_ssh="${2:-}"; shift 2 ;;
      --node-b-ssh) node_b_ssh="${2:-}"; shift 2 ;;
      --node-a-label) node_a_label="${2:-}"; shift 2 ;;
      --node-b-label) node_b_label="${2:-}"; shift 2 ;;
      --node-a-v4) node_a_v4="${2:-}"; shift 2 ;;
      --node-a-v6) node_a_v6="${2:-}"; shift 2 ;;
      --node-b-v4) node_b_v4="${2:-}"; shift 2 ;;
      --node-b-v6) node_b_v6="${2:-}"; shift 2 ;;
      --phase-label) phase_label="${2:-}"; shift 2 ;;
      --artifact-sha256) artifact_sha256="${2:-}"; shift 2 ;;
      --confirm-policy-test) confirmation="${2:-}"; shift 2 ;;
      --ssh-driver) ssh_driver="${2:-}"; shift 2 ;;
      --tcp-port) tcp_port="${2:-}"; shift 2 ;;
      --udp-port) udp_port="${2:-}"; shift 2 ;;
      --probe-timeout-seconds) probe_timeout_seconds="${2:-}"; shift 2 ;;
      --ssh-connect-timeout-seconds) ssh_connect_timeout_seconds="${2:-}"; shift 2 ;;
      --expect-a-to-b-tcp) expect_a_to_b_tcp="${2:-}"; shift 2 ;;
      --expect-a-to-b-udp) expect_a_to_b_udp="${2:-}"; shift 2 ;;
      --expect-a-to-b-icmp4) expect_a_to_b_icmp4="${2:-}"; shift 2 ;;
      --expect-a-to-b-icmp6) expect_a_to_b_icmp6="${2:-}"; shift 2 ;;
      --expect-b-to-a-tcp) expect_b_to_a_tcp="${2:-}"; shift 2 ;;
      --expect-b-to-a-udp) expect_b_to_a_udp="${2:-}"; shift 2 ;;
      --expect-b-to-a-icmp4) expect_b_to_a_icmp4="${2:-}"; shift 2 ;;
      --expect-b-to-a-icmp6) expect_b_to_a_icmp6="${2:-}"; shift 2 ;;
      --help|-h) usage; return 0 ;;
      *) fail "unknown or incomplete argument: $1" ;;
    esac
  done

  [[ -n "${node_a_ssh}" && -n "${node_b_ssh}" ]] ||
    fail "--node-a-ssh and --node-b-ssh are required"
  [[ -n "${node_a_label}" && -n "${node_b_label}" ]] ||
    fail "--node-a-label and --node-b-label are required"
  [[ -n "${node_a_v4}" && -n "${node_a_v6}" ]] ||
    fail "--node-a-v4 and --node-a-v6 are required"
  [[ -n "${node_b_v4}" && -n "${node_b_v6}" ]] ||
    fail "--node-b-v4 and --node-b-v6 are required"
  [[ -n "${phase_label}" ]] || fail "--phase-label is required"
  [[ -n "${artifact_sha256}" ]] || fail "--artifact-sha256 is required"

  validate_ssh_destination "${node_a_ssh}"
  validate_ssh_destination "${node_b_ssh}"
  [[ "${node_a_ssh}" != "${node_b_ssh}" ]] || fail "node SSH destinations must differ"
  validate_label node-a-label "${node_a_label}"
  validate_label node-b-label "${node_b_label}"
  [[ "${node_a_label}" != "${node_b_label}" ]] || fail "node labels must differ"
  validate_label phase-label "${phase_label}"
  [[ "${confirmation}" == "${phase_label}" ]] ||
    fail "--confirm-policy-test must exactly match --phase-label"
  validate_overlay_addresses "${node_a_v4}" "${node_a_v6}"
  validate_overlay_addresses "${node_b_v4}" "${node_b_v6}"
  [[ "${node_a_v4}" != "${node_b_v4}" && "${node_a_v6}" != "${node_b_v6}" ]] ||
    fail "node overlay addresses must differ"
  [[ "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]] ||
    fail "artifact-sha256 must contain exactly 64 hexadecimal characters"
  validate_port tcp-port "${tcp_port}"
  validate_port udp-port "${udp_port}"
  validate_positive_integer probe-timeout-seconds "${probe_timeout_seconds}" 10
  validate_positive_integer ssh-connect-timeout-seconds "${ssh_connect_timeout_seconds}" 30

  expected=(
    "${expect_a_to_b_tcp}"
    "${expect_a_to_b_tcp}"
    "${expect_a_to_b_udp}"
    "${expect_a_to_b_udp}"
    "${expect_a_to_b_icmp4}"
    "${expect_a_to_b_icmp6}"
    "${expect_b_to_a_tcp}"
    "${expect_b_to_a_tcp}"
    "${expect_b_to_a_udp}"
    "${expect_b_to_a_udp}"
    "${expect_b_to_a_icmp4}"
    "${expect_b_to_a_icmp6}"
  )
  for index in 0 1 2 3 4 5 6 7 8 9 10 11; do
    [[ -n "${expected[${index}]}" ]] || fail "every directional protocol expectation is required"
    validate_expectation "${expected[${index}]}"
    [[ "${expected[${index}]}" == allow ]] && any_allow=true
  done

  for command_name in date jq mktemp python3 scp ssh; do
    require_command "${command_name}"
  done
  [[ -x "${peer_helper}" ]] || fail "policy peer helper is unavailable or not executable"

  case "${ssh_driver}" in
    ssh)
      ssh_command=(ssh)
      copy_command=(scp)
      ;;
    rtk)
      require_command rtk
      ssh_command=(rtk proxy ssh)
      copy_command=(rtk proxy scp)
      ;;
    *) fail "ssh-driver must be ssh or rtk" ;;
  esac

  progress "checking both Linux nodes"
  for source_ssh in "${node_a_ssh}" "${node_b_ssh}"; do
    remote_exec "${source_ssh}" \
      "command -v python3 >/dev/null && command -v setpriv >/dev/null && command -v ping >/dev/null && id meshd >/dev/null 2>&1 && systemctl is-active --quiet meshd.service meshnetd.service" ||
      fail "remote prerequisite check failed"
  done

  node_a_status="$(remote_exec "${node_a_ssh}" "meshctl --timeout 3s --json status")" ||
    fail "node A status is unavailable"
  node_b_status="$(remote_exec "${node_b_ssh}" "meshctl --timeout 3s --json status")" ||
    fail "node B status is unavailable"
  status_is_ready "${node_a_status}" "${any_allow}" ||
    fail "node A is not synchronized and ready for the expected phase"
  status_is_ready "${node_b_status}" "${any_allow}" ||
    fail "node B is not synchronized and ready for the expected phase"
  status_has_addresses "${node_a_status}" "${node_a_v4}" "${node_a_v6}" ||
    fail "node A status does not contain the expected self addresses"
  status_has_addresses "${node_b_status}" "${node_b_v4}" "${node_b_v6}" ||
    fail "node B status does not contain the expected self addresses"
  node_a_metrics_before="$(collect_service_metrics "${node_a_ssh}")" ||
    fail "node A service metrics are unavailable"
  node_b_metrics_before="$(collect_service_metrics "${node_b_ssh}")" ||
    fail "node B service metrics are unavailable"
  if mesh_route_present "${node_a_ssh}" 4 "${node_b_v4}"; then
    node_a_route4=true
  fi
  if mesh_route_present "${node_a_ssh}" 6 "${node_b_v6}"; then
    node_a_route6=true
  fi
  if mesh_route_present "${node_b_ssh}" 4 "${node_a_v4}"; then
    node_b_route4=true
  fi
  if mesh_route_present "${node_b_ssh}" 6 "${node_a_v6}"; then
    node_b_route6=true
  fi
  if [[ "${any_allow}" == true ]]; then
    status_has_peer_path "${node_a_status}" || fail "node A has no encrypted peer path"
    status_has_peer_path "${node_b_status}" || fail "node B has no encrypted peer path"
    [[ "${node_a_route4}" == true && "${node_a_route6}" == true ]] ||
      fail "node A dual-stack mesh routes are unavailable"
    [[ "${node_b_route4}" == true && "${node_b_route6}" == true ]] ||
      fail "node B dual-stack mesh routes are unavailable"
  fi

  if any_mesh_route \
    "${node_a_route4}" "${node_a_route6}" "${node_b_route4}" "${node_b_route6}"; then
    node_a_remote_dir="$(remote_exec "${node_a_ssh}" "mktemp -d /tmp/meshd-policy.XXXXXXXX")" ||
      fail "could not create node A temporary directory"
    validate_remote_dir "${node_a_remote_dir}"
    node_b_remote_dir="$(remote_exec "${node_b_ssh}" "mktemp -d /tmp/meshd-policy.XXXXXXXX")" ||
      fail "could not create node B temporary directory"
    validate_remote_dir "${node_b_remote_dir}"
    remote_exec "${node_a_ssh}" "chown meshd:meshd ${node_a_remote_dir} && chmod 0700 ${node_a_remote_dir}"
    remote_exec "${node_b_ssh}" "chown meshd:meshd ${node_b_remote_dir} && chmod 0700 ${node_b_remote_dir}"
    copy_helper "${node_a_ssh}" "${node_a_remote_dir}"
    copy_helper "${node_b_ssh}" "${node_b_remote_dir}"

    progress "starting bounded peer listeners"
    remote_exec "${node_a_ssh}" \
      "setpriv --reuid=meshd --regid=meshd --init-groups -- python3 ${node_a_remote_dir}/policy_peer.py serve --address ${node_a_v4} --address ${node_a_v6} --tcp-port ${tcp_port} --udp-port ${udp_port} --ready-file ${node_a_remote_dir}/ready >/dev/null 2>&1 & echo \$! >${node_a_remote_dir}/server.pid"
    remote_exec "${node_b_ssh}" \
      "setpriv --reuid=meshd --regid=meshd --init-groups -- python3 ${node_b_remote_dir}/policy_peer.py serve --address ${node_b_v4} --address ${node_b_v6} --tcp-port ${tcp_port} --udp-port ${udp_port} --ready-file ${node_b_remote_dir}/ready >/dev/null 2>&1 & echo \$! >${node_b_remote_dir}/server.pid"

    for _ in {1..20}; do
      if [[ "${node_a_listener_ready}" != true ]] &&
        policy_peer_is_ready "${node_a_ssh}" "${node_a_remote_dir}"; then
        node_a_listener_ready=true
      fi
      if [[ "${node_b_listener_ready}" != true ]] &&
        policy_peer_is_ready "${node_b_ssh}" "${node_b_remote_dir}"; then
        node_b_listener_ready=true
      fi
      if [[ "${node_a_listener_ready}" == true && "${node_b_listener_ready}" == true ]]; then
        break
      fi
      sleep 0.25
    done
    if [[ "${node_a_listener_ready}" != true ]]; then
      node_b_route4=false
      node_b_route6=false
      mesh_route_present "${node_b_ssh}" 4 "${node_a_v4}" && node_b_route4=true
      mesh_route_present "${node_b_ssh}" 6 "${node_a_v6}" && node_b_route6=true
      if [[ "${node_b_route4}" == true || "${node_b_route6}" == true ]]; then
        fail "node A policy peer did not become ready while an inbound mesh route remained"
      fi
      progress "node A listener became unnecessary after its inbound mesh routes were removed"
    fi
    if [[ "${node_b_listener_ready}" != true ]]; then
      node_a_route4=false
      node_a_route6=false
      mesh_route_present "${node_a_ssh}" 4 "${node_b_v4}" && node_a_route4=true
      mesh_route_present "${node_a_ssh}" 6 "${node_b_v6}" && node_a_route6=true
      if [[ "${node_a_route4}" == true || "${node_a_route6}" == true ]]; then
        fail "node B policy peer did not become ready while an inbound mesh route remained"
      fi
      progress "node B listener became unnecessary after its inbound mesh routes were removed"
    fi
  else
    progress "no mesh routes are present; recording route-level deny evidence"
  fi

  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for direction in a_to_b b_to_a; do
    if [[ "${direction}" == a_to_b ]]; then
      source_ssh="${node_a_ssh}"
      source_dir="${node_a_remote_dir}"
    else
      source_ssh="${node_b_ssh}"
      source_dir="${node_b_remote_dir}"
    fi
    for protocol in tcp4 tcp6 udp4 udp6 icmp4 icmp6; do
      destination_port="${tcp_port}"
      family_flag=""
      icmp_identifier=""
      route_present=true
      case "${direction}_${protocol}" in
        a_to_b_tcp4)
          source_address="${node_a_v4}"; destination_address="${node_b_v4}"
          route_present="${node_a_route4}"
          ;;
        a_to_b_tcp6)
          source_address="${node_a_v6}"; destination_address="${node_b_v6}"
          route_present="${node_a_route6}"
          ;;
        a_to_b_udp4)
          source_address="${node_a_v4}"; destination_address="${node_b_v4}"
          destination_port="${udp_port}"; route_present="${node_a_route4}"
          ;;
        a_to_b_udp6)
          source_address="${node_a_v6}"; destination_address="${node_b_v6}"
          destination_port="${udp_port}"; route_present="${node_a_route6}"
          ;;
        a_to_b_icmp4)
          destination_address="${node_b_v4}"; family_flag=-4; icmp_identifier=12001
          route_present="${node_a_route4}"
          ;;
        a_to_b_icmp6)
          destination_address="${node_b_v6}"; family_flag=-6; icmp_identifier=12002
          route_present="${node_a_route6}"
          ;;
        b_to_a_tcp4)
          source_address="${node_b_v4}"; destination_address="${node_a_v4}"
          route_present="${node_b_route4}"
          ;;
        b_to_a_tcp6)
          source_address="${node_b_v6}"; destination_address="${node_a_v6}"
          route_present="${node_b_route6}"
          ;;
        b_to_a_udp4)
          source_address="${node_b_v4}"; destination_address="${node_a_v4}"
          destination_port="${udp_port}"; route_present="${node_b_route4}"
          ;;
        b_to_a_udp6)
          source_address="${node_b_v6}"; destination_address="${node_a_v6}"
          destination_port="${udp_port}"; route_present="${node_b_route6}"
          ;;
        b_to_a_icmp4)
          destination_address="${node_a_v4}"; family_flag=-4; icmp_identifier=22001
          route_present="${node_b_route4}"
          ;;
        b_to_a_icmp6)
          destination_address="${node_a_v6}"; family_flag=-6; icmp_identifier=22002
          route_present="${node_b_route6}"
          ;;
      esac

      start_ms="$(now_ms)"
      helper_exit=0
      if [[ "${route_present}" != true ]]; then
        helper_exit=90
        actual=deny
      elif [[ "${protocol}" == tcp4 || "${protocol}" == tcp6 ||
        "${protocol}" == udp4 || "${protocol}" == udp6 ]]; then
        remote_exec "${source_ssh}" \
          "setpriv --reuid=meshd --regid=meshd --init-groups -- python3 ${source_dir}/policy_peer.py probe --protocol ${protocol%?} --source-address ${source_address} --address ${destination_address} --port ${destination_port} --timeout ${probe_timeout_seconds}" \
          >/dev/null 2>&1 || helper_exit=$?
        actual="$(classify_helper_probe "${helper_exit}")"
      else
        remote_exec "${source_ssh}" \
          "ping ${family_flag} -n -c 1 -W ${probe_timeout_seconds} -e ${icmp_identifier} ${destination_address}" \
          >/dev/null 2>&1 || helper_exit=$?
        actual="$(classify_ping_probe "${helper_exit}")"
      fi
      end_ms="$(now_ms)"
      observed[probe_index]="${actual}"
      durations[probe_index]="$((end_ms - start_ms))"
      exit_codes[probe_index]="${helper_exit}"
      if [[ "${actual}" == error ]]; then
        infrastructure_error_count=$((infrastructure_error_count + 1))
      elif [[ "${actual}" != "${expected[${probe_index}]}" ]]; then
        mismatch_count=$((mismatch_count + 1))
      fi
      probe_index=$((probe_index + 1))
    done
  done

  if [[ "${node_a_listener_ready}" == true ]] &&
    ! policy_peer_is_ready "${node_a_ssh}" "${node_a_remote_dir}"; then
    if [[ "${any_allow}" == true ]] ||
      mesh_route_present "${node_b_ssh}" 4 "${node_a_v4}" ||
      mesh_route_present "${node_b_ssh}" 6 "${node_a_v6}"; then
      infrastructure_error_count=$((infrastructure_error_count + 1))
    else
      node_b_route4=false
      node_b_route6=false
    fi
  fi
  if [[ "${node_b_listener_ready}" == true ]] &&
    ! policy_peer_is_ready "${node_b_ssh}" "${node_b_remote_dir}"; then
    if [[ "${any_allow}" == true ]] ||
      mesh_route_present "${node_a_ssh}" 4 "${node_b_v4}" ||
      mesh_route_present "${node_a_ssh}" 6 "${node_b_v6}"; then
      infrastructure_error_count=$((infrastructure_error_count + 1))
    else
      node_a_route4=false
      node_a_route6=false
    fi
  fi

  node_a_metrics_after="$(collect_service_metrics "${node_a_ssh}")" ||
    fail "node A post-probe service metrics are unavailable"
  node_b_metrics_after="$(collect_service_metrics "${node_b_ssh}")" ||
    fail "node B post-probe service metrics are unavailable"
  node_a_runtime="$(compare_service_metrics \
    "${node_a_metrics_before}" "${node_a_metrics_after}")"
  node_b_runtime="$(compare_service_metrics \
    "${node_b_metrics_before}" "${node_b_metrics_after}")"

  expected_json="$(jq -n \
    --arg a_tcp "${expected[0]}" --arg a_udp "${expected[2]}" \
    --arg a_i4 "${expected[4]}" --arg a_i6 "${expected[5]}" \
    --arg b_tcp "${expected[6]}" --arg b_udp "${expected[8]}" \
    --arg b_i4 "${expected[10]}" --arg b_i6 "${expected[11]}" \
    '{a_to_b:{tcp:{ipv4:$a_tcp,ipv6:$a_tcp},udp:{ipv4:$a_udp,ipv6:$a_udp},icmp4:$a_i4,icmp6:$a_i6},b_to_a:{tcp:{ipv4:$b_tcp,ipv6:$b_tcp},udp:{ipv4:$b_udp,ipv6:$b_udp},icmp4:$b_i4,icmp6:$b_i6}}')"
  observed_json="$(jq -n \
    --arg a_tcp4 "${observed[0]}" --arg a_tcp6 "${observed[1]}" \
    --arg a_udp4 "${observed[2]}" --arg a_udp6 "${observed[3]}" \
    --arg a_i4 "${observed[4]}" --arg a_i6 "${observed[5]}" \
    --arg b_tcp4 "${observed[6]}" --arg b_tcp6 "${observed[7]}" \
    --arg b_udp4 "${observed[8]}" --arg b_udp6 "${observed[9]}" \
    --arg b_i4 "${observed[10]}" --arg b_i6 "${observed[11]}" \
    '{a_to_b:{tcp:{ipv4:$a_tcp4,ipv6:$a_tcp6},udp:{ipv4:$a_udp4,ipv6:$a_udp6},icmp4:$a_i4,icmp6:$a_i6},b_to_a:{tcp:{ipv4:$b_tcp4,ipv6:$b_tcp6},udp:{ipv4:$b_udp4,ipv6:$b_udp6},icmp4:$b_i4,icmp6:$b_i6}}')"
  durations_json="$(jq -n \
    --argjson a_tcp4 "${durations[0]}" --argjson a_tcp6 "${durations[1]}" \
    --argjson a_udp4 "${durations[2]}" --argjson a_udp6 "${durations[3]}" \
    --argjson a_i4 "${durations[4]}" --argjson a_i6 "${durations[5]}" \
    --argjson b_tcp4 "${durations[6]}" --argjson b_tcp6 "${durations[7]}" \
    --argjson b_udp4 "${durations[8]}" --argjson b_udp6 "${durations[9]}" \
    --argjson b_i4 "${durations[10]}" --argjson b_i6 "${durations[11]}" \
    '{a_to_b:{tcp:{ipv4:$a_tcp4,ipv6:$a_tcp6},udp:{ipv4:$a_udp4,ipv6:$a_udp6},icmp4:$a_i4,icmp6:$a_i6},b_to_a:{tcp:{ipv4:$b_tcp4,ipv6:$b_tcp6},udp:{ipv4:$b_udp4,ipv6:$b_udp6},icmp4:$b_i4,icmp6:$b_i6}}')"
  exit_codes_json="$(jq -n \
    --argjson a_tcp4 "${exit_codes[0]}" --argjson a_tcp6 "${exit_codes[1]}" \
    --argjson a_udp4 "${exit_codes[2]}" --argjson a_udp6 "${exit_codes[3]}" \
    --argjson a_i4 "${exit_codes[4]}" --argjson a_i6 "${exit_codes[5]}" \
    --argjson b_tcp4 "${exit_codes[6]}" --argjson b_tcp6 "${exit_codes[7]}" \
    --argjson b_udp4 "${exit_codes[8]}" --argjson b_udp6 "${exit_codes[9]}" \
    --argjson b_i4 "${exit_codes[10]}" --argjson b_i6 "${exit_codes[11]}" \
    '{a_to_b:{tcp:{ipv4:$a_tcp4,ipv6:$a_tcp6},udp:{ipv4:$a_udp4,ipv6:$a_udp6},icmp4:$a_i4,icmp6:$a_i6},b_to_a:{tcp:{ipv4:$b_tcp4,ipv6:$b_tcp6},udp:{ipv4:$b_udp4,ipv6:$b_udp6},icmp4:$b_i4,icmp6:$b_i6}}')"

  report="$(jq -n \
    --arg schema "${schema_version}" \
    --arg started_at "${started_at}" \
    --arg phase_label "${phase_label}" \
    --arg node_a_label "${node_a_label}" \
    --arg node_b_label "${node_b_label}" \
    --arg artifact_sha256 "${artifact_sha256}" \
    --arg node_a_version "$(jq -r '.daemon.version' <<<"${node_a_status}")" \
    --arg node_a_commit "$(jq -r '.daemon.commit' <<<"${node_a_status}")" \
    --arg node_b_version "$(jq -r '.daemon.version' <<<"${node_b_status}")" \
    --arg node_b_commit "$(jq -r '.daemon.commit' <<<"${node_b_status}")" \
    --argjson node_a_revision "$(jq -r '.netmap_revision' <<<"${node_a_status}")" \
    --argjson node_b_revision "$(jq -r '.netmap_revision' <<<"${node_b_status}")" \
    --argjson node_a_rules "$(jq -r '.policy_rule_count' <<<"${node_a_status}")" \
    --argjson node_b_rules "$(jq -r '.policy_rule_count' <<<"${node_b_status}")" \
    --argjson node_a_route4 "${node_a_route4}" \
    --argjson node_a_route6 "${node_a_route6}" \
    --argjson node_b_route4 "${node_b_route4}" \
    --argjson node_b_route6 "${node_b_route6}" \
    --argjson node_a_runtime "${node_a_runtime}" \
    --argjson node_b_runtime "${node_b_runtime}" \
    --argjson tcp_port "${tcp_port}" \
    --argjson udp_port "${udp_port}" \
    --argjson probe_timeout "${probe_timeout_seconds}" \
    --argjson evidence_complete "${evidence_complete}" \
    --argjson mismatch_count "${mismatch_count}" \
    --argjson infrastructure_error_count "${infrastructure_error_count}" \
    --argjson expected "${expected_json}" \
    --argjson observed "${observed_json}" \
    --argjson durations "${durations_json}" \
    --argjson exit_codes "${exit_codes_json}" '
      {
        schema: $schema,
        started_at: $started_at,
        phase: $phase_label,
        topology: {
          node_a_label: $node_a_label,
          node_b_label: $node_b_label,
          address_families: ["ipv4", "ipv6"]
        },
        artifact: {
          sha256: $artifact_sha256,
          evidence_complete: $evidence_complete,
          node_a: {version: $node_a_version, commit: $node_a_commit},
          node_b: {version: $node_b_version, commit: $node_b_commit},
          same_runtime: ($node_a_version == $node_b_version and $node_a_commit == $node_b_commit)
        },
        policy: {
          node_a: {netmap_revision: $node_a_revision, rule_count: $node_a_rules},
          node_b: {netmap_revision: $node_b_revision, rule_count: $node_b_rules}
        },
        mesh_route_present: {
          a_to_b: {ipv4: $node_a_route4, ipv6: $node_a_route6},
          b_to_a: {ipv4: $node_b_route4, ipv6: $node_b_route6}
        },
        runtime: {node_a:$node_a_runtime, node_b:$node_b_runtime},
        listeners: {tcp_port: $tcp_port, udp_port: $udp_port},
        probe_timeout_seconds: $probe_timeout,
        expected: $expected,
        observed: $observed,
        duration_ms: $durations,
        remote_exit_codes: $exit_codes,
        mismatch_count: $mismatch_count,
        infrastructure_error_count: $infrastructure_error_count
      }
      | .failures = [
          if .artifact.same_runtime != true then "runtime_mismatch" else empty end,
          if ([.runtime.node_a, .runtime.node_b] | all(
            .service_pid_stable and .restarts.before == .restarts.after
          ) | not) then "daemon_restarted" else empty end,
          if .mismatch_count != 0 then "policy_expectation_mismatch" else empty end,
          if .infrastructure_error_count != 0 then "probe_infrastructure_error" else empty end
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

if [[ "${1:-}" == __validate-expectation ]]; then
  [[ $# -eq 2 ]] || fail "__validate-expectation requires one value"
  validate_expectation "$2"
  exit
fi

if [[ "${1:-}" == __validate-port ]]; then
  [[ $# -eq 2 ]] || fail "__validate-port requires one value"
  validate_port port "$2"
  exit
fi

if [[ "${1:-}" == __classify-helper-probe ]]; then
  [[ $# -eq 2 ]] || fail "__classify-helper-probe requires one value"
  classify_helper_probe "$2"
  exit
fi

if [[ "${1:-}" == __classify-ping-probe ]]; then
  [[ $# -eq 2 ]] || fail "__classify-ping-probe requires one value"
  classify_ping_probe "$2"
  exit
fi

if [[ "${1:-}" == __status-has-addresses ]]; then
  [[ $# -eq 4 ]] || fail "__status-has-addresses requires status, IPv4, and IPv6 values"
  status_has_addresses "$2" "$3" "$4"
  exit
fi

if [[ "${1:-}" == __status-is-ready ]]; then
  [[ $# -eq 3 ]] || fail "__status-is-ready requires status and an online requirement"
  [[ "$3" == true || "$3" == false ]] || fail "online requirement must be true or false"
  status_is_ready "$2" "$3"
  exit
fi

if [[ "${1:-}" == __any-mesh-route ]]; then
  [[ $# -eq 5 ]] || fail "__any-mesh-route requires four route states"
  any_mesh_route "$2" "$3" "$4" "$5"
  exit
fi

if [[ "${1:-}" == __parse-service-metrics ]]; then
  [[ $# -eq 2 ]] || fail "__parse-service-metrics requires one systemd output value"
  parse_service_metrics "$2"
  exit
fi

if [[ "${1:-}" == __compare-service-metrics ]]; then
  [[ $# -eq 3 ]] || fail "__compare-service-metrics requires before and after values"
  compare_service_metrics "$2" "$3"
  exit
fi

main "$@"
