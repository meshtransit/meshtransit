#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-runtime-recovery-repeat-qualification/v1"
readonly single_schema_version="meshtransit.linux-runtime-recovery-qualification/v1"
readonly helper_socket="/run/meshnetd/meshnetd.sock"
readonly api_socket="/run/meshd/meshd.sock"
readonly dns_resolver_address="192.0.2.53"
readonly dns_resolver_port="1053"
readonly fd_headroom=4

temp_dir=""
restore_services=false
temporary_files=()

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-runtime-recovery-repeat.sh \
    --node-label LABEL \
    --confirm-helper-socket-fault LABEL \
    [--artifact-sha256 HEX] \
    [--iterations N] \
    [--inter-run-seconds N] \
    [--recovery-timeout-seconds N] \
    [--resource-timeout-seconds N] \
    [--poll-interval SECONDS] \
    [--data-interface NAME] \
    [--dns-interface NAME]

Runs the reversible helper-socket fault serially and stops at the first failed
sample. After every recovery it rejects extra processes, interfaces or DNS
listeners, changed routes, resolver state or persisted identity/configuration,
excessive descriptor growth, an incorrect helper-socket contract, and pending
runtime recovery. A redacted aggregate report with nearest-rank p95 timing is
written to stdout.
EOF
}

fail() {
  printf 'linux-runtime-recovery-repeat: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-runtime-recovery-repeat: %s\n' "$*" >&2
}

cleanup() {
  local path

  set +e
  if [[ "${restore_services}" == true ]]; then
    if [[ -S "${helper_socket}" ]]; then
      chmod 0660 "${helper_socket}" >/dev/null 2>&1
    fi
    systemctl start meshnetd.service meshd.service >/dev/null 2>&1
  fi
  if (( ${#temporary_files[@]} > 0 )); then
    for path in "${temporary_files[@]}"; do
      rm -f -- "${path}"
    done
  fi
  if [[ -n "${temp_dir}" ]]; then
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

named_process_count() {
  local process_name="$1"
  local processes

  processes="$(pgrep -x -- "${process_name}" 2>/dev/null || true)"
  awk 'NF { count++ } END { print count + 0 }' <<<"${processes}"
}

interface_count() {
  local interface_name="$1"
  local output

  output="$(ip -o link show 2>/dev/null || true)"
  awk -F': ' -v expected="${interface_name}" '
    {
      candidate = $2
      sub(/@.*/, "", candidate)
      if (candidate == expected) {
        count++
      }
    }
    END { print count + 0 }
  ' <<<"${output}"
}

listener_count() {
  local transport="$1"
  local output

  case "${transport}" in
    udp) output="$(ss -H -lnu "sport = :${dns_resolver_port}" 2>/dev/null || true)" ;;
    tcp) output="$(ss -H -lnt "sport = :${dns_resolver_port}" 2>/dev/null || true)" ;;
    *) fail "unsupported listener transport: ${transport}" ;;
  esac
  awk -v expected="${dns_resolver_address}:${dns_resolver_port}" '
    $4 == expected { count++ }
    END { print count + 0 }
  ' <<<"${output}"
}

fd_count() {
  local pid="$1"

  if [[ "${pid}" == 0 || ! -d "/proc/${pid}/fd" ]]; then
    printf '0\n'
    return
  fi
  {
    find "/proc/${pid}/fd" -mindepth 1 -maxdepth 1 -print 2>/dev/null || true
  } | awk 'NF { count++ } END { print count + 0 }'
}

state_digest() {
  local file
  local digest
  local -a fixed_files=(
    /var/lib/meshd/profiles.json
    /etc/meshd/meshd.env
  )

  {
    if [[ -d /var/lib/meshd/identities ]]; then
      while IFS= read -r -d '' file; do
        digest="$(sha256sum -- "${file}" | awk '{print $1}')"
        printf 'identity:%s:%s:' "${file##*/}" "${digest}"
        stat -c '%a:%u:%g\n' -- "${file}"
      done < <(
        find /var/lib/meshd/identities -maxdepth 1 -type f -print0 2>/dev/null |
          sort -z
      )
    else
      printf 'identities:missing\n'
    fi
    for file in "${fixed_files[@]}"; do
      if [[ -f "${file}" ]]; then
        digest="$(sha256sum -- "${file}" | awk '{print $1}')"
        printf 'fixed:%s:%s:' "${file}" "${digest}"
        stat -c '%a:%u:%g\n' -- "${file}"
      else
        printf 'fixed:%s:missing\n' "${file}"
      fi
    done
  } | sha256sum | awk '{print $1}'
}

route_digest() {
  local interface_name="$1"

  {
    ip -4 route show table main dev "${interface_name}" 2>/dev/null || true
    ip -6 route show table main dev "${interface_name}" 2>/dev/null || true
  } | normalize_routes | sort | sha256sum | awk '{print $1}'
}

normalize_routes() {
  # The kernel-owned IPv6 link-local route follows address generation and DAD,
  # so its presence is not an overlay-route invariant. All other routes remain
  # byte-for-byte inputs to the digest.
  awk '$1 != "fe80::/64" && NF { print }'
}

dns_digest() {
  local interface_name="$1"

  {
    resolvectl status "${interface_name}" --no-pager 2>&1 || true
  } | sed -E 's/^Link [0-9]+ /Link /' | sha256sum | awk '{print $1}'
}

read_status() {
  curl --fail --silent --show-error --max-time 2 \
    --unix-socket "${api_socket}" http://localhost/v1/status 2>/dev/null || true
}

resource_snapshot() {
  local data_interface="$1"
  local dns_interface="$2"
  local baseline_state_digest="$3"
  local baseline_route_digest="$4"
  local baseline_dns_digest="$5"
  local baseline_meshd_restarts="$6"
  local baseline_meshnetd_restarts="$7"
  local baseline_meshd_fds="$8"
  local baseline_meshnetd_fds="$9"
  local services_active=false
  local helper_socket_contract=false
  local status_ready=false
  local recovery_idle=false
  local meshd_pid
  local meshnetd_pid
  local meshd_processes
  local meshnetd_processes
  local data_interfaces
  local dns_interfaces
  local udp_listeners
  local tcp_listeners
  local state_preserved=false
  local routes_preserved=false
  local dns_preserved=false
  local restart_counts_stable=false
  local meshd_fds
  local meshnetd_fds
  local meshd_fd_increase
  local meshnetd_fd_increase
  local status

  if systemctl is-active --quiet meshd.service meshnetd.service; then
    services_active=true
  fi
  if [[ -S "${helper_socket}" ]] &&
    [[ "$(stat -c %a "${helper_socket}" 2>/dev/null || true)" == 660 ]] &&
    [[ "$(stat -c %U "${helper_socket}" 2>/dev/null || true)" == root ]] &&
    [[ "$(stat -c %G "${helper_socket}" 2>/dev/null || true)" == meshd ]]; then
    helper_socket_contract=true
  fi
  status="$(read_status)"
  if jq -e '
    .state == "online" and
    .control_session == "synchronized" and
    .dns == "configured" and
    (.data_plane | type) == "string" and
    .data_plane != "failed"
  ' >/dev/null 2>&1 <<<"${status}"; then
    status_ready=true
  fi
  if jq -e '
    (.runtime_recovery.failures | type) == "number" and
    (.runtime_recovery.recoveries | type) == "number" and
    .runtime_recovery.failures >= 1 and
    .runtime_recovery.recoveries >= 1 and
    .runtime_recovery.pending == false
  ' >/dev/null 2>&1 <<<"${status}"; then
    recovery_idle=true
  fi

  meshd_pid="$(unit_pid meshd.service)"
  meshnetd_pid="$(unit_pid meshnetd.service)"
  meshd_processes="$(named_process_count meshd)"
  meshnetd_processes="$(named_process_count meshnetd)"
  data_interfaces="$(interface_count "${data_interface}")"
  dns_interfaces="$(interface_count "${dns_interface}")"
  udp_listeners="$(listener_count udp)"
  tcp_listeners="$(listener_count tcp)"
  [[ "$(state_digest)" == "${baseline_state_digest}" ]] && state_preserved=true
  [[ "$(route_digest "${data_interface}")" == "${baseline_route_digest}" ]] &&
    routes_preserved=true
  [[ "$(dns_digest "${dns_interface}")" == "${baseline_dns_digest}" ]] &&
    dns_preserved=true
  if [[ "$(unit_restart_count meshd.service)" == "${baseline_meshd_restarts}" ]] &&
    [[ "$(unit_restart_count meshnetd.service)" == "${baseline_meshnetd_restarts}" ]]; then
    restart_counts_stable=true
  fi
  meshd_fds="$(fd_count "${meshd_pid}")"
  meshnetd_fds="$(fd_count "${meshnetd_pid}")"
  meshd_fd_increase=$(( meshd_fds - baseline_meshd_fds ))
  meshnetd_fd_increase=$(( meshnetd_fds - baseline_meshnetd_fds ))

  jq -n \
    --argjson services_active "${services_active}" \
    --argjson helper_socket_contract "${helper_socket_contract}" \
    --argjson status_ready "${status_ready}" \
    --argjson recovery_idle "${recovery_idle}" \
    --argjson meshd_processes "${meshd_processes}" \
    --argjson meshnetd_processes "${meshnetd_processes}" \
    --argjson data_interfaces "${data_interfaces}" \
    --argjson dns_interfaces "${dns_interfaces}" \
    --argjson udp_listeners "${udp_listeners}" \
    --argjson tcp_listeners "${tcp_listeners}" \
    --argjson state_preserved "${state_preserved}" \
    --argjson routes_preserved "${routes_preserved}" \
    --argjson dns_preserved "${dns_preserved}" \
    --argjson restart_counts_stable "${restart_counts_stable}" \
    --argjson meshd_fds "${meshd_fds}" \
    --argjson meshnetd_fds "${meshnetd_fds}" \
    --argjson meshd_fd_increase "${meshd_fd_increase}" \
    --argjson meshnetd_fd_increase "${meshnetd_fd_increase}" \
    --argjson fd_headroom "${fd_headroom}" '
      {
        services_active: $services_active,
        helper_socket_contract: $helper_socket_contract,
        status_ready: $status_ready,
        runtime_recovery_idle: $recovery_idle,
        process_count: {
          meshd: $meshd_processes,
          meshnetd: $meshnetd_processes
        },
        interface_count: {
          data: $data_interfaces,
          dns: $dns_interfaces
        },
        listener_count: {
          udp: $udp_listeners,
          tcp: $tcp_listeners
        },
        persisted_state_preserved: $state_preserved,
        route_state_preserved: $routes_preserved,
        dns_state_preserved: $dns_preserved,
        restart_counts_stable: $restart_counts_stable,
        descriptors: {
          meshd: $meshd_fds,
          meshnetd: $meshnetd_fds,
          meshd_increase_from_baseline: $meshd_fd_increase,
          meshnetd_increase_from_baseline: $meshnetd_fd_increase,
          allowed_increase: $fd_headroom
        }
      }
      | .failures = [
          if .services_active != true then "services_not_active" else empty end,
          if .helper_socket_contract != true then "helper_socket_contract_changed" else empty end,
          if .status_ready != true then "daemon_not_ready" else empty end,
          if .runtime_recovery_idle != true then "runtime_recovery_not_idle" else empty end,
          if .process_count.meshd != 1 then "unexpected_meshd_process_count" else empty end,
          if .process_count.meshnetd != 1 then "unexpected_meshnetd_process_count" else empty end,
          if .interface_count.data != 1 then "unexpected_data_interface_count" else empty end,
          if .interface_count.dns != 1 then "unexpected_dns_interface_count" else empty end,
          if .listener_count.udp != 1 then "unexpected_udp_listener_count" else empty end,
          if .listener_count.tcp != 1 then "unexpected_tcp_listener_count" else empty end,
          if .persisted_state_preserved != true then "persisted_state_changed" else empty end,
          if .route_state_preserved != true then "route_state_changed" else empty end,
          if .dns_state_preserved != true then "dns_state_changed" else empty end,
          if .restart_counts_stable != true then "restart_count_increased" else empty end,
          if .descriptors.meshd == 0 then "meshd_descriptors_unavailable" else empty end,
          if .descriptors.meshnetd == 0 then "meshnetd_descriptors_unavailable" else empty end,
          if .descriptors.meshd_increase_from_baseline > .descriptors.allowed_increase then "meshd_descriptor_growth" else empty end,
          if .descriptors.meshnetd_increase_from_baseline > .descriptors.allowed_increase then "meshnetd_descriptor_growth" else empty end
        ]
      | .outcome = if (.failures | length) == 0 then "pass" else "fail" end
    '
}

wait_for_resources() {
  local data_interface="$1"
  local dns_interface="$2"
  local baseline_state_digest="$3"
  local baseline_route_digest="$4"
  local baseline_dns_digest="$5"
  local baseline_meshd_restarts="$6"
  local baseline_meshnetd_restarts="$7"
  local baseline_meshd_fds="$8"
  local baseline_meshnetd_fds="$9"
  local timeout_seconds="${10}"
  local poll_interval="${11}"
  local start_ns
  local deadline_ns
  local current_ns
  local snapshot
  local initial_failures

  start_ns="$(now_ns)"
  deadline_ns=$(( start_ns + timeout_seconds * 1000000000 ))
  snapshot="$(resource_snapshot \
    "${data_interface}" \
    "${dns_interface}" \
    "${baseline_state_digest}" \
    "${baseline_route_digest}" \
    "${baseline_dns_digest}" \
    "${baseline_meshd_restarts}" \
    "${baseline_meshnetd_restarts}" \
    "${baseline_meshd_fds}" \
    "${baseline_meshnetd_fds}")"
  initial_failures="$(jq -c '.failures' <<<"${snapshot}")"

  while ! jq -e '.outcome == "pass"' >/dev/null <<<"${snapshot}"; do
    current_ns="$(now_ns)"
    if (( current_ns >= deadline_ns )); then
      break
    fi
    sleep "${poll_interval}"
    snapshot="$(resource_snapshot \
      "${data_interface}" \
      "${dns_interface}" \
      "${baseline_state_digest}" \
      "${baseline_route_digest}" \
      "${baseline_dns_digest}" \
      "${baseline_meshd_restarts}" \
      "${baseline_meshnetd_restarts}" \
      "${baseline_meshd_fds}" \
      "${baseline_meshnetd_fds}")"
  done
  current_ns="$(now_ns)"
  jq \
    --argjson initial_failures "${initial_failures}" \
    --argjson settle_ms "$(elapsed_ms "${start_ns}" "${current_ns}")" '
      . + {
        initial_failures: $initial_failures,
        settle_ms: $settle_ms
      }
    ' <<<"${snapshot}"
}

sample_identity_matches() {
  local report_path="$1"
  local node_label="$2"
  local version="$3"
  local commit="$4"
  local sha256_json="$5"
  local kernel_release="$6"
  local architecture="$7"

  jq -e \
    --arg schema "${single_schema_version}" \
    --arg node_label "${node_label}" \
    --arg version "${version}" \
    --arg commit "${commit}" \
    --argjson sha256 "${sha256_json}" \
    --arg kernel_release "${kernel_release}" \
    --arg architecture "${architecture}" '
      .schema == $schema and
      .topology.node_label == $node_label and
      .artifact.version == $version and
      .artifact.commit == $commit and
      .artifact.sha256 == $sha256 and
      .platform.kernel_release == $kernel_release and
      .platform.architecture == $architecture
    ' "${report_path}" >/dev/null 2>&1
}

valid_repeat_report() {
  local report_path="$1"

  jq -e --arg schema "${schema_version}" '
    type == "object" and
    .schema == $schema and
    .scenario.action == "helper_socket_permission_fault_at_startup" and
    (.scenario.iterations_requested | type) == "number" and
    .scenario.iterations_completed == .scenario.iterations_requested and
    (.samples | type) == "array" and
    (.samples | length) == .scenario.iterations_completed and
    (.samples | all(
      .harness_exit_code == 0 and
      .report_valid == true and
      .identity_consistent == true and
      .outcome == "pass" and
      (.failures | type == "array" and length == 0) and
      .resource_check.outcome == "pass"
    )) and
    (.summary.failure_observed_p95_ms | type) == "number" and
    (.summary.synchronized_p95_ms | type) == "number" and
    (.summary.resource_stable_p95_ms | type) == "number" and
    .outcome == "pass" and
    (.failures | type == "array" and length == 0)
  ' "${report_path}" >/dev/null 2>&1
}

main() {
  local node_label=""
  local confirmation=""
  local artifact_sha256=""
  local iterations=5
  local inter_run_seconds=1
  local recovery_timeout_seconds=30
  local resource_timeout_seconds=5
  local poll_interval=0.1
  local data_interface=mesh0
  local dns_interface=meshdns0
  local script_dir
  local single_run_harness
  local command_name
  local baseline_state_digest
  local baseline_route_digest
  local baseline_dns_digest
  local baseline_meshd_restarts
  local baseline_meshnetd_restarts
  local baseline_meshd_fds
  local baseline_meshnetd_fds
  local baseline_resources
  local run_path
  local runs_path
  local run_exit_code
  local run_report
  local resources
  local report_valid=false
  local identity_consistent=false
  local completed_iterations=0
  local runner_failure=""
  local iteration
  local anchor_version=""
  local anchor_commit=""
  local anchor_sha256_json=null
  local anchor_kernel=""
  local anchor_architecture=""
  local runs
  local started_at
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
      --iterations)
        [[ $# -ge 2 ]] || fail "--iterations requires a value"
        iterations="$2"
        shift 2
        ;;
      --inter-run-seconds)
        [[ $# -ge 2 ]] || fail "--inter-run-seconds requires a value"
        inter_run_seconds="$2"
        shift 2
        ;;
      --recovery-timeout-seconds)
        [[ $# -ge 2 ]] || fail "--recovery-timeout-seconds requires a value"
        recovery_timeout_seconds="$2"
        shift 2
        ;;
      --resource-timeout-seconds)
        [[ $# -ge 2 ]] || fail "--resource-timeout-seconds requires a value"
        resource_timeout_seconds="$2"
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
      *) fail "unknown argument: $1" ;;
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
  validate_positive_integer iterations "${iterations}" 20
  validate_positive_integer inter-run-seconds "${inter_run_seconds}" 60
  validate_positive_integer recovery-timeout-seconds "${recovery_timeout_seconds}" 120
  validate_positive_integer resource-timeout-seconds "${resource_timeout_seconds}" 30
  validate_interval poll-interval "${poll_interval}"
  if [[ -n "${artifact_sha256}" && ! "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    fail "artifact-sha256 must contain exactly 64 hexadecimal characters"
  fi

  script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  single_run_harness="${script_dir}/linux-runtime-recovery.sh"
  [[ -x "${single_run_harness}" ]] || fail "single-run harness is not executable"
  for command_name in \
    awk chmod curl date find ip jq meshctl mktemp pgrep resolvectl sha256sum sleep \
    sort ss stat systemctl uname; do
    require_command "${command_name}"
  done

  baseline_state_digest="$(state_digest)"
  baseline_route_digest="$(route_digest "${data_interface}")"
  baseline_dns_digest="$(dns_digest "${dns_interface}")"
  baseline_meshd_restarts="$(unit_restart_count meshd.service)"
  baseline_meshnetd_restarts="$(unit_restart_count meshnetd.service)"
  baseline_meshd_fds="$(fd_count "$(unit_pid meshd.service)")"
  baseline_meshnetd_fds="$(fd_count "$(unit_pid meshnetd.service)")"

  # Runtime counters are process-local. The baseline does not need a previous
  # recovery, so qualify structural resources before requiring recovery_idle.
  baseline_resources="$(resource_snapshot \
    "${data_interface}" \
    "${dns_interface}" \
    "${baseline_state_digest}" \
    "${baseline_route_digest}" \
    "${baseline_dns_digest}" \
    "${baseline_meshd_restarts}" \
    "${baseline_meshnetd_restarts}" \
    "${baseline_meshd_fds}" \
    "${baseline_meshnetd_fds}")"
  baseline_resources="$(jq '
    .failures |= map(select(. != "runtime_recovery_not_idle"))
    | .outcome = if (.failures | length) == 0 then "pass" else "fail" end
  ' <<<"${baseline_resources}")"
  jq -e '.outcome == "pass"' >/dev/null <<<"${baseline_resources}" ||
    fail "baseline resource invariants are not satisfied"

  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-runtime-recovery-repeat.XXXXXXXX")"
  runs_path="${temp_dir}/runs.ndjson"
  temporary_files+=("${runs_path}")
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  restore_services=true

  for (( iteration = 1; iteration <= iterations; iteration++ )); do
    run_path="${temp_dir}/run-${iteration}.json"
    temporary_files+=("${run_path}")
    report_valid=false
    identity_consistent=false
    progress "running local-runtime recovery sample ${iteration}/${iterations}"
    if "${single_run_harness}" \
      --node-label "${node_label}" \
      --confirm-helper-socket-fault "${node_label}" \
      --artifact-sha256 "${artifact_sha256}" \
      --recovery-timeout-seconds "${recovery_timeout_seconds}" \
      --poll-interval "${poll_interval}" \
      --data-interface "${data_interface}" \
      --dns-interface "${dns_interface}" >"${run_path}"; then
      run_exit_code=0
    else
      run_exit_code=$?
    fi

    if ! jq -e 'type == "object"' >/dev/null 2>&1 <"${run_path}"; then
      runner_failure="single_run_report_invalid"
      progress "sample ${iteration} did not produce a valid JSON object"
      break
    fi
    run_report="$(<"${run_path}")"
    if "${single_run_harness}" __validate-report "${run_path}"; then
      report_valid=true
    fi

    if (( iteration == 1 )); then
      anchor_version="$(jq -r '.artifact.version' <<<"${run_report}")"
      anchor_commit="$(jq -r '.artifact.commit' <<<"${run_report}")"
      anchor_sha256_json="$(jq -c '.artifact.sha256' <<<"${run_report}")"
      anchor_kernel="$(jq -r '.platform.kernel_release' <<<"${run_report}")"
      anchor_architecture="$(jq -r '.platform.architecture' <<<"${run_report}")"
    fi
    if sample_identity_matches \
      "${run_path}" \
      "${node_label}" \
      "${anchor_version}" \
      "${anchor_commit}" \
      "${anchor_sha256_json}" \
      "${anchor_kernel}" \
      "${anchor_architecture}"; then
      identity_consistent=true
    fi

    resources="$(wait_for_resources \
      "${data_interface}" \
      "${dns_interface}" \
      "${baseline_state_digest}" \
      "${baseline_route_digest}" \
      "${baseline_dns_digest}" \
      "${baseline_meshd_restarts}" \
      "${baseline_meshnetd_restarts}" \
      "${baseline_meshd_fds}" \
      "${baseline_meshnetd_fds}" \
      "${resource_timeout_seconds}" \
      "${poll_interval}")"
    jq -c \
      --argjson iteration "${iteration}" \
      --argjson run_exit_code "${run_exit_code}" \
      --argjson report_valid "${report_valid}" \
      --argjson identity_consistent "${identity_consistent}" \
      --argjson resources "${resources}" '
        . + {
          iteration: $iteration,
          harness_exit_code: $run_exit_code,
          report_valid: $report_valid,
          identity_consistent: $identity_consistent,
          resource_check: $resources
        }
      ' <<<"${run_report}" >>"${runs_path}"
    completed_iterations="${iteration}"

    if (( run_exit_code != 0 )) ||
      [[ "${report_valid}" != true ]] ||
      [[ "${identity_consistent}" != true ]] ||
      ! jq -e '.outcome == "pass"' >/dev/null <<<"${resources}"; then
      progress "sample ${iteration} failed; stopping the repeated qualification"
      break
    fi
    if (( iteration < iterations )); then
      sleep "${inter_run_seconds}"
    fi
  done

  if [[ -s "${runs_path}" ]]; then
    runs="$(jq -s '.' "${runs_path}")"
  else
    runs='[]'
  fi
  report="$(jq -n \
    --arg schema "${schema_version}" \
    --arg started_at "${started_at}" \
    --arg node_label "${node_label}" \
    --arg version "${anchor_version}" \
    --arg commit "${anchor_commit}" \
    --argjson sha256 "${anchor_sha256_json}" \
    --arg kernel_release "${anchor_kernel}" \
    --arg architecture "${anchor_architecture}" \
    --arg runner_failure "${runner_failure}" \
    --argjson iterations_requested "${iterations}" \
    --argjson iterations_completed "${completed_iterations}" \
    --argjson inter_run_seconds "${inter_run_seconds}" \
    --argjson recovery_timeout_seconds "${recovery_timeout_seconds}" \
    --argjson resource_timeout_seconds "${resource_timeout_seconds}" \
    --argjson fd_headroom "${fd_headroom}" \
    --argjson baseline_resources "${baseline_resources}" \
    --argjson runs "${runs}" '
      def p95(values):
        (values | map(select(type == "number")) | sort) as $sorted
        | if ($sorted | length) == 0 then null
          else $sorted[((($sorted | length) * 0.95 | ceil) - 1)]
          end;
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
          evidence_complete: ($sha256 != null)
        },
        scenario: {
          action: "helper_socket_permission_fault_at_startup",
          iterations_requested: $iterations_requested,
          iterations_completed: $iterations_completed,
          inter_run_seconds: $inter_run_seconds,
          recovery_timeout_seconds: $recovery_timeout_seconds,
          resource_timeout_seconds: $resource_timeout_seconds
        },
        resource_contract: {
          descriptor_increase_headroom: $fd_headroom,
          baseline: $baseline_resources
        },
        samples: ($runs | map({
          iteration,
          harness_exit_code,
          report_valid,
          identity_consistent,
          fault,
          recovery_ms,
          generation,
          final,
          resource_check,
          failures,
          outcome
        })),
        summary: {
          failure_observed_p95_ms: p95($runs | map(.recovery_ms.failure_observed)),
          synchronized_p95_ms: p95($runs | map(.recovery_ms.synchronized)),
          resource_stable_p95_ms: p95($runs | map(.resource_check.settle_ms))
        }
      }
      | .failures = ([
          if $runner_failure != "" then $runner_failure else empty end,
          if .scenario.iterations_completed != .scenario.iterations_requested then "iterations_incomplete" else empty end,
          (.samples[] | select(.harness_exit_code != 0) | "single_run_harness_failed"),
          (.samples[] | select(.report_valid != true) | "single_run_report_rejected"),
          (.samples[] | select(.identity_consistent != true) | "sample_identity_changed"),
          (.samples[].failures[]),
          (.samples[].resource_check.failures[])
        ] | unique)
      | .outcome = if (.failures | length) == 0 then "pass" else "fail" end
    ')"

  printf '%s\n' "${report}"
  outcome="$(jq -r '.outcome' <<<"${report}")"
  if [[ "${outcome}" != pass ]]; then
    progress "repeated qualification failed; inspect the JSON failure codes"
    return 2
  fi
  restore_services=false
  progress "repeated qualification passed"
}

case "${1:-}" in
  __validate-label)
    [[ $# -eq 2 ]] || fail "__validate-label requires one value"
    validate_label label "$2"
    ;;
  __validate-positive-integer)
    [[ $# -eq 4 ]] || fail "__validate-positive-integer requires LABEL VALUE MAXIMUM"
    validate_positive_integer "$2" "$3" "$4"
    ;;
  __validate-sample-identity)
    [[ $# -eq 8 ]] || fail "__validate-sample-identity requires REPORT LABEL VERSION COMMIT SHA256_JSON KERNEL ARCH"
    sample_identity_matches "$2" "$3" "$4" "$5" "$6" "$7" "$8"
    ;;
  __normalize-routes)
    [[ $# -eq 1 ]] || fail "__normalize-routes takes no arguments"
    normalize_routes
    ;;
  __validate-report)
    [[ $# -eq 2 ]] || fail "__validate-report requires one report path"
    valid_repeat_report "$2"
    ;;
  *)
    main "$@"
    ;;
esac
