#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-crash-repeat-qualification/v1"
readonly dns_resolver_address="192.0.2.53"
readonly dns_resolver_port="1053"
readonly fd_headroom=4

temp_dir=""
restore_services=false
temporary_files=()

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-crash-repeat.sh \
    --node-label LABEL \
    --peer-label LABEL \
    --peer-v4 ADDRESS \
    --peer-v6 ADDRESS \
    --peer-name MAGICDNS_NAME \
    --service meshd|meshnetd \
    [--artifact-sha256 HEX] \
    [--iterations N] \
    [--inter-run-seconds N] \
    [--ready-timeout-seconds N] \
    [--data-interface NAME] \
    [--dns-interface NAME]

Runs bounded repeated SIGKILL recovery qualification by invoking the single-run
harness serially. After every run it rejects extra service processes, duplicate
interfaces or listeners, changed routes, changed resolver state, changed
persisted identity/configuration bytes, excessive descriptor growth, and failed
service state. The aggregate redacted JSON report is written to stdout.
EOF
}

fail() {
  printf 'linux-crash-repeat: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-crash-repeat: %s\n' "$*" >&2
}

cleanup() {
  local path

  set +e
  if [[ "${restore_services}" == true ]]; then
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

validate_positive_integer() {
  local label="$1"
  local value="$2"
  local maximum="$3"

  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]] || (( value > maximum )); then
    fail "${label} must be an integer between 1 and ${maximum}"
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

route_count() {
  local family="$1"
  local interface_name="$2"
  local output

  output="$(ip "-${family}" route show table main dev "${interface_name}" 2>/dev/null || true)"
  awk 'NF { count++ } END { print count + 0 }' <<<"${output}"
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
  } | sort | sha256sum | awk '{print $1}'
}

dns_digest() {
  local interface_name="$1"

  {
    resolvectl status "${interface_name}" --no-pager 2>&1 || true
  } | sed -E 's/^Link [0-9]+ /Link /' | sha256sum | awk '{print $1}'
}

resource_snapshot() {
  local data_interface="$1"
  local dns_interface="$2"
  local baseline_state_digest="$3"
  local baseline_route_digest="$4"
  local baseline_dns_digest="$5"
  local baseline_meshd_fds="$6"
  local baseline_meshnetd_fds="$7"
  local services_active=false
  local meshd_pid
  local meshnetd_pid
  local meshd_processes
  local meshnetd_processes
  local data_interfaces
  local dns_interfaces
  local udp_listeners
  local tcp_listeners
  local ipv4_routes
  local ipv6_routes
  local current_state_digest
  local current_route_digest
  local current_dns_digest
  local state_preserved=false
  local routes_preserved=false
  local dns_preserved=false
  local meshd_fds
  local meshnetd_fds
  local meshd_fd_increase
  local meshnetd_fd_increase

  if systemctl is-active --quiet meshd.service meshnetd.service; then
    services_active=true
  fi
  meshd_pid="$(unit_pid meshd.service)"
  meshnetd_pid="$(unit_pid meshnetd.service)"
  meshd_processes="$(named_process_count meshd)"
  meshnetd_processes="$(named_process_count meshnetd)"
  data_interfaces="$(interface_count "${data_interface}")"
  dns_interfaces="$(interface_count "${dns_interface}")"
  udp_listeners="$(listener_count udp)"
  tcp_listeners="$(listener_count tcp)"
  ipv4_routes="$(route_count 4 "${data_interface}")"
  ipv6_routes="$(route_count 6 "${data_interface}")"
  current_state_digest="$(state_digest)"
  current_route_digest="$(route_digest "${data_interface}")"
  current_dns_digest="$(dns_digest "${dns_interface}")"
  [[ "${current_state_digest}" == "${baseline_state_digest}" ]] && state_preserved=true
  [[ "${current_route_digest}" == "${baseline_route_digest}" ]] && routes_preserved=true
  [[ "${current_dns_digest}" == "${baseline_dns_digest}" ]] && dns_preserved=true
  meshd_fds="$(fd_count "${meshd_pid}")"
  meshnetd_fds="$(fd_count "${meshnetd_pid}")"
  meshd_fd_increase=$(( meshd_fds - baseline_meshd_fds ))
  meshnetd_fd_increase=$(( meshnetd_fds - baseline_meshnetd_fds ))

  jq -n \
    --argjson services_active "${services_active}" \
    --argjson meshd_processes "${meshd_processes}" \
    --argjson meshnetd_processes "${meshnetd_processes}" \
    --argjson data_interfaces "${data_interfaces}" \
    --argjson dns_interfaces "${dns_interfaces}" \
    --argjson udp_listeners "${udp_listeners}" \
    --argjson tcp_listeners "${tcp_listeners}" \
    --argjson ipv4_routes "${ipv4_routes}" \
    --argjson ipv6_routes "${ipv6_routes}" \
    --argjson state_preserved "${state_preserved}" \
    --argjson routes_preserved "${routes_preserved}" \
    --argjson dns_preserved "${dns_preserved}" \
    --argjson meshd_fds "${meshd_fds}" \
    --argjson meshnetd_fds "${meshnetd_fds}" \
    --argjson meshd_fd_increase "${meshd_fd_increase}" \
    --argjson meshnetd_fd_increase "${meshnetd_fd_increase}" \
    --argjson fd_headroom "${fd_headroom}" '
      {
        services_active: $services_active,
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
        route_count: {
          ipv4: $ipv4_routes,
          ipv6: $ipv6_routes
        },
        persisted_state_preserved: $state_preserved,
        route_state_preserved: $routes_preserved,
        dns_state_preserved: $dns_preserved,
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
          if .process_count.meshd != 1 then "unexpected_meshd_process_count" else empty end,
          if .process_count.meshnetd != 1 then "unexpected_meshnetd_process_count" else empty end,
          if .interface_count.data != 1 then "unexpected_data_interface_count" else empty end,
          if .interface_count.dns != 1 then "unexpected_dns_interface_count" else empty end,
          if .listener_count.udp != 1 then "unexpected_udp_listener_count" else empty end,
          if .listener_count.tcp != 1 then "unexpected_tcp_listener_count" else empty end,
          if .persisted_state_preserved != true then "persisted_state_changed" else empty end,
          if .route_state_preserved != true then "route_state_changed" else empty end,
          if .dns_state_preserved != true then "dns_state_changed" else empty end,
          if .descriptors.meshd == 0 then "meshd_descriptors_unavailable" else empty end,
          if .descriptors.meshnetd == 0 then "meshnetd_descriptors_unavailable" else empty end,
          if .descriptors.meshd_increase_from_baseline > .descriptors.allowed_increase then "meshd_descriptor_growth" else empty end,
          if .descriptors.meshnetd_increase_from_baseline > .descriptors.allowed_increase then "meshnetd_descriptor_growth" else empty end
        ]
      | .outcome = if (.failures | length) == 0 then "pass" else "fail" end
    '
}

main() {
  local node_label=""
  local peer_label=""
  local peer_v4=""
  local peer_v6=""
  local peer_name=""
  local service_name=""
  local artifact_sha256=""
  local iterations=3
  local inter_run_seconds=2
  local ready_timeout_seconds=20
  local data_interface=mesh0
  local dns_interface=meshdns0
  local script_dir
  local single_run_harness
  local command_name
  local baseline_state_digest
  local baseline_route_digest
  local baseline_dns_digest
  local baseline_meshd_pid
  local baseline_meshnetd_pid
  local baseline_meshd_fds
  local baseline_meshnetd_fds
  local baseline_resources
  local started_at
  local run_path
  local runs_path
  local run_exit_code
  local run_report
  local resources
  local completed_iterations=0
  local iteration
  local service_error_entries
  local runs
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
      --ready-timeout-seconds)
        [[ $# -ge 2 ]] || fail "--ready-timeout-seconds requires a value"
        ready_timeout_seconds="$2"
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
  (( EUID == 0 )) || fail "run as root so service recovery can be qualified"
  [[ -n "${node_label}" ]] || fail "--node-label is required"
  [[ -n "${peer_label}" ]] || fail "--peer-label is required"
  [[ -n "${peer_v4}" ]] || fail "--peer-v4 is required"
  [[ -n "${peer_v6}" ]] || fail "--peer-v6 is required"
  [[ -n "${peer_name}" ]] || fail "--peer-name is required"
  case "${service_name}" in
    meshd|meshnetd) ;;
    *) fail "service must be meshd or meshnetd" ;;
  esac
  validate_positive_integer iterations "${iterations}" 20
  validate_positive_integer inter-run-seconds "${inter_run_seconds}" 60
  validate_positive_integer ready-timeout-seconds "${ready_timeout_seconds}" 300

  script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  single_run_harness="${script_dir}/linux-restart.sh"
  [[ -x "${single_run_harness}" ]] || fail "single-run harness is not executable"
  for command_name in \
    awk date find ip journalctl jq meshctl mktemp pgrep resolvectl sha256sum \
    sed sleep sort ss stat systemctl uname; do
    require_command "${command_name}"
  done

  baseline_state_digest="$(state_digest)"
  baseline_route_digest="$(route_digest "${data_interface}")"
  baseline_dns_digest="$(dns_digest "${dns_interface}")"
  baseline_meshd_pid="$(unit_pid meshd.service)"
  baseline_meshnetd_pid="$(unit_pid meshnetd.service)"
  baseline_meshd_fds="$(fd_count "${baseline_meshd_pid}")"
  baseline_meshnetd_fds="$(fd_count "${baseline_meshnetd_pid}")"
  baseline_resources="$(resource_snapshot \
    "${data_interface}" \
    "${dns_interface}" \
    "${baseline_state_digest}" \
    "${baseline_route_digest}" \
    "${baseline_dns_digest}" \
    "${baseline_meshd_fds}" \
    "${baseline_meshnetd_fds}")"
  jq -e '.outcome == "pass"' >/dev/null <<<"${baseline_resources}" ||
    fail "baseline resource invariants are not satisfied"

  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-linux-crash-repeat.XXXXXXXX")"
  runs_path="${temp_dir}/runs.ndjson"
  temporary_files+=("${runs_path}")
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  restore_services=true

  for (( iteration = 1; iteration <= iterations; iteration++ )); do
    run_path="${temp_dir}/run-${iteration}.json"
    temporary_files+=("${run_path}")
    progress "running ${service_name} SIGKILL sample ${iteration}/${iterations}"
    if "${single_run_harness}" \
      --node-label "${node_label}" \
      --peer-label "${peer_label}" \
      --peer-v4 "${peer_v4}" \
      --peer-v6 "${peer_v6}" \
      --peer-name "${peer_name}" \
      --service "${service_name}" \
      --action sigkill \
      --artifact-sha256 "${artifact_sha256}" \
      --ready-timeout-seconds "${ready_timeout_seconds}" \
      --data-interface "${data_interface}" \
      --dns-interface "${dns_interface}" >"${run_path}"; then
      run_exit_code=0
    else
      run_exit_code=$?
    fi
    if ! jq -e 'type == "object"' >/dev/null 2>&1 <"${run_path}"; then
      progress "single-run report ${iteration} is unavailable or invalid"
      break
    fi
    run_report="$(<"${run_path}")"
    resources="$(resource_snapshot \
      "${data_interface}" \
      "${dns_interface}" \
      "${baseline_state_digest}" \
      "${baseline_route_digest}" \
      "${baseline_dns_digest}" \
      "${baseline_meshd_fds}" \
      "${baseline_meshnetd_fds}")"
    jq -c \
      --argjson iteration "${iteration}" \
      --argjson run_exit_code "${run_exit_code}" \
      --argjson resources "${resources}" \
      '. + {
        iteration: $iteration,
        harness_exit_code: $run_exit_code,
        resource_check: $resources
      }' <<<"${run_report}" >>"${runs_path}"
    completed_iterations="${iteration}"

    if (( run_exit_code != 0 )) ||
      ! jq -e '.outcome == "pass"' >/dev/null <<<"${run_report}" ||
      ! jq -e '.outcome == "pass"' >/dev/null <<<"${resources}"; then
      progress "sample ${iteration} failed; stopping the repeated qualification"
      break
    fi
    if (( iteration < iterations )); then
      sleep "${inter_run_seconds}"
    fi
  done

  service_error_entries="$(
    journalctl \
      -u meshd.service \
      -u meshnetd.service \
      --since "${started_at}" \
      --priority=err \
      --no-pager \
      -o cat 2>/dev/null |
      awk 'NF { count++ } END { print count + 0 }'
  )"
  if [[ -s "${runs_path}" ]]; then
    runs="$(jq -s '.' "${runs_path}")"
  else
    runs='[]'
  fi

  report="$(jq -n \
    --arg schema "${schema_version}" \
    --arg started_at "${started_at}" \
    --arg node_label "${node_label}" \
    --arg peer_label "${peer_label}" \
    --arg service "${service_name}.service" \
    --argjson iterations_requested "${iterations}" \
    --argjson iterations_completed "${completed_iterations}" \
    --argjson inter_run_seconds "${inter_run_seconds}" \
    --argjson ready_timeout_seconds "${ready_timeout_seconds}" \
    --argjson fd_headroom "${fd_headroom}" \
    --argjson baseline_resources "${baseline_resources}" \
    --argjson service_error_entries "${service_error_entries}" \
    --argjson runs "${runs}" '
      def p95(values):
        (values | map(select(type == "number")) | sort) as $sorted
        | if ($sorted | length) == 0 then null
          else $sorted[((($sorted | length) * 0.95 | ceil) - 1)]
          end;
      def full_ready:
        [.readiness_ms.services_active,
         .readiness_ms.data_interface,
         .readiness_ms.daemon_online,
         .readiness_ms.magic_dns]
        | map(select(type == "number"))
        | if length == 0 then null else max end;
      def stable_traffic:
        [.traffic.ipv4.stable_recovery_ms,
         .traffic.ipv6.stable_recovery_ms]
        | map(select(type == "number"))
        | if length == 0 then null else max end;
      {
        schema: $schema,
        started_at: $started_at,
        topology: {
          node_label: $node_label,
          peer_label: $peer_label,
          address_families: ["ipv4", "ipv6"]
        },
        artifact: ($runs[0].artifact // null),
        scenario: {
          action: "sigkill",
          service: $service,
          iterations_requested: $iterations_requested,
          iterations_completed: $iterations_completed,
          inter_run_seconds: $inter_run_seconds,
          ready_timeout_seconds: $ready_timeout_seconds
        },
        resource_contract: {
          descriptor_increase_headroom: $fd_headroom,
          baseline: $baseline_resources
        },
        samples: ($runs | map({
          iteration,
          harness_exit_code,
          action,
          dns_cleanup,
          readiness_ms,
          traffic,
          resource_check,
          failures,
          outcome
        })),
        summary: {
          full_readiness_p95_ms: p95($runs | map(full_ready)),
          stable_traffic_p95_ms: p95($runs | map(stable_traffic)),
          dns_cleanup_p95_ms: p95($runs | map(.dns_cleanup.observed_ms)),
          service_error_log_entries: $service_error_entries
        }
      }
      | .failures = ([
          if .scenario.iterations_completed != .scenario.iterations_requested then "iterations_incomplete" else empty end,
          if .summary.service_error_log_entries != 0 then "service_error_logs_present" else empty end,
          (.samples[] | select(.harness_exit_code != 0) | "single_run_harness_failed"),
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

if [[ "${1:-}" == __validate-positive-integer ]]; then
  [[ $# -eq 4 ]] || fail "__validate-positive-integer requires LABEL VALUE MAXIMUM"
  validate_positive_integer "$2" "$3" "$4"
  exit
fi

main "$@"
