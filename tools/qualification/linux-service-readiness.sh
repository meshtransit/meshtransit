#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-service-readiness-qualification/v1"

qualification_started=false
qualification_completed=false

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-service-readiness.sh \
    --node-label LABEL \
    --artifact-sha256 HEX \
    --confirm-restarts LABEL \
    [--iterations N] \
    [--request-timeout-seconds N]

Restarts the packaged meshd and meshnetd units together and proves that each
systemctl restart returns only after both Type=notify services are ready. The
local API health request is issued exactly once, without readiness retries,
immediately after every completed restart. A redacted JSON report is written
to stdout; progress and errors are written to stderr.
EOF
}

fail() {
  printf 'linux-service-readiness: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-service-readiness: %s\n' "$*" >&2
}

cleanup() {
  if [[ "${qualification_started}" == true && "${qualification_completed}" != true ]]; then
    systemctl start meshnetd.service meshd.service >/dev/null 2>&1 || true
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
  local value="$1"

  [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] ||
    fail "node label must contain 1-64 safe label characters"
}

validate_positive_integer() {
  local label="$1"
  local value="$2"
  local maximum="$3"

  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]] || (( value > maximum )); then
    fail "${label} must be an integer between 1 and ${maximum}"
  fi
}

now_ms() {
  python3 -c 'import time; print(time.time_ns() // 1000000)'
}

health_is_ready() {
  jq -e '
    type == "object" and
    .status == "ok" and
    .api_version == "v1"
  ' >/dev/null <<<"$1"
}

unit_property() {
  local unit="$1"
  local property="$2"

  systemctl show --property="${property}" --value "${unit}"
}

require_unit_property() {
  local unit="$1"
  local property="$2"
  local expected="$3"
  local actual

  actual="$(unit_property "${unit}" "${property}")" ||
    fail "unable to inspect ${property} for ${unit}"
  [[ "${actual}" == "${expected}" ]] ||
    fail "${unit} ${property} is ${actual:-empty}, want ${expected}"
}

unit_pid() {
  local unit="$1"
  local pid

  pid="$(unit_property "${unit}" MainPID)" ||
    fail "unable to inspect MainPID for ${unit}"
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] ||
    fail "${unit} does not have a live main process"
  printf '%s\n' "${pid}"
}

unit_restarts() {
  local unit="$1"
  local count

  count="$(unit_property "${unit}" NRestarts)" ||
    fail "unable to inspect NRestarts for ${unit}"
  [[ "${count}" =~ ^[0-9]+$ ]] || fail "${unit} returned an invalid restart count"
  printf '%s\n' "${count}"
}

main() {
  local node_label=""
  local artifact_sha256=""
  local restart_confirmation=""
  local iterations=5
  local request_timeout_seconds=2
  local os_id
  local os_version
  local package_version
  local baseline_meshd_pid
  local baseline_meshnetd_pid
  local baseline_meshd_restarts
  local baseline_meshnetd_restarts
  local iteration
  local restart_start_ms
  local restart_end_ms
  local health_start_ms
  local health_end_ms
  local current_meshd_pid
  local current_meshnetd_pid
  local current_meshd_restarts
  local current_meshnetd_restarts
  local health
  local results='[]'

  while (( $# > 0 )); do
    case "$1" in
      --node-label)
        [[ $# -ge 2 ]] || fail "--node-label requires a value"
        node_label="$2"
        shift 2
        ;;
      --artifact-sha256)
        [[ $# -ge 2 ]] || fail "--artifact-sha256 requires a value"
        artifact_sha256="$2"
        shift 2
        ;;
      --confirm-restarts)
        [[ $# -ge 2 ]] || fail "--confirm-restarts requires a value"
        restart_confirmation="$2"
        shift 2
        ;;
      --iterations)
        [[ $# -ge 2 ]] || fail "--iterations requires a value"
        iterations="$2"
        shift 2
        ;;
      --request-timeout-seconds)
        [[ $# -ge 2 ]] || fail "--request-timeout-seconds requires a value"
        request_timeout_seconds="$2"
        shift 2
        ;;
      --help|-h)
        usage
        return 0
        ;;
      *)
        fail "unsupported argument: $1"
        ;;
    esac
  done

  (( EUID == 0 )) || fail "run as root so the packaged services can be restarted"
  [[ -n "${node_label}" ]] || fail "--node-label is required"
  validate_label "${node_label}"
  [[ "${restart_confirmation}" == "${node_label}" ]] ||
    fail "--confirm-restarts must exactly match --node-label"
  [[ "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]] ||
    fail "--artifact-sha256 must contain exactly 64 hexadecimal characters"
  artifact_sha256="${artifact_sha256,,}"
  validate_positive_integer iterations "${iterations}" 20
  validate_positive_integer request-timeout-seconds "${request_timeout_seconds}" 10

  for command_name in curl dpkg-query jq python3 systemctl; do
    require_command "${command_name}"
  done
  [[ -r /etc/os-release ]] || fail "/etc/os-release is unavailable"
  # shellcheck source=/dev/null
  source /etc/os-release
  os_id="${ID:-unknown}"
  os_version="${VERSION_ID:-unknown}"
  package_version="$(dpkg-query --show --showformat='${Version}' meshd)" ||
    fail "the meshd package is not installed"

  for unit in meshnetd.service meshd.service; do
    require_unit_property "${unit}" Type notify
    require_unit_property "${unit}" NotifyAccess main
    require_unit_property "${unit}" TimeoutStartUSec 30s
  done
  systemctl is-active --quiet meshnetd.service meshd.service ||
    fail "meshd.service and meshnetd.service must both be active before qualification"
  [[ -S /run/meshd/meshd.sock ]] || fail "the meshd local API socket is unavailable"
  [[ -S /run/meshnetd/meshnetd.sock ]] || fail "the meshnetd helper socket is unavailable"

  baseline_meshd_pid="$(unit_pid meshd.service)"
  baseline_meshnetd_pid="$(unit_pid meshnetd.service)"
  baseline_meshd_restarts="$(unit_restarts meshd.service)"
  baseline_meshnetd_restarts="$(unit_restarts meshnetd.service)"
  qualification_started=true

  for ((iteration = 1; iteration <= iterations; iteration++)); do
    progress "restart ${iteration}/${iterations}"
    restart_start_ms="$(now_ms)"
    systemctl restart meshnetd.service meshd.service ||
      fail "coordinated service restart failed at iteration ${iteration}"
    restart_end_ms="$(now_ms)"

    systemctl is-active --quiet meshnetd.service meshd.service ||
      fail "a service was not active after restart ${iteration}"
    current_meshd_pid="$(unit_pid meshd.service)"
    current_meshnetd_pid="$(unit_pid meshnetd.service)"
    [[ "${current_meshd_pid}" != "${baseline_meshd_pid}" ]] ||
      fail "meshd process generation did not change at iteration ${iteration}"
    [[ "${current_meshnetd_pid}" != "${baseline_meshnetd_pid}" ]] ||
      fail "meshnetd process generation did not change at iteration ${iteration}"
    [[ -S /run/meshd/meshd.sock ]] ||
      fail "the meshd socket was absent after restart ${iteration}"
    [[ -S /run/meshnetd/meshnetd.sock ]] ||
      fail "the meshnetd socket was absent after restart ${iteration}"

    health_start_ms="$(now_ms)"
    health="$(curl \
      --silent \
      --show-error \
      --fail \
      --max-time "${request_timeout_seconds}" \
      --unix-socket /run/meshd/meshd.sock \
      http://localhost/v1/health)" ||
      fail "the immediate, single-attempt health request failed after restart ${iteration}"
    health_end_ms="$(now_ms)"
    health_is_ready "${health}" ||
      fail "the immediate health response was invalid after restart ${iteration}"

    current_meshd_restarts="$(unit_restarts meshd.service)"
    current_meshnetd_restarts="$(unit_restarts meshnetd.service)"
    [[ "${current_meshd_restarts}" == "${baseline_meshd_restarts}" ]] ||
      fail "meshd restarted unexpectedly during iteration ${iteration}"
    [[ "${current_meshnetd_restarts}" == "${baseline_meshnetd_restarts}" ]] ||
      fail "meshnetd restarted unexpectedly during iteration ${iteration}"

    results="$(jq -cn \
      --argjson existing "${results}" \
      --argjson index "${iteration}" \
      --argjson restart_ms "$((restart_end_ms - restart_start_ms))" \
      --argjson health_ms "$((health_end_ms - health_start_ms))" \
      '$existing + [{
        iteration: $index,
        restart_duration_ms: $restart_ms,
        immediate_health_duration_ms: $health_ms,
        health_attempts: 1,
        service_generations_changed: true,
        sockets_present: true,
        services_active: true,
        automatic_restart_counts_unchanged: true,
        health_ready: true
      }]')"
    baseline_meshd_pid="${current_meshd_pid}"
    baseline_meshnetd_pid="${current_meshnetd_pid}"
  done

  qualification_completed=true
  jq -n \
    --arg schema_version "${schema_version}" \
    --arg node_label "${node_label}" \
    --arg artifact_sha256 "${artifact_sha256}" \
    --arg package_version "${package_version}" \
    --arg os_id "${os_id}" \
    --arg os_version "${os_version}" \
    --arg kernel_release "$(uname -r)" \
    --argjson iterations "${iterations}" \
    --argjson results "${results}" \
    '{
      schema_version: $schema_version,
      node_label: $node_label,
      artifact: {
        package: "meshd",
        version: $package_version,
        sha256: $artifact_sha256,
        evidence_complete: true
      },
      platform: {
        os: $os_id,
        version: $os_version,
        kernel: $kernel_release
      },
      contract: {
        services: ["meshnetd.service", "meshd.service"],
        type: "notify",
        notify_access: "main",
        timeout_start_seconds: 30,
        health_attempts_after_each_restart: 1
      },
      iterations_requested: $iterations,
      iterations: $results,
      secrets_redacted: true,
      pass: (($results | length) == $iterations and all($results[]; .health_ready == true))
    }'
}

case "${1:-}" in
  __validate-label)
    [[ $# -eq 2 ]] || fail "__validate-label requires VALUE"
    validate_label "$2"
    exit 0
    ;;
  __validate-positive-integer)
    [[ $# -eq 4 ]] || fail "__validate-positive-integer requires LABEL VALUE MAXIMUM"
    validate_positive_integer "$2" "$3" "$4"
    exit 0
    ;;
  __health-is-ready)
    [[ $# -eq 2 ]] || fail "__health-is-ready requires JSON"
    health_is_ready "$2"
    exit 0
    ;;
  __now-ms)
    [[ $# -eq 1 ]] || fail "__now-ms does not accept arguments"
    now_ms
    exit 0
    ;;
esac

main "$@"
