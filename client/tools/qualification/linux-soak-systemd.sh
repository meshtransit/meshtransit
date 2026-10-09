#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness_source="${script_dir}/linux-soak.sh"
readonly default_state_root="/root/meshtransit-qualification"
readonly alternative_state_root="/var/lib/meshtransit-qualification"
readonly default_duration_seconds=259200
readonly runtime_grace_seconds=3600

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-soak-systemd.sh start \
    --run-id SAFE_ID \
    [--state-root /root/meshtransit-qualification] \
    -- \
    --node-label LABEL \
    --peer-label LABEL \
    --peer-v4 ADDRESS \
    --peer-v6 ADDRESS \
    --peer-name MAGICDNS_NAME \
    --artifact-sha256 HEX \
    [linux-soak.sh options]

Starts one protected transient systemd observer for a Linux soak. The unit sets
RefuseManualStop=yes, which needrestart honors, and Restart=no, so an observer
failure cannot silently create a fresh evidence window. A pinned read-only copy
of the harness and its output directory are private root-owned files under the
selected state root.

The report stays empty until the run completes. Inspect lifecycle properties
with systemctl show meshtransit-soak-SAFE_ID.service. To deliberately abort an
active run, use systemctl kill only after independently confirming the unit.
EOF
}

fail() {
  printf 'linux-soak-systemd: %s\n' "$*" >&2
  exit 1
}

require_command() {
  local command_name="$1"

  command -v "${command_name}" >/dev/null 2>&1 ||
    fail "required command not found: ${command_name}"
}

validate_run_id() {
  local run_id="$1"

  [[ "${run_id}" =~ ^[a-z0-9][a-z0-9-]{0,47}$ ]] ||
    fail "run-id must contain 1-48 lowercase letters, digits, or hyphens"
}

validate_positive_integer() {
  local label="$1"
  local value="$2"
  local maximum="$3"

  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]] || (( value > maximum )); then
    fail "${label} must be an integer between 1 and ${maximum}"
  fi
}

duration_from_harness_args() {
  local duration="${default_duration_seconds}"
  local expect_duration=false
  local argument

  for argument in "$@"; do
    if [[ "${expect_duration}" == true ]]; then
      duration="${argument}"
      expect_duration=false
      continue
    fi
    if [[ "${argument}" == --duration-seconds ]]; then
      expect_duration=true
    fi
  done
  [[ "${expect_duration}" == false ]] || fail "--duration-seconds requires a value"
  validate_positive_integer duration-seconds "${duration}" 604800
  printf '%s\n' "${duration}"
}

validate_private_directory() {
  local path="$1"
  local mode
  local owner

  [[ -d "${path}" && ! -L "${path}" ]] ||
    fail "private directory is missing or is a symlink: ${path}"
  mode="$(stat -c '%a' -- "${path}")"
  owner="$(stat -c '%u:%g' -- "${path}")"
  [[ "${mode}" == 700 && "${owner}" == 0:0 ]] ||
    fail "private directory must be root:root mode 0700: ${path}"
}

build_systemd_command() {
  local unit_name="$1"
  local report_path="$2"
  local stderr_path="$3"
  local harness_path="$4"
  local working_directory="$5"
  local runtime_max_seconds="$6"
  shift 6

  systemd_command=(
    systemd-run
    --quiet
    "--unit=${unit_name}"
    "--description=MeshTransit fixed-topology qualification soak"
    "--property=Type=exec"
    "--property=UMask=0077"
    "--property=Nice=10"
    "--property=RuntimeMaxSec=${runtime_max_seconds}s"
    "--property=TimeoutStopSec=30s"
    "--property=PrivateTmp=yes"
    "--property=ProtectSystem=strict"
    "--property=ProtectHome=read-only"
    "--property=NoNewPrivileges=yes"
    "--property=ProtectKernelTunables=yes"
    "--property=ProtectKernelModules=yes"
    "--property=ProtectControlGroups=yes"
    "--property=RestrictSUIDSGID=yes"
    "--property=LockPersonality=yes"
    "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6"
    "--property=RefuseManualStop=yes"
    "--property=Restart=no"
    "--property=WorkingDirectory=${working_directory}"
    "--property=StandardOutput=file:${report_path}"
    "--property=StandardError=file:${stderr_path}"
    "${harness_path}"
    "$@"
  )
}

verify_started_unit() {
  local unit_name="$1"
  local active_state
  local refuse_manual_stop
  local restart_policy

  active_state="$(systemctl show --property=ActiveState --value "${unit_name}")"
  refuse_manual_stop="$(systemctl show --property=RefuseManualStop --value "${unit_name}")"
  restart_policy="$(systemctl show --property=Restart --value "${unit_name}")"
  [[ "${active_state}" == active ]] || fail "observer did not remain active"
  [[ "${refuse_manual_stop}" == yes ]] || fail "observer lacks RefuseManualStop protection"
  [[ "${restart_policy}" == no ]] || fail "observer restart policy is not fail closed"
}

require_unit_absent() {
  local unit_name="$1"
  local load_state

  load_state="$(systemctl show --property=LoadState --value "${unit_name}" 2>/dev/null)" ||
    fail "unable to inspect unit state: ${unit_name}"
  [[ -n "${load_state}" ]] || fail "systemd returned an empty unit state: ${unit_name}"
  [[ "${load_state}" == not-found ]] || fail "unit already exists: ${unit_name}"
}

start_observer() {
  local run_id=""
  local state_root="${default_state_root}"
  local output_dir
  local harness_copy
  local report_path
  local stderr_path
  local unit_name
  local duration_seconds
  local runtime_max_seconds
  local command_name
  local -a harness_args=()

  while (( $# > 0 )); do
    case "$1" in
      --run-id)
        [[ $# -ge 2 ]] || fail "--run-id requires a value"
        run_id="$2"
        shift 2
        ;;
      --state-root)
        [[ $# -ge 2 ]] || fail "--state-root requires a value"
        state_root="$2"
        shift 2
        ;;
      --)
        shift
        harness_args=("$@")
        break
        ;;
      *) fail "unknown launcher argument: $1" ;;
    esac
  done

  (( EUID == 0 )) || fail "run as root"
  [[ "$(uname -s)" == Linux ]] || fail "this launcher requires Linux"
  [[ -n "${run_id}" ]] || fail "--run-id is required"
  validate_run_id "${run_id}"
  [[ "${state_root}" == "${default_state_root}" ||
    "${state_root}" == "${alternative_state_root}" ]] ||
    fail "state-root must be ${default_state_root} or ${alternative_state_root}"
  (( ${#harness_args[@]} > 0 )) || fail "linux-soak.sh arguments are required after --"

  for command_name in install sha256sum stat systemctl systemd-run uname; do
    require_command "${command_name}"
  done
  [[ -f "${harness_source}" && ! -L "${harness_source}" ]] ||
    fail "soak harness source is missing or is a symlink"

  duration_seconds="$(duration_from_harness_args "${harness_args[@]}")"
  runtime_max_seconds=$(( duration_seconds + runtime_grace_seconds ))
  unit_name="meshtransit-soak-${run_id}.service"
  output_dir="${state_root}/${run_id}"
  harness_copy="${output_dir}/linux-soak.sh"
  report_path="${output_dir}/report.json"
  stderr_path="${output_dir}/stderr.log"

  require_unit_absent "${unit_name}"
  [[ ! -e "${output_dir}" && ! -L "${output_dir}" ]] ||
    fail "run output already exists: ${output_dir}"

  if [[ ! -e "${state_root}" ]]; then
    install -d -m 0700 -o root -g root -- "${state_root}"
  fi
  validate_private_directory "${state_root}"
  install -d -m 0700 -o root -g root -- "${output_dir}"
  validate_private_directory "${output_dir}"
  install -m 0500 -o root -g root -- "${harness_source}" "${harness_copy}"
  sha256sum -- "${harness_copy}" >"${output_dir}/HARNESS_SHA256"
  chmod 0600 -- "${output_dir}/HARNESS_SHA256"

  build_systemd_command \
    "${unit_name}" \
    "${report_path}" \
    "${stderr_path}" \
    "${harness_copy}" \
    "${output_dir}" \
    "${runtime_max_seconds}" \
    "${harness_args[@]}"
  "${systemd_command[@]}"
  verify_started_unit "${unit_name}"

  printf 'observer started: %s\n' "${unit_name}"
  printf 'report: %s\n' "${report_path}"
  printf 'stderr: %s\n' "${stderr_path}"
}

if [[ "${1:-}" == __render-systemd-command ]]; then
  [[ $# -ge 8 ]] ||
    fail "__render-systemd-command requires UNIT REPORT STDERR HARNESS WORKDIR RUNTIME ARGS..."
  shift
  build_systemd_command "$@"
  printf '%s\n' "${systemd_command[@]}"
  exit
fi

if [[ "${1:-}" == __require-unit-absent ]]; then
  [[ $# -eq 2 ]] || fail "__require-unit-absent requires UNIT"
  require_unit_absent "$2"
  exit
fi

case "${1:-}" in
  start)
    shift
    start_observer "$@"
    ;;
  --help|-h|help)
    usage
    ;;
  '')
    usage >&2
    exit 1
    ;;
  *) fail "unknown command: $1" ;;
esac
