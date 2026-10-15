#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-dns-qualification/v1"
readonly resolver_address="192.0.2.53"
readonly resolver_port="1053"

restore_needed=false

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-dns.sh \
    --node-label LABEL \
    --peer-label LABEL \
    --peer-v4 ADDRESS \
    --peer-v6 ADDRESS \
    --peer-name SHORT_NAME \
    --dns-domain DOMAIN \
    --confirm-dns-lifecycle LABEL \
    [--artifact-sha256 HEX] \
    [--recovery-timeout-seconds N] \
    [--poll-interval SECONDS] \
    [--dns-interface NAME] \
    [--external-name DOMAIN]

Runs a bounded Linux split-DNS qualification. It verifies authoritative
A/AAAA/PTR/NODATA/NXDOMAIN responses over UDP and TCP, short-name search, and
preservation of the host's non-mesh DNS path. It then stops only meshd.service,
proves that the dedicated DNS link and listeners are removed, and starts the
service again. A trap restores the service after interruption or failure.

DOMAIN is the peer's Network zone, <workspace code>.<network code>.<suffix>
(the node's search domain), and SHORT_NAME the peer's DNS label, so the peer
resolves as SHORT_NAME.DOMAIN.
EOF
}

fail() {
  printf 'linux-dns: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-dns: %s\n' "$*" >&2
}

cleanup() {
  set +e
  if [[ "${restore_needed}" == true ]]; then
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
  local value="$1"

  [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]
}

validate_dns_label() {
  local value="$1"

  (( ${#value} > 0 && ${#value} <= 63 )) || return 1
  [[ "${value}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]
}

validate_dns_name() {
  local value="$1"
  local dns_label
  local -a dns_labels

  (( ${#value} > 0 && ${#value} <= 253 )) || return 1
  [[ "${value}" != *. ]] || return 1
  IFS=. read -r -a dns_labels <<<"${value}"
  for dns_label in "${dns_labels[@]}"; do
    validate_dns_label "${dns_label}" || return 1
  done
}

validate_interface() {
  local value="$1"

  [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ ]]
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

validate_positive_integer() {
  local value="$1"
  local maximum="$2"

  [[ "${value}" =~ ^[1-9][0-9]*$ ]] && (( value <= maximum ))
}

validate_interval() {
  local value="$1"

  awk -v value="${value}" 'BEGIN {
    if (value !~ /^[0-9]+([.][0-9]+)?$/ || value < 0.1 || value > 2) {
      exit 1
    }
  }'
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

  printf '%d\n' $(( (end_ns - start_ns + 500000) / 1000000 ))
}

listener_ready() {
  ss -H -lnu "sport = :${resolver_port}" 2>/dev/null |
    grep -Fq -- "${resolver_address}:${resolver_port}" || return 1
  ss -H -lnt "sport = :${resolver_port}" 2>/dev/null |
    grep -Fq -- "${resolver_address}:${resolver_port}"
}

resolved_split_state() {
  local dns_interface="$1"
  local dns_domain="$2"
  local output

  output="$(resolvectl status "${dns_interface}" --no-pager 2>/dev/null)" || return 1
  grep -Fq -- "DNS Servers: ${resolver_address}:${resolver_port}" <<<"${output}" ||
    return 1
  grep -Fq -- "Protocols: -DefaultRoute" <<<"${output}" || return 1
  grep -Fq -- "DNS Domain: ${dns_domain}" <<<"${output}" || return 1
  ! grep -Eq '(^|[[:space:]])~[.]($|[[:space:]])' <<<"${output}"
}

resolved_link_removed() {
  local dns_interface="$1"
  local output

  output="$(resolvectl status "${dns_interface}" --no-pager 2>&1 || true)"
  ! awk -v expected="(${dns_interface})" '
    $1 == "Link" && $3 == expected { found = 1 }
    END { exit found ? 0 : 1 }
  ' <<<"${output}"
}

status_ready() {
  local status="$1"

  jq -e '
    .state == "online" and
    .control_session == "synchronized" and
    .dns == "configured" and
    (.data_plane | type) == "string" and
    (.data_plane | startswith("encrypted_"))
  ' >/dev/null <<<"${status}"
}

has_authoritative_flag() {
  grep -Eq '^;; flags:.*[[:space:]]aa[[:space:];]' <<<"$1"
}

direct_address_query() {
  local fqdn="$1"
  local record_type="$2"
  local expected="$3"
  local transport="$4"
  local output
  local -a transport_args=()

  if [[ "${transport}" == tcp ]]; then
    transport_args=(+tcp)
  fi
  output="$(timeout 4s dig "@${resolver_address}" -p "${resolver_port}" \
    "${fqdn}" "${record_type}" "${transport_args[@]}" \
    +time=2 +tries=1 +noall +comments +answer +authority 2>/dev/null)" || return 1
  grep -Fq -- 'status: NOERROR' <<<"${output}" || return 1
  has_authoritative_flag "${output}" || return 1
  awk -v name="${fqdn}." -v record_type="${record_type}" -v expected="${expected}" '
    $1 == name && $4 == record_type && $5 == expected { found = 1 }
    END { exit found ? 0 : 1 }
  ' <<<"${output}"
}

direct_nodata_query() {
  local fqdn="$1"
  local dns_domain="$2"
  local output

  output="$(timeout 4s dig "@${resolver_address}" -p "${resolver_port}" \
    "${fqdn}" MX +time=2 +tries=1 +noall +comments +answer +authority \
    2>/dev/null)" || return 1
  grep -Fq -- 'status: NOERROR' <<<"${output}" || return 1
  grep -Fq -- 'ANSWER: 0, AUTHORITY: 1' <<<"${output}" || return 1
  has_authoritative_flag "${output}" || return 1
  awk -v zone="${dns_domain}." '
    $1 == zone && $4 == "SOA" { found = 1 }
    END { exit found ? 0 : 1 }
  ' <<<"${output}"
}

direct_nxdomain_query() {
  local dns_domain="$1"
  local output

  output="$(timeout 4s dig "@${resolver_address}" -p "${resolver_port}" \
    "missing-qualification.${dns_domain}" A \
    +time=2 +tries=1 +noall +comments +answer +authority 2>/dev/null)" || return 1
  grep -Fq -- 'status: NXDOMAIN' <<<"${output}" || return 1
  grep -Fq -- 'ANSWER: 0, AUTHORITY: 1' <<<"${output}" || return 1
  has_authoritative_flag "${output}" || return 1
  awk -v zone="${dns_domain}." '
    $1 == zone && $4 == "SOA" { found = 1 }
    END { exit found ? 0 : 1 }
  ' <<<"${output}"
}

direct_ptr_query() {
  local address="$1"
  local fqdn="$2"
  local output

  output="$(timeout 4s dig "@${resolver_address}" -p "${resolver_port}" \
    -x "${address}" +time=2 +tries=1 +noall +comments +answer +authority \
    2>/dev/null)" || return 1
  grep -Fq -- 'status: NOERROR' <<<"${output}" || return 1
  has_authoritative_flag "${output}" || return 1
  awk -v expected="${fqdn}." '
    $4 == "PTR" && $5 == expected { found = 1 }
    END { exit found ? 0 : 1 }
  ' <<<"${output}"
}

os_name_query() {
  local name="$1"
  local peer_v4="$2"
  local peer_v6="$3"
  local dns_interface="$4"
  local output

  output="$(timeout 4s resolvectl query "${name}" --legend=no 2>/dev/null)" || return 1
  grep -Fq -- "${peer_v4}" <<<"${output}" || return 1
  grep -Fq -- "${peer_v6}" <<<"${output}" || return 1
  grep -Fq -- "link: ${dns_interface}" <<<"${output}"
}

external_query_avoids_mesh() {
  local external_name="$1"
  local dns_interface="$2"
  local output

  output="$(timeout 5s resolvectl query "${external_name}" --legend=no 2>/dev/null)" ||
    return 1
  ! grep -Fq -- "link: ${dns_interface}" <<<"${output}"
}

a_udp_ok=false
aaaa_udp_ok=false
a_tcp_ok=false
nodata_ok=false
nxdomain_ok=false
ptr4_ok=false
ptr6_ok=false
short_name_ok=false
fqdn_ok=false

collect_dns_checks() {
  local peer_name="$1"
  local dns_domain="$2"
  local peer_v4="$3"
  local peer_v6="$4"
  local dns_interface="$5"
  local fqdn="${peer_name}.${dns_domain}"

  a_udp_ok=false
  aaaa_udp_ok=false
  a_tcp_ok=false
  nodata_ok=false
  nxdomain_ok=false
  ptr4_ok=false
  ptr6_ok=false
  short_name_ok=false
  fqdn_ok=false

  direct_address_query "${fqdn}" A "${peer_v4}" udp && a_udp_ok=true
  direct_address_query "${fqdn}" AAAA "${peer_v6}" udp && aaaa_udp_ok=true
  direct_address_query "${fqdn}" A "${peer_v4}" tcp && a_tcp_ok=true
  direct_nodata_query "${fqdn}" "${dns_domain}" && nodata_ok=true
  direct_nxdomain_query "${dns_domain}" && nxdomain_ok=true
  direct_ptr_query "${peer_v4}" "${fqdn}" && ptr4_ok=true
  direct_ptr_query "${peer_v6}" "${fqdn}" && ptr6_ok=true
  os_name_query "${peer_name}" "${peer_v4}" "${peer_v6}" "${dns_interface}" &&
    short_name_ok=true
  os_name_query "${fqdn}" "${peer_v4}" "${peer_v6}" "${dns_interface}" &&
    fqdn_ok=true

  [[ "${a_udp_ok}" == true && "${aaaa_udp_ok}" == true &&
    "${a_tcp_ok}" == true && "${nodata_ok}" == true &&
    "${nxdomain_ok}" == true && "${ptr4_ok}" == true &&
    "${ptr6_ok}" == true && "${short_name_ok}" == true &&
    "${fqdn_ok}" == true ]]
}

main() {
  local node_label=""
  local peer_label=""
  local peer_v4=""
  local peer_v6=""
  local peer_name=""
  local dns_domain=""
  local confirmation=""
  local artifact_sha256=""
  local recovery_timeout_seconds=20
  local poll_interval=0.1
  local dns_interface=meshdns0
  local external_name=example.com
  local command_name
  local baseline_status
  local daemon_version
  local daemon_commit
  local started_at
  local kernel_release
  local machine_arch
  local action_start_ns
  local action_end_ns
  local stop_duration_ms=0
  local removal_deadline_ns
  local removal_observed_ns=""
  local removal_ms=null
  local start_ns
  local recovery_deadline_ns
  local recovery_observed_ns=""
  local recovery_ms=null
  local current_ns
  local current_status
  local stop_exit_code=0
  local start_exit_code=0
  local link_removed=false
  local external_during_stop=false
  local final_status_ready=false
  local final_split_state=false
  local final_listener_ready=false
  local final_dns_suite=false
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
      --dns-domain)
        [[ $# -ge 2 ]] || fail "--dns-domain requires a value"
        dns_domain="$2"
        shift 2
        ;;
      --confirm-dns-lifecycle)
        [[ $# -ge 2 ]] || fail "--confirm-dns-lifecycle requires a value"
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
      --dns-interface)
        [[ $# -ge 2 ]] || fail "--dns-interface requires a value"
        dns_interface="$2"
        shift 2
        ;;
      --external-name)
        [[ $# -ge 2 ]] || fail "--external-name requires a value"
        external_name="$2"
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
  (( EUID == 0 )) || fail "run as root so meshd.service can be stopped and restored"
  [[ -n "${node_label}" ]] || fail "--node-label is required"
  [[ -n "${peer_label}" ]] || fail "--peer-label is required"
  [[ -n "${peer_v4}" ]] || fail "--peer-v4 is required"
  [[ -n "${peer_v6}" ]] || fail "--peer-v6 is required"
  [[ -n "${peer_name}" ]] || fail "--peer-name is required"
  [[ -n "${dns_domain}" ]] || fail "--dns-domain is required"
  [[ "${confirmation}" == "${node_label}" ]] ||
    fail "--confirm-dns-lifecycle must exactly match --node-label"

  validate_label "${node_label}" || fail "node-label contains unsupported characters"
  validate_label "${peer_label}" || fail "peer-label contains unsupported characters"
  validate_dns_label "${peer_name}" || fail "peer-name must be one valid DNS label"
  validate_dns_name "${dns_domain}" || fail "dns-domain must be a bounded DNS name"
  validate_dns_name "${external_name}" || fail "external-name must be a bounded DNS name"
  validate_interface "${dns_interface}" || fail "dns-interface is invalid"
  validate_ipv4 "${peer_v4}" || fail "peer-v4 must be a canonical IPv4 address"
  validate_ipv6 "${peer_v6}" ||
    fail "peer-v6 must be an IPv6 address without a zone identifier"
  validate_positive_integer "${recovery_timeout_seconds}" 60 ||
    fail "recovery-timeout-seconds must be between 1 and 60"
  validate_interval "${poll_interval}" || fail "poll-interval must be between 0.1 and 2"
  if [[ -n "${artifact_sha256}" && ! "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    fail "artifact-sha256 must contain exactly 64 hexadecimal characters"
  fi

  for command_name in awk date dig grep ip jq meshctl resolvectl sleep ss systemctl timeout uname; do
    require_command "${command_name}"
  done
  systemctl is-active --quiet meshd.service meshnetd.service ||
    fail "meshd.service and meshnetd.service must both be active"
  ip link show dev "${dns_interface}" >/dev/null 2>&1 ||
    fail "DNS interface ${dns_interface} is not present"
  listener_ready || fail "local UDP/TCP DNS listeners are not ready"
  resolved_split_state "${dns_interface}" "${dns_domain}" ||
    fail "systemd-resolved does not contain the expected split-DNS state"
  baseline_status="$(meshctl --timeout 2s --json status 2>/dev/null)" ||
    fail "meshctl could not read baseline daemon status"
  status_ready "${baseline_status}" || fail "baseline daemon or DNS is not ready"
  collect_dns_checks "${peer_name}" "${dns_domain}" "${peer_v4}" "${peer_v6}" \
    "${dns_interface}" || fail "baseline authoritative DNS suite failed"
  external_query_avoids_mesh "${external_name}" "${dns_interface}" ||
    fail "baseline non-mesh DNS did not remain on the host resolver path"

  daemon_version="$(jq -r '.daemon.version' <<<"${baseline_status}")"
  daemon_commit="$(jq -r '.daemon.commit' <<<"${baseline_status}")"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  kernel_release="$(uname -r)"
  machine_arch="$(uname -m)"

  progress "preflight passed; stopping meshd.service to verify DNS cleanup"
  restore_needed=true
  action_start_ns="$(now_ns)"
  if systemctl stop meshd.service; then
    stop_exit_code=0
  else
    stop_exit_code=$?
  fi
  action_end_ns="$(now_ns)"
  stop_duration_ms="$(elapsed_ms "${action_start_ns}" "${action_end_ns}")"
  removal_deadline_ns=$(( action_start_ns + recovery_timeout_seconds * 1000000000 ))
  while true; do
    current_ns="$(now_ns)"
    if ! ip link show dev "${dns_interface}" >/dev/null 2>&1 &&
      ! listener_ready &&
      resolved_link_removed "${dns_interface}"; then
      removal_observed_ns="${current_ns}"
      link_removed=true
      break
    fi
    (( current_ns < removal_deadline_ns )) || break
    sleep "${poll_interval}"
  done
  [[ -z "${removal_observed_ns}" ]] ||
    removal_ms="$(elapsed_ms "${action_start_ns}" "${removal_observed_ns}")"
  external_query_avoids_mesh "${external_name}" "${dns_interface}" &&
    external_during_stop=true

  progress "starting meshd.service and waiting for DNS recovery"
  start_ns="$(now_ns)"
  if systemctl start meshd.service; then
    start_exit_code=0
  else
    start_exit_code=$?
  fi
  recovery_deadline_ns=$(( start_ns + recovery_timeout_seconds * 1000000000 ))
  while true; do
    current_ns="$(now_ns)"
    current_status="$(meshctl --timeout 1s --json status 2>/dev/null || true)"
    if [[ -n "${current_status}" ]] && status_ready "${current_status}" &&
      ip link show dev "${dns_interface}" >/dev/null 2>&1 && listener_ready &&
      resolved_split_state "${dns_interface}" "${dns_domain}"; then
      recovery_observed_ns="${current_ns}"
      restore_needed=false
      break
    fi
    (( current_ns < recovery_deadline_ns )) || break
    sleep "${poll_interval}"
  done
  [[ -z "${recovery_observed_ns}" ]] ||
    recovery_ms="$(elapsed_ms "${start_ns}" "${recovery_observed_ns}")"

  current_status="$(meshctl --timeout 2s --json status 2>/dev/null || true)"
  [[ -n "${current_status}" ]] && status_ready "${current_status}" &&
    final_status_ready=true
  resolved_split_state "${dns_interface}" "${dns_domain}" && final_split_state=true
  listener_ready && final_listener_ready=true
  collect_dns_checks "${peer_name}" "${dns_domain}" "${peer_v4}" "${peer_v6}" \
    "${dns_interface}" && final_dns_suite=true

  if [[ -n "${artifact_sha256}" ]]; then
    artifact_digest_json="\"${artifact_sha256,,}\""
  fi
  report="$(jq -n \
    --arg schema "${schema_version}" \
    --arg started_at "${started_at}" \
    --arg node_label "${node_label}" \
    --arg peer_label "${peer_label}" \
    --arg kernel_release "${kernel_release}" \
    --arg architecture "${machine_arch}" \
    --arg daemon_version "${daemon_version}" \
    --arg daemon_commit "${daemon_commit}" \
    --argjson artifact_sha256 "${artifact_digest_json}" \
    --argjson timeout_seconds "${recovery_timeout_seconds}" \
    --argjson stop_exit_code "${stop_exit_code}" \
    --argjson stop_duration_ms "${stop_duration_ms}" \
    --argjson link_removed "${link_removed}" \
    --argjson removal_ms "${removal_ms}" \
    --argjson external_during_stop "${external_during_stop}" \
    --argjson start_exit_code "${start_exit_code}" \
    --argjson recovery_ms "${recovery_ms}" \
    --argjson final_status_ready "${final_status_ready}" \
    --argjson final_split_state "${final_split_state}" \
    --argjson final_listener_ready "${final_listener_ready}" \
    --argjson final_dns_suite "${final_dns_suite}" \
    --argjson a_udp_ok "${a_udp_ok}" \
    --argjson aaaa_udp_ok "${aaaa_udp_ok}" \
    --argjson a_tcp_ok "${a_tcp_ok}" \
    --argjson nodata_ok "${nodata_ok}" \
    --argjson nxdomain_ok "${nxdomain_ok}" \
    --argjson ptr4_ok "${ptr4_ok}" \
    --argjson ptr6_ok "${ptr6_ok}" \
    --argjson short_name_ok "${short_name_ok}" \
    --argjson fqdn_ok "${fqdn_ok}" '
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
          architecture: $architecture
        },
        artifact: {
          version: $daemon_version,
          commit: $daemon_commit,
          sha256: $artifact_sha256,
          evidence_complete: ($artifact_sha256 != null)
        },
        scenario: {
          action: "graceful_meshd_stop_start",
          dns_mode: "split_only",
          changes_host_dns_directly: false
        },
        limits: {
          cleanup_and_recovery_timeout_seconds: $timeout_seconds
        },
        cleanup: {
          stop_exit_code: $stop_exit_code,
          stop_duration_ms: $stop_duration_ms,
          dedicated_link_and_listeners_removed: $link_removed,
          removal_ms: $removal_ms,
          non_mesh_dns_available: $external_during_stop
        },
        recovery: {
          start_exit_code: $start_exit_code,
          ready_ms: $recovery_ms,
          daemon_ready: $final_status_ready,
          split_routing_restored: $final_split_state,
          udp_tcp_listeners_restored: $final_listener_ready
        },
        dns: {
          complete_suite: $final_dns_suite,
          authoritative_a_udp: $a_udp_ok,
          authoritative_aaaa_udp: $aaaa_udp_ok,
          authoritative_a_tcp: $a_tcp_ok,
          authoritative_nodata: $nodata_ok,
          authoritative_nxdomain: $nxdomain_ok,
          ptr_ipv4: $ptr4_ok,
          ptr_ipv6: $ptr6_ok,
          short_name_search: $short_name_ok,
          fqdn_system_resolution: $fqdn_ok
        }
      }
      | .failures = [
          if .cleanup.stop_exit_code != 0 then "meshd_stop_failed" else empty end,
          if .cleanup.dedicated_link_and_listeners_removed != true then "dns_cleanup_timeout" else empty end,
          if .cleanup.non_mesh_dns_available != true then "host_dns_unavailable_during_stop" else empty end,
          if .recovery.start_exit_code != 0 then "meshd_start_failed" else empty end,
          if .recovery.ready_ms == null then "dns_recovery_timeout" else empty end,
          if .recovery.daemon_ready != true then "daemon_not_ready" else empty end,
          if .recovery.split_routing_restored != true then "split_routing_not_restored" else empty end,
          if .recovery.udp_tcp_listeners_restored != true then "dns_listeners_not_restored" else empty end,
          if .dns.complete_suite != true then "dns_query_suite_failed" else empty end
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

case "${1:-}" in
  __validate-label)
    [[ $# -eq 2 ]] || exit 2
    validate_label "$2"
    exit
    ;;
  __validate-dns-label)
    [[ $# -eq 2 ]] || exit 2
    validate_dns_label "$2"
    exit
    ;;
  __validate-dns-name)
    [[ $# -eq 2 ]] || exit 2
    validate_dns_name "$2"
    exit
    ;;
  __validate-ipv4)
    [[ $# -eq 2 ]] || exit 2
    validate_ipv4 "$2"
    exit
    ;;
  __validate-ipv6)
    [[ $# -eq 2 ]] || exit 2
    validate_ipv6 "$2"
    exit
    ;;
esac

main "$@"
