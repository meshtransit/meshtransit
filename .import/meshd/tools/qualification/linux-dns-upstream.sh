#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-dns-upstream-node-qualification/v1"
readonly resolver_address="192.0.2.53"
readonly resolver_port="1053"
readonly nft_family="inet"
readonly nft_table="meshtransit_dnsq"

fault_table_active=false

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-dns-upstream.sh \
    --node-label LABEL \
    --peer-label LABEL \
    --peer-v4 ADDRESS \
    --peer-v6 ADDRESS \
    --peer-name MAGICDNS_NAME \
    --magic-domain DOMAIN \
    --test-domain DOMAIN \
    --test-query NAME \
    --phase failover|fail-closed|rollback \
    --artifact-sha256 HEX \
    --confirm-dns-upstream LABEL \
    [--blocked-resolver IPV4] \
    [--fallback-resolver IPV4] \
    [--samples N] \
    [--maximum-query-ms N] \
    [--dns-interface NAME]

Runs one installed-host upstream DNS qualification phase. The failover phase
requires a control-issued split route containing the blocked resolver first and
the fallback resolver second. The fail-closed phase requires only the blocked
resolver. The rollback phase requires the temporary split route to be absent.
Successful failover and fail-closed responses may be immediate when resolver
racing, cached health, or a circuit breaker has already selected the outcome.
Resolver counters prove fault exercise; the maximum query time remains bounded.

For failure phases, a temporary nftables output chain drops port 53 traffic
from the meshd service UID to only the declared blocked resolver and counts the
declared fallback and unexpected destinations. A trap removes the exact table.
The script never edits control configuration or host resolver files.
EOF
}

fail() {
  printf 'linux-dns-upstream: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-dns-upstream: %s\n' "$*" >&2
}

cleanup() {
  set +e
  if [[ "${fault_table_active}" == true ]]; then
    nft delete table "${nft_family}" "${nft_table}" >/dev/null 2>&1
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
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]
}

validate_interface() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ ]]
}

validate_dns_name() {
  local value="$1"
  local label
  local -a labels

  (( ${#value} > 0 && ${#value} <= 253 )) || return 1
  [[ "${value}" != *. ]] || return 1
  IFS=. read -r -a labels <<<"${value}"
  for label in "${labels[@]}"; do
    (( ${#label} > 0 && ${#label} <= 63 )) || return 1
    [[ "${label}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
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
  [[ "$1" =~ ^[0-9A-Fa-f:]+$ && "$1" == *:* ]]
}

validate_positive_integer() {
  local value="$1"
  local maximum="$2"

  [[ "${value}" =~ ^[1-9][0-9]*$ ]] && (( value <= maximum ))
}

validate_phase() {
  case "$1" in
    failover|fail-closed|rollback) return 0 ;;
    *) return 1 ;;
  esac
}

query_time_within_bounds() {
  local query_ms="$1"
  local maximum_query_ms="$2"

  (( query_ms <= maximum_query_ms ))
}

dns_name_has_suffix() {
  local name="$1"
  local suffix="$2"

  [[ "${name}" == "${suffix}" || "${name}" == *."${suffix}" ]]
}

status_is_ready() {
  jq -e '
    .state == "online" and
    .control_session == "synchronized" and
    .dns == "configured" and
    .registration == "registered" and
    (.data_plane | type) == "string" and
    (.data_plane | startswith("encrypted_")) and
    .paths.available == true
  ' >/dev/null <<<"$1"
}

split_route_present() {
  local dns_interface="$1"
  local test_domain="$2"

  resolvectl status "${dns_interface}" --no-pager 2>/dev/null |
    grep -Fq -- "~${test_domain}"
}

magic_domain_present() {
  local dns_interface="$1"
  local magic_domain="$2"

  resolvectl status "${dns_interface}" --no-pager 2>/dev/null |
    grep -Fq -- "${magic_domain}"
}

magic_dns_ready() {
  local peer_name="$1"
  local peer_v4="$2"
  local peer_v6="$3"
  local dns_interface="$4"
  local output

  output="$(timeout 4s resolvectl query "${peer_name}" --legend=no 2>/dev/null)" ||
    return 1
  grep -Fq -- "${peer_v4}" <<<"${output}" || return 1
  grep -Fq -- "${peer_v6}" <<<"${output}" || return 1
  grep -Fq -- "link: ${dns_interface}" <<<"${output}"
}

peer_traffic_ready() {
  ping -4 -n -c 5 -W 1 "$1" >/dev/null 2>&1 &&
    ping -6 -n -c 5 -W 1 "$2" >/dev/null 2>&1
}

parse_dig_result() {
  local expected_status="$1"

  awk -v expected="${expected_status}" '
    /^;; ->>HEADER<<-/ {
      for (field_index = 1; field_index <= NF; field_index++) {
        if ($field_index == "status:") {
          status = $(field_index + 1)
          gsub(/,/, "", status)
        }
      }
    }
    /^;; flags:/ {
      for (field_index = 1; field_index <= NF; field_index++) {
        if ($field_index == "ANSWER:") {
          answers = $(field_index + 1)
          gsub(/,/, "", answers)
        }
      }
    }
    /^;; Query time:/ {
      query_ms = $4
    }
    END {
      if (status != expected || answers !~ /^[0-9]+$/ || query_ms !~ /^[0-9]+$/) {
        exit 2
      }
      if ((expected == "NOERROR" && answers < 1) ||
          (expected == "SERVFAIL" && answers != 0)) {
        exit 3
      }
      printf "%s\t%d\t%d\n", status, answers, query_ms
    }
  '
}

query_once() {
  local query_name="$1"
  local transport="$2"
  local expected_status="$3"
  local output
  local -a transport_args=()

  if [[ "${transport}" == tcp ]]; then
    transport_args=(+tcp)
  fi
  output="$(timeout 7s dig "@${resolver_address}" -p "${resolver_port}" \
    "${query_name}" A "${transport_args[@]}" \
    +time=5 +tries=1 +noall +comments +answer +stats 2>/dev/null)" || return 1
  parse_dig_result "${expected_status}" <<<"${output}"
}

upstream_ready() {
  local resolver="$1"
  local query_name="$2"
  local transport="$3"
  local output
  local -a transport_args=()

  if [[ "${transport}" == tcp ]]; then
    transport_args=(+tcp)
  fi
  output="$(timeout 4s dig "@${resolver}" "${query_name}" A \
    "${transport_args[@]}" +time=3 +tries=1 +noall +comments +answer +stats \
    2>/dev/null)" || return 1
  parse_dig_result NOERROR <<<"${output}" >/dev/null
}

parse_nft_counter() {
  local counter_name="$1"

  jq -er --arg name "${counter_name}" '
    [
      .nftables[]
      | .rule?
      | select(.comment == $name)
      | .expr[]?
      | select(has("counter"))
      | .counter.packets
    ][0] // 0
  '
}

nft_counter() {
  local counter_name="$1"

  nft -j list chain "${nft_family}" "${nft_table}" output |
    parse_nft_counter "${counter_name}"
}

install_fault_table() {
  local service_uid="$1"
  local blocked_resolver="$2"
  local fallback_resolver="$3"

  if nft list table "${nft_family}" "${nft_table}" >/dev/null 2>&1; then
    fail "qualification nftables table already exists"
  fi
  nft add table "${nft_family}" "${nft_table}"
  fault_table_active=true
  nft "add chain ${nft_family} ${nft_table} output { type filter hook output priority -10; policy accept; }"
  nft "add rule ${nft_family} ${nft_table} output meta skuid ${service_uid} ip daddr ${blocked_resolver} udp dport 53 counter drop comment \"blocked_udp\""
  nft "add rule ${nft_family} ${nft_table} output meta skuid ${service_uid} ip daddr ${blocked_resolver} tcp dport 53 counter drop comment \"blocked_tcp\""
  if [[ -n "${fallback_resolver}" ]]; then
    nft "add rule ${nft_family} ${nft_table} output meta skuid ${service_uid} ip daddr ${fallback_resolver} udp dport 53 counter return comment \"fallback_udp\""
    nft "add rule ${nft_family} ${nft_table} output meta skuid ${service_uid} ip daddr ${fallback_resolver} tcp dport 53 counter return comment \"fallback_tcp\""
  fi
  nft "add rule ${nft_family} ${nft_table} output meta skuid ${service_uid} udp dport 53 counter comment \"unexpected_udp\""
  nft "add rule ${nft_family} ${nft_table} output meta skuid ${service_uid} tcp dport 53 counter comment \"unexpected_tcp\""
}

main() {
  local node_label=""
  local peer_label=""
  local peer_v4=""
  local peer_v6=""
  local peer_name=""
  local magic_domain=""
  local test_domain=""
  local test_query=""
  local phase=""
  local artifact_sha256=""
  local confirmation=""
  local blocked_resolver=""
  local fallback_resolver=""
  local samples=5
  local maximum_query_ms=4500
  local dns_interface="meshdns0"
  local command_name
  local baseline_status
  local final_status
  local daemon_version
  local daemon_commit
  local kernel_release
  local machine_arch
  local started_at
  local meshd_pid_before
  local meshd_pid_after
  local invocation_before
  local invocation_after
  local restarts_before
  local restarts_after
  local service_user
  local service_uid
  local expected_status
  local route_state_ok=false
  local parser_ok=true
  local query_results_ok=true
  local host_query_ok=false
  local magic_dns_ok=false
  local peer_traffic_ok=false
  local final_status_ok=false
  local service_generation_preserved=false
  local restart_count_preserved=false
  local nft_cleanup_ok=true
  local journal_error_count=0
  local udp_passed=0
  local tcp_passed=0
  local udp_min_ms=null
  local udp_max_ms=null
  local tcp_min_ms=null
  local tcp_max_ms=null
  local metrics
  local parsed_status
  local answer_count
  local query_ms
  local sample
  local transport
  local blocked_udp=0
  local blocked_tcp=0
  local fallback_udp=0
  local fallback_tcp=0
  local unexpected_udp=0
  local unexpected_tcp=0
  local counters_ok=true
  local blocked_baseline_ok=null
  local fallback_baseline_ok=null
  local host_output=""
  local report
  local outcome

  while (( $# > 0 )); do
    case "$1" in
      --node-label) node_label="${2:-}"; shift 2 ;;
      --peer-label) peer_label="${2:-}"; shift 2 ;;
      --peer-v4) peer_v4="${2:-}"; shift 2 ;;
      --peer-v6) peer_v6="${2:-}"; shift 2 ;;
      --peer-name) peer_name="${2:-}"; shift 2 ;;
      --magic-domain) magic_domain="${2:-}"; shift 2 ;;
      --test-domain) test_domain="${2:-}"; shift 2 ;;
      --test-query) test_query="${2:-}"; shift 2 ;;
      --phase) phase="${2:-}"; shift 2 ;;
      --artifact-sha256) artifact_sha256="${2:-}"; shift 2 ;;
      --confirm-dns-upstream) confirmation="${2:-}"; shift 2 ;;
      --blocked-resolver) blocked_resolver="${2:-}"; shift 2 ;;
      --fallback-resolver) fallback_resolver="${2:-}"; shift 2 ;;
      --samples) samples="${2:-}"; shift 2 ;;
      --maximum-query-ms) maximum_query_ms="${2:-}"; shift 2 ;;
      --dns-interface) dns_interface="${2:-}"; shift 2 ;;
      --help|-h) usage; return 0 ;;
      *) fail "unknown argument: $1" ;;
    esac
  done

  [[ "$(uname -s)" == Linux ]] || fail "this harness requires Linux"
  (( EUID == 0 )) || fail "run as root for the bounded nftables fault"
  validate_label "${node_label}" || fail "node-label is invalid"
  validate_label "${peer_label}" || fail "peer-label is invalid"
  validate_dns_name "${peer_name}" || fail "peer-name is invalid"
  validate_dns_name "${magic_domain}" || fail "magic-domain is invalid"
  validate_dns_name "${test_domain}" || fail "test-domain is invalid"
  validate_dns_name "${test_query}" || fail "test-query is invalid"
  dns_name_has_suffix "${test_query}" "${test_domain}" ||
    fail "test-query must be inside test-domain"
  validate_ipv4 "${peer_v4}" || fail "peer-v4 is invalid"
  validate_ipv6 "${peer_v6}" || fail "peer-v6 is invalid"
  validate_phase "${phase}" || fail "phase must be failover, fail-closed, or rollback"
  validate_interface "${dns_interface}" || fail "dns-interface is invalid"
  [[ "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]] ||
    fail "artifact-sha256 must contain exactly 64 hexadecimal characters"
  [[ "${confirmation}" == "${node_label}" ]] ||
    fail "confirm-dns-upstream must exactly match node-label"
  validate_positive_integer "${samples}" 20 || fail "samples must be between 1 and 20"
  validate_positive_integer "${maximum_query_ms}" 10000 ||
    fail "maximum-query-ms must be between 1 and 10000"

  case "${phase}" in
    failover)
      validate_ipv4 "${blocked_resolver}" || fail "blocked-resolver is required"
      validate_ipv4 "${fallback_resolver}" || fail "fallback-resolver is required"
      [[ "${blocked_resolver}" != "${fallback_resolver}" ]] ||
        fail "blocked and fallback resolvers must differ"
      expected_status=NOERROR
      ;;
    fail-closed)
      validate_ipv4 "${blocked_resolver}" || fail "blocked-resolver is required"
      [[ -z "${fallback_resolver}" ]] || fail "fallback-resolver is invalid for fail-closed"
      expected_status=SERVFAIL
      ;;
    rollback)
      [[ -z "${blocked_resolver}" && -z "${fallback_resolver}" ]] ||
        fail "resolver arguments are invalid for rollback"
      expected_status=SERVFAIL
      ;;
  esac

  for command_name in awk date dig grep id ip jq journalctl meshctl nft ping \
    resolvectl systemctl timeout uname; do
    require_command "${command_name}"
  done
  systemctl is-active --quiet meshd.service meshnetd.service ||
    fail "meshd.service and meshnetd.service must both be active"
  ip link show dev "${dns_interface}" >/dev/null 2>&1 ||
    fail "DNS interface is absent"

  baseline_status="$(meshctl --timeout 3s --json status 2>/dev/null)" ||
    fail "baseline status is unavailable"
  status_is_ready "${baseline_status}" || fail "baseline status is not ready"
  magic_domain_present "${dns_interface}" "${magic_domain}" ||
    fail "MagicDNS domain does not match the expected network"
  magic_dns_ready "${peer_name}" "${peer_v4}" "${peer_v6}" "${dns_interface}" ||
    fail "baseline MagicDNS is not ready"
  peer_traffic_ready "${peer_v4}" "${peer_v6}" ||
    fail "baseline dual-stack peer traffic is not ready"

  if [[ "${phase}" == rollback ]]; then
    if ! split_route_present "${dns_interface}" "${test_domain}"; then
      route_state_ok=true
    fi
  elif split_route_present "${dns_interface}" "${test_domain}"; then
    route_state_ok=true
  fi
  [[ "${route_state_ok}" == true ]] || fail "control-issued split route does not match the phase"

  daemon_version="$(jq -r '.daemon.version' <<<"${baseline_status}")"
  daemon_commit="$(jq -r '.daemon.commit' <<<"${baseline_status}")"
  kernel_release="$(uname -r)"
  machine_arch="$(uname -m)"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  meshd_pid_before="$(systemctl show meshd.service -p MainPID --value)"
  invocation_before="$(systemctl show meshd.service -p InvocationID --value)"
  restarts_before="$(systemctl show meshd.service -p NRestarts --value)"
  service_user="$(systemctl show meshd.service -p User --value)"
  [[ -n "${service_user}" ]] || fail "meshd service user is unavailable"
  service_uid="$(id -u "${service_user}")" || fail "meshd service UID is unavailable"
  [[ "${service_uid}" =~ ^[1-9][0-9]*$ ]] || fail "meshd must use a non-root service UID"

  if [[ "${phase}" != rollback ]]; then
    blocked_baseline_ok=true
    for transport in udp tcp; do
      upstream_ready "${blocked_resolver}" "${test_query}" "${transport}" ||
        blocked_baseline_ok=false
    done
    [[ "${blocked_baseline_ok}" == true ]] ||
      fail "blocked resolver is not healthy before fault injection"
    if [[ "${phase}" == failover ]]; then
      fallback_baseline_ok=true
      for transport in udp tcp; do
        upstream_ready "${fallback_resolver}" "${test_query}" "${transport}" ||
          fallback_baseline_ok=false
      done
      [[ "${fallback_baseline_ok}" == true ]] ||
        fail "fallback resolver is not healthy before fault injection"
    fi
    progress "installing a UID-scoped resolver fault"
    install_fault_table "${service_uid}" "${blocked_resolver}" "${fallback_resolver}"
  fi

  progress "running ${samples} UDP and ${samples} TCP samples"
  for transport in udp tcp; do
    for ((sample = 1; sample <= samples; sample++)); do
      if metrics="$(query_once "${test_query}" "${transport}" "${expected_status}")"; then
        IFS=$'\t' read -r parsed_status answer_count query_ms <<<"${metrics}"
        if [[ "${parsed_status}" != "${expected_status}" ]] ||
          [[ "${expected_status}" == NOERROR && ${answer_count} -lt 1 ]] ||
          [[ "${expected_status}" == SERVFAIL && ${answer_count} -ne 0 ]]; then
          query_results_ok=false
        fi
        if ! query_time_within_bounds "${query_ms}" "${maximum_query_ms}"; then
          query_results_ok=false
        fi
        if [[ "${transport}" == udp ]]; then
          udp_passed=$((udp_passed + 1))
          [[ "${udp_min_ms}" != null && ${query_ms} -ge ${udp_min_ms} ]] || udp_min_ms="${query_ms}"
          [[ "${udp_max_ms}" != null && ${query_ms} -le ${udp_max_ms} ]] || udp_max_ms="${query_ms}"
        else
          tcp_passed=$((tcp_passed + 1))
          [[ "${tcp_min_ms}" != null && ${query_ms} -ge ${tcp_min_ms} ]] || tcp_min_ms="${query_ms}"
          [[ "${tcp_max_ms}" != null && ${query_ms} -le ${tcp_max_ms} ]] || tcp_max_ms="${query_ms}"
        fi
      else
        parser_ok=false
        query_results_ok=false
      fi
    done
  done
  if (( udp_passed != samples || tcp_passed != samples )); then
    query_results_ok=false
  fi

  if [[ "${phase}" == failover ]]; then
    host_output="$(timeout 7s resolvectl query "${test_query}" --legend=no 2>/dev/null || true)"
    if [[ -n "${host_output}" ]] && grep -Fq -- "link: ${dns_interface}" <<<"${host_output}"; then
      host_query_ok=true
    fi
  elif [[ "${phase}" == fail-closed ]]; then
    if ! timeout 7s resolvectl query "${test_query}" --legend=no >/dev/null 2>&1; then
      host_query_ok=true
    fi
  else
    host_output="$(timeout 7s resolvectl query "${test_query}" --legend=no 2>/dev/null || true)"
    if [[ -n "${host_output}" ]] && ! grep -Fq -- "link: ${dns_interface}" <<<"${host_output}"; then
      host_query_ok=true
    fi
  fi

  magic_dns_ready "${peer_name}" "${peer_v4}" "${peer_v6}" "${dns_interface}" &&
    magic_dns_ok=true
  peer_traffic_ready "${peer_v4}" "${peer_v6}" && peer_traffic_ok=true
  final_status="$(meshctl --timeout 3s --json status 2>/dev/null || true)"
  if [[ -n "${final_status}" ]] && status_is_ready "${final_status}" &&
    [[ "$(jq -r '.daemon.version' <<<"${final_status}")" == "${daemon_version}" ]] &&
    [[ "$(jq -r '.daemon.commit' <<<"${final_status}")" == "${daemon_commit}" ]]; then
    final_status_ok=true
  fi

  if [[ "${phase}" != rollback ]]; then
    blocked_udp="$(nft_counter blocked_udp)"
    blocked_tcp="$(nft_counter blocked_tcp)"
    unexpected_udp="$(nft_counter unexpected_udp)"
    unexpected_tcp="$(nft_counter unexpected_tcp)"
    if [[ "${phase}" == failover ]]; then
      fallback_udp="$(nft_counter fallback_udp)"
      fallback_tcp="$(nft_counter fallback_tcp)"
      if (( fallback_udp < samples || fallback_tcp < samples )); then
        counters_ok=false
      fi
    fi
    if (( blocked_udp < samples || blocked_tcp < samples ||
      unexpected_udp != 0 || unexpected_tcp != 0 )); then
      counters_ok=false
    fi
    nft delete table "${nft_family}" "${nft_table}"
    fault_table_active=false
    if nft list table "${nft_family}" "${nft_table}" >/dev/null 2>&1; then
      nft_cleanup_ok=false
    fi
  fi

  meshd_pid_after="$(systemctl show meshd.service -p MainPID --value)"
  invocation_after="$(systemctl show meshd.service -p InvocationID --value)"
  restarts_after="$(systemctl show meshd.service -p NRestarts --value)"
  if [[ "${meshd_pid_after}" == "${meshd_pid_before}" &&
    "${invocation_after}" == "${invocation_before}" ]]; then
    service_generation_preserved=true
  fi
  if [[ "${restarts_after}" == "${restarts_before}" ]]; then
    restart_count_preserved=true
  fi
  journal_error_count="$(journalctl -u meshd.service -u meshnetd.service \
    --since "${started_at}" -p err --no-pager -o cat 2>/dev/null |
    awk 'NF { count++ } END { print count + 0 }')"

  report="$(jq -n \
    --arg schema "${schema_version}" \
    --arg started_at "${started_at}" \
    --arg node_label "${node_label}" \
    --arg peer_label "${peer_label}" \
    --arg phase "${phase}" \
    --arg kernel_release "${kernel_release}" \
    --arg architecture "${machine_arch}" \
    --arg daemon_version "${daemon_version}" \
    --arg daemon_commit "${daemon_commit}" \
    --arg artifact_sha256 "${artifact_sha256,,}" \
    --arg expected_status "${expected_status}" \
    --argjson samples "${samples}" \
    --argjson maximum_query_ms "${maximum_query_ms}" \
    --argjson route_state_ok "${route_state_ok}" \
    --argjson parser_ok "${parser_ok}" \
    --argjson query_results_ok "${query_results_ok}" \
    --argjson host_query_ok "${host_query_ok}" \
    --argjson udp_passed "${udp_passed}" \
    --argjson tcp_passed "${tcp_passed}" \
    --argjson udp_min_ms "${udp_min_ms}" \
    --argjson udp_max_ms "${udp_max_ms}" \
    --argjson tcp_min_ms "${tcp_min_ms}" \
    --argjson tcp_max_ms "${tcp_max_ms}" \
    --argjson blocked_udp "${blocked_udp}" \
    --argjson blocked_tcp "${blocked_tcp}" \
    --argjson fallback_udp "${fallback_udp}" \
    --argjson fallback_tcp "${fallback_tcp}" \
    --argjson unexpected_udp "${unexpected_udp}" \
    --argjson unexpected_tcp "${unexpected_tcp}" \
    --argjson counters_ok "${counters_ok}" \
    --argjson blocked_baseline_ok "${blocked_baseline_ok}" \
    --argjson fallback_baseline_ok "${fallback_baseline_ok}" \
    --argjson nft_cleanup_ok "${nft_cleanup_ok}" \
    --argjson magic_dns_ok "${magic_dns_ok}" \
    --argjson peer_traffic_ok "${peer_traffic_ok}" \
    --argjson final_status_ok "${final_status_ok}" \
    --argjson service_generation_preserved "${service_generation_preserved}" \
    --argjson restart_count_preserved "${restart_count_preserved}" \
    --argjson journal_error_count "${journal_error_count}" '
      {
        schema: $schema,
        started_at: $started_at,
        topology: {
          node_label: $node_label,
          peer_label: $peer_label,
          address_families: ["ipv4", "ipv6"]
        },
        platform: {kernel_release: $kernel_release, architecture: $architecture},
        artifact: {
          version: $daemon_version,
          commit: $daemon_commit,
          sha256: $artifact_sha256,
          evidence_complete: true
        },
        scenario: {
          phase: $phase,
          split_route_expected: ($phase != "rollback"),
          blocked_resolver_count: (if $phase == "rollback" then 0 else 1 end),
          fallback_resolver_count: (if $phase == "failover" then 1 else 0 end),
          changes_control_configuration: false,
          changes_host_resolver_files: false
        },
        limits: {
          samples_per_transport: $samples,
          maximum_query_ms: $maximum_query_ms
        },
        queries: {
          expected_status: $expected_status,
          parser_ok: $parser_ok,
          results_within_bounds: $query_results_ok,
          host_resolver_behavior_correct: $host_query_ok,
          udp: {passed: $udp_passed, minimum_ms: $udp_min_ms, maximum_ms: $udp_max_ms},
          tcp: {passed: $tcp_passed, minimum_ms: $tcp_min_ms, maximum_ms: $tcp_max_ms}
        },
        resolver_traffic: {
          uid_scoped: ($phase != "rollback"),
          blocked_resolver_healthy_before_fault: $blocked_baseline_ok,
          fallback_resolver_healthy_before_fault: $fallback_baseline_ok,
          blocked_udp_packets: $blocked_udp,
          blocked_tcp_packets: $blocked_tcp,
          fallback_udp_packets: $fallback_udp,
          fallback_tcp_packets: $fallback_tcp,
          unexpected_udp_packets: $unexpected_udp,
          unexpected_tcp_packets: $unexpected_tcp,
          destination_gate_passed: $counters_ok,
          fault_table_removed: $nft_cleanup_ok
        },
        continuity: {
          split_route_state_correct: $route_state_ok,
          magic_dns_healthy: $magic_dns_ok,
          peer_dual_stack_healthy: $peer_traffic_ok,
          daemon_ready: $final_status_ok,
          service_generation_preserved: $service_generation_preserved,
          restart_count_preserved: $restart_count_preserved,
          error_journal_entries: $journal_error_count
        }
      }
      | .failures = [
          if .queries.parser_ok != true then "query_result_unparseable" else empty end,
          if .queries.results_within_bounds != true then "query_result_out_of_bounds" else empty end,
          if .queries.host_resolver_behavior_correct != true then "host_resolver_behavior_incorrect" else empty end,
          if .resolver_traffic.destination_gate_passed != true then "resolver_destination_gate_failed" else empty end,
          if .resolver_traffic.fault_table_removed != true then "fault_table_cleanup_failed" else empty end,
          if .continuity.split_route_state_correct != true then "split_route_state_incorrect" else empty end,
          if .continuity.magic_dns_healthy != true then "magic_dns_unhealthy" else empty end,
          if .continuity.peer_dual_stack_healthy != true then "peer_traffic_unhealthy" else empty end,
          if .continuity.daemon_ready != true then "daemon_not_ready" else empty end,
          if .continuity.service_generation_preserved != true then "service_generation_changed" else empty end,
          if .continuity.restart_count_preserved != true then "restart_count_changed" else empty end,
          if .continuity.error_journal_entries != 0 then "service_error_logged" else empty end
        ]
      | .outcome = if (.failures | length) == 0 then "pass" else "fail" end
    ')"

  printf '%s\n' "${report}"
  outcome="$(jq -r '.outcome' <<<"${report}")"
  [[ "${outcome}" == pass ]] || return 2
  progress "qualification passed"
}

case "${1:-}" in
  __validate-phase)
    [[ $# -eq 2 ]] || exit 2
    validate_phase "$2"
    exit
    ;;
  __validate-dns-name)
    [[ $# -eq 2 ]] || exit 2
    validate_dns_name "$2"
    exit
    ;;
  __dns-name-has-suffix)
    [[ $# -eq 3 ]] || exit 2
    dns_name_has_suffix "$2" "$3"
    exit
    ;;
  __parse-dig-result)
    [[ $# -eq 2 ]] || exit 2
    parse_dig_result "$2"
    exit
    ;;
  __parse-nft-counter)
    [[ $# -eq 2 ]] || exit 2
    parse_nft_counter "$2"
    exit
    ;;
  __query-time-within-bounds)
    [[ $# -eq 3 ]] || exit 2
    query_time_within_bounds "$2" "$3"
    exit
    ;;
esac

main "$@"
