#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C
umask 077

readonly schema_version="meshtransit.linux-soak-qualification/v2"
readonly dns_resolver_address="192.0.2.53"
readonly dns_resolver_port="1053"
readonly release_duration_seconds=259200
readonly release_warmup_seconds=3600
readonly maximum_samples=20000

temp_dir=""

node_label=""
peer_label=""
peer_v4=""
peer_v6=""
peer_name=""
artifact_sha256=""
data_interface="mesh0"
dns_interface="meshdns0"
baseline_meshd_pid=0
baseline_meshnetd_pid=0
baseline_meshd_restarts=0
baseline_meshnetd_restarts=0
baseline_state_digest=""
baseline_route_digest=""
baseline_dns_digest=""
baseline_direct_count=0
baseline_network_observed=0
baseline_endpoint_refreshes=0
expected_daemon_version=""
expected_daemon_commit=""
observer_unit_bound=false
observer_restart_protected=false

usage() {
  cat <<'EOF'
Usage:
  sudo tools/qualification/linux-soak.sh \
    --node-label LABEL \
    --peer-label LABEL \
    --peer-v4 ADDRESS \
    --peer-v6 ADDRESS \
    --peer-name MESH_DNS_NAME \
    [--artifact-sha256 HEX] \
    [--duration-seconds N] \
    [--sample-interval-seconds N] \
    [--warmup-seconds N] \
    [--max-rss-growth-percent N] \
    [--max-goroutine-increase N] \
    [--max-fd-increase N] \
    [--max-thread-increase N] \
    [--data-interface NAME] \
    [--dns-interface NAME]

Runs a read-only fixed-topology Linux soak. Every sample verifies service
generation, resource cardinality, persisted state, routes, resolver policy,
online control status, MeshTransit DNS, and IPv4/IPv6 peer traffic. It measures RSS,
threads, descriptors, and authenticated local Go runtime health without
changing services, interfaces, routes, DNS, profiles, policy, or identity.

Release-candidate defaults are 72 hours, a 30-second sample interval, a
one-hour warmup, at most 10 percent post-warmup RSS growth, and bounded
goroutine, descriptor, and thread headroom. The redacted JSON report is written
to stdout. Release-candidate runs must use linux-soak-systemd.sh so systemd and
needrestart cannot replace the observer during the evidence window.
EOF
}

fail() {
  printf 'linux-soak: %s\n' "$*" >&2
  exit 1
}

progress() {
  printf 'linux-soak: %s\n' "$*" >&2
}

cleanup() {
  set +e
  if [[ -n "${temp_dir}" ]]; then
    rm -f -- "${temp_dir}/samples.ndjson"
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

  if (( ${#value} > 15 )) || [[ ! "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
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

validate_nonnegative_integer() {
  local label="$1"
  local value="$2"
  local maximum="$3"

  if [[ ! "${value}" =~ ^[0-9]+$ ]] || (( value > maximum )); then
    fail "${label} must be an integer between 0 and ${maximum}"
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

systemd_unit_from_cgroup() {
  local cgroup_path="${1:-/proc/self/cgroup}"
  local hierarchy
  local controllers
  local path
  local unit

  [[ -r "${cgroup_path}" ]] || return 1
  while IFS=: read -r hierarchy controllers path; do
    if [[ "${hierarchy}" != 0 && ",${controllers}," != *,name=systemd,* ]]; then
      continue
    fi
    unit="${path##*/}"
    if [[ "${unit}" =~ ^meshtransit-soak-[a-z0-9][a-z0-9_.@-]{0,63}\.service$ ]]; then
      printf '%s\n' "${unit}"
      return 0
    fi
  done <"${cgroup_path}"
  return 1
}

observer_has_restart_protection() {
  local unit="$1"
  local refuse_manual_stop
  local restart_policy

  [[ "${unit}" =~ ^meshtransit-soak-[a-z0-9][a-z0-9_.@-]{0,63}\.service$ ]] || return 1
  refuse_manual_stop="$(systemctl show --property=RefuseManualStop --value "${unit}" 2>/dev/null)" ||
    return 1
  restart_policy="$(systemctl show --property=Restart --value "${unit}" 2>/dev/null)" ||
    return 1
  [[ "${refuse_manual_stop}" == yes && "${restart_policy}" == no ]]
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

process_status_value() {
  local pid="$1"
  local field="$2"

  if [[ "${pid}" == 0 || ! -r "/proc/${pid}/status" ]]; then
    printf '0\n'
    return
  fi
  awk -v expected="${field}:" '
    $1 == expected {
      print $2 + 0
      found = 1
      exit
    }
    END { if (!found) print 0 }
  ' "/proc/${pid}/status"
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

dns_is_ready() {
  local dns_output

  dns_output="$(timeout 2s resolvectl query "${peer_name}" 2>/dev/null)" || return 1
  grep -Fq -- "${peer_v4}" <<<"${dns_output}" || return 1
  grep -Fq -- "${peer_v6}" <<<"${dns_output}"
}

status_is_ready() {
  local status="$1"

  jq -e --argjson minimum_direct "${baseline_direct_count}" '
    .state == "online" and
    .control_session == "synchronized" and
    .dns == "configured" and
    (.data_plane | type) == "string" and
    (.data_plane | startswith("encrypted_")) and
    .paths.available == true and
    .paths.direct_count >= $minimum_direct and
    .network_changes.available == true and
    (.runtime.goroutines | type) == "number" and .runtime.goroutines > 0 and
    (.runtime.heap_alloc_bytes | type) == "number" and .runtime.heap_alloc_bytes > 0 and
    (.runtime.heap_in_use_bytes | type) == "number" and .runtime.heap_in_use_bytes > 0 and
    (.runtime.heap_objects | type) == "number" and .runtime.heap_objects > 0 and
    (.runtime.stack_in_use_bytes | type) == "number" and .runtime.stack_in_use_bytes > 0 and
    (.runtime.sys_bytes | type) == "number" and .runtime.sys_bytes > 0 and
    (.runtime.gc_cycles | type) == "number"
  ' >/dev/null <<<"${status}"
}

take_sample() {
  local index="$1"
  local elapsed_seconds="$2"
  local observed_at
  local services_active=false
  local current_meshd_pid
  local current_meshnetd_pid
  local meshd_generation_stable=false
  local meshnetd_generation_stable=false
  local meshd_restart_count_stable=false
  local meshnetd_restart_count_stable=false
  local meshd_processes
  local meshnetd_processes
  local data_interfaces
  local dns_interfaces
  local udp_listeners
  local tcp_listeners
  local state_preserved=false
  local routes_preserved=false
  local dns_preserved=false
  local ipv4_route_ok=false
  local ipv6_route_ok=false
  local status_ready=false
  local artifact_stable=false
  local network_counters_stable=false
  local dns_ready=false
  local ipv4_traffic=false
  local ipv6_traffic=false
  local current_status="{}"
  local direct_count=0
  local relay_count=0
  local meshd_rss_kib
  local meshd_threads
  local meshd_fds
  local meshnetd_rss_kib
  local meshnetd_threads
  local meshnetd_fds
  local goroutines=0
  local heap_alloc_bytes=0
  local heap_in_use_bytes=0
  local heap_objects=0
  local stack_in_use_bytes=0
  local sys_bytes=0
  local gc_cycles=0

  observed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if systemctl is-active --quiet meshd.service meshnetd.service; then
    services_active=true
  fi
  current_meshd_pid="$(unit_pid meshd.service)"
  current_meshnetd_pid="$(unit_pid meshnetd.service)"
  [[ "${current_meshd_pid}" == "${baseline_meshd_pid}" && "${current_meshd_pid}" != 0 ]] &&
    meshd_generation_stable=true
  [[ "${current_meshnetd_pid}" == "${baseline_meshnetd_pid}" && "${current_meshnetd_pid}" != 0 ]] &&
    meshnetd_generation_stable=true
  [[ "$(unit_restart_count meshd.service)" == "${baseline_meshd_restarts}" ]] &&
    meshd_restart_count_stable=true
  [[ "$(unit_restart_count meshnetd.service)" == "${baseline_meshnetd_restarts}" ]] &&
    meshnetd_restart_count_stable=true

  meshd_processes="$(named_process_count meshd)"
  meshnetd_processes="$(named_process_count meshnetd)"
  data_interfaces="$(interface_count "${data_interface}")"
  dns_interfaces="$(interface_count "${dns_interface}")"
  udp_listeners="$(listener_count udp)"
  tcp_listeners="$(listener_count tcp)"
  [[ "$(state_digest)" == "${baseline_state_digest}" ]] && state_preserved=true
  [[ "$(route_digest "${data_interface}")" == "${baseline_route_digest}" ]] && routes_preserved=true
  [[ "$(dns_digest "${dns_interface}")" == "${baseline_dns_digest}" ]] && dns_preserved=true
  route_uses_interface 4 "${peer_v4}" "${data_interface}" && ipv4_route_ok=true
  route_uses_interface 6 "${peer_v6}" "${data_interface}" && ipv6_route_ok=true

  current_status="$(meshctl --timeout 2s --json status 2>/dev/null || printf '{}')"
  if status_is_ready "${current_status}"; then
    status_ready=true
  fi
  if jq -e \
    --arg version "${expected_daemon_version}" \
    --arg commit "${expected_daemon_commit}" \
    '.daemon.version == $version and .daemon.commit == $commit' \
    >/dev/null 2>&1 <<<"${current_status}"; then
    artifact_stable=true
  fi
  if jq -e \
    --argjson observed "${baseline_network_observed}" \
    --argjson refreshes "${baseline_endpoint_refreshes}" \
    '.network_changes.observed == $observed and
     .network_changes.endpoint_refreshes == $refreshes' \
    >/dev/null 2>&1 <<<"${current_status}"; then
    network_counters_stable=true
  fi
  direct_count="$(jq -r '.paths.direct_count // 0' <<<"${current_status}" 2>/dev/null || printf '0')"
  relay_count="$(jq -r '.paths.relay_count // 0' <<<"${current_status}" 2>/dev/null || printf '0')"
  dns_is_ready && dns_ready=true
  ping -4 -n -c 1 -W 1 "${peer_v4}" >/dev/null 2>&1 && ipv4_traffic=true
  ping -6 -n -c 1 -W 1 "${peer_v6}" >/dev/null 2>&1 && ipv6_traffic=true

  meshd_rss_kib="$(process_status_value "${current_meshd_pid}" VmRSS)"
  meshd_threads="$(process_status_value "${current_meshd_pid}" Threads)"
  meshd_fds="$(fd_count "${current_meshd_pid}")"
  meshnetd_rss_kib="$(process_status_value "${current_meshnetd_pid}" VmRSS)"
  meshnetd_threads="$(process_status_value "${current_meshnetd_pid}" Threads)"
  meshnetd_fds="$(fd_count "${current_meshnetd_pid}")"

  if [[ "${status_ready}" == true ]]; then
    goroutines="$(jq -r '.runtime.goroutines' <<<"${current_status}")"
    heap_alloc_bytes="$(jq -r '.runtime.heap_alloc_bytes' <<<"${current_status}")"
    heap_in_use_bytes="$(jq -r '.runtime.heap_in_use_bytes' <<<"${current_status}")"
    heap_objects="$(jq -r '.runtime.heap_objects' <<<"${current_status}")"
    stack_in_use_bytes="$(jq -r '.runtime.stack_in_use_bytes' <<<"${current_status}")"
    sys_bytes="$(jq -r '.runtime.sys_bytes' <<<"${current_status}")"
    gc_cycles="$(jq -r '.runtime.gc_cycles' <<<"${current_status}")"
  fi

  jq -n \
    --argjson index "${index}" \
    --argjson elapsed_seconds "${elapsed_seconds}" \
    --arg observed_at "${observed_at}" \
    --argjson services_active "${services_active}" \
    --argjson meshd_generation_stable "${meshd_generation_stable}" \
    --argjson meshnetd_generation_stable "${meshnetd_generation_stable}" \
    --argjson meshd_restart_count_stable "${meshd_restart_count_stable}" \
    --argjson meshnetd_restart_count_stable "${meshnetd_restart_count_stable}" \
    --argjson meshd_processes "${meshd_processes}" \
    --argjson meshnetd_processes "${meshnetd_processes}" \
    --argjson data_interfaces "${data_interfaces}" \
    --argjson dns_interfaces "${dns_interfaces}" \
    --argjson udp_listeners "${udp_listeners}" \
    --argjson tcp_listeners "${tcp_listeners}" \
    --argjson state_preserved "${state_preserved}" \
    --argjson routes_preserved "${routes_preserved}" \
    --argjson dns_preserved "${dns_preserved}" \
    --argjson ipv4_route_ok "${ipv4_route_ok}" \
    --argjson ipv6_route_ok "${ipv6_route_ok}" \
    --argjson status_ready "${status_ready}" \
    --argjson artifact_stable "${artifact_stable}" \
    --argjson network_counters_stable "${network_counters_stable}" \
    --argjson dns_ready "${dns_ready}" \
    --argjson ipv4_traffic "${ipv4_traffic}" \
    --argjson ipv6_traffic "${ipv6_traffic}" \
    --argjson direct_count "${direct_count}" \
    --argjson relay_count "${relay_count}" \
    --argjson meshd_rss_kib "${meshd_rss_kib}" \
    --argjson meshd_threads "${meshd_threads}" \
    --argjson meshd_fds "${meshd_fds}" \
    --argjson meshnetd_rss_kib "${meshnetd_rss_kib}" \
    --argjson meshnetd_threads "${meshnetd_threads}" \
    --argjson meshnetd_fds "${meshnetd_fds}" \
    --argjson goroutines "${goroutines}" \
    --argjson heap_alloc_bytes "${heap_alloc_bytes}" \
    --argjson heap_in_use_bytes "${heap_in_use_bytes}" \
    --argjson heap_objects "${heap_objects}" \
    --argjson stack_in_use_bytes "${stack_in_use_bytes}" \
    --argjson sys_bytes "${sys_bytes}" \
    --argjson gc_cycles "${gc_cycles}" '
      {
        index: $index,
        elapsed_seconds: $elapsed_seconds,
        observed_at: $observed_at,
        health: {
          services_active: $services_active,
          status_ready: $status_ready,
          artifact_stable: $artifact_stable,
          generation_stable: {
            meshd: $meshd_generation_stable,
            meshnetd: $meshnetd_generation_stable
          },
          restart_count_stable: {
            meshd: $meshd_restart_count_stable,
            meshnetd: $meshnetd_restart_count_stable
          },
          persisted_state_preserved: $state_preserved,
          routes_preserved: $routes_preserved,
          resolver_policy_preserved: $dns_preserved,
          network_counters_stable: $network_counters_stable,
          route_usable: {ipv4: $ipv4_route_ok, ipv6: $ipv6_route_ok},
          magic_dns: $dns_ready,
          traffic: {ipv4: $ipv4_traffic, ipv6: $ipv6_traffic}
        },
        cardinality: {
          process: {meshd: $meshd_processes, meshnetd: $meshnetd_processes},
          interface: {data: $data_interfaces, dns: $dns_interfaces},
          dns_listener: {udp: $udp_listeners, tcp: $tcp_listeners}
        },
        paths: {direct: $direct_count, relay: $relay_count},
        process: {
          meshd: {rss_kib: $meshd_rss_kib, threads: $meshd_threads, descriptors: $meshd_fds},
          meshnetd: {rss_kib: $meshnetd_rss_kib, threads: $meshnetd_threads, descriptors: $meshnetd_fds}
        },
        runtime: {
          goroutines: $goroutines,
          heap_alloc_bytes: $heap_alloc_bytes,
          heap_in_use_bytes: $heap_in_use_bytes,
          heap_objects: $heap_objects,
          stack_in_use_bytes: $stack_in_use_bytes,
          sys_bytes: $sys_bytes,
          gc_cycles: $gc_cycles
        }
      }
      | .failures = [
          if .health.services_active != true then "services_not_active" else empty end,
          if .health.status_ready != true then "daemon_status_not_ready" else empty end,
          if .health.artifact_stable != true then "artifact_changed" else empty end,
          if .health.generation_stable.meshd != true then "meshd_generation_changed" else empty end,
          if .health.generation_stable.meshnetd != true then "meshnetd_generation_changed" else empty end,
          if .health.restart_count_stable.meshd != true then "meshd_restart_count_changed" else empty end,
          if .health.restart_count_stable.meshnetd != true then "meshnetd_restart_count_changed" else empty end,
          if .health.persisted_state_preserved != true then "persisted_state_changed" else empty end,
          if .health.routes_preserved != true then "route_state_changed" else empty end,
          if .health.resolver_policy_preserved != true then "resolver_policy_changed" else empty end,
          if .health.network_counters_stable != true then "unexpected_host_network_change" else empty end,
          if .health.route_usable.ipv4 != true then "ipv4_route_unavailable" else empty end,
          if .health.route_usable.ipv6 != true then "ipv6_route_unavailable" else empty end,
          if .health.magic_dns != true then "magic_dns_unavailable" else empty end,
          if .health.traffic.ipv4 != true then "ipv4_traffic_unavailable" else empty end,
          if .health.traffic.ipv6 != true then "ipv6_traffic_unavailable" else empty end,
          if .cardinality.process.meshd != 1 then "unexpected_meshd_process_count" else empty end,
          if .cardinality.process.meshnetd != 1 then "unexpected_meshnetd_process_count" else empty end,
          if .cardinality.interface.data != 1 then "unexpected_data_interface_count" else empty end,
          if .cardinality.interface.dns != 1 then "unexpected_dns_interface_count" else empty end,
          if .cardinality.dns_listener.udp != 1 then "unexpected_udp_listener_count" else empty end,
          if .cardinality.dns_listener.tcp != 1 then "unexpected_tcp_listener_count" else empty end,
          if .process.meshd.rss_kib == 0 then "meshd_rss_unavailable" else empty end,
          if .process.meshd.threads == 0 then "meshd_threads_unavailable" else empty end,
          if .process.meshd.descriptors == 0 then "meshd_descriptors_unavailable" else empty end,
          if .process.meshnetd.rss_kib == 0 then "meshnetd_rss_unavailable" else empty end,
          if .process.meshnetd.threads == 0 then "meshnetd_threads_unavailable" else empty end,
          if .process.meshnetd.descriptors == 0 then "meshnetd_descriptors_unavailable" else empty end,
          if .runtime.goroutines == 0 then "goroutine_count_unavailable" else empty end,
          if .runtime.heap_alloc_bytes == 0 then "heap_allocation_unavailable" else empty end,
          if .runtime.heap_objects == 0 then "heap_object_count_unavailable" else empty end
        ]
      | .outcome = if (.failures | length) == 0 then "pass" else "fail" end
    '
}

summarize_samples() {
  local samples_path="$1"
  local warmup_seconds="$2"
  local max_rss_growth_percent="$3"
  local max_goroutine_increase="$4"
  local max_fd_increase="$5"
  local max_thread_increase="$6"

  jq -s \
    --argjson warmup_seconds "${warmup_seconds}" \
    --argjson max_rss_growth_percent "${max_rss_growth_percent}" \
    --argjson max_goroutine_increase "${max_goroutine_increase}" \
    --argjson max_fd_increase "${max_fd_increase}" \
    --argjson max_thread_increase "${max_thread_increase}" '
      def maximum($items; $path):
        [$items[] | getpath($path) | select(type == "number")] |
        if length == 0 then null else max end;
      def increase($baseline; $current):
        if $baseline == null or $current == null then null else $current - $baseline end;
      def growth_percent($baseline; $current):
        if $baseline == null or $baseline == 0 or $current == null then null
        else (((($current - $baseline) * 10000 / $baseline) | round) / 100)
        end;
      [.[] | select(.elapsed_seconds >= $warmup_seconds)] as $steady |
      ($steady[0] // null) as $baseline |
      ($steady[-1] // null) as $final |
      {
        warmup_seconds: $warmup_seconds,
        sample_count: ($steady | length),
        baseline_sample_index: ($baseline.index // null),
        baseline_elapsed_seconds: ($baseline.elapsed_seconds // null),
        baseline: (if $baseline == null then null else {
          process: $baseline.process,
          runtime: $baseline.runtime
        } end),
        final: (if $final == null then null else {
          process: $final.process,
          runtime: $final.runtime
        } end),
        maximum: {
          process: {
            meshd: {
              rss_kib: maximum($steady; ["process", "meshd", "rss_kib"]),
              threads: maximum($steady; ["process", "meshd", "threads"]),
              descriptors: maximum($steady; ["process", "meshd", "descriptors"])
            },
            meshnetd: {
              rss_kib: maximum($steady; ["process", "meshnetd", "rss_kib"]),
              threads: maximum($steady; ["process", "meshnetd", "threads"]),
              descriptors: maximum($steady; ["process", "meshnetd", "descriptors"])
            }
          },
          runtime: {
            goroutines: maximum($steady; ["runtime", "goroutines"]),
            heap_alloc_bytes: maximum($steady; ["runtime", "heap_alloc_bytes"]),
            heap_in_use_bytes: maximum($steady; ["runtime", "heap_in_use_bytes"]),
            heap_objects: maximum($steady; ["runtime", "heap_objects"]),
            stack_in_use_bytes: maximum($steady; ["runtime", "stack_in_use_bytes"]),
            sys_bytes: maximum($steady; ["runtime", "sys_bytes"])
          }
        }
      }
      | .increase_from_baseline = {
          process: {
            meshd: {
              rss_kib: increase(.baseline.process.meshd.rss_kib; .maximum.process.meshd.rss_kib),
              rss_percent: growth_percent(.baseline.process.meshd.rss_kib; .maximum.process.meshd.rss_kib),
              threads: increase(.baseline.process.meshd.threads; .maximum.process.meshd.threads),
              descriptors: increase(.baseline.process.meshd.descriptors; .maximum.process.meshd.descriptors)
            },
            meshnetd: {
              rss_kib: increase(.baseline.process.meshnetd.rss_kib; .maximum.process.meshnetd.rss_kib),
              rss_percent: growth_percent(.baseline.process.meshnetd.rss_kib; .maximum.process.meshnetd.rss_kib),
              threads: increase(.baseline.process.meshnetd.threads; .maximum.process.meshnetd.threads),
              descriptors: increase(.baseline.process.meshnetd.descriptors; .maximum.process.meshnetd.descriptors)
            }
          },
          runtime: {
            goroutines: increase(.baseline.runtime.goroutines; .maximum.runtime.goroutines),
            heap_alloc_bytes: increase(.baseline.runtime.heap_alloc_bytes; .maximum.runtime.heap_alloc_bytes),
            heap_objects: increase(.baseline.runtime.heap_objects; .maximum.runtime.heap_objects),
            sys_bytes: increase(.baseline.runtime.sys_bytes; .maximum.runtime.sys_bytes)
          }
        }
      | .limits = {
          max_rss_growth_percent: $max_rss_growth_percent,
          max_goroutine_increase: $max_goroutine_increase,
          max_descriptor_increase: $max_fd_increase,
          max_thread_increase: $max_thread_increase
        }
      | .failures = [
          if .sample_count < 2 then "insufficient_post_warmup_samples" else empty end,
          if .increase_from_baseline.process.meshd.rss_percent > $max_rss_growth_percent then "meshd_rss_growth_exceeded" else empty end,
          if .increase_from_baseline.process.meshnetd.rss_percent > $max_rss_growth_percent then "meshnetd_rss_growth_exceeded" else empty end,
          if .increase_from_baseline.process.meshd.threads > $max_thread_increase then "meshd_thread_growth_exceeded" else empty end,
          if .increase_from_baseline.process.meshnetd.threads > $max_thread_increase then "meshnetd_thread_growth_exceeded" else empty end,
          if .increase_from_baseline.process.meshd.descriptors > $max_fd_increase then "meshd_descriptor_growth_exceeded" else empty end,
          if .increase_from_baseline.process.meshnetd.descriptors > $max_fd_increase then "meshnetd_descriptor_growth_exceeded" else empty end,
          if .increase_from_baseline.runtime.goroutines > $max_goroutine_increase then "goroutine_growth_exceeded" else empty end
        ]
      | .outcome = if (.failures | length) == 0 then "pass" else "fail" end
    ' "${samples_path}"
}

finalize_report() {
  jq '
    .failures = ([
      if .scenario.actual_duration_seconds < .scenario.requested_duration_seconds then "duration_incomplete" else empty end,
      if .scenario.samples_completed != .scenario.samples_expected then "sample_count_incomplete" else empty end,
      if .journal.available != true then "journal_unavailable" else empty end,
      if .journal.warning_or_higher_entries != 0 then "service_warning_entries_present" else empty end,
      if .journal.error_or_higher_entries != 0 then "service_error_entries_present" else empty end,
      (.steady_state.failures[]),
      (.samples[].failures[])
    ] | unique)
    | .outcome = if (.failures | length) == 0 then "pass" else "fail" end
  '
}

journal_count() {
  local priority="$1"
  local since="$2"
  local output

  if output="$(journalctl \
    -u meshd.service \
    -u meshnetd.service \
    --since "${since}" \
    --priority="${priority}" \
    --no-pager \
    -o cat 2>/dev/null)"; then
    awk 'NF { count++ } END { print count + 0 }' <<<"${output}"
    return
  fi
  printf '%s\n' -1
}

main() {
  local duration_seconds=259200
  local sample_interval_seconds=30
  local warmup_seconds=3600
  local max_rss_growth_percent=10
  local max_goroutine_increase=8
  local max_fd_increase=4
  local max_thread_increase=4
  local command_name
  local expected_samples
  local baseline_status
  local artifact_digest_json=null
  local samples_path
  local sample
  local sample_index
  local target_elapsed
  local elapsed_seconds
  local remaining_seconds
  local started_epoch
  local finished_epoch
  local actual_duration_seconds
  local started_at
  local finished_at
  local completed_samples=0
  local samples
  local resource_summary
  local warning_entries
  local error_entries
  local journal_available=true
  local kernel_release
  local machine_arch
  local release_candidate_eligible=false
  local release_candidate_requested=false
  local observer_unit=""
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
      --artifact-sha256)
        [[ $# -ge 2 ]] || fail "--artifact-sha256 requires a value"
        artifact_sha256="$2"
        shift 2
        ;;
      --duration-seconds)
        [[ $# -ge 2 ]] || fail "--duration-seconds requires a value"
        duration_seconds="$2"
        shift 2
        ;;
      --sample-interval-seconds)
        [[ $# -ge 2 ]] || fail "--sample-interval-seconds requires a value"
        sample_interval_seconds="$2"
        shift 2
        ;;
      --warmup-seconds)
        [[ $# -ge 2 ]] || fail "--warmup-seconds requires a value"
        warmup_seconds="$2"
        shift 2
        ;;
      --max-rss-growth-percent)
        [[ $# -ge 2 ]] || fail "--max-rss-growth-percent requires a value"
        max_rss_growth_percent="$2"
        shift 2
        ;;
      --max-goroutine-increase)
        [[ $# -ge 2 ]] || fail "--max-goroutine-increase requires a value"
        max_goroutine_increase="$2"
        shift 2
        ;;
      --max-fd-increase)
        [[ $# -ge 2 ]] || fail "--max-fd-increase requires a value"
        max_fd_increase="$2"
        shift 2
        ;;
      --max-thread-increase)
        [[ $# -ge 2 ]] || fail "--max-thread-increase requires a value"
        max_thread_increase="$2"
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
  (( EUID == 0 )) || fail "run as root so process descriptors can be measured"
  [[ -n "${node_label}" ]] || fail "--node-label is required"
  [[ -n "${peer_label}" ]] || fail "--peer-label is required"
  [[ -n "${peer_v4}" ]] || fail "--peer-v4 is required"
  [[ -n "${peer_v6}" ]] || fail "--peer-v6 is required"
  [[ -n "${peer_name}" ]] || fail "--peer-name is required"
  validate_label node-label "${node_label}"
  validate_label peer-label "${peer_label}"
  validate_dns_name "${peer_name}"
  validate_interface data-interface "${data_interface}"
  validate_interface dns-interface "${dns_interface}"
  validate_positive_integer duration-seconds "${duration_seconds}" 604800
  validate_positive_integer sample-interval-seconds "${sample_interval_seconds}" 3600
  (( sample_interval_seconds >= 10 )) || fail "sample-interval-seconds must be at least 10"
  validate_nonnegative_integer warmup-seconds "${warmup_seconds}" 604799
  (( warmup_seconds < duration_seconds )) || fail "warmup-seconds must be less than duration-seconds"
  validate_nonnegative_integer max-rss-growth-percent "${max_rss_growth_percent}" 100
  validate_nonnegative_integer max-goroutine-increase "${max_goroutine_increase}" 1024
  validate_nonnegative_integer max-fd-increase "${max_fd_increase}" 1024
  validate_nonnegative_integer max-thread-increase "${max_thread_increase}" 1024
  [[ "${peer_v4}" =~ ^[0-9.]+$ ]] || fail "peer-v4 must be an IPv4 address"
  [[ "${peer_v6}" =~ ^[0-9A-Fa-f:]+$ ]] ||
    fail "peer-v6 must be an IPv6 address without a zone identifier"
  if [[ -n "${artifact_sha256}" && ! "${artifact_sha256}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    fail "artifact-sha256 must contain exactly 64 hexadecimal characters"
  fi

  expected_samples=$(( (duration_seconds + sample_interval_seconds - 1) / sample_interval_seconds + 1 ))
  (( expected_samples <= maximum_samples )) ||
    fail "duration and interval would exceed ${maximum_samples} retained samples"

  for command_name in \
    awk date find grep ip jq journalctl meshctl mktemp pgrep ping resolvectl \
    sed sha256sum sleep sort ss stat systemctl timeout uname; do
    require_command "${command_name}"
  done

  if observer_unit="$(systemd_unit_from_cgroup)"; then
    observer_unit_bound=true
    if observer_has_restart_protection "${observer_unit}"; then
      observer_restart_protected=true
    fi
  fi
  if (( duration_seconds >= release_duration_seconds &&
    warmup_seconds >= release_warmup_seconds &&
    sample_interval_seconds <= 30 &&
    max_rss_growth_percent <= 10 &&
    max_goroutine_increase <= 8 &&
    max_fd_increase <= 4 &&
    max_thread_increase <= 4 )) && [[ -n "${artifact_sha256}" ]]; then
    release_candidate_requested=true
  fi
  if [[ "${release_candidate_requested}" == true && "${observer_restart_protected}" != true ]]; then
    fail "release-candidate soak requires linux-soak-systemd.sh restart protection"
  fi

  systemctl is-active --quiet meshd.service meshnetd.service ||
    fail "meshd.service and meshnetd.service must both be active"
  baseline_meshd_pid="$(unit_pid meshd.service)"
  baseline_meshnetd_pid="$(unit_pid meshnetd.service)"
  [[ "${baseline_meshd_pid}" != 0 && "${baseline_meshnetd_pid}" != 0 ]] ||
    fail "could not resolve both service PIDs"
  baseline_meshd_restarts="$(unit_restart_count meshd.service)"
  baseline_meshnetd_restarts="$(unit_restart_count meshnetd.service)"
  baseline_status="$(meshctl --timeout 2s --json status 2>/dev/null)" ||
    fail "meshctl could not read baseline daemon status"
  baseline_direct_count="$(jq -r '.paths.direct_count // 0' <<<"${baseline_status}")"
  (( baseline_direct_count > 0 )) || fail "baseline requires at least one direct peer path"
  status_is_ready "${baseline_status}" ||
    fail "baseline status is not ready or does not expose runtime health"
  expected_daemon_version="$(jq -r '.daemon.version' <<<"${baseline_status}")"
  expected_daemon_commit="$(jq -r '.daemon.commit' <<<"${baseline_status}")"
  baseline_network_observed="$(jq -r '.network_changes.observed' <<<"${baseline_status}")"
  baseline_endpoint_refreshes="$(jq -r '.network_changes.endpoint_refreshes' <<<"${baseline_status}")"
  route_uses_interface 4 "${peer_v4}" "${data_interface}" ||
    fail "peer-v4 does not resolve through ${data_interface}"
  route_uses_interface 6 "${peer_v6}" "${data_interface}" ||
    fail "peer-v6 does not resolve through ${data_interface}"
  dns_is_ready || fail "MeshTransit DNS does not return both expected peer addresses"
  ping -4 -n -c 3 -W 1 "${peer_v4}" >/dev/null 2>&1 ||
    fail "baseline IPv4 peer traffic is unavailable"
  ping -6 -n -c 3 -W 1 "${peer_v6}" >/dev/null 2>&1 ||
    fail "baseline IPv6 peer traffic is unavailable"

  baseline_state_digest="$(state_digest)"
  baseline_route_digest="$(route_digest "${data_interface}")"
  baseline_dns_digest="$(dns_digest "${dns_interface}")"
  kernel_release="$(uname -r)"
  machine_arch="$(uname -m)"
  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-linux-soak.XXXXXXXX")"
  samples_path="${temp_dir}/samples.ndjson"
  started_epoch="$(date +%s)"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  progress "preflight passed; starting ${duration_seconds}-second fixed-topology soak"
  for (( sample_index = 0; sample_index < expected_samples; sample_index++ )); do
    target_elapsed=$(( sample_index * sample_interval_seconds ))
    if (( target_elapsed > duration_seconds )); then
      target_elapsed="${duration_seconds}"
    fi
    elapsed_seconds=$(( $(date +%s) - started_epoch ))
    if (( elapsed_seconds < target_elapsed )); then
      remaining_seconds=$(( target_elapsed - elapsed_seconds ))
      sleep "${remaining_seconds}"
    fi
    elapsed_seconds=$(( $(date +%s) - started_epoch ))
    sample="$(take_sample "${sample_index}" "${elapsed_seconds}")"
    jq -c . <<<"${sample}" >>"${samples_path}"
    completed_samples=$(( sample_index + 1 ))
    if ! jq -e '.outcome == "pass"' >/dev/null <<<"${sample}"; then
      progress "sample ${sample_index} failed; stopping soak early"
      break
    fi
    if (( elapsed_seconds >= duration_seconds )); then
      break
    fi
  done

  finished_epoch="$(date +%s)"
  actual_duration_seconds=$(( finished_epoch - started_epoch ))
  finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  samples="$(jq -s '.' "${samples_path}")"
  resource_summary="$(summarize_samples \
    "${samples_path}" \
    "${warmup_seconds}" \
    "${max_rss_growth_percent}" \
    "${max_goroutine_increase}" \
    "${max_fd_increase}" \
    "${max_thread_increase}")"
  warning_entries="$(journal_count warning "${started_at}")"
  error_entries="$(journal_count err "${started_at}")"
  if (( warning_entries < 0 || error_entries < 0 )); then
    journal_available=false
  fi
  if [[ -n "${artifact_sha256}" ]]; then
    artifact_digest_json="\"${artifact_sha256,,}\""
  fi
  if [[ "${release_candidate_requested}" == true ]]; then
    release_candidate_eligible=true
  fi

  report="$(jq -n \
    --arg schema "${schema_version}" \
    --arg started_at "${started_at}" \
    --arg finished_at "${finished_at}" \
    --arg node_label "${node_label}" \
    --arg peer_label "${peer_label}" \
    --arg kernel_release "${kernel_release}" \
    --arg architecture "${machine_arch}" \
    --arg daemon_version "${expected_daemon_version}" \
    --arg daemon_commit "${expected_daemon_commit}" \
    --argjson artifact_sha256 "${artifact_digest_json}" \
    --argjson duration_requested "${duration_seconds}" \
    --argjson duration_actual "${actual_duration_seconds}" \
    --argjson sample_interval "${sample_interval_seconds}" \
    --argjson warmup_seconds "${warmup_seconds}" \
    --argjson samples_expected "${expected_samples}" \
    --argjson samples_completed "${completed_samples}" \
    --argjson release_candidate_eligible "${release_candidate_eligible}" \
    --argjson observer_unit_bound "${observer_unit_bound}" \
    --argjson observer_restart_protected "${observer_restart_protected}" \
    --argjson warning_entries "${warning_entries}" \
    --argjson error_entries "${error_entries}" \
    --argjson journal_available "${journal_available}" \
    --argjson resource_summary "${resource_summary}" \
    --argjson samples "${samples}" '
      {
        schema: $schema,
        started_at: $started_at,
        finished_at: $finished_at,
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
          action: "read_only_fixed_topology_soak",
          requested_duration_seconds: $duration_requested,
          actual_duration_seconds: $duration_actual,
          sample_interval_seconds: $sample_interval,
          warmup_seconds: $warmup_seconds,
          samples_expected: $samples_expected,
          samples_completed: $samples_completed,
          release_candidate_eligible: $release_candidate_eligible
        },
        observer: {
          systemd_unit_bound: $observer_unit_bound,
          restart_protected: $observer_restart_protected
        },
        traffic_load: {
          ipv4_icmp_requests_per_sample: 1,
          ipv6_icmp_requests_per_sample: 1,
          magic_dns_queries_per_sample: 1,
          baseline_icmp_requests_per_family: 3
        },
        journal: {
          available: $journal_available,
          warning_or_higher_entries: $warning_entries,
          error_or_higher_entries: $error_entries
        },
        steady_state: $resource_summary,
        samples: $samples
      }
    ' | finalize_report)"

  printf '%s\n' "${report}"
  outcome="$(jq -r '.outcome' <<<"${report}")"
  if [[ "${outcome}" != pass ]]; then
    progress "qualification failed; inspect the JSON failure codes"
    return 2
  fi
  progress "qualification passed"
}

if [[ "${1:-}" == __summarize-samples ]]; then
  [[ $# -eq 7 ]] ||
    fail "__summarize-samples requires FILE WARMUP RSS GOROUTINES FDS THREADS"
  summarize_samples "$2" "$3" "$4" "$5" "$6" "$7"
  exit
fi

if [[ "${1:-}" == __finalize-report ]]; then
  [[ $# -eq 1 ]] || fail "__finalize-report does not accept arguments"
  finalize_report
  exit
fi

if [[ "${1:-}" == __systemd-unit-from-cgroup ]]; then
  [[ $# -eq 2 ]] || fail "__systemd-unit-from-cgroup requires FILE"
  systemd_unit_from_cgroup "$2"
  exit
fi

if [[ "${1:-}" == __observer-has-restart-protection ]]; then
  [[ $# -eq 2 ]] || fail "__observer-has-restart-protection requires UNIT"
  observer_has_restart_protection "$2"
  exit
fi

main "$@"
