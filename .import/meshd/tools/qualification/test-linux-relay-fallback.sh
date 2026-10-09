#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-relay-fallback.sh"

help_output="$("${harness}" --help)"
grep -Fq -- 'Runs a bounded, reversible direct-path loss scenario on a single-peer Linux' <<<"${help_output}"
grep -Fq -- 'SSH, the default route' <<<"${help_output}"
grep -Fq -- 'A trap removes' <<<"${help_output}"

for valid_ipv4 in 198.51.100.20 10.0.0.5 172.16.0.2; do
  "${harness}" __validate-ipv4 "${valid_ipv4}"
done
for invalid_ipv4 in \
  '198.51.100.20;reboot' \
  '198.51.100.20/32' \
  '01.2.3.4' \
  '256.1.1.1' \
  '1.2.3'; do
  if "${harness}" __validate-ipv4 "${invalid_ipv4}" >/dev/null 2>&1; then
    printf 'accepted invalid IPv4 address: %s\n' "${invalid_ipv4}" >&2
    exit 1
  fi
done

for valid_ipv6 in 2001:db8::1 fd00::2; do
  "${harness}" __validate-ipv6 "${valid_ipv6}"
done
for invalid_ipv6 in \
  '2001:db8::1%eth0' \
  '2001:db8::1;reboot' \
  'not-an-address'; do
  if "${harness}" __validate-ipv6 "${invalid_ipv6}" >/dev/null 2>&1; then
    printf 'accepted invalid IPv6 address: %s\n' "${invalid_ipv6}" >&2
    exit 1
  fi
done

rules="$("${harness}" __render-nft-batch \
  --v4 198.51.100.20 \
  --v4 10.0.0.2 \
  --v6 2001:db8::2)"
[[ "$(grep -c '^add table inet meshd_relay_qual$' <<<"${rules}")" -eq 1 ]]
[[ "$(grep -c '^add chain inet meshd_relay_qual ' <<<"${rules}")" -eq 2 ]]
[[ "$(grep -c ' meta l4proto udp counter drop comment "mesh-direct-loss"$' <<<"${rules}")" -eq 6 ]]
grep -Fq -- 'direct_out ip daddr 198.51.100.20 meta l4proto udp' <<<"${rules}"
grep -Fq -- 'direct_in ip saddr 10.0.0.2 meta l4proto udp' <<<"${rules}"
grep -Fq -- 'direct_out ip6 daddr 2001:db8::2 meta l4proto udp' <<<"${rules}"
if grep -Eq -- 'accept|tcp|ssh|443|22' <<<"$(grep '^add rule ' <<<"${rules}")"; then
  printf 'rendered rules escaped the intended UDP-only drop scope\n' >&2
  exit 1
fi

printf 'linux relay-fallback qualification validation passed\n'
