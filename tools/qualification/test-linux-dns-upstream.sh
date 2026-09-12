#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-dns-upstream.sh"

assert_equal() {
  local label="$1"
  local actual="$2"
  local expected="$3"

  if [[ "${actual}" != "${expected}" ]]; then
    printf '%s: got %q, want %q\n' "${label}" "${actual}" "${expected}" >&2
    exit 1
  fi
}

for phase in failover fail-closed rollback; do
  "${harness}" __validate-phase "${phase}"
done
if "${harness}" __validate-phase invalid 2>/dev/null; then
  printf 'invalid phase was accepted\n' >&2
  exit 1
fi

"${harness}" __validate-dns-name service.release-gate.example
if "${harness}" __validate-dns-name 'unsafe;name' 2>/dev/null; then
  printf 'unsafe DNS name was accepted\n' >&2
  exit 1
fi
"${harness}" __dns-name-has-suffix service.release-gate.example release-gate.example
if "${harness}" __dns-name-has-suffix notrelease-gate.example release-gate.example; then
  printf 'non-label DNS suffix match was accepted\n' >&2
  exit 1
fi

noerror_result="$(
  "${harness}" __parse-dig-result NOERROR <<'EOF'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
;; Query time: 1512 msec
EOF
)"
assert_equal noerror-result "${noerror_result}" $'NOERROR\t2\t1512'

servfail_result="$(
  "${harness}" __parse-dig-result SERVFAIL <<'EOF'
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1234
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; Query time: 1501 msec
EOF
)"
assert_equal servfail-result "${servfail_result}" $'SERVFAIL\t0\t1501'

if "${harness}" __parse-dig-result NOERROR <<'EOF' >/dev/null 2>&1
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1234
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; Query time: 1501 msec
EOF
then
  printf 'unexpected DNS status was accepted\n' >&2
  exit 1
fi

nft_counter="$(
  "${harness}" __parse-nft-counter fallback_udp <<'EOF'
{"nftables":[{"metainfo":{"json_schema_version":1}},{"rule":{"family":"inet","table":"meshtransit_dnsq","chain":"output","expr":[{"match":{"op":"=="}},{"counter":{"packets":7,"bytes":512}},{"return":null}],"comment":"fallback_udp"}}]}
EOF
)"
assert_equal nft-counter "${nft_counter}" 7

missing_counter="$(
  "${harness}" __parse-nft-counter unexpected_tcp <<'EOF'
{"nftables":[{"metainfo":{"json_schema_version":1}}]}
EOF
)"
assert_equal missing-counter "${missing_counter}" 0

"${harness}" __query-time-within-bounds 0 4500
"${harness}" __query-time-within-bounds 3 4500
if "${harness}" __query-time-within-bounds 4501 4500; then
  printf 'slow failover query was accepted\n' >&2
  exit 1
fi

"${harness}" --help >/dev/null

printf 'linux DNS upstream qualification validation tests passed\n'
