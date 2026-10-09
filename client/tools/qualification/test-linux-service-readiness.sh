#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-service-readiness.sh"

help_output="$("${harness}" --help)"
grep -Fq -- 'both Type=notify services are ready' <<<"${help_output}"
grep -Fq -- 'issued exactly once' <<<"${help_output}"
grep -Fq -- 'redacted JSON report' <<<"${help_output}"

"${harness}" __validate-label ubuntu-readiness
"${harness}" __validate-label debian_13
if "${harness}" __validate-label 'host;reboot' 2>/dev/null; then
  printf 'unsafe node label was accepted\n' >&2
  exit 1
fi
if "${harness}" __validate-label '' 2>/dev/null; then
  printf 'empty node label was accepted\n' >&2
  exit 1
fi

"${harness}" __validate-positive-integer iterations 5 20
if "${harness}" __validate-positive-integer iterations 0 20 2>/dev/null; then
  printf 'zero iterations were accepted\n' >&2
  exit 1
fi
if "${harness}" __validate-positive-integer iterations 21 20 2>/dev/null; then
  printf 'excessive iterations were accepted\n' >&2
  exit 1
fi

"${harness}" __health-is-ready '{"status":"ok","api_version":"v1"}'
if "${harness}" __health-is-ready '{"status":"starting","api_version":"v1"}' 2>/dev/null; then
  printf 'non-ready health response was accepted\n' >&2
  exit 1
fi
if "${harness}" __health-is-ready '{"status":"ok","api_version":"v2"}' 2>/dev/null; then
  printf 'unexpected API version was accepted\n' >&2
  exit 1
fi

first_ms="$("${harness}" __now-ms)"
sleep 1
second_ms="$("${harness}" __now-ms)"
if (( second_ms - first_ms < 900 )); then
  printf 'cross-process clock advanced by %dms, want at least 900ms\n' \
    "$((second_ms - first_ms))" >&2
  exit 1
fi

printf 'linux service readiness qualification validation passed\n'
