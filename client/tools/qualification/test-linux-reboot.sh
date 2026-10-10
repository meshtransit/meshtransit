#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-reboot.sh"

"${harness}" __validate-ssh-destination root@192.0.2.10
"${harness}" __validate-ssh-destination operator@node-a.example.com

if "${harness}" __validate-ssh-destination 'root@host;reboot' 2>/dev/null; then
  printf 'unsafe SSH destination was accepted\n' >&2
  exit 1
fi
if "${harness}" __validate-ssh-destination '-oProxyCommand=unsafe' 2>/dev/null; then
  printf 'SSH option injection was accepted\n' >&2
  exit 1
fi

if [[ "$("${harness}" __ssh-driver-command ssh)" != ssh ]]; then
  printf 'ssh driver did not select the native SSH command\n' >&2
  exit 1
fi
if [[ "$("${harness}" __ssh-driver-command rtk)" != 'rtk proxy ssh' ]]; then
  printf 'rtk driver did not select the RTK SSH command\n' >&2
  exit 1
fi
if "${harness}" __ssh-driver-command unsupported 2>/dev/null; then
  printf 'unsupported SSH driver was accepted\n' >&2
  exit 1
fi

if "${harness}" \
  --target-ssh root@192.0.2.10 \
  --observer-ssh root@192.0.2.11 \
  --target-label ubuntu-a \
  --observer-label ubuntu-b \
  --target-v4 100.64.0.5 \
  --target-v6 fd07:d4de:9d87::6 \
  --target-name ubuntu-a \
  --observer-v4 100.64.0.6 \
  --observer-v6 fd07:d4de:9d87::d \
  --observer-name ubuntu-b \
  --artifact-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --confirm-reboot ubuntu-b 2>/dev/null; then
  printf 'mismatched reboot confirmation was accepted\n' >&2
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

"${harness}" --help >/dev/null

printf 'linux reboot qualification validation tests passed\n'
