#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-crash-repeat.sh"

help_output="$("${harness}" --help)"
grep -Fq -- 'Runs bounded repeated SIGKILL recovery qualification' <<<"${help_output}"
grep -Fq -- 'persisted identity/configuration bytes' <<<"${help_output}"

"${harness}" __validate-positive-integer iterations 1 20
"${harness}" __validate-positive-integer iterations 20 20
if "${harness}" __validate-positive-integer iterations 0 20 2>/dev/null; then
  printf 'zero iterations were accepted\n' >&2
  exit 1
fi
if "${harness}" __validate-positive-integer iterations 21 20 2>/dev/null; then
  printf 'excessive iterations were accepted\n' >&2
  exit 1
fi
if "${harness}" __validate-positive-integer iterations invalid 20 2>/dev/null; then
  printf 'non-numeric iterations were accepted\n' >&2
  exit 1
fi

printf 'linux repeated crash qualification validation passed\n'
