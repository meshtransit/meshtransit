#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly harness="${script_dir}/linux-network-change.sh"

help_output="$("${harness}" --help)"
grep -Fq -- 'Runs a bounded, reversible Linux interface-address change.' <<<"${help_output}"
grep -Fq -- 'never changes the' <<<"${help_output}"

printf 'linux network-change qualification validation passed\n'
