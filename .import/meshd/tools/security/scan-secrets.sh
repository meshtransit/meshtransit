#!/usr/bin/env bash
set -Eeuo pipefail

command -v gitleaks >/dev/null || {
    printf 'gitleaks is required\n' >&2
    exit 1
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_dir="$(cd "${script_dir}/../.." && pwd)"
readonly repository_dir

gitleaks git --redact --no-banner --no-color --verbose "${repository_dir}"
gitleaks dir --redact --no-banner --no-color --verbose "${repository_dir}"
