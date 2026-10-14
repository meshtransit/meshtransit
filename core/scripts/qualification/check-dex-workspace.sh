#!/usr/bin/env bash
# Checks a prepared Dex workspace before it is used to build or test the
# identity broker, and prints the Go toolchain it pins.
#
# Usage: check-dex-workspace.sh <prepared root> <MeshCore repository root>
#
# The go.work must be byte for byte the one the artifact verifier writes
# (writeGoWorkspace in core/tools/qualification/dexartifact): the go and
# toolchain directives naming exactly the release of the repository's go.mod,
# and one use block listing the repository, the prepared source and its
# api/v2 module. Anything else (replace, godebug, another use path, another
# release) could pull unqualified code or another toolchain into the broker
# build, so it is refused.

set -euo pipefail

prepared_root="${1:-}"
repo_root="${2:-}"
[[ -f "${prepared_root}/go.work" && -f "${repo_root}/go.mod" ]] || {
	printf '%s\n' 'Prepared go.work or repository go.mod is unavailable.' >&2
	exit 2
}

module_go="$(awk '{ sub(/\r$/, "") } $1 == "go" {print $2}' "${repo_root}/go.mod")"
[[ "${module_go}" =~ ^1\.[0-9]+\.[0-9]+$ ]] || {
	printf '%s\n' 'Repository go.mod does not name one exact Go release.' >&2
	exit 1
}

# The verifier resolves symbolic links in both roots before writing go.work.
unset CDPATH
prepared_root="$(cd -- "${prepared_root}" && pwd -P)"
repo_root="$(cd -- "${repo_root}" && pwd -P)"
# strconv.Quote escapes quotes, backslashes and control characters; such paths
# are refused rather than re-encoded here.
for path in "${prepared_root}" "${repo_root}"; do
	if [[ "${path}" == *[\"\\]* || "${path}" =~ [[:cntrl:]] ]]; then
		printf '%s\n' 'Workspace paths must not need quoting escapes.' >&2
		exit 1
	fi
done

expected="$(mktemp)"
trap 'rm -f "${expected}"' EXIT
printf 'go %s\n\ntoolchain go%s\n\nuse (\n\t"%s"\n\t"%s"\n\t"%s"\n)\n' \
	"${module_go}" "${module_go}" "${repo_root}" \
	"${prepared_root}/source" "${prepared_root}/source/api/v2" >"${expected}"

cmp -s "${expected}" "${prepared_root}/go.work" || {
	printf '%s\n' 'Prepared go.work is not the verified workspace for this go.mod.' >&2
	exit 1
}

printf 'go%s\n' "${module_go}"
