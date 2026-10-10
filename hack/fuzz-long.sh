#!/usr/bin/env bash
# Runs every fuzz target in the repository for a fixed time each and reports
# the targets that failed. Failing inputs stay in each package's
# testdata/fuzz directory, where `go test` replays them from then on.
#
#   FUZZ_TIME=10m FUZZ_JOBS=4 hack/fuzz-long.sh            # all targets
#   FUZZ_TIME=2h  hack/fuzz-long.sh ./shared/... ./relay/...  # some trees
#
# The production criterion (docs: 24 h without a failure) is met by running
# this on a dedicated host with FUZZ_TIME set so that every target gets its
# share of 24 h, for example FUZZ_TIME=30m with FUZZ_JOBS equal to the cores.
set -euo pipefail

fuzz_time="${FUZZ_TIME:-5m}"
jobs="${FUZZ_JOBS:-2}"
log_dir="${FUZZ_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/meshtransit-fuzz.XXXXXX")}"
trees=("$@")
if [[ ${#trees[@]} -eq 0 ]]; then
	trees=(./shared/... ./relay/... ./client/... ./core/... ./test/...)
fi

module="$(go list -m)"
targets=()
while IFS= read -r line; do
	targets+=("${line}")
done < <(
	for package in $(go list "${trees[@]}" | grep -vE "^${module}/scripts(/|$)"); do
		dir="$(go list -f '{{.Dir}}' "${package}")"
		grep -hoE '^func (Fuzz[A-Za-z0-9_]+)\(f \*testing\.F\)' "${dir}"/*_test.go 2>/dev/null |
			sed -E "s/^func (Fuzz[A-Za-z0-9_]+).*/${package//\//\\/} \1/" || true
	done
)
if [[ ${#targets[@]} -eq 0 ]]; then
	echo "no fuzz targets found" >&2
	exit 1
fi
printf 'fuzzing %d targets for %s each, %d at a time; logs in %s\n' \
	"${#targets[@]}" "${fuzz_time}" "${jobs}" "${log_dir}"

run_target() {
	local package="$1" target="$2" log
	log="${log_dir}/$(echo "${package}" | tr '/' '_')__${target}.log"
	if go test "${package}" -run '^$' -fuzz "^${target}\$" -fuzztime "${fuzz_time}" >"${log}" 2>&1; then
		echo "ok   ${package} ${target}"
	else
		echo "FAIL ${package} ${target} (${log})"
	fi
}
export -f run_target
export fuzz_time log_dir

printf '%s\n' "${targets[@]}" |
	xargs -P "${jobs}" -L 1 bash -c 'run_target "$0" "$1"' |
	tee "${log_dir}/summary.txt"

if grep -q '^FAIL' "${log_dir}/summary.txt"; then
	exit 1
fi
