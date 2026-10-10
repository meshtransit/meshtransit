#!/usr/bin/env bash
# Apache-2.0 code (client/, shared/, api/, test/) must never depend on AGPL-3.0 code
# (core/, relay/). Run from the repository root.
set -euo pipefail

module="$(go list -m)"
violations=0
for tree in client shared api test; do
	[[ -d "${tree}" ]] || continue
	while IFS= read -r package; do
		deps="$(go list -deps "${package}" | grep -E "^${module}/(core|relay)(/|$)" || true)"
		if [[ -n "${deps}" ]]; then
			printf '%s imports AGPL packages:\n%s\n' "${package}" "${deps}" >&2
			violations=1
		fi
	done < <(go list "./${tree}/..." 2>/dev/null)
done

# Every module go.mod requires must be on the reviewed allowlist, so a new
# dependency cannot arrive without review.
unreviewed="$(awk '/^require \($/ {block = 1; next} block && /^\)/ {block = 0}
	block && NF {print $1} /^require [^(]/ {print $2}' go.mod \
	| grep -vxF -f <(grep -vE '^(#|$)' hack/allowed-modules.txt) || true)"
if [[ -n "${unreviewed}" ]]; then
	printf 'go.mod requires modules missing from hack/allowed-modules.txt:\n%s\n' "${unreviewed}" >&2
	violations=1
fi

exit "${violations}"
