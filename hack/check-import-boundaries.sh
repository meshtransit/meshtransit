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

tailscale_outside="$(go list -f '{{.ImportPath}} {{join .Imports " "}}' ./... \
	| grep 'tailscale.com' \
	| grep -vE "^${module}/(client/internal/compat|core/internal/adapter/legacyts2021)" || true)"
if [[ -n "${tailscale_outside}" ]]; then
	printf 'tailscale.com imported outside the compatibility adapters:\n%s\n' "${tailscale_outside}" >&2
	violations=1
fi

exit "${violations}"
