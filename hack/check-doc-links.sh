#!/usr/bin/env bash
# Every link in the repository's Markdown and every docs/*.md path named in
# code, comments or API descriptions must point at a tracked file or
# directory that is present, so docs can move without leaving dangling
# references. Paths are compared with the index, so a wrong letter case fails
# on every filesystem.
#
# Checked: inline links [text](target) and reference definitions
# [label]: target outside fenced code blocks, and Markdown paths under docs/
# named outside Markdown. Not checked: fragments (#section) and raw HTML.
#
# Applied migrations are immutable (Core checks their checksums), so the
# paths their comments name are not checked; vendored third-party trees keep
# their upstream links.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

known="$(mktemp)"
trap 'rm -f "${known}"' EXIT
git ls-files -z | while IFS= read -r -d '' path; do
	if [[ -e "${path}" ]]; then printf '%s\n' "${path}"; fi
done | awk '{print; while (sub(/\/[^\/]*$/, "")) print}' | sort -u >"${known}"

broken=0
report() {
	printf '%s: %s is not in the repository\n' "$1" "$2" >&2
	broken=1
}

# normalize resolves "." and ".." segments of a relative path; it fails for a
# path that leaves the repository.
normalize() {
	local part result=''
	local -a parts
	IFS='/' read -ra parts <<<"$1"
	for part in ${parts[@]+"${parts[@]}"}; do
		case "${part}" in
		'' | .) ;;
		..)
			[[ -n "${result}" ]] || return 1
			if [[ "${result}" == */* ]]; then result="${result%/*}"; else result=''; fi
			;;
		*) result="${result:+${result}/}${part}" ;;
		esac
	done
	printf '%s\n' "${result}"
}

exists() {
	local path
	path="$(normalize "$1")" || return 1
	[[ -z "${path}" ]] || grep -qxF -- "${path}" "${known}"
}

tracked() {
	git ls-files -- "$@" | grep -vE '^(core/third_party|core/migrations)/' || true
}

# markdown_targets prints the link targets of a Markdown file, skipping
# fenced code blocks.
markdown_targets() {
	awk '/^[[:space:]]*(```|~~~)/ { fenced = !fenced; next } !fenced' "$1" |
		{
			grep -oE '\]\([^) ]+|^[[:space:]]*\[[^]^][^]]*\]:[[:space:]]+[^[:space:]]+' || true
		} |
		sed -E 's/^\]\(//; s/^[[:space:]]*\[[^]]+\]:[[:space:]]+//; s/^<//; s/>$//'
}

while IFS= read -r file; do
	dir="$(dirname "${file}")"
	while IFS= read -r target; do
		target="${target%%#*}"
		target="${target%%\?*}"
		[[ -n "${target}" ]] || continue
		case "${target}" in
		*:*) continue ;; # a URI: https:, mailto:, ...
		/*) path="${target#/}" ;;
		*) path="${dir}/${target}" ;;
		esac
		exists "${path}" || report "${file}" "${target}"
	done < <(markdown_targets "${file}")
done < <(tracked '*.md')

# docs/... paths named outside Markdown are relative to the repository root.
while IFS= read -r match; do
	exists "${match#*:}" || report "${match%%:*}" "${match#*:}"
done < <(tracked ':!*.md' | tr '\n' '\0' |
	xargs -0 grep -HIoE '(^|[^A-Za-z0-9_./-])docs/[A-Za-z0-9_./-]+\.md' 2>/dev/null |
	sed -E 's/^([^:]*):.*(docs\/[A-Za-z0-9_.\/-]+\.md)$/\1:\2/' | sort -u)

exit "${broken}"
