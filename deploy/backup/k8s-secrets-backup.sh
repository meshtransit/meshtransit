#!/usr/bin/env bash
# Backs up the Kubernetes Secrets a MeshTransit install cannot rebuild
# (V1-51): the chart's generated Secrets, entitlement and renewal keys, the
# Kubernetes CA wrap key, meshflow's keys. Each run writes a new
# age-encrypted file and never replaces an older one, so every key version
# stays as long as the database's point-in-time window needs it.
#
#   k8s-secrets-backup.sh --names FILE --recipients FILE --out DIR
#   k8s-secrets-backup.sh --names FILE --out DIR --check
#
# --names lists one namespace/name per line (# comments allowed): an
# explicit list, so a Secret made by hand is never missed by a label. A
# listed Secret that does not exist fails the run.
# --check compares each Secret's resourceVersion with the newest backup and
# exits 3 when one changed since (run it from cron as a drift alarm).
#
# Needs kubectl (the current context), jq and age (AGE overrides the
# command, e.g. AGE="go run filippo.io/age/cmd/age@v1.2.1").
set -euo pipefail
umask 077

names="" recipients="" out="" check=false
while [ $# -gt 0 ]; do
	case "$1" in
	--names) names="$2"; shift 2 ;;
	--recipients) recipients="$2"; shift 2 ;;
	--out) out="$2"; shift 2 ;;
	--check) check=true; shift ;;
	*) echo "unknown argument $1" >&2; exit 2 ;;
	esac
done
[ -n "$names" ] && [ -n "$out" ] || { echo "--names and --out are required" >&2; exit 2; }
[ -f "$names" ] || { echo "$names is not a file" >&2; exit 2; }
AGE=${AGE:-age}

list=()
while IFS= read -r line || [ -n "$line" ]; do
	line="${line%%#*}"
	line="$(echo "$line" | tr -d '[:space:]')"
	[ -z "$line" ] && continue
	case "$line" in
	*/*) list+=("$line") ;;
	*) echo "$names: '$line' is not namespace/name" >&2; exit 2 ;;
	esac
done <"$names"
[ "${#list[@]}" -gt 0 ] || { echo "$names lists no Secret" >&2; exit 2; }

# versions prints "namespace/name resourceVersion" for every listed Secret.
versions() {
	for item in "${list[@]}"; do
		version="$(kubectl get secret -n "${item%%/*}" "${item#*/}" -o jsonpath='{.metadata.resourceVersion}')" ||
			{ echo "missing Secret $item" >&2; exit 4; }
		echo "$item $version"
	done
}

if $check; then
	latest="$(ls -1 "$out"/secrets-*.versions 2>/dev/null | sort | tail -n 1)"
	[ -n "$latest" ] || { echo "no backup in $out yet" >&2; exit 3; }
	now="$(versions)" || exit 4
	if ! diff -u "$latest" <(printf '%s\n' "$now"); then
		echo "Secrets changed since $(basename "$latest"): run a backup" >&2
		exit 3
	fi
	echo "no drift since $(basename "$latest")"
	exit 0
fi

[ -n "$recipients" ] && [ -f "$recipients" ] || { echo "--recipients FILE (age public keys) is required" >&2; exit 2; }
mkdir -p "$out"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
target="$out/secrets-$stamp.json.age"
[ ! -e "$target" ] || { echo "$target exists" >&2; exit 2; }
# Every listed Secret must exist before anything is written.
current="$(versions)"
trap 'rm -f "$target.partial"' EXIT

# Runtime fields are dropped; data stays base64 as Kubernetes holds it.
{
	echo '{"format":1,"created":"'"$stamp"'","context":'"$(kubectl config current-context | jq -R .)"',"secrets":['
	first=true
	for item in "${list[@]}"; do
		secret="$(kubectl get secret -n "${item%%/*}" "${item#*/}" -o json)" ||
			{ echo "missing Secret $item" >&2; exit 4; }
		$first || echo ","
		first=false
		echo "$secret" | jq -c 'del(.metadata.uid, .metadata.resourceVersion, .metadata.creationTimestamp,
			.metadata.managedFields, .metadata.selfLink, .metadata.generation, .metadata.ownerReferences,
			.metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"])'
	done
	echo ']}'
} | jq -c . | $AGE -R "$recipients" -o "$target.partial"
mv "$target.partial" "$target"
trap - EXIT
printf '%s\n' "$current" >"$out/.secrets-$stamp.versions.partial"
mv "$out/.secrets-$stamp.versions.partial" "$out/secrets-$stamp.versions"
sha256="$( (sha256sum "$target" 2>/dev/null || shasum -a 256 "$target") | cut -d' ' -f1)"
echo "wrote $target (${#list[@]} Secrets, sha256 $sha256)"
