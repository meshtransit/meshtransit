#!/usr/bin/env bash
# Restores Secrets from a k8s-secrets-backup.sh file into the current
# kubectl context (V1-51).
#
#   k8s-secrets-restore.sh --from FILE --identity FILE [--namespace OLD=NEW]... [--replace] [--dry-run]
#
# A Secret that already exists is refused unless --replace. --namespace
# moves Secrets of OLD into NEW (a restore drill in its own namespace).
# The identity is the age private key; keep it off the cluster's machines.
set -euo pipefail
umask 077

from="" identity="" replace=false dry=false
maps=()
while [ $# -gt 0 ]; do
	case "$1" in
	--from) from="$2"; shift 2 ;;
	--identity) identity="$2"; shift 2 ;;
	--namespace) maps+=("$2"); shift 2 ;;
	--replace) replace=true; shift ;;
	--dry-run) dry=true; shift ;;
	*) echo "unknown argument $1" >&2; exit 2 ;;
	esac
done
[ -f "$from" ] && [ -n "$identity" ] || { echo "--from FILE and --identity FILE are required" >&2; exit 2; }
AGE=${AGE:-age}

rename='.'
for map in "${maps[@]+"${maps[@]}"}"; do
	old="${map%%=*}" new="${map#*=}"
	[ -n "$old" ] && [ -n "$new" ] && [ "$old" != "$map" ] || { echo "--namespace wants OLD=NEW" >&2; exit 2; }
	rename="$rename | if .metadata.namespace == $(jq -n --arg v "$old" '$v') then .metadata.namespace = $(jq -n --arg v "$new" '$v') else . end"
done

secrets="$($AGE -d -i "$identity" "$from" | jq -c '.secrets[]' | jq -c "$rename")"
# Read through a pipe, never a here-string (bash may back it with a
# temporary file: decrypted Secrets would reach the disk).
items=()
while IFS= read -r secret; do
	[ -n "$secret" ] && items+=("$secret")
done < <(printf '%s\n' "$secrets")

# Check every Secret before changing any: the namespace must exist, and an
# error other than "not found" (RBAC, API down) stops the run.
existing=()
for secret in "${items[@]}"; do
	namespace="$(printf '%s' "$secret" | jq -r .metadata.namespace)"
	name="$(printf '%s' "$secret" | jq -r .metadata.name)"
	kubectl get namespace "$namespace" -o name >/dev/null ||
		{ echo "namespace $namespace missing or unreadable: nothing restored" >&2; exit 4; }
	found="$(kubectl get secret -n "$namespace" "$name" --ignore-not-found -o name)" ||
		{ echo "cannot read Secret $namespace/$name: nothing restored" >&2; exit 4; }
	if [ -n "$found" ]; then
		$replace || { echo "Secret $namespace/$name exists: refusing, nothing restored (--replace to overwrite)" >&2; exit 3; }
		existing+=("$namespace/$name")
	fi
done
for secret in "${items[@]}"; do
	namespace="$(printf '%s' "$secret" | jq -r .metadata.namespace)"
	name="$(printf '%s' "$secret" | jq -r .metadata.name)"
	if $dry; then
		echo "would restore $namespace/$name"
	elif [[ " ${existing[*]+"${existing[*]}"} " == *" $namespace/$name "* ]]; then
		# Delete and create, not apply or replace: keys missing from the
		# backup must not survive, and a Secret's type cannot change in
		# place. Core is scaled to zero during a restore (runbook).
		kubectl delete secret -n "$namespace" "$name" >/dev/null
		printf '%s' "$secret" | kubectl create -f - >/dev/null
		echo "replaced $namespace/$name"
	else
		printf '%s' "$secret" | kubectl create -f - >/dev/null
		echo "restored $namespace/$name"
	fi
done
echo "${#items[@]} Secrets"
