#!/usr/bin/env bash
# pg-backend-sampler.sh OUTPUT [--interval SECONDS] -- EXEC_PREFIX...
#
# Samples every PostgreSQL process's private anonymous resident memory (RssAnon)
# about once a second, until it is stopped, appending "pid kB title" lines to
# OUTPUT for `pgmemgate -backend-samples`. EXEC_PREFIX reaches the processes,
# for example `docker exec <postgres container>` or `docker exec <kind node>`.
# A backend keeps what it builds (compiled PL/pgSQL functions, plans,
# relcache) until it closes, so a one-second sample sees that cached total.
# It is a lower bound: a connection shorter than about a second, or a spike
# inside one query that is freed again, can be missed (the statement gate,
# pgmemgate -max-mb, covers query spikes).
set -euo pipefail
if (( $# < 3 )); then
	echo "usage: $0 OUTPUT [--interval SECONDS] -- EXEC_PREFIX..." >&2
	exit 2
fi
output="$1"
shift
interval=1
if [[ "$1" == "--interval" ]]; then
	interval="$2"
	shift 2
fi
[[ "$1" == "--" ]] || { echo "missing -- before the exec prefix" >&2; exit 2; }
shift
# Runs inside the target: one line per postgres process. The title comes from
# the process's argv, which PostgreSQL rewrites to "postgres: role db host state".
probe='for p in /proc/[0-9]*; do
	read -r c < "$p/comm" 2>/dev/null || continue
	[ "$c" = postgres ] || continue
	t=$(tr "\0" " " < "$p/cmdline" 2>/dev/null) || continue
	case "$t" in "postgres: "*) ;; *) continue ;; esac
	k=$(awk "/^RssAnon:/{print \$2}" "$p/status" 2>/dev/null) || continue
	[ -n "$k" ] && echo "${p#/proc/} $k $t"
done'
while true; do
	"$@" sh -c "${probe}" >>"${output}" 2>/dev/null || true
	sleep "${interval}"
done
