#!/usr/bin/env bash
# Runs the map-stream scale test (TestRoleControlProcessScalesMapStreams) on a
# load-test host prepared by bootstrap-host.sh, from a checkout of this repo.
#
# Usage: core/scripts/loadtest/run.sh SESSIONS PROCESSES
# Optional: PARALLELISM (128), POOL (20), SCALE_TIMEOUT (5h), OUT_DIR (.).
set -euo pipefail
sessions=${1:?sessions}
processes=${2:?processes}
out_dir=$(cd "${OUT_DIR:-.}" && pwd -P)
cd "$(dirname "$0")/../../.."
ulimit -n 2097152
export PATH=/usr/local/go/bin:$PATH
# The host copy is synced without a module cache; let go resolve modules.
export GOFLAGS=-mod=mod
export MESHTRANSIT_SCALE_SESSIONS=$sessions
export MESHTRANSIT_SCALE_CONTROL_PROCESSES=$processes
export MESHTRANSIT_SCALE_PARALLELISM=${PARALLELISM:-128}
export MESHTRANSIT_SCALE_POSTGRES_RUNTIME_MAX_CONNECTIONS=${POOL:-20}
export MESHTRANSIT_SCALE_REDIS_POOL_SIZE=${POOL:-20}
export MESHTRANSIT_SCALE_PROFILE_ADDRESS=127.0.0.1:16060
export MESHTRANSIT_SCALE_PROFILE_FILE=$out_dir/heap-$sessions.pb.gz
export PLATFORM_SCALE=1
export PLATFORM_SCALE_TIMEOUT=${SCALE_TIMEOUT:-5h}
export POSTGRES_SHM_SIZE=8g
export POSTGRES_SERVER_ARGS="-c max_connections=500 -c shared_buffers=8GB -c effective_cache_size=24GB -c work_mem=16MB -c maintenance_work_mem=1GB -c synchronous_commit=off -c max_wal_size=8GB"
bash core/scripts/ci/run-platform-integration.sh 2>&1 | tee "$out_dir/scale-$sessions.log"
