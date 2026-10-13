#!/usr/bin/env bash

set -euo pipefail

go_runner="${PLATFORM_GO_RUNNER:-host}"
case "${go_runner}" in
	host | container) ;;
	*) printf '%s\n' 'Invalid platform Go runner mode.' >&2; exit 2 ;;
esac
go_runner_image='golang:1.26.8-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81'
source_dir="$(pwd -P)"
postgres_image="${POSTGRES_IMAGE:-postgres:18.6-bookworm}"
# PLATFORM_SCALE=1 runs the opt-in map-stream scale test in place of the
# control process tests and stops there (core/scripts/loadtest/run.sh).
# POSTGRES_SHM_SIZE and POSTGRES_SERVER_ARGS ("-c name=value ...") size the
# fixture database for it.
scale_mode="${PLATFORM_SCALE:-0}"
# PLATFORM_SHARE_SCALE=N builds N Device shares on the migrated fixture
# database and measures map reads (TestPostgreSQLShareScale), then stops.
share_scale="${PLATFORM_SHARE_SCALE:-0}"
postgres_shm_size="${POSTGRES_SHM_SIZE:-64m}"
postgres_command=(postgres)
if [[ -n "${POSTGRES_SERVER_ARGS:-}" ]]; then
	read -r -a postgres_server_args <<<"${POSTGRES_SERVER_ARGS}"
	postgres_command+=("${postgres_server_args[@]}")
fi
redis_image="${REDIS_IMAGE:-redis:8.8.0-trixie}"
fixture_dir="$(mktemp -d)"
runner_dir=''
module_dir=''
fixture_network="meshtransit-platform-$RANDOM-$$"
runner_container="meshtransit-platform-go-$RANDOM-$$"
postgres_container="meshtransit-postgres-$RANDOM-$$"
redis_container="meshtransit-redis-$RANDOM-$$"
# Keep arrays nonempty under macOS Bash 3.2's nounset behavior. Native-host
# fixtures retain Docker's ordinary default bridge; only Linux uses its owned one.
postgres_network=(--network bridge --publish 127.0.0.1::5432)
redis_network=(--network bridge --publish 127.0.0.1::6379)
postgres_password="$(openssl rand -hex 24)"
migration_password="$(openssl rand -hex 24)"
runtime_password="$(openssl rand -hex 24)"
worker_password="$(openssl rand -hex 24)"
redis_password="$(openssl rand -hex 24)"
enrollment_digest_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
account_session_digest_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
idempotency_digest_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
rate_limit_digest_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
noise_private_key="privkey:$(openssl rand -hex 32)"
# GNU date on Linux, BSD date on macOS.
control_key_not_after="$(date -u -d '+1 day' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null ||
	date -u -v+1d '+%Y-%m-%dT%H:%M:%SZ')"

cleanup() {
	docker rm --force "${runner_container}" >/dev/null 2>&1 || true
	docker rm --force "${redis_container}" >/dev/null 2>&1 || true
	docker rm --force "${postgres_container}" >/dev/null 2>&1 || true
	if [[ "${go_runner}" == container ]]; then
		docker network rm "${fixture_network}" >/dev/null 2>&1 || true
	fi
	if [[ -n "${runner_dir}" ]]; then
		rm -rf "${runner_dir}"
	fi
	rm -rf "${fixture_dir}"
}
trap cleanup EXIT

if [[ "${go_runner}" == container ]]; then
	runner_dir="$(mktemp -d)"
	mkdir -p "${runner_dir}/tmp"
	module_dir="$(go env GOMODCACHE)"
	[[ -d "${module_dir}" ]] || { printf '%s\n' 'Missing offline module cache.' >&2; exit 2; }
	docker network create --internal "${fixture_network}" >/dev/null
	postgres_network=(--network "${fixture_network}" --network-alias meshtransit-postgres)
	redis_network=(--network "${fixture_network}" --network-alias meshtransit-redis)
fi

# Never forward inherited host credentials or the Docker socket. This explicit
# fixture-only environment remains the same for every owned Go invocation.
run_go() {
	if [[ "${go_runner}" == host ]]; then
		go "$@"
		return
	fi
	docker run --rm \
		--name "${runner_container}" \
		--network "${fixture_network}" \
		--user "$(id -u):$(id -g)" \
		--cap-drop ALL \
		--security-opt no-new-privileges \
		--read-only \
		--tmpfs /tmp:rw,nosuid,nodev \
		--mount "type=bind,source=${source_dir},target=/src,readonly" \
		--mount "type=bind,source=${module_dir},target=/modules,readonly" \
		--mount "type=bind,source=${fixture_dir},target=${fixture_dir}" \
		--mount "type=bind,source=${runner_dir},target=/runner" \
		--workdir /src \
		--env GOTOOLCHAIN=local \
		--env GOENV=off \
		--env 'GOFLAGS=-mod=readonly -buildvcs=false' \
		--env GOCACHE=/runner/build \
		--env GOMODCACHE=/modules \
		--env GOPROXY=off \
		--env GOPATH=/runner/gopath \
		--env GOTMPDIR=/runner/tmp \
		--env MESHTRANSIT_MIGRATION_INTEGRATION \
		--env MESHTRANSIT_INTEGRATION \
		--env MESHTRANSIT_SHARE_SCALE \
		--env MESHTRANSIT_SHARE_SCALE_REPORT \
		--env MESHTRANSIT_SHARE_SCALE_EXPLAIN \
		--env MESHTRANSIT_SHARE_SCALE_COLD \
		--env MESHTRANSIT_SHARE_SCALE_PUBLISH \
		--env MESHTRANSIT_MIGRATION_POSTGRES_ADDRESS \
		--env MESHTRANSIT_MIGRATION_POSTGRES_DATABASE \
		--env MESHTRANSIT_MIGRATION_POSTGRES_USER \
		--env MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE \
		--env MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE \
		--env MESHTRANSIT_MIGRATION_ACTOR \
		--env MESHTRANSIT_MIGRATION_CONNECT_TIMEOUT \
		--env MESHTRANSIT_MIGRATION_LOCK_TIMEOUT \
		--env MESHTRANSIT_MIGRATION_STATEMENT_TIMEOUT \
		--env MESHTRANSIT_ROLE \
		--env MESHTRANSIT_POSTGRES_ADDRESS \
		--env MESHTRANSIT_POSTGRES_DATABASE \
		--env MESHTRANSIT_POSTGRES_RUNTIME_USER \
		--env MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE \
		--env MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS \
		--env MESHTRANSIT_POSTGRES_WORKER_USER \
		--env MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE \
		--env MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS \
		--env MESHTRANSIT_POSTGRES_CA_FILE \
		--env MESHTRANSIT_REDIS_ADDRESS \
		--env MESHTRANSIT_REDIS_USERNAME \
		--env MESHTRANSIT_REDIS_PASSWORD_FILE \
		--env MESHTRANSIT_REDIS_CA_FILE \
		--env MESHTRANSIT_REDIS_POOL_SIZE \
		--env MESHTRANSIT_RELAY_DIRECTORY_FILE \
		--env MESHTRANSIT_RELAY_DIRECTORY_SHA256 \
		--env MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID \
		--env MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_FILE \
		--env MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE \
		--env MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE \
		--env MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE \
		--env MESHTRANSIT_CONTROL_MAX_SESSIONS \
		--env MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER \
		--env MESHTRANSIT_API_TLS_CERTIFICATE_FILE \
		--env MESHTRANSIT_API_TLS_PRIVATE_KEY_FILE \
		--env MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_ID \
		--env MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_FILE \
		--env MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_ID \
		--env MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_FILE \
		--env MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_ID \
		--env MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_FILE \
		--env MESHTRANSIT_API_MAX_CONNECTIONS \
		--env MESHTRANSIT_API_MAX_CONCURRENT_REQUESTS \
		--env MESHTRANSIT_TEST_POSTGRES_ADMIN_PASSWORD_FILE \
		--env MESHTRANSIT_TEST_POSTGRES_WORKER_PASSWORD_FILE \
		--env MESHTRANSIT_IDENTITY_SUBJECT_TRANSITION_INTEGRATION \
		--env MESHTRANSIT_TEST_MESHCORE_BINARY \
		--env MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION \
		--env MESHTRANSIT_TEST_OIDC_TLS_CERTIFICATE_FILE \
		--env MESHTRANSIT_TEST_OIDC_TLS_PRIVATE_KEY_FILE \
		--env SSL_CERT_FILE \
		--env SSL_CERT_DIR \
		"${go_runner_image}" go "$@"
}

openssl req \
	-x509 \
	-newkey rsa:2048 \
	-nodes \
	-days 1 \
	-subj "/CN=MeshTransit test CA" \
	-keyout "${fixture_dir}/ca.key" \
	-out "${fixture_dir}/ca.crt" \
	>/dev/null 2>&1
openssl req \
	-newkey rsa:2048 \
	-nodes \
	-subj "/CN=127.0.0.1" \
	-keyout "${fixture_dir}/server.key" \
	-out "${fixture_dir}/server.csr" \
	>/dev/null 2>&1
printf '%s\n' \
	'[server]' \
	'subjectAltName=IP:127.0.0.1,DNS:meshtransit-postgres,DNS:meshtransit-redis' \
	'extendedKeyUsage=serverAuth' \
	>"${fixture_dir}/server.ext"
openssl x509 \
	-req \
	-days 1 \
	-in "${fixture_dir}/server.csr" \
	-CA "${fixture_dir}/ca.crt" \
	-CAkey "${fixture_dir}/ca.key" \
	-CAcreateserial \
	-extfile "${fixture_dir}/server.ext" \
	-extensions server \
	-out "${fixture_dir}/server.crt" \
	>/dev/null 2>&1
openssl req \
	-newkey rsa:2048 \
	-nodes \
	-subj "/CN=example.com" \
	-keyout "${fixture_dir}/control-server.key" \
	-out "${fixture_dir}/control-server.csr" \
	>/dev/null 2>&1
printf '%s\n' \
	'[server]' \
	'subjectAltName=DNS:example.com' \
	'extendedKeyUsage=serverAuth' \
	>"${fixture_dir}/control-server.ext"
openssl x509 \
	-req \
	-days 1 \
	-in "${fixture_dir}/control-server.csr" \
	-CA "${fixture_dir}/ca.crt" \
	-CAkey "${fixture_dir}/ca.key" \
	-CAcreateserial \
	-extfile "${fixture_dir}/control-server.ext" \
	-extensions server \
	-out "${fixture_dir}/control-server.crt" \
	>/dev/null 2>&1
printf '%s\n' "${migration_password}" >"${fixture_dir}/migration-password"
printf '%s\n' "${runtime_password}" >"${fixture_dir}/runtime-password"
printf '%s\n' "${worker_password}" >"${fixture_dir}/worker-password"
printf '%s\n' "${postgres_password}" >"${fixture_dir}/postgres-admin-password"
printf 'redis-%s\n' "${redis_password}" >"${fixture_dir}/redis-password"
printf '%s\n' "${enrollment_digest_key}" >"${fixture_dir}/enrollment-digest-key"
printf '%s\n' "${account_session_digest_key}" >"${fixture_dir}/account-session-digest-key"
printf '%s\n' "${idempotency_digest_key}" >"${fixture_dir}/idempotency-digest-key"
printf '%s\n' "${rate_limit_digest_key}" >"${fixture_dir}/rate-limit-digest-key"
printf '%s\n' "${noise_private_key}" >"${fixture_dir}/control-noise-private-key"
printf '%s\n' \
	'{"schema_version":1,"revision":1,"regions":[{"id":1,"code":"sin","name":"Singapore","nodes":[{"name":"1a","host_name":"relay.example.com","cert_name":"","ipv4":"192.0.2.10","ipv6":"2001:db8::10","stun_port":3478,"relay_port":443,"stun_only":false}]}]}' \
	>"${fixture_dir}/relay-directory.json"
relay_directory_digest="$(openssl dgst -sha256 -r "${fixture_dir}/relay-directory.json" | awk '{print $1}')"
chmod 0600 "${fixture_dir}/migration-password"
chmod 0600 "${fixture_dir}/runtime-password"
chmod 0600 "${fixture_dir}/worker-password"
chmod 0600 "${fixture_dir}/postgres-admin-password"
chmod 0600 "${fixture_dir}/redis-password"
chmod 0600 "${fixture_dir}/enrollment-digest-key"
chmod 0600 "${fixture_dir}/account-session-digest-key"
chmod 0600 "${fixture_dir}/idempotency-digest-key"
chmod 0600 "${fixture_dir}/rate-limit-digest-key"
chmod 0600 "${fixture_dir}/control-noise-private-key"
chmod 0600 "${fixture_dir}/control-server.key"
chmod 0600 "${fixture_dir}/relay-directory.json"

docker run \
	--detach \
	--name "${postgres_container}" \
	"${postgres_network[@]}" \
	--env "POSTGRES_PASSWORD=${postgres_password}" \
	--env 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256' \
	--shm-size "${postgres_shm_size}" \
	"${postgres_image}" \
	"${postgres_command[@]}" \
	>/dev/null

for _ in $(seq 1 60); do
	if docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		pg_isready --username postgres --dbname postgres \
		>/dev/null 2>&1; then
		break
	fi
	sleep 1
done
docker exec \
	--env "PGPASSWORD=${postgres_password}" \
	"${postgres_container}" \
	pg_isready --username postgres --dbname postgres \
	>/dev/null

docker cp "${fixture_dir}/server.crt" "${postgres_container}:/tmp/server.crt"
docker cp "${fixture_dir}/server.key" "${postgres_container}:/tmp/server.key"
docker exec --user root "${postgres_container}" chown postgres:postgres /tmp/server.crt /tmp/server.key
docker exec --user root "${postgres_container}" chmod 0600 /tmp/server.key
docker exec \
	--env "PGPASSWORD=${postgres_password}" \
	"${postgres_container}" \
	psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
	--command "ALTER SYSTEM SET ssl = 'on'" \
	--command "ALTER SYSTEM SET ssl_cert_file = '/tmp/server.crt'" \
	--command "ALTER SYSTEM SET ssl_key_file = '/tmp/server.key'" \
	>/dev/null
docker restart "${postgres_container}" >/dev/null

for _ in $(seq 1 60); do
	if docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		pg_isready --username postgres --dbname postgres \
		>/dev/null 2>&1; then
		break
	fi
	sleep 1
done
printf \
	"CREATE ROLE mesh_migrator LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_runtime LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_worker LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_audit_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_share_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_direct_map_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_device_alias_observer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_device_alias_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_device_alias_map_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_observer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n" \
	"${migration_password}" \
	"${runtime_password}" \
	"${worker_password}" \
	| docker exec \
		--interactive \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
		>/dev/null
docker exec \
	--env "PGPASSWORD=${postgres_password}" \
	"${postgres_container}" \
	psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
	--command "CREATE DATABASE meshtransit OWNER mesh_migrator" \
	>/dev/null
docker exec \
	--env "PGPASSWORD=${postgres_password}" \
	"${postgres_container}" \
	psql --username postgres --dbname meshtransit --set ON_ERROR_STOP=1 \
	--command 'CREATE EXTENSION btree_gist' \
	>/dev/null

docker run \
	--detach \
	--name "${redis_container}" \
	"${redis_network[@]}" \
	--entrypoint sh \
	"${redis_image}" \
	-c 'while :; do sleep 3600; done' \
	>/dev/null
docker cp "${fixture_dir}/ca.crt" "${redis_container}:/tmp/ca.crt"
docker cp "${fixture_dir}/server.crt" "${redis_container}:/tmp/server.crt"
docker cp "${fixture_dir}/server.key" "${redis_container}:/tmp/server.key"
docker exec --user root "${redis_container}" chown redis:redis \
	/tmp/ca.crt /tmp/server.crt /tmp/server.key
docker exec --user root "${redis_container}" chmod 0600 /tmp/server.key
docker exec --detach --user redis "${redis_container}" redis-server \
	--bind 0.0.0.0 \
	--port 0 \
	--tls-port 6379 \
	--tls-cert-file /tmp/server.crt \
	--tls-key-file /tmp/server.key \
	--tls-ca-cert-file /tmp/ca.crt \
	--tls-auth-clients no \
	--user default off \
	--user mesh_worker on ">redis-${redis_password}" resetkeys resetchannels \
	"+ping" "+publish" "+subscribe" "+eval" "+evalsha" \
	"+hget" "+hset" "+hmget" "+exists" "+pexpire" "+del" \
	"+get" "+set" "+time" "+hgetall" "+hdel" \
	"~meshtransit:v1:presence:node:*" \
	"~meshtransit:v1:control:replicas" \
	"~meshtransit:v1:endpoints:node:*" \
	"~meshtransit:v1:delivery:node:*" \
	"~meshtransit:v1:ratelimit:management:*" \
	"&meshtransit:v1:wakeup:network_revision_advanced" \
	"&meshtransit:v1:wakeup:connectivity_changed"

for _ in $(seq 1 60); do
	if docker exec "${redis_container}" redis-cli \
		--tls \
		--cacert /tmp/ca.crt \
		--user mesh_worker \
		--pass "redis-${redis_password}" \
		--no-auth-warning \
		ping \
		>/dev/null 2>&1; then
		break
	fi
	sleep 1
done
docker exec "${redis_container}" redis-cli \
	--tls \
	--cacert /tmp/ca.crt \
	--user mesh_worker \
	--pass "redis-${redis_password}" \
	--no-auth-warning \
	ping \
	>/dev/null

if [[ "${go_runner}" == container ]]; then
	postgres_address='meshtransit-postgres:5432'
	redis_address='meshtransit-redis:6379'
else
	postgres_address="$(docker port "${postgres_container}" 5432/tcp)"
	redis_address="$(docker port "${redis_container}" 6379/tcp)"
fi
export MESHTRANSIT_MIGRATION_INTEGRATION=1
export MESHTRANSIT_INTEGRATION=1
export MESHTRANSIT_MIGRATION_POSTGRES_ADDRESS="${postgres_address}"
export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit
export MESHTRANSIT_MIGRATION_POSTGRES_USER=mesh_migrator
export MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE="${fixture_dir}/migration-password"
export MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE="${fixture_dir}/ca.crt"
export MESHTRANSIT_MIGRATION_ACTOR=ci
export MESHTRANSIT_MIGRATION_CONNECT_TIMEOUT=10s
export MESHTRANSIT_MIGRATION_LOCK_TIMEOUT=5s
export MESHTRANSIT_MIGRATION_STATEMENT_TIMEOUT=30s
export MESHTRANSIT_ROLE=api
export MESHTRANSIT_POSTGRES_ADDRESS="${postgres_address}"
export MESHTRANSIT_POSTGRES_DATABASE=meshtransit
export MESHTRANSIT_POSTGRES_RUNTIME_USER=mesh_runtime
export MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE="${fixture_dir}/runtime-password"
export MESHTRANSIT_POSTGRES_CA_FILE="${fixture_dir}/ca.crt"
export MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS=2
export MESHTRANSIT_REDIS_ADDRESS="${redis_address}"
export MESHTRANSIT_REDIS_USERNAME=mesh_worker
export MESHTRANSIT_REDIS_PASSWORD_FILE="${fixture_dir}/redis-password"
export MESHTRANSIT_REDIS_CA_FILE="${fixture_dir}/ca.crt"
export MESHTRANSIT_REDIS_POOL_SIZE=1
export MESHTRANSIT_RELAY_DIRECTORY_FILE="${fixture_dir}/relay-directory.json"
export MESHTRANSIT_RELAY_DIRECTORY_SHA256="sha256:${relay_directory_digest}"
export MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID=integration-v1
export MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_FILE="${fixture_dir}/enrollment-digest-key"
export MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE="${fixture_dir}/control-server.crt"
export MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE="${fixture_dir}/control-server.key"
export MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE="${fixture_dir}/control-noise-private-key"
export MESHTRANSIT_CONTROL_MAX_SESSIONS=8
# MTCP advertises the control key's expiry; keep it inside the fixture's life.
export MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER="${control_key_not_after}"
export MESHTRANSIT_API_TLS_CERTIFICATE_FILE="${fixture_dir}/control-server.crt"
export MESHTRANSIT_API_TLS_PRIVATE_KEY_FILE="${fixture_dir}/control-server.key"
export MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_ID=integration-v1
export MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_FILE="${fixture_dir}/account-session-digest-key"
export MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_ID=integration-v1
export MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_FILE="${fixture_dir}/idempotency-digest-key"
export MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_ID=integration-v1
export MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_FILE="${fixture_dir}/rate-limit-digest-key"
export MESHTRANSIT_API_MAX_CONNECTIONS=8
export MESHTRANSIT_API_MAX_CONCURRENT_REQUESTS=4
export MESHTRANSIT_TEST_POSTGRES_ADMIN_PASSWORD_FILE="${fixture_dir}/postgres-admin-password"
export MESHTRANSIT_TEST_POSTGRES_WORKER_PASSWORD_FILE="${fixture_dir}/worker-password"

run_go test \
	-tags=integration \
	-count=1 \
	-race \
	-run '^TestPostgreSQLMigrations$' \
	-timeout=5m \
	./core/test/integration

if [[ "${share_scale}" != 0 ]]; then
	share_scale_status=0
	MESHTRANSIT_SHARE_SCALE="${share_scale}" run_go test \
		-tags=integration \
		-count=1 \
		-v \
		-run '^TestPostgreSQLShareScale$' \
		-timeout="${PLATFORM_SCALE_TIMEOUT:-4h}" \
		./core/test/integration || share_scale_status=$?
	if [[ -n "${SHARE_SCALE_POSTGRES_LOG:-}" ]]; then
		docker logs "${postgres_container}" > "${SHARE_SCALE_POSTGRES_LOG}" 2>&1 || true
	fi
	exit "${share_scale_status}"
fi

export MESHTRANSIT_IDENTITY_SUBJECT_TRANSITION_INTEGRATION=1
run_go test \
	-tags=integration \
	-count=1 \
	-race \
	-run '^TestIdentitySubjectTransitionPlan$' \
	-timeout=2m \
	./core/tools/qualification/identitysubjecttransition

# Base primitive tests retain five-minute open Auth rows. Keep their unchanged
# batch-one process oracles adjacent, before unrelated natural-expiry waits.
# Aggregate-only diagnostics use the canonical bounded selector; no row data,
# deletion, deadline rewrite or background worker drains the base fixture.
if [[ "${go_runner}" == container ]]; then
	docker exec --env "PGPASSWORD=${postgres_password}" "${postgres_container}" \
		psql --username postgres --dbname meshtransit --set ON_ERROR_STOP=1 \
		--quiet --no-align --tuples-only \
		--command "BEGIN READ ONLY; SET LOCAL statement_timeout='5s'; SELECT 'owned base expiry candidates before process matrix: ' || jsonb_array_length(mesh_ops.list_due_oidc_browser_v1('01890f00-0000-7000-8000-000000000001'::UUID,128)); ROLLBACK"
fi
export MESHTRANSIT_ROLE=control
export MESHTRANSIT_POSTGRES_WORKER_USER=mesh_worker
export MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE="${fixture_dir}/worker-password"
export MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS=2
export MESHTRANSIT_TEST_MESHCORE_BINARY="${fixture_dir}/meshcore"
run_go build -trimpath -o "${MESHTRANSIT_TEST_MESHCORE_BINARY}" ./core/cmd/meshcore
if [[ "${scale_mode}" == 1 ]]; then
	run_go test \
		-tags=integration \
		-count=1 \
		-v \
		-run '^TestRoleControlProcessScalesMapStreams$' \
		-timeout="${PLATFORM_SCALE_TIMEOUT:-40m}" \
		./core/test/integration
	exit 0
fi
run_go test \
	-tags=integration \
	-count=1 \
	-race \
	-run '^(TestTLSAuthenticatedDependencies|TestRoleControlProcessRegistrationConvergesAcrossRestart|TestRoleControlProcessRestartsAfterGracefulShutdown|TestRoleControlProcessRejectsInvalidConfigurationBeforeListening|TestRoleWorkerProcessExpiryConvergesAcrossRestart)$' \
	-timeout=5m \
	./core/test/integration
export MESHTRANSIT_ROLE=api
unset MESHTRANSIT_POSTGRES_WORKER_USER MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE
unset MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS

# The concrete private factory has no injected trust/clock/transport. Qualify its
# initiation separately on a cold owned database and explicit Linux startup roots.
# Native-host clock/trust qualification remains an independent gate.
if [[ "${go_runner}" == container ]]; then
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
		--command 'CREATE DATABASE meshtransit_private_factory OWNER mesh_migrator' \
		>/dev/null
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname meshtransit_private_factory --set ON_ERROR_STOP=1 \
		--command 'CREATE EXTENSION btree_gist' \
		>/dev/null
	mkdir "${fixture_dir}/empty-roots"
	export MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION=1
	export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit_private_factory
	export MESHTRANSIT_POSTGRES_DATABASE=meshtransit_private_factory
	export MESHTRANSIT_TEST_OIDC_TLS_CERTIFICATE_FILE="${fixture_dir}/server.crt"
	export MESHTRANSIT_TEST_OIDC_TLS_PRIVATE_KEY_FILE="${fixture_dir}/server.key"
	export SSL_CERT_FILE="${fixture_dir}/ca.crt"
	export SSL_CERT_DIR="${fixture_dir}/empty-roots"
	run_go test -tags=integration -count=1 -race -shuffle=on -v \
		-run '^TestPrivateIdentityFactoryInitiationIntegration$' -timeout=5m ./core/cmd/meshcore
	# Callback owns another cold scope; neither test depends on prior authority.
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
		--command 'CREATE DATABASE meshtransit_private_factory_callback OWNER mesh_migrator' \
		>/dev/null
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname meshtransit_private_factory_callback --set ON_ERROR_STOP=1 \
		--command 'CREATE EXTENSION btree_gist' \
		>/dev/null
	export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit_private_factory_callback
	export MESHTRANSIT_POSTGRES_DATABASE=meshtransit_private_factory_callback
	run_go test -tags=integration -count=1 -race -shuffle=on -v \
		-run '^TestPrivateIdentityFactoryCallbackIntegration$' -timeout=5m ./core/cmd/meshcore
	# Provider transport outages own a cold authority scope so each failed
	# callback and subsequent fresh recovery login can be counted exactly.
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
		--command 'CREATE DATABASE meshtransit_private_factory_provider_outage OWNER mesh_migrator' \
		>/dev/null
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname meshtransit_private_factory_provider_outage --set ON_ERROR_STOP=1 \
		--command 'CREATE EXTENSION btree_gist' \
		>/dev/null
	export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit_private_factory_provider_outage
	export MESHTRANSIT_POSTGRES_DATABASE=meshtransit_private_factory_provider_outage
	run_go test -tags=integration -count=1 -race -shuffle=on -v \
		-run '^TestPrivateIdentityFactoryProviderOutageRecoveryIntegration$' -timeout=5m ./core/cmd/meshcore
	# Provider anti-rollback owns a cold authority scope. It advances the Core
	# recovery generation without depending on restored broker state.
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
		--command 'CREATE DATABASE meshtransit_private_factory_recovery OWNER mesh_migrator' \
		>/dev/null
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname meshtransit_private_factory_recovery --set ON_ERROR_STOP=1 \
		--command 'CREATE EXTENSION btree_gist' \
		>/dev/null
	export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit_private_factory_recovery
	export MESHTRANSIT_POSTGRES_DATABASE=meshtransit_private_factory_recovery
	run_go test -tags=integration -count=1 -race -shuffle=on -v \
		-run '^TestPrivateIdentityFactoryProviderRecoveryGenerationIntegration$' -timeout=5m ./core/cmd/meshcore
	# Natural factory expiry keeps original timestamps and its one-minute minimum.
	# This third cold scope has both runtime and independent worker credentials.
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
		--command 'CREATE DATABASE meshtransit_private_factory_expiry OWNER mesh_migrator' \
		>/dev/null
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname meshtransit_private_factory_expiry --set ON_ERROR_STOP=1 \
		--command 'CREATE EXTENSION btree_gist' \
		>/dev/null
	export MESHTRANSIT_ROLE=all
	export MESHTRANSIT_POSTGRES_WORKER_USER=mesh_worker
	export MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE="${fixture_dir}/worker-password"
	export MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS=2
	export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit_private_factory_expiry
	export MESHTRANSIT_POSTGRES_DATABASE=meshtransit_private_factory_expiry
	run_go test -tags=integration -count=1 -race -shuffle=on -v \
		-run '^TestPrivateIdentityFactoryExpiryQuarantineIntegration$' -timeout=5m ./core/cmd/meshcore
	# Cleanup wins against an actual in-flight factory exchange on a fourth cold scope.
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
		--command 'CREATE DATABASE meshtransit_private_factory_consuming OWNER mesh_migrator' \
		>/dev/null
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname meshtransit_private_factory_consuming --set ON_ERROR_STOP=1 \
		--command 'CREATE EXTENSION btree_gist' \
		>/dev/null
	export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit_private_factory_consuming
	export MESHTRANSIT_POSTGRES_DATABASE=meshtransit_private_factory_consuming
	run_go test -tags=integration -count=1 -race -shuffle=on -v \
		-run '^TestPrivateIdentityFactoryConsumingCleanupIntegration$' -timeout=5m ./core/cmd/meshcore
	# Confirmed-claim process death owns a fifth cold scope and exact child PID.
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
		--command 'CREATE DATABASE meshtransit_private_factory_abandoned OWNER mesh_migrator' \
		>/dev/null
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname meshtransit_private_factory_abandoned --set ON_ERROR_STOP=1 \
		--command 'CREATE EXTENSION btree_gist' \
		>/dev/null
	export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit_private_factory_abandoned
	export MESHTRANSIT_POSTGRES_DATABASE=meshtransit_private_factory_abandoned
	run_go test -tags=integration -count=1 -race -shuffle=on -v \
		-run '^TestPrivateIdentityFactoryProcessAbandonedIntegration$' -timeout=5m ./core/cmd/meshcore
	# Real committed wire ACK loss owns a seventh scope; no application wrapper.
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
		--command 'CREATE DATABASE meshtransit_private_factory_ack OWNER mesh_migrator' \
		>/dev/null
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname meshtransit_private_factory_ack --set ON_ERROR_STOP=1 \
		--command 'CREATE EXTENSION btree_gist' \
		>/dev/null
	export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit_private_factory_ack
	export MESHTRANSIT_POSTGRES_DATABASE=meshtransit_private_factory_ack
	run_go test -tags=integration -count=1 -race -shuffle=on -v \
		-run '^TestPrivateIdentityFactoryWireACKIntegration$' -timeout=5m ./core/cmd/meshcore
	unset MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION
	unset SSL_CERT_FILE SSL_CERT_DIR
	export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit
	export MESHTRANSIT_POSTGRES_DATABASE=meshtransit
fi

export MESHTRANSIT_ROLE=all
export MESHTRANSIT_POSTGRES_WORKER_USER=mesh_worker
export MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE="${fixture_dir}/worker-password"
export MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS=2

if [[ "${go_runner}" == container ]]; then
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
		--command 'CREATE DATABASE meshtransit_private_process OWNER mesh_migrator' \
		>/dev/null
	docker exec \
		--env "PGPASSWORD=${postgres_password}" \
		"${postgres_container}" \
		psql --username postgres --dbname meshtransit_private_process --set ON_ERROR_STOP=1 \
		--command 'CREATE EXTENSION btree_gist' \
		>/dev/null
	export MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION=1
	export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit_private_process
	export MESHTRANSIT_POSTGRES_DATABASE=meshtransit_private_process
	export SSL_CERT_FILE="${fixture_dir}/ca.crt"
	export SSL_CERT_DIR="${fixture_dir}/empty-roots"
	run_go test -tags=integration -count=1 -race -shuffle=on -v \
		-run '^TestPrivateIdentityRuntimeProcessIntegration$' -timeout=5m ./core/cmd/meshcore
	unset MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION
	unset SSL_CERT_FILE SSL_CERT_DIR
	export MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit
	export MESHTRANSIT_POSTGRES_DATABASE=meshtransit
fi

if [[ "${go_runner}" == container ]]; then
	docker exec --env "PGPASSWORD=${postgres_password}" "${postgres_container}" \
		psql --username postgres --dbname meshtransit --set ON_ERROR_STOP=1 \
		--quiet --no-align --tuples-only \
		--command "BEGIN READ ONLY; SET LOCAL statement_timeout='5s'; SELECT 'owned base expiry candidates after private scopes: ' || jsonb_array_length(mesh_ops.list_due_oidc_browser_v1('01890f00-0000-7000-8000-000000000001'::UUID,128)); ROLLBACK"
fi
