#!/usr/bin/env bash

set -euo pipefail

postgres_image="${POSTGRES_IMAGE:-postgres:18.6-bookworm}"
redis_image="${REDIS_IMAGE:-redis:8.8.0-trixie}"
fixture_dir="$(mktemp -d)"
postgres_container="meshtransit-postgres-$RANDOM-$$"
redis_container="meshtransit-redis-$RANDOM-$$"
postgres_password="$(openssl rand -hex 24)"
migration_password="$(openssl rand -hex 24)"
runtime_password="$(openssl rand -hex 24)"
worker_password="$(openssl rand -hex 24)"
redis_password="$(openssl rand -hex 24)"
enrollment_digest_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
noise_private_key="privkey:$(openssl rand -hex 32)"

cleanup() {
	docker rm --force "${redis_container}" >/dev/null 2>&1 || true
	docker rm --force "${postgres_container}" >/dev/null 2>&1 || true
	rm -rf "${fixture_dir}"
}
trap cleanup EXIT

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
	'subjectAltName=IP:127.0.0.1' \
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
printf '%s\n' "${noise_private_key}" >"${fixture_dir}/control-noise-private-key"
chmod 0600 "${fixture_dir}/migration-password"
chmod 0600 "${fixture_dir}/runtime-password"
chmod 0600 "${fixture_dir}/worker-password"
chmod 0600 "${fixture_dir}/postgres-admin-password"
chmod 0600 "${fixture_dir}/redis-password"
chmod 0600 "${fixture_dir}/enrollment-digest-key"
chmod 0600 "${fixture_dir}/control-noise-private-key"
chmod 0600 "${fixture_dir}/control-server.key"

docker run \
	--detach \
	--name "${postgres_container}" \
	--publish 127.0.0.1::5432 \
	--env "POSTGRES_PASSWORD=${postgres_password}" \
	--env 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256' \
	"${postgres_image}" \
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
	"CREATE ROLE mesh_migrator LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_runtime LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_worker LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_audit_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_share_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE mesh_observer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n" \
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
	--publish 127.0.0.1::6379 \
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
	"+hget" "+hset" "+pexpire" "+del" \
	"~meshtransit:v1:presence:node:*" \
	"~meshtransit:v1:endpoints:node:*" \
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

postgres_address="$(docker port "${postgres_container}" 5432/tcp)"
redis_address="$(docker port "${redis_container}" 6379/tcp)"
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
export MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID=integration-v1
export MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_FILE="${fixture_dir}/enrollment-digest-key"
export MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE="${fixture_dir}/control-server.crt"
export MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE="${fixture_dir}/control-server.key"
export MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE="${fixture_dir}/control-noise-private-key"
export MESHTRANSIT_CONTROL_MAX_SESSIONS=8
export MESHTRANSIT_CONTROL_MAX_STREAMS_PER_SESSION=2
export MESHTRANSIT_TEST_POSTGRES_ADMIN_PASSWORD_FILE="${fixture_dir}/postgres-admin-password"
export MESHTRANSIT_TEST_POSTGRES_WORKER_PASSWORD_FILE="${fixture_dir}/worker-password"

go test \
	-tags=integration \
	-count=1 \
	-race \
	-run '^TestPostgreSQLMigrations$' \
	-timeout=5m \
	./internal/integration

export MESHTRANSIT_ROLE=all
export MESHTRANSIT_POSTGRES_WORKER_USER=mesh_worker
export MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE="${fixture_dir}/worker-password"
export MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS=2
export MESHTRANSIT_TEST_MESHCORE_BINARY="${fixture_dir}/meshcore"
go build -trimpath -o "${MESHTRANSIT_TEST_MESHCORE_BINARY}" ./cmd/meshcore

go test \
	-tags=integration \
	-count=1 \
	-race \
	-run '^(TestTLSAuthenticatedDependencies|TestRoleAllProcessRegistrationConvergesAcrossRestart|TestRoleAllProcessRestartsAfterGracefulShutdown|TestRoleAllProcessRejectsInvalidConfigurationBeforeListening)$' \
	-timeout=5m \
	./internal/integration
