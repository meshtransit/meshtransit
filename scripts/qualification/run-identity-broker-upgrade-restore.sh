#!/usr/bin/env bash

set -euo pipefail

on_error() {
	local line="$1"
	printf 'Identity-broker qualification failed at line %s.\n' "${line}" >&2
}
trap 'on_error "${LINENO}"' ERR

readonly old_version='v2.45.0'
readonly old_commit='bcc2283694018a59e9b84c43c6c50ce996e9409b'
readonly current_version='v2.45.1+compat.8'
readonly postgres_image='postgres@sha256:3725f4e2499eef5134592b3b4ab79a543ed7f8e533b05b5b637af926630f6650'

old_source="${DEX_OLD_SOURCE:-}"
prepared_root="${DEX_PREPARED_ROOT:-}"
current_binary="${DEX_CURRENT_BINARY:-}"
current_binary_sha256="${DEX_CURRENT_BINARY_SHA256:-}"
qualification_date="${QUALIFICATION_DATE:-$(date -u +%F)}"

for path in "${old_source}" "${prepared_root}" "${current_binary}"; do
	[[ "${path}" = /* ]] || { printf '%s\n' 'Identity-broker qualification requires absolute input paths.' >&2; exit 2; }
done
[[ -d "${old_source}/.git" ]] || { printf '%s\n' 'Old upstream checkout is unavailable.' >&2; exit 2; }
[[ -f "${prepared_root}/go.work" ]] || { printf '%s\n' 'Verified broker workspace is unavailable.' >&2; exit 2; }
[[ -f "${prepared_root}/source/go.mod" ]] || { printf '%s\n' 'Prepared broker source is unavailable.' >&2; exit 2; }
[[ -x "${current_binary}" ]] || { printf '%s\n' 'Current broker binary is unavailable.' >&2; exit 2; }
[[ "${current_binary_sha256}" =~ ^[0-9a-f]{64}$ ]] || { printf '%s\n' 'Current broker digest is invalid.' >&2; exit 2; }

actual_current_sha256="$(openssl dgst -sha256 -r "${current_binary}" | awk '{print $1}')"
[[ "${actual_current_sha256}" = "${current_binary_sha256}" ]] || {
	printf '%s\n' 'Current broker binary digest does not match.' >&2
	exit 2
}
[[ "$("${current_binary}" version | awk '/Dex Version:/ {print $3}')" = "${current_version}" ]] || {
	printf '%s\n' 'Current broker binary version does not match.' >&2
	exit 2
}
[[ "$(git -C "${old_source}" remote get-url origin)" = 'https://github.com/dexidp/dex.git' ]] || {
	printf '%s\n' 'Old upstream origin does not match.' >&2
	exit 2
}
[[ "$(git -C "${old_source}" rev-parse "${old_version}^{}")" = "${old_commit}" ]] || {
	printf '%s\n' 'Old upstream tag does not match.' >&2
	exit 2
}

fixture_dir="$(mktemp -d)"
postgres_container="meshtransit-broker-upgrade-$RANDOM-$$"
old_tree="${fixture_dir}/old-source"
old_binary="${fixture_dir}/dex-old"
storage_helper="${fixture_dir}/dexstorage"
broker_pid=''

cleanup() {
	if [[ -n "${broker_pid}" ]]; then
		kill -TERM "${broker_pid}" >/dev/null 2>&1 || true
		wait "${broker_pid}" >/dev/null 2>&1 || true
	fi
	docker rm --force "${postgres_container}" >/dev/null 2>&1 || true
	rm -rf "${fixture_dir}"
}
trap cleanup EXIT

mkdir -p "${old_tree}"
git -C "${old_source}" archive --format=tar "${old_commit}" \
	| tar --extract --file=- --directory="${old_tree}"

env GOWORK=off GOTOOLCHAIN=go1.26.8 CGO_ENABLED=0 \
	go -C "${old_tree}" build -buildvcs=false -trimpath \
	-ldflags "-w -X main.version=${old_version}" \
	-o "${old_binary}" ./cmd/dex
old_binary_sha256="$(openssl dgst -sha256 -r "${old_binary}" | awk '{print $1}')"
[[ "$("${old_binary}" version | awk '/Dex Version:/ {print $3}')" = "${old_version}" ]] || {
	printf '%s\n' 'Old broker binary version does not match.' >&2
	exit 1
}

env GOWORK="${prepared_root}/go.work" GOTOOLCHAIN=go1.26.8 CGO_ENABLED=0 \
	go test -count=1 -tags=dexbroker,qualification ./tools/qualification/dexstorage
env GOWORK="${prepared_root}/go.work" GOTOOLCHAIN=go1.26.8 CGO_ENABLED=0 \
	go build -buildvcs=false -trimpath -tags=dexbroker,qualification \
	-o "${storage_helper}" ./tools/qualification/dexstorage
storage_helper_sha256="$(openssl dgst -sha256 -r "${storage_helper}" | awk '{print $1}')"

postgres_password="$(openssl rand -hex 24)"
migrator_password="$(openssl rand -hex 24)"
runtime_password="$(openssl rand -hex 24)"
client_secret="$(openssl rand -hex 24)"
printf '%s\n' "${migrator_password}" >"${fixture_dir}/migrator-password"
printf '%s\n' "${runtime_password}" >"${fixture_dir}/runtime-password"
chmod 0600 "${fixture_dir}/migrator-password" "${fixture_dir}/runtime-password"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-subj '/CN=MeshTransit broker qualification CA' \
	-keyout "${fixture_dir}/ca.key" -out "${fixture_dir}/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=127.0.0.1' \
	-keyout "${fixture_dir}/server.key" -out "${fixture_dir}/server.csr" >/dev/null 2>&1
printf '%s\n' \
	'[server]' \
	'subjectAltName=IP:127.0.0.1' \
	'extendedKeyUsage=serverAuth' \
	>"${fixture_dir}/server.ext"
openssl x509 -req -days 1 -in "${fixture_dir}/server.csr" \
	-CA "${fixture_dir}/ca.crt" -CAkey "${fixture_dir}/ca.key" -CAcreateserial \
	-extfile "${fixture_dir}/server.ext" -extensions server \
	-out "${fixture_dir}/server.crt" >/dev/null 2>&1
chmod 0600 "${fixture_dir}/server.key"

docker run --detach --name "${postgres_container}" --publish 127.0.0.1::5432 \
	--env "POSTGRES_PASSWORD=${postgres_password}" \
	--env 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256' \
	"${postgres_image}" >/dev/null
for _ in $(seq 1 60); do
	if docker exec --env "PGPASSWORD=${postgres_password}" "${postgres_container}" \
		pg_isready --username postgres --dbname postgres >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
docker exec --env "PGPASSWORD=${postgres_password}" "${postgres_container}" \
	pg_isready --username postgres --dbname postgres >/dev/null
docker cp "${fixture_dir}/server.crt" "${postgres_container}:/tmp/server.crt"
docker cp "${fixture_dir}/server.key" "${postgres_container}:/tmp/server.key"
docker exec --user root "${postgres_container}" \
	chown postgres:postgres /tmp/server.crt /tmp/server.key
docker exec --user root "${postgres_container}" chmod 0600 /tmp/server.key
docker exec --env "PGPASSWORD=${postgres_password}" "${postgres_container}" \
	psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
	--command "ALTER SYSTEM SET ssl = 'on'" \
	--command "ALTER SYSTEM SET ssl_cert_file = '/tmp/server.crt'" \
	--command "ALTER SYSTEM SET ssl_key_file = '/tmp/server.key'" >/dev/null
docker restart "${postgres_container}" >/dev/null
for _ in $(seq 1 60); do
	if docker exec --env "PGPASSWORD=${postgres_password}" "${postgres_container}" \
		pg_isready --username postgres --dbname postgres >/dev/null 2>&1; then
		break
	fi
	sleep 1
done

printf \
	"CREATE ROLE dex_migrator LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE ROLE dex_runtime LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n" \
	"${migrator_password}" "${runtime_password}" \
	| docker exec --interactive --env "PGPASSWORD=${postgres_password}" \
	"${postgres_container}" psql --username postgres --dbname postgres \
	--set ON_ERROR_STOP=1 >/dev/null
for database in dex_upgrade dex_restore dex_rollback; do
	docker exec --env "PGPASSWORD=${postgres_password}" "${postgres_container}" \
		psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
		--command "CREATE DATABASE ${database} OWNER dex_migrator" >/dev/null
done

postgres_address="$(docker port "${postgres_container}" 5432/tcp)"
postgres_port="${postgres_address##*:}"

choose_port() {
	local candidate
	for _ in $(seq 1 100); do
		candidate=$((20000 + RANDOM % 20000))
		if ! nc -z 127.0.0.1 "${candidate}" >/dev/null 2>&1; then
			printf '%s' "${candidate}"
			return 0
		fi
	done
	return 1
}

report_broker_failure() {
	local log_path="$1"
	tail -n 20 "${log_path}" \
		| sed \
			-e "s/${postgres_password}/[redacted]/g" \
			-e "s/${migrator_password}/[redacted]/g" \
			-e "s/${runtime_password}/[redacted]/g" \
			-e "s/${client_secret}/[redacted]/g" >&2
}

start_broker() {
	local binary="$1"
	local database="$2"
	local label="$3"
	local port config_path
	port="$(choose_port)"
	config_path="${fixture_dir}/${label}.yaml"
	cat >"${config_path}" <<EOF
issuer: http://127.0.0.1:${port}
storage:
  type: postgres
  config:
    host: 127.0.0.1
    port: ${postgres_port}
    database: ${database}
    user: dex_migrator
    password: ${migrator_password}
    connectionTimeout: 5
    maxOpenConns: 2
    maxIdleConns: 1
    ssl:
      mode: verify-full
      caFile: ${fixture_dir}/ca.crt
web:
  http: 127.0.0.1:${port}
oauth2:
  responseTypes: ["code"]
expiry:
  signingKeys: 24h
  idTokens: 5m
staticClients:
  - id: meshtransit-upgrade-fixture
    name: MeshTransit upgrade fixture
    secret: ${client_secret}
    redirectURIs:
      - http://127.0.0.1/callback
connectors:
  - type: mockCallback
    id: qualification
    name: Qualification fixture
enablePasswordDB: false
logger:
  level: error
  format: json
EOF
	chmod 0600 "${config_path}"
	"${binary}" serve "${config_path}" >"${fixture_dir}/${label}.log" 2>&1 &
	broker_pid=$!
	for _ in $(seq 1 100); do
		if curl --fail --silent --show-error \
			"http://127.0.0.1:${port}/.well-known/openid-configuration" \
			>"${fixture_dir}/${label}-discovery.json" 2>/dev/null; then
			broker_port="${port}"
			return 0
		fi
		if ! kill -0 "${broker_pid}" >/dev/null 2>&1; then
			printf '%s\n' 'Identity broker exited before readiness.' >&2
			report_broker_failure "${fixture_dir}/${label}.log"
			return 1
		fi
		sleep 0.1
	done
	printf '%s\n' 'Identity broker did not become ready.' >&2
	return 1
}

capture_jwks() {
	local label="$1"
	curl --fail --silent --show-error "http://127.0.0.1:${broker_port}/keys" \
		>"${fixture_dir}/${label}-jwks.json"
	jq --sort-keys --compact-output '.keys | sort_by(.kid)' \
		"${fixture_dir}/${label}-jwks.json" >"${fixture_dir}/${label}-jwks-normalized.json"
	jq -e 'length > 0 and all(.[]; .kty == "RSA" and .use == "sig" and .alg == "RS256" and (.kid | length > 0))' \
		"${fixture_dir}/${label}-jwks-normalized.json" >/dev/null
}

stop_broker() {
	kill -TERM "${broker_pid}" >/dev/null 2>&1 || true
	wait "${broker_pid}" >/dev/null 2>&1 || true
	broker_pid=''
}

migration_level() {
	local database="$1"
	docker exec --env "PGPASSWORD=${migrator_password}" "${postgres_container}" \
		psql --username dex_migrator --dbname "${database}" \
		--quiet --no-align --tuples-only --set ON_ERROR_STOP=1 \
		--command 'SELECT pg_catalog.max(num) FROM public.migrations'
}

grant_runtime() {
	local database="$1"
	docker exec --env "PGPASSWORD=${migrator_password}" "${postgres_container}" \
		psql --username dex_migrator --dbname "${database}" --set ON_ERROR_STOP=1 \
		--command 'GRANT CONNECT ON DATABASE '"${database}"' TO dex_runtime' \
		--command 'GRANT USAGE ON SCHEMA public TO dex_runtime' \
		--command 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dex_runtime' \
		--command 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO dex_runtime' >/dev/null
}

run_storage_helper() {
	local mode="$1"
	local database="$2"
	local user password_file
	user='dex_runtime'
	password_file="${fixture_dir}/runtime-password"
	if [[ "${mode}" = 'migrate' ]]; then
		user='dex_migrator'
		password_file="${fixture_dir}/migrator-password"
	fi
	"${storage_helper}" \
		-mode "${mode}" \
		-address "127.0.0.1:${postgres_port}" \
		-database "${database}" \
		-user "${user}" \
		-password-file "${password_file}" \
		-ca-file "${fixture_dir}/ca.crt" >/dev/null
}

dump_database() {
	local database="$1"
	local output="$2"
	docker exec --env "PGPASSWORD=${migrator_password}" "${postgres_container}" \
		pg_dump --username dex_migrator --dbname "${database}" \
		--format=custom --no-owner --no-privileges >"${output}"
}

restore_database() {
	local database="$1"
	local input="$2"
	docker exec --interactive --env "PGPASSWORD=${migrator_password}" \
		"${postgres_container}" pg_restore --username dex_migrator \
		--dbname "${database}" --exit-on-error --no-owner --no-privileges <"${input}"
}

start_broker "${old_binary}" dex_upgrade old
capture_jwks old
stop_broker
old_level="$(migration_level dex_upgrade)"
[[ "${old_level}" =~ ^[0-9]+$ ]] || { printf '%s\n' 'Old migration level is invalid.' >&2; exit 1; }
dump_database dex_upgrade "${fixture_dir}/old.dump"
old_backup_sha256="$(openssl dgst -sha256 -r "${fixture_dir}/old.dump" | awk '{print $1}')"

run_storage_helper migrate dex_upgrade
current_level="$(migration_level dex_upgrade)"
[[ "${current_level}" =~ ^[0-9]+$ ]] || { printf '%s\n' 'Current migration level is invalid.' >&2; exit 1; }
(( current_level >= old_level )) || { printf '%s\n' 'Current migration level moved backward.' >&2; exit 1; }
grant_runtime dex_upgrade
run_storage_helper verify dex_upgrade
start_broker "${current_binary}" dex_upgrade current
capture_jwks current
stop_broker
cmp "${fixture_dir}/old-jwks-normalized.json" "${fixture_dir}/current-jwks-normalized.json"
dump_database dex_upgrade "${fixture_dir}/current.dump"
current_backup_sha256="$(openssl dgst -sha256 -r "${fixture_dir}/current.dump" | awk '{print $1}')"

restore_database dex_restore "${fixture_dir}/current.dump"
grant_runtime dex_restore
run_storage_helper verify dex_restore
start_broker "${current_binary}" dex_restore restored-current
capture_jwks restored-current
stop_broker
cmp "${fixture_dir}/current-jwks-normalized.json" "${fixture_dir}/restored-current-jwks-normalized.json"

restore_database dex_rollback "${fixture_dir}/old.dump"
start_broker "${old_binary}" dex_rollback rolled-back-old
capture_jwks rolled-back-old
stop_broker
cmp "${fixture_dir}/old-jwks-normalized.json" "${fixture_dir}/rolled-back-old-jwks-normalized.json"

jwks_sha256="$(openssl dgst -sha256 -r "${fixture_dir}/old-jwks-normalized.json" | awk '{print $1}')"
jq --null-input --sort-keys \
	--arg evaluated_on "${qualification_date}" \
	--arg postgres_image "${postgres_image}" \
	--arg old_version "${old_version}" \
	--arg old_commit "${old_commit}" \
	--arg old_binary_sha256 "${old_binary_sha256}" \
	--arg old_level "${old_level}" \
	--arg current_version "${current_version}" \
	--arg current_binary_sha256 "${current_binary_sha256}" \
	--arg storage_helper_sha256 "${storage_helper_sha256}" \
	--arg current_level "${current_level}" \
	--arg old_backup_sha256 "${old_backup_sha256}" \
	--arg current_backup_sha256 "${current_backup_sha256}" \
	--arg jwks_sha256 "${jwks_sha256}" \
	'{
	  schema_version: "meshtransit.identity-broker-upgrade-restore/v1",
	  evaluated_on: $evaluated_on,
	  postgres_image: $postgres_image,
	  old: {
	    version: $old_version,
	    commit: $old_commit,
	    binary_sha256: $old_binary_sha256,
	    migration_level: ($old_level | tonumber)
	  },
	  current: {
	    version: $current_version,
	    binary_sha256: $current_binary_sha256,
	    storage_helper_sha256: $storage_helper_sha256,
	    migration_level: ($current_level | tonumber)
	  },
	  backups: {
	    pre_upgrade_sha256: $old_backup_sha256,
	    post_upgrade_sha256: $current_backup_sha256
	  },
	  continuity: {
	    normalized_public_jwks_sha256: $jwks_sha256,
	    upgrade_equal: true,
	    restored_current_equal: true,
	    restored_old_rollback_equal: true
	  },
	  prepared_schema: {
	    upgraded_database: "pass",
	    restored_current_database: "pass"
	  },
	  result: "pass"
	}'
