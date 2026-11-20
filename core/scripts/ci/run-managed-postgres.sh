#!/usr/bin/env bash
# Core's database install chain on a PostgreSQL whose administrator is not a
# superuser, as on a managed service (V1-11 step 2): CREATEROLE CREATEDB plus
# provider-style default roles, for each
# createrole_self_grant a provider may set.
#
#   bash core/scripts/ci/run-managed-postgres.sh            # '' and 'set,inherit'
#   SELF_GRANTS="set,inherit" bash core/scripts/ci/run-managed-postgres.sh
#
# For each, and once more with a superuser administrator (a self-run
# server, the POC): install bootstrap postgres -> operator apply -> migrate
# up -> operator apply -> operator apply --after-rollout -> operator status
# -> migrate verify (clean), then a second bootstrap changes nothing, a
# login that is not this installation's and has another password is
# refused, and the administrator keeps no membership beyond the ADMIN-only
# grants. Managed: a SET the administrator left on itself is removed by the
# next run, and an expired login is renewed. Superuser: a login's membership another grantor gave SET is
# narrowed.
set -euo pipefail

postgres_image="${POSTGRES_IMAGE:-postgres:18.6-bookworm}"
self_grants="${SELF_GRANTS:-, set,inherit}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
work="$(mktemp -d)"
containers=()
cleanup() {
	for container in "${containers[@]+"${containers[@]}"}"; do
		docker rm -f "${container}" >/dev/null 2>&1 || true
	done
	rm -rf "${work}"
}
trap cleanup EXIT

(cd "${root}" && go build -o "${work}/meshcore" ./core/cmd/meshcore)

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=managed-postgres test CA" \
	-keyout "${work}/ca.key" -out "${work}/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" \
	-keyout "${work}/server.key" -out "${work}/server.csr" >/dev/null 2>&1
printf '[s]\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' >"${work}/server.ext"
openssl x509 -req -days 1 -in "${work}/server.csr" -CA "${work}/ca.crt" -CAkey "${work}/ca.key" \
	-CAcreateserial -extfile "${work}/server.ext" -extensions s -out "${work}/server.crt" >/dev/null 2>&1

current_container=""
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	if [[ -n "${current_container}" ]]; then
		docker logs "${current_container}" 2>&1 | grep -E 'ERROR|STATEMENT|DETAIL' | tail -6 >&2 || true
	fi
	exit 1
}

run_case() {
	local self_grant="$1" index="$2" admin_kind="${3:-managed}"
	local dir="${work}/case${index}" container="meshtransit-managed-pg-$$-${index}"
	mkdir -p "${dir}"
	containers+=("${container}")
	current_container="${container}"
	for name in super admin migrator runtime control worker identity_migrator identity_runtime other; do
		openssl rand -hex 24 >"${dir}/${name}"
	done
	chmod 0600 "${dir}"/*
	docker run --detach --name "${container}" --publish 127.0.0.1::5432 \
		--env "POSTGRES_PASSWORD=$(cat "${dir}/super")" --env 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256' \
		"${postgres_image}" >/dev/null
	wait_ready "${container}"
	docker cp "${work}/server.crt" "${container}:/tmp/server.crt"
	docker cp "${work}/server.key" "${container}:/tmp/server.key"
	docker exec --user root "${container}" chown postgres:postgres /tmp/server.crt /tmp/server.key
	docker exec --user root "${container}" chmod 0600 /tmp/server.key
	docker exec "${container}" psql --username postgres --quiet \
		--command "ALTER SYSTEM SET ssl = 'on'" --command "ALTER SYSTEM SET ssl_cert_file = '/tmp/server.crt'" \
		--command "ALTER SYSTEM SET ssl_key_file = '/tmp/server.key'" >/dev/null
	docker restart "${container}" >/dev/null
	wait_ready "${container}"
	local admin=cloudadmin admin_password="${dir}/admin"
	if [[ "${admin_kind}" == superuser ]]; then
		admin=postgres admin_password="${dir}/super"
	else
		# The managed-style administrator.
		docker exec "${container}" psql --username postgres --quiet --set ON_ERROR_STOP=1 \
			--command "CREATE ROLE cloudadmin LOGIN CREATEROLE CREATEDB PASSWORD '$(cat "${dir}/admin")'" \
			--command "GRANT pg_monitor, pg_signal_backend, pg_read_all_stats TO cloudadmin" \
			--command "ALTER ROLE cloudadmin SET createrole_self_grant = '${self_grant}'" >/dev/null
	fi
	local port
	port="$(docker port "${container}" 5432/tcp | head -1 | sed 's/.*://')"
	export MESHTRANSIT_BOOTSTRAP_POSTGRES_ADDRESS="127.0.0.1:${port}"
	export MESHTRANSIT_BOOTSTRAP_POSTGRES_USER="${admin}"
	export MESHTRANSIT_BOOTSTRAP_POSTGRES_PASSWORD_FILE="${admin_password}"
	export MESHTRANSIT_BOOTSTRAP_POSTGRES_CA_FILE="${work}/ca.crt"
	export MESHTRANSIT_BOOTSTRAP_IDENTITY_DATABASE=identity
	export MESHTRANSIT_BOOTSTRAP_MARKER="meshtransit:managed-test-${index}"
	export MESHTRANSIT_BOOTSTRAP_LOGIN_PASSWORD_FILES="mesh_migrator=${dir}/migrator,mesh_runtime=${dir}/runtime,mesh_control=${dir}/control,mesh_worker=${dir}/worker,identity_migrator=${dir}/identity_migrator,identity_runtime=${dir}/identity_runtime"
	export MESHTRANSIT_OPERATOR_POSTGRES_ADDRESS="127.0.0.1:${port}" MESHTRANSIT_OPERATOR_POSTGRES_DATABASE=meshtransit
	export MESHTRANSIT_OPERATOR_POSTGRES_USER="${admin}" MESHTRANSIT_OPERATOR_POSTGRES_PASSWORD_FILE="${admin_password}"
	export MESHTRANSIT_OPERATOR_POSTGRES_CA_FILE="${work}/ca.crt"
	export MESHTRANSIT_MIGRATION_POSTGRES_ADDRESS="127.0.0.1:${port}" MESHTRANSIT_MIGRATION_POSTGRES_DATABASE=meshtransit
	export MESHTRANSIT_MIGRATION_POSTGRES_USER=mesh_migrator MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE="${dir}/migrator"
	export MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE="${work}/ca.crt" MESHTRANSIT_MIGRATION_ACTOR=managed-postgres-test
	export MESHTRANSIT_MIGRATION_STATEMENT_TIMEOUT=120s

	printf '== %s, %s administrator, createrole_self_grant=%q\n' "${postgres_image}" "${admin_kind}" "${self_grant}"
	step "install bootstrap postgres" "${work}/meshcore" install bootstrap postgres
	step "operator apply (before migrate)" "${work}/meshcore" migrate operator apply
	step "migrate up" "${work}/meshcore" migrate up
	step "operator apply" "${work}/meshcore" migrate operator apply
	step "operator apply --after-rollout" "${work}/meshcore" migrate operator apply --after-rollout
	local status
	status="$("${work}/meshcore" migrate operator status)" || fail "operator status"
	if grep -q '"role_memberships"' <<<"${status}"; then fail "operator status reports memberships: ${status}"; fi
	printf 'ok   operator status, no membership reported\n'
	local verify
	verify="$("${work}/meshcore" migrate verify)" || fail "migrate verify"
	grep -q '"state":"clean"' <<<"${verify}" || fail "migrate verify is not clean"
	if grep -q '"status":"\(missing\|pending\|waiting\)"' <<<"${verify}"; then fail "an operator step is not applied"; fi
	printf 'ok   migrate verify: clean, every operator step applied\n'

	local again
	again="$("${work}/meshcore" install bootstrap postgres)" || fail "second bootstrap"
	[[ "${again}" == '{"operation":"install bootstrap postgres"}' ]] || fail "second bootstrap changed: ${again}"
	printf 'ok   second bootstrap changes nothing\n'

	if [[ "${admin_kind}" == superuser ]]; then
		# Another grantor gives mesh_runtime SET on one of its groups.
		local group
		group="$(psql_value "${container}" "SELECT g.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
			JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = 'mesh_runtime' ORDER BY 1 LIMIT 1")"
		[[ -n "${group}" ]] || fail "mesh_runtime has no group"
		docker exec "${container}" psql --username postgres --quiet --set ON_ERROR_STOP=1 \
			--command "CREATE ROLE other_grantor NOLOGIN" \
			--command "GRANT \"${group}\" TO other_grantor WITH ADMIN TRUE" \
			--command "SET ROLE other_grantor" \
			--command "GRANT \"${group}\" TO mesh_runtime WITH INHERIT TRUE, SET TRUE GRANTED BY other_grantor" >/dev/null
		step "bootstrap narrows another grantor's SET" "${work}/meshcore" install bootstrap postgres
		[[ "$(psql_value "${container}" "SELECT count(*) FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member
			WHERE u.rolname = 'mesh_runtime' AND (m.set_option OR m.admin_option)")" == 0 ]] ||
			fail "mesh_runtime keeps SET or ADMIN"
		printf 'ok   no MeshTransit login keeps SET or ADMIN\n'
	else
		# A run stopped after taking SET on itself.
		docker exec "${container}" psql --username postgres --quiet --set ON_ERROR_STOP=1 \
			--command "SET ROLE cloudadmin" \
			--command "GRANT mesh_worker TO cloudadmin WITH INHERIT TRUE, SET TRUE" >/dev/null
		local cleaned
		cleaned="$("${work}/meshcore" install bootstrap postgres)" || fail "bootstrap after a stopped run"
		grep -q '"self:mesh_worker"' <<<"${cleaned}" || fail "leftover SET not removed: ${cleaned}"
		printf 'ok   a leftover SET on the administrator is removed\n'
		# An expired login refuses its right password: the next run clears it.
		docker exec "${container}" psql --username postgres --quiet --set ON_ERROR_STOP=1 \
			--command "ALTER ROLE mesh_worker VALID UNTIL '2000-01-01'" >/dev/null
		local renewed
		renewed="$("${work}/meshcore" install bootstrap postgres)" || fail "bootstrap of an expired login"
		grep -q '"mesh_worker:attributes"' <<<"${renewed}" || fail "expired login not fixed: ${renewed}"
		grep -q 'passwords_changed' <<<"${renewed}" && fail "an expired login's password was rewritten: ${renewed}"
		printf 'ok   an expired login is renewed without a new password\n'
	fi

	# A login not marked as this installation's, with another password.
	docker exec "${container}" psql --username postgres --quiet --set ON_ERROR_STOP=1 \
		--command "COMMENT ON ROLE mesh_worker IS NULL" \
		--command "ALTER ROLE mesh_worker PASSWORD '$(cat "${dir}/other")'" >/dev/null
	if "${work}/meshcore" install bootstrap postgres 2>"${dir}/refused.log" >/dev/null; then
		fail "a foreign login's password was changed"
	fi
	grep -q bootstrap_login_password_differs "${dir}/refused.log" || fail "refusal code: $(cat "${dir}/refused.log")"
	printf 'ok   a foreign login with another password is refused\n'

	[[ "${admin_kind}" == superuser ]] && return 0
	local extra
	extra="$(docker exec "${container}" psql --username postgres --no-align --tuples-only --command \
		"SELECT count(*) FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = 'cloudadmin'
		 AND (m.inherit_option OR m.set_option) AND m.roleid NOT IN (SELECT oid FROM pg_roles WHERE rolname LIKE 'pg\_%')")"
	[[ "${extra}" == 0 ]] || fail "the administrator keeps ${extra} memberships"
	printf 'ok   the administrator keeps only ADMIN-only grants\n'
}

psql_value() {
	docker exec "$1" psql --username postgres --no-align --tuples-only --command "$2"
}

wait_ready() {
	for _ in $(seq 1 60); do
		docker exec "$1" pg_isready --username postgres >/dev/null 2>&1 && return 0
		sleep 1
	done
	fail "PostgreSQL did not start"
}

step() {
	local name="$1"; shift
	local out
	if ! out="$("$@" 2>&1)"; then
		printf '%s\n' "${out}" | tail -5 >&2
		fail "${name}"
	fi
	printf 'ok   %s\n' "${name}"
}

index=0
IFS=' ' read -r -a grants <<<"${self_grants}"
for self_grant in "${grants[@]}"; do
	[[ "${self_grant}" == "," ]] && self_grant=""
	run_case "${self_grant}" "${index}"
	index=$((index + 1))
done
run_case "" "${index}" superuser
printf 'managed PostgreSQL install chain: all cases passed\n'
