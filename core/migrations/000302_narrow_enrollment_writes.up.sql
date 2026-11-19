-- Schema 302: the narrowing role isolation design §3.3 planned for step S2 on enrollment (TD-SEC-90).
--
-- Migration 298 copied mesh_runtime's column grants on the enrollment tables to the group roles, so after schema 300:
-- * control's group could still set state, revoked_at and deleted_at of mesh.enrollment_credential, i.e. re-enable a
--   revoked enrollment key in any tenant it set its scope to; control only counts uses (used_count) and reads the key
--   through definers;
-- * both groups could update every column of mesh.enrollment_profile (use limits, route advertisement, state), which no
--   Go code writes any more. Registration still locks the profile FOR UPDATE, and PostgreSQL requires UPDATE on at
--   least one column for that lock: both groups keep UPDATE on updated_at only;
-- * both groups could set authorized_principal_id of mesh.pending_registration, which only definers set (design §4.2),
--   and the api could set the completion columns (device_id, completed_*), which only control's registration writes;
--   the api only expires browser approvals (state, version, updated_at).
--
-- Contract step. The code of schemas 297–301 writes none of these columns (core/migrations/role_grants.json and the
-- statements in core/internal/adapter/postgres), so rolling the image back needs nothing.

REVOKE UPDATE (state, revoked_at, deleted_at) ON mesh.enrollment_credential FROM mesh_control_rights, mesh_api_rights;

DO $profile$
DECLARE
    v_column TEXT;
BEGIN
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog', TRUE);
    REVOKE UPDATE, INSERT, DELETE ON mesh.enrollment_profile FROM mesh_api_rights, mesh_control_rights;
    FOR v_column IN
        SELECT attribute.attname FROM pg_catalog.pg_attribute AS attribute
        WHERE attribute.attrelid = 'mesh.enrollment_profile'::REGCLASS AND attribute.attnum > 0
          AND NOT attribute.attisdropped
    LOOP
        EXECUTE pg_catalog.format('REVOKE UPDATE (%I), INSERT (%I) ON mesh.enrollment_profile FROM mesh_api_rights, '
            'mesh_control_rights', v_column, v_column);
    END LOOP;
END;
$profile$;
GRANT UPDATE (updated_at) ON mesh.enrollment_profile TO mesh_api_rights, mesh_control_rights;

REVOKE UPDATE (authorized_principal_id) ON mesh.pending_registration FROM mesh_api_rights, mesh_control_rights;
REVOKE UPDATE (device_id, completed_hostname, completed_disposition, completed_network_revision)
    ON mesh.pending_registration FROM mesh_api_rights;

-- What is left, checked for the groups and every login (a login's privileges include what it inherits): no role may
-- change a credential's state, write a profile's content, or set who authorized a pending registration.
DO $check$
BEGIN
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog', TRUE);
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles AS grantee
        CROSS JOIN (VALUES
            ('mesh.enrollment_credential', 'state', 'UPDATE'),
            ('mesh.enrollment_credential', 'revoked_at', 'UPDATE'),
            ('mesh.enrollment_credential', 'deleted_at', 'UPDATE'),
            ('mesh.pending_registration', 'authorized_principal_id', 'UPDATE')) AS forbidden(relation, name, privilege)
        WHERE grantee.rolname IN ('mesh_api_rights', 'mesh_control_rights', 'mesh_runtime', 'mesh_control', 'mesh_all',
              'mesh_worker')
          AND pg_catalog.has_column_privilege(grantee.oid, forbidden.relation::REGCLASS, forbidden.name,
              forbidden.privilege))
        OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles AS grantee
        CROSS JOIN (VALUES ('mesh.enrollment_credential'), ('mesh.enrollment_profile')) AS target(relation)
        CROSS JOIN (VALUES ('INSERT'), ('DELETE')) AS forbidden(privilege)
        WHERE grantee.rolname IN ('mesh_api_rights', 'mesh_control_rights', 'mesh_runtime', 'mesh_control', 'mesh_all',
              'mesh_worker')
          AND (pg_catalog.has_table_privilege(grantee.oid, target.relation::REGCLASS, forbidden.privilege)
              OR (forbidden.privilege = 'INSERT'
                  AND pg_catalog.has_any_column_privilege(grantee.oid, target.relation::REGCLASS, 'INSERT'))))
        OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles AS grantee
        CROSS JOIN pg_catalog.pg_attribute AS attribute
        WHERE grantee.rolname IN ('mesh_api_rights', 'mesh_control_rights', 'mesh_runtime', 'mesh_control', 'mesh_all',
              'mesh_worker')
          AND attribute.attrelid = 'mesh.enrollment_profile'::REGCLASS AND attribute.attnum > 0
          AND NOT attribute.attisdropped AND attribute.attname <> 'updated_at'
          AND pg_catalog.has_column_privilege(grantee.oid, attribute.attrelid, attribute.attnum, 'UPDATE')) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'a role can still change enrollment credentials, profiles or registration authorization';
    END IF;
END;
$check$;
