-- Display labels are separate from UUIDv7 authorization identities. A sidecar
-- avoids rewriting existing tenant authority rows or their immutable evidence.
CREATE TABLE mesh_ops.tenant_display_identity (
    display_code TEXT PRIMARY KEY CHECK (display_code ~ '^[0-9]{12}$'),
    workspace_public_id UUID UNIQUE REFERENCES mesh.workspace(public_id) ON DELETE RESTRICT,
    network_public_id UUID UNIQUE REFERENCES mesh.network(public_id) ON DELETE RESTRICT,
    CHECK (pg_catalog.num_nonnulls(workspace_public_id, network_public_id) = 1)
);
ALTER TABLE mesh_ops.tenant_display_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.tenant_display_identity FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_display_identity_migrator_policy ON mesh_ops.tenant_display_identity
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.tenant_display_identity
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER tenant_display_identity_immutable
BEFORE UPDATE OR DELETE ON mesh_ops.tenant_display_identity
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();

CREATE FUNCTION mesh_ops.assign_tenant_display_code_v1(p_kind TEXT, p_public_id UUID)
RETURNS TEXT LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
DECLARE
    existing_code TEXT;
    candidate TEXT;
    attempt INTEGER;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN ('workspace','network')
       OR p_public_id IS NULL
       OR pg_catalog.get_byte(pg_catalog.uuid_send(p_public_id),6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid tenant display identity';
    END IF;
    FOR attempt IN 1..8 LOOP
        SELECT identity.display_code INTO existing_code
        FROM mesh_ops.tenant_display_identity AS identity
        WHERE (p_kind='workspace' AND identity.workspace_public_id=p_public_id)
           OR (p_kind='network' AND identity.network_public_id=p_public_id);
        IF FOUND THEN RETURN existing_code; END IF;
        -- gen_random_uuid is PostgreSQL's built-in CSPRNG-backed UUID function.
        -- This bounded decimal reduction is a label, never a secret/token.
        candidate := pg_catalog.lpad(
            ((('x' || pg_catalog.substr(pg_catalog.replace(
                pg_catalog.gen_random_uuid()::TEXT,'-',''),1,15))::BIT(60)::BIGINT)
                % 1000000000000)::TEXT,12,'0');
        INSERT INTO mesh_ops.tenant_display_identity (
            display_code, workspace_public_id, network_public_id
        ) VALUES (
            candidate,
            CASE WHEN p_kind='workspace' THEN p_public_id END,
            CASE WHEN p_kind='network' THEN p_public_id END
        ) ON CONFLICT DO NOTHING;
        IF FOUND THEN RETURN candidate; END IF;
    END LOOP;
    RAISE EXCEPTION USING ERRCODE='53000', MESSAGE='tenant display identity allocation unavailable';
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.assign_tenant_display_code_v1(TEXT,UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.capture_tenant_display_identity()
RETURNS TRIGGER LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
BEGIN
    IF TG_TABLE_SCHEMA <> 'mesh' OR TG_TABLE_NAME NOT IN ('workspace','network')
       OR TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid tenant display identity trigger';
    END IF;
    PERFORM mesh_ops.assign_tenant_display_code_v1(TG_TABLE_NAME,NEW.public_id);
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.capture_tenant_display_identity()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER workspace_display_identity
AFTER INSERT ON mesh.workspace FOR EACH ROW
EXECUTE FUNCTION mesh_ops.capture_tenant_display_identity();
CREATE TRIGGER network_display_identity
AFTER INSERT ON mesh.network FOR EACH ROW
EXECUTE FUNCTION mesh_ops.capture_tenant_display_identity();

-- These migrator-only SELECT policies exist solely inside this migration
-- transaction. They are dropped before commit, with FORCE RLS kept enabled.
CREATE POLICY workspace_display_identity_backfill_policy ON mesh.workspace
FOR SELECT TO mesh_migrator USING (TRUE);
CREATE POLICY network_display_identity_backfill_policy ON mesh.network
FOR SELECT TO mesh_migrator USING (TRUE);

DO $backfill$
DECLARE entity RECORD;
BEGIN
    FOR entity IN
        SELECT 'workspace'::TEXT AS kind,public_id FROM mesh.workspace
        UNION ALL SELECT 'network'::TEXT,public_id FROM mesh.network
        ORDER BY kind,public_id
    LOOP
        PERFORM mesh_ops.assign_tenant_display_code_v1(entity.kind,entity.public_id);
    END LOOP;
END;
$backfill$;
DROP POLICY workspace_display_identity_backfill_policy ON mesh.workspace;
DROP POLICY network_display_identity_backfill_policy ON mesh.network;

-- Enrich only the exact scope already authorized by v1. Older binaries keep
-- their original JSON contract; new binaries explicitly opt into v2.
CREATE FUNCTION mesh_ops.read_console_management_scopes_v2(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_evaluated_at TIMESTAMPTZ, p_after_network_public_id UUID, p_limit INTEGER
)
RETURNS JSONB LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
DECLARE
    result JSONB;
    workspace_code TEXT;
    network_code TEXT;
    scope JSONB;
    scopes JSONB := '[]'::JSONB;
BEGIN
    result := mesh_ops.read_console_management_scopes_v1(
        p_session_public_id,p_deployment_public_id,p_principal_public_id,p_identity_subject_public_id,
        p_session_version,p_principal_authority_generation,p_account_session_generation,
        p_provider_generation,p_deployment_recovery_epoch,p_workspace_public_id,
        p_evaluated_at,p_after_network_public_id,p_limit);
    IF result IS NULL THEN RETURN NULL; END IF;
    SELECT identity.display_code INTO STRICT workspace_code
    FROM mesh_ops.tenant_display_identity AS identity
    WHERE identity.workspace_public_id=(result->>'workspace_id')::UUID;
    FOR scope IN SELECT value FROM pg_catalog.jsonb_array_elements(result->'scopes') LOOP
        SELECT identity.display_code INTO STRICT network_code
        FROM mesh_ops.tenant_display_identity AS identity
        WHERE identity.network_public_id=(scope->>'network_id')::UUID;
        scopes := scopes || pg_catalog.jsonb_build_array(
            scope || pg_catalog.jsonb_build_object('network_display_code',network_code));
    END LOOP;
    RETURN result || pg_catalog.jsonb_build_object(
        'workspace_display_code',workspace_code,'scopes',scopes);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_management_scopes_v2(
    UUID,UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,UUID,TIMESTAMPTZ,UUID,INTEGER
) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_management_scopes_v2(
    UUID,UUID,UUID,UUID,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,UUID,TIMESTAMPTZ,UUID,INTEGER
) TO mesh_runtime;
