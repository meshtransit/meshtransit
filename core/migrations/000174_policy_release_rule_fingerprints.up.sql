-- Schema 174: every Policy Release keeps the fingerprints of its Access
-- Rules, so the next publication can say in its policy.published event which
-- rules it added, removed or changed.
--
-- Core computes the fingerprints (one 49-byte entry per rule: rule ID,
-- destination kind and ID, digest of the rule as written) and compares the
-- previous release's with the new ones itself. The database only stores one
-- row per release and returns the previous one; it never compares compiled
-- rows. A release published before this schema, or by an older binary, has
-- no row: the next publication then records that its baseline is unknown.
--
-- The row is written in the publishing transaction, right after the release,
-- and never changes. Rollback: older binaries neither read nor write it.

CREATE TABLE mesh.policy_release_rule_fingerprint (
    policy_release_id BIGINT PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    rule_count INTEGER NOT NULL CHECK (rule_count BETWEEN 0 AND 10000),
    fingerprints BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT policy_release_rule_fingerprint_shape_check CHECK (
        pg_catalog.octet_length(fingerprints) = 5 + rule_count * 49
        AND pg_catalog.get_byte(fingerprints, 0) = 1
    ),
    CONSTRAINT policy_release_rule_fingerprint_release_fk FOREIGN KEY (
        workspace_id, network_id, policy_release_id, policy_revision
    ) REFERENCES mesh.policy_release (workspace_id, network_id, id, policy_revision) ON DELETE RESTRICT
);

CREATE TRIGGER policy_release_rule_fingerprint_immutable
BEFORE UPDATE OR DELETE ON mesh.policy_release_rule_fingerprint
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();

ALTER TABLE mesh.policy_release_rule_fingerprint ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.policy_release_rule_fingerprint FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_release_rule_fingerprint_migrator_policy ON mesh.policy_release_rule_fingerprint
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.policy_release_rule_fingerprint
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Stores the fingerprints of the release published in this transaction and
-- returns its rule count. The encoding is checked here only for its frame
-- (format byte, count, length); Core checks the entries.
CREATE FUNCTION mesh_ops.record_policy_release_rule_fingerprints_v1(
    p_release_public_id UUID, p_fingerprints BYTEA
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_release mesh.policy_release%ROWTYPE;
    v_count BIGINT;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL OR p_fingerprints IS NULL
        OR pg_catalog.octet_length(p_fingerprints) NOT BETWEEN 5 AND 5 + 10000 * 49
        OR pg_catalog.get_byte(p_fingerprints, 0) <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy rule fingerprints are invalid';
    END IF;
    v_count := (pg_catalog.get_byte(p_fingerprints, 1)::BIGINT << 24)
        | (pg_catalog.get_byte(p_fingerprints, 2)::BIGINT << 16)
        | (pg_catalog.get_byte(p_fingerprints, 3)::BIGINT << 8)
        | pg_catalog.get_byte(p_fingerprints, 4)::BIGINT;
    IF v_count > 10000 OR pg_catalog.octet_length(p_fingerprints) <> 5 + v_count * 49 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy rule fingerprints are invalid';
    END IF;
    SELECT * INTO v_release FROM mesh.policy_release AS release
    WHERE release.workspace_id = v_workspace AND release.network_id = v_network
      AND release.public_id = p_release_public_id AND release.state = 'active'
      AND EXISTS (
          SELECT 1 FROM mesh_audit.authority_mutation AS mutation
          WHERE mutation.aggregate_kind = 'policy_release' AND mutation.operation = 'insert'
            AND mutation.row_public_id = p_release_public_id
            AND mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy rule fingerprints need the release published now';
    END IF;
    INSERT INTO mesh.policy_release_rule_fingerprint (
        policy_release_id, workspace_id, network_id, policy_revision, rule_count, fingerprints, created_at
    ) VALUES (
        v_release.id, v_workspace, v_network, v_release.policy_revision, v_count::INTEGER, p_fingerprints,
        pg_catalog.transaction_timestamp()
    );
    RETURN v_count::INTEGER;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.record_policy_release_rule_fingerprints_v1(UUID, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_policy_release_rule_fingerprints_v1(UUID, BYTEA) TO mesh_runtime;

-- Returns the fingerprints of one release of the transaction's Network, or
-- NULL when it has none.
CREATE FUNCTION mesh_ops.read_policy_release_rule_fingerprints_v1(p_release_public_id UUID)
RETURNS BYTEA
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_fingerprints BYTEA;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy release is invalid';
    END IF;
    SELECT fingerprint.fingerprints INTO v_fingerprints
    FROM mesh.policy_release AS release
    JOIN mesh.policy_release_rule_fingerprint AS fingerprint
      ON fingerprint.policy_release_id = release.id
     AND fingerprint.workspace_id = release.workspace_id
     AND fingerprint.network_id = release.network_id
    WHERE release.workspace_id = v_workspace AND release.network_id = v_network
      AND release.public_id = p_release_public_id;
    RETURN v_fingerprints;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_policy_release_rule_fingerprints_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_release_rule_fingerprints_v1(UUID) TO mesh_runtime;
