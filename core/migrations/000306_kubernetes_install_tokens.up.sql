-- Schema 306 (V1-12 step 1a, docs k8s-v1-12-install-token-design.md v4.1):
-- the records a one-command gateway install needs. Functions come in later
-- schemas; nothing here changes what an existing cluster does.
--
-- * A cluster says how it trusts its ServiceAccount token issuer
--   (trust_mode): 'code' (the K1 way, every existing cluster), or
--   'private_tofu': the first replica with a preapproved install token pins
--   its signing material, unconfirmed until an administrator confirms its
--   digest. 'issuer' (Core fetches the public issuer's keys) comes with
--   step 3; the value is allowed so a later schema adds no CHECK change.
-- * A signing trust gets a state and a digest: one SHA-256 over the
--   canonical tuple (issuer, canonical kube-sa-trust/v1 JWKS sorted by
--   key ID, namespace, ServiceAccount, StatefulSet), computed in Go
--   (kubejoin.ClusterTrustDigest). Existing trusts
--   are confirmed and keep a NULL digest; an install-token trust always has
--   one. A contested trust keeps the other side's digest and material, so
--   an administrator can choose.
-- * A join key (an enrollment credential of the cluster's profile) may be
--   preapproved: the extension row names who made it (the named approver of
--   every replica it approves, checked again at each approval) and how
--   many replicas it covers. Uses are per ordinal: one replica name uses a
--   token at most once.
--
-- Every new table follows the cluster tables: RLS forced, only the
-- migrator's policy, nothing granted to runtime roles (functions only),
-- a version for the authority journal and its triggers.

ALTER TABLE mesh.kubernetes_cluster
    ADD COLUMN trust_mode TEXT NOT NULL DEFAULT 'code'
        CONSTRAINT kubernetes_cluster_trust_mode_check CHECK (trust_mode IN ('code', 'private_tofu', 'issuer'));

ALTER TABLE mesh.kubernetes_cluster_signing_trust
    DROP CONSTRAINT kubernetes_cluster_signing_trust_source_check,
    DROP CONSTRAINT kubernetes_cluster_signing_trust_source_request_check,
    ADD COLUMN state TEXT NOT NULL DEFAULT 'confirmed',
    ADD COLUMN digest BYTEA,
    ADD COLUMN confirmed_by_principal_id BIGINT,
    ADD COLUMN confirmed_at TIMESTAMPTZ,
    ADD COLUMN contested_digest BYTEA,
    ADD COLUMN contested_issuer TEXT,
    ADD COLUMN contested_jwks BYTEA,
    ADD COLUMN contested_key_thumbprints BYTEA[],
    ADD COLUMN contested_namespace TEXT,
    ADD COLUMN contested_service_account TEXT,
    ADD COLUMN contested_statefulset TEXT,
    ADD COLUMN contested_request_id BIGINT,
    ADD COLUMN contested_at TIMESTAMPTZ,
    ADD CONSTRAINT kubernetes_cluster_signing_trust_source_check
        CHECK (source IN ('replica_approval', 'admin_paste', 'install_token')),
    ADD CONSTRAINT kubernetes_cluster_signing_trust_source_request_check
        CHECK ((source IN ('replica_approval', 'install_token')) = (source_request_id IS NOT NULL)),
    ADD CONSTRAINT kubernetes_cluster_signing_trust_state_check
        CHECK (state IN ('confirmed', 'unconfirmed', 'contested')),
    -- Only a trust pinned from an install token is ever unconfirmed or
    -- contested, and it always carries its digest.
    -- An older writer (approval by code, admin paste) that met an
    -- install-token trust fails here loudly instead of keeping a stale digest
    -- or confirmer: those functions are gated before any cluster can be
    -- private_tofu (step 1c).
    ADD CONSTRAINT kubernetes_cluster_signing_trust_install_token_check CHECK (
        (state = 'confirmed' OR source = 'install_token')
        AND (source = 'install_token') = (digest IS NOT NULL)
        AND (source = 'install_token' OR confirmed_by_principal_id IS NULL)
    ),
    ADD CONSTRAINT kubernetes_cluster_signing_trust_digest_check
        CHECK (digest IS NULL OR pg_catalog.octet_length(digest) = 32),
    -- An install-token trust is confirmed by a named administrator.
    ADD CONSTRAINT kubernetes_cluster_signing_trust_confirmed_check CHECK (
        (confirmed_by_principal_id IS NULL) = (confirmed_at IS NULL)
        AND (source <> 'install_token' OR (state = 'confirmed') = (confirmed_at IS NOT NULL))
    ),
    ADD CONSTRAINT kubernetes_cluster_signing_trust_contested_check CHECK (
        (state = 'contested') = (contested_digest IS NOT NULL)
        AND (contested_digest IS NULL) = (contested_issuer IS NULL)
        AND (contested_digest IS NULL) = (contested_jwks IS NULL)
        AND (contested_digest IS NULL) = (contested_key_thumbprints IS NULL)
        AND (contested_digest IS NULL) = (contested_namespace IS NULL)
        AND (contested_digest IS NULL) = (contested_service_account IS NULL)
        AND (contested_digest IS NULL) = (contested_statefulset IS NULL)
        AND (contested_digest IS NULL) = (contested_request_id IS NULL)
        AND (contested_digest IS NULL) = (contested_at IS NULL)
    ),
    ADD CONSTRAINT kubernetes_cluster_signing_trust_contested_material_check CHECK (
        contested_digest IS NULL OR (
            pg_catalog.octet_length(contested_digest) = 32 AND contested_digest <> digest
            AND mesh_ops.kubernetes_issuer_is_valid_v1(contested_issuer)
            AND pg_catalog.octet_length(contested_jwks) BETWEEN 2 AND 16384
            AND mesh_ops.kubernetes_thumbprints_are_valid_v1(contested_key_thumbprints)
            AND mesh_ops.kubernetes_namespace_is_valid_v1(contested_namespace)
            AND mesh_ops.kubernetes_name_is_valid_v1(contested_service_account)
            AND mesh_ops.kubernetes_name_is_valid_v1(contested_statefulset)
        )
    ),
    ADD CONSTRAINT kubernetes_cluster_signing_trust_confirmer_fk FOREIGN KEY (confirmed_by_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    ADD CONSTRAINT kubernetes_cluster_signing_trust_contested_request_fk
        FOREIGN KEY (workspace_id, network_id, contested_request_id)
        REFERENCES mesh.kubernetes_replica_request (workspace_id, network_id, id) ON DELETE RESTRICT;

-- A preapproved join key (an install token): the extension of one
-- enrollment credential of a cluster's gateway profile.
CREATE TABLE mesh.kubernetes_join_key_preapproval (
    enrollment_credential_id BIGINT PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    -- The cluster is the credential's: its enrollment profile names it, so
    -- it is never stored twice.
    -- The named approver of every replica the token approves; their rights
    -- are checked again at each approval.
    created_by_principal_id BIGINT NOT NULL,
    replicas SMALLINT NOT NULL CHECK (replicas BETWEEN 1 AND 5),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT kubernetes_join_key_preapproval_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_join_key_preapproval_credential_fk FOREIGN KEY (workspace_id, network_id, enrollment_credential_id)
        REFERENCES mesh.enrollment_credential (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_join_key_preapproval_creator_fk FOREIGN KEY (created_by_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, enrollment_credential_id)
);

-- One use of a preapproved token per replica name (ordinal): a replica that
-- comes back with the same pod UID before its request completes replaces
-- that request instead of spending another use.
CREATE TABLE mesh.kubernetes_join_key_ordinal_use (
    enrollment_credential_id BIGINT NOT NULL,
    ordinal SMALLINT NOT NULL CHECK (ordinal BETWEEN 0 AND 4),
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    pod_uid UUID NOT NULL,
    replica_request_id BIGINT NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    used_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (enrollment_credential_id, ordinal),
    CONSTRAINT kubernetes_join_key_ordinal_use_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_join_key_ordinal_use_preapproval_fk FOREIGN KEY (workspace_id, network_id, enrollment_credential_id)
        REFERENCES mesh.kubernetes_join_key_preapproval (workspace_id, network_id, enrollment_credential_id)
        ON DELETE RESTRICT,
    CONSTRAINT kubernetes_join_key_ordinal_use_request_fk FOREIGN KEY (workspace_id, network_id, replica_request_id)
        REFERENCES mesh.kubernetes_replica_request (workspace_id, network_id, id) ON DELETE RESTRICT
);

ALTER TABLE mesh.kubernetes_join_key_preapproval ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_join_key_preapproval FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_join_key_preapproval_migrator_policy ON mesh.kubernetes_join_key_preapproval
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_join_key_preapproval
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER kubernetes_join_key_preapproval_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.kubernetes_join_key_preapproval
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_join_key_preapproval', 'public_id');

ALTER TABLE mesh.kubernetes_join_key_ordinal_use ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_join_key_ordinal_use FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_join_key_ordinal_use_migrator_policy ON mesh.kubernetes_join_key_ordinal_use
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_join_key_ordinal_use
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER kubernetes_join_key_ordinal_use_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.kubernetes_join_key_ordinal_use
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_join_key_ordinal_use', 'public_id');
