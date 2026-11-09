-- Network summaries computed ahead of reads (docs/console-load-design.md §5,
-- TD-CON-43/48, step C3).
--
-- The Console's Workspace Overview and Networks list read six resources for
-- every Network (97 requests for 16 Networks). A summary row per Network,
-- kept current by the worker, lets one read answer a page of Networks.
-- Counting at read time is not bounded: address usage counts every lease of
-- a Network. Counting at write time is not enough: Devices, held addresses,
-- offers, approvals and contracts change with time, with no write.
--
-- Writers never lock a summary row. Their triggers only append to
-- network_summary_mark, which takes no row lock, so a writer's lock order is
-- unchanged and no new deadlock is possible (Opus review of C3, B1). The
-- worker folds the marks into network_summary_queue, one row per Network:
--   - dirty_generation rises by the marks folded in, computed_generation is
--     the generation the stored summary reflects;
--   - recompute_at is the next instant a figure changes with time;
--   - not_before spaces recomputes of one Network (adaptive, in the worker);
--   - claimed_until and claimed_by keep two workers off one Network.
-- Rows are never deleted or reset: the stored marker only moves forward.
--
-- Every function here is SECURITY DEFINER and owned by mesh_migrator, which
-- reads across Workspaces only while mesh.network_summary_scan is on; the
-- functions set it and clear it before returning. Only mesh_worker may call
-- them. Console reads of the summaries come in step C4.

CREATE TABLE mesh_ops.network_summary_queue (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    dirty_generation BIGINT NOT NULL DEFAULT 1 CHECK (dirty_generation > 0),
    computed_generation BIGINT NOT NULL DEFAULT 0 CHECK (computed_generation >= 0),
    -- When the row last went from current to dirty, for the lag metric.
    dirty_since TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    not_before TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
    recompute_at TIMESTAMPTZ,
    claimed_until TIMESTAMPTZ,
    claimed_by UUID,
    last_compute_ms INTEGER NOT NULL DEFAULT 0 CHECK (last_compute_ms >= 0),
    PRIMARY KEY (workspace_id, network_id),
    CONSTRAINT network_summary_queue_generation_check CHECK (computed_generation <= dirty_generation),
    CONSTRAINT network_summary_queue_claim_check CHECK ((claimed_until IS NULL) = (claimed_by IS NULL)),
    CONSTRAINT network_summary_queue_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);

-- Claims read one of these two indexes each: never the whole queue.
CREATE INDEX network_summary_queue_dirty_idx
    ON mesh_ops.network_summary_queue (not_before)
    WHERE dirty_generation > computed_generation;
CREATE INDEX network_summary_queue_recompute_idx
    ON mesh_ops.network_summary_queue (recompute_at)
    WHERE recompute_at IS NOT NULL;

-- Append-only change marks. No foreign key: a key check would take a lock
-- on the Network row inside the writer's transaction.
CREATE TABLE mesh_ops.network_summary_mark (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    marked_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

-- Both tables churn: vacuum them by row count, not by table share.
ALTER TABLE mesh_ops.network_summary_mark SET (autovacuum_vacuum_scale_factor = 0, autovacuum_vacuum_threshold = 1000);
ALTER TABLE mesh_ops.network_summary_queue SET (autovacuum_vacuum_scale_factor = 0, autovacuum_vacuum_threshold = 1000);

-- Counting active Devices and their next expiry reads only active Devices.
CREATE INDEX device_network_active_expiry_idx ON mesh.device (workspace_id, network_id, expires_at)
    WHERE state = 'active';

CREATE TABLE mesh_ops.network_summary (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    -- The marker: what the counts reflect, read in the same snapshot.
    network_revision BIGINT NOT NULL CHECK (network_revision > 0),
    dirty_generation BIGINT NOT NULL CHECK (dirty_generation > 0),
    evaluated_at TIMESTAMPTZ NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL,
    ipv4_prefix CIDR,
    addresses_capacity BIGINT CHECK (addresses_capacity >= 0),
    addresses_in_use BIGINT NOT NULL CHECK (addresses_in_use >= 0),
    addresses_held BIGINT NOT NULL CHECK (addresses_held >= 0),
    active_devices BIGINT NOT NULL CHECK (active_devices >= 0),
    rule_count BIGINT NOT NULL CHECK (rule_count >= 0),
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    policy_published_at TIMESTAMPTZ,
    shares_out_active INTEGER NOT NULL CHECK (shares_out_active >= 0),
    shares_in_active INTEGER NOT NULL CHECK (shares_in_active >= 0),
    offers_waiting INTEGER NOT NULL CHECK (offers_waiting >= 0),
    pending_approvals INTEGER NOT NULL CHECK (pending_approvals >= 0),
    sites INTEGER NOT NULL CHECK (sites >= 0),
    kubernetes_clusters INTEGER NOT NULL CHECK (kubernetes_clusters >= 0),
    PRIMARY KEY (workspace_id, network_id),
    CONSTRAINT network_summary_ipv4_check CHECK (
        (ipv4_prefix IS NULL AND addresses_capacity IS NULL)
        OR (pg_catalog.family(ipv4_prefix) = 4 AND addresses_capacity IS NOT NULL)
    ),
    CONSTRAINT network_summary_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);

-- Shares of one Network with each other side, for the Workspace trust
-- links. The other side is a Network of the same Workspace, or another
-- Workspace as a whole: never a Network of another Workspace.
CREATE TABLE mesh_ops.network_summary_peer (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('outgoing', 'incoming')),
    peer_workspace_id BIGINT NOT NULL,
    -- 0 when the peer is another Workspace: a key column cannot be NULL.
    peer_network_id BIGINT NOT NULL,
    active INTEGER NOT NULL CHECK (active >= 0),
    waiting INTEGER NOT NULL CHECK (waiting >= 0),
    PRIMARY KEY (workspace_id, network_id, direction, peer_workspace_id, peer_network_id),
    CONSTRAINT network_summary_peer_shape_check CHECK (
        (peer_workspace_id = workspace_id AND peer_network_id > 0 AND peer_network_id <> network_id)
        OR (peer_workspace_id <> workspace_id AND peer_network_id = 0)
    ),
    CONSTRAINT network_summary_peer_counts_check CHECK (active + waiting > 0),
    CONSTRAINT network_summary_peer_summary_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh_ops.network_summary (workspace_id, network_id) ON DELETE RESTRICT
);

ALTER TABLE mesh_ops.network_summary_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.network_summary_queue FORCE ROW LEVEL SECURITY;
CREATE POLICY network_summary_queue_migrator_policy ON mesh_ops.network_summary_queue
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.network_summary_mark ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.network_summary_mark FORCE ROW LEVEL SECURITY;
CREATE POLICY network_summary_mark_migrator_policy ON mesh_ops.network_summary_mark
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.network_summary ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.network_summary FORCE ROW LEVEL SECURITY;
CREATE POLICY network_summary_migrator_policy ON mesh_ops.network_summary
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.network_summary_peer ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.network_summary_peer FORCE ROW LEVEL SECURITY;
CREATE POLICY network_summary_peer_migrator_policy ON mesh_ops.network_summary_peer
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.network_summary_queue, mesh_ops.network_summary_mark, mesh_ops.network_summary,
    mesh_ops.network_summary_peer FROM PUBLIC;

-- The worker discovers and counts across the installation. These rows are
-- readable by the function owner only while mesh.network_summary_scan is on,
-- and only in a session of the worker or of the migration (any role can set
-- a custom setting; no role can change its session user).
CREATE POLICY workspace_network_summary_scan ON mesh.workspace
    FOR SELECT TO mesh_migrator
    USING (pg_catalog.current_setting('mesh.network_summary_scan', TRUE) = 'on'
        AND (pg_catalog.pg_has_role(SESSION_USER, 'mesh_worker', 'MEMBER')
             OR pg_catalog.pg_has_role(SESSION_USER, 'mesh_migrator', 'MEMBER')));
CREATE POLICY network_network_summary_scan ON mesh.network
    FOR SELECT TO mesh_migrator
    USING (pg_catalog.current_setting('mesh.network_summary_scan', TRUE) = 'on'
        AND (pg_catalog.pg_has_role(SESSION_USER, 'mesh_worker', 'MEMBER')
             OR pg_catalog.pg_has_role(SESSION_USER, 'mesh_migrator', 'MEMBER')));
CREATE POLICY network_revision_network_summary_scan ON mesh_ops.network_revision
    FOR SELECT TO mesh_migrator
    USING (pg_catalog.current_setting('mesh.network_summary_scan', TRUE) = 'on'
        AND (pg_catalog.pg_has_role(SESSION_USER, 'mesh_worker', 'MEMBER')
             OR pg_catalog.pg_has_role(SESSION_USER, 'mesh_migrator', 'MEMBER')));
CREATE POLICY network_prefix_network_summary_scan ON mesh.network_prefix
    FOR SELECT TO mesh_migrator
    USING (pg_catalog.current_setting('mesh.network_summary_scan', TRUE) = 'on'
        AND (pg_catalog.pg_has_role(SESSION_USER, 'mesh_worker', 'MEMBER')
             OR pg_catalog.pg_has_role(SESSION_USER, 'mesh_migrator', 'MEMBER')));

-- Every change of a Network's map advances its revision: Devices, leases,
-- policy, sharing, Sites and more. Creating a Network inserts the row.
CREATE FUNCTION mesh_ops.network_summary_revision_trigger_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.network_revision <> OLD.network_revision THEN
        INSERT INTO mesh_ops.network_summary_mark (workspace_id, network_id)
        VALUES (NEW.workspace_id, NEW.network_id);
    END IF;
    RETURN NULL;
END;
$function$;

CREATE TRIGGER network_summary_revision_dirty
AFTER INSERT OR UPDATE OF network_revision ON mesh_ops.network_revision
FOR EACH ROW EXECUTE FUNCTION mesh_ops.network_summary_revision_trigger_v1();

-- A share changes both sides: the provider's and the consumer's Network,
-- in another Workspace too.
CREATE FUNCTION mesh_ops.network_summary_share_trigger_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
DECLARE
    v_row RECORD;
BEGIN
    IF TG_OP = 'DELETE' THEN v_row := OLD; ELSE v_row := NEW; END IF;
    IF TG_OP = 'UPDATE' AND NEW.state IS NOT DISTINCT FROM OLD.state
       AND NEW.expires_at IS NOT DISTINCT FROM OLD.expires_at THEN
        RETURN NULL;
    END IF;
    INSERT INTO mesh_ops.network_summary_mark (workspace_id, network_id)
    VALUES (v_row.provider_workspace_id, v_row.provider_network_id),
           (v_row.consumer_workspace_id, v_row.consumer_network_id);
    RETURN NULL;
END;
$function$;

CREATE TRIGGER network_summary_share_offer_dirty
AFTER INSERT OR DELETE OR UPDATE OF state, expires_at ON mesh.share_offer
FOR EACH ROW EXECUTE FUNCTION mesh_ops.network_summary_share_trigger_v1();
CREATE TRIGGER network_summary_trust_contract_dirty
AFTER INSERT OR DELETE OR UPDATE OF state, expires_at ON mesh.trust_contract
FOR EACH ROW EXECUTE FUNCTION mesh_ops.network_summary_share_trigger_v1();

-- Approvals, Sites and clusters belong to one Network.
CREATE FUNCTION mesh_ops.network_summary_scoped_trigger_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
DECLARE
    v_row RECORD;
BEGIN
    IF TG_OP = 'DELETE' THEN v_row := OLD; ELSE v_row := NEW; END IF;
    IF TG_OP = 'UPDATE' AND NEW.state IS NOT DISTINCT FROM OLD.state THEN
        RETURN NULL;
    END IF;
    INSERT INTO mesh_ops.network_summary_mark (workspace_id, network_id)
    VALUES (v_row.workspace_id, v_row.network_id);
    RETURN NULL;
END;
$function$;

CREATE TRIGGER network_summary_policy_approval_dirty
AFTER INSERT OR DELETE OR UPDATE OF state ON mesh.policy_approval_request
FOR EACH ROW EXECUTE FUNCTION mesh_ops.network_summary_scoped_trigger_v1();
CREATE TRIGGER network_summary_site_dirty
AFTER INSERT OR DELETE OR UPDATE OF state ON mesh.network_site
FOR EACH ROW EXECUTE FUNCTION mesh_ops.network_summary_scoped_trigger_v1();
CREATE TRIGGER network_summary_kubernetes_cluster_dirty
AFTER INSERT OR DELETE OR UPDATE OF state ON mesh.kubernetes_cluster
FOR EACH ROW EXECUTE FUNCTION mesh_ops.network_summary_scoped_trigger_v1();

-- Folds up to p_limit change marks into the queue, oldest first, and says
-- how many it folded. The summary worker folds before each claim, in a
-- transaction of its own; the retention maintainer, which always runs on
-- the worker role, folds too, so marks never pile up while the summary
-- worker is off (Opus review of C3, M-A). One fold runs at a time (a
-- transaction advisory lock; the others fold nothing), so two folds never
-- lock queue rows in different orders.
CREATE FUNCTION mesh_ops.fold_network_summary_marks_v1(p_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
DECLARE
    v_folded INTEGER;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 50000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid network summary fold';
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock(
        pg_catalog.hashtextextended('meshtransit/network-summary-fold', 0)) THEN
        RETURN 0;
    END IF;
    WITH taken AS (
        DELETE FROM mesh_ops.network_summary_mark
        WHERE id IN (SELECT mark.id FROM mesh_ops.network_summary_mark AS mark ORDER BY mark.id LIMIT p_limit)
        RETURNING workspace_id, network_id, marked_at
    ), grouped AS (
        SELECT taken.workspace_id, taken.network_id, pg_catalog.count(*) AS marks,
            pg_catalog.min(taken.marked_at) AS first_marked
        FROM taken GROUP BY taken.workspace_id, taken.network_id
    ), folded AS (
        INSERT INTO mesh_ops.network_summary_queue AS queue (workspace_id, network_id, dirty_generation, dirty_since)
        SELECT grouped.workspace_id, grouped.network_id, grouped.marks, grouped.first_marked
        FROM grouped ORDER BY grouped.workspace_id, grouped.network_id
        ON CONFLICT (workspace_id, network_id) DO UPDATE SET
            dirty_generation = queue.dirty_generation + EXCLUDED.dirty_generation,
            dirty_since = CASE WHEN queue.dirty_generation = queue.computed_generation
                THEN EXCLUDED.dirty_since ELSE queue.dirty_since END
        RETURNING 1
    )
    -- The INSERT runs whether or not it is read (a data-modifying WITH).
    SELECT COALESCE(pg_catalog.sum(grouped.marks), 0)::INTEGER INTO v_folded FROM grouped;
    RETURN v_folded;
END;
$function$;

-- Claims up to p_limit Networks for p_lease_seconds: first those changed and
-- past their spacing, then those a figure of which changes with time now.
-- Each claim commits at once; the queue row is never held while counting.
CREATE FUNCTION mesh_ops.claim_network_summary_work_v1(
    p_deployment_public_id UUID, p_worker UUID, p_limit INTEGER, p_lease_seconds INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_claimed JSONB := '[]'::JSONB;
    v_row RECORD;
    v_count INTEGER := 0;
BEGIN
    IF p_deployment_public_id IS NULL OR p_worker IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 64
       OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid network summary claim';
    END IF;
    PERFORM pg_catalog.set_config('mesh.network_summary_scan', 'on', TRUE);
    FOR v_row IN
        SELECT queue.workspace_id, queue.network_id FROM mesh_ops.network_summary_queue AS queue
        JOIN mesh.workspace AS workspace ON workspace.id = queue.workspace_id
        JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
        WHERE queue.dirty_generation > queue.computed_generation AND queue.not_before <= v_now
          AND (queue.claimed_until IS NULL OR queue.claimed_until <= v_now)
          AND deployment.installation_public_id = p_deployment_public_id
        ORDER BY queue.not_before
        LIMIT p_limit
        FOR UPDATE OF queue SKIP LOCKED
    LOOP
        UPDATE mesh_ops.network_summary_queue
        SET claimed_until = v_now + pg_catalog.make_interval(secs => p_lease_seconds), claimed_by = p_worker
        WHERE workspace_id = v_row.workspace_id AND network_id = v_row.network_id;
        v_claimed := v_claimed || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_array(v_row.workspace_id, v_row.network_id));
        v_count := v_count + 1;
    END LOOP;
    IF v_count < p_limit THEN
        FOR v_row IN
            SELECT queue.workspace_id, queue.network_id FROM mesh_ops.network_summary_queue AS queue
            JOIN mesh.workspace AS workspace ON workspace.id = queue.workspace_id
            JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
            WHERE queue.recompute_at <= v_now AND queue.not_before <= v_now
              AND queue.dirty_generation = queue.computed_generation
              AND (queue.claimed_until IS NULL OR queue.claimed_until <= v_now)
              AND deployment.installation_public_id = p_deployment_public_id
            ORDER BY queue.recompute_at
            LIMIT p_limit - v_count
            FOR UPDATE OF queue SKIP LOCKED
        LOOP
            UPDATE mesh_ops.network_summary_queue
            SET claimed_until = v_now + pg_catalog.make_interval(secs => p_lease_seconds), claimed_by = p_worker
            WHERE workspace_id = v_row.workspace_id AND network_id = v_row.network_id;
            v_claimed := v_claimed || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_array(v_row.workspace_id, v_row.network_id));
        END LOOP;
    END IF;
    -- A deleted Network has nothing to count: its row is settled, so it
    -- drops out of both claim indexes.
    UPDATE mesh_ops.network_summary_queue AS queue SET
        computed_generation = queue.dirty_generation, recompute_at = NULL,
        claimed_until = NULL, claimed_by = NULL
    FROM pg_catalog.jsonb_array_elements(v_claimed) AS item
    JOIN mesh.network AS network
      ON network.workspace_id = (item ->> 0)::BIGINT AND network.id = (item ->> 1)::BIGINT
    WHERE network.state = 'deleted'
      AND queue.workspace_id = network.workspace_id AND queue.network_id = network.id;
    -- Public identifiers only leave this function, of this installation's
    -- live Networks.
    SELECT pg_catalog.jsonb_build_object('items', COALESCE(pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object('workspace_id', workspace.public_id, 'network_id', network.public_id)
        ORDER BY network.id), '[]'::JSONB))
    INTO v_claimed
    FROM pg_catalog.jsonb_array_elements(v_claimed) AS item
    JOIN mesh.network AS network
      ON network.workspace_id = (item ->> 0)::BIGINT AND network.id = (item ->> 1)::BIGINT
    JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id AND network.state <> 'deleted';
    PERFORM pg_catalog.set_config('mesh.network_summary_scan', '', TRUE);
    RETURN v_claimed;
END;
$function$;

-- Counts one Network as of this transaction's snapshot. The worker calls it
-- first in a REPEATABLE READ READ ONLY transaction, so the marker and every
-- count come from one snapshot. It writes nothing.
CREATE FUNCTION mesh_ops.compute_network_summary_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_workspace BIGINT;
    v_network BIGINT;
    v_revision BIGINT;
    v_policy_revision BIGINT;
    v_generation BIGINT;
    v_release BIGINT;
    v_published TIMESTAMPTZ;
    v_rules BIGINT := 0;
    v_prefix_id BIGINT;
    v_prefix CIDR;
    v_in_use BIGINT := 0;
    v_held BIGINT := 0;
    v_active BIGINT;
    v_next TIMESTAMPTZ;
    v_candidate TIMESTAMPTZ;
    v_shares_out INTEGER;
    v_shares_in INTEGER;
    v_offers INTEGER;
    v_approvals INTEGER;
    v_sites INTEGER;
    v_clusters INTEGER;
    v_peers JSONB;
BEGIN
    IF p_deployment_public_id IS NULL OR p_workspace_public_id IS NULL OR p_network_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid network summary input';
    END IF;
    PERFORM pg_catalog.set_config('mesh.network_summary_scan', 'on', TRUE);
    -- The marker first: everything below reflects at least this.
    SELECT network.workspace_id, network.id, revision.network_revision, revision.policy_revision
    INTO v_workspace, v_network, v_revision, v_policy_revision
    FROM mesh.network AS network
    JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    JOIN mesh_ops.network_revision AS revision
      ON revision.workspace_id = network.workspace_id AND revision.network_id = network.id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND network.state <> 'deleted';
    IF NOT FOUND THEN
        PERFORM pg_catalog.set_config('mesh.network_summary_scan', '', TRUE);
        RETURN NULL;
    END IF;
    SELECT queue.dirty_generation INTO v_generation FROM mesh_ops.network_summary_queue AS queue
    WHERE queue.workspace_id = v_workspace AND queue.network_id = v_network;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'network summary queue row is missing';
    END IF;

    -- Addresses of the IPv4 range, as read_network_address_usage_v1 counts them.
    SELECT prefix.id, prefix.prefix INTO v_prefix_id, v_prefix
    FROM mesh.network_prefix AS prefix
    WHERE prefix.workspace_id = v_workspace AND prefix.network_id = v_network AND prefix.family = 4
      AND prefix.state = 'active' AND prefix.deleted_at IS NULL
    ORDER BY prefix.prefix LIMIT 1;
    IF v_prefix_id IS NOT NULL THEN
        SELECT
            pg_catalog.count(*) FILTER (WHERE held.kind = 'in_use'),
            pg_catalog.count(*) FILTER (WHERE held.kind IN ('expired', 'revoked')),
            pg_catalog.min(held.changes_at) FILTER (WHERE held.changes_at > v_now)
        INTO v_in_use, v_held, v_next
        FROM (
            SELECT
                CASE
                    WHEN lease.state = 'quarantined' THEN
                        CASE WHEN lease.quarantine_until > v_now THEN 'revoked' END
                    WHEN device.state = 'revoked' THEN
                        CASE WHEN device.updated_at + mesh_ops.node_address_quarantine_v1() > v_now THEN 'revoked' END
                    WHEN device.expires_at > v_now THEN 'in_use'
                    ELSE 'expired'
                END AS kind,
                -- The next instant this lease moves to another kind.
                CASE
                    WHEN lease.state = 'quarantined' THEN lease.quarantine_until
                    WHEN device.state = 'revoked' THEN device.updated_at + mesh_ops.node_address_quarantine_v1()
                    ELSE device.expires_at
                END AS changes_at
            FROM mesh.node_address_lease AS lease
            JOIN mesh.device AS device
              ON device.workspace_id = lease.workspace_id AND device.network_id = lease.network_id
             AND device.id = lease.device_id
            WHERE lease.workspace_id = v_workspace AND lease.network_id = v_network
              AND lease.network_prefix_id = v_prefix_id AND lease.state IN ('active', 'quarantined')
        ) AS held;
    END IF;

    -- Devices that can connect now, as the Device list's "active" filter.
    SELECT pg_catalog.count(*), pg_catalog.min(device.expires_at)
    INTO v_active, v_candidate
    FROM mesh.device AS device
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.state = 'active' AND device.expires_at > v_now;
    v_next := LEAST(v_next, v_candidate);

    -- Rules of the active release, as read_active_policy_v4 counts them.
    SELECT release.id, release.activated_at INTO v_release, v_published
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = v_workspace AND release.network_id = v_network
      AND release.policy_revision = v_policy_revision AND release.state = 'active';
    IF v_release IS NOT NULL THEN
        SELECT
            (SELECT pg_catalog.count(*) FROM mesh.compiled_policy_rule AS rule
             WHERE rule.workspace_id = v_workspace AND rule.network_id = v_network
               AND rule.policy_release_id = v_release AND rule.policy_revision = v_policy_revision)
          + (SELECT pg_catalog.count(*) FROM mesh.compiled_policy_imported_resource_destination AS rule
             WHERE rule.workspace_id = v_workspace AND rule.network_id = v_network
               AND rule.policy_release_id = v_release AND rule.policy_revision = v_policy_revision)
          + (SELECT pg_catalog.count(*) FROM mesh.compiled_policy_group_rule AS rule
             WHERE rule.workspace_id = v_workspace AND rule.network_id = v_network
               AND rule.policy_release_id = v_release AND rule.policy_revision = v_policy_revision)
          + (SELECT pg_catalog.count(*) FROM mesh.compiled_policy_route_rule AS rule
             WHERE rule.workspace_id = v_workspace AND rule.network_id = v_network
               AND rule.policy_release_id = v_release AND rule.policy_revision = v_policy_revision)
          + (SELECT pg_catalog.count(*) FROM mesh.compiled_policy_exit_rule AS rule
             WHERE rule.workspace_id = v_workspace AND rule.network_id = v_network
               AND rule.policy_release_id = v_release AND rule.policy_revision = v_policy_revision)
        INTO v_rules;
    END IF;

    -- Shares through this Network's locators: live contracts each way, and
    -- offers to it that wait for a decision.
    WITH share AS (
        SELECT locator.direction,
            CASE WHEN locator.direction = 'outgoing' THEN offer.consumer_workspace_id
                 ELSE offer.provider_workspace_id END AS peer_workspace_id,
            CASE WHEN locator.direction = 'outgoing' THEN offer.consumer_network_id
                 ELSE offer.provider_network_id END AS peer_network_id,
            (offer.state = 'accepted' AND contract.state IN ('activating', 'active')
                AND contract.expires_at > v_now) AS live,
            (offer.state = 'offered' AND offer.expires_at > v_now) AS waiting,
            CASE WHEN offer.state = 'offered' AND offer.expires_at > v_now THEN offer.expires_at
                 WHEN offer.state = 'accepted' AND contract.state IN ('activating', 'active')
                      AND contract.expires_at > v_now THEN contract.expires_at END AS changes_at
        FROM mesh.share_offer_locator AS locator
        JOIN mesh.share_offer AS offer ON offer.id = locator.offer_id
        LEFT JOIN mesh.trust_contract AS contract ON contract.share_offer_id = offer.id
        WHERE locator.local_workspace_id = v_workspace AND locator.local_network_id = v_network
          AND locator.state IN ('offered', 'accepted') AND offer.state IN ('offered', 'accepted')
    ), peer AS (
        SELECT share.direction, share.peer_workspace_id,
            CASE WHEN share.peer_workspace_id = v_workspace THEN share.peer_network_id ELSE 0 END AS peer_network_id,
            pg_catalog.count(*) FILTER (WHERE share.live)::INTEGER AS active,
            pg_catalog.count(*) FILTER (WHERE share.waiting)::INTEGER AS waiting
        FROM share
        GROUP BY 1, 2, 3
        HAVING pg_catalog.count(*) FILTER (WHERE share.live OR share.waiting) > 0
    )
    SELECT
        COALESCE((SELECT pg_catalog.count(*) FROM share WHERE share.direction = 'outgoing' AND share.live), 0)::INTEGER,
        COALESCE((SELECT pg_catalog.count(*) FROM share WHERE share.direction = 'incoming' AND share.live), 0)::INTEGER,
        COALESCE((SELECT pg_catalog.count(*) FROM share WHERE share.direction = 'incoming' AND share.waiting), 0)::INTEGER,
        (SELECT pg_catalog.min(share.changes_at) FROM share),
        COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'direction', peer.direction, 'peer_workspace_id', peer.peer_workspace_id,
            'peer_network_id', peer.peer_network_id, 'active', peer.active, 'waiting', peer.waiting)
            ORDER BY peer.direction, peer.peer_workspace_id, peer.peer_network_id) FROM peer), '[]'::JSONB)
    INTO v_shares_out, v_shares_in, v_offers, v_candidate, v_peers;
    v_next := LEAST(v_next, v_candidate);

    -- Policy changes waiting for approval that can still be approved.
    SELECT pg_catalog.count(*)::INTEGER, pg_catalog.min(request.expires_at)
    INTO v_approvals, v_candidate
    FROM mesh.policy_approval_request AS request
    WHERE request.workspace_id = v_workspace AND request.network_id = v_network
      AND request.state = 'pending' AND request.expires_at > v_now;
    v_next := LEAST(v_next, v_candidate);

    SELECT pg_catalog.count(*)::INTEGER INTO v_sites FROM mesh.network_site AS site
    WHERE site.workspace_id = v_workspace AND site.network_id = v_network AND site.state = 'active';
    SELECT pg_catalog.count(*)::INTEGER INTO v_clusters FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_workspace AND cluster.network_id = v_network AND cluster.state = 'active';

    PERFORM pg_catalog.set_config('mesh.network_summary_scan', '', TRUE);
    RETURN pg_catalog.jsonb_build_object(
        'workspace_id', v_workspace, 'network_id', v_network,
        'network_revision', v_revision, 'dirty_generation', v_generation, 'evaluated_at', v_now,
        'ipv4_prefix', v_prefix::TEXT,
        'addresses_capacity', CASE WHEN v_prefix IS NULL THEN NULL
            ELSE (1::BIGINT << (32 - pg_catalog.masklen(v_prefix))) - 2 END,
        'addresses_in_use', v_in_use, 'addresses_held', v_held,
        'active_devices', v_active, 'rule_count', v_rules, 'policy_revision', v_policy_revision,
        'policy_published_at', v_published,
        'shares_out_active', v_shares_out, 'shares_in_active', v_shares_in, 'offers_waiting', v_offers,
        'pending_approvals', v_approvals, 'sites', v_sites, 'kubernetes_clusters', v_clusters,
        'recompute_at', v_next, 'peers', v_peers
    );
END;
$function$;

-- Stores a summary the worker computed, only if it is newer than the stored
-- one (marker, then evaluation time), and releases the claim. The Network's
-- next recompute is spaced by p_spacing_ms, and a time-based recompute is
-- never sooner than 30 s after this one.
CREATE FUNCTION mesh_ops.store_network_summary_v1(
    p_deployment_public_id UUID, p_worker UUID, p_summary JSONB, p_compute_ms INTEGER, p_spacing_ms INTEGER
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_workspace BIGINT := (p_summary ->> 'workspace_id')::BIGINT;
    v_network BIGINT := (p_summary ->> 'network_id')::BIGINT;
    v_revision BIGINT := (p_summary ->> 'network_revision')::BIGINT;
    v_generation BIGINT := (p_summary ->> 'dirty_generation')::BIGINT;
    v_evaluated TIMESTAMPTZ := (p_summary ->> 'evaluated_at')::TIMESTAMPTZ;
    v_recompute TIMESTAMPTZ := (p_summary ->> 'recompute_at')::TIMESTAMPTZ;
    v_queue mesh_ops.network_summary_queue%ROWTYPE;
    v_stored mesh_ops.network_summary%ROWTYPE;
    v_newer BOOLEAN;
    v_peer JSONB;
BEGIN
    IF p_deployment_public_id IS NULL OR p_worker IS NULL OR p_summary IS NULL
       OR v_workspace IS NULL OR v_network IS NULL OR v_revision IS NULL OR v_generation IS NULL
       OR v_evaluated IS NULL OR p_compute_ms IS NULL OR p_compute_ms < 0
       OR p_spacing_ms IS NULL OR p_spacing_ms NOT BETWEEN 0 AND 600000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid network summary';
    END IF;
    PERFORM pg_catalog.set_config('mesh.network_summary_scan', 'on', TRUE);
    IF NOT EXISTS (
        SELECT 1 FROM mesh.network AS network
        JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
        JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND network.workspace_id = v_workspace AND network.id = v_network
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'network summary scope is unavailable';
    END IF;
    -- The queue row first, then the summary: the same order for every caller.
    SELECT * INTO v_queue FROM mesh_ops.network_summary_queue
    WHERE workspace_id = v_workspace AND network_id = v_network FOR UPDATE;
    IF NOT FOUND OR v_generation > v_queue.dirty_generation THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'network summary is ahead of its queue';
    END IF;
    SELECT * INTO v_stored FROM mesh_ops.network_summary
    WHERE workspace_id = v_workspace AND network_id = v_network FOR UPDATE;
    v_newer := NOT FOUND
        OR (v_revision, v_generation) > (v_stored.network_revision, v_stored.dirty_generation)
        OR ((v_revision, v_generation) = (v_stored.network_revision, v_stored.dirty_generation)
            AND v_evaluated > v_stored.evaluated_at);
    IF v_newer THEN
        INSERT INTO mesh_ops.network_summary AS summary (
            workspace_id, network_id, network_revision, dirty_generation, evaluated_at, computed_at,
            ipv4_prefix, addresses_capacity, addresses_in_use, addresses_held, active_devices,
            rule_count, policy_revision, policy_published_at, shares_out_active, shares_in_active,
            offers_waiting, pending_approvals, sites, kubernetes_clusters
        ) VALUES (
            v_workspace, v_network, v_revision, v_generation, v_evaluated, v_now,
            (p_summary ->> 'ipv4_prefix')::CIDR, (p_summary ->> 'addresses_capacity')::BIGINT,
            (p_summary ->> 'addresses_in_use')::BIGINT, (p_summary ->> 'addresses_held')::BIGINT,
            (p_summary ->> 'active_devices')::BIGINT, (p_summary ->> 'rule_count')::BIGINT,
            (p_summary ->> 'policy_revision')::BIGINT, (p_summary ->> 'policy_published_at')::TIMESTAMPTZ,
            (p_summary ->> 'shares_out_active')::INTEGER, (p_summary ->> 'shares_in_active')::INTEGER,
            (p_summary ->> 'offers_waiting')::INTEGER, (p_summary ->> 'pending_approvals')::INTEGER,
            (p_summary ->> 'sites')::INTEGER, (p_summary ->> 'kubernetes_clusters')::INTEGER
        )
        ON CONFLICT (workspace_id, network_id) DO UPDATE SET
            network_revision = EXCLUDED.network_revision, dirty_generation = EXCLUDED.dirty_generation,
            evaluated_at = EXCLUDED.evaluated_at, computed_at = EXCLUDED.computed_at,
            ipv4_prefix = EXCLUDED.ipv4_prefix, addresses_capacity = EXCLUDED.addresses_capacity,
            addresses_in_use = EXCLUDED.addresses_in_use, addresses_held = EXCLUDED.addresses_held,
            active_devices = EXCLUDED.active_devices, rule_count = EXCLUDED.rule_count,
            policy_revision = EXCLUDED.policy_revision, policy_published_at = EXCLUDED.policy_published_at,
            shares_out_active = EXCLUDED.shares_out_active, shares_in_active = EXCLUDED.shares_in_active,
            offers_waiting = EXCLUDED.offers_waiting, pending_approvals = EXCLUDED.pending_approvals,
            sites = EXCLUDED.sites, kubernetes_clusters = EXCLUDED.kubernetes_clusters;
        DELETE FROM mesh_ops.network_summary_peer WHERE workspace_id = v_workspace AND network_id = v_network;
        FOR v_peer IN SELECT * FROM pg_catalog.jsonb_array_elements(COALESCE(p_summary -> 'peers', '[]'::JSONB)) LOOP
            INSERT INTO mesh_ops.network_summary_peer (
                workspace_id, network_id, direction, peer_workspace_id, peer_network_id, active, waiting
            ) VALUES (
                v_workspace, v_network, v_peer ->> 'direction', (v_peer ->> 'peer_workspace_id')::BIGINT,
                (v_peer ->> 'peer_network_id')::BIGINT, (v_peer ->> 'active')::INTEGER,
                (v_peer ->> 'waiting')::INTEGER
            );
        END LOOP;
    END IF;
    -- A change marked after the snapshot keeps the row dirty: the computed
    -- generation is the snapshot's, never the queue's current one. Only a
    -- newer summary sets the schedule; an older one (a worker whose lease
    -- ran out) must not replace the newer one's next recompute.
    UPDATE mesh_ops.network_summary_queue SET
        computed_generation = GREATEST(computed_generation, v_generation),
        not_before = CASE WHEN v_newer
            THEN v_now + pg_catalog.make_interval(secs => p_spacing_ms / 1000.0) ELSE not_before END,
        recompute_at = CASE WHEN NOT v_newer THEN recompute_at
            WHEN v_recompute IS NULL THEN NULL
            ELSE GREATEST(v_recompute, v_now + INTERVAL '30 seconds') END,
        last_compute_ms = CASE WHEN v_newer THEN LEAST(p_compute_ms, 2147483647) ELSE last_compute_ms END,
        -- Still dirty: the oldest change not counted is after this snapshot.
        dirty_since = CASE WHEN GREATEST(computed_generation, v_generation) < dirty_generation
            THEN GREATEST(dirty_since, v_evaluated) ELSE dirty_since END,
        claimed_until = CASE WHEN claimed_by = p_worker THEN NULL ELSE claimed_until END,
        claimed_by = CASE WHEN claimed_by = p_worker THEN NULL ELSE claimed_by END
    WHERE workspace_id = v_workspace AND network_id = v_network;
    PERFORM pg_catalog.set_config('mesh.network_summary_scan', '', TRUE);
    RETURN v_newer;
END;
$function$;

-- Releases a claim the worker could not finish. After a failure the Network
-- waits p_retry_ms before it is claimed again, so a count that always fails
-- or times out does not run back to back.
CREATE FUNCTION mesh_ops.release_network_summary_claim_v1(
    p_deployment_public_id UUID, p_worker UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    p_retry_ms INTEGER
)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF p_retry_ms IS NULL OR p_retry_ms NOT BETWEEN 0 AND 600000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid network summary release';
    END IF;
    PERFORM pg_catalog.set_config('mesh.network_summary_scan', 'on', TRUE);
    UPDATE mesh_ops.network_summary_queue AS queue SET claimed_until = NULL, claimed_by = NULL,
        not_before = GREATEST(queue.not_before,
            pg_catalog.clock_timestamp() + pg_catalog.make_interval(secs => p_retry_ms / 1000.0))
    FROM mesh.network AS network
    JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND queue.workspace_id = network.workspace_id AND queue.network_id = network.id
      AND queue.claimed_by = p_worker;
    PERFORM pg_catalog.set_config('mesh.network_summary_scan', '', TRUE);
END;
$function$;

-- The oldest change not yet in a summary, in seconds, and how many Networks
-- wait: the worker's lag metric. Reads only the dirty part of the queue.
CREATE FUNCTION mesh_ops.network_summary_lag_v1(p_deployment_public_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_result JSONB;
BEGIN
    IF p_deployment_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid network summary lag input';
    END IF;
    PERFORM pg_catalog.set_config('mesh.network_summary_scan', 'on', TRUE);
    -- Marks not folded yet count too: a fold that stalls must show.
    SELECT pg_catalog.jsonb_build_object(
        'pending', pg_catalog.count(*),
        'oldest_seconds', GREATEST(
            COALESCE(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp() - pg_catalog.min(queue.dirty_since)), 0),
            COALESCE((SELECT pg_catalog.date_part('epoch', pg_catalog.clock_timestamp() - mark.marked_at)
                FROM mesh_ops.network_summary_mark AS mark ORDER BY mark.id LIMIT 1), 0)),
        'marks', (SELECT pg_catalog.count(*) FROM (SELECT 1 FROM mesh_ops.network_summary_mark LIMIT 100000) AS bounded))
    INTO v_result
    FROM mesh_ops.network_summary_queue AS queue
    JOIN mesh.workspace AS workspace ON workspace.id = queue.workspace_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    WHERE queue.dirty_generation > queue.computed_generation
      AND deployment.installation_public_id = p_deployment_public_id;
    PERFORM pg_catalog.set_config('mesh.network_summary_scan', '', TRUE);
    RETURN v_result;
END;
$function$;

-- Every Network gets a queue row now, due at once.
DO $backfill$
BEGIN
    PERFORM pg_catalog.set_config('mesh.network_summary_scan', 'on', TRUE);
    INSERT INTO mesh_ops.network_summary_queue (workspace_id, network_id)
    SELECT network.workspace_id, network.id FROM mesh.network AS network
    ON CONFLICT (workspace_id, network_id) DO NOTHING;
    PERFORM pg_catalog.set_config('mesh.network_summary_scan', '', TRUE);
END;
$backfill$;

REVOKE ALL ON FUNCTION mesh_ops.network_summary_revision_trigger_v1(),
    mesh_ops.network_summary_share_trigger_v1(), mesh_ops.network_summary_scoped_trigger_v1(),
    mesh_ops.fold_network_summary_marks_v1(INTEGER),
    mesh_ops.claim_network_summary_work_v1(UUID, UUID, INTEGER, INTEGER),
    mesh_ops.compute_network_summary_v1(UUID, UUID, UUID),
    mesh_ops.store_network_summary_v1(UUID, UUID, JSONB, INTEGER, INTEGER),
    mesh_ops.release_network_summary_claim_v1(UUID, UUID, UUID, UUID, INTEGER),
    mesh_ops.network_summary_lag_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.fold_network_summary_marks_v1(INTEGER),
    mesh_ops.claim_network_summary_work_v1(UUID, UUID, INTEGER, INTEGER),
    mesh_ops.compute_network_summary_v1(UUID, UUID, UUID),
    mesh_ops.store_network_summary_v1(UUID, UUID, JSONB, INTEGER, INTEGER),
    mesh_ops.release_network_summary_claim_v1(UUID, UUID, UUID, UUID, INTEGER),
    mesh_ops.network_summary_lag_v1(UUID)
    TO mesh_worker;
