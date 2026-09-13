REVOKE ALL ON mesh_ops.outbox_event FROM PUBLIC;
REVOKE ALL ON mesh_ops.outbox_attempt FROM PUBLIC;
REVOKE ALL ON SEQUENCE mesh_ops.outbox_attempt_id_seq FROM PUBLIC;

CREATE POLICY outbox_event_worker_policy ON mesh_ops.outbox_event
    TO mesh_worker
    USING (TRUE)
    WITH CHECK (TRUE);

GRANT SELECT (
    id,
    public_id,
    workspace_id,
    network_id,
    network_revision,
    state,
    available_at,
    claim_token,
    claimed_by,
    claimed_at,
    claim_expires_at,
    completed_at,
    attempt_count
) ON mesh_ops.outbox_event TO mesh_worker;

GRANT UPDATE (
    state,
    available_at,
    claim_token,
    claimed_by,
    claimed_at,
    claim_expires_at,
    completed_at,
    attempt_count,
    last_error_class
) ON mesh_ops.outbox_event TO mesh_worker;

GRANT INSERT (
    outbox_event_id,
    attempt_number,
    worker_id,
    started_at,
    finished_at,
    result,
    error_class,
    next_retry_at
) ON mesh_ops.outbox_attempt TO mesh_worker;

GRANT USAGE, SELECT ON SEQUENCE mesh_ops.outbox_attempt_id_seq TO mesh_worker;
