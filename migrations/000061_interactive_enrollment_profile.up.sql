-- Existing credentials retain their current behavior. Browser enrollment is
-- denied until an operator explicitly enables one active profile per Network.
ALTER TABLE mesh.enrollment_profile
    ADD COLUMN interactive_authorization_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE UNIQUE INDEX enrollment_profile_interactive_active_uidx
    ON mesh.enrollment_profile (workspace_id, network_id)
    WHERE state = 'active'
      AND deleted_at IS NULL
      AND interactive_authorization_enabled;
