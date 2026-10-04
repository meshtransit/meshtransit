package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const lockBrowserApprovalExpiryScopeV1SQL = `SELECT workspace_internal_id,
 network_internal_id, machine_key_fingerprint
FROM mesh_ops.lock_browser_registration_approval_authority_v1(
 $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::BYTEA, $6::UUID
)`

const lockBrowserApprovalExpiryScopeV2SQL = `SELECT workspace_internal_id,
 network_internal_id, machine_key_fingerprint
FROM mesh_ops.lock_browser_registration_approval_authority_v2(
 $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::BYTEA, $6::UUID, $7::UUID
)`

const lockExpiredBrowserApprovalSQL = `SELECT public_id::TEXT,state,version,expires_at
FROM mesh.pending_registration
WHERE workspace_id=$1::BIGINT AND network_id=$2::BIGINT
 AND machine_key_fingerprint=$3::BYTEA AND state IN ('pending','authorized')
 AND expires_at <= pg_catalog.clock_timestamp()
FOR UPDATE`

const retireExpiredBrowserApprovalSQL = `UPDATE mesh.pending_registration
SET state='expired', version=version+1, updated_at=pg_catalog.clock_timestamp()
WHERE public_id=$1::UUID AND version=$2::BIGINT AND state=$3::TEXT
 AND expires_at <= pg_catalog.clock_timestamp()
RETURNING version`

type expiredBrowserApproval struct {
	id                    publicid.ID
	version               int64
	beforeHash, afterHash [sha256.Size]byte
}

// Expiry is a lifecycle transition, not a deletion or a second authorization.
// Locks and exact scope come from the same SSO authority used to approve the
// new intent. The caller records both mutations under one change, then commits
// them together. No live registration may be retired to make room.
func retireExpiredBrowserApproval(
	ctx context.Context, tx accountSessionTransaction, selectedWorkspace workspace.ID,
	changeID publicid.ID, authorityArguments []any,
) (*expiredBrowserApproval, error) {
	query := lockBrowserApprovalExpiryScopeV1SQL
	if selectedWorkspace.IsValid() {
		query = lockBrowserApprovalExpiryScopeV2SQL
	}
	var workspaceInternal, networkInternal int64
	var fingerprint []byte
	err := tx.QueryRow(ctx, query, authorityArguments...).Scan(&workspaceInternal, &networkInternal, &fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if workspaceInternal <= 0 || networkInternal <= 0 || len(fingerprint) != sha256.Size {
		return nil, ErrBrowserApprovalEvidence
	}
	var encodedID, state string
	var version int64
	var expires time.Time
	err = tx.QueryRow(ctx, lockExpiredBrowserApprovalSQL, workspaceInternal, networkInternal, fingerprint).Scan(&encodedID, &state, &version, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	id, err := publicid.Parse(encodedID)
	if err != nil || version <= 0 || (state != "pending" && state != "authorized") || expires.IsZero() {
		return nil, ErrBrowserApprovalEvidence
	}
	before, err := browserApprovalExpiryHash(id, state, version, expires)
	if err != nil {
		return nil, err
	}
	if err := tx.Exec(ctx, setBrowserIntentChangeSQL, changeID.String()); err != nil {
		return nil, err
	}
	var committedVersion int64
	if err := tx.QueryRow(ctx, retireExpiredBrowserApprovalSQL, id.String(), version, state).Scan(&committedVersion); err != nil {
		return nil, err
	}
	if committedVersion != version+1 {
		return nil, ErrBrowserApprovalEvidence
	}
	after, err := browserApprovalExpiryHash(id, "expired", committedVersion, expires)
	if err != nil {
		return nil, err
	}
	return &expiredBrowserApproval{id: id, version: committedVersion, beforeHash: before, afterHash: after}, nil
}

func browserApprovalExpiryHash(id publicid.ID, state string, version int64, expires time.Time) ([sha256.Size]byte, error) {
	payload, err := json.Marshal(struct {
		Domain         string `json:"domain"`
		RegistrationID string `json:"registration_id"`
		State          string `json:"state"`
		Version        int64  `json:"version"`
		ExpiresAt      string `json:"expires_at"`
	}{Domain: "meshtransit/registration-expiry/v1", RegistrationID: id.String(), State: state, Version: version, ExpiresAt: expires.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(payload), nil
}
