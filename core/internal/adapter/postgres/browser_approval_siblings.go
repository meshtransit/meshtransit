package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const approvalSiblingConflictSQL = `SELECT mesh_ops.browser_sibling_conflict_v1(
    $1::UUID, $2::BIGINT, $3::BYTEA, NULL::BYTEA, NULL::BYTEA[], $4::UUID, $5::UUID, $6::UUID
) IS NOT NULL`

const minimizeBrowserIntentSiblingsSQL = `SELECT mesh_ops.minimize_browser_intent_siblings_v1(
    $1::UUID, $2::BIGINT, $3::BYTEA, $4::UUID
)`

// The rows come back as one JSON array (at most 16 Devices).
const lookupBrowserSiblingDevicesSQL = `SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'device', device_public_id::TEXT, 'hostname', device_hostname, 'state', device_state,
    'workspace', workspace_public_id::TEXT, 'network', network_public_id::TEXT, 'name', network_display_name)),
    '[]'::JSONB)
FROM mesh_ops.lookup_browser_sibling_devices_v1($1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::BYTEA)`

type siblingDeviceRow struct {
	Device    string `json:"device"`
	Hostname  string `json:"hostname"`
	State     string `json:"state"`
	Workspace string `json:"workspace"`
	Network   string `json:"network"`
	Name      string `json:"name"`
}

const joinBrowserExistingDeviceSQL = `SELECT joined_intent_public_id::TEXT, joined_intent_version,
    joined_principal_public_id::TEXT, joined_workspace_public_id::TEXT, joined_network_public_id::TEXT,
    joined_network_revision
FROM mesh_ops.join_browser_existing_device_v1($1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::BYTEA, $6::UUID, $7::UUID)`

// The evidence of "Use that account": the sign-in (its intent) ended.
const appendBrowserJoinedEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'browser_registration_intent', $7::UUID, $8::BIGINT, $9::BIGINT, $10::UUID,
    'registration.joined_existing', 'device.register', $7::UUID,
    NULL::BYTEA, $11::BYTEA, $12::JSONB,
    'registration.joined_existing', $13::JSONB
)`

// browserJoinedEvidence is what one "Use that account" records.
type browserJoinedEvidence struct {
	changeID, eventID, outboxID, intentID, principalID, deviceID publicid.ID
	workspaceID, networkID                                       string
	version, networkRevision                                     int64
}

// approvalSiblingConflict reports whether the approved Network already holds
// the approver's Device through one of the sign-in's sibling keys.
func approvalSiblingConflict(ctx context.Context, transaction accountSessionTransaction, store *BrowserApprovalStore,
	intentDigest []byte, principal publicid.ID, selectedWorkspace workspace.ID, selectedNetwork network.ID,
) (bool, error) {
	var conflict bool
	err := transaction.QueryRow(ctx, approvalSiblingConflictSQL, store.deploymentID.String(), store.recoveryEpoch,
		intentDigest, principal.String(), selectedWorkspace.String(), selectedNetwork.String()).Scan(&conflict)
	return conflict, err
}

// minimizeApprovalSiblings keeps, from the approval on, only sibling keys of
// the approver's Devices or of no Device (duplicate-device design §6.2).
func minimizeApprovalSiblings(ctx context.Context, transaction accountSessionTransaction,
	store *BrowserApprovalStore, intentDigest []byte, principal publicid.ID,
) error {
	var dropped int
	return transaction.QueryRow(ctx, minimizeBrowserIntentSiblingsSQL, store.deploymentID.String(),
		store.recoveryEpoch, intentDigest, principal.String()).Scan(&dropped)
}

// LookupSiblingDevices lists what the approval page tells the signed-in
// person: their Devices on this machine, through the pending sign-in's
// sibling keys (duplicate-device design §7). Empty when the session or
// sign-in does not hold, or there are none.
func (store *BrowserApprovalStore) LookupSiblingDevices(ctx context.Context, digest accountsession.Digest,
	token string,
) (_ []control.BrowserSiblingDevice, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !digest.IsValid() {
		return nil, ErrInvalidBrowserApproval
	}
	intentDigest, err := enrollment.DigestPresentedBrowserIntentToken(token)
	if err != nil {
		return nil, ErrInvalidBrowserApproval
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		return nil, ErrBrowserApprovalUnavailable
	}
	defer func() {
		resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(transaction))
	}()
	if err := transaction.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.IdleTimeout)); err != nil {
		return nil, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	sessionBytes := digest.Bytes()
	intentBytes := intentDigest.Bytes()
	var encoded []byte
	if err := transaction.QueryRow(ctx, lookupBrowserSiblingDevicesSQL, store.deploymentID.String(),
		store.recoveryEpoch, digest.KeyID().String(), sessionBytes[:], intentBytes[:]).Scan(&encoded); err != nil {
		return nil, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	var rows []siblingDeviceRow
	if err := json.Unmarshal(encoded, &rows); err != nil || len(rows) > MaxBrowserSiblings {
		return nil, ErrBrowserApprovalEvidence
	}
	devices := make([]control.BrowserSiblingDevice, 0, len(rows))
	for _, row := range rows {
		switch row.State {
		case control.SiblingActive, control.SiblingSignedOut, control.SiblingExpired, control.SiblingSuspended:
		default:
			return nil, ErrBrowserApprovalEvidence
		}
		devices = append(devices, control.BrowserSiblingDevice{
			DeviceID: row.Device, Hostname: row.Hostname,
			State: row.State, WorkspaceID: row.Workspace, NetworkID: row.Network, NetworkName: row.Name,
		})
	}
	return devices, nil
}

// JoinExistingDevice ends the pending sign-in with "Use that account": the
// person chose their Device a sibling key holds (duplicate-device design
// §8.2). False, with nothing changed, when anything does not hold.
func (store *BrowserApprovalStore) JoinExistingDevice(ctx context.Context, digest accountsession.Digest,
	token string, device publicid.ID,
) (_ bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !digest.IsValid() || !device.IsValid() {
		return false, ErrInvalidBrowserApproval
	}
	intentDigest, err := enrollment.DigestPresentedBrowserIntentToken(token)
	if err != nil {
		return false, ErrInvalidBrowserApproval
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		return false, ErrBrowserApprovalUnavailable
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(transaction))
		}
	}()
	if err := transaction.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.IdleTimeout)); err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	evidence := browserJoinedEvidence{deviceID: device}
	if evidence.changeID, err = publicid.New(); err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	if evidence.eventID, err = publicid.New(); err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	if evidence.outboxID, err = publicid.New(); err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	sessionBytes := digest.Bytes()
	intentBytes := intentDigest.Bytes()
	var intent, principal string
	err = transaction.QueryRow(ctx, joinBrowserExistingDeviceSQL, store.deploymentID.String(), store.recoveryEpoch,
		digest.KeyID().String(), sessionBytes[:], intentBytes[:], device.String(), evidence.changeID.String()).Scan(
		&intent, &evidence.version, &principal, &evidence.workspaceID, &evidence.networkID, &evidence.networkRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	intentID, intentErr := publicid.Parse(intent)
	principalID, principalErr := publicid.Parse(principal)
	if intentErr != nil || principalErr != nil || evidence.version <= 1 || evidence.networkRevision <= 0 {
		return false, ErrBrowserApprovalEvidence
	}
	evidence.intentID, evidence.principalID = intentID, principalID
	if err := appendBrowserJoinedEvidence(ctx, transaction, evidence); err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	closed = true
	return true, nil
}

// appendBrowserJoinedEvidence records registration.joined_existing on the
// Network stream of the Device the person chose (design §8.4); it names that
// Device by public id and never a machine key.
func appendBrowserJoinedEvidence(ctx context.Context, transaction accountSessionTransaction,
	value browserJoinedEvidence,
) error {
	const action = "registration.joined_existing"
	var streamID, sequence int64
	var previousBytes []byte
	if err := transaction.QueryRow(ctx, lockBrowserApprovalAuditSQL).Scan(
		&streamID, &sequence, &previousBytes,
	); err != nil || streamID <= 0 || sequence <= 0 || len(previousBytes) != sha256.Size {
		return errors.Join(ErrBrowserApprovalEvidence, err)
	}
	previousHash := [sha256.Size]byte(previousBytes)
	auditPayload, err := json.Marshal(struct {
		IntentID    string `json:"intent_id"`
		DeviceID    string `json:"device_id"`
		WorkspaceID string `json:"workspace_id"`
		NetworkID   string `json:"network_id"`
	}{
		IntentID: value.intentID.String(), DeviceID: value.deviceID.String(),
		WorkspaceID: value.workspaceID, NetworkID: value.networkID,
	})
	if err != nil {
		return errors.Join(ErrBrowserApprovalEvidence, err)
	}
	outboxPayload, err := json.Marshal(struct {
		IntentID        string `json:"intent_id"`
		NetworkRevision int64  `json:"network_revision"`
	}{IntentID: value.intentID.String(), NetworkRevision: value.networkRevision})
	if err != nil {
		return errors.Join(ErrBrowserApprovalEvidence, err)
	}
	afterHash := sha256.Sum256([]byte("meshtransit/browser-intent-joined/v1\x00" + value.intentID.String() +
		"\x00" + value.deviceID.String()))
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: value.eventID, ChangeID: value.changeID,
		AggregateKind: "browser_registration_intent", AggregateID: value.intentID,
		AggregateVersion: value.version, NetworkRevision: value.networkRevision,
		ActorPrincipalID: value.principalID, Action: action,
		Permission: "device.register", CorrelationID: value.intentID,
		AfterSemanticHash: afterHash,
		AuditPayloadHash:  sha256.Sum256(auditPayload),
		OutboxEventClass:  action,
		OutboxPayloadHash: sha256.Sum256(outboxPayload),
	})
	if err != nil {
		return errors.Join(ErrBrowserApprovalEvidence, err)
	}
	var appended int64
	if err := transaction.QueryRow(ctx, appendBrowserJoinedEvidenceSQL,
		streamID, value.eventID.String(), value.outboxID.String(), sequence, previousHash[:], eventHash[:],
		value.intentID.String(), value.version, value.networkRevision, value.principalID.String(),
		afterHash[:], auditPayload, outboxPayload,
	).Scan(&appended); err != nil || appended != sequence {
		return errors.Join(ErrBrowserApprovalEvidence, err)
	}
	return nil
}
