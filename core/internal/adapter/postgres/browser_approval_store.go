package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

const recordBrowserApprovalSQL = `SELECT
    approved_registration_public_id::TEXT,
    approved_registration_version,
    approved_intent_public_id::TEXT,
    approved_session_public_id::TEXT,
    approved_principal_public_id::TEXT,
    approved_network_revision,
    approved_request_hash
FROM mesh_ops.record_browser_registration_approval_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA,
    $5::BYTEA, $6::UUID, $7::UUID, $8::UUID
)`

const lockBrowserApprovalAuditSQL = `SELECT
    stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_network_stream_head()`

const recordBrowserWorkspaceApprovalSQL = `SELECT
    approved_registration_public_id::TEXT, approved_registration_version,
    approved_intent_public_id::TEXT, approved_session_public_id::TEXT,
    approved_principal_public_id::TEXT, approved_network_revision, approved_request_hash
FROM mesh_ops.record_browser_registration_approval_v2(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA,
    $5::BYTEA, $6::UUID, $7::UUID, $8::UUID, $9::UUID
)`

const appendBrowserApprovalEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'pending_registration', $7::UUID, $8::BIGINT, $9::BIGINT, $10::UUID,
    $15::TEXT, 'device.register', $11::UUID,
    $16::BYTEA, $12::BYTEA, $13::JSONB,
    $15::TEXT, $14::JSONB
)`

var (
	// ErrInvalidBrowserApproval reports missing or malformed approval input.
	ErrInvalidBrowserApproval = errors.New("invalid browser registration approval")
	// ErrBrowserApprovalUnavailable reports a failed authority or evidence transaction.
	ErrBrowserApprovalUnavailable = errors.New("browser registration approval unavailable")
	// ErrBrowserApprovalEvidence reports malformed durable authority evidence.
	ErrBrowserApprovalEvidence = errors.New("browser registration approval evidence invalid")
)

// BrowserApprovalStore owns one short, audited Network selection transaction.
type BrowserApprovalStore struct {
	database      browserIntentDatabase
	options       AccountSessionOptions
	deploymentID  deployment.ID
	recoveryEpoch int64
}

// NewBrowserApprovalStore admits only the runtime pool and a bounded profile.
func NewBrowserApprovalStore(
	pool *Pool, options AccountSessionOptions,
	deploymentID deployment.ID, recoveryEpoch int64,
) (*BrowserApprovalStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.browserIntentDatabase == nil ||
		!validAccountSessionOptions(options) || !deploymentID.IsValid() || recoveryEpoch <= 0 {
		return nil, ErrInvalidBrowserApproval
	}
	return &BrowserApprovalStore{
		database: pool.browserIntentDatabase, options: options,
		deploymentID: deploymentID, recoveryEpoch: recoveryEpoch,
	}, nil
}

// Approve rechecks SSO, membership, profile, Network, and intent in PostgreSQL.
// A missing authority path returns false; no choice is inferred from the client.
func (store *BrowserApprovalStore) Approve(
	ctx context.Context, sessionDigest accountsession.Digest,
	encodedToken string, selectedNetwork network.ID,
) (bool, error) {
	return store.approve(ctx, sessionDigest, encodedToken, workspace.ID{}, selectedNetwork)
}

// ApproveInWorkspace requires an explicit Workspace and rechecks its current
// membership and SSO route, then the exact Network, in the audited transaction.
func (store *BrowserApprovalStore) ApproveInWorkspace(ctx context.Context,
	digest accountsession.Digest, token string, selectedWorkspace workspace.ID, selectedNetwork network.ID,
) (bool, error) {
	if !selectedWorkspace.IsValid() {
		return false, ErrInvalidBrowserApproval
	}
	return store.approve(ctx, digest, token, selectedWorkspace, selectedNetwork)
}

func (store *BrowserApprovalStore) approve(ctx context.Context, sessionDigest accountsession.Digest,
	encodedToken string, selectedWorkspace workspace.ID, selectedNetwork network.ID,
) (_ bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil ||
		!validAccountSessionOptions(store.options) || !store.deploymentID.IsValid() ||
		store.recoveryEpoch <= 0 || !sessionDigest.IsValid() ||
		!selectedNetwork.IsValid() {
		return false, ErrInvalidBrowserApproval
	}
	intentDigest, err := enrollment.DigestPresentedBrowserIntentToken(encodedToken)
	if err != nil {
		return false, ErrInvalidBrowserApproval
	}
	registrationID, err := publicid.New()
	if err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	changeID, err := publicid.New()
	if err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	eventID, err := publicid.New()
	if err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	outboxID, err := publicid.New()
	if err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
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
	sessionBytes := sessionDigest.Bytes()
	intentBytes := intentDigest.Bytes()
	var issuedRegistration, intent, session, principal string
	var version, networkRevision int64
	var requestHashBytes []byte
	query := recordBrowserApprovalSQL
	arguments := []any{
		store.deploymentID.String(), store.recoveryEpoch,
		sessionDigest.KeyID().String(), sessionBytes[:], intentBytes[:],
		selectedNetwork.String(), registrationID.String(), changeID.String(),
	}
	if selectedWorkspace.IsValid() {
		query = recordBrowserWorkspaceApprovalSQL
		arguments = []any{store.deploymentID.String(), store.recoveryEpoch,
			sessionDigest.KeyID().String(), sessionBytes[:], intentBytes[:],
			selectedWorkspace.String(), selectedNetwork.String(), registrationID.String(), changeID.String()}
	}
	expired, err := retireExpiredBrowserApproval(ctx, transaction, selectedWorkspace, changeID, arguments[:len(arguments)-2])
	if err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	err = transaction.QueryRow(ctx, query, arguments...).Scan(&issuedRegistration, &version, &intent, &session, &principal,
		&networkRevision, &requestHashBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		// The second authority check can expire while locks were held. Never
		// commit a retired registration without the fresh approved successor.
		if expired != nil {
			return false, nil
		}
		if err := transaction.Commit(ctx); err != nil {
			return false, errors.Join(ErrBrowserApprovalUnavailable, err)
		}
		closed = true
		return false, nil
	}
	if err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	intentID, intentErr := publicid.Parse(intent)
	sessionID, sessionErr := publicid.Parse(session)
	principalID, principalErr := publicid.Parse(principal)
	if issuedRegistration != registrationID.String() || version != 1 ||
		intentErr != nil || sessionErr != nil || principalErr != nil ||
		networkRevision <= 0 || len(requestHashBytes) != sha256.Size {
		return false, ErrBrowserApprovalEvidence
	}
	var requestHash [sha256.Size]byte
	copy(requestHash[:], requestHashBytes)
	if requestHash == ([sha256.Size]byte{}) {
		return false, ErrBrowserApprovalEvidence
	}
	if expired != nil {
		expiryEventID, eventErr := publicid.New()
		expiryOutboxID, outboxErr := publicid.New()
		if eventErr != nil || outboxErr != nil {
			return false, errors.Join(ErrBrowserApprovalUnavailable, eventErr, outboxErr)
		}
		if err := appendBrowserApprovalEvidence(ctx, transaction, browserApprovalEvidence{
			registrationID: expired.id, changeID: changeID,
			eventID: expiryEventID, outboxID: expiryOutboxID, intentID: intentID,
			sessionID: sessionID, principalID: principalID,
			workspaceID: selectedWorkspace, networkID: selectedNetwork,
			version: expired.version, networkRevision: networkRevision,
			requestHash: expired.afterHash, beforeHash: expired.beforeHash, expired: true,
		}); err != nil {
			return false, errors.Join(ErrBrowserApprovalUnavailable, err)
		}
	}
	if err := appendBrowserApprovalEvidence(ctx, transaction, browserApprovalEvidence{
		registrationID: registrationID, changeID: changeID,
		eventID: eventID, outboxID: outboxID, intentID: intentID,
		sessionID: sessionID, principalID: principalID,
		workspaceID: selectedWorkspace,
		networkID:   selectedNetwork, version: version,
		networkRevision: networkRevision, requestHash: requestHash,
	}); err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return false, errors.Join(ErrBrowserApprovalUnavailable, err)
	}
	closed = true
	return true, nil
}

type browserApprovalEvidence struct {
	registrationID  publicid.ID
	changeID        publicid.ID
	eventID         publicid.ID
	outboxID        publicid.ID
	intentID        publicid.ID
	sessionID       publicid.ID
	principalID     publicid.ID
	networkID       network.ID
	workspaceID     workspace.ID
	version         int64
	networkRevision int64
	requestHash     [sha256.Size]byte
	beforeHash      [sha256.Size]byte
	expired         bool
}

func appendBrowserApprovalEvidence(
	ctx context.Context, transaction accountSessionTransaction,
	value browserApprovalEvidence,
) error {
	action := "registration.browser.approved"
	var beforeBytes []byte
	if value.expired {
		if value.version <= 1 || value.beforeHash == ([sha256.Size]byte{}) {
			return ErrBrowserApprovalEvidence
		}
		action = "registration.expired"
		beforeBytes = value.beforeHash[:]
	}
	var streamID, sequence int64
	var previousBytes []byte
	if err := transaction.QueryRow(ctx, lockBrowserApprovalAuditSQL).Scan(
		&streamID, &sequence, &previousBytes,
	); err != nil || streamID <= 0 || sequence <= 0 || len(previousBytes) != sha256.Size {
		return errors.Join(ErrBrowserApprovalEvidence, err)
	}
	var previousHash [sha256.Size]byte
	copy(previousHash[:], previousBytes)
	auditPayload, err := json.Marshal(struct {
		IntentID       string `json:"intent_id"`
		RegistrationID string `json:"registration_id"`
		SessionID      string `json:"session_id"`
		NetworkID      string `json:"network_id"`
		WorkspaceID    string `json:"workspace_id,omitempty"`
	}{
		IntentID: value.intentID.String(), RegistrationID: value.registrationID.String(),
		SessionID: value.sessionID.String(), NetworkID: value.networkID.String(),
		WorkspaceID: browserApprovalWorkspaceID(value.workspaceID),
	})
	if err != nil {
		return fmt.Errorf("encode browser approval audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(struct {
		RegistrationID  string `json:"registration_id"`
		NetworkRevision int64  `json:"network_revision"`
	}{RegistrationID: value.registrationID.String(), NetworkRevision: value.networkRevision})
	if err != nil {
		return fmt.Errorf("encode browser approval outbox payload: %w", err)
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: value.eventID, ChangeID: value.changeID,
		AggregateKind: "pending_registration", AggregateID: value.registrationID,
		AggregateVersion: value.version, NetworkRevision: value.networkRevision,
		ActorPrincipalID: value.principalID, Action: action,
		Permission: "device.register", CorrelationID: value.intentID,
		BeforeSemanticHash: value.beforeHash, AfterSemanticHash: value.requestHash,
		AuditPayloadHash:  sha256.Sum256(auditPayload),
		OutboxEventClass:  action,
		OutboxPayloadHash: sha256.Sum256(outboxPayload),
	})
	if err != nil {
		return errors.Join(ErrBrowserApprovalEvidence, err)
	}
	var appendedSequence int64
	if err := transaction.QueryRow(ctx, appendBrowserApprovalEvidenceSQL,
		streamID, value.eventID.String(), value.outboxID.String(), sequence,
		previousHash[:], eventHash[:], value.registrationID.String(),
		value.version, value.networkRevision, value.principalID.String(),
		value.intentID.String(), value.requestHash[:], auditPayload, outboxPayload, action, beforeBytes,
	).Scan(&appendedSequence); err != nil || appendedSequence != sequence {
		return errors.Join(ErrBrowserApprovalEvidence, err)
	}
	return nil
}

func browserApprovalWorkspaceID(id workspace.ID) string {
	if id.IsValid() {
		return id.String()
	}
	return ""
}
