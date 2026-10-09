package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment/entitlement"
	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrEntitlementRejected reports an entitlement PostgreSQL refused: an
	// inactive Deployment, a profile mismatch or conflicting generation content.
	ErrEntitlementRejected = errors.New("postgres: Deployment entitlement rejected")
	// ErrEntitlementUnavailable reports an unavailable or uncertain record.
	ErrEntitlementUnavailable = errors.New("postgres: Deployment entitlement unavailable")
)

// EntitlementOutcome is what recording one verified generation did.
type EntitlementOutcome string

const (
	// EntitlementRecorded stored a new current generation with audit evidence.
	EntitlementRecorded EntitlementOutcome = "recorded"
	// EntitlementReplayed found the identical generation already current.
	EntitlementReplayed EntitlementOutcome = "replayed"
	// EntitlementSuperseded found a newer generation; nothing changed.
	EntitlementSuperseded EntitlementOutcome = "superseded"
)

const setEntitlementChangeSQL = `SELECT pg_catalog.set_config('mesh.change_public_id', $1::TEXT, TRUE)`

const recordDeploymentEntitlementSQL = `SELECT current_entitlement_public_id::TEXT, current_generation, outcome
FROM mesh_ops.record_deployment_entitlement_v1(
 $1::UUID,$2::UUID,$3::BIGINT,$4::TEXT,$5::BIGINT,$6::BIGINT,$7::TEXT[],
 $8::TIMESTAMPTZ,$9::TIMESTAMPTZ,$10::TIMESTAMPTZ,$11::BIGINT,$12::TEXT,$13::BYTEA)`

const appendDeploymentEntitlementEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'deployment_entitlement',$7::UUID,1,NULL::BIGINT,NULL::UUID,'deployment_entitlement.recorded',
 'system.entitlement',$8::UUID,NULL::BYTEA,$9::BYTEA,$10::JSONB,'deployment_entitlement.recorded',$10::JSONB)`

// DeploymentEntitlementStore records verified entitlement generations.
type DeploymentEntitlementStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

// NewDeploymentEntitlementStore uses the runtime pool.
func NewDeploymentEntitlementStore(pool *Pool, options AccountSessionOptions) (*DeploymentEntitlementStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, ErrEntitlementUnavailable
	}
	return &DeploymentEntitlementStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

// Record stores one verified generation. The verifier has already checked the
// signature, the Deployment and installation binding and the claims.
func (store *DeploymentEntitlementStore) Record(ctx context.Context, verified entitlement.Entitlement) (
	_ EntitlementOutcome, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !verified.DeploymentID.IsValid() || verified.Generation <= 0 {
		return "", ErrEntitlementUnavailable
	}
	var ids [3]publicid.ID
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return "", ErrEntitlementUnavailable
		}
		ids[index] = id
	}
	change, event, outbox := ids[0], ids[1], ids[2]
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return "", ErrEntitlementUnavailable
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return "", errors.Join(ErrEntitlementUnavailable, err)
	}
	if err := tx.Exec(ctx, setEntitlementChangeSQL, change.String()); err != nil {
		return "", errors.Join(ErrEntitlementUnavailable, err)
	}
	capabilities := make([]string, 0, len(verified.Capabilities))
	for _, capability := range verified.Capabilities {
		capabilities = append(capabilities, string(capability))
	}
	var currentID, outcome string
	var currentGeneration int64
	if err := tx.QueryRow(ctx, recordDeploymentEntitlementSQL,
		verified.DeploymentID.String(), verified.ID.String(), verified.Generation, string(verified.Profile),
		verified.Limits.MaxActiveWorkspaces, verified.Limits.MaxOwnedWorkspacesPerAccount, capabilities,
		verified.IssuedAt, verified.NotBefore, verified.ExpiresAt, int64(verified.Grace/time.Second),
		verified.KeyID, verified.ContentSHA256[:],
	).Scan(&currentID, &currentGeneration, &outcome); err != nil {
		return "", entitlementError(err)
	}
	result := EntitlementOutcome(outcome)
	switch result {
	case EntitlementRecorded:
		if currentID != verified.ID.String() || currentGeneration != verified.Generation {
			return "", ErrEntitlementUnavailable
		}
		if err := appendEntitlementEvidence(ctx, tx, verified, change, event, outbox); err != nil {
			return "", errors.Join(ErrEntitlementUnavailable, err)
		}
	case EntitlementReplayed:
		if currentGeneration != verified.Generation {
			return "", ErrEntitlementUnavailable
		}
	case EntitlementSuperseded:
		if currentGeneration <= verified.Generation {
			return "", ErrEntitlementUnavailable
		}
	default:
		return "", ErrEntitlementUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return "", errors.Join(ErrEntitlementUnavailable, err)
	}
	committed = true
	return result, nil
}

func entitlementError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "P0002", "42501", "23505", "22023", "23514":
			return errors.Join(ErrEntitlementRejected, err)
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrEntitlementRejected
	}
	return errors.Join(ErrEntitlementUnavailable, err)
}

func appendEntitlementEvidence(ctx context.Context, tx accountSessionTransaction, verified entitlement.Entitlement,
	change, event, outbox publicid.ID) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_deployment_stream_head($1::UUID)`, verified.DeploymentID.String()).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return ErrEntitlementUnavailable
	}
	// Only non-secret identity is logged: ID, profile, generation, limits,
	// capability digest, signer key ID and validity window.
	payload, err := json.Marshal(struct {
		EntitlementID       string `json:"entitlement_id"`
		Profile             string `json:"profile"`
		Generation          int64  `json:"generation"`
		MaxActive           int64  `json:"max_active_workspaces"`
		MaxOwned            int64  `json:"max_owned_workspaces_per_account"`
		CapabilitiesSHA256  string `json:"capabilities_sha256"`
		SignerKeyID         string `json:"signer_key_id"`
		NotBefore           string `json:"not_before"`
		ExpiresAt           string `json:"expires_at"`
		GraceSeconds        int64  `json:"grace_seconds"`
		ContentSHA256Prefix string `json:"content_sha256_prefix"`
	}{verified.ID.String(), string(verified.Profile), verified.Generation, verified.Limits.MaxActiveWorkspaces,
		verified.Limits.MaxOwnedWorkspacesPerAccount, verified.CapabilitiesSHA256(), verified.KeyID,
		verified.NotBefore.UTC().Format(time.RFC3339), verified.ExpiresAt.UTC().Format(time.RFC3339),
		int64(verified.Grace / time.Second), hexPrefix(verified.ContentSHA256[:])})
	if err != nil {
		return err
	}
	after := sha256.Sum256(payload)
	var previousHash [32]byte
	copy(previousHash[:], previous)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: event, ChangeID: change,
		AggregateKind: "deployment_entitlement", AggregateID: verified.ID, AggregateVersion: 1,
		Action: "deployment_entitlement.recorded", Permission: "system.entitlement", CorrelationID: change,
		AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: "deployment_entitlement.recorded", OutboxPayloadHash: sha256.Sum256(payload),
	})
	if err != nil {
		return err
	}
	var appended int64
	return tx.QueryRow(ctx, appendDeploymentEntitlementEvidenceSQL, streamID, event.String(), outbox.String(), sequence,
		previousHash[:], eventHash[:], verified.ID.String(), change.String(), after[:], payload).Scan(&appended)
}

func hexPrefix(digest []byte) string {
	const hexDigits = "0123456789abcdef"
	encoded := make([]byte, 0, 16)
	for _, value := range digest[:8] {
		encoded = append(encoded, hexDigits[value>>4], hexDigits[value&15])
	}
	return string(encoded)
}
