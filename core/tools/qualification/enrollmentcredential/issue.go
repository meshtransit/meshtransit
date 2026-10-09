package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	issueTimeout        = 30 * time.Second
	issueCleanupTimeout = 2 * time.Second

	issueAuditAction = "qualification.enrollment_credential.issued"
	issuePermission  = "system.bootstrap"
	issueEventClass  = "qualification.enrollment_credential.issued"
)

type issueScope struct {
	deploymentInternalID     int64
	deploymentProfile        string
	recoveryEpoch            int64
	deploymentState          string
	deploymentRecoveryState  string
	principalInternalID      int64
	principalKind            string
	principalState           string
	principalGeneration      int64
	workspaceInternalID      int64
	workspaceState           string
	workspaceGeneration      int64
	networkInternalID        int64
	networkState             string
	networkGeneration        int64
	networkRevision          int64
	profileInternalID        int64
	profileCreatorInternalID int64
	profileState             string
	nodeLifetimeSeconds      int64
	ephemeralMode            string
	credentialUsePolicy      string
	credentialMaxUses        int64
	profileVersion           int64
	profileDeleted           bool
}

func (scope issueScope) isValid() bool {
	return validPositiveInt64(scope.deploymentInternalID) &&
		scope.deploymentProfile == "self_hosted" && validPositiveInt64(scope.recoveryEpoch) &&
		scope.deploymentState == "active" && scope.deploymentRecoveryState == "verified" &&
		validPositiveInt64(scope.principalInternalID) && scope.principalKind == "account" &&
		scope.principalState == "active" && validPositiveInt64(scope.principalGeneration) &&
		validPositiveInt64(scope.workspaceInternalID) && scope.workspaceState == "active" &&
		validPositiveInt64(scope.workspaceGeneration) && validPositiveInt64(scope.networkInternalID) &&
		scope.networkState == "active" && validPositiveInt64(scope.networkGeneration) &&
		validPositiveInt64(scope.networkRevision) &&
		validPositiveInt64(scope.profileInternalID) &&
		scope.profileCreatorInternalID == scope.principalInternalID &&
		scope.profileState == "active" && validPositiveInt64(scope.nodeLifetimeSeconds) &&
		scope.ephemeralMode == "persistent" && scope.credentialUsePolicy == "bounded" &&
		scope.credentialMaxUses == 1 && validPositiveInt64(scope.profileVersion) &&
		!scope.profileDeleted
}

type issueIDs struct {
	credential publicid.ID
	change     publicid.ID
	event      publicid.ID
	outbox     publicid.ID
}

func (ids issueIDs) isValid() bool {
	values := []publicid.ID{ids.credential, ids.change, ids.event, ids.outbox}
	for index, value := range values {
		if !value.IsValid() {
			return false
		}
		for other := index + 1; other < len(values); other++ {
			if value == values[other] {
				return false
			}
		}
	}
	return true
}

type publicIDGenerator func() (publicid.ID, error)

func newIssueIDs(generate publicIDGenerator) (issueIDs, error) {
	if generate == nil {
		return issueIDs{}, errInvalidInput
	}
	values := make([]publicid.ID, 4)
	for index := range values {
		id, err := generate()
		if err != nil {
			return issueIDs{}, fmt.Errorf("generate qualification public id: %w", err)
		}
		values[index] = id
	}
	ids := issueIDs{
		credential: values[0],
		change:     values[1],
		event:      values[2],
		outbox:     values[3],
	}
	if !ids.isValid() {
		return issueIDs{}, errInvalidInput
	}
	return ids, nil
}

type issueAuditPayload struct {
	AuditReason       string `json:"audit_reason"`
	QualificationOnly bool   `json:"qualification_only"`
	CredentialID      string `json:"credential_public_id"`
	ProfileID         string `json:"profile_public_id"`
	MaximumUses       int64  `json:"maximum_uses"`
	ExpiresAt         string `json:"expires_at"`
}

type issueOutboxPayload struct {
	CredentialID string `json:"credential_public_id"`
}

func executeIssue(
	ctx context.Context,
	spec issueSpec,
	database databaseSettings,
	entropy io.Reader,
) (output issueOutput, resultErr error) {
	if ctx == nil || !spec.isValid() || entropy == nil {
		return issueOutput{}, errInvalidInput
	}
	operationCtx, cancel := context.WithTimeout(ctx, issueTimeout)
	defer cancel()

	connection, err := openAdminDatabase(operationCtx, database)
	if err != nil {
		return issueOutput{}, err
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.WithoutCancel(operationCtx),
			issueCleanupTimeout,
		)
		defer cleanupCancel()
		resultErr = errors.Join(resultErr, connection.Close(cleanupCtx))
	}()

	initialScope, err := loadInitialIssueScope(operationCtx, connection, spec)
	if err != nil {
		return issueOutput{}, err
	}
	if !initialScope.isValid() {
		return issueOutput{}, errInvalidInput
	}
	ids, err := newIssueIDs(publicid.New)
	if err != nil {
		return issueOutput{}, err
	}
	credentialID, err := enrollment.ParseCredentialID(ids.credential.String())
	if err != nil {
		return issueOutput{}, errInvalidInput
	}
	digest, bearerFile, err := prepareCredential(
		spec,
		database,
		credentialID,
		initialScope.recoveryEpoch,
		entropy,
	)
	if err != nil {
		return issueOutput{}, err
	}
	keepBearer := false
	defer func() {
		if keepBearer {
			return
		}
		resultErr = errors.Join(resultErr, bearerFile.discard())
	}()

	transaction, err := connection.BeginTx(operationCtx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return issueOutput{}, fmt.Errorf("begin qualification issue transaction: %w", err)
	}
	transactionClosed := false
	defer func() {
		if transactionClosed {
			return
		}
		rollbackCtx, rollbackCancel := context.WithTimeout(
			context.WithoutCancel(operationCtx),
			issueCleanupTimeout,
		)
		defer rollbackCancel()
		resultErr = errors.Join(resultErr, transaction.Rollback(rollbackCtx))
	}()
	if _, err := transaction.Exec(operationCtx, configureIssueTransactionSQL); err != nil {
		return issueOutput{}, fmt.Errorf("configure qualification issue transaction: %w", err)
	}
	var scopedWorkspaceID int64
	var scopedNetworkID int64
	if err := transaction.QueryRow(
		operationCtx,
		setIssueScopeSQL,
		spec.scope.WorkspaceID().String(),
		spec.scope.NetworkID().String(),
	).Scan(&scopedWorkspaceID, &scopedNetworkID); err != nil {
		return issueOutput{}, fmt.Errorf("set qualification issue scope: %w", err)
	}
	lockedScope, err := loadIssueScope(operationCtx, transaction, lockIssueScopeSQL, spec)
	if err != nil {
		return issueOutput{}, err
	}
	if lockedScope != initialScope || !lockedScope.isValid() ||
		scopedWorkspaceID != lockedScope.workspaceInternalID ||
		scopedNetworkID != lockedScope.networkInternalID {
		return issueOutput{}, errInvalidInput
	}
	var usableAuthorities int64
	if err := transaction.QueryRow(
		operationCtx,
		countUsableEnrollmentAuthoritiesSQL,
		lockedScope.workspaceInternalID,
		lockedScope.networkInternalID,
		lockedScope.profileInternalID,
	).Scan(&usableAuthorities); err != nil {
		return issueOutput{}, fmt.Errorf("count usable enrollment credentials: %w", err)
	}
	if usableAuthorities != 0 {
		return issueOutput{}, errors.New("qualification enrollment profile already has usable authority")
	}
	var issuedAt time.Time
	if err := transaction.QueryRow(operationCtx, loadIssueTimeSQL).Scan(&issuedAt); err != nil {
		return issueOutput{}, fmt.Errorf("load qualification issue time: %w", err)
	}
	credential, err := buildCredential(spec, lockedScope, credentialID, issuedAt)
	if err != nil {
		return issueOutput{}, err
	}
	if _, err := transaction.Exec(operationCtx, setIssueChangeSQL, ids.change.String()); err != nil {
		return issueOutput{}, fmt.Errorf("set qualification authority change: %w", err)
	}
	digestBytes := digest.Bytes()
	fingerprint := digest.Fingerprint()
	var credentialVersion int64
	if err := transaction.QueryRow(
		operationCtx,
		insertCredentialSQL,
		credentialID.String(),
		lockedScope.workspaceInternalID,
		lockedScope.networkInternalID,
		lockedScope.profileInternalID,
		lockedScope.principalInternalID,
		digest.KeyID().String(),
		digestBytes[:],
		fingerprint[:],
		lockedScope.recoveryEpoch,
		credential.ValidFrom(),
		credential.ExpiresAt(),
	).Scan(&credentialVersion); err != nil {
		return issueOutput{}, fmt.Errorf("insert qualification enrollment credential: %w", err)
	}
	if credentialVersion != 1 {
		return issueOutput{}, errInvalidInput
	}
	if err := appendIssueEvidence(
		operationCtx,
		transaction,
		spec,
		lockedScope,
		ids,
		credential.ExpiresAt(),
	); err != nil {
		return issueOutput{}, err
	}
	if err := transaction.Commit(operationCtx); err != nil {
		return issueOutput{}, fmt.Errorf("commit qualification enrollment credential: %w", err)
	}
	transactionClosed = true
	if err := bearerFile.keep(); err != nil {
		return issueOutput{}, errors.New("finalize enrollment credential output")
	}
	keepBearer = true
	return issueOutput{
		CredentialID: credentialID.String(),
		ProfileID:    spec.profileID.String(),
		ExpiresAt:    credential.ExpiresAt(),
		MaximumUses:  1,
	}, nil
}

func loadInitialIssueScope(
	ctx context.Context,
	connection *pgx.Conn,
	spec issueSpec,
) (scope issueScope, resultErr error) {
	if ctx == nil || connection == nil || !spec.isValid() {
		return issueScope{}, errInvalidInput
	}
	transaction, err := connection.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return issueScope{}, fmt.Errorf("begin qualification preflight transaction: %w", err)
	}
	transactionClosed := false
	defer func() {
		if transactionClosed {
			return
		}
		rollbackCtx, rollbackCancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			issueCleanupTimeout,
		)
		defer rollbackCancel()
		resultErr = errors.Join(resultErr, transaction.Rollback(rollbackCtx))
	}()
	if _, err := transaction.Exec(ctx, configureIssueTransactionSQL); err != nil {
		return issueScope{}, fmt.Errorf("configure qualification preflight transaction: %w", err)
	}
	var scopedWorkspaceID int64
	var scopedNetworkID int64
	if err := transaction.QueryRow(
		ctx,
		setIssueScopeSQL,
		spec.scope.WorkspaceID().String(),
		spec.scope.NetworkID().String(),
	).Scan(&scopedWorkspaceID, &scopedNetworkID); err != nil {
		return issueScope{}, fmt.Errorf("set qualification preflight scope: %w", err)
	}
	scope, err = loadIssueScope(ctx, transaction, loadIssueScopeSQL, spec)
	if err != nil {
		return issueScope{}, err
	}
	if scopedWorkspaceID != scope.workspaceInternalID ||
		scopedNetworkID != scope.networkInternalID {
		return issueScope{}, errInvalidInput
	}
	if err := transaction.Commit(ctx); err != nil {
		return issueScope{}, fmt.Errorf("commit qualification preflight transaction: %w", err)
	}
	transactionClosed = true

	return scope, nil
}

type issueScopeQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadIssueScope(
	ctx context.Context,
	querier issueScopeQuerier,
	query string,
	spec issueSpec,
) (issueScope, error) {
	if ctx == nil || querier == nil || query == "" || !spec.isValid() {
		return issueScope{}, errInvalidInput
	}
	var scope issueScope
	if err := querier.QueryRow(
		ctx,
		query,
		spec.deploymentID.String(),
		spec.scope.WorkspaceID().String(),
		spec.scope.NetworkID().String(),
		spec.profileID.String(),
		spec.issuerPrincipal.String(),
	).Scan(
		&scope.deploymentInternalID,
		&scope.deploymentProfile,
		&scope.recoveryEpoch,
		&scope.deploymentState,
		&scope.deploymentRecoveryState,
		&scope.principalInternalID,
		&scope.principalKind,
		&scope.principalState,
		&scope.principalGeneration,
		&scope.workspaceInternalID,
		&scope.workspaceState,
		&scope.workspaceGeneration,
		&scope.networkInternalID,
		&scope.networkState,
		&scope.networkGeneration,
		&scope.networkRevision,
		&scope.profileInternalID,
		&scope.profileCreatorInternalID,
		&scope.profileState,
		&scope.nodeLifetimeSeconds,
		&scope.ephemeralMode,
		&scope.credentialUsePolicy,
		&scope.credentialMaxUses,
		&scope.profileVersion,
		&scope.profileDeleted,
	); err != nil {
		return issueScope{}, fmt.Errorf("load qualification enrollment scope: %w", err)
	}
	return scope, nil
}

func buildCredential(
	spec issueSpec,
	scope issueScope,
	credentialID enrollment.CredentialID,
	issuedAt time.Time,
) (enrollment.Credential, error) {
	if !spec.isValid() || !scope.isValid() || !credentialID.IsValid() || issuedAt.IsZero() {
		return enrollment.Credential{}, errInvalidInput
	}
	limit, err := enrollment.NewBoundedUseLimit(1)
	if err != nil {
		return enrollment.Credential{}, fmt.Errorf("construct single-use limit: %w", err)
	}
	profile, err := enrollment.NewProfile(enrollment.ProfileParams{
		ID:                 spec.profileID,
		Scope:              spec.scope,
		State:              enrollment.ProfileStateActive,
		NodeLifetime:       time.Duration(scope.nodeLifetimeSeconds) * time.Second,
		EphemeralMode:      enrollment.EphemeralModePersistent,
		CredentialUseLimit: limit,
	})
	if err != nil {
		return enrollment.Credential{}, fmt.Errorf("construct enrollment profile: %w", err)
	}
	credential, err := enrollment.NewCredential(enrollment.CredentialParams{
		ID:                  credentialID,
		ProfileID:           spec.profileID,
		IssuerID:            spec.issuerPrincipal,
		State:               enrollment.CredentialStateActive,
		UseLimit:            limit,
		IssuedRecoveryEpoch: scope.recoveryEpoch,
		ValidFrom:           issuedAt,
		ExpiresAt:           issuedAt.Add(spec.expiresIn),
	})
	if err != nil {
		return enrollment.Credential{}, fmt.Errorf("construct enrollment credential: %w", err)
	}
	if err := profile.ValidateCredential(credential); err != nil {
		return enrollment.Credential{}, fmt.Errorf("validate enrollment credential: %w", err)
	}
	return credential, nil
}

func appendIssueEvidence(
	ctx context.Context,
	transaction pgx.Tx,
	spec issueSpec,
	scope issueScope,
	ids issueIDs,
	expiresAt time.Time,
) error {
	if ctx == nil || transaction == nil || !spec.isValid() || !scope.isValid() ||
		!ids.isValid() || expiresAt.IsZero() {
		return errInvalidInput
	}
	var streamID int64
	var nextSequence int64
	var previousHashBytes []byte
	if err := transaction.QueryRow(
		ctx,
		lockIssueAuditStreamSQL,
	).Scan(&streamID, &nextSequence, &previousHashBytes); err != nil {
		return fmt.Errorf("lock qualification audit stream: %w", err)
	}
	if !validPositiveInt64(streamID) || !validPositiveInt64(nextSequence) ||
		len(previousHashBytes) != sha256.Size {
		return errInvalidInput
	}
	var previousHash [sha256.Size]byte
	copy(previousHash[:], previousHashBytes)
	auditPayload, err := json.Marshal(issueAuditPayload{
		AuditReason:       spec.auditReason,
		QualificationOnly: true,
		CredentialID:      ids.credential.String(),
		ProfileID:         spec.profileID.String(),
		MaximumUses:       1,
		ExpiresAt:         expiresAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return fmt.Errorf("encode qualification enrollment audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(issueOutboxPayload{
		CredentialID: ids.credential.String(),
	})
	if err != nil {
		return fmt.Errorf("encode qualification enrollment outbox payload: %w", err)
	}
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	afterSemanticHash := sha256.Sum256([]byte(
		ids.credential.String() + "\x00" + spec.profileID.String() + "\x00" +
			expiresAt.UTC().Format(time.RFC3339Nano) + "\x001",
	))
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:      previousHash,
		EventID:           ids.event,
		ChangeID:          ids.change,
		AggregateKind:     "enrollment_credential",
		AggregateID:       ids.credential,
		AggregateVersion:  1,
		NetworkRevision:   scope.networkRevision,
		ActorPrincipalID:  publicid.ID(spec.issuerPrincipal),
		Action:            issueAuditAction,
		Permission:        issuePermission,
		AfterSemanticHash: afterSemanticHash,
		AuditPayloadHash:  auditPayloadHash,
		OutboxEventClass:  issueEventClass,
		OutboxPayloadHash: outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash qualification enrollment audit event: %w", err)
	}
	var appendedSequence int64
	if err := transaction.QueryRow(
		ctx,
		appendIssueEvidenceSQL,
		streamID,
		ids.event.String(),
		ids.outbox.String(),
		nextSequence,
		previousHash[:],
		eventHash[:],
		ids.credential.String(),
		scope.networkRevision,
		spec.issuerPrincipal.String(),
		afterSemanticHash[:],
		auditPayload,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append qualification enrollment evidence: %w", err)
	}
	if appendedSequence != nextSequence {
		return errors.New("qualification enrollment audit sequence mismatch")
	}
	return nil
}
