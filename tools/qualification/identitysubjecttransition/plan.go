package main

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	planTimeout        = 30 * time.Second
	planCleanupTimeout = 2 * time.Second
)

type providerState struct {
	internalID             int64
	issuer                 string
	protocol               string
	authorityKind          string
	currentGeneration      int64
	generation             int64
	recoveryState          string
	state                  string
	version                int64
	trustHash              []byte
	generationRecoveryMode string
	generationValidUntil   *time.Time
	generationState        string
	generationVersion      int64
}

type authorityState struct {
	deploymentInternalID    int64
	deploymentProfile       string
	deploymentRecoveryState string
	deploymentState         string
	actorInternalID         int64
	actorKind               string
	actorState              string
	source                  providerState
	target                  providerState
}

type subjectRow struct {
	internalID          int64
	publicID            string
	principalInternalID int64
	principalID         string
	algorithm           string
	keyID               string
	digest              []byte
	claimsRevision      int64
	lastSeenAt          time.Time
	version             int64
}

type validatedSnapshot struct {
	authority            authorityState
	subjects             []subjectRow
	activeSessions       int64
	openAuthTransactions int64
}

func executeTransition(
	ctx context.Context,
	spec planSpec,
	database databaseSettings,
) (planOutput, error) {
	switch spec.mode {
	case transitionModePlan:
		return executePlan(ctx, spec, database)
	case transitionModeApply:
		return executeApply(ctx, spec, database)
	default:
		return planOutput{}, errInvalidInput
	}
}

func executePlan(
	ctx context.Context,
	spec planSpec,
	database databaseSettings,
) (output planOutput, resultErr error) {
	if ctx == nil || spec.mode != transitionModePlan || !spec.valid() {
		return planOutput{}, errInvalidInput
	}
	operationCtx, cancel := context.WithTimeout(ctx, planTimeout)
	defer cancel()
	connection, err := openAdminDatabase(operationCtx, database)
	if err != nil {
		return planOutput{}, err
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.WithoutCancel(operationCtx),
			planCleanupTimeout,
		)
		defer cleanupCancel()
		resultErr = errors.Join(resultErr, connection.Close(cleanupCtx))
	}()
	transaction, err := connection.BeginTx(operationCtx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return planOutput{}, fmt.Errorf("begin identity subject transition plan: %w", err)
	}
	transactionClosed := false
	defer func() {
		if transactionClosed {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.WithoutCancel(operationCtx),
			planCleanupTimeout,
		)
		defer cleanupCancel()
		resultErr = errors.Join(resultErr, transaction.Rollback(cleanupCtx))
	}()
	if _, err := transaction.Exec(operationCtx, configurePlanSQL); err != nil {
		return planOutput{}, fmt.Errorf("configure identity subject transition plan: %w", err)
	}
	snapshot, err := validateSnapshot(
		operationCtx,
		transaction,
		loadAuthorityStateSQL,
		spec,
	)
	if err != nil {
		return planOutput{}, err
	}
	if err := transaction.Commit(operationCtx); err != nil {
		return planOutput{}, fmt.Errorf("finish identity subject transition plan: %w", err)
	}
	transactionClosed = true
	return planOutput{
		SchemaVersion: manifestSchemaVersion, Operation: "validated",
		MigrationID: spec.migrationID.String(), ManifestSHA256: spec.manifestSHA256,
		DeploymentID:     spec.deploymentID.String(),
		SourceProviderID: spec.sourceProviderID.String(), TargetProviderID: spec.targetProviderID.String(),
		MappingCount: len(spec.mappings), ActiveSourceSubjectCount: int64(len(snapshot.subjects)),
		ActiveSessionCount:       snapshot.activeSessions,
		OpenAuthTransactionCount: snapshot.openAuthTransactions,
	}, nil
}

func validateSnapshot(
	ctx context.Context,
	transaction pgx.Tx,
	authorityQuery string,
	spec planSpec,
) (validatedSnapshot, error) {
	state, err := loadAuthorityState(ctx, transaction, authorityQuery, spec)
	if err != nil || !state.matches(spec) {
		return validatedSnapshot{}, errInvalidInput
	}
	subjects, err := loadActiveSourceSubjects(
		ctx,
		transaction,
		state.deploymentInternalID,
		state.source.internalID,
	)
	if err != nil || !subjectsMatchPlan(subjects, spec) {
		return validatedSnapshot{}, errInvalidInput
	}
	collision, err := targetCollision(
		ctx,
		transaction,
		state.deploymentInternalID,
		state.target.internalID,
		spec,
	)
	if err != nil || collision {
		return validatedSnapshot{}, errInvalidInput
	}
	activeSessions, err := countBoundedRows(
		ctx,
		transaction,
		loadActiveSessionIDsSQL,
		state.deploymentInternalID,
		state.source.internalID,
		maximumActiveSessions+1,
	)
	if err != nil || activeSessions != spec.manifest.ExpectedActiveSessions {
		return validatedSnapshot{}, errInvalidInput
	}
	openAuth, err := countBoundedRows(
		ctx,
		transaction,
		loadOpenAuthTransactionIDsSQL,
		state.deploymentInternalID,
		state.source.internalID,
		maximumOpenAuthTransactions+1,
	)
	if err != nil || openAuth != spec.manifest.ExpectedOpenAuthTransactions {
		return validatedSnapshot{}, errInvalidInput
	}
	return validatedSnapshot{
		authority: state, subjects: subjects,
		activeSessions: activeSessions, openAuthTransactions: openAuth,
	}, nil
}

func loadAuthorityState(
	ctx context.Context,
	transaction pgx.Tx,
	query string,
	spec planSpec,
) (authorityState, error) {
	if query == "" {
		return authorityState{}, errInvalidInput
	}
	var state authorityState
	err := transaction.QueryRow(
		ctx,
		query,
		spec.deploymentID.String(),
		spec.actorPrincipalID.String(),
		spec.sourceProviderID.String(),
		spec.targetProviderID.String(),
	).Scan(
		&state.deploymentInternalID,
		&state.deploymentProfile,
		&state.deploymentRecoveryState,
		&state.deploymentState,
		&state.actorInternalID,
		&state.actorKind,
		&state.actorState,
		&state.source.internalID,
		&state.source.issuer,
		&state.source.protocol,
		&state.source.authorityKind,
		&state.source.currentGeneration,
		&state.source.recoveryState,
		&state.source.state,
		&state.source.version,
		&state.source.generation,
		&state.source.trustHash,
		&state.source.generationRecoveryMode,
		&state.source.generationValidUntil,
		&state.source.generationState,
		&state.source.generationVersion,
		&state.target.internalID,
		&state.target.issuer,
		&state.target.protocol,
		&state.target.authorityKind,
		&state.target.currentGeneration,
		&state.target.recoveryState,
		&state.target.state,
		&state.target.version,
		&state.target.generation,
		&state.target.trustHash,
		&state.target.generationRecoveryMode,
		&state.target.generationValidUntil,
		&state.target.generationState,
		&state.target.generationVersion,
	)
	if err != nil {
		return authorityState{}, fmt.Errorf("load exact identity authority state: %w", err)
	}
	return state, nil
}

func (state authorityState) matches(spec planSpec) bool {
	return state.deploymentInternalID > 0 && state.deploymentProfile != "" &&
		state.deploymentRecoveryState == "verified" && state.deploymentState == "active" &&
		state.actorInternalID > 0 && state.actorKind == "account" && state.actorState == "active" &&
		state.source.matches(spec.manifest.Source) && state.target.matches(spec.manifest.Target)
}

func (state providerState) matches(reference providerReference) bool {
	validRecoveryMode := state.generationRecoveryMode == "initial" ||
		state.generationRecoveryMode == "continuous"
	validAuthorityKind := state.authorityKind == "managed_oidc" || state.authorityKind == "external_oidc"
	return state.internalID > 0 && state.issuer == reference.Issuer && state.protocol == "oidc" &&
		validAuthorityKind && state.currentGeneration == reference.ExpectedGeneration &&
		state.generation == reference.ExpectedGeneration &&
		state.recoveryState == "verified" && state.state == "active" &&
		state.version == reference.ExpectedProviderVersion && len(state.trustHash) == 32 &&
		validRecoveryMode && state.generationValidUntil == nil && state.generationState == "current" &&
		state.generationVersion == reference.ExpectedGenerationVersion
}

func loadActiveSourceSubjects(
	ctx context.Context,
	transaction pgx.Tx,
	deploymentInternalID int64,
	providerInternalID int64,
) ([]subjectRow, error) {
	rows, err := transaction.Query(
		ctx,
		loadActiveSourceSubjectsSQL,
		deploymentInternalID,
		providerInternalID,
		maximumMappings+1,
	)
	if err != nil {
		return nil, fmt.Errorf("load active source subjects: %w", err)
	}
	defer rows.Close()
	result := make([]subjectRow, 0)
	for rows.Next() {
		var row subjectRow
		if err := rows.Scan(
			&row.internalID,
			&row.publicID,
			&row.principalInternalID,
			&row.principalID,
			&row.algorithm,
			&row.keyID,
			&row.digest,
			&row.claimsRevision,
			&row.lastSeenAt,
			&row.version,
		); err != nil {
			return nil, fmt.Errorf("scan active source subject: %w", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active source subjects: %w", err)
	}
	return result, nil
}

func subjectsMatchPlan(rows []subjectRow, spec planSpec) bool {
	if len(rows) != len(spec.mappings) || len(rows) != int(spec.manifest.ExpectedActiveSourceSubjects) {
		return false
	}
	planned := make(map[string]plannedMapping, len(spec.mappings))
	for _, mapping := range spec.mappings {
		planned[mapping.sourceSubjectID.String()] = mapping
	}
	for _, row := range rows {
		mapping, found := planned[row.publicID]
		if !found || row.internalID <= 0 || row.principalInternalID <= 0 ||
			row.principalID != mapping.principalID.String() ||
			row.algorithm != mapping.sourceDigest.Algorithm() || row.keyID != mapping.sourceDigest.KeyID().String() ||
			row.claimsRevision != mapping.expectedClaimsRevision || row.version != mapping.expectedSourceVersion {
			return false
		}
		expected := mapping.sourceDigest.Bytes()
		if len(row.digest) != len(expected) || !hmac.Equal(row.digest, expected[:]) {
			return false
		}
		delete(planned, row.publicID)
	}
	return len(planned) == 0
}

func targetCollision(
	ctx context.Context,
	transaction pgx.Tx,
	deploymentInternalID int64,
	providerInternalID int64,
	spec planSpec,
) (bool, error) {
	principalIDs := make([]string, 0, len(spec.mappings))
	digests := make([][]byte, 0, len(spec.mappings))
	targetSubjectIDs := make([]string, 0, len(spec.mappings))
	for _, mapping := range spec.mappings {
		principalIDs = append(principalIDs, mapping.principalID.String())
		targetSubjectIDs = append(targetSubjectIDs, mapping.targetSubjectID.String())
		digest := mapping.targetDigest.Bytes()
		digests = append(digests, digest[:])
	}
	if len(principalIDs) != len(digests) || len(digests) != len(targetSubjectIDs) ||
		len(digests) == 0 {
		return false, errInvalidInput
	}
	var collision bool
	err := transaction.QueryRow(
		ctx,
		targetCollisionSQL,
		deploymentInternalID,
		providerInternalID,
		principalIDs,
		digests,
		spec.targetKey.ID().String(),
		targetSubjectIDs,
	).Scan(&collision)
	if err != nil {
		return false, fmt.Errorf("check target subject collision: %w", err)
	}
	return collision, nil
}

func countBoundedRows(
	ctx context.Context,
	transaction pgx.Tx,
	query string,
	deploymentInternalID int64,
	providerInternalID int64,
	limit int,
) (int64, error) {
	rows, err := transaction.Query(ctx, query, deploymentInternalID, providerInternalID, limit)
	if err != nil {
		return 0, fmt.Errorf("load bounded transition rows: %w", err)
	}
	defer rows.Close()
	var count int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil || id <= 0 {
			return 0, errInvalidInput
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate bounded transition rows: %w", err)
	}
	if count >= int64(limit) {
		return 0, errInvalidInput
	}
	return count, nil
}

func (spec planSpec) valid() bool {
	return spec.manifest.valid() && validSHA256(spec.manifestSHA256) &&
		(spec.mode == transitionModePlan || spec.mode == transitionModeApply) &&
		spec.migrationID.IsValid() && spec.deploymentID.IsValid() && spec.actorPrincipalID.IsValid() &&
		spec.auditEventID.IsValid() && spec.outboxEventID.IsValid() &&
		spec.sourceProviderID.IsValid() && spec.targetProviderID.IsValid() &&
		spec.sourceProviderID != spec.targetProviderID &&
		spec.sourceKey.ID().String() == spec.manifest.Source.SubjectKeyID &&
		spec.targetKey.ID().String() == spec.manifest.Target.SubjectKeyID &&
		len(spec.mappings) == len(spec.manifest.Mappings)
}
