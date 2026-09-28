package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	applyTimeout        = 30 * time.Second
	applyCleanupTimeout = 2 * time.Second
)

type applyResult struct {
	sourceProviderVersion  int64
	migratedSubjects       int64
	revokedSessions        int64
	failedAuthTransactions int64
}

func executeApply(
	ctx context.Context,
	spec planSpec,
	database databaseSettings,
) (output planOutput, resultErr error) {
	if ctx == nil || spec.mode != transitionModeApply || !spec.valid() {
		return planOutput{}, errInvalidInput
	}
	operationCtx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()
	connection, err := openAdminDatabase(operationCtx, database)
	if err != nil {
		return planOutput{}, err
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.WithoutCancel(operationCtx),
			applyCleanupTimeout,
		)
		defer cleanupCancel()
		resultErr = errors.Join(resultErr, connection.Close(cleanupCtx))
	}()
	transaction, err := connection.BeginTx(operationCtx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return planOutput{}, fmt.Errorf("begin identity subject transition apply: %w", err)
	}
	transactionClosed := false
	defer func() {
		if transactionClosed {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.WithoutCancel(operationCtx),
			applyCleanupTimeout,
		)
		defer cleanupCancel()
		resultErr = errors.Join(resultErr, transaction.Rollback(cleanupCtx))
	}()
	if _, err := transaction.Exec(operationCtx, configurePlanSQL); err != nil {
		return planOutput{}, fmt.Errorf("configure identity subject transition apply: %w", err)
	}
	if err := acquireApplyFence(operationCtx, transaction, spec); err != nil {
		return planOutput{}, err
	}
	snapshot, err := validateSnapshot(
		operationCtx,
		transaction,
		lockAuthorityStateSQL,
		spec,
	)
	if err != nil {
		return planOutput{}, err
	}
	if _, err := transaction.Exec(
		operationCtx,
		setApplyChangeSQL,
		spec.migrationID.String(),
	); err != nil {
		return planOutput{}, fmt.Errorf("set identity subject transition change: %w", err)
	}
	result, err := mutateApply(operationCtx, transaction, spec, snapshot)
	if err != nil {
		return planOutput{}, err
	}
	if err := appendApplyEvidence(operationCtx, transaction, spec, snapshot, result); err != nil {
		return planOutput{}, err
	}
	expectedMutations := int64(1+2*len(spec.mappings)) +
		result.revokedSessions + result.failedAuthTransactions
	if err := verifyApplyEvidence(
		operationCtx,
		transaction,
		spec,
		expectedMutations,
	); err != nil {
		return planOutput{}, err
	}
	if err := transaction.Commit(operationCtx); err != nil {
		return planOutput{}, fmt.Errorf("commit identity subject transition apply: %w", err)
	}
	transactionClosed = true
	return planOutput{
		SchemaVersion: manifestSchemaVersion, Operation: "applied",
		MigrationID: spec.migrationID.String(), ManifestSHA256: spec.manifestSHA256,
		DeploymentID:             spec.deploymentID.String(),
		SourceProviderID:         spec.sourceProviderID.String(),
		TargetProviderID:         spec.targetProviderID.String(),
		MappingCount:             len(spec.mappings),
		ActiveSourceSubjectCount: result.migratedSubjects,
		ActiveSessionCount:       result.revokedSessions,
		OpenAuthTransactionCount: result.failedAuthTransactions,
		ChangeID:                 spec.migrationID.String(),
		AuditEventID:             spec.auditEventID.String(),
		OutboxEventID:            spec.outboxEventID.String(),
		SourceProviderVersion:    result.sourceProviderVersion,
	}, nil
}

func acquireApplyFence(ctx context.Context, transaction pgx.Tx, spec planSpec) error {
	var sourceInternalID int64
	if err := transaction.QueryRow(
		ctx,
		lockSourceProviderFenceSQL,
		spec.deploymentID.String(),
		spec.sourceProviderID.String(),
	).Scan(&sourceInternalID); err != nil || sourceInternalID <= 0 {
		return fmt.Errorf("lock source provider maintenance fence: %w", errorOrInvalid(err))
	}
	if _, err := transaction.Exec(ctx, lockApplyTablesSQL); err != nil {
		return fmt.Errorf("lock identity transition authority tables: %w", err)
	}
	return nil
}

func mutateApply(
	ctx context.Context,
	transaction pgx.Tx,
	spec planSpec,
	snapshot validatedSnapshot,
) (applyResult, error) {
	var result applyResult
	if err := transaction.QueryRow(
		ctx,
		suspendSourceProviderSQL,
		snapshot.authority.source.internalID,
		spec.sourceProviderID.String(),
		spec.manifest.Source.ExpectedGeneration,
		spec.manifest.Source.ExpectedProviderVersion,
	).Scan(&result.sourceProviderVersion); err != nil ||
		result.sourceProviderVersion != spec.manifest.Source.ExpectedProviderVersion+1 {
		return applyResult{}, fmt.Errorf("suspend source identity provider: %w", errorOrInvalid(err))
	}

	planned := make(map[string]plannedMapping, len(spec.mappings))
	for _, mapping := range spec.mappings {
		planned[mapping.sourceSubjectID.String()] = mapping
	}
	for _, source := range snapshot.subjects {
		mapping, found := planned[source.publicID]
		if !found {
			return applyResult{}, errInvalidInput
		}
		sourceDigest := mapping.sourceDigest.Bytes()
		var sourceVersion int64
		if err := transaction.QueryRow(
			ctx,
			unlinkSourceSubjectSQL,
			source.internalID,
			source.publicID,
			snapshot.authority.deploymentInternalID,
			snapshot.authority.source.internalID,
			source.principalInternalID,
			mapping.sourceDigest.Algorithm(),
			mapping.sourceDigest.KeyID().String(),
			sourceDigest[:],
			mapping.expectedClaimsRevision,
			mapping.expectedSourceVersion,
		).Scan(&sourceVersion); err != nil ||
			sourceVersion != mapping.expectedSourceVersion+1 {
			return applyResult{}, fmt.Errorf("unlink source identity subject: %w", errorOrInvalid(err))
		}
		targetDigest := mapping.targetDigest.Bytes()
		var targetVersion int64
		if err := transaction.QueryRow(
			ctx,
			insertTargetSubjectSQL,
			mapping.targetSubjectID.String(),
			snapshot.authority.deploymentInternalID,
			snapshot.authority.target.internalID,
			source.principalInternalID,
			mapping.targetDigest.Algorithm(),
			mapping.targetDigest.KeyID().String(),
			targetDigest[:],
			mapping.expectedClaimsRevision,
		).Scan(&targetVersion); err != nil || targetVersion != 1 {
			return applyResult{}, fmt.Errorf("insert target identity subject: %w", errorOrInvalid(err))
		}
		result.migratedSubjects++
		delete(planned, source.publicID)
	}
	if len(planned) != 0 || result.migratedSubjects != int64(len(spec.mappings)) {
		return applyResult{}, errInvalidInput
	}

	sessions, err := transaction.Exec(
		ctx,
		revokeSourceSessionsSQL,
		snapshot.authority.deploymentInternalID,
		snapshot.authority.source.internalID,
	)
	if err != nil {
		return applyResult{}, fmt.Errorf("revoke source identity sessions: %w", err)
	}
	result.revokedSessions = sessions.RowsAffected()
	if result.revokedSessions != snapshot.activeSessions {
		return applyResult{}, errInvalidInput
	}
	auth, err := transaction.Exec(
		ctx,
		failSourceAuthTransactionsSQL,
		snapshot.authority.deploymentInternalID,
		snapshot.authority.source.internalID,
	)
	if err != nil {
		return applyResult{}, fmt.Errorf("fail source authentication transactions: %w", err)
	}
	result.failedAuthTransactions = auth.RowsAffected()
	if result.failedAuthTransactions != snapshot.openAuthTransactions {
		return applyResult{}, errInvalidInput
	}
	return result, nil
}

func verifyApplyEvidence(
	ctx context.Context,
	transaction pgx.Tx,
	spec planSpec,
	expectedMutations int64,
) error {
	var mutations, auditEvents, outboxEvents int64
	if err := transaction.QueryRow(
		ctx,
		verifyApplyEvidenceSQL,
		spec.migrationID.String(),
	).Scan(&mutations, &auditEvents, &outboxEvents); err != nil {
		return fmt.Errorf("verify identity subject transition evidence: %w", err)
	}
	if expectedMutations <= 0 || mutations != expectedMutations ||
		auditEvents != 1 || outboxEvents != 1 {
		return errors.New("identity subject transition evidence is incomplete")
	}
	return nil
}

func errorOrInvalid(err error) error {
	if err != nil {
		return err
	}
	return errInvalidInput
}
