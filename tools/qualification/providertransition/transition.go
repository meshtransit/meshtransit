package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const (
	transitionTimeout        = 30 * time.Second
	transitionCleanupTimeout = 2 * time.Second
	transitionMutationCount  = 4
)

var (
	previousScopes = []string{"openid"}
	currentScopes  = []string{"openid", "federated:id"}
)

type transitionState struct {
	deploymentInternalID    int64
	deploymentProfile       string
	deploymentRecoveryState string
	deploymentState         string
	providerInternalID      int64
	providerGeneration      int64
	providerRecoveryState   string
	providerState           string
	providerProtocol        string
	providerAuthorityKind   string
	providerVersion         int64
	generationInternalID    int64
	generationPublicID      string
	generation              int64
	trustConfigurationHash  []byte
	generationRecoveryMode  string
	generationValidUntil    *time.Time
	generationState         string
	generationVersion       int64
	clientInternalID        int64
	clientKind              string
	clientAllowedFlows      []string
	clientAllowedScopes     []string
	clientState             string
	clientVersion           int64
	actorInternalID         int64
	actorKind               string
	actorState              string
	activeRouteCount        int64
}

type transitionIDs struct {
	change      publicid.ID
	generation  publicid.ID
	auditEvent  publicid.ID
	outboxEvent publicid.ID
}

type transitionResult struct {
	providerGeneration int64
	providerVersion    int64
	clientVersion      int64
}

type transitionRowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func executeTransition(
	ctx context.Context,
	spec transitionSpec,
	database databaseSettings,
) (output transitionOutput, resultErr error) {
	if ctx == nil || !spec.isValid() {
		return transitionOutput{}, errInvalidInput
	}
	operationCtx, cancel := context.WithTimeout(ctx, transitionTimeout)
	defer cancel()

	connection, err := openAdminDatabase(operationCtx, database)
	if err != nil {
		return transitionOutput{}, err
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.WithoutCancel(operationCtx),
			transitionCleanupTimeout,
		)
		defer cleanupCancel()
		resultErr = errors.Join(resultErr, connection.Close(cleanupCtx))
	}()

	accessMode := pgx.ReadWrite
	stateQuery := lockTransitionStateSQL
	if spec.mode == transitionModeDryRun {
		accessMode = pgx.ReadOnly
		stateQuery = loadTransitionStateSQL
	}
	transaction, err := connection.BeginTx(operationCtx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: accessMode,
	})
	if err != nil {
		return transitionOutput{}, fmt.Errorf("begin provider transition: %w", err)
	}
	transactionClosed := false
	defer func() {
		if transactionClosed {
			return
		}
		rollbackCtx, rollbackCancel := context.WithTimeout(
			context.WithoutCancel(operationCtx),
			transitionCleanupTimeout,
		)
		defer rollbackCancel()
		resultErr = errors.Join(resultErr, transaction.Rollback(rollbackCtx))
	}()
	if _, err := transaction.Exec(operationCtx, configureTransitionSQL); err != nil {
		return transitionOutput{}, fmt.Errorf("configure provider transition: %w", err)
	}
	state, err := loadTransitionState(operationCtx, transaction, stateQuery, spec)
	if err != nil {
		return transitionOutput{}, err
	}
	if !state.matches(spec) {
		return transitionOutput{}, errInvalidInput
	}
	if spec.mode == transitionModeDryRun {
		if err := transaction.Commit(operationCtx); err != nil {
			return transitionOutput{}, fmt.Errorf("finish provider transition dry-run: %w", err)
		}
		transactionClosed = true
		return newTransitionOutput("validated", spec, state, transitionIDs{}), nil
	}

	ids, err := newTransitionIDs(publicid.New)
	if err != nil {
		return transitionOutput{}, err
	}
	if _, err := transaction.Exec(operationCtx, setTransitionChangeSQL, ids.change.String()); err != nil {
		return transitionOutput{}, fmt.Errorf("set provider transition change: %w", err)
	}
	result, err := mutateProviderTransition(operationCtx, transaction, spec, state, ids)
	if err != nil {
		return transitionOutput{}, err
	}
	if err := appendTransitionEvidence(
		operationCtx,
		transaction,
		spec,
		state,
		result,
		ids,
	); err != nil {
		return transitionOutput{}, err
	}
	if err := verifyTransitionEvidence(operationCtx, transaction, ids.change); err != nil {
		return transitionOutput{}, err
	}
	if err := transaction.Commit(operationCtx); err != nil {
		return transitionOutput{}, fmt.Errorf("commit provider transition: %w", err)
	}
	transactionClosed = true
	return newTransitionOutput("applied", spec, state, ids), nil
}

func loadTransitionState(
	ctx context.Context,
	database transitionRowQuerier,
	query string,
	spec transitionSpec,
) (transitionState, error) {
	if ctx == nil || database == nil || query == "" || !spec.isValid() {
		return transitionState{}, errInvalidInput
	}
	var state transitionState
	err := database.QueryRow(
		ctx,
		query,
		spec.deploymentID.String(),
		spec.providerID.String(),
		spec.clientID.String(),
		spec.actorPrincipalID.String(),
	).Scan(
		&state.deploymentInternalID,
		&state.deploymentProfile,
		&state.deploymentRecoveryState,
		&state.deploymentState,
		&state.providerInternalID,
		&state.providerGeneration,
		&state.providerRecoveryState,
		&state.providerState,
		&state.providerProtocol,
		&state.providerAuthorityKind,
		&state.providerVersion,
		&state.generationInternalID,
		&state.generationPublicID,
		&state.generation,
		&state.trustConfigurationHash,
		&state.generationRecoveryMode,
		&state.generationValidUntil,
		&state.generationState,
		&state.generationVersion,
		&state.clientInternalID,
		&state.clientKind,
		&state.clientAllowedFlows,
		&state.clientAllowedScopes,
		&state.clientState,
		&state.clientVersion,
		&state.actorInternalID,
		&state.actorKind,
		&state.actorState,
		&state.activeRouteCount,
	)
	if err != nil {
		return transitionState{}, fmt.Errorf("load exact provider transition state: %w", err)
	}
	return state, nil
}

func (state transitionState) matches(spec transitionSpec) bool {
	_, generationIDErr := publicid.Parse(state.generationPublicID)
	return state.deploymentInternalID > 0 && state.deploymentProfile != "" &&
		state.deploymentRecoveryState == "verified" && state.deploymentState == "active" &&
		state.providerInternalID > 0 && state.providerGeneration == spec.expectedGeneration &&
		state.providerRecoveryState == "verified" && state.providerState == "active" &&
		state.providerProtocol == "oidc" && state.providerAuthorityKind == "managed_oidc" &&
		state.providerVersion == spec.expectedProviderVersion &&
		state.generationInternalID > 0 && generationIDErr == nil &&
		state.generation == spec.expectedGeneration && len(state.trustConfigurationHash) == 32 &&
		(state.generationRecoveryMode == "initial" ||
			state.generationRecoveryMode == "continuous") &&
		state.generationValidUntil == nil &&
		state.generationState == "current" &&
		state.generationVersion == spec.expectedGenerationVersion &&
		state.clientInternalID > 0 && state.clientKind == "confidential" &&
		slices.Contains(state.clientAllowedFlows, "authorization_code") &&
		slices.Equal(state.clientAllowedScopes, previousScopes) &&
		state.clientState == "active" && state.clientVersion == spec.expectedClientVersion &&
		state.actorInternalID > 0 && state.actorKind == "account" && state.actorState == "active" &&
		state.activeRouteCount > 0
}

func mutateProviderTransition(
	ctx context.Context,
	transaction pgx.Tx,
	spec transitionSpec,
	state transitionState,
	ids transitionIDs,
) (transitionResult, error) {
	var supersededVersion int64
	if err := transaction.QueryRow(
		ctx,
		supersedeProviderGenerationSQL,
		state.generationInternalID,
		state.generationPublicID,
		spec.expectedGeneration,
		spec.expectedGenerationVersion,
	).Scan(&supersededVersion); err != nil || supersededVersion != spec.expectedGenerationVersion+1 {
		return transitionResult{}, fmt.Errorf("supersede provider generation: %w", errorOrInvalid(err))
	}
	evidenceReference := "meshtransit/provider-client-scope-transition/" + ids.change.String()
	var newGenerationVersion int64
	if err := transaction.QueryRow(
		ctx,
		insertProviderGenerationSQL,
		ids.generation.String(),
		state.deploymentInternalID,
		state.providerInternalID,
		spec.expectedGeneration+1,
		state.trustConfigurationHash,
		evidenceReference,
	).Scan(&newGenerationVersion); err != nil || newGenerationVersion != 1 {
		return transitionResult{}, fmt.Errorf("insert provider generation: %w", errorOrInvalid(err))
	}
	var result transitionResult
	if err := transaction.QueryRow(
		ctx,
		advanceProviderGenerationSQL,
		state.providerInternalID,
		spec.providerID.String(),
		spec.expectedGeneration,
		spec.expectedProviderVersion,
	).Scan(&result.providerGeneration, &result.providerVersion); err != nil ||
		result.providerGeneration != spec.expectedGeneration+1 ||
		result.providerVersion != spec.expectedProviderVersion+1 {
		return transitionResult{}, fmt.Errorf("advance provider generation: %w", errorOrInvalid(err))
	}
	if err := transaction.QueryRow(
		ctx,
		updateProviderClientScopesSQL,
		state.clientInternalID,
		spec.clientID.String(),
		spec.expectedClientVersion,
	).Scan(&result.clientVersion); err != nil || result.clientVersion != spec.expectedClientVersion+1 {
		return transitionResult{}, fmt.Errorf("update provider-client scopes: %w", errorOrInvalid(err))
	}
	return result, nil
}

func verifyTransitionEvidence(
	ctx context.Context,
	transaction pgx.Tx,
	changeID publicid.ID,
) error {
	var mutationCount, auditCount, outboxCount int64
	if err := transaction.QueryRow(
		ctx,
		verifyTransitionEvidenceSQL,
		changeID.String(),
	).Scan(&mutationCount, &auditCount, &outboxCount); err != nil {
		return fmt.Errorf("verify provider transition evidence: %w", err)
	}
	if mutationCount != transitionMutationCount || auditCount != 1 || outboxCount != 1 {
		return errors.New("provider transition evidence is incomplete")
	}
	return nil
}

func newTransitionIDs(generate func() (publicid.ID, error)) (transitionIDs, error) {
	if generate == nil {
		return transitionIDs{}, errInvalidInput
	}
	values := make([]publicid.ID, 4)
	for index := range values {
		id, err := generate()
		if err != nil {
			return transitionIDs{}, fmt.Errorf("generate provider transition identity: %w", err)
		}
		values[index] = id
	}
	if !allDistinctIDs(values) {
		return transitionIDs{}, errInvalidInput
	}
	return transitionIDs{
		change: values[0], generation: values[1], auditEvent: values[2], outboxEvent: values[3],
	}, nil
}

func allDistinctIDs(ids []publicid.ID) bool {
	for index, id := range ids {
		if !id.IsValid() || slices.Contains(ids[:index], id) {
			return false
		}
	}
	return true
}

func newTransitionOutput(
	operation string,
	spec transitionSpec,
	state transitionState,
	ids transitionIDs,
) transitionOutput {
	output := transitionOutput{
		Operation:  operation,
		ProviderID: spec.providerID.String(), ClientID: spec.clientID.String(),
		PreviousGeneration:      spec.expectedGeneration,
		CurrentGeneration:       spec.expectedGeneration + 1,
		PreviousProviderVersion: spec.expectedProviderVersion,
		CurrentProviderVersion:  spec.expectedProviderVersion + 1,
		PreviousClientVersion:   spec.expectedClientVersion,
		CurrentClientVersion:    spec.expectedClientVersion + 1,
		PreviousScopes:          slices.Clone(state.clientAllowedScopes),
		CurrentScopes:           slices.Clone(currentScopes),
	}
	if ids.change.IsValid() {
		output.ChangeID = ids.change.String()
		output.GenerationID = ids.generation.String()
		output.AuditEventID = ids.auditEvent.String()
		output.OutboxEventID = ids.outboxEvent.String()
	}
	return output
}

func errorOrInvalid(err error) error {
	if err != nil {
		return err
	}
	return errInvalidInput
}
