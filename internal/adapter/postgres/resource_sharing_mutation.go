package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

const (
	resourceSharingCreateOperation   = "resource_sharing.offer.create"
	resourceSharingDecideOperation   = "resource_sharing.offer.decide"
	resourceSharingActivateOperation = "resource_sharing.contract.activate"
	resourceSharingRevokeOperation   = "resource_sharing.contract.revoke"
	// #nosec G101 -- this is a public hash domain-separation label, not credential material.
	resourceSharingTokenDomain = "meshtransit/resource-sharing/offer-token/v1\x00"
)

type resourceSharingMutationIDs struct {
	changeID            publicid.ID
	idempotencyRecordID publicid.ID
	providerAuditID     publicid.ID
	providerOutboxID    publicid.ID
	consumerAuditID     publicid.ID
	consumerOutboxID    publicid.ID
	exportID            sharing.ExportID
	offerID             sharing.OfferID
	contractID          sharing.ContractID
	importedResourceID  sharing.ImportedResourceID
	constraintIDs       []publicid.ID
}

type resourceSharingScopeLocator struct {
	provider resourceSharingNetworkState
	consumer resourceSharingNetworkState
	offerID  sharing.OfferID
}

type resourceSharingMutationRevisions struct {
	providerNetwork int64
	providerSharing int64
	consumerNetwork int64
	consumerSharing int64
	importedVersion int64
}

// CreateOffer commits one provider-owned export and targeted offer atomically.
func (store *ResourceSharingStore) CreateOffer(
	ctx context.Context,
	command sharing.CreateOffer,
	evaluatedAt time.Time,
) (_ sharing.MutationResult, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		evaluatedAt.IsZero() || !command.ExpiresAt().After(evaluatedAt) ||
		command.ExpiresAt().After(evaluatedAt.Add(30*24*time.Hour)) ||
		!validResourceSharingOptions(store.options) {
		return sharing.MutationResult{}, sharing.ErrInvalidManagementRequest
	}
	provider, _, err := store.resolveResourceSharingPreflight(ctx, command.ProviderScope())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	consumer, consumerHead, err := store.resolveResourceSharingPreflight(ctx, command.ConsumerScope())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	ids, err := newResourceSharingMutationIDs(len(command.MaximumTraffic().Constraints()), false)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	token, nonceDigest, err := resourceSharingOfferToken(command.IdempotencyEvidence())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	requestHash, err := resourceSharingCreateHash(command)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	transaction, err := store.begin(ctx)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceSharing(transaction))
		}
	}()
	localState, err := setResourceSharingScope(ctx, transaction, command.ProviderScope())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if !sameResourceSharingInternalScope(localState, provider) {
		return sharing.MutationResult{}, sharing.ErrConflict
	}
	provider = localState
	authorizationEvidence, err := authorizeResourceSharing(
		ctx,
		transaction,
		command.AccountSession(),
		command.ProviderScope(),
		authorization.PermissionShareOffer,
		evaluatedAt,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	binding, err := readResourceSharingBinding(ctx, transaction, command.ProviderScope(), command.ResourceID())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	record, replay, err := store.claimResourceSharingIdempotency(
		ctx,
		transaction,
		command.AccountSession().PrincipalID().String(),
		resourceSharingCreateOperation,
		command.IdempotencyEvidence(),
		requestHash,
		ids.idempotencyRecordID,
		evaluatedAt,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if replay != nil {
		result, err := replayResourceSharingResult(
			ctx, transaction, command.ProviderScope(), *replay, token, true,
		)
		if err != nil {
			return sharing.MutationResult{}, err
		}
		if err := transaction.Commit(ctx); err != nil {
			return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
		}
		closed = true
		return result, nil
	}
	locator := resourceSharingScopeLocator{provider: provider, consumer: consumer, offerID: ids.offerID}
	providerHead, err := readResourceSharingAuditHead(ctx, transaction)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	auditHeads := map[network.Scope]resourceAuthorityAuditHead{
		provider.scope: providerHead,
		consumer.scope: consumerHead,
	}
	if err := setResourceSharingChange(ctx, transaction, ids.changeID); err != nil {
		return sharing.MutationResult{}, err
	}
	constraints, constraintIDs, err := encodeResourceSharingConstraints(
		command.MaximumTraffic(), ids.constraintIDs,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	semanticHash := binding.SemanticHash().Bytes()
	trafficHash := command.MaximumTraffic().Hash()
	var revisions resourceSharingMutationRevisions
	var exportVersion, offerVersion int64
	if err := transaction.QueryRow(
		ctx,
		createResourceShareOfferSQL,
		provider.workspaceInternal,
		provider.networkInternal,
		consumer.workspaceInternal,
		consumer.networkInternal,
		provider.scope.WorkspaceID().String(),
		provider.scope.NetworkID().String(),
		consumer.scope.WorkspaceID().String(),
		consumer.scope.NetworkID().String(),
		binding.ResourceID().String(),
		binding.ResourceVersion(),
		binding.TargetGeneration(),
		semanticHash[:],
		ids.exportID.String(),
		ids.offerID.String(),
		constraintIDs,
		constraints,
		trafficHash[:],
		nonceDigest[:],
		provider.authorityGeneration,
		consumer.authorityGeneration,
		provider.sharingRevision,
		consumer.sharingRevision,
		command.ExpiresAt(),
		evaluatedAt,
	).Scan(
		&revisions.providerNetwork,
		&revisions.providerSharing,
		&revisions.consumerNetwork,
		&revisions.consumerSharing,
		&exportVersion,
		&offerVersion,
	); err != nil {
		return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
	}
	if exportVersion != 1 || offerVersion != 1 {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	projection, err := readResourceSharingOffer(ctx, transaction, ids.offerID)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	result, err := newResourceSharingMutationResult(projection, revisions, token, true)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	payload := resourceSharingIdempotencyPayloadFromResult(
		resourceSharingCreateOperation, result, ids.offerID, sharing.ContractID{},
	)
	if err := appendResourceSharingMutationEvidence(
		ctx,
		transaction,
		command.AccountSession(),
		command.Reason(),
		command.IdempotencyEvidence(),
		command.ProviderScope(),
		authorizationEvidence,
		locator,
		auditHeads,
		ids,
		record,
		requestHash,
		"share_offer",
		publicid.ID(ids.offerID),
		offerVersion,
		"share_offer.created",
		authorization.PermissionShareOffer,
		payload,
		evaluatedAt,
	); err != nil {
		return sharing.MutationResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
	}
	closed = true
	return result, nil
}

// DecideOffer terminally accepts, rejects, or withdraws one offered capability.
func (store *ResourceSharingStore) DecideOffer(
	ctx context.Context,
	command sharing.DecideOffer,
	evaluatedAt time.Time,
) (_ sharing.MutationResult, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		evaluatedAt.IsZero() || !validResourceSharingOptions(store.options) {
		return sharing.MutationResult{}, sharing.ErrInvalidManagementRequest
	}
	localScope := command.ConsumerScope()
	permission := authorization.PermissionShareAccept
	if command.Action() == sharing.DecisionActionRevoke {
		localScope = command.ProviderScope()
		permission = authorization.PermissionShareRevoke
	}
	provider, providerHead, err := store.resolveResourceSharingPreflight(ctx, command.ProviderScope())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	consumer, consumerHead, err := store.resolveResourceSharingPreflight(ctx, command.ConsumerScope())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	accept := command.Action() == sharing.DecisionActionAccept
	ids, err := newResourceSharingMutationIDs(0, accept)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	requestHash, err := resourceSharingDecisionHash(command)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	transaction, err := store.begin(ctx)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceSharing(transaction))
		}
	}()
	localState, err := setResourceSharingScope(ctx, transaction, localScope)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if localScope == provider.scope {
		if !sameResourceSharingInternalScope(localState, provider) {
			return sharing.MutationResult{}, sharing.ErrConflict
		}
		provider = localState
	} else {
		if !sameResourceSharingInternalScope(localState, consumer) {
			return sharing.MutationResult{}, sharing.ErrConflict
		}
		consumer = localState
	}
	authorizationEvidence, err := authorizeResourceSharing(
		ctx, transaction, command.AccountSession(), localScope, permission, evaluatedAt,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	locator, err := readResourceSharingOfferLocator(ctx, transaction, command.OfferID())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if locator.provider.scope != command.ProviderScope() ||
		locator.consumer.scope != command.ConsumerScope() {
		return sharing.MutationResult{}, sharing.ErrNotFound
	}
	if !sameResourceSharingInternalScope(provider, locator.provider) ||
		!sameResourceSharingInternalScope(consumer, locator.consumer) {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	locator.provider = provider
	locator.consumer = consumer
	record, replay, err := store.claimResourceSharingIdempotency(
		ctx,
		transaction,
		command.AccountSession().PrincipalID().String(),
		resourceSharingDecideOperation,
		command.IdempotencyEvidence(),
		requestHash,
		ids.idempotencyRecordID,
		evaluatedAt,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if replay != nil {
		result, err := replayResourceSharingResult(
			ctx, transaction, localScope, *replay, sharing.OfferToken{}, false,
		)
		if err != nil {
			return sharing.MutationResult{}, err
		}
		if err := transaction.Commit(ctx); err != nil {
			return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
		}
		closed = true
		return result, nil
	}
	localHead, err := readResourceSharingAuditHead(ctx, transaction)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if localScope == provider.scope {
		providerHead = localHead
	} else {
		consumerHead = localHead
	}
	auditHeads := map[network.Scope]resourceAuthorityAuditHead{
		provider.scope: providerHead,
		consumer.scope: consumerHead,
	}
	if err := setResourceSharingChange(ctx, transaction, ids.changeID); err != nil {
		return sharing.MutationResult{}, err
	}
	tokenBytes := command.Token().Bytes()
	nonceDigest := sha256.Sum256(tokenBytes[:])
	action := resourceSharingDecisionAction(command.Action())
	var contractID, importedID any
	var importedName any
	if accept {
		contractID = ids.contractID.String()
		importedID = ids.importedResourceID.String()
		importedName = command.ImportedDisplayName().String()
	}
	var revisions resourceSharingMutationRevisions
	var offerVersion, contractVersion int64
	var contractState string
	if err := transaction.QueryRow(
		ctx,
		decideResourceShareOfferSQL,
		provider.workspaceInternal,
		provider.networkInternal,
		consumer.workspaceInternal,
		consumer.networkInternal,
		provider.scope.WorkspaceID().String(),
		provider.scope.NetworkID().String(),
		consumer.scope.WorkspaceID().String(),
		consumer.scope.NetworkID().String(),
		command.OfferID().String(),
		command.ExpectedOfferVersion(),
		nonceDigest[:],
		action,
		contractID,
		importedID,
		importedName,
		provider.authorityGeneration,
		consumer.authorityGeneration,
		command.AccountSession().DeploymentRecoveryEpoch(),
		provider.sharingRevision,
		consumer.sharingRevision,
		evaluatedAt,
	).Scan(
		&revisions.providerNetwork,
		&revisions.providerSharing,
		&revisions.consumerNetwork,
		&revisions.consumerSharing,
		&offerVersion,
		&contractVersion,
		&revisions.importedVersion,
		&contractState,
	); err != nil {
		return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
	}
	if offerVersion != command.ExpectedOfferVersion()+1 ||
		(accept && (contractVersion != 1 || contractState != "activating" || revisions.importedVersion != 1)) ||
		(!accept && (contractVersion != 0 || contractState != "" || revisions.importedVersion != 0)) {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	projection, err := readResourceSharingOffer(ctx, transaction, command.OfferID())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	result, err := newResourceSharingMutationResult(
		projection, revisions, sharing.OfferToken{}, false,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	payload := resourceSharingIdempotencyPayloadFromResult(
		resourceSharingDecideOperation, result, command.OfferID(), ids.contractID,
	)
	if err := appendResourceSharingMutationEvidence(
		ctx,
		transaction,
		command.AccountSession(),
		command.Reason(),
		command.IdempotencyEvidence(),
		localScope,
		authorizationEvidence,
		locator,
		auditHeads,
		ids,
		record,
		requestHash,
		"share_offer",
		publicid.ID(command.OfferID()),
		offerVersion,
		resourceSharingDecisionAuditAction(command.Action()),
		permission,
		payload,
		evaluatedAt,
	); err != nil {
		return sharing.MutationResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
	}
	closed = true
	return result, nil
}

// ActivateContract revalidates every bilateral authority input and makes the
// accepted contract eligible for policy compilation. It grants no endpoint path.
func (store *ResourceSharingStore) ActivateContract(
	ctx context.Context,
	command sharing.ActivateContract,
	evaluatedAt time.Time,
) (_ sharing.MutationResult, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		evaluatedAt.IsZero() || !validResourceSharingOptions(store.options) {
		return sharing.MutationResult{}, sharing.ErrInvalidManagementRequest
	}
	provider, providerHead, err := store.resolveResourceSharingPreflight(ctx, command.ProviderScope())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	consumer, _, err := store.resolveResourceSharingPreflight(ctx, command.ConsumerScope())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	ids, err := newResourceSharingMutationIDs(0, false)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	requestHash, err := resourceSharingActivationHash(command)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	transaction, err := store.begin(ctx)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceSharing(transaction))
		}
	}()
	localState, err := setResourceSharingScope(ctx, transaction, command.ConsumerScope())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if !sameResourceSharingInternalScope(localState, consumer) {
		return sharing.MutationResult{}, sharing.ErrConflict
	}
	consumer = localState
	authorizationEvidence, err := authorizeResourceSharing(
		ctx,
		transaction,
		command.AccountSession(),
		command.ConsumerScope(),
		authorization.PermissionShareAccept,
		evaluatedAt,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	locator, err := readResourceSharingContractLocator(ctx, transaction, command.ContractID())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if locator.provider.scope != command.ProviderScope() ||
		locator.consumer.scope != command.ConsumerScope() {
		return sharing.MutationResult{}, sharing.ErrNotFound
	}
	if !sameResourceSharingInternalScope(provider, locator.provider) ||
		!sameResourceSharingInternalScope(consumer, locator.consumer) {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	locator.provider = provider
	locator.consumer = consumer
	record, replay, err := store.claimResourceSharingIdempotency(
		ctx,
		transaction,
		command.AccountSession().PrincipalID().String(),
		resourceSharingActivateOperation,
		command.IdempotencyEvidence(),
		requestHash,
		ids.idempotencyRecordID,
		evaluatedAt,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if replay != nil {
		result, replayErr := replayResourceSharingResult(
			ctx, transaction, command.ConsumerScope(), *replay, sharing.OfferToken{}, false,
		)
		if replayErr != nil {
			return sharing.MutationResult{}, replayErr
		}
		if err := transaction.Commit(ctx); err != nil {
			return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
		}
		closed = true
		return result, nil
	}
	consumerHead, err := readResourceSharingAuditHead(ctx, transaction)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	auditHeads := map[network.Scope]resourceAuthorityAuditHead{
		provider.scope: providerHead,
		consumer.scope: consumerHead,
	}
	if err := setResourceSharingChange(ctx, transaction, ids.changeID); err != nil {
		return sharing.MutationResult{}, err
	}
	var revisions resourceSharingMutationRevisions
	var contractVersion int64
	if err := transaction.QueryRow(
		ctx,
		activateResourceShareSQL,
		provider.workspaceInternal,
		provider.networkInternal,
		consumer.workspaceInternal,
		consumer.networkInternal,
		command.ContractID().String(),
		command.ExpectedContractVersion(),
		provider.sharingRevision,
		consumer.sharingRevision,
		evaluatedAt,
	).Scan(
		&revisions.providerNetwork,
		&revisions.providerSharing,
		&revisions.consumerNetwork,
		&revisions.consumerSharing,
		&contractVersion,
		&revisions.importedVersion,
	); err != nil {
		return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
	}
	if contractVersion != command.ExpectedContractVersion()+1 || revisions.importedVersion <= 1 {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	projection, err := readResourceSharingOffer(ctx, transaction, locator.offerID)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	result, err := newResourceSharingMutationResult(
		projection, revisions, sharing.OfferToken{}, false,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	payload := resourceSharingIdempotencyPayloadFromResult(
		resourceSharingActivateOperation, result, locator.offerID, command.ContractID(),
	)
	if err := appendResourceSharingMutationEvidence(
		ctx,
		transaction,
		command.AccountSession(),
		command.Reason(),
		command.IdempotencyEvidence(),
		command.ConsumerScope(),
		authorizationEvidence,
		locator,
		auditHeads,
		ids,
		record,
		requestHash,
		"trust_contract",
		publicid.ID(command.ContractID()),
		contractVersion,
		"trust_contract.activated",
		authorization.PermissionShareAccept,
		payload,
		evaluatedAt,
	); err != nil {
		return sharing.MutationResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
	}
	closed = true
	return result, nil
}

// RevokeContract removes an activating or active contract from both Networks.
func (store *ResourceSharingStore) RevokeContract(
	ctx context.Context,
	command sharing.RevokeContract,
	evaluatedAt time.Time,
) (_ sharing.MutationResult, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		evaluatedAt.IsZero() || !validResourceSharingOptions(store.options) {
		return sharing.MutationResult{}, sharing.ErrInvalidManagementRequest
	}
	provider, providerHead, err := store.resolveResourceSharingPreflight(ctx, command.ProviderScope())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	consumer, consumerHead, err := store.resolveResourceSharingPreflight(ctx, command.ConsumerScope())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	ids, err := newResourceSharingMutationIDs(0, false)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	requestHash, err := resourceSharingRevocationHash(command)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	transaction, err := store.begin(ctx)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceSharing(transaction))
		}
	}()
	localState, err := setResourceSharingScope(ctx, transaction, command.LocalScope())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if command.LocalScope() == provider.scope {
		if !sameResourceSharingInternalScope(localState, provider) {
			return sharing.MutationResult{}, sharing.ErrConflict
		}
		provider = localState
	} else {
		if !sameResourceSharingInternalScope(localState, consumer) {
			return sharing.MutationResult{}, sharing.ErrConflict
		}
		consumer = localState
	}
	authorizationEvidence, err := authorizeResourceSharing(
		ctx,
		transaction,
		command.AccountSession(),
		command.LocalScope(),
		authorization.PermissionShareRevoke,
		evaluatedAt,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	locator, err := readResourceSharingContractLocator(ctx, transaction, command.ContractID())
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if locator.provider.scope != command.ProviderScope() ||
		locator.consumer.scope != command.ConsumerScope() {
		return sharing.MutationResult{}, sharing.ErrNotFound
	}
	if !sameResourceSharingInternalScope(provider, locator.provider) ||
		!sameResourceSharingInternalScope(consumer, locator.consumer) {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	locator.provider = provider
	locator.consumer = consumer
	record, replay, err := store.claimResourceSharingIdempotency(
		ctx,
		transaction,
		command.AccountSession().PrincipalID().String(),
		resourceSharingRevokeOperation,
		command.IdempotencyEvidence(),
		requestHash,
		ids.idempotencyRecordID,
		evaluatedAt,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if replay != nil {
		result, err := replayResourceSharingResult(
			ctx, transaction, command.LocalScope(), *replay, sharing.OfferToken{}, false,
		)
		if err != nil {
			return sharing.MutationResult{}, err
		}
		if err := transaction.Commit(ctx); err != nil {
			return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
		}
		closed = true
		return result, nil
	}
	localHead, err := readResourceSharingAuditHead(ctx, transaction)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	if command.LocalScope() == provider.scope {
		providerHead = localHead
	} else {
		consumerHead = localHead
	}
	auditHeads := map[network.Scope]resourceAuthorityAuditHead{
		provider.scope: providerHead,
		consumer.scope: consumerHead,
	}
	if err := setResourceSharingChange(ctx, transaction, ids.changeID); err != nil {
		return sharing.MutationResult{}, err
	}
	var revisions resourceSharingMutationRevisions
	var contractVersion int64
	if err := transaction.QueryRow(
		ctx,
		revokeResourceShareSQL,
		provider.workspaceInternal,
		provider.networkInternal,
		consumer.workspaceInternal,
		consumer.networkInternal,
		command.ContractID().String(),
		command.ExpectedContractVersion(),
		provider.sharingRevision,
		consumer.sharingRevision,
		evaluatedAt,
	).Scan(
		&revisions.providerNetwork,
		&revisions.providerSharing,
		&revisions.consumerNetwork,
		&revisions.consumerSharing,
		&contractVersion,
		&revisions.importedVersion,
	); err != nil {
		return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
	}
	if contractVersion != command.ExpectedContractVersion()+1 || revisions.importedVersion <= 1 {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	projection, err := readResourceSharingOffer(ctx, transaction, locator.offerID)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	result, err := newResourceSharingMutationResult(
		projection, revisions, sharing.OfferToken{}, false,
	)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	payload := resourceSharingIdempotencyPayloadFromResult(
		resourceSharingRevokeOperation, result, locator.offerID, command.ContractID(),
	)
	if err := appendResourceSharingMutationEvidence(
		ctx,
		transaction,
		command.AccountSession(),
		command.Reason(),
		command.IdempotencyEvidence(),
		command.LocalScope(),
		authorizationEvidence,
		locator,
		auditHeads,
		ids,
		record,
		requestHash,
		"trust_contract",
		publicid.ID(command.ContractID()),
		contractVersion,
		"trust_contract.revoked",
		authorization.PermissionShareRevoke,
		payload,
		evaluatedAt,
	); err != nil {
		return sharing.MutationResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return sharing.MutationResult{}, resourceSharingDatabaseError(ctx, err)
	}
	closed = true
	return result, nil
}

func (store *ResourceSharingStore) resolveResourceSharingPreflight(
	ctx context.Context,
	scope network.Scope,
) (_ resourceSharingNetworkState, _ resourceAuthorityAuditHead, resultErr error) {
	transaction, err := store.begin(ctx)
	if err != nil {
		return resourceSharingNetworkState{}, resourceAuthorityAuditHead{}, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceSharing(transaction))
		}
	}()
	state, err := setResourceSharingScope(ctx, transaction, scope)
	if err != nil {
		return resourceSharingNetworkState{}, resourceAuthorityAuditHead{}, err
	}
	head, err := readResourceSharingAuditHead(ctx, transaction)
	if err != nil {
		return resourceSharingNetworkState{}, resourceAuthorityAuditHead{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return resourceSharingNetworkState{}, resourceAuthorityAuditHead{},
			resourceSharingDatabaseError(ctx, err)
	}
	closed = true
	return state, head, nil
}

func readResourceSharingBinding(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	scope network.Scope,
	id resource.ID,
) (sharing.ResourceBinding, error) {
	var version, targetGeneration int64
	var semanticHashBytes []byte
	err := transaction.QueryRow(ctx, readResourceSharingResourceSQL, id.String()).Scan(
		&version, &targetGeneration, &semanticHashBytes,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return sharing.ResourceBinding{}, sharing.ErrNotFound
	}
	if err != nil {
		return sharing.ResourceBinding{}, resourceSharingDatabaseError(ctx, err)
	}
	if len(semanticHashBytes) != sha256.Size {
		return sharing.ResourceBinding{}, sharing.ErrUnavailable
	}
	var fixed [sha256.Size]byte
	copy(fixed[:], semanticHashBytes)
	semanticHash, err := resource.NewSemanticHash(fixed)
	if err != nil {
		return sharing.ResourceBinding{}, sharing.ErrUnavailable
	}
	binding, err := sharing.NewResourceBinding(scope, id, version, targetGeneration, semanticHash)
	if err != nil {
		return sharing.ResourceBinding{}, sharing.ErrUnavailable
	}
	return binding, nil
}

func (store *ResourceSharingStore) claimResourceSharingIdempotency(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	principalID, operation string,
	proof idempotency.Proof,
	requestHash [sha256.Size]byte,
	recordID publicid.ID,
	evaluatedAt time.Time,
) (resourceAuthorityIdempotencyRecord, *resourceSharingIdempotencyPayload, error) {
	digest := proof.Digest()
	record, err := scanResourceAuthorityIdempotencyRecord(transaction.QueryRow(
		ctx,
		claimResourceAuthorityIdempotencySQL,
		recordID.String(),
		principalID,
		operation,
		proof.DigestKeyID(),
		digest[:],
		requestHash[:],
		evaluatedAt,
		evaluatedAt.Add(store.options.IdempotencyTTL),
	), true)
	if err != nil {
		return resourceAuthorityIdempotencyRecord{}, nil, resourceSharingDatabaseError(ctx, err)
	}
	payload, replay, err := decodeResourceSharingIdempotencyPayload(
		record, operation, requestHash, evaluatedAt,
	)
	if err != nil {
		return resourceAuthorityIdempotencyRecord{}, nil, err
	}
	if !replay && record.publicID != recordID.String() {
		return resourceAuthorityIdempotencyRecord{}, nil, sharing.ErrUnavailable
	}
	if replay {
		return record, &payload, nil
	}
	return record, nil, nil
}

func replayResourceSharingResult(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	localScope network.Scope,
	payload resourceSharingIdempotencyPayload,
	token sharing.OfferToken,
	hasToken bool,
) (sharing.MutationResult, error) {
	offerID, err := sharing.ParseOfferID(payload.OfferID)
	if err != nil {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	if _, err := setResourceSharingScope(ctx, transaction, localScope); err != nil {
		return sharing.MutationResult{}, err
	}
	projection, err := readResourceSharingOffer(ctx, transaction, offerID)
	if err != nil {
		return sharing.MutationResult{}, err
	}
	revisions := resourceSharingMutationRevisions{
		providerNetwork: payload.ProviderNetworkRevision,
		providerSharing: payload.ProviderSharingRevision,
		consumerNetwork: payload.ConsumerNetworkRevision,
		consumerSharing: payload.ConsumerSharingRevision,
		importedVersion: payload.ImportedResourceVersion,
	}
	return newResourceSharingMutationResult(projection, revisions, token, hasToken)
}

func newResourceSharingMutationResult(
	projection resourceSharingProjection,
	revisions resourceSharingMutationRevisions,
	token sharing.OfferToken,
	hasToken bool,
) (sharing.MutationResult, error) {
	params := sharing.MutationResultParams{
		Offer: projection.offer, Token: token,
		ProviderNetworkRevision: revisions.providerNetwork,
		ProviderSharingRevision: revisions.providerSharing,
		ConsumerNetworkRevision: revisions.consumerNetwork,
		ConsumerSharingRevision: revisions.consumerSharing,
		ImportedResourceVersion: revisions.importedVersion,
		HasOffer:                true, HasToken: hasToken,
	}
	if projection.contract.IsValid() {
		params.Contract = projection.contract
		params.HasContract = true
	}
	result, err := sharing.NewMutationResult(params)
	if err != nil {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	return result, nil
}

func readResourceSharingOfferLocator(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	offerID sharing.OfferID,
) (resourceSharingScopeLocator, error) {
	var locatorValues [8]any
	var providerWorkspaceInternal, providerNetworkInternal int64
	var consumerWorkspaceInternal, consumerNetworkInternal int64
	var providerWorkspace, providerNetwork, consumerWorkspace, consumerNetwork string
	locatorValues = [8]any{
		&providerWorkspaceInternal,
		&providerNetworkInternal,
		&consumerWorkspaceInternal,
		&consumerNetworkInternal,
		&providerWorkspace,
		&providerNetwork,
		&consumerWorkspace,
		&consumerNetwork,
	}
	err := transaction.QueryRow(ctx, readResourceSharingLocatorSQL, offerID.String()).Scan(locatorValues[:]...)
	if errors.Is(err, pgx.ErrNoRows) {
		return resourceSharingScopeLocator{}, sharing.ErrNotFound
	}
	if err != nil {
		return resourceSharingScopeLocator{}, resourceSharingDatabaseError(ctx, err)
	}
	return newResourceSharingScopeLocator(
		offerID,
		providerWorkspaceInternal,
		providerNetworkInternal,
		consumerWorkspaceInternal,
		consumerNetworkInternal,
		providerWorkspace,
		providerNetwork,
		consumerWorkspace,
		consumerNetwork,
	)
}

func readResourceSharingContractLocator(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	contractID sharing.ContractID,
) (resourceSharingScopeLocator, error) {
	var providerWorkspaceInternal, providerNetworkInternal int64
	var consumerWorkspaceInternal, consumerNetworkInternal int64
	var providerWorkspace, providerNetwork, consumerWorkspace, consumerNetwork, offerValue string
	err := transaction.QueryRow(ctx, readResourceSharingContractLocatorSQL, contractID.String()).Scan(
		&providerWorkspaceInternal,
		&providerNetworkInternal,
		&consumerWorkspaceInternal,
		&consumerNetworkInternal,
		&providerWorkspace,
		&providerNetwork,
		&consumerWorkspace,
		&consumerNetwork,
		&offerValue,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return resourceSharingScopeLocator{}, sharing.ErrNotFound
	}
	if err != nil {
		return resourceSharingScopeLocator{}, resourceSharingDatabaseError(ctx, err)
	}
	offerID, err := sharing.ParseOfferID(offerValue)
	if err != nil {
		return resourceSharingScopeLocator{}, sharing.ErrUnavailable
	}
	return newResourceSharingScopeLocator(
		offerID,
		providerWorkspaceInternal,
		providerNetworkInternal,
		consumerWorkspaceInternal,
		consumerNetworkInternal,
		providerWorkspace,
		providerNetwork,
		consumerWorkspace,
		consumerNetwork,
	)
}

func newResourceSharingScopeLocator(
	offerID sharing.OfferID,
	providerWorkspaceInternal, providerNetworkInternal int64,
	consumerWorkspaceInternal, consumerNetworkInternal int64,
	providerWorkspace, providerNetwork, consumerWorkspace, consumerNetwork string,
) (resourceSharingScopeLocator, error) {
	providerScope, err := resourceSharingScope(providerWorkspace, providerNetwork)
	if err != nil {
		return resourceSharingScopeLocator{}, err
	}
	consumerScope, err := resourceSharingScope(consumerWorkspace, consumerNetwork)
	if err != nil || providerScope == consumerScope {
		return resourceSharingScopeLocator{}, sharing.ErrUnavailable
	}
	locator := resourceSharingScopeLocator{
		provider: resourceSharingNetworkState{
			scope: providerScope, workspaceInternal: providerWorkspaceInternal,
			networkInternal: providerNetworkInternal,
		},
		consumer: resourceSharingNetworkState{
			scope: consumerScope, workspaceInternal: consumerWorkspaceInternal,
			networkInternal: consumerNetworkInternal,
		},
		offerID: offerID,
	}
	if providerWorkspaceInternal <= 0 || providerNetworkInternal <= 0 ||
		consumerWorkspaceInternal <= 0 || consumerNetworkInternal <= 0 {
		return resourceSharingScopeLocator{}, sharing.ErrUnavailable
	}
	return locator, nil
}

func sameResourceSharingInternalScope(
	left, right resourceSharingNetworkState,
) bool {
	return left.scope == right.scope && left.workspaceInternal == right.workspaceInternal &&
		left.networkInternal == right.networkInternal
}

func newResourceSharingMutationIDs(
	constraintCount int,
	accept bool,
) (resourceSharingMutationIDs, error) {
	if constraintCount < 0 || constraintCount > sharing.MaximumTrafficConstraints {
		return resourceSharingMutationIDs{}, sharing.ErrUnavailable
	}
	count := 8 + constraintCount
	if accept {
		count += 2
	}
	generated := make([]publicid.ID, count)
	for index := range generated {
		id, err := publicid.New()
		if err != nil {
			return resourceSharingMutationIDs{}, fmt.Errorf("generate Resource Sharing ID: %w", err)
		}
		generated[index] = id
	}
	ids := resourceSharingMutationIDs{
		changeID: generated[0], idempotencyRecordID: generated[1],
		providerAuditID: generated[2], providerOutboxID: generated[3],
		consumerAuditID: generated[4], consumerOutboxID: generated[5],
		exportID: sharing.ExportID(generated[6]), offerID: sharing.OfferID(generated[7]),
		constraintIDs: generated[8 : 8+constraintCount],
	}
	if accept {
		ids.contractID = sharing.ContractID(generated[count-2])
		ids.importedResourceID = sharing.ImportedResourceID(generated[count-1])
	}
	return ids, nil
}

func resourceSharingOfferToken(
	proof idempotency.Proof,
) (sharing.OfferToken, [sha256.Size]byte, error) {
	digest := proof.Digest()
	material := make([]byte, 0, len(resourceSharingTokenDomain)+len(digest))
	material = append(material, resourceSharingTokenDomain...)
	material = append(material, digest[:]...)
	raw := sha256.Sum256(material)
	token, err := sharing.NewOfferToken(raw)
	if err != nil {
		return sharing.OfferToken{}, [sha256.Size]byte{}, sharing.ErrUnavailable
	}
	nonceDigest := sha256.Sum256(raw[:])
	return token, nonceDigest, nil
}

func encodeResourceSharingConstraints(
	traffic sharing.TrafficSet,
	ids []publicid.ID,
) ([]byte, []byte, error) {
	constraints := traffic.Constraints()
	if len(constraints) != len(ids) {
		return nil, nil, sharing.ErrUnavailable
	}
	type portRange struct {
		First uint16 `json:"first"`
		Last  uint16 `json:"last"`
	}
	type constraint struct {
		Protocol string      `json:"protocol"`
		Ranges   []portRange `json:"ranges"`
	}
	encodedConstraints := make([]constraint, len(constraints))
	encodedIDs := make([]string, len(ids))
	for index, value := range constraints {
		ranges := value.DestinationPortRanges()
		encodedRanges := make([]portRange, len(ranges))
		for rangeIndex, value := range ranges {
			encodedRanges[rangeIndex] = portRange{First: value.First(), Last: value.Last()}
		}
		encodedConstraints[index] = constraint{
			Protocol: value.Protocol().String(), Ranges: encodedRanges,
		}
		encodedIDs[index] = ids[index].String()
	}
	constraintsJSON, err := json.Marshal(encodedConstraints)
	if err != nil {
		return nil, nil, sharing.ErrUnavailable
	}
	idsJSON, err := json.Marshal(encodedIDs)
	if err != nil {
		return nil, nil, sharing.ErrUnavailable
	}
	return constraintsJSON, idsJSON, nil
}

func resourceSharingDecisionAction(action sharing.DecisionAction) string {
	switch action {
	case sharing.DecisionActionAccept:
		return "accept"
	case sharing.DecisionActionReject:
		return "reject"
	case sharing.DecisionActionRevoke:
		return "revoke"
	default:
		return ""
	}
}

func resourceSharingDecisionAuditAction(action sharing.DecisionAction) string {
	switch action {
	case sharing.DecisionActionAccept:
		return "share_offer.accepted"
	case sharing.DecisionActionReject:
		return "share_offer.rejected"
	case sharing.DecisionActionRevoke:
		return "share_offer.revoked"
	default:
		return ""
	}
}

func resourceSharingCreateHash(command sharing.CreateOffer) ([sha256.Size]byte, error) {
	trafficHash := command.MaximumTraffic().Hash()
	return resourceSharingRequestHash(struct {
		Operation     string `json:"operation"`
		ProviderScope string `json:"provider_scope"`
		ConsumerScope string `json:"consumer_scope"`
		ResourceID    string `json:"resource_id"`
		TrafficHash   string `json:"traffic_hash"`
		ExpiresAt     string `json:"expires_at"`
		Reason        string `json:"reason"`
	}{
		Operation:     resourceSharingCreateOperation,
		ProviderScope: resourceSharingScopeKey(command.ProviderScope()),
		ConsumerScope: resourceSharingScopeKey(command.ConsumerScope()),
		ResourceID:    command.ResourceID().String(), TrafficHash: hex.EncodeToString(trafficHash[:]),
		ExpiresAt: command.ExpiresAt().UTC().Format(time.RFC3339Nano),
		Reason:    command.Reason().String(),
	})
}

func resourceSharingDecisionHash(command sharing.DecideOffer) ([sha256.Size]byte, error) {
	token := command.Token().Bytes()
	tokenDigest := sha256.Sum256(token[:])
	return resourceSharingRequestHash(struct {
		Operation       string `json:"operation"`
		ProviderScope   string `json:"provider_scope"`
		ConsumerScope   string `json:"consumer_scope"`
		OfferID         string `json:"offer_id"`
		ExpectedVersion int64  `json:"expected_version"`
		TokenDigest     string `json:"token_digest"`
		Action          string `json:"action"`
		ImportedName    string `json:"imported_name,omitempty"`
		Reason          string `json:"reason"`
	}{
		Operation:     resourceSharingDecideOperation,
		ProviderScope: resourceSharingScopeKey(command.ProviderScope()),
		ConsumerScope: resourceSharingScopeKey(command.ConsumerScope()),
		OfferID:       command.OfferID().String(), ExpectedVersion: command.ExpectedOfferVersion(),
		TokenDigest:  hex.EncodeToString(tokenDigest[:]),
		Action:       resourceSharingDecisionAction(command.Action()),
		ImportedName: command.ImportedDisplayName().String(),
		Reason:       command.Reason().String(),
	})
}

func resourceSharingRevocationHash(command sharing.RevokeContract) ([sha256.Size]byte, error) {
	return resourceSharingRequestHash(struct {
		Operation       string `json:"operation"`
		ProviderScope   string `json:"provider_scope"`
		ConsumerScope   string `json:"consumer_scope"`
		LocalScope      string `json:"local_scope"`
		ContractID      string `json:"contract_id"`
		ExpectedVersion int64  `json:"expected_version"`
		Reason          string `json:"reason"`
	}{
		Operation:       resourceSharingRevokeOperation,
		ProviderScope:   resourceSharingScopeKey(command.ProviderScope()),
		ConsumerScope:   resourceSharingScopeKey(command.ConsumerScope()),
		LocalScope:      resourceSharingScopeKey(command.LocalScope()),
		ContractID:      command.ContractID().String(),
		ExpectedVersion: command.ExpectedContractVersion(),
		Reason:          command.Reason().String(),
	})
}

func resourceSharingActivationHash(command sharing.ActivateContract) ([sha256.Size]byte, error) {
	return resourceSharingRequestHash(struct {
		Operation       string `json:"operation"`
		ProviderScope   string `json:"provider_scope"`
		ConsumerScope   string `json:"consumer_scope"`
		ContractID      string `json:"contract_id"`
		ExpectedVersion int64  `json:"expected_version"`
		Reason          string `json:"reason"`
	}{
		Operation:       resourceSharingActivateOperation,
		ProviderScope:   resourceSharingScopeKey(command.ProviderScope()),
		ConsumerScope:   resourceSharingScopeKey(command.ConsumerScope()),
		ContractID:      command.ContractID().String(),
		ExpectedVersion: command.ExpectedContractVersion(),
		Reason:          command.Reason().String(),
	})
}

func resourceSharingRequestHash(value any) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, sharing.ErrUnavailable
	}
	return sha256.Sum256(encoded), nil
}

func resourceSharingScopeKey(scope network.Scope) string {
	return scope.WorkspaceID().String() + "/" + scope.NetworkID().String()
}

func resourceSharingIdempotencyPayloadFromResult(
	operation string,
	result sharing.MutationResult,
	offerID sharing.OfferID,
	contractID sharing.ContractID,
) resourceSharingIdempotencyPayload {
	payload := resourceSharingIdempotencyPayload{
		Operation: operation, OfferID: offerID.String(),
		ProviderNetworkRevision: result.ProviderNetworkRevision(),
		ProviderSharingRevision: result.ProviderSharingRevision(),
		ConsumerNetworkRevision: result.ConsumerNetworkRevision(),
		ConsumerSharingRevision: result.ConsumerSharingRevision(),
		ImportedResourceVersion: result.ImportedResourceVersion(),
	}
	if contractID.IsValid() {
		payload.ContractID = contractID.String()
	}
	return payload
}
