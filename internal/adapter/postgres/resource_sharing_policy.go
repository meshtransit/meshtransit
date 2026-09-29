package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

const maximumImportedPolicyDestinations = 256

type importedPolicyLocatorRecord struct {
	ImportedResourceID          string `json:"imported_resource_id"`
	ProviderWorkspaceInternalID int64  `json:"provider_workspace_internal_id"`
	ProviderNetworkInternalID   int64  `json:"provider_network_internal_id"`
	ConsumerWorkspaceInternalID int64  `json:"consumer_workspace_internal_id"`
	ConsumerNetworkInternalID   int64  `json:"consumer_network_internal_id"`
	ProviderWorkspaceID         string `json:"provider_workspace_id"`
	ProviderNetworkID           string `json:"provider_network_id"`
	ConsumerWorkspaceID         string `json:"consumer_workspace_id"`
	ConsumerNetworkID           string `json:"consumer_network_id"`
}

type importedPolicyDestinationRecord struct {
	ImportedResourceID          string                         `json:"imported_resource_id"`
	ImportedResourceVersion     int64                          `json:"imported_resource_version"`
	ContractID                  string                         `json:"contract_id"`
	ContractVersion             int64                          `json:"contract_version"`
	OfferID                     string                         `json:"offer_id"`
	ExportID                    string                         `json:"export_id"`
	ExportVersion               int64                          `json:"export_version"`
	ProviderWorkspaceID         string                         `json:"provider_workspace_id"`
	ProviderNetworkID           string                         `json:"provider_network_id"`
	ConsumerWorkspaceID         string                         `json:"consumer_workspace_id"`
	ConsumerNetworkID           string                         `json:"consumer_network_id"`
	ResourceID                  string                         `json:"resource_id"`
	ResourceVersion             int64                          `json:"resource_version"`
	TargetGeneration            int64                          `json:"target_generation"`
	ResourceSemanticHash        string                         `json:"resource_semantic_hash"`
	ProviderInventoryRevision   int64                          `json:"provider_inventory_revision"`
	ProviderSharingRevision     int64                          `json:"provider_sharing_revision"`
	ConsumerSharingRevision     int64                          `json:"consumer_sharing_revision"`
	ProviderAuthorityGeneration int64                          `json:"provider_authority_generation"`
	ConsumerAuthorityGeneration int64                          `json:"consumer_authority_generation"`
	RecoveryEpoch               int64                          `json:"recovery_epoch"`
	ExpiresAt                   time.Time                      `json:"expires_at"`
	ConstraintHash              string                         `json:"constraint_hash"`
	Constraints                 []resourceSharingTrafficRecord `json:"constraints"`
}

type importedPolicyLocatorGroup struct {
	record importedPolicyLocatorRecord
	ids    []sharing.ImportedResourceID
}

// ResolveImportedPolicyDestinations returns one repeatable-read, freshly
// authorized snapshot of current bilateral Imported Resource authority.
func (store *ResourceSharingStore) ResolveImportedPolicyDestinations(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	ids []sharing.ImportedResourceID,
) (_ []sharing.PolicyDestination, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !session.IsValid() ||
		!scope.IsValid() || len(ids) == 0 || len(ids) > maximumImportedPolicyDestinations ||
		!validResourceSharingOptions(store.options) {
		return nil, sharing.ErrInvalidManagementRequest
	}
	ids, err := canonicalImportedPolicyDestinationIDs(ids)
	if err != nil {
		return nil, err
	}
	evaluatedAt := time.Now().UTC()
	transaction, err := store.begin(ctx)
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceSharing(transaction))
		}
	}()
	if _, err = setResourceSharingScope(ctx, transaction, scope); err != nil {
		return nil, err
	}
	if _, err = authorizeResourceSharing(
		ctx,
		transaction,
		session,
		scope,
		authorization.PermissionShareRead,
		evaluatedAt,
	); err != nil {
		return nil, err
	}

	encodedIDs := make([]string, len(ids))
	for index, id := range ids {
		encodedIDs[index] = id.String()
	}
	var encodedLocators string
	if err = transaction.QueryRow(
		ctx,
		readImportedPolicyLocatorsSQL,
		encodedIDs,
	).Scan(&encodedLocators); err != nil {
		return nil, resourceSharingDatabaseError(ctx, err)
	}
	groups, err := decodeImportedPolicyLocatorGroups(encodedLocators, scope, ids)
	if err != nil {
		return nil, err
	}

	values := make([]sharing.PolicyDestination, 0, len(ids))
	for _, group := range groups {
		groupIDs := make([]string, len(group.ids))
		for index, id := range group.ids {
			groupIDs[index] = id.String()
		}
		locator := group.record
		var encodedDestinations string
		if err = transaction.QueryRow(
			ctx,
			resolveImportedPolicyDestinationsSQL,
			locator.ProviderWorkspaceInternalID,
			locator.ProviderNetworkInternalID,
			locator.ConsumerWorkspaceInternalID,
			locator.ConsumerNetworkInternalID,
			locator.ProviderWorkspaceID,
			locator.ProviderNetworkID,
			locator.ConsumerWorkspaceID,
			locator.ConsumerNetworkID,
			groupIDs,
			evaluatedAt,
		).Scan(&encodedDestinations); err != nil {
			return nil, resourceSharingDatabaseError(ctx, err)
		}
		resolved, decodeErr := decodeImportedPolicyDestinations(
			encodedDestinations,
			evaluatedAt,
			scope,
		)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if len(resolved) != len(group.ids) {
			return nil, sharing.ErrConflict
		}
		values = append(values, resolved...)
	}
	if len(values) != len(ids) {
		return nil, sharing.ErrConflict
	}
	slices.SortFunc(values, func(left, right sharing.PolicyDestination) int {
		return strings.Compare(left.ImportedResourceID().String(), right.ImportedResourceID().String())
	})
	for index, value := range values {
		if value.ImportedResourceID() != ids[index] {
			return nil, sharing.ErrConflict
		}
	}
	if err = transaction.Commit(ctx); err != nil {
		return nil, resourceSharingDatabaseError(ctx, err)
	}
	closed = true
	return values, nil
}

func canonicalImportedPolicyDestinationIDs(
	values []sharing.ImportedResourceID,
) ([]sharing.ImportedResourceID, error) {
	canonical := slices.Clone(values)
	for _, id := range canonical {
		if !id.IsValid() {
			return nil, sharing.ErrInvalidManagementRequest
		}
	}
	slices.SortFunc(canonical, func(left, right sharing.ImportedResourceID) int {
		return strings.Compare(left.String(), right.String())
	})
	for index := 1; index < len(canonical); index++ {
		if canonical[index] == canonical[index-1] {
			return nil, sharing.ErrInvalidManagementRequest
		}
	}
	return canonical, nil
}

func decodeImportedPolicyLocatorGroups(
	encoded string,
	consumerScope network.Scope,
	requested []sharing.ImportedResourceID,
) ([]importedPolicyLocatorGroup, error) {
	var records []importedPolicyLocatorRecord
	if err := json.Unmarshal([]byte(encoded), &records); err != nil {
		return nil, errors.Join(sharing.ErrUnavailable, err)
	}
	if len(records) != len(requested) {
		return nil, sharing.ErrConflict
	}
	type groupKey struct {
		providerWorkspaceInternalID int64
		providerNetworkInternalID   int64
		providerWorkspaceID         string
		providerNetworkID           string
	}
	byKey := make(map[groupKey]int, len(records))
	groups := make([]importedPolicyLocatorGroup, 0, len(records))
	seen := make(map[sharing.ImportedResourceID]struct{}, len(records))
	for _, record := range records {
		id, err := sharing.ParseImportedResourceID(record.ImportedResourceID)
		providerScope, providerErr := resourceSharingScope(
			record.ProviderWorkspaceID,
			record.ProviderNetworkID,
		)
		resolvedConsumerScope, consumerErr := resourceSharingScope(
			record.ConsumerWorkspaceID,
			record.ConsumerNetworkID,
		)
		if err != nil || providerErr != nil || consumerErr != nil ||
			providerScope == consumerScope || resolvedConsumerScope != consumerScope ||
			record.ProviderWorkspaceInternalID <= 0 || record.ProviderNetworkInternalID <= 0 ||
			record.ConsumerWorkspaceInternalID <= 0 || record.ConsumerNetworkInternalID <= 0 {
			return nil, sharing.ErrUnavailable
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, sharing.ErrUnavailable
		}
		seen[id] = struct{}{}
		key := groupKey{
			providerWorkspaceInternalID: record.ProviderWorkspaceInternalID,
			providerNetworkInternalID:   record.ProviderNetworkInternalID,
			providerWorkspaceID:         record.ProviderWorkspaceID,
			providerNetworkID:           record.ProviderNetworkID,
		}
		groupIndex, found := byKey[key]
		if !found {
			groupIndex = len(groups)
			byKey[key] = groupIndex
			groups = append(groups, importedPolicyLocatorGroup{record: record})
		}
		groups[groupIndex].ids = append(groups[groupIndex].ids, id)
	}
	slices.SortFunc(groups, func(left, right importedPolicyLocatorGroup) int {
		return strings.Compare(
			left.record.ProviderWorkspaceID+"/"+left.record.ProviderNetworkID,
			right.record.ProviderWorkspaceID+"/"+right.record.ProviderNetworkID,
		)
	})
	return groups, nil
}

func decodeImportedPolicyDestinations(
	encoded string,
	evaluatedAt time.Time,
	consumerScope network.Scope,
) ([]sharing.PolicyDestination, error) {
	var records []importedPolicyDestinationRecord
	if err := json.Unmarshal([]byte(encoded), &records); err != nil {
		return nil, errors.Join(sharing.ErrUnavailable, err)
	}
	values := make([]sharing.PolicyDestination, len(records))
	for index, record := range records {
		value, err := record.value(evaluatedAt, consumerScope)
		if err != nil {
			return nil, err
		}
		values[index] = value
	}
	return values, nil
}

func (record importedPolicyDestinationRecord) value(
	evaluatedAt time.Time,
	consumerScope network.Scope,
) (sharing.PolicyDestination, error) {
	providerScope, err := resourceSharingScope(
		record.ProviderWorkspaceID,
		record.ProviderNetworkID,
	)
	resolvedConsumerScope, consumerErr := resourceSharingScope(
		record.ConsumerWorkspaceID,
		record.ConsumerNetworkID,
	)
	if err != nil || consumerErr != nil || providerScope == consumerScope ||
		resolvedConsumerScope != consumerScope {
		return sharing.PolicyDestination{}, sharing.ErrUnavailable
	}
	importedID, importedErr := sharing.ParseImportedResourceID(record.ImportedResourceID)
	contractID, contractErr := sharing.ParseContractID(record.ContractID)
	offerID, offerErr := sharing.ParseOfferID(record.OfferID)
	exportID, exportErr := sharing.ParseExportID(record.ExportID)
	resourceID, resourceErr := resource.ParseID(record.ResourceID)
	if importedErr != nil || contractErr != nil || offerErr != nil || exportErr != nil ||
		resourceErr != nil {
		return sharing.PolicyDestination{}, sharing.ErrUnavailable
	}
	semanticHash, err := resourceSharingSemanticHash(record.ResourceSemanticHash)
	if err != nil {
		return sharing.PolicyDestination{}, err
	}
	binding, err := sharing.NewResourceBinding(
		providerScope,
		resourceID,
		record.ResourceVersion,
		record.TargetGeneration,
		semanticHash,
	)
	if err != nil {
		return sharing.PolicyDestination{}, sharing.ErrUnavailable
	}
	traffic, err := resourceSharingTrafficSet(record.Constraints)
	if err != nil {
		return sharing.PolicyDestination{}, err
	}
	constraintHash, err := resourceSharingDigest(record.ConstraintHash)
	if err != nil || traffic.Hash() != constraintHash {
		return sharing.PolicyDestination{}, sharing.ErrUnavailable
	}
	contract, err := sharing.NewContract(sharing.ContractParams{
		ID: contractID, ImportedResourceID: importedID, OfferID: offerID, ExportID: exportID,
		ProviderScope: providerScope, ConsumerScope: consumerScope, Resource: binding,
		MaximumTraffic:              traffic,
		ProviderAuthorityGeneration: record.ProviderAuthorityGeneration,
		ConsumerAuthorityGeneration: record.ConsumerAuthorityGeneration,
		RecoveryEpoch:               record.RecoveryEpoch, ExpiresAt: record.ExpiresAt,
		State: sharing.ContractStateActive, Version: record.ContractVersion,
	})
	if err != nil || !contract.IsUsableAt(
		evaluatedAt,
		record.RecoveryEpoch,
		record.ProviderAuthorityGeneration,
		record.ConsumerAuthorityGeneration,
		record.ResourceVersion,
		record.TargetGeneration,
		semanticHash,
	) {
		return sharing.PolicyDestination{}, sharing.ErrConflict
	}
	value, err := sharing.NewPolicyDestination(sharing.PolicyDestinationParams{
		ImportedResourceID: importedID, ImportedResourceVersion: record.ImportedResourceVersion,
		Contract: contract, ExportVersion: record.ExportVersion,
		ProviderInventoryRevision: record.ProviderInventoryRevision,
		ProviderSharingRevision:   record.ProviderSharingRevision,
		ConsumerSharingRevision:   record.ConsumerSharingRevision,
		EvaluatedAt:               evaluatedAt,
	})
	if err != nil {
		return sharing.PolicyDestination{}, fmt.Errorf("decode policy destination: %w", err)
	}
	return value, nil
}
