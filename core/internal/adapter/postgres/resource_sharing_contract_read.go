package postgres

import (
	"context"
	"errors"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
	"time"
)

// Consumer-only RLS and exact joins retain historical names without granting access.
const readConsumerContractMetadataSQL = `SELECT imported.version, imported.display_name, name.access_name
FROM mesh.imported_resource imported
JOIN mesh.trust_contract contract ON contract.id=imported.trust_contract_id
 AND contract.consumer_workspace_id=imported.workspace_id
 AND contract.consumer_network_id=imported.network_id
 AND contract.imported_resource_public_id=imported.public_id
JOIN mesh.imported_resource_access_name name ON name.imported_resource_id=imported.id
 AND name.workspace_id=imported.workspace_id AND name.network_id=imported.network_id
WHERE imported.workspace_id=mesh_ops.current_workspace_id()
 AND imported.network_id=mesh_ops.current_network_id()
 AND contract.public_id=$1::UUID AND imported.public_id=$2::UUID`

// GetContract reads one repeatable, freshly authorized consumer-local snapshot.
func (store *ResourceSharingStore) GetContract(ctx context.Context, session accountsession.Session, scope network.Scope, id sharing.ContractID, evaluatedAt time.Time) (_ sharing.ContractSnapshot, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !session.IsValid() ||
		!scope.IsValid() || !id.IsValid() || evaluatedAt.IsZero() || !validResourceSharingOptions(store.options) {
		return sharing.ContractSnapshot{}, sharing.ErrInvalidManagementRequest
	}
	transaction, err := store.begin(ctx)
	if err != nil {
		return sharing.ContractSnapshot{}, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceSharing(transaction))
		}
	}()
	if _, err := setResourceSharingScope(ctx, transaction, scope); err != nil {
		return sharing.ContractSnapshot{}, err
	}
	if _, err := authorizeResourceSharing(ctx, transaction, session, scope, authorization.PermissionShareRead, evaluatedAt); err != nil {
		return sharing.ContractSnapshot{}, err
	}
	locator, err := readResourceSharingContractLocator(ctx, transaction, id)
	if err != nil {
		return sharing.ContractSnapshot{}, err
	}
	if locator.consumer.scope != scope {
		return sharing.ContractSnapshot{}, sharing.ErrNotFound
	}
	projection, err := readResourceSharingOffer(ctx, transaction, locator.offerID)
	if err != nil {
		return sharing.ContractSnapshot{}, err
	}
	contract := projection.contract
	if !contract.IsValid() || contract.ID() != id || contract.ConsumerScope() != scope {
		return sharing.ContractSnapshot{}, sharing.ErrUnavailable
	}
	var importedVersion int64
	var nameValue, accessValue string
	if err := transaction.QueryRow(ctx, readConsumerContractMetadataSQL, id.String(), contract.ImportedResourceID().String()).Scan(&importedVersion, &nameValue, &accessValue); err != nil {
		return sharing.ContractSnapshot{}, resourceSharingDatabaseError(ctx, err)
	}
	name, err := resource.ParseDisplayName(nameValue)
	if err != nil {
		return sharing.ContractSnapshot{}, sharing.ErrUnavailable
	}
	accessName, err := sharing.ParseAccessName(accessValue)
	if err != nil {
		return sharing.ContractSnapshot{}, sharing.ErrUnavailable
	}
	snapshot, err := sharing.NewContractSnapshot(sharing.ContractSnapshotParams{
		Contract: contract, ImportedDisplayName: name, ImportedResourceVersion: importedVersion, AccessName: accessName,
	})
	if err != nil {
		return sharing.ContractSnapshot{}, sharing.ErrUnavailable
	}
	if err := transaction.Commit(ctx); err != nil {
		return sharing.ContractSnapshot{}, resourceSharingDatabaseError(ctx, err)
	}
	closed = true
	return snapshot, nil
}
