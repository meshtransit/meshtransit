package sharing

import "meshtransit.net/core/internal/domain/resource"

// ContractSnapshotParams supplies one consumer-local management projection.
type ContractSnapshotParams struct {
	Contract                Contract
	ImportedDisplayName     resource.DisplayName
	ImportedResourceVersion int64
	AccessName              AccessName
}

// ContractSnapshot is read evidence, never packet authorization.
type ContractSnapshot struct{ params ContractSnapshotParams }

// NewContractSnapshot validates the durable contract and its local projection.
func NewContractSnapshot(params ContractSnapshotParams) (ContractSnapshot, error) {
	snapshot := ContractSnapshot{params: params}
	if !snapshot.IsValid() {
		return ContractSnapshot{}, ErrInvalidManagementRequest
	}
	return snapshot, nil
}

// IsValid reports whether both durable and local metadata are well formed.
func (snapshot ContractSnapshot) IsValid() bool {
	return snapshot.params.Contract.IsValid() && snapshot.params.ImportedDisplayName.IsValid() &&
		snapshot.params.ImportedResourceVersion > 0 && snapshot.params.AccessName.IsValid()
}

// Contract returns the current immutable bilateral contract.
func (snapshot ContractSnapshot) Contract() Contract { return snapshot.params.Contract }

// ImportedDisplayName returns the consumer-local label.
func (snapshot ContractSnapshot) ImportedDisplayName() resource.DisplayName {
	return snapshot.params.ImportedDisplayName
}

// ImportedResourceVersion returns the current consumer projection version.
func (snapshot ContractSnapshot) ImportedResourceVersion() int64 {
	return snapshot.params.ImportedResourceVersion
}

// AccessName returns reserved or withdrawn naming intent, not DNS authorization.
func (snapshot ContractSnapshot) AccessName() AccessName { return snapshot.params.AccessName }
