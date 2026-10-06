package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

// maximumAccessGraphContextBytes bounds the explanation context document;
// it holds two short names, codes and one DNS name.
const maximumAccessGraphContextBytes = 4 * 1024

// accessGraphContextRecord is the context document of explain_active_policy_v3.
type accessGraphContextRecord struct {
	Source accessGraphParticipantRecord `json:"source"`
	Target accessGraphTargetRecord      `json:"target"`
	Share  *accessGraphShareRecord      `json:"share"`
}

type accessGraphParticipantRecord struct {
	State string  `json:"state"`
	Name  *string `json:"name"`
}

type accessGraphTargetRecord struct {
	Kind  string  `json:"kind"`
	State string  `json:"state"`
	Name  *string `json:"name"`
}

type accessGraphShareRecord struct {
	TrustContractID       string     `json:"trust_contract_id"`
	State                 string     `json:"state"`
	ExpiresAt             *time.Time `json:"expires_at"`
	ProviderWorkspaceCode *string    `json:"provider_workspace_code"`
	ProviderNetworkCode   *string    `json:"provider_network_code"`
	AccessName            *string    `json:"access_name"`
}

// decodeAccessGraphContext strictly decodes one bounded context document.
// Unknown fields, trailing data and oversized input are rejected.
func decodeAccessGraphContext(encoded string) (accessGraphContextRecord, error) {
	if len(encoded) > maximumAccessGraphContextBytes {
		return accessGraphContextRecord{}, accessgraph.ErrInvalidSnapshot
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	decoder.DisallowUnknownFields()
	var record accessGraphContextRecord
	if err := decoder.Decode(&record); err != nil {
		return accessGraphContextRecord{}, errors.Join(accessgraph.ErrInvalidSnapshot, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return accessGraphContextRecord{}, accessgraph.ErrInvalidSnapshot
	}
	return record, nil
}

// apply copies the validated context into snapshot parameters.
func (record accessGraphContextRecord) apply(params *accessgraph.SnapshotParams) error {
	source, err := record.Source.participant()
	if err != nil {
		return err
	}
	target, err := accessGraphParticipantRecord{State: record.Target.State, Name: record.Target.Name}.participant()
	if err != nil {
		return err
	}
	params.Source, params.Target = source, target
	params.TargetKind = parseAccessGraphTargetKind(record.Target.Kind)
	if record.Share != nil {
		share, err := record.Share.share()
		if err != nil {
			return err
		}
		params.Share = &share
	}
	return nil
}

func (record accessGraphParticipantRecord) participant() (accessgraph.Participant, error) {
	name := ""
	if record.Name != nil {
		name = *record.Name
	}
	return accessgraph.NewParticipant(parseAccessGraphParticipantState(record.State), name)
}

func (record accessGraphShareRecord) share() (accessgraph.ShareContext, error) {
	contractID, err := sharing.ParseContractID(record.TrustContractID)
	if err != nil || record.ProviderWorkspaceCode == nil || record.ProviderNetworkCode == nil {
		return accessgraph.ShareContext{}, accessgraph.ErrInvalidSnapshot
	}
	workspaceCode, workspaceErr := identity.ParseDisplayCode(*record.ProviderWorkspaceCode)
	networkCode, networkErr := identity.ParseDisplayCode(*record.ProviderNetworkCode)
	if workspaceErr != nil || networkErr != nil {
		return accessgraph.ShareContext{}, accessgraph.ErrInvalidSnapshot
	}
	params := accessgraph.ShareContextParams{
		ContractID: contractID, State: resourceSharingContractState(record.State),
		ProviderWorkspaceCode: workspaceCode, ProviderNetworkCode: networkCode,
	}
	if record.ExpiresAt != nil {
		if record.ExpiresAt.IsZero() {
			return accessgraph.ShareContext{}, accessgraph.ErrInvalidSnapshot
		}
		params.ExpiresAt = *record.ExpiresAt
	}
	if record.AccessName != nil {
		params.AccessName = *record.AccessName
	}
	return accessgraph.NewShareContext(params)
}

func parseAccessGraphParticipantState(value string) accessgraph.ParticipantState {
	switch value {
	case "active":
		return accessgraph.ParticipantStateActive
	case "inactive":
		return accessgraph.ParticipantStateInactive
	case "missing":
		return accessgraph.ParticipantStateMissing
	default:
		return accessgraph.ParticipantStateUnknown
	}
}

func parseAccessGraphTargetKind(value string) accessgraph.TargetKind {
	switch value {
	case "device":
		return accessgraph.TargetKindDevice
	case "resource":
		return accessgraph.TargetKindResource
	case "imported_resource":
		return accessgraph.TargetKindImportedResource
	default:
		return accessgraph.TargetKindUnknown
	}
}
