package postgres

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

type resourceSharingTrafficRecord struct {
	Protocol string     `json:"protocol"`
	Ranges   [][2]int64 `json:"ranges"`
}

type resourceSharingContractRecord struct {
	ID                          string     `json:"contract_id"`
	ImportedResourceID          string     `json:"imported_resource_id"`
	ProviderAuthorityGeneration int64      `json:"provider_authority_generation"`
	ConsumerAuthorityGeneration int64      `json:"consumer_authority_generation"`
	RecoveryEpoch               int64      `json:"recovery_epoch"`
	ExpiresAt                   time.Time  `json:"expires_at"`
	State                       string     `json:"state"`
	Version                     int64      `json:"version"`
	EndedAt                     *time.Time `json:"ended_at"`
}

type resourceSharingOfferRecord struct {
	OfferID                     string                         `json:"offer_id"`
	ExportID                    string                         `json:"export_id"`
	ProviderWorkspaceID         string                         `json:"provider_workspace_id"`
	ProviderNetworkID           string                         `json:"provider_network_id"`
	ConsumerWorkspaceID         string                         `json:"consumer_workspace_id"`
	ConsumerNetworkID           string                         `json:"consumer_network_id"`
	ResourceID                  string                         `json:"resource_id"`
	ResourceVersion             int64                          `json:"resource_version"`
	TargetGeneration            int64                          `json:"target_generation"`
	ResourceSemanticHash        string                         `json:"resource_semantic_hash"`
	ProviderAuthorityGeneration int64                          `json:"provider_authority_generation"`
	ExportExpiresAt             time.Time                      `json:"export_expires_at"`
	ExportState                 string                         `json:"export_state"`
	ExportVersion               int64                          `json:"export_version"`
	NonceDigest                 string                         `json:"nonce_digest"`
	OfferExpiresAt              time.Time                      `json:"offer_expires_at"`
	OfferState                  string                         `json:"offer_state"`
	OfferVersion                int64                          `json:"offer_version"`
	OfferDecidedAt              *time.Time                     `json:"offer_decided_at"`
	AcceptedContractID          *string                        `json:"accepted_contract_id"`
	CreatedAt                   time.Time                      `json:"created_at"`
	Constraints                 []resourceSharingTrafficRecord `json:"constraints"`
	Contract                    *resourceSharingContractRecord `json:"contract"`
}

type resourceSharingProjection struct {
	offer    sharing.OfferSnapshot
	contract sharing.Contract
}

func decodeResourceSharingOffer(value string) (resourceSharingProjection, error) {
	var record resourceSharingOfferRecord
	if err := json.Unmarshal([]byte(value), &record); err != nil {
		return resourceSharingProjection{}, fmt.Errorf("decode Resource Sharing projection: %w", err)
	}
	return record.value()
}

func decodeResourceSharingOffers(value string) ([]resourceSharingProjection, error) {
	var records []resourceSharingOfferRecord
	if err := json.Unmarshal([]byte(value), &records); err != nil {
		return nil, fmt.Errorf("decode Resource Sharing page: %w", err)
	}
	values := make([]resourceSharingProjection, len(records))
	for index, record := range records {
		projection, err := record.value()
		if err != nil {
			return nil, err
		}
		values[index] = projection
	}
	return values, nil
}

func (record resourceSharingOfferRecord) value() (resourceSharingProjection, error) {
	providerScope, err := resourceSharingScope(record.ProviderWorkspaceID, record.ProviderNetworkID)
	if err != nil {
		return resourceSharingProjection{}, err
	}
	consumerScope, err := resourceSharingScope(record.ConsumerWorkspaceID, record.ConsumerNetworkID)
	if err != nil || providerScope == consumerScope {
		return resourceSharingProjection{}, sharing.ErrUnavailable
	}
	resourceID, err := resource.ParseID(record.ResourceID)
	if err != nil {
		return resourceSharingProjection{}, sharing.ErrUnavailable
	}
	semanticHash, err := resourceSharingSemanticHash(record.ResourceSemanticHash)
	if err != nil {
		return resourceSharingProjection{}, err
	}
	binding, err := sharing.NewResourceBinding(
		providerScope,
		resourceID,
		record.ResourceVersion,
		record.TargetGeneration,
		semanticHash,
	)
	if err != nil {
		return resourceSharingProjection{}, sharing.ErrUnavailable
	}
	maximumTraffic, err := resourceSharingTrafficSet(record.Constraints)
	if err != nil {
		return resourceSharingProjection{}, err
	}
	exportID, err := sharing.ParseExportID(record.ExportID)
	if err != nil {
		return resourceSharingProjection{}, sharing.ErrUnavailable
	}
	offerID, err := sharing.ParseOfferID(record.OfferID)
	if err != nil {
		return resourceSharingProjection{}, sharing.ErrUnavailable
	}
	nonceDigest, err := resourceSharingDigest(record.NonceDigest)
	if err != nil {
		return resourceSharingProjection{}, err
	}
	acceptedContractID := sharing.ContractID{}
	if record.AcceptedContractID != nil {
		acceptedContractID, err = sharing.ParseContractID(*record.AcceptedContractID)
		if err != nil {
			return resourceSharingProjection{}, sharing.ErrUnavailable
		}
	}
	decidedAt := time.Time{}
	if record.OfferDecidedAt != nil {
		decidedAt = record.OfferDecidedAt.UTC()
	}
	offer, err := sharing.NewOffer(sharing.OfferParams{
		ID: offerID, ExportID: exportID,
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		MaximumTraffic: maximumTraffic, NonceDigest: nonceDigest,
		ExpiresAt: record.OfferExpiresAt, State: resourceSharingOfferState(record.OfferState),
		Version: record.OfferVersion, DecidedAt: decidedAt,
		AcceptedContractID: acceptedContractID,
	})
	if err != nil {
		return resourceSharingProjection{}, sharing.ErrUnavailable
	}
	snapshot, err := sharing.NewOfferSnapshot(offer, binding, record.CreatedAt)
	if err != nil {
		return resourceSharingProjection{}, sharing.ErrUnavailable
	}
	projection := resourceSharingProjection{offer: snapshot}
	if record.Contract == nil {
		return projection, nil
	}
	contractID, err := sharing.ParseContractID(record.Contract.ID)
	if err != nil {
		return resourceSharingProjection{}, sharing.ErrUnavailable
	}
	importedID, err := sharing.ParseImportedResourceID(record.Contract.ImportedResourceID)
	if err != nil {
		return resourceSharingProjection{}, sharing.ErrUnavailable
	}
	endedAt := time.Time{}
	if record.Contract.EndedAt != nil {
		endedAt = record.Contract.EndedAt.UTC()
	}
	contract, err := sharing.NewContract(sharing.ContractParams{
		ID: contractID, ImportedResourceID: importedID, OfferID: offerID, ExportID: exportID,
		ProviderScope: providerScope, ConsumerScope: consumerScope, Resource: binding,
		MaximumTraffic:              maximumTraffic,
		ProviderAuthorityGeneration: record.Contract.ProviderAuthorityGeneration,
		ConsumerAuthorityGeneration: record.Contract.ConsumerAuthorityGeneration,
		RecoveryEpoch:               record.Contract.RecoveryEpoch, ExpiresAt: record.Contract.ExpiresAt,
		State:   resourceSharingContractState(record.Contract.State),
		Version: record.Contract.Version, EndedAt: endedAt,
	})
	if err != nil || contract.ID() != acceptedContractID {
		return resourceSharingProjection{}, sharing.ErrUnavailable
	}
	projection.contract = contract
	return projection, nil
}

func resourceSharingScope(workspaceValue, networkValue string) (network.Scope, error) {
	workspaceID, workspaceErr := workspace.ParseID(workspaceValue)
	networkID, networkErr := network.ParseID(networkValue)
	if workspaceErr != nil || networkErr != nil {
		return network.Scope{}, sharing.ErrUnavailable
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return network.Scope{}, sharing.ErrUnavailable
	}
	return scope, nil
}

func resourceSharingSemanticHash(encoded string) (resource.SemanticHash, error) {
	digest, err := resourceSharingDigest(encoded)
	if err != nil {
		return resource.SemanticHash{}, err
	}
	value, err := resource.NewSemanticHash(digest)
	if err != nil {
		return resource.SemanticHash{}, sharing.ErrUnavailable
	}
	return value, nil
}

func resourceSharingDigest(encoded string) ([32]byte, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, sharing.ErrUnavailable
	}
	var digest [32]byte
	copy(digest[:], decoded)
	if digest == ([32]byte{}) {
		return [32]byte{}, sharing.ErrUnavailable
	}
	return digest, nil
}

func resourceSharingTrafficSet(records []resourceSharingTrafficRecord) (sharing.TrafficSet, error) {
	constraints := make([]sharing.TrafficConstraint, len(records))
	for index, record := range records {
		protocol := resourceSharingProtocol(record.Protocol)
		ranges := make([]policy.PortRange, len(record.Ranges))
		for rangeIndex, raw := range record.Ranges {
			if raw[0] < 1 || raw[0] > 65535 || raw[1] < raw[0] || raw[1] > 65535 {
				return sharing.TrafficSet{}, sharing.ErrUnavailable
			}
			// #nosec G115 -- both values are range-checked against uint16's positive domain above.
			value, err := policy.NewPortRange(uint16(raw[0]), uint16(raw[1]))
			if err != nil {
				return sharing.TrafficSet{}, sharing.ErrUnavailable
			}
			ranges[rangeIndex] = value
		}
		constraint, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
			Protocol: protocol, DestinationPortRanges: ranges,
		})
		if err != nil {
			return sharing.TrafficSet{}, sharing.ErrUnavailable
		}
		constraints[index] = constraint
	}
	set, err := sharing.NewTrafficSet(constraints)
	if err != nil {
		return sharing.TrafficSet{}, sharing.ErrUnavailable
	}
	return set, nil
}

func resourceSharingProtocol(value string) policy.Protocol {
	switch value {
	case "tcp":
		return policy.ProtocolTCP
	case "udp":
		return policy.ProtocolUDP
	case "icmp":
		return policy.ProtocolICMP
	default:
		return policy.ProtocolUnknown
	}
}

func resourceSharingOfferState(value string) sharing.OfferState {
	switch value {
	case "offered":
		return sharing.OfferStateOffered
	case "accepted":
		return sharing.OfferStateAccepted
	case "rejected":
		return sharing.OfferStateRejected
	case "expired":
		return sharing.OfferStateExpired
	case "revoked":
		return sharing.OfferStateRevoked
	default:
		return sharing.OfferStateUnknown
	}
}

func resourceSharingContractState(value string) sharing.ContractState {
	switch value {
	case "activating":
		return sharing.ContractStateActivating
	case "active":
		return sharing.ContractStateActive
	case "revoked":
		return sharing.ContractStateRevoked
	case "expired":
		return sharing.ContractStateExpired
	case "invalidated":
		return sharing.ContractStateInvalidated
	default:
		return sharing.ContractStateUnknown
	}
}

func resourceSharingDirection(value sharing.Direction) string {
	if value == sharing.DirectionOutgoing {
		return "outgoing"
	}
	if value == sharing.DirectionIncoming {
		return "incoming"
	}
	return ""
}

func resourceSharingOfferStateFilter(value sharing.OfferState) any {
	switch value {
	case sharing.OfferStateUnknown:
		return nil
	case sharing.OfferStateOffered:
		return "offered"
	case sharing.OfferStateAccepted:
		return "accepted"
	case sharing.OfferStateRejected:
		return "rejected"
	case sharing.OfferStateExpired:
		return "expired"
	case sharing.OfferStateRevoked:
		return "revoked"
	default:
		return errors.New("invalid Resource Sharing offer state")
	}
}
