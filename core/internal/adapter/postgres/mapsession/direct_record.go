package mapsession

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/resource/catalog"
	"meshtransit.net/core/internal/domain/sharing"
)

// This adapter accepts only the durable schema-80 profile. Installing independently
// configured ceilings must disable that profile until their authority is resolved.
const noAdditionalTrafficCeilings = "no-additional-traffic-ceilings-v1"
const maximumDirectEdgeBytes = 64 * 1024

type directTrafficRecord struct {
	Protocol string     `json:"protocol"`
	Ranges   [][2]int64 `json:"ranges"`
}

type directEdgeRecord struct {
	EvaluatedAt                 time.Time `json:"evaluated_at"`
	CeilingProfile              string    `json:"ceiling_profile"`
	ProviderWorkspaceID         string    `json:"provider_workspace_id"`
	ConsumerWorkspaceID         string    `json:"consumer_workspace_id"`
	ProviderNetworkID           string    `json:"provider_network_id"`
	ConsumerNetworkID           string    `json:"consumer_network_id"`
	ProviderNetworkRevision     int64     `json:"provider_network_revision"`
	ConsumerNetworkRevision     int64     `json:"consumer_network_revision"`
	ConsumerPolicyRevision      int64     `json:"consumer_policy_revision"`
	ProviderInventoryRevision   int64     `json:"provider_inventory_revision"`
	ProviderSharingRevision     int64     `json:"provider_sharing_revision"`
	ConsumerSharingRevision     int64     `json:"consumer_sharing_revision"`
	ProviderAuthorityGeneration int64     `json:"provider_authority_generation"`
	ConsumerAuthorityGeneration int64     `json:"consumer_authority_generation"`
	RecoveryEpoch               int64     `json:"recovery_epoch"`
	Contract                    struct {
		ID                      string    `json:"id"`
		Version                 int64     `json:"version"`
		ImportedResourceID      string    `json:"imported_resource_id"`
		ImportedResourceVersion int64     `json:"imported_resource_version"`
		OfferID                 string    `json:"offer_id"`
		ExportID                string    `json:"export_id"`
		ExpiresAt               time.Time `json:"expires_at"`
		ConstraintHash          string    `json:"constraint_hash"`
	} `json:"contract"`
	Export struct {
		Version     int64                 `json:"version"`
		ExpiresAt   time.Time             `json:"expires_at"`
		Constraints []directTrafficRecord `json:"constraints"`
	} `json:"export"`
	Endpoint struct {
		ID              string    `json:"id"`
		AccessName      string    `json:"access_name"`
		Generation      int64     `json:"generation"`
		ExpiresAt       time.Time `json:"expires_at"`
		ResourceAddress string    `json:"resource_address"`
	} `json:"endpoint"`
	Target directTargetRecord `json:"target"`
	Rule   struct {
		ID       string     `json:"id"`
		SourceID string     `json:"source_id"`
		Protocol string     `json:"protocol"`
		Ranges   [][2]int64 `json:"ranges"`
	} `json:"rule"`
	Aliases *aliasEdgeRecord `json:"aliases,omitempty"`
	Peer    struct {
		NumericNodeID     int64     `json:"numeric_node_id"`
		NumericOwnerID    int64     `json:"numeric_owner_id"`
		ID                string    `json:"id"`
		OwnerID           string    `json:"owner_id"`
		Hostname          string    `json:"hostname"`
		MachineKey        string    `json:"machine_key"`
		NodeKey           string    `json:"node_key"`
		SessionGeneration int64     `json:"session_generation"`
		CreatedAt         time.Time `json:"created_at"`
		KeyExpiry         time.Time `json:"key_expiry"`
		Addresses         []string  `json:"addresses"`
	} `json:"peer"`
}

type directTargetRecord struct {
	ID                       string    `json:"id"`
	Version                  int64     `json:"version"`
	TargetGeneration         int64     `json:"target_generation"`
	SemanticHash             string    `json:"semantic_hash"`
	DisplayName              string    `json:"display_name"`
	DeviceID                 string    `json:"device_id"`
	OwnerID                  string    `json:"owner_id"`
	CustodianID              string    `json:"custodian_id"`
	ActivatedNetworkRevision int64     `json:"activated_network_revision"`
	InventoryRevision        int64     `json:"inventory_revision"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

func decodeDirectEdge(value []byte, self appmapsession.Snapshot) (appmapsession.DirectDeviceProjection, error) {
	if len(value) == 0 || len(value) > maximumDirectEdgeBytes {
		return appmapsession.DirectDeviceProjection{}, ErrSnapshotEvidence
	}
	var record directEdgeRecord
	if err := json.Unmarshal(value, &record); err != nil {
		return appmapsession.DirectDeviceProjection{}, errors.Join(ErrSnapshotEvidence, err)
	}
	if record.Aliases != nil {
		return appmapsession.DirectDeviceProjection{}, ErrSnapshotEvidence
	}
	return record.projection(self)
}

func (record directEdgeRecord) projection(self appmapsession.Snapshot) (appmapsession.DirectDeviceProjection, error) {
	var parseErr error
	provider := evidenceValue(scopePair(record.ProviderWorkspaceID), record.ProviderNetworkID, &parseErr)
	consumer := evidenceValue(scopePair(record.ConsumerWorkspaceID), record.ConsumerNetworkID, &parseErr)
	target := evidenceValue(record.Target.value, provider, &parseErr)
	maximum := evidenceValue(directTrafficSet, record.Export.Constraints, &parseErr)
	constraintHash := evidenceValue(directDigest, record.Contract.ConstraintHash, &parseErr)
	contractID := evidenceValue(sharing.ParseContractID, record.Contract.ID, &parseErr)
	importedID := evidenceValue(sharing.ParseImportedResourceID, record.Contract.ImportedResourceID, &parseErr)
	offerID := evidenceValue(sharing.ParseOfferID, record.Contract.OfferID, &parseErr)
	exportID := evidenceValue(sharing.ParseExportID, record.Contract.ExportID, &parseErr)
	binding := evidenceValue(func(value catalog.Resource) (sharing.ResourceBinding, error) {
		return sharing.NewResourceBinding(value.Scope(), value.ID(), value.Version(), value.TargetGeneration(), value.SemanticHash())
	}, target, &parseErr)
	ceilings := evidenceValue(additionalTrafficCeilings, record.CeilingProfile, &parseErr)
	if parseErr != nil || maximum.Hash() != constraintHash {
		return appmapsession.DirectDeviceProjection{}, errors.Join(ErrSnapshotEvidence, parseErr)
	}
	contract, err := sharing.NewContract(sharing.ContractParams{
		ID: contractID, ImportedResourceID: importedID, OfferID: offerID, ExportID: exportID,
		ProviderScope: provider, ConsumerScope: consumer, Resource: binding, MaximumTraffic: maximum,
		ProviderAuthorityGeneration: record.ProviderAuthorityGeneration,
		ConsumerAuthorityGeneration: record.ConsumerAuthorityGeneration, RecoveryEpoch: record.RecoveryEpoch,
		ExpiresAt: record.Contract.ExpiresAt, State: sharing.ContractStateActive, Version: record.Contract.Version,
	})
	if err != nil {
		return appmapsession.DirectDeviceProjection{}, errors.Join(ErrSnapshotEvidence, err)
	}
	export, err := sharing.NewExport(sharing.ExportParams{
		ID: exportID, ProviderScope: provider, ConsumerScope: consumer, Resource: binding,
		MaximumTraffic: maximum, ProviderAuthorityGeneration: record.ProviderAuthorityGeneration,
		ExpiresAt: record.Export.ExpiresAt, State: sharing.ExportStateActive, Version: record.Export.Version,
	})
	if err != nil {
		return appmapsession.DirectDeviceProjection{}, errors.Join(ErrSnapshotEvidence, err)
	}
	resolution, err := sharing.NewPolicyDestination(sharing.PolicyDestinationParams{
		ImportedResourceID: importedID, ImportedResourceVersion: record.Contract.ImportedResourceVersion,
		Contract: contract, ExportVersion: record.Export.Version,
		ProviderInventoryRevision: record.ProviderInventoryRevision,
		ProviderSharingRevision:   record.ProviderSharingRevision, ConsumerSharingRevision: record.ConsumerSharingRevision,
		EvaluatedAt: record.EvaluatedAt,
	})
	if err != nil {
		return appmapsession.DirectDeviceProjection{}, errors.Join(ErrSnapshotEvidence, err)
	}
	ruleID := evidenceValue(policy.ParseRuleID, record.Rule.ID, &parseErr)
	sourceID := evidenceValue(node.ParseID, record.Rule.SourceID, &parseErr)
	ruleTraffic := evidenceValue(directTrafficSet, []directTrafficRecord{{Protocol: record.Rule.Protocol, Ranges: record.Rule.Ranges}}, &parseErr)
	endpointID := evidenceValue(sharing.ParsePrivateEndpointID, record.Endpoint.ID, &parseErr)
	accessName := evidenceValue(sharing.ParseAccessName, record.Endpoint.AccessName, &parseErr)
	resourceAddress := evidenceValue(netip.ParseAddr, record.Endpoint.ResourceAddress, &parseErr)
	peerScope := provider
	if self.Scope() == provider {
		peerScope = consumer
	}
	peer := evidenceValue(record.peerCandidate, peerScope, &parseErr)
	if parseErr != nil {
		return appmapsession.DirectDeviceProjection{}, errors.Join(ErrSnapshotEvidence, parseErr)
	}
	traffic := ruleTraffic.Constraints()[0]
	rule, err := publication.NewImportedResourceDestination(publication.ImportedResourceDestinationParams{
		RuleID: ruleID, SourceNodeID: sourceID, Resolution: resolution,
		Protocol: traffic.Protocol(), DestinationPortRanges: traffic.DestinationPortRanges(),
	})
	if err != nil {
		return appmapsession.DirectDeviceProjection{}, errors.Join(ErrSnapshotEvidence, err)
	}
	mode := sharing.EndpointModeDirect
	var aliases appmapsession.DeviceAlias
	if record.Aliases != nil {
		mode = sharing.EndpointModeFederationAlias
		aliases, err = record.Aliases.value(self, peer, contractID, endpointID, record.Endpoint.Generation, record.RecoveryEpoch)
		if err != nil {
			return appmapsession.DirectDeviceProjection{}, errors.Join(ErrSnapshotEvidence, err)
		}
	}
	endpoint, err := sharing.NewPrivateEndpoint(sharing.PrivateEndpointParams{
		ID: endpointID, Contract: contract, AccessName: accessName, Mode: mode,
		ResourceAlias: resourceAddress, Generation: record.Endpoint.Generation,
		ImportedResourceVersion: record.Contract.ImportedResourceVersion, Grant: maximum,
		ExpiresAt: record.Endpoint.ExpiresAt, State: sharing.EndpointStateReady,
	})
	if err != nil {
		return appmapsession.DirectDeviceProjection{}, errors.Join(ErrSnapshotEvidence, err)
	}
	projection, err := appmapsession.NewDirectDeviceProjection(appmapsession.DirectDeviceProjectionParams{
		Self: self, Peer: peer, Aliases: aliases, ProviderTarget: target, ProviderExport: export, ConsumerRule: rule,
		ProviderNetworkRevision: record.ProviderNetworkRevision, ConsumerNetworkRevision: record.ConsumerNetworkRevision,
		ConsumerPolicyRevision: record.ConsumerPolicyRevision,
		Authority: sharing.EffectiveAccessParams{
			Contract: contract, EvaluatedAt: record.EvaluatedAt, RecoveryEpoch: record.RecoveryEpoch,
			ProviderAuthorityGeneration: record.ProviderAuthorityGeneration,
			ConsumerAuthorityGeneration: record.ConsumerAuthorityGeneration,
			ResourceVersion:             target.Version(), TargetGeneration: target.TargetGeneration(), ResourceSemanticHash: target.SemanticHash(),
			IsResourceActive: true, IsImportedResourceActive: true,
			ImportedResourceVersion: record.Contract.ImportedResourceVersion, Endpoint: endpoint,
			ConsumerRule: ruleTraffic, ProviderGuardrail: ceilings, ConsumerGuardrail: ceilings, ResourceConstraints: ceilings,
		},
	})
	if err != nil {
		return appmapsession.DirectDeviceProjection{}, errors.Join(ErrSnapshotEvidence, err)
	}
	return projection, nil
}

func (record directTargetRecord) value(scope network.Scope) (catalog.Resource, error) {
	var parseErr error
	id := evidenceValue(resource.ParseID, record.ID, &parseErr)
	name := evidenceValue(resource.ParseDisplayName, record.DisplayName, &parseErr)
	owner := evidenceValue(identity.ParsePrincipalID, record.OwnerID, &parseErr)
	custodian := evidenceValue(identity.ParsePrincipalID, record.CustodianID, &parseErr)
	device := evidenceValue(node.ParseID, record.DeviceID, &parseErr)
	digest := evidenceValue(directDigest, record.SemanticHash, &parseErr)
	hash := evidenceValue(resource.NewSemanticHash, digest, &parseErr)
	if parseErr != nil {
		return catalog.Resource{}, errors.Join(ErrSnapshotEvidence, parseErr)
	}
	return catalog.NewResource(catalog.ResourceParams{
		ID: id, Scope: scope, DisplayName: name, OwnerPrincipalID: owner, CustodianPrincipalID: custodian,
		DeviceID: device, State: resource.StateActive, Provenance: resource.ProvenanceManual,
		Version: record.Version, TargetGeneration: record.TargetGeneration, SemanticHash: hash,
		ActivatedNetworkRevision: record.ActivatedNetworkRevision, InventoryRevision: record.InventoryRevision,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	})
}

func (record directEdgeRecord) peerCandidate(scope network.Scope) (appmapsession.PeerCandidate, error) {
	machine, err := hex.DecodeString(record.Peer.MachineKey)
	if err != nil {
		return appmapsession.PeerCandidate{}, ErrSnapshotEvidence
	}
	key, err := hex.DecodeString(record.Peer.NodeKey)
	if err != nil {
		return appmapsession.PeerCandidate{}, ErrSnapshotEvidence
	}
	return (peerCandidateRecord{
		numericNodeID: record.Peer.NumericNodeID, numericOwnerID: record.Peer.NumericOwnerID,
		nodeID: record.Peer.ID, ownerID: record.Peer.OwnerID, hostname: record.Peer.Hostname,
		machineKey: machine, nodeKey: key, sessionGeneration: record.Peer.SessionGeneration,
		createdAt: record.Peer.CreatedAt, keyExpiry: record.Peer.KeyExpiry, addresses: record.Peer.Addresses,
	}).candidate(scope)
}

func directTrafficSet(records []directTrafficRecord) (sharing.TrafficSet, error) {
	if len(records) == 0 || len(records) > sharing.MaximumTrafficConstraints {
		return sharing.TrafficSet{}, ErrSnapshotEvidence
	}
	constraints := make([]sharing.TrafficConstraint, len(records))
	for index, record := range records {
		protocol, err := protocolFromText(record.Protocol)
		if err != nil || len(record.Ranges) > policy.MaximumPortRangesPerRule {
			return sharing.TrafficSet{}, ErrSnapshotEvidence
		}
		ports := make([]policy.PortRange, len(record.Ranges))
		for portIndex, interval := range record.Ranges {
			if interval[0] < 1 || interval[0] > 65535 || interval[1] < interval[0] || interval[1] > 65535 {
				return sharing.TrafficSet{}, ErrSnapshotEvidence
			}
			ports[portIndex], err = policy.NewPortRange(uint16(interval[0]), uint16(interval[1])) // #nosec G115 -- both values are checked against uint16 bounds above.
			if err != nil {
				return sharing.TrafficSet{}, ErrSnapshotEvidence
			}
		}
		constraints[index], err = sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
			Protocol: protocol, DestinationPortRanges: ports,
		})
		if err != nil {
			return sharing.TrafficSet{}, ErrSnapshotEvidence
		}
	}
	return sharing.NewTrafficSet(constraints)
}

func additionalTrafficCeilings(profile string) (sharing.TrafficSet, error) {
	if profile != noAdditionalTrafficCeilings {
		return sharing.TrafficSet{}, ErrSnapshotEvidence
	}
	// Intersection identity, never an Access Rule or a substitute for an export.
	return directTrafficSet([]directTrafficRecord{
		{Protocol: "tcp", Ranges: [][2]int64{{1, 65535}}},
		{Protocol: "udp", Ranges: [][2]int64{{1, 65535}}},
		{Protocol: "icmp", Ranges: [][2]int64{}},
	})
}

func directDigest(value string) ([32]byte, error) {
	var digest [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		return digest, ErrSnapshotEvidence
	}
	copy(digest[:], decoded)
	if digest == [32]byte{} {
		return digest, ErrSnapshotEvidence
	}
	return digest, nil
}

func scopePair(workspaceID string) func(string) (network.Scope, error) {
	return func(networkID string) (network.Scope, error) { return scopeFromText(workspaceID, networkID) }
}

// Accumulate independent boundary parse failures before constructing any grant.
func evidenceValue[Input, Output any](parse func(Input) (Output, error), input Input, resultErr *error) Output {
	value, err := parse(input)
	if err != nil {
		*resultErr = errors.Join(*resultErr, err)
	}
	return value
}
