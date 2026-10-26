package mapsession

import (
	"net/netip"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/relay"
	"meshtransit.net/core/internal/domain/workspace"
)

type snapshotRecord struct {
	// readLocal is this host's clock, with its monotonic reading, taken
	// before the read whose database time is readAt.
	readLocal         time.Time
	numericNodeID     int64
	numericOwnerID    int64
	networkName       string
	nodeID            string
	hostname          string
	machineKey        []byte
	nodeKey           []byte
	sessionGeneration int64
	createdAt         time.Time
	keyExpiry         time.Time
	networkRevision   int64
	policyRevision    int64
	addresses         []string
	readAt            time.Time // PostgreSQL transaction time
	// Schema 169: the Device's DNS label and the scope's display codes.
	dnsLabel      *string
	workspaceCode *string
	networkCode   *string
}

type peerCandidateRecord struct {
	numericNodeID     int64
	numericOwnerID    int64
	nodeID            string
	ownerID           string
	hostname          string
	machineKey        []byte
	nodeKey           []byte
	sessionGeneration int64
	createdAt         time.Time
	keyExpiry         time.Time
	addresses         []string
	// dnsLabel is set for every Device of the read scope (schema 169) and
	// absent for a peer of another Network.
	dnsLabel *string
	// kubernetesCluster is set for a gateway replica of the read scope
	// (schema 231).
	kubernetesCluster kubecluster.Name
}

func (record snapshotRecord) snapshot(
	workspaceValue string,
	networkValue string,
	recoveryEpoch int64,
	peerCandidates []appmapsession.PeerCandidate,
	packetPolicy policy.Snapshot,
	relayDirectory relay.Directory,
) (appmapsession.Snapshot, error) {
	scope, err := scopeFromText(workspaceValue, networkValue)
	if err != nil {
		return appmapsession.Snapshot{}, ErrSnapshotEvidence
	}
	networkName, err := network.ParseDisplayName(record.networkName)
	if err != nil {
		return appmapsession.Snapshot{}, ErrSnapshotEvidence
	}
	nodeID, err := node.ParseID(record.nodeID)
	if err != nil {
		return appmapsession.Snapshot{}, ErrSnapshotEvidence
	}
	hostname, err := node.ParseHostname(record.hostname)
	if err != nil {
		return appmapsession.Snapshot{}, ErrSnapshotEvidence
	}
	machineKey, err := machineKeyFromBytes(record.machineKey)
	if err != nil {
		return appmapsession.Snapshot{}, err
	}
	nodeKey, err := nodeKeyFromBytes(record.nodeKey)
	if err != nil {
		return appmapsession.Snapshot{}, err
	}
	addresses, err := addressesFromText(record.addresses)
	if err != nil {
		return appmapsession.Snapshot{}, err
	}
	// Names are discovery metadata: without them the map publishes no Device
	// names, it does not fail.
	dnsLabel := optionalDNSLabel(record.dnsLabel)
	workspaceCode, networkCode := optionalDisplayCodes(record.workspaceCode, record.networkCode)
	snapshot, err := appmapsession.NewSnapshot(appmapsession.SnapshotParams{
		Scope:             scope,
		DatabaseReadAt:    record.readAt,
		ReadAtLocal:       record.readLocal,
		NetworkName:       networkName,
		NetworkRevision:   record.networkRevision,
		RecoveryEpoch:     recoveryEpoch,
		SessionGeneration: record.sessionGeneration,
		NumericNodeID:     record.numericNodeID,
		NumericOwnerID:    record.numericOwnerID,
		NodeID:            nodeID,
		Hostname:          hostname,
		DNSLabel:          dnsLabel,
		WorkspaceCode:     workspaceCode,
		NetworkCode:       networkCode,
		MachineKey:        machineKey,
		NodeKey:           nodeKey,
		Addresses:         addresses,
		CreatedAt:         record.createdAt,
		KeyExpiry:         record.keyExpiry,
		PeerCandidates:    peerCandidates,
		PacketPolicy:      packetPolicy,
		RelayDirectory:    relayDirectory,
	})
	if err != nil {
		return appmapsession.Snapshot{}, ErrSnapshotEvidence
	}
	return snapshot, nil
}

func (record peerCandidateRecord) candidate(
	scope network.Scope,
) (appmapsession.PeerCandidate, error) {
	nodeID, err := node.ParseID(record.nodeID)
	if err != nil {
		return appmapsession.PeerCandidate{}, ErrSnapshotEvidence
	}
	ownerID, err := identity.ParsePrincipalID(record.ownerID)
	if err != nil {
		return appmapsession.PeerCandidate{}, ErrSnapshotEvidence
	}
	hostname, err := node.ParseHostname(record.hostname)
	if err != nil {
		return appmapsession.PeerCandidate{}, ErrSnapshotEvidence
	}
	machineKey, err := machineKeyFromBytes(record.machineKey)
	if err != nil {
		return appmapsession.PeerCandidate{}, err
	}
	nodeKey, err := nodeKeyFromBytes(record.nodeKey)
	if err != nil {
		return appmapsession.PeerCandidate{}, err
	}
	addresses, err := addressesFromText(record.addresses)
	if err != nil {
		return appmapsession.PeerCandidate{}, err
	}
	dnsLabel := optionalDNSLabel(record.dnsLabel)
	candidate, err := appmapsession.NewPeerCandidate(appmapsession.PeerCandidateParams{
		NumericNodeID:     record.numericNodeID,
		NumericOwnerID:    record.numericOwnerID,
		Scope:             scope,
		NodeID:            nodeID,
		OwnerID:           ownerID,
		Hostname:          hostname,
		DNSLabel:          dnsLabel,
		KubernetesCluster: record.kubernetesCluster,
		MachineKey:        machineKey,
		NodeKey:           nodeKey,
		SessionGeneration: record.sessionGeneration,
		Addresses:         addresses,
		CreatedAt:         record.createdAt,
		KeyExpiry:         record.keyExpiry,
	})
	if err != nil {
		return appmapsession.PeerCandidate{}, ErrSnapshotEvidence
	}
	return candidate, nil
}

// optionalDNSLabel is the Device's label, or the zero label when the read
// gave none or a malformed one: such a Device is listed without a name
// (DNSView.Unnamed counts it), never failing the map.
func optionalDNSLabel(value *string) node.DNSLabel {
	if value == nil {
		return node.DNSLabel{}
	}
	label, err := node.ParseDNSLabel(*value)
	if err != nil {
		return node.DNSLabel{}
	}
	return label
}

// optionalDisplayCodes are the scope's display codes, or none when either is
// missing or malformed: the map then names no Device.
func optionalDisplayCodes(workspaceValue, networkValue *string) (identity.DisplayCode, identity.DisplayCode) {
	if workspaceValue == nil || networkValue == nil {
		return "", ""
	}
	workspaceCode, workspaceErr := identity.ParseDisplayCode(*workspaceValue)
	networkCode, networkErr := identity.ParseDisplayCode(*networkValue)
	if workspaceErr != nil || networkErr != nil {
		return "", ""
	}
	return workspaceCode, networkCode
}

func scopeFromText(workspaceValue, networkValue string) (network.Scope, error) {
	workspaceID, err := workspace.ParseID(workspaceValue)
	if err != nil {
		return network.Scope{}, ErrSnapshotEvidence
	}
	networkID, err := network.ParseID(networkValue)
	if err != nil {
		return network.Scope{}, ErrSnapshotEvidence
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return network.Scope{}, ErrSnapshotEvidence
	}
	return scope, nil
}

func machineKeyFromBytes(value []byte) (node.MachineKey, error) {
	if len(value) != 32 {
		return node.MachineKey{}, ErrSnapshotEvidence
	}
	var raw [32]byte
	copy(raw[:], value)
	key, err := node.NewMachineKey(raw)
	clear(raw[:])
	if err != nil {
		return node.MachineKey{}, ErrSnapshotEvidence
	}
	return key, nil
}

func nodeKeyFromBytes(value []byte) (node.Key, error) {
	if len(value) != 32 {
		return node.Key{}, ErrSnapshotEvidence
	}
	var raw [32]byte
	copy(raw[:], value)
	key, err := node.NewKey(raw)
	clear(raw[:])
	if err != nil {
		return node.Key{}, ErrSnapshotEvidence
	}
	return key, nil
}

func addressesFromText(values []string) ([]netip.Prefix, error) {
	addresses := make([]netip.Prefix, len(values))
	for index, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, ErrSnapshotEvidence
		}
		addresses[index] = prefix
	}
	return addresses, nil
}
