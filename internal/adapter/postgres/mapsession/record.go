package mapsession

import (
	"net/netip"
	"time"

	appmapsession "github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

type snapshotRecord struct {
	numericNodeID     int64
	numericOwnerID    int64
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
}

type peerCandidateRecord struct {
	nodeID            string
	ownerID           string
	hostname          string
	machineKey        []byte
	nodeKey           []byte
	sessionGeneration int64
	createdAt         time.Time
	keyExpiry         time.Time
	addresses         []string
}

func (record snapshotRecord) snapshot(
	workspaceValue string,
	networkValue string,
	recoveryEpoch int64,
	peerCandidates []appmapsession.PeerCandidate,
	packetPolicy policy.Snapshot,
) (appmapsession.Snapshot, error) {
	scope, err := scopeFromText(workspaceValue, networkValue)
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
	snapshot, err := appmapsession.NewSnapshot(appmapsession.SnapshotParams{
		Scope:             scope,
		NetworkRevision:   record.networkRevision,
		RecoveryEpoch:     recoveryEpoch,
		SessionGeneration: record.sessionGeneration,
		NumericNodeID:     record.numericNodeID,
		NumericOwnerID:    record.numericOwnerID,
		NodeID:            nodeID,
		Hostname:          hostname,
		MachineKey:        machineKey,
		NodeKey:           nodeKey,
		Addresses:         addresses,
		CreatedAt:         record.createdAt,
		KeyExpiry:         record.keyExpiry,
		PeerCandidates:    peerCandidates,
		PacketPolicy:      packetPolicy,
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
	candidate, err := appmapsession.NewPeerCandidate(appmapsession.PeerCandidateParams{
		Scope:             scope,
		NodeID:            nodeID,
		OwnerID:           ownerID,
		Hostname:          hostname,
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
