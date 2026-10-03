package mapsession

import (
	"encoding/json"
	"errors"
	appmapsession "github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"time"
)

type aliasEdgeRecord struct {
	LocalAddresses  []string  `json:"local_addresses"`
	RemoteAddresses []string  `json:"remote_addresses"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func decodeAliasEdge(encoded []byte, self appmapsession.Snapshot) (appmapsession.DirectDeviceProjection, error) {
	if len(encoded) == 0 || len(encoded) > maximumDirectEdgeBytes {
		return appmapsession.DirectDeviceProjection{}, ErrSnapshotEvidence
	}
	var record directEdgeRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		return appmapsession.DirectDeviceProjection{}, errors.Join(ErrSnapshotEvidence, err)
	}
	if record.Aliases == nil {
		return appmapsession.DirectDeviceProjection{}, ErrSnapshotEvidence
	}
	return record.projection(self)
}

func (record aliasEdgeRecord) value(self appmapsession.Snapshot, peer appmapsession.PeerCandidate, contract sharing.ContractID, endpoint sharing.PrivateEndpointID, generation, recovery int64) (appmapsession.DeviceAlias, error) {
	if len(record.LocalAddresses) < 1 || len(record.LocalAddresses) > 2 || len(record.RemoteAddresses) != len(record.LocalAddresses) {
		return appmapsession.DeviceAlias{}, ErrSnapshotEvidence
	}
	local, err := addressesFromText(record.LocalAddresses)
	if err != nil {
		return appmapsession.DeviceAlias{}, err
	}
	remote, err := addressesFromText(record.RemoteAddresses)
	if err != nil {
		return appmapsession.DeviceAlias{}, err
	}
	return appmapsession.NewDeviceAlias(appmapsession.DeviceAliasParams{
		ContractID: contract, EndpointID: endpoint, Generation: generation, RecoveryEpoch: recovery,
		SelfKey: self.NodeKey(), PeerKey: peer.NodeKey(), SelfSessionGeneration: self.SessionGeneration(), PeerSessionGeneration: peer.SessionGeneration(),
		LocalAddresses: local, RemoteAddresses: remote, ExpiresAt: record.ExpiresAt,
	})
}
