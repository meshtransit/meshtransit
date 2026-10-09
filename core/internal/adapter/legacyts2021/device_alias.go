package legacyts2021

import (
	"encoding/json"
	"slices"
	"time"

	"tailscale.com/tailcfg"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/policy"
)

const deviceAliasCapability tailcfg.NodeCapability = "https://meshtransit.io/cap/device-alias-v1"
const maximumAliasDocumentBytes = 8192
const maximumAliasServices = 64

type deviceAliasDocument struct {
	Version       uint64               `json:"version"`
	ContractID    string               `json:"contract_id"`
	EndpointID    string               `json:"endpoint_id"`
	Generation    int64                `json:"generation"`
	GrantRevision uint64               `json:"grant_revision"`
	RecoveryEpoch int64                `json:"recovery_epoch"`
	SelfKey       string               `json:"self_key"`
	PeerKey       string               `json:"peer_key"`
	Role          string               `json:"role"`
	ExpiresAt     time.Time            `json:"expires_at"`
	Services      []deviceAliasService `json:"services"`
}

type deviceAliasService struct {
	Protocol uint8  `json:"protocol"`
	PortFrom uint16 `json:"port_from"`
	PortTo   uint16 `json:"port_to"`
}

func applyDeviceAliasGrant(peer *tailcfg.Node, snapshot mapsession.Snapshot, candidate mapsession.PeerCandidate) error {
	grant, found := snapshot.DeviceAliasFor(candidate.NodeID())
	if !found {
		return nil
	}
	selfKey, err := nodePublicKey(grant.SelfKey)
	if err != nil {
		return err
	}
	peerKey, err := nodePublicKey(grant.PeerKey)
	if err != nil {
		return err
	}
	services, err := deviceAliasServices(grant)
	if err != nil {
		return err
	}
	role := "provider"
	if grant.IsConsumer {
		role = "consumer"
	}
	body, err := json.Marshal(deviceAliasDocument{Version: 1, ContractID: grant.ContractID.String(), EndpointID: grant.EndpointID.String(),
		Generation: grant.Generation, GrantRevision: grant.GrantRevision, RecoveryEpoch: grant.RecoveryEpoch,
		SelfKey: selfKey.String(), PeerKey: peerKey.String(), Role: role, ExpiresAt: grant.ExpiresAt, Services: services})
	if err != nil || len(body) > maximumAliasDocumentBytes {
		return ErrMapResponse
	}
	peer.CapMap = tailcfg.NodeCapMap{deviceAliasCapability: []tailcfg.RawMessage{tailcfg.RawMessage(body)}}
	for _, prefix := range grant.LocalAddresses {
		address := prefix.Addr()
		if address.Is4() {
			peer.SelfNodeV4MasqAddrForThisPeer = &address
		} else {
			peer.SelfNodeV6MasqAddrForThisPeer = &address
		}
	}
	return nil
}

func deviceAliasServices(grant mapsession.DeviceAliasGrant) ([]deviceAliasService, error) {
	values := make([]deviceAliasService, 0, 4)
	for _, constraint := range grant.Traffic.Constraints() {
		switch constraint.Protocol() {
		case policy.ProtocolTCP, policy.ProtocolUDP:
			protocol := uint8(6)
			if constraint.Protocol() == policy.ProtocolUDP {
				protocol = 17
			}
			for _, ports := range constraint.DestinationPortRanges() {
				values = append(values, deviceAliasService{Protocol: protocol, PortFrom: ports.First(), PortTo: ports.Last()})
			}
		case policy.ProtocolICMP:
			for _, prefix := range grant.LocalAddresses {
				protocol := uint8(58)
				if prefix.Addr().Is4() {
					protocol = 1
				}
				values = append(values, deviceAliasService{Protocol: protocol})
			}
		default:
			return nil, ErrMapResponse
		}
	}
	if len(values) == 0 || len(values) > maximumAliasServices {
		return nil, ErrMapResponse
	}
	slices.SortFunc(values, func(a, b deviceAliasService) int {
		if a.Protocol != b.Protocol {
			return int(a.Protocol) - int(b.Protocol)
		}
		return int(a.PortFrom) - int(b.PortFrom)
	})
	return values, nil
}
