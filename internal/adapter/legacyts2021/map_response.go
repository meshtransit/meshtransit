package legacyts2021

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
)

const (
	maxMapResponseBytes    = 256 << 10
	mapResponseContentType = "application/octet-stream"
)

// ErrMapResponse reports invalid authority evidence or a failed bounded encoding.
var ErrMapResponse = errors.New("legacyts2021: map response failed")

type fullMapResponseWire struct {
	Domain       string               `json:"Domain"`
	Node         *tailcfg.Node        `json:"Node"`
	Peers        []*tailcfg.Node      `json:"Peers"`
	PacketFilter []tailcfg.FilterRule `json:"PacketFilter"`
	DERPMap      *tailcfg.DERPMap     `json:"DERPMap"`
}

type authorityWithdrawalMapResponseWire struct {
	Node         *tailcfg.Node        `json:"Node"`
	Peers        []*tailcfg.Node      `json:"Peers"`
	PacketFilter []tailcfg.FilterRule `json:"PacketFilter"`
}

// EncodeFullMapResponse encodes one zstd-compressed length-delimited full map.
// Empty peers and packet filter remain explicit to clear any prior client state.
func EncodeFullMapResponse(
	snapshot mapsession.Snapshot,
	capabilityVersion int,
) ([]byte, error) {
	return encodeFullMapResponse(
		snapshot,
		capabilityVersion,
		mapResponseCompressionZstd,
	)
}

func encodeFullMapResponse(
	snapshot mapsession.Snapshot,
	capabilityVersion int,
	compression mapResponseCompression,
) ([]byte, error) {
	if !snapshot.IsValid() || capabilityVersion != supportedCapabilityVersion {
		return nil, ErrMapResponse
	}
	self, err := fullMapNode(snapshot, capabilityVersion)
	if err != nil {
		return nil, err
	}
	peers, candidates, err := fullMapPeers(snapshot, capabilityVersion)
	if err != nil {
		return nil, err
	}
	packetFilter, err := fullMapPacketFilter(snapshot, candidates)
	if err != nil {
		return nil, err
	}
	relayDirectory, err := mapRelayDirectory(snapshot.RelayDirectory())
	if err != nil {
		return nil, err
	}
	document, err := json.Marshal(fullMapResponseWire{
		Domain:       snapshot.NetworkName().String(),
		Node:         self,
		Peers:        peers,
		PacketFilter: packetFilter,
		DERPMap:      relayDirectory,
	})
	if err != nil {
		clear(document)
		return nil, ErrMapResponse
	}
	return encodeMapDocument(document, compression)
}

func encodeAuthorityWithdrawalMapResponse(
	snapshot mapsession.Snapshot,
	capabilityVersion int,
	compression mapResponseCompression,
) ([]byte, error) {
	if !snapshot.IsValid() || capabilityVersion != supportedCapabilityVersion {
		return nil, ErrMapResponse
	}
	self, err := fullMapNode(snapshot, capabilityVersion)
	if err != nil {
		return nil, err
	}
	self.Expired = true
	self.MachineAuthorized = false
	self.DiscoKey = key.DiscoPublic{}
	self.Endpoints = nil
	self.Online = nil
	document, err := json.Marshal(authorityWithdrawalMapResponseWire{
		Node:         self,
		Peers:        []*tailcfg.Node{},
		PacketFilter: []tailcfg.FilterRule{},
	})
	if err != nil {
		clear(document)
		return nil, ErrMapResponse
	}
	return encodeMapDocument(document, compression)
}

func fullMapPeers(
	snapshot mapsession.Snapshot,
	capabilityVersion int,
) ([]*tailcfg.Node, map[node.ID]mapsession.PeerCandidate, error) {
	authorized := snapshot.AuthorizedPeers()
	peers := make([]*tailcfg.Node, 0, len(authorized))
	candidates := make(map[node.ID]mapsession.PeerCandidate, len(authorized))
	for _, candidate := range authorized {
		connectivity, found := snapshot.ConnectivityFor(candidate.NodeID())
		peer, err := fullMapPeer(candidate, connectivity, found, capabilityVersion)
		if err != nil {
			return nil, nil, err
		}
		peers = append(peers, peer)
		candidates[candidate.NodeID()] = candidate
	}
	slices.SortFunc(peers, func(first, second *tailcfg.Node) int {
		switch {
		case first.ID < second.ID:
			return -1
		case first.ID > second.ID:
			return 1
		default:
			return 0
		}
	})
	return peers, candidates, nil
}

func fullMapPeer(
	candidate mapsession.PeerCandidate,
	connectivity mapsession.Connectivity,
	hasConnectivity bool,
	capabilityVersion int,
) (*tailcfg.Node, error) {
	machineKey, err := machinePublicKey(candidate.MachineKey())
	if err != nil {
		return nil, err
	}
	nodeKey, err := nodePublicKey(candidate.NodeKey())
	if err != nil {
		return nil, err
	}
	addresses := candidate.Addresses()
	result := &tailcfg.Node{
		ID:                tailcfg.NodeID(candidate.NumericNodeID()),
		StableID:          tailcfg.StableNodeID(candidate.NodeID().String()),
		Name:              candidate.Hostname().String() + ".",
		User:              tailcfg.UserID(candidate.NumericOwnerID()),
		Key:               nodeKey,
		KeyExpiry:         candidate.KeyExpiry(),
		Machine:           machineKey,
		Addresses:         addresses,
		AllowedIPs:        append(addresses[:0:0], addresses...),
		Created:           candidate.CreatedAt(),
		Cap:               tailcfg.CapabilityVersion(capabilityVersion),
		MachineAuthorized: true,
		ComputedName:      candidate.Hostname().String(),
	}
	if hasConnectivity {
		if err := applyConnectivity(result, connectivity, false); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func fullMapPacketFilter(
	snapshot mapsession.Snapshot,
	candidates map[node.ID]mapsession.PeerCandidate,
) ([]tailcfg.FilterRule, error) {
	rules := make([]tailcfg.FilterRule, 0)
	for _, rule := range snapshot.PacketPolicy().Rules() {
		if rule.DestinationNodeID() != snapshot.NodeID() {
			continue
		}
		candidate, ok := candidates[rule.SourceNodeID()]
		if !ok {
			return nil, ErrMapResponse
		}
		sources := candidate.Addresses()
		sourceIPs := make([]string, 0, len(sources))
		for _, source := range sources {
			sourceIPs = append(sourceIPs, source.Addr().String())
		}
		destinations, protocols, err := fullMapDestinations(
			snapshot.Addresses(),
			rule,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, tailcfg.FilterRule{
			SrcIPs:   sourceIPs,
			DstPorts: destinations,
			IPProto:  protocols,
		})
	}
	return rules, nil
}

func fullMapDestinations(
	addresses []netip.Prefix,
	rule policy.Rule,
) ([]tailcfg.NetPortRange, []int, error) {
	portRanges := rule.DestinationPortRanges()
	protocols := make([]int, 0, 2)
	switch rule.Protocol() {
	case policy.ProtocolTCP:
		protocols = append(protocols, 6)
	case policy.ProtocolUDP:
		protocols = append(protocols, 17)
	case policy.ProtocolICMP:
		portRanges = nil
		for _, address := range addresses {
			if address.Addr().Is4() && !slices.Contains(protocols, 1) {
				protocols = append(protocols, 1)
			}
			if address.Addr().Is6() && !slices.Contains(protocols, 58) {
				protocols = append(protocols, 58)
			}
		}
	default:
		return nil, nil, ErrMapResponse
	}
	destinations := make([]tailcfg.NetPortRange, 0, len(addresses)*max(1, len(portRanges)))
	for _, address := range addresses {
		if rule.Protocol() == policy.ProtocolICMP {
			destinations = append(destinations, tailcfg.NetPortRange{
				IP:    address.Addr().String(),
				Ports: tailcfg.PortRangeAny,
			})
			continue
		}
		for _, portRange := range portRanges {
			destinations = append(destinations, tailcfg.NetPortRange{
				IP: address.Addr().String(),
				Ports: tailcfg.PortRange{
					First: portRange.First(),
					Last:  portRange.Last(),
				},
			})
		}
	}
	if len(destinations) == 0 || len(protocols) == 0 {
		return nil, nil, ErrMapResponse
	}
	return destinations, protocols, nil
}

// EncodeKeepAliveMapResponse encodes one non-empty transport keepalive frame.
func EncodeKeepAliveMapResponse() ([]byte, error) {
	return encodeKeepAliveMapResponse(mapResponseCompressionZstd)
}

func encodeKeepAliveMapResponse(compression mapResponseCompression) ([]byte, error) {
	document, err := json.Marshal(struct {
		KeepAlive bool `json:"KeepAlive"`
	}{KeepAlive: true})
	if err != nil {
		return nil, ErrMapResponse
	}
	return encodeMapDocument(document, compression)
}

func encodeMapDocument(
	document []byte,
	compression mapResponseCompression,
) ([]byte, error) {
	defer clear(document)
	if len(document) == 0 || len(document) > maxMapResponseBytes {
		return nil, ErrMapResponse
	}
	payload := document
	switch compression {
	case mapResponseCompressionNone:
	case mapResponseCompressionZstd:
		payload = zstdframe.AppendEncode(nil, document, zstdframe.FastestCompression)
	default:
		return nil, ErrMapResponse
	}
	if len(payload) == 0 || len(payload) > maxMapResponseBytes {
		if compression == mapResponseCompressionZstd {
			clear(payload)
		}
		return nil, ErrMapResponse
	}
	// The response bound is smaller than uint32. Encode through the wider form
	// and retain its low four little-endian bytes without a narrowing cast.
	var encodedLength [8]byte
	binary.LittleEndian.PutUint64(encodedLength[:], uint64(len(payload)))
	framed := make([]byte, 4, len(payload)+4)
	copy(framed, encodedLength[:4])
	framed = append(framed, payload...)
	if compression == mapResponseCompressionZstd {
		clear(payload)
	}
	return framed, nil
}

func fullMapNode(snapshot mapsession.Snapshot, capabilityVersion int) (*tailcfg.Node, error) {
	machineKey, err := machinePublicKey(snapshot.MachineKey())
	if err != nil {
		return nil, err
	}
	nodeKey, err := nodePublicKey(snapshot.NodeKey())
	if err != nil {
		return nil, err
	}
	addresses := snapshot.Addresses()
	result := &tailcfg.Node{
		ID:                tailcfg.NodeID(snapshot.NumericNodeID()),
		StableID:          tailcfg.StableNodeID(snapshot.NodeID().String()),
		Name:              snapshot.Hostname().String() + ".",
		User:              tailcfg.UserID(snapshot.NumericOwnerID()),
		Key:               nodeKey,
		KeyExpiry:         snapshot.KeyExpiry(),
		Machine:           machineKey,
		Addresses:         addresses,
		AllowedIPs:        append(addresses[:0:0], addresses...),
		Created:           snapshot.CreatedAt(),
		Cap:               tailcfg.CapabilityVersion(capabilityVersion),
		MachineAuthorized: true,
		ComputedName:      snapshot.Hostname().String(),
	}
	if connectivity, found := snapshot.ConnectivityFor(snapshot.NodeID()); found {
		if err := applyConnectivity(result, connectivity, true); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func applyConnectivity(
	result *tailcfg.Node,
	connectivity mapsession.Connectivity,
	self bool,
) error {
	if result == nil || !connectivity.IsValid() {
		return ErrMapResponse
	}
	if set, present := connectivity.EndpointSet(); present {
		discoveryKey, err := discoveryPublicKey(set.DiscoveryKey())
		if err != nil {
			return err
		}
		endpoints := set.Endpoints()
		result.DiscoKey = discoveryKey
		result.Endpoints = make([]netip.AddrPort, len(endpoints))
		for index, endpoint := range endpoints {
			result.Endpoints[index] = endpoint.Address()
		}
	}
	if preferredRelay, present := connectivity.PreferredRelay(); present {
		result.HomeDERP = preferredRelay
	}
	if !self {
		online := connectivity.Online()
		result.Online = &online
	}
	return nil
}

func machinePublicKey(value node.MachineKey) (key.MachinePublic, error) {
	var result key.MachinePublic
	if err := unmarshalTypedPublicKey(&result, "mkey:", value.Bytes()); err != nil {
		return key.MachinePublic{}, err
	}
	return result, nil
}

func nodePublicKey(value node.Key) (key.NodePublic, error) {
	var result key.NodePublic
	if err := unmarshalTypedPublicKey(&result, nodeKeyPrefix, value.Bytes()); err != nil {
		return key.NodePublic{}, err
	}
	return result, nil
}

func discoveryPublicKey(value node.DiscoveryKey) (key.DiscoPublic, error) {
	var result key.DiscoPublic
	if err := unmarshalTypedPublicKey(&result, discoveryKeyPrefix, value.Bytes()); err != nil {
		return key.DiscoPublic{}, err
	}
	return result, nil
}

type textPublicKey interface {
	UnmarshalText([]byte) error
}

func unmarshalTypedPublicKey(target textPublicKey, prefix string, raw [32]byte) error {
	if target == nil || raw == [32]byte{} {
		return ErrMapResponse
	}
	encoded := make([]byte, len(prefix)+hex.EncodedLen(len(raw)))
	copy(encoded, prefix)
	hex.Encode(encoded[len(prefix):], raw[:])
	defer clear(encoded)
	if err := target.UnmarshalText(encoded); err != nil {
		return fmt.Errorf("%w: encode public identity", ErrMapResponse)
	}
	return nil
}
