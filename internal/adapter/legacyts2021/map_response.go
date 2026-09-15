package legacyts2021

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/node"
)

const (
	maxMapResponseBytes    = 64 << 10
	mapResponseContentType = "application/octet-stream"
)

// ErrMapResponse reports invalid authority evidence or a failed bounded encoding.
var ErrMapResponse = errors.New("legacyts2021: map response failed")

type fullMapResponseWire struct {
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
	if !snapshot.IsValid() || capabilityVersion != supportedCapabilityVersion {
		return nil, ErrMapResponse
	}
	// Until the legacy adapter can encode both an authorized peer and its exact
	// packet filter atomically, fail closed instead of emitting peer identity
	// with an empty or incomplete policy.
	if len(snapshot.AuthorizedPeers()) != 0 {
		return nil, ErrMapResponse
	}
	self, err := fullMapNode(snapshot, capabilityVersion)
	if err != nil {
		return nil, err
	}
	document, err := json.Marshal(fullMapResponseWire{
		Node:         self,
		Peers:        make([]*tailcfg.Node, 0),
		PacketFilter: make([]tailcfg.FilterRule, 0),
	})
	if err != nil {
		clear(document)
		return nil, ErrMapResponse
	}
	return encodeMapDocument(document)
}

// EncodeKeepAliveMapResponse encodes one non-empty transport keepalive frame.
func EncodeKeepAliveMapResponse() ([]byte, error) {
	document, err := json.Marshal(struct {
		KeepAlive bool `json:"KeepAlive"`
	}{KeepAlive: true})
	if err != nil {
		return nil, ErrMapResponse
	}
	return encodeMapDocument(document)
}

func encodeMapDocument(document []byte) ([]byte, error) {
	defer clear(document)
	if len(document) == 0 || len(document) > maxMapResponseBytes {
		return nil, ErrMapResponse
	}
	compressed := zstdframe.AppendEncode(nil, document, zstdframe.FastestCompression)
	if len(compressed) == 0 || len(compressed) > maxMapResponseBytes {
		clear(compressed)
		return nil, ErrMapResponse
	}
	// The response bound is smaller than uint32. Encode through the wider form
	// and retain its low four little-endian bytes without a narrowing cast.
	var encodedLength [8]byte
	binary.LittleEndian.PutUint64(encodedLength[:], uint64(len(compressed)))
	framed := make([]byte, 4, len(compressed)+4)
	copy(framed, encodedLength[:4])
	framed = append(framed, compressed...)
	clear(compressed)
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
	return &tailcfg.Node{
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
	}, nil
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
