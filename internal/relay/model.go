// Package relay owns the protocol-independent encrypted-packet relay model.
package relay

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strconv"
)

const (
	maxRegions        = 256
	maxNodesPerRegion = 32
	maxPeers          = 256
)

// Key is one WireGuard-compatible node identity used only as a relay address.
type Key [32]byte

// Node is one TLS relay endpoint authorized by the control plane.
type Node struct {
	Name     string
	HostName string
	CertName string
	IPv4     string
	IPv6     string
	Port     uint16
}

// Region is an ordered failover group of relay nodes.
type Region struct {
	ID    int
	Nodes []Node
}

// Peer binds a relay destination to a signed peer identity and rate-limit key.
type Peer struct {
	Key        Key
	HomeRegion int
	Address    netip.Addr
}

// Config is an immutable-by-convention relay authority for one map revision.
type Config struct {
	PrivateKey Key
	PublicKey  Key
	HomeRegion int
	Regions    map[int]Region
	Peers      []Peer
}

// ReceivedPacket is one encrypted packet delivered by a wire adapter.
type ReceivedPacket struct {
	Source Key
	Data   []byte
}

// Packet is one encrypted packet plus the relay region where it arrived.
type Packet struct {
	RegionID int
	Source   Key
	Data     []byte
}

// Client is the small wire-protocol contract consumed by the relay pool.
// Close must interrupt a concurrent Receive call.
type Client interface {
	Send(Key, []byte) error
	Receive() (ReceivedPacket, error)
	Close() error
}

// Dialer establishes one authenticated client connection to an ordered region.
type Dialer interface {
	Dial(context.Context, Key, Region) (Client, error)
}

var errInvalidConfig = errors.New("relay: invalid configuration")

// Validate returns a defensive, canonical copy of one relay configuration.
func Validate(config Config) (Config, error) {
	if config.PrivateKey == (Key{}) || config.PublicKey == (Key{}) || config.HomeRegion <= 0 ||
		len(config.Regions) == 0 || len(config.Regions) > maxRegions ||
		len(config.Peers) == 0 || len(config.Peers) > maxPeers {
		return Config{}, errInvalidConfig
	}
	home, exists := config.Regions[config.HomeRegion]
	if !exists || home.ID != config.HomeRegion {
		return Config{}, errInvalidConfig
	}

	validated := Config{
		PrivateKey: config.PrivateKey,
		PublicKey:  config.PublicKey,
		HomeRegion: config.HomeRegion,
		Regions:    make(map[int]Region, len(config.Regions)),
		Peers:      append([]Peer{}, config.Peers...),
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(config.PrivateKey[:])
	if err != nil || subtle.ConstantTimeCompare(
		privateKey.PublicKey().Bytes(),
		config.PublicKey[:],
	) != 1 {
		return Config{}, errInvalidConfig
	}
	for id, region := range config.Regions {
		if id <= 0 || region.ID != id || len(region.Nodes) == 0 ||
			len(region.Nodes) > maxNodesPerRegion {
			return Config{}, errInvalidConfig
		}
		region.Nodes = append([]Node{}, region.Nodes...)
		for _, node := range region.Nodes {
			if node.Name == "" || node.HostName == "" || node.Port == 0 {
				return Config{}, errInvalidConfig
			}
		}
		validated.Regions[id] = region
	}

	slices.SortFunc(validated.Peers, func(left, right Peer) int {
		return bytes.Compare(left.Key[:], right.Key[:])
	})
	for index, peer := range validated.Peers {
		region, regionExists := validated.Regions[peer.HomeRegion]
		isValidAddress := peer.Address.IsValid() && peer.Address.IsGlobalUnicast() &&
			!peer.Address.Is4In6() && peer.Address.Zone() == "" &&
			peer.Address == peer.Address.Unmap() && !peer.Address.IsLinkLocalUnicast()
		if peer.Key == (Key{}) || peer.HomeRegion <= 0 || !regionExists ||
			region.ID != peer.HomeRegion || !isValidAddress {
			return Config{}, errInvalidConfig
		}
		if index > 0 && peer.Key == validated.Peers[index-1].Key {
			return Config{}, errInvalidConfig
		}
	}

	return validated, nil
}

// Fingerprint returns a deterministic public-authority fingerprint. The node
// private key is deliberately excluded.
func Fingerprint(config Config) [32]byte {
	var encoded bytes.Buffer
	encoded.Write(config.PublicKey[:])
	writeString(&encoded, strconv.Itoa(config.HomeRegion))
	regionIDs := make([]int, 0, len(config.Regions))
	for id := range config.Regions {
		regionIDs = append(regionIDs, id)
	}
	slices.Sort(regionIDs)
	for _, id := range regionIDs {
		region := config.Regions[id]
		writeString(&encoded, strconv.Itoa(region.ID))
		for _, node := range region.Nodes {
			writeString(&encoded, node.Name)
			writeString(&encoded, node.HostName)
			writeString(&encoded, node.CertName)
			writeString(&encoded, node.IPv4)
			writeString(&encoded, node.IPv6)
			writeUint64(&encoded, uint64(node.Port))
		}
	}
	for _, peer := range config.Peers {
		encoded.Write(peer.Key[:])
		writeString(&encoded, strconv.Itoa(peer.HomeRegion))
		writeString(&encoded, peer.Address.String())
	}

	return sha256.Sum256(encoded.Bytes())
}

func writeString(buffer *bytes.Buffer, value string) {
	writeUint64(buffer, uint64(len(value)))
	buffer.WriteString(value)
}

func writeUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	buffer.Write(encoded[:])
}
