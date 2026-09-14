package legacyts2021

import (
	"encoding/hex"
	"strings"

	"tailscale.com/tailcfg"

	"github.com/meshtransit/meshtransit/internal/node"
)

const discoveryKeyPrefix = "discokey:"

func decodeEndpointSet(request tailcfg.MapRequest) (node.EndpointSet, bool, error) {
	hasEndpointSet := !request.DiscoKey.IsZero() || len(request.Endpoints) != 0 ||
		len(request.EndpointTypes) != 0
	if !hasEndpointSet {
		return node.EndpointSet{}, false, nil
	}
	if request.DiscoKey.IsZero() || len(request.EndpointTypes) != len(request.Endpoints) {
		return node.EndpointSet{}, false, ErrInvalidMapRequest
	}
	discoveryKey, err := decodeDiscoveryKey(request)
	if err != nil {
		return node.EndpointSet{}, false, ErrInvalidMapRequest
	}
	endpoints := make([]node.Endpoint, len(request.Endpoints))
	for index := range request.Endpoints {
		source, ok := endpointSource(request.EndpointTypes[index])
		if !ok {
			return node.EndpointSet{}, false, ErrInvalidMapRequest
		}
		endpoints[index], err = node.NewEndpoint(request.Endpoints[index], source)
		if err != nil {
			return node.EndpointSet{}, false, ErrInvalidMapRequest
		}
	}
	set, err := node.NewEndpointSet(discoveryKey, endpoints)
	if err != nil {
		return node.EndpointSet{}, false, ErrInvalidMapRequest
	}
	return set, true, nil
}

func decodeDiscoveryKey(request tailcfg.MapRequest) (node.DiscoveryKey, error) {
	encoded, err := request.DiscoKey.MarshalText()
	defer clear(encoded)
	if err != nil || len(encoded) != len(discoveryKeyPrefix)+publicKeyHexLength ||
		!strings.HasPrefix(string(encoded), discoveryKeyPrefix) {
		return node.DiscoveryKey{}, ErrInvalidMapRequest
	}
	hexValue := encoded[len(discoveryKeyPrefix):]
	for _, character := range hexValue {
		if !lowerHexCharacter(character) {
			return node.DiscoveryKey{}, ErrInvalidMapRequest
		}
	}
	var raw [32]byte
	if _, err := hex.Decode(raw[:], hexValue); err != nil {
		return node.DiscoveryKey{}, ErrInvalidMapRequest
	}
	key, err := node.NewDiscoveryKey(raw)
	if err != nil {
		return node.DiscoveryKey{}, ErrInvalidMapRequest
	}
	return key, nil
}

func lowerHexCharacter(character byte) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
}

func endpointSource(value tailcfg.EndpointType) (node.EndpointSource, bool) {
	switch value {
	case tailcfg.EndpointLocal:
		return node.EndpointSourceLocal, true
	case tailcfg.EndpointSTUN:
		return node.EndpointSourceSTUN, true
	case tailcfg.EndpointPortmapped:
		return node.EndpointSourcePortMapped, true
	case tailcfg.EndpointSTUN4LocalPort:
		return node.EndpointSourceSTUNLocalPort, true
	case tailcfg.EndpointExplicitConf:
		return node.EndpointSourceConfigured, true
	default:
		return node.EndpointSourceUnknown, false
	}
}
