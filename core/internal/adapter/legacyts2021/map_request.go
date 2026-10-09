package legacyts2021

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"tailscale.com/tailcfg"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
)

const maxMapRequestBytes = 128 << 10

type mapResponseCompression uint8

const (
	mapResponseCompressionInvalid mapResponseCompression = iota
	mapResponseCompressionNone
	mapResponseCompressionZstd
)

// ErrInvalidMapRequest reports malformed or unsupported map input without
// disclosing request content.
var ErrInvalidMapRequest = errors.New("legacyts2021: invalid map request")

// DecodeFullMapRequest decodes the bounded one-shot full-map subset of the
// pinned client profile and translates it to a product-owned request.
func DecodeFullMapRequest(body io.Reader) (mapsession.Request, error) {
	request, streaming, _, err := decodeMapRequest(body)
	if err != nil || streaming {
		return mapsession.Request{}, ErrInvalidMapRequest
	}
	return request, nil
}

// DecodeMapRequest decodes the bounded one-shot or streaming map subset and
// returns product-owned authority input plus the requested transport mode.
func DecodeMapRequest(body io.Reader) (mapsession.Request, bool, error) {
	request, streaming, _, err := decodeMapRequest(body)
	return request, streaming, err
}

func decodeMapRequest(
	body io.Reader,
) (mapsession.Request, bool, mapResponseCompression, error) {
	if body == nil {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}
	encoded, err := io.ReadAll(io.LimitReader(body, maxMapRequestBytes+1))
	defer clear(encoded)
	if err != nil || len(encoded) == 0 || len(encoded) > maxMapRequestBytes {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}
	if err := validateUniqueJSONNames(encoded); err != nil {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}

	var wire struct {
		tailcfg.MapRequest
		DeviceAliasVersion json.RawMessage `json:"DeviceAliasVersion"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || !validMapRequest(wire.MapRequest) {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}
	// Read the legacy compatibility bit separately so validation remains strict
	// without binding new code to the dependency's deprecated field API.
	var compatibility struct {
		ReadOnly bool `json:"ReadOnly"`
	}
	if err := json.Unmarshal(encoded, &compatibility); err != nil || compatibility.ReadOnly {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}
	nodeKeyText, err := wire.NodeKey.MarshalText()
	defer clear(nodeKeyText)
	if err != nil {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}
	nodeKey, err := parseNodeKey(string(nodeKeyText))
	if err != nil {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}
	request, err := mapsession.NewRequest(nodeKey, int(wire.Version))
	if err != nil {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}
	aliasVersion, err := decodeDeviceAliasVersion(encoded, wire.DeviceAliasVersion)
	if err != nil {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}
	request, err = request.WithDeviceAliasVersion(aliasVersion)
	if err != nil {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}
	endpointSet, hasEndpointSet, err := decodeEndpointSet(wire.MapRequest)
	preferredRelay, hasPreferredRelay, preferredRelayErr := decodePreferredRelay(wire.MapRequest)
	if err != nil || preferredRelayErr != nil ||
		wire.OmitPeers && (wire.Stream || !hasEndpointSet) ||
		!wire.Stream && hasPreferredRelay && !hasEndpointSet {
		return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
	}
	if hasEndpointSet && !wire.Stream {
		request, err = request.WithEndpointSet(endpointSet)
		if err != nil {
			return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
		}
		if hasPreferredRelay {
			request, err = request.WithPreferredRelay(preferredRelay)
			if err != nil {
				return mapsession.Request{}, false, mapResponseCompressionInvalid, ErrInvalidMapRequest
			}
		}
	}
	return request, wire.Stream, responseCompression(wire.Compress), nil
}

func decodePreferredRelay(request tailcfg.MapRequest) (int, bool, error) {
	if request.Hostinfo == nil || request.Hostinfo.NetInfo == nil {
		return 0, false, nil
	}
	regionID := request.Hostinfo.NetInfo.PreferredDERP
	if regionID < 0 || regionID > node.MaximumRelayRegionID {
		return 0, false, ErrInvalidMapRequest
	}
	return regionID, true, nil
}

func validMapRequest(request tailcfg.MapRequest) bool {
	if request.Version != supportedCapabilityVersion ||
		responseCompression(request.Compress) == mapResponseCompressionInvalid ||
		request.NodeKey.IsZero() ||
		request.MapSessionHandle != "" || request.MapSessionSeq != 0 || request.TKAHead != "" ||
		!request.HardwareAttestationKey.IsZero() ||
		len(request.HardwareAttestationKeySignature) != 0 ||
		!request.HardwareAttestationKeySignatureTimestamp.IsZero() {
		return false
	}
	if request.Hostinfo != nil && (len(request.Hostinfo.RoutableIPs) != 0 ||
		len(request.Hostinfo.RequestTags) != 0 || !request.Hostinfo.ExitNodeID.IsZero()) {
		return false
	}
	return true
}

func responseCompression(value string) mapResponseCompression {
	switch value {
	case "":
		return mapResponseCompressionNone
	case "zstd":
		return mapResponseCompressionZstd
	default:
		return mapResponseCompressionInvalid
	}
}

func decodeDeviceAliasVersion(encoded []byte, value json.RawMessage) (uint8, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return 0, ErrInvalidMapRequest
	}
	for name := range fields {
		if strings.EqualFold(name, "DeviceAliasVersion") && name != "DeviceAliasVersion" {
			return 0, ErrInvalidMapRequest
		}
	}
	if len(value) == 0 {
		return 0, nil
	}
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return 0, ErrInvalidMapRequest
	}
	var version uint8
	if err := json.Unmarshal(value, &version); err != nil || version > 1 {
		return 0, ErrInvalidMapRequest
	}
	return version, nil
}
