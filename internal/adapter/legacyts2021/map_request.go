package legacyts2021

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"tailscale.com/tailcfg"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
)

const maxMapRequestBytes = 128 << 10

// ErrInvalidMapRequest reports malformed or unsupported map input without
// disclosing request content.
var ErrInvalidMapRequest = errors.New("legacyts2021: invalid map request")

// DecodeFullMapRequest decodes the bounded one-shot full-map subset of the
// pinned client profile and translates it to a product-owned request.
func DecodeFullMapRequest(body io.Reader) (mapsession.Request, error) {
	request, streaming, err := decodeMapRequest(body)
	if err != nil || streaming {
		return mapsession.Request{}, ErrInvalidMapRequest
	}
	return request, nil
}

// DecodeMapRequest decodes the bounded one-shot or streaming map subset and
// returns product-owned authority input plus the requested transport mode.
func DecodeMapRequest(body io.Reader) (mapsession.Request, bool, error) {
	return decodeMapRequest(body)
}

func decodeMapRequest(body io.Reader) (mapsession.Request, bool, error) {
	if body == nil {
		return mapsession.Request{}, false, ErrInvalidMapRequest
	}
	encoded, err := io.ReadAll(io.LimitReader(body, maxMapRequestBytes+1))
	defer clear(encoded)
	if err != nil || len(encoded) == 0 || len(encoded) > maxMapRequestBytes {
		return mapsession.Request{}, false, ErrInvalidMapRequest
	}
	if err := validateUniqueJSONNames(encoded); err != nil {
		return mapsession.Request{}, false, ErrInvalidMapRequest
	}

	var wire tailcfg.MapRequest
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return mapsession.Request{}, false, ErrInvalidMapRequest
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || !validMapRequest(wire) {
		return mapsession.Request{}, false, ErrInvalidMapRequest
	}
	// Read the legacy compatibility bit separately so validation remains strict
	// without binding new code to the dependency's deprecated field API.
	var compatibility struct {
		ReadOnly bool `json:"ReadOnly"`
	}
	if err := json.Unmarshal(encoded, &compatibility); err != nil || compatibility.ReadOnly {
		return mapsession.Request{}, false, ErrInvalidMapRequest
	}
	nodeKeyText, err := wire.NodeKey.MarshalText()
	defer clear(nodeKeyText)
	if err != nil {
		return mapsession.Request{}, false, ErrInvalidMapRequest
	}
	nodeKey, err := parseNodeKey(string(nodeKeyText))
	if err != nil {
		return mapsession.Request{}, false, ErrInvalidMapRequest
	}
	request, err := mapsession.NewRequest(nodeKey, int(wire.Version))
	if err != nil {
		return mapsession.Request{}, false, ErrInvalidMapRequest
	}
	return request, wire.Stream, nil
}

func validMapRequest(request tailcfg.MapRequest) bool {
	if request.Version != supportedCapabilityVersion || request.Compress != "zstd" ||
		request.NodeKey.IsZero() || request.OmitPeers ||
		request.MapSessionHandle != "" || request.MapSessionSeq != 0 || request.TKAHead != "" ||
		!request.HardwareAttestationKey.IsZero() ||
		len(request.HardwareAttestationKeySignature) != 0 ||
		!request.HardwareAttestationKeySignatureTimestamp.IsZero() {
		return false
	}
	if len(request.EndpointTypes) != 0 && len(request.EndpointTypes) != len(request.Endpoints) {
		return false
	}
	if request.Hostinfo != nil && (len(request.Hostinfo.RoutableIPs) != 0 ||
		len(request.Hostinfo.RequestTags) != 0 || !request.Hostinfo.ExitNodeID.IsZero()) {
		return false
	}
	return true
}
