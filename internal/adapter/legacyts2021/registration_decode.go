package legacyts2021

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/node"
)

const (
	maxRegistrationRequestBytes = 64 << 10
	maxRegistrationJSONDepth    = 8
	supportedCapabilityVersion  = 142
	nodeKeyPrefix               = "nodekey:"
	networkLockKeyPrefix        = "nlpub:"
	publicKeyHexLength          = 64
)

// ErrInvalidRegistrationRequest reports malformed or unsupported wire input
// without disclosing credential material or field-level authentication detail.
var ErrInvalidRegistrationRequest = errors.New("legacyts2021: invalid registration request")

// DecodeCredentialRegistration decodes the bounded credential-enrollment or
// machine-authenticated Node-key rotation subset of the pinned registration
// profile. The server, not the client, supplies registrationID.
func DecodeCredentialRegistration(
	body io.Reader,
	registrationID enrollment.RegistrationID,
) (control.RegistrationRequest, error) {
	if body == nil || !registrationID.IsValid() {
		return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	encoded, err := io.ReadAll(io.LimitReader(body, maxRegistrationRequestBytes+1))
	defer clear(encoded)
	if err != nil {
		return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	if len(encoded) == 0 || len(encoded) > maxRegistrationRequestBytes {
		return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	if err := validateUniqueJSONNames(encoded); err != nil {
		return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
	}

	var wire registrationRequestWire
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	return wire.toControl(registrationID)
}

func validateUniqueJSONNames(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	return scanJSONValue(decoder, 0)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxRegistrationJSONDepth {
		return ErrInvalidRegistrationRequest
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		names := map[string]struct{}{}
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, isName := nameToken.(string)
			if !isName {
				return ErrInvalidRegistrationRequest
			}
			canonicalName := strings.ToLower(name)
			if _, exists := names[canonicalName]; exists {
				return ErrInvalidRegistrationRequest
			}
			names[canonicalName] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidRegistrationRequest
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return nil
}

type registrationRequestWire struct {
	Version          int                   `json:"Version"`
	NodeKey          string                `json:"NodeKey"`
	OldNodeKey       string                `json:"OldNodeKey"`
	NetworkLockKey   string                `json:"NLKey"`
	Auth             *registrationAuthWire `json:"Auth"`
	Expiry           time.Time             `json:"Expiry"`
	Followup         string                `json:"Followup"`
	HostInfo         *registrationHostWire `json:"Hostinfo"`
	Ephemeral        bool                  `json:"Ephemeral"`
	NodeKeySignature []byte                `json:"NodeKeySignature"`
	SignatureType    int                   `json:"SignatureType"`
	Timestamp        *time.Time            `json:"Timestamp"`
	DeviceCert       []byte                `json:"DeviceCert"`
	Signature        []byte                `json:"Signature"`
	NetworkSelector  string                `json:"Tailnet"`
}

type registrationAuthWire struct {
	OAuth2Token json.RawMessage `json:"Oauth2Token"`
	AuthKey     string          `json:"AuthKey"`
}

type registrationHostWire struct {
	IPNVersion      string `json:"IPNVersion"`
	OS              string `json:"OS"`
	Hostname        string `json:"Hostname"`
	GoArch          string `json:"GoArch"`
	GoVersion       string `json:"GoVersion"`
	NoLogsNoSupport bool   `json:"NoLogsNoSupport"`
}

func (wire registrationRequestWire) toControl(
	registrationID enrollment.RegistrationID,
) (control.RegistrationRequest, error) {
	if wire.Version != supportedCapabilityVersion || wire.HostInfo == nil ||
		wire.hasUnsupportedSemantics() {
		return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	nodeKey, err := parseNodeKey(wire.NodeKey)
	if err != nil {
		return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	credential := enrollment.CredentialPresentation{}
	oldNodeKey := node.Key{}
	switch {
	case wire.Auth != nil && isZeroTypedPublicKey(wire.OldNodeKey, nodeKeyPrefix):
		if wire.Auth.OAuth2Token != nil {
			return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
		}
		credential, err = enrollment.ParseCredentialPresentation(wire.Auth.AuthKey)
		wire.Auth.AuthKey = ""
		if err != nil {
			return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
		}
	case wire.Auth == nil:
		oldNodeKey, err = parseNodeKey(wire.OldNodeKey)
		if err != nil || oldNodeKey == nodeKey {
			return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
		}
	default:
		return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	hostname, err := node.ParseHostname(wire.HostInfo.Hostname)
	if err != nil {
		return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	request, err := control.NewRegistrationRequest(control.RegistrationRequestParams{
		RegistrationID: registrationID,
		Credential:     credential,
		NodeKey:        nodeKey,
		OldNodeKey:     oldNodeKey,
		Hostname:       hostname,
	})
	if err != nil {
		return control.RegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	return request, nil
}

func (wire registrationRequestWire) hasUnsupportedSemantics() bool {
	return !isZeroTypedPublicKey(wire.NetworkLockKey, networkLockKeyPrefix) ||
		!wire.Expiry.IsZero() || wire.Followup != "" || wire.Ephemeral ||
		len(wire.NodeKeySignature) != 0 || wire.SignatureType != 0 || wire.Timestamp != nil ||
		len(wire.DeviceCert) != 0 || len(wire.Signature) != 0 || wire.NetworkSelector != ""
}

func parseNodeKey(encoded string) (node.Key, error) {
	if len(encoded) != len(nodeKeyPrefix)+publicKeyHexLength ||
		!strings.HasPrefix(encoded, nodeKeyPrefix) {
		return node.Key{}, ErrInvalidRegistrationRequest
	}
	hexValue := encoded[len(nodeKeyPrefix):]
	for index := range len(hexValue) {
		character := hexValue[index]
		isDigit := character >= '0' && character <= '9'
		isLowerHex := character >= 'a' && character <= 'f'
		if !isDigit && !isLowerHex {
			return node.Key{}, ErrInvalidRegistrationRequest
		}
	}
	var raw [32]byte
	if _, err := hex.Decode(raw[:], []byte(hexValue)); err != nil {
		return node.Key{}, ErrInvalidRegistrationRequest
	}
	key, err := node.NewKey(raw)
	if err != nil {
		return node.Key{}, ErrInvalidRegistrationRequest
	}
	return key, nil
}

func isZeroTypedPublicKey(encoded, prefix string) bool {
	if len(encoded) != len(prefix)+publicKeyHexLength || !strings.HasPrefix(encoded, prefix) {
		return false
	}
	for index := len(prefix); index < len(encoded); index++ {
		if encoded[index] != '0' {
			return false
		}
	}
	return true
}
