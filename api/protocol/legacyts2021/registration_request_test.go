package legacyts2021

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/node"
)

const validRegistrationRequestJSON = `{
  "Version": 142,
  "NodeKey": "nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "OldNodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
  "NLKey": "nlpub:0000000000000000000000000000000000000000000000000000000000000000",
  "Auth": {
    "AuthKey": "mtc1.01890f90-0000-7000-8000-000000000001.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
  },
  "Expiry": "0001-01-01T00:00:00Z",
  "Followup": "",
  "Hostinfo": {
    "IPNVersion": "meshd/test",
    "OS": "linux",
    "Hostname": "Node-One.Example",
    "GoArch": "amd64",
    "GoVersion": "go1.26.8",
    "NoLogsNoSupport": true
  },
  "NodeKeySignature": null
}`

func TestDecodeCredentialRegistration(t *testing.T) {
	t.Parallel()

	registrationID := parseRegistrationID(t)
	request, err := DecodeCredentialRegistration(
		strings.NewReader(validRegistrationRequestJSON),
		registrationID,
	)
	if err != nil {
		t.Fatalf("DecodeCredentialRegistration() error = %v", err)
	}
	if !request.IsValid() {
		t.Fatal("DecodeCredentialRegistration() returned invalid product request")
	}
	machineKey, err := node.NewMachineKey([32]byte{0: 1})
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatalf("control.NewAuthenticatedMachine() error = %v", err)
	}
	bound, err := machine.BindRegistration(request)
	if err != nil {
		t.Fatalf("AuthenticatedMachine.BindRegistration() error = %v", err)
	}
	wantNodeKey := [32]byte{}
	for index := range wantNodeKey {
		wantNodeKey[index] = byte(index + 1)
	}
	if bound.RegistrationID != registrationID || bound.Identity.NodeKey().Bytes() != wantNodeKey ||
		bound.Hostname.String() != "node-one.example" ||
		bound.CredentialID.String() != "01890f90-0000-7000-8000-000000000001" {
		t.Fatal("DecodeCredentialRegistration() changed observed registration semantics")
	}
}

func TestDecodeCredentialRegistrationRejectsUnsupportedSemantics(t *testing.T) {
	t.Parallel()

	nonzeroTime := time.Unix(1, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*registrationRequestWire)
	}{
		{name: "wrong capability", mutate: func(wire *registrationRequestWire) { wire.Version-- }},
		{name: "invalid node key", mutate: func(wire *registrationRequestWire) { wire.NodeKey = "invalid" }},
		{name: "uppercase node key", mutate: func(wire *registrationRequestWire) {
			wire.NodeKey = strings.ToUpper(wire.NodeKey)
		}},
		{name: "zero node key", mutate: func(wire *registrationRequestWire) {
			wire.NodeKey = nodeKeyPrefix + strings.Repeat("0", publicKeyHexLength)
		}},
		{name: "old node key", mutate: func(wire *registrationRequestWire) {
			wire.OldNodeKey = nodeKeyPrefix + "1" + strings.Repeat("0", publicKeyHexLength-1)
		}},
		{name: "network lock key", mutate: func(wire *registrationRequestWire) {
			wire.NetworkLockKey = networkLockKeyPrefix + "1" + strings.Repeat("0", publicKeyHexLength-1)
		}},
		{name: "missing auth", mutate: func(wire *registrationRequestWire) { wire.Auth = nil }},
		{name: "oauth token", mutate: func(wire *registrationRequestWire) {
			wire.Auth.OAuth2Token = json.RawMessage(`{"AccessToken":"opaque"}`)
		}},
		{name: "invalid credential", mutate: func(wire *registrationRequestWire) {
			wire.Auth.AuthKey = "mtc2.invalid.invalid"
		}},
		{name: "requested expiry", mutate: func(wire *registrationRequestWire) { wire.Expiry = nonzeroTime }},
		{name: "browser followup", mutate: func(wire *registrationRequestWire) {
			wire.Followup = "https://control.example.com/register/opaque"
		}},
		{name: "missing host info", mutate: func(wire *registrationRequestWire) { wire.HostInfo = nil }},
		{name: "invalid hostname", mutate: func(wire *registrationRequestWire) {
			wire.HostInfo.Hostname = "node_one"
		}},
		{name: "ephemeral request", mutate: func(wire *registrationRequestWire) { wire.Ephemeral = true }},
		{name: "node key signature", mutate: func(wire *registrationRequestWire) {
			wire.NodeKeySignature = []byte{1}
		}},
		{name: "signature type", mutate: func(wire *registrationRequestWire) { wire.SignatureType = 1 }},
		{name: "signature timestamp", mutate: func(wire *registrationRequestWire) {
			wire.Timestamp = &nonzeroTime
		}},
		{name: "device certificate", mutate: func(wire *registrationRequestWire) {
			wire.DeviceCert = []byte{1}
		}},
		{name: "signature", mutate: func(wire *registrationRequestWire) { wire.Signature = []byte{1} }},
		{name: "network selector", mutate: func(wire *registrationRequestWire) {
			wire.NetworkSelector = "untrusted.example"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			wire := validRegistrationWire(t)
			test.mutate(&wire)
			encoded, err := json.Marshal(wire)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			_, err = DecodeCredentialRegistration(bytes.NewReader(encoded), parseRegistrationID(t))
			if !errors.Is(err, ErrInvalidRegistrationRequest) {
				t.Fatalf("DecodeCredentialRegistration() error = %v, want invalid request", err)
			}
		})
	}
}

func TestDecodeCredentialRegistrationRejectsMalformedWire(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body io.Reader
	}{
		{name: "nil body"},
		{name: "empty body", body: strings.NewReader("")},
		{name: "malformed json", body: strings.NewReader("{")},
		{name: "trailing json", body: strings.NewReader(validRegistrationRequestJSON + `{}`)},
		{name: "duplicate top-level field", body: strings.NewReader(strings.Replace(
			validRegistrationRequestJSON,
			`"Version": 142,`,
			`"Version": 142, "version": 142,`,
			1,
		))},
		{name: "duplicate nested field", body: strings.NewReader(strings.Replace(
			validRegistrationRequestJSON,
			`"AuthKey": "mtc1.`,
			`"AuthKey": "ignored", "authkey": "mtc1.`,
			1,
		))},
		{name: "unknown top-level field", body: strings.NewReader(`{"Unknown":true}`)},
		{name: "unknown host field", body: strings.NewReader(strings.Replace(
			validRegistrationRequestJSON,
			`"Hostname": "Node-One.Example",`,
			`"Hostname": "Node-One.Example", "RequestTags": ["privileged"],`,
			1,
		))},
		{name: "oversized body", body: strings.NewReader(strings.Repeat(" ", maxRegistrationRequestBytes+1))},
		{name: "read failure", body: registrationErrorReader{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := DecodeCredentialRegistration(test.body, parseRegistrationID(t))
			if !errors.Is(err, ErrInvalidRegistrationRequest) {
				t.Fatalf("DecodeCredentialRegistration() error = %v, want invalid request", err)
			}
		})
	}
	if _, err := DecodeCredentialRegistration(
		strings.NewReader(validRegistrationRequestJSON),
		enrollment.RegistrationID{},
	); !errors.Is(err, ErrInvalidRegistrationRequest) {
		t.Fatalf("DecodeCredentialRegistration(zero id) error = %v, want invalid request", err)
	}
}

func TestRegistrationWireErrorsAndResultsAreRedacted(t *testing.T) {
	t.Parallel()

	request, err := DecodeCredentialRegistration(
		strings.NewReader(validRegistrationRequestJSON),
		parseRegistrationID(t),
	)
	if err != nil {
		t.Fatalf("DecodeCredentialRegistration() error = %v", err)
	}
	if fmt.Sprint(request) != "[REDACTED]" || strings.Contains(fmt.Sprint(request), "mtc1.") {
		t.Fatal("decoded product request formatting disclosed bearer material")
	}
	rejected := strings.Replace(validRegistrationRequestJSON, "mtc1.", "rejected-bearer.", 1)
	_, err = DecodeCredentialRegistration(strings.NewReader(rejected), parseRegistrationID(t))
	if !errors.Is(err, ErrInvalidRegistrationRequest) || strings.Contains(err.Error(), "rejected-bearer") {
		t.Fatal("registration wire error disclosed rejected bearer material")
	}
}

func FuzzDecodeCredentialRegistration(f *testing.F) {
	f.Add([]byte(validRegistrationRequestJSON))
	f.Add([]byte(""))
	f.Add([]byte(`{"Version":142}`))

	registrationID, err := enrollment.ParseRegistrationID("01890f90-0000-7000-8000-000000000002")
	if err != nil {
		f.Fatalf("ParseRegistrationID() error = %v", err)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		request, decodeErr := DecodeCredentialRegistration(bytes.NewReader(encoded), registrationID)
		if decodeErr == nil && !request.IsValid() {
			t.Fatal("DecodeCredentialRegistration() accepted an invalid product request")
		}
	})
}

func validRegistrationWire(t *testing.T) registrationRequestWire {
	t.Helper()

	credentialID, err := enrollment.ParseCredentialID("01890f90-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("ParseCredentialID() error = %v", err)
	}
	var secret [32]byte
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	token, err := enrollment.NewCredentialToken(secret)
	if err != nil {
		t.Fatalf("NewCredentialToken() error = %v", err)
	}
	credential, err := enrollment.NewCredentialPresentation(credentialID, token)
	if err != nil {
		t.Fatalf("NewCredentialPresentation() error = %v", err)
	}
	return registrationRequestWire{
		Version:        supportedCapabilityVersion,
		NodeKey:        nodeKeyPrefix + "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		OldNodeKey:     nodeKeyPrefix + strings.Repeat("0", publicKeyHexLength),
		NetworkLockKey: networkLockKeyPrefix + strings.Repeat("0", publicKeyHexLength),
		Auth:           &registrationAuthWire{AuthKey: credential.Reveal()},
		HostInfo:       &registrationHostWire{Hostname: "Node-One.Example"},
	}
}

func parseRegistrationID(t testing.TB) enrollment.RegistrationID {
	t.Helper()

	id, err := enrollment.ParseRegistrationID("01890f90-0000-7000-8000-000000000002")
	if err != nil {
		t.Fatalf("ParseRegistrationID() error = %v", err)
	}
	return id
}

type registrationErrorReader struct{}

func (registrationErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("controlled read failure")
}
