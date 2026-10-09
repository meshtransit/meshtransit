package legacyts2021

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

const fixtureFollowupURL = "https://control.example.test/register/v1/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"

type browserRegistrationFixture struct {
	Profile         string          `json:"profile"`
	ClientCommit    string          `json:"client_commit"`
	InitialRequest  json.RawMessage `json:"initial_request"`
	PendingResponse struct {
		MachineAuthorized bool   `json:"MachineAuthorized"`
		AuthURL           string `json:"AuthURL"`
	} `json:"pending_response"`
	FollowupRequest    json.RawMessage `json:"followup_request"`
	AuthorizedResponse struct {
		MachineAuthorized bool   `json:"MachineAuthorized"`
		AuthURL           string `json:"AuthURL"`
	} `json:"authorized_response"`
}

func TestDecodeBrowserRegistrationClientContract(t *testing.T) {
	t.Parallel()

	encoded, err := os.ReadFile("testdata/browser_registration_cap142_v1.json")
	if err != nil {
		t.Fatalf("read client contract fixture: %v", err)
	}
	var fixture browserRegistrationFixture
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatalf("decode client contract fixture: %v", err)
	}
	if fixture.Profile != "legacy-ts2021-cap142-v1" ||
		fixture.ClientCommit != "484cb397cde7d1a9e199035cd1360127189319c2" {
		t.Fatal("fixture does not pin the observed client profile and commit")
	}
	initial, err := DecodeBrowserRegistration(bytes.NewReader(fixture.InitialRequest))
	if err != nil {
		t.Fatalf("DecodeBrowserRegistration(initial) error = %v", err)
	}
	followup, err := DecodeBrowserRegistration(bytes.NewReader(fixture.FollowupRequest))
	if err != nil {
		t.Fatalf("DecodeBrowserRegistration(followup) error = %v", err)
	}
	if initial.IsFollowup() || !followup.IsFollowup() ||
		initial.NodeKey() != followup.NodeKey() ||
		initial.Hostname() != followup.Hostname() ||
		initial.Hostname().String() != "node-one.example" ||
		fixture.PendingResponse.MachineAuthorized ||
		fixture.PendingResponse.AuthURL != fixtureFollowupURL ||
		followup.FollowupURL() != fixture.PendingResponse.AuthURL ||
		!fixture.AuthorizedResponse.MachineAuthorized ||
		fixture.AuthorizedResponse.AuthURL != "" {
		t.Fatal("browser registration fixture violates the pinned client contract")
	}
	if strings.Contains(initial.String(), fixtureFollowupURL) ||
		strings.Contains(followup.GoString(), fixtureFollowupURL) {
		t.Fatal("browser registration diagnostic exposed the secret URL")
	}
	var pending bytes.Buffer
	if err := WritePendingBrowserRegistrationResponse(&pending, fixture.PendingResponse.AuthURL); err != nil {
		t.Fatalf("write pending registration response: %v", err)
	}
	var pendingWire struct {
		MachineAuthorized bool   `json:"MachineAuthorized"`
		AuthURL           string `json:"AuthURL"`
	}
	if err := json.Unmarshal(pending.Bytes(), &pendingWire); err != nil ||
		pendingWire != fixture.PendingResponse {
		t.Fatal("pending response does not match the pinned client fixture")
	}
	var authorized bytes.Buffer
	if err := WriteAuthorizedRegistrationResponse(&authorized); err != nil {
		t.Fatalf("write authorized registration response: %v", err)
	}
	var authorizedWire struct {
		MachineAuthorized bool   `json:"MachineAuthorized"`
		AuthURL           string `json:"AuthURL"`
	}
	if err := json.Unmarshal(authorized.Bytes(), &authorizedWire); err != nil ||
		authorizedWire != fixture.AuthorizedResponse ||
		bytes.Contains(authorized.Bytes(), []byte(`"AuthURL"`)) {
		t.Fatal("authorized response does not match the pinned client fixture")
	}
}

func TestWritePendingBrowserRegistrationResponseRejectsInvalidURL(t *testing.T) {
	t.Parallel()
	var response bytes.Buffer
	if err := WritePendingBrowserRegistrationResponse(&response, "http://control.example.test/register/v1/short"); !errors.Is(err, ErrRegistrationResponse) || response.Len() != 0 {
		t.Fatalf("pending response accepted an invalid URL: %v", err)
	}
}

func TestDecodeBrowserRegistrationRejectsUnsupportedSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*registrationRequestWire)
	}{
		{name: "credential request", mutate: func(_ *registrationRequestWire) {}},
		{name: "node key rotation", mutate: func(wire *registrationRequestWire) {
			wire.Auth = nil
			wire.OldNodeKey = nodeKeyPrefix + strings.Repeat("1", publicKeyHexLength)
		}},
		{name: "network selector", mutate: func(wire *registrationRequestWire) {
			wire.Auth = nil
			wire.NetworkSelector = "chosen-by-client"
		}},
		{name: "wrong capability", mutate: func(wire *registrationRequestWire) {
			wire.Auth = nil
			wire.Version--
		}},
		{name: "invalid followup query", mutate: func(wire *registrationRequestWire) {
			wire.Auth = nil
			wire.Followup = fixtureFollowupURL + "?network=other"
		}},
		{name: "invalid followup fragment", mutate: func(wire *registrationRequestWire) {
			wire.Auth = nil
			wire.Followup = fixtureFollowupURL + "#extra"
		}},
		{name: "invalid followup path", mutate: func(wire *registrationRequestWire) {
			wire.Auth = nil
			wire.Followup = "https://control.example.test/other/" + strings.Repeat("A", 43)
		}},
		{name: "invalid followup token", mutate: func(wire *registrationRequestWire) {
			wire.Auth = nil
			wire.Followup = "https://control.example.test/register/v1/short"
		}},
		{name: "non-TLS followup", mutate: func(wire *registrationRequestWire) {
			wire.Auth = nil
			wire.Followup = strings.Replace(fixtureFollowupURL, "https:", "http:", 1)
		}},
		{name: "wrong followup port", mutate: func(wire *registrationRequestWire) {
			wire.Auth = nil
			wire.Followup = strings.Replace(fixtureFollowupURL, ".test/", ".test:8443/", 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wire := validRegistrationWire(t)
			test.mutate(&wire)
			encoded, err := json.Marshal(wire)
			if err != nil {
				t.Fatalf("encode wire request: %v", err)
			}
			_, err = DecodeBrowserRegistration(bytes.NewReader(encoded))
			if !errors.Is(err, ErrInvalidRegistrationRequest) {
				t.Fatalf("DecodeBrowserRegistration() error = %v, want invalid request", err)
			}
		})
	}
}
