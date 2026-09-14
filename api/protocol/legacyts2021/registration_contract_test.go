package legacyts2021

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"slices"
	"testing"
)

//go:embed registration_contract.json
var registrationContractJSON []byte

type registrationContract struct {
	ContractVersion int    `json:"contract_version"`
	Profile         string `json:"profile"`
	ClientEvidence  struct {
		Repository string `json:"repository"`
		Revision   string `json:"revision"`
	} `json:"client_evidence"`
	TrustEstablishment struct {
		Capability            int    `json:"capability"`
		KeyMethod             string `json:"key_method"`
		KeyPath               string `json:"key_path"`
		UpgradeMethod         string `json:"upgrade_method"`
		UpgradePath           string `json:"upgrade_path"`
		SessionProtocol       string `json:"session_protocol"`
		MachineIdentitySource string `json:"machine_identity_source"`
	} `json:"trust_establishment"`
	Request struct {
		CredentialFormat             string   `json:"credential_format"`
		AuthenticatedTransportFields []string `json:"authenticated_transport_fields"`
		PayloadSemantics             []string `json:"payload_semantics"`
		ForbiddenPayloadAuthority    []string `json:"forbidden_payload_authority"`
	} `json:"registration_request"`
}

func TestRegistrationContractPinsObservedClientBoundary(t *testing.T) {
	t.Parallel()

	var contract registrationContract
	decoder := json.NewDecoder(bytes.NewReader(registrationContractJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("Decode(trailing) error = %v, want EOF", err)
	}
	if contract.ContractVersion != 3 || contract.Profile != "legacy-ts2021-cap142-v1" {
		t.Fatalf("contract identity = (%d, %q), want version 3 legacy profile", contract.ContractVersion, contract.Profile)
	}
	if contract.ClientEvidence.Repository != "https://github.com/meshtransit/meshd.git" ||
		contract.ClientEvidence.Revision != "78cb5130400bc003974f7730b319350fed129bbe" {
		t.Fatalf("client evidence = %+v, want pinned meshd revision", contract.ClientEvidence)
	}
	trust := contract.TrustEstablishment
	if trust.Capability != 142 || trust.KeyMethod != "GET" || trust.KeyPath != "/key?v=142" ||
		trust.UpgradeMethod != "POST" || trust.UpgradePath != "/ts2021" ||
		trust.SessionProtocol != "noise-http2" ||
		trust.MachineIdentitySource != "noise_peer_key" {
		t.Fatalf("trust establishment = %+v, want pinned authenticated transport", trust)
	}
	if !slices.Equal(contract.Request.AuthenticatedTransportFields, []string{"machine_key"}) {
		t.Fatalf(
			"authenticated transport fields = %v, want machine key only",
			contract.Request.AuthenticatedTransportFields,
		)
	}
	if contract.Request.CredentialFormat != "mtc1.<credential-uuid>.<base64url-32-byte-token>" {
		t.Fatalf("credential format = %q, want canonical mtc1 format", contract.Request.CredentialFormat)
	}
	wantPayload := []string{"version", "node_key", "host_info", "followup", "credential"}
	if !slices.Equal(contract.Request.PayloadSemantics, wantPayload) {
		t.Fatalf("payload semantics = %v, want %v", contract.Request.PayloadSemantics, wantPayload)
	}
	wantForbidden := []string{"workspace_id", "network_id", "tenant_id", "account_id"}
	if !slices.Equal(contract.Request.ForbiddenPayloadAuthority, wantForbidden) {
		t.Fatalf(
			"forbidden payload authority = %v, want %v",
			contract.Request.ForbiddenPayloadAuthority,
			wantForbidden,
		)
	}
	for _, field := range contract.Request.ForbiddenPayloadAuthority {
		if slices.Contains(contract.Request.PayloadSemantics, field) {
			t.Fatalf("payload semantics contains forbidden authority field %q", field)
		}
	}
}
