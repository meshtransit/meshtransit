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
	Request struct {
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
	if contract.ContractVersion != 1 || contract.Profile != "legacy-ts2021-cap142-v1" {
		t.Fatalf("contract identity = (%d, %q), want version 1 legacy profile", contract.ContractVersion, contract.Profile)
	}
	if contract.ClientEvidence.Repository != "https://github.com/meshtransit/meshd.git" ||
		contract.ClientEvidence.Revision != "78cb5130400bc003974f7730b319350fed129bbe" {
		t.Fatalf("client evidence = %+v, want pinned meshd revision", contract.ClientEvidence)
	}
	if !slices.Equal(contract.Request.AuthenticatedTransportFields, []string{"machine_key"}) {
		t.Fatalf(
			"authenticated transport fields = %v, want machine key only",
			contract.Request.AuthenticatedTransportFields,
		)
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
