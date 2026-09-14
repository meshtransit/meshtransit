package legacyts2021

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"slices"
	"testing"
)

//go:embed map_contract.json
var mapContractJSON []byte

type mapContract struct {
	ContractVersion int    `json:"contract_version"`
	Profile         string `json:"profile"`
	ClientEvidence  struct {
		Repository string `json:"repository"`
		Revision   string `json:"revision"`
	} `json:"client_evidence"`
	Request struct {
		Method                       string   `json:"method"`
		Path                         string   `json:"path"`
		SessionProtocol              string   `json:"session_protocol"`
		Capability                   int      `json:"capability"`
		Compression                  string   `json:"compression"`
		Stream                       bool     `json:"stream"`
		AuthenticatedPayloadBindings []string `json:"authenticated_payload_bindings"`
		ForbiddenPayloadAuthority    []string `json:"forbidden_payload_authority"`
	} `json:"request"`
	Response struct {
		Framing                    string   `json:"framing"`
		Compression                string   `json:"compression"`
		MaximumDecodedBytes        int      `json:"maximum_decoded_bytes"`
		RequiredFields             []string `json:"required_fields"`
		EmptyPeersSemantics        string   `json:"empty_peers_semantics"`
		EmptyPacketFilterSemantics string   `json:"empty_packet_filter_semantics"`
	} `json:"response"`
}

func TestMapContractPinsOneShotFailClosedBoundary(t *testing.T) {
	t.Parallel()

	var contract mapContract
	decoder := json.NewDecoder(bytes.NewReader(mapContractJSON))
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
	request := contract.Request
	if request.Method != "POST" || request.Path != "/machine/map" ||
		request.SessionProtocol != "noise-http2" || request.Capability != 142 ||
		request.Compression != "zstd" || request.Stream {
		t.Fatalf("map request contract = %+v, want pinned one-shot request", request)
	}
	if !slices.Equal(request.AuthenticatedPayloadBindings, []string{"node_key"}) {
		t.Fatalf("authenticated bindings = %v, want node key", request.AuthenticatedPayloadBindings)
	}
	wantForbidden := []string{"workspace_id", "network_id", "tenant_id", "account_id"}
	if !slices.Equal(request.ForbiddenPayloadAuthority, wantForbidden) {
		t.Fatalf("forbidden payload authority = %v, want %v", request.ForbiddenPayloadAuthority, wantForbidden)
	}
	response := contract.Response
	if response.Framing != "uint32-little-endian-length" || response.Compression != "zstd" ||
		response.MaximumDecodedBytes != 64<<10 ||
		!slices.Equal(response.RequiredFields, []string{"Node", "Peers", "PacketFilter"}) ||
		response.EmptyPeersSemantics != "replace-complete-set-with-empty" ||
		response.EmptyPacketFilterSemantics != "deny-all" {
		t.Fatalf("map response contract = %+v, want bounded fail-closed first response", response)
	}
}
