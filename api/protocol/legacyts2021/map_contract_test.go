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
		EndpointUpdate               struct {
			Mode                          string `json:"mode"`
			MaximumEndpoints              int    `json:"maximum_endpoints"`
			RequiresDiscoveryKey          bool   `json:"requires_discovery_key"`
			RequiresParallelEndpointTypes bool   `json:"requires_parallel_endpoint_types"`
			OmitPeers                     string `json:"omit_peers"`
			Storage                       string `json:"storage"`
			Wakeup                        string `json:"wakeup"`
			Authority                     string `json:"authority"`
		} `json:"endpoint_update"`
	} `json:"request"`
	Response struct {
		Framing                    string   `json:"framing"`
		Compression                string   `json:"compression"`
		MaximumDecodedBytes        int      `json:"maximum_decoded_bytes"`
		RequiredFields             []string `json:"required_fields"`
		NetworkNameField           string   `json:"network_name_field"`
		NetworkNameSource          string   `json:"network_name_source"`
		NetworkNameAuthority       string   `json:"network_name_authority"`
		PeerProjection             string   `json:"peer_projection"`
		PeerOrder                  string   `json:"peer_order"`
		PacketFilterProjection     string   `json:"packet_filter_projection"`
		PeerPolicyAtomicity        string   `json:"peer_policy_atomicity"`
		ConnectivityProjection     string   `json:"connectivity_projection"`
		ConnectivityFields         []string `json:"connectivity_fields"`
		ConnectivityAuthority      string   `json:"connectivity_authority"`
		EmptyPeersSemantics        string   `json:"empty_peers_semantics"`
		EmptyPacketFilterSemantics string   `json:"empty_packet_filter_semantics"`
		RelayDirectoryField        string   `json:"relay_directory_field"`
		RelayDirectoryEncoding     string   `json:"relay_directory_encoding"`
		RelayDirectoryAuthority    string   `json:"relay_directory_authority"`
		RelayDirectoryDefaultMerge string   `json:"relay_directory_default_merge"`
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
	if contract.ContractVersion != 6 || contract.Profile != "legacy-ts2021-cap142-v1" {
		t.Fatalf("contract identity = (%d, %q), want version 6 legacy profile", contract.ContractVersion, contract.Profile)
	}
	if contract.ClientEvidence.Repository != "https://github.com/meshtransit/meshd.git" ||
		contract.ClientEvidence.Revision != "84ee0f41068e8c5abcf529d68f5ad13fe21f3f3f" {
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
	endpointUpdate := request.EndpointUpdate
	if endpointUpdate.Mode != "one-shot-only" || endpointUpdate.MaximumEndpoints != 64 ||
		!endpointUpdate.RequiresDiscoveryKey || !endpointUpdate.RequiresParallelEndpointTypes ||
		endpointUpdate.OmitPeers != "accepted-only-with-endpoint-report" ||
		endpointUpdate.Storage != "redis-ttl-generation-fenced" ||
		endpointUpdate.Wakeup != "connectivity-changed" ||
		endpointUpdate.Authority != "non-authoritative" {
		t.Fatalf("endpoint update contract = %+v, want bounded transient contract", endpointUpdate)
	}
	response := contract.Response
	if response.Framing != "uint32-little-endian-length" || response.Compression != "zstd" ||
		response.MaximumDecodedBytes != 256<<10 ||
		!slices.Equal(response.RequiredFields, []string{"Domain", "Node", "Peers", "PacketFilter", "DERPMap"}) ||
		response.NetworkNameField != "Domain" ||
		response.NetworkNameSource != "authorized-network-display-name" ||
		response.NetworkNameAuthority != "presentation-only" ||
		response.PeerProjection != "explicit-policy-edge-either-direction" ||
		response.PeerOrder != "numeric-node-id" ||
		response.PacketFilterProjection != "inbound-to-self-only" ||
		response.PeerPolicyAtomicity != "same-map-response" ||
		response.ConnectivityProjection != "redis-exact-generation-self-and-authorized-peers" ||
		!slices.Equal(response.ConnectivityFields, []string{"DiscoKey", "Endpoints", "Online"}) ||
		response.ConnectivityAuthority != "non-authoritative" ||
		response.EmptyPeersSemantics != "replace-complete-set-with-empty" ||
		response.EmptyPacketFilterSemantics != "deny-all" ||
		response.RelayDirectoryField != "DERPMap" ||
		response.RelayDirectoryEncoding != "complete-replacement" ||
		response.RelayDirectoryAuthority != "routing-metadata-only" ||
		response.RelayDirectoryDefaultMerge != "forbidden" {
		t.Fatalf("map response contract = %+v, want bounded fail-closed first response", response)
	}
}
