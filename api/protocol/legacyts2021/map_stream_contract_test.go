package legacyts2021

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"slices"
	"testing"
)

//go:embed map_stream_contract.json
var mapStreamContractJSON []byte

type mapStreamContract struct {
	ContractVersion int    `json:"contract_version"`
	Profile         string `json:"profile"`
	ClientEvidence  struct {
		Repository string `json:"repository"`
		Revision   string `json:"revision"`
	} `json:"client_evidence"`
	Request struct {
		Method          string `json:"method"`
		Path            string `json:"path"`
		SessionProtocol string `json:"session_protocol"`
		Capability      int    `json:"capability"`
		Compression     string `json:"compression"`
		Stream          bool   `json:"stream"`
	} `json:"request"`
	Lifecycle struct {
		FirstMessage                    string   `json:"first_message"`
		KeepAlive                       string   `json:"keepalive"`
		MaximumSilence                  int      `json:"maximum_silence_seconds"`
		PresenceAuthority               string   `json:"presence_authority"`
		PresenceFence                   []string `json:"presence_fence"`
		RedisLoss                       string   `json:"redis_loss"`
		RevisionWakeup                  string   `json:"revision_wakeup"`
		ConnectivityWakeup              string   `json:"connectivity_wakeup"`
		ConnectivityCoalescing          string   `json:"connectivity_coalescing"`
		SameRevisionConnectivityRefresh bool     `json:"same_revision_connectivity_refresh"`
		MissedWakeupRepair              string   `json:"missed_wakeup_repair"`
		Reconnect                       string   `json:"reconnect"`
	} `json:"lifecycle"`
	ConnectivityDelta struct {
		Selection          string   `json:"selection"`
		SelfEncoding       string   `json:"self_encoding"`
		PeerEncoding       string   `json:"peer_encoding"`
		EndpointWithdrawal string   `json:"endpoint_withdrawal"`
		PeerOnline         string   `json:"peer_online"`
		PeerOrder          string   `json:"peer_order"`
		ForbiddenFields    []string `json:"forbidden_fields"`
	} `json:"connectivity_delta"`
}

func TestMapStreamContractPinsFailClosedLifecycle(t *testing.T) {
	t.Parallel()

	var contract mapStreamContract
	decoder := json.NewDecoder(bytes.NewReader(mapStreamContractJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("Decode(trailing) error = %v, want EOF", err)
	}
	if contract.ContractVersion != 3 || contract.Profile != "legacy-ts2021-cap142-v1" ||
		contract.ClientEvidence.Repository != "https://github.com/meshtransit/meshd.git" ||
		contract.ClientEvidence.Revision != "78cb5130400bc003974f7730b319350fed129bbe" {
		t.Fatalf("stream contract identity = %+v", contract)
	}
	request := contract.Request
	if request.Method != "POST" || request.Path != "/machine/map" ||
		request.SessionProtocol != "noise-http2" || request.Capability != 142 ||
		request.Compression != "zstd" || !request.Stream {
		t.Fatalf("stream request contract = %+v", request)
	}
	lifecycle := contract.Lifecycle
	if lifecycle.FirstMessage != "complete-snapshot" ||
		lifecycle.KeepAlive != "non-empty-framed-message" || lifecycle.MaximumSilence != 90 ||
		lifecycle.PresenceAuthority != "non-authoritative" ||
		!slices.Equal(lifecycle.PresenceFence, []string{"node_id", "session_generation", "replica_id"}) ||
		lifecycle.RedisLoss != "terminate-stream" ||
		lifecycle.RevisionWakeup != "network-revision-advanced" ||
		lifecycle.ConnectivityWakeup != "network-scoped-connectivity-changed" ||
		lifecycle.ConnectivityCoalescing != "latest-wins-full-state-reload" ||
		!lifecycle.SameRevisionConnectivityRefresh ||
		lifecycle.MissedWakeupRepair != "postgresql-and-redis-reconciliation" ||
		lifecycle.Reconnect != "fresh-authenticated-snapshot" {
		t.Fatalf("stream lifecycle contract = %+v", lifecycle)
	}
	delta := contract.ConnectivityDelta
	if delta.Selection != "same-authority-revision-connectivity-only" ||
		delta.SelfEncoding != "Node-complete-replacement" ||
		delta.PeerEncoding != "PeersChanged-complete-replacement" ||
		delta.EndpointWithdrawal != "replacement-node-with-no-endpoints" ||
		delta.PeerOnline != "explicit-boolean" || delta.PeerOrder != "numeric-node-id" ||
		!slices.Equal(delta.ForbiddenFields, []string{"Peers", "PacketFilter"}) {
		t.Fatalf("stream connectivity delta contract = %+v", delta)
	}
}
