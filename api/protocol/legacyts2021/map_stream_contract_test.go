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
		NetworkNameChange               string   `json:"network_name_change"`
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
	AuthorityDelta struct {
		Selection              string   `json:"selection"`
		Atomicity              string   `json:"atomicity"`
		PeerEncoding           string   `json:"peer_encoding"`
		PeerRemoval            string   `json:"peer_removal"`
		PolicyEncoding         string   `json:"policy_encoding"`
		CoincidentConnectivity string   `json:"coincident_connectivity"`
		PeerOrder              string   `json:"peer_order"`
		FullSnapshotFallback   []string `json:"full_snapshot_fallback"`
		ForbiddenFields        []string `json:"forbidden_fields"`
	} `json:"authority_delta"`
	TerminalAuthority struct {
		Selection          string   `json:"selection"`
		Causes             []string `json:"causes"`
		SelfEncoding       string   `json:"self_encoding"`
		Peers              string   `json:"peers"`
		PacketFilter       string   `json:"packet_filter"`
		ClientBehavior     string   `json:"client_behavior"`
		TransientExclusion string   `json:"transient_exclusion"`
	} `json:"terminal_authority"`
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
	if contract.ContractVersion != 6 || contract.Profile != "legacy-ts2021-cap142-v1" ||
		contract.ClientEvidence.Repository != "https://github.com/meshtransit/meshd.git" ||
		contract.ClientEvidence.Revision != "659d9e76d1ddf36a86abb70109fbab527c2bccd1" {
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
		lifecycle.NetworkNameChange != "full-snapshot-after-network-revision" ||
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
	authorityDelta := contract.AuthorityDelta
	if authorityDelta.Selection != "contiguous-network-revision-stable-self-authority" ||
		authorityDelta.Atomicity != "single-map-response-frame" ||
		authorityDelta.PeerEncoding != "PeersChanged-complete-replacement" ||
		authorityDelta.PeerRemoval != "PeersRemoved-numeric-node-id" ||
		authorityDelta.PolicyEncoding != "PacketFilter-complete-replacement-explicit-empty" ||
		authorityDelta.CoincidentConnectivity != "Node-and-PeersChanged-complete-replacement" ||
		authorityDelta.PeerOrder != "numeric-node-id" ||
		!slices.Equal(authorityDelta.FullSnapshotFallback, []string{
			"first-message",
			"reconnect",
			"revision-gap",
			"self-authority-change",
			"ambiguous-peer-id-transition",
		}) || !slices.Equal(authorityDelta.ForbiddenFields, []string{"Peers", "Domain"}) {
		t.Fatalf("stream authority delta contract = %+v", authorityDelta)
	}
	terminal := contract.TerminalAuthority
	if terminal.Selection != "established-stream-self-authority-loss" ||
		!slices.Equal(terminal.Causes, []string{
			"device-or-node-key-revoked",
			"node-key-expired",
			"session-generation-or-recovery-epoch-changed",
			"authority-snapshot-discontinuity",
		}) ||
		terminal.SelfEncoding != "same-self-complete-node-expired-and-machine-unauthorized" ||
		terminal.Peers != "explicit-empty-complete-replacement" ||
		terminal.PacketFilter != "explicit-empty-complete-replacement" ||
		terminal.ClientBehavior != "permanent-stop-and-runtime-teardown-without-reconnect" ||
		terminal.TransientExclusion != "redis-presence-or-transport-loss-no-terminal-withdrawal" {
		t.Fatalf("stream terminal authority contract = %+v", terminal)
	}
}
