package legacyts2021

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"testing"
)

//go:embed relay_bootstrap_contract.json
var relayBootstrapContractJSON []byte

type relayBootstrapContract struct {
	ContractVersion int    `json:"contract_version"`
	Profile         string `json:"profile"`
	ClientEvidence  struct {
		Repository string `json:"repository"`
		Revision   string `json:"revision"`
	} `json:"client_evidence"`
	Directory struct {
		Authority           string `json:"authority"`
		InitialResponse     string `json:"initial_response"`
		UnchangedDelta      string `json:"unchanged_delta"`
		ChangedDelta        string `json:"changed_delta"`
		STUNOnlyPacketRelay string `json:"stun_only_packet_relay"`
		AuthorizationEffect string `json:"authorization_effect"`
	} `json:"directory"`
	HomeSelection struct {
		Owner       string `json:"owner"`
		Input       string `json:"input"`
		Publication string `json:"publication"`
		Unknown     string `json:"unknown"`
		Withdrawal  string `json:"withdrawal"`
		Activation  string `json:"activation"`
	} `json:"home_selection"`
	PathLifecycle struct {
		InitialPath      string `json:"initial_path"`
		DirectDiscovery  string `json:"direct_discovery"`
		DirectActivation string `json:"direct_activation"`
		DirectExpiry     string `json:"direct_expiry"`
		NetworkChange    string `json:"network_change"`
	} `json:"path_lifecycle"`
	Failure struct {
		MissingUsableRelay string `json:"missing_usable_relay"`
		DirectoryInvalid   string `json:"directory_invalid"`
		RelayUnavailable   string `json:"relay_unavailable"`
		PeerRevoked        string `json:"peer_revoked"`
	} `json:"failure"`
}

func TestRelayBootstrapContractPinsPathLifecycle(t *testing.T) {
	t.Parallel()

	var contract relayBootstrapContract
	decoder := json.NewDecoder(bytes.NewReader(relayBootstrapContractJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("Decode(trailing) error = %v, want EOF", err)
	}
	if contract.ContractVersion != 1 || contract.Profile != "encrypted-relay-bootstrap-v1" ||
		contract.ClientEvidence.Repository != "https://github.com/meshtransit/meshd.git" ||
		contract.ClientEvidence.Revision != "87a3dd293aa95be1a1a0435055b1b31413258d83" {
		t.Fatalf("contract identity = %+v", contract)
	}
	directory := contract.Directory
	if directory.Authority != "control-signed-routing-metadata-only" ||
		directory.InitialResponse != "complete-replacement" ||
		directory.UnchangedDelta != "omitted" ||
		directory.ChangedDelta != "complete-replacement" ||
		directory.STUNOnlyPacketRelay != "forbidden" ||
		directory.AuthorizationEffect != "none" {
		t.Fatalf("directory contract = %+v", directory)
	}
	home := contract.HomeSelection
	if home.Owner != "client" ||
		home.Input != "bounded-stun-latency-and-authenticated-relay-health" ||
		home.Publication != "complete-endpoint-update" ||
		home.Unknown != "omitted" ||
		home.Withdrawal != "explicit-zero" ||
		home.Activation != "validated-control-echo" {
		t.Fatalf("home selection contract = %+v", home)
	}
	lifecycle := contract.PathLifecycle
	if lifecycle.InitialPath != "encrypted-relay" ||
		lifecycle.DirectDiscovery != "concurrent" ||
		lifecycle.DirectActivation != "session-bound-authenticated-proof" ||
		lifecycle.DirectExpiry != "restore-encrypted-relay" ||
		lifecycle.NetworkChange != "restore-encrypted-relay-and-reprobe" {
		t.Fatalf("path lifecycle contract = %+v", lifecycle)
	}
	failure := contract.Failure
	if failure.MissingUsableRelay != "direct-only-with-no-invented-relay" ||
		failure.DirectoryInvalid != "reject-map-atomically" ||
		failure.RelayUnavailable != "bounded-reconnect-and-region-failover" ||
		failure.PeerRevoked != "remove-direct-and-relay-authority" {
		t.Fatalf("failure contract = %+v", failure)
	}
}
