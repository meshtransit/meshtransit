package mapsession

import (
	"encoding/hex"
	"errors"
	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/sharing/sharingtest"
	"net/netip"
	"testing"
)

func aliasRecordFixture(t *testing.T) (directEdgeRecord, appmapsession.Snapshot) {
	t.Helper()
	record, self := directRecordFixture(t)
	record.ProviderWorkspaceID = "01890f00-0000-7000-8000-000000000102"
	record.Endpoint.ResourceAddress = "100.96.0.1"
	provider, err := scopeFromText(record.ProviderWorkspaceID, record.ProviderNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := node.ParseID(record.Target.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	port, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	evidence := sharingtest.New(t, sharingtest.Params{ProviderScope: provider, ConsumerScope: self.Scope(), ProviderDeviceID: peerID, ConsumerDeviceID: self.NodeID(), ProviderAddress: netip.MustParseAddr(record.Endpoint.ResourceAddress), EvaluatedAt: record.EvaluatedAt, RecoveryEpoch: record.RecoveryEpoch, Protocol: policy.ProtocolTCP, Ports: []policy.PortRange{port}})
	hash := evidence.Target.SemanticHash().Bytes()
	record.Target.SemanticHash = hex.EncodeToString(hash[:])
	record.Peer.Addresses = []string{"100.96.0.1/32"}
	record.Aliases = &aliasEdgeRecord{LocalAddresses: []string{"100.96.1.1/32"}, RemoteAddresses: []string{"100.96.0.1/32"}, ExpiresAt: record.Contract.ExpiresAt}
	return record, self
}

func TestAliasRecordKeepsForeignCanonicalAddressesOutOfMap(t *testing.T) {
	record, self := aliasRecordFixture(t)
	projection, err := decodeAliasEdge([]byte(encodeDirectRecord(t, record)), self)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := self.WithDirectDeviceProjections([]appmapsession.DirectDeviceProjection{projection})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.PeerCandidates()) != len(self.PeerCandidates()) {
		t.Fatal("alias entered ordinary inventory")
	}
	alias, ok := snapshot.DeviceAliasFor(projection.Peer().NodeID())
	if !ok || alias.RemoteAddresses[0].String() != "100.96.0.1/32" {
		t.Fatal("peer alias proof missing")
	}
	if _, err := decodeDirectEdge([]byte(encodeDirectRecord(t, record)), self); !errors.Is(err, ErrSnapshotEvidence) {
		t.Fatal("direct reader accepted cross-Workspace alias proof")
	}
}

func TestAliasRecordRejectsAbsentOrMismatchedProof(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*directEdgeRecord)
	}{
		{"missing aliases", func(record *directEdgeRecord) { record.Aliases = nil }},
		{"canonical self as local alias", func(record *directEdgeRecord) { record.Aliases.LocalAddresses = []string{"100.64.0.1/32"} }},
		{"canonical foreign peer", func(record *directEdgeRecord) { record.Peer.Addresses = []string{"100.64.0.1/32"} }},
		{"wrong remote address", func(record *directEdgeRecord) { record.Aliases.RemoteAddresses = []string{"100.96.0.2/32"} }},
		{"unbound Resource alias", func(record *directEdgeRecord) { record.Endpoint.ResourceAddress = "100.96.0.2" }},
		{"expired grant", func(record *directEdgeRecord) { record.Aliases.ExpiresAt = record.EvaluatedAt }},
		{"extended deadline", func(record *directEdgeRecord) { record.Aliases.ExpiresAt = record.Peer.KeyExpiry.AddDate(0, 0, 1) }},
		{"wrong family", func(record *directEdgeRecord) { record.Aliases.LocalAddresses = []string{"fd00:feed:1::1/128"} }},
		{"unsafe range", func(record *directEdgeRecord) { record.Aliases.LocalAddresses = []string{"100.96.1.0/24"} }},
		{"unbounded families", func(record *directEdgeRecord) { record.Aliases.LocalAddresses = make([]string, 3) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			record, self := aliasRecordFixture(t)
			test.mutate(&record)
			if _, err := decodeAliasEdge([]byte(encodeDirectRecord(t, record)), self); !errors.Is(err, ErrSnapshotEvidence) {
				t.Fatalf("unsafe alias accepted: %v", err)
			}
		})
	}
}

func TestStoreLoadsAliasOnlyWhenEnabledInSameTransaction(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		store, _, transaction, _, identity := validStoreFixture(t)
		record, _ := aliasRecordFixture(t)
		store.options.EnableDeviceAliases = enabled
		transaction.aliasRows = &directEdgeRows{values: []string{encodeDirectRecord(t, record)}}
		snapshot, err := store.Load(t.Context(), identity)
		if err != nil {
			t.Fatal(err)
		}
		if !transaction.committed || transaction.aliasRows.closed != enabled {
			t.Fatal("feature flag or owned transaction changed")
		}
		scope, err := scopeFromText(record.ProviderWorkspaceID, record.ProviderNetworkID)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := record.peerCandidate(scope)
		if err != nil {
			t.Fatal(err)
		}
		_, present := snapshot.DeviceAliasFor(peerID.NodeID())
		if present != enabled {
			t.Fatal("alias enablement ignored")
		}
	}
}

// Same-Workspace shares use the alias path too. The fixture's Networks share
// one Workspace; the Resource Alias is the IPv6 legacy lease, as on the POC.
func TestAliasRecordAcceptsSameWorkspaceDualStackShare(t *testing.T) {
	record, self := directRecordFixture(t)
	if record.ProviderWorkspaceID != record.ConsumerWorkspaceID {
		t.Fatal("fixture is not a same-Workspace share")
	}
	record.Endpoint.ResourceAddress = "fd02:48de:ec1b:1::1"
	provider, err := scopeFromText(record.ProviderWorkspaceID, record.ProviderNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := node.ParseID(record.Target.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	port, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	evidence := sharingtest.New(t, sharingtest.Params{ProviderScope: provider, ConsumerScope: self.Scope(), ProviderDeviceID: peerID,
		ConsumerDeviceID: self.NodeID(), ProviderAddress: netip.MustParseAddr(record.Endpoint.ResourceAddress), EvaluatedAt: record.EvaluatedAt,
		RecoveryEpoch: record.RecoveryEpoch, Protocol: policy.ProtocolTCP, Ports: []policy.PortRange{port}, Mode: sharing.EndpointModeFederationAlias})
	hash := evidence.Target.SemanticHash().Bytes()
	record.Target.SemanticHash = hex.EncodeToString(hash[:])
	record.Peer.Addresses = []string{"198.18.0.1/32", "fd02:48de:ec1b:1::1/128"}
	record.Aliases = &aliasEdgeRecord{LocalAddresses: []string{"198.19.0.1/32", "fd02:48de:ec1b:2::1/128"},
		RemoteAddresses: []string{"198.18.0.1/32", "fd02:48de:ec1b:1::1/128"}, ExpiresAt: record.Contract.ExpiresAt}
	projection, err := decodeAliasEdge([]byte(encodeDirectRecord(t, record)), self)
	if err != nil {
		t.Fatalf("same-Workspace alias edge rejected: %v", err)
	}
	snapshot, err := self.WithDirectDeviceProjections([]appmapsession.DirectDeviceProjection{projection})
	if err != nil {
		t.Fatal(err)
	}
	alias, ok := snapshot.DeviceAliasFor(projection.Peer().NodeID())
	if !ok || !alias.IsConsumer || len(alias.LocalAddresses) != 2 || alias.LocalAddresses[0].String() != "198.19.0.1/32" {
		t.Fatal("same-Workspace consumer grant has the wrong local alias")
	}
	if _, err := decodeDirectEdge([]byte(encodeDirectRecord(t, record)), self); !errors.Is(err, ErrSnapshotEvidence) {
		t.Fatal("direct reader accepted alias proof")
	}
}
