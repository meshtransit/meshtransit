package mapsession

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/sharing/sharingtest"
)

type directEdgeRows struct {
	values []string
	index  int
	err    error
	closed bool
}

func (rows *directEdgeRows) Next() bool {
	if rows.index >= len(rows.values) {
		return false
	}
	rows.index++
	return true
}
func (rows *directEdgeRows) Scan(destinations ...any) error {
	if rows.index == 0 || rows.index > len(rows.values) {
		return ErrSnapshotEvidence
	}
	*destinations[0].(*string) = rows.values[rows.index-1]
	return nil
}
func (rows *directEdgeRows) Err() error { return rows.err }
func (rows *directEdgeRows) Close()     { rows.closed = true }

func TestStoreLoadsDirectGrantInSameTransaction(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	record, _ := directRecordFixture(t)
	transaction.directRows = &directEdgeRows{values: []string{encodeDirectRecord(t, record)}}
	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if !transaction.committed || !transaction.directRows.closed || len(snapshot.SharingScopes()) != 1 ||
		len(snapshot.AuthorizedPeers()) != 2 || len(snapshot.PeerCandidates()) != 1 {
		t.Fatal("direct grant must be separate from ordinary inventory and committed atomically")
	}
	peers := snapshot.AuthorizedPeers()
	var found bool
	for _, peer := range peers {
		if peer.NodeID().String() == record.Peer.ID {
			found = true
			if !peer.KeyExpiry().Equal(record.Contract.ExpiresAt) {
				t.Fatal("sharing deadline did not cap peer key")
			}
		}
	}
	if !found {
		t.Fatal("exact provider peer missing")
	}
}

func TestDirectRecordRejectsUnsafeAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*directEdgeRecord)
	}{
		{"missing profile", func(r *directEdgeRecord) { r.CeilingProfile = "" }},
		{"unknown profile", func(r *directEdgeRecord) { r.CeilingProfile = "future-guardrails" }},
		{"blocked profile", func(r *directEdgeRecord) { r.CeilingProfile = "blocked" }},
		{"foreign Workspace", func(r *directEdgeRecord) { r.ProviderWorkspaceID = "01890f00-0000-7000-8000-000000000102" }},
		{"wrong source", func(r *directEdgeRecord) { r.Rule.SourceID = r.Peer.ID }},
		{"wrong target", func(r *directEdgeRecord) { r.Target.DeviceID = r.Rule.SourceID }},
		{"expired contract", func(r *directEdgeRecord) { r.Contract.ExpiresAt = r.EvaluatedAt }},
		{"expired endpoint", func(r *directEdgeRecord) { r.Endpoint.ExpiresAt = r.EvaluatedAt }},
		{"regressed consumer vector", func(r *directEdgeRecord) { r.ConsumerNetworkRevision-- }},
		{"wrong published revision", func(r *directEdgeRecord) { r.ConsumerPolicyRevision-- }},
		{"widened rule", func(r *directEdgeRecord) { r.Rule.Ranges = [][2]int64{{22, 22}} }},
		{"bad traffic hash", func(r *directEdgeRecord) { r.Contract.ConstraintHash = r.Target.SemanticHash }},
		{"port overflow", func(r *directEdgeRecord) { r.Rule.Ranges = [][2]int64{{443, 65536}} }},
		{"address collision", func(r *directEdgeRecord) { r.Peer.Addresses = []string{"100.64.0.1/32"} }},
		{"bad machine key", func(r *directEdgeRecord) { r.Peer.MachineKey = "00" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			record, self := directRecordFixture(t)
			test.mutate(&record)
			if _, err := decodeDirectEdge([]byte(encodeDirectRecord(t, record)), self); !errors.Is(err, ErrSnapshotEvidence) {
				t.Fatalf("unsafe authority accepted: %v", err)
			}
		})
	}
}

func TestDirectReaderFailureRollsBackCompleteSnapshot(t *testing.T) {
	for _, test := range []struct {
		name   string
		values []string
		err    error
	}{
		{name: "malformed edge", values: []string{"{}"}},
		{name: "iteration failure", err: errors.New("read interrupted")},
		{name: "oversized evidence", values: []string{string(make([]byte, maximumDirectEdgeBytes+1))}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, _, transaction, _, identity := validStoreFixture(t)
			transaction.directRows = &directEdgeRows{values: test.values, err: test.err}
			snapshot, err := store.Load(t.Context(), identity)
			if err == nil || snapshot.IsValid() || transaction.committed || transaction.rollbackCalls != 1 || !transaction.directRows.closed {
				t.Fatalf("failed bilateral read retained a partial map: %v", err)
			}
		})
	}
}

func directRecordFixture(t *testing.T) (directEdgeRecord, appmapsession.Snapshot) {
	t.Helper()
	store, _, _, _, identity := validStoreFixture(t)
	self, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := scopeFromText(testWorkspaceID, "01890f00-0000-7000-8000-000000000202")
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := node.ParseID("01890f00-0000-7000-8000-000000000703")
	if err != nil {
		t.Fatal(err)
	}
	port, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	evaluatedAt := self.CreatedAt().Add(time.Hour)
	evidence := sharingtest.New(t, sharingtest.Params{
		ProviderScope: provider, ConsumerScope: self.Scope(), ProviderDeviceID: peerID,
		ConsumerDeviceID: self.NodeID(), ProviderAddress: netip.MustParseAddr("100.64.2.3"),
		EvaluatedAt: evaluatedAt, RecoveryEpoch: self.RecoveryEpoch(), Protocol: policy.ProtocolTCP,
		Ports: []policy.PortRange{port},
	})
	contract, endpoint, target := evidence.Authority.Contract, evidence.Authority.Endpoint, evidence.Target
	var r directEdgeRecord
	r.EvaluatedAt, r.CeilingProfile = evaluatedAt, noAdditionalTrafficCeilings
	r.ProviderWorkspaceID, r.ConsumerWorkspaceID = testWorkspaceID, testWorkspaceID
	r.ProviderNetworkID, r.ConsumerNetworkID = provider.NetworkID().String(), self.Scope().NetworkID().String()
	r.ProviderNetworkRevision, r.ConsumerNetworkRevision, r.ConsumerPolicyRevision = 7, self.NetworkRevision(), self.PacketPolicy().Revision()
	r.ProviderInventoryRevision, r.ProviderSharingRevision, r.ConsumerSharingRevision = 3, 2, 2
	r.ProviderAuthorityGeneration, r.ConsumerAuthorityGeneration, r.RecoveryEpoch = 1, 1, self.RecoveryEpoch()
	r.Contract.ID, r.Contract.Version = contract.ID().String(), contract.Version()
	r.Contract.ImportedResourceID, r.Contract.ImportedResourceVersion = contract.ImportedResourceID().String(), 1
	r.Contract.OfferID, r.Contract.ExportID, r.Contract.ExpiresAt = contract.OfferID().String(), contract.ExportID().String(), contract.ExpiresAt()
	trafficHash := contract.MaximumTraffic().Hash()
	r.Contract.ConstraintHash = hex.EncodeToString(trafficHash[:])
	r.Export.Version, r.Export.ExpiresAt = evidence.Export.Version(), evidence.Export.ExpiresAt()
	r.Export.Constraints = []directTrafficRecord{{Protocol: "tcp", Ranges: [][2]int64{{443, 443}}}}
	r.Endpoint.ID, r.Endpoint.AccessName = endpoint.ID().String(), endpoint.AccessName().String()
	r.Endpoint.Generation, r.Endpoint.ExpiresAt, r.Endpoint.ResourceAddress = endpoint.Generation(), endpoint.ExpiresAt(), endpoint.ResourceAlias().String()
	hash := target.SemanticHash().Bytes()
	r.Target = directTargetRecord{
		ID: target.ID().String(), Version: 1, TargetGeneration: 1, SemanticHash: hex.EncodeToString(hash[:]),
		DisplayName: target.DisplayName().String(), DeviceID: target.DeviceID().String(),
		OwnerID: target.OwnerPrincipalID().String(), CustodianID: target.CustodianPrincipalID().String(),
		ActivatedNetworkRevision: 3, InventoryRevision: 3, CreatedAt: target.CreatedAt(), UpdatedAt: target.UpdatedAt(),
	}
	r.Rule.ID, r.Rule.SourceID, r.Rule.Protocol, r.Rule.Ranges = "01890f00-0000-7000-8000-000000000899", self.NodeID().String(), "tcp", [][2]int64{{443, 443}}
	machineKey, nodeKey := filledBytes(3), filledBytes(103)
	r.Peer.NumericNodeID, r.Peer.NumericOwnerID, r.Peer.ID = 703, 11, peerID.String()
	r.Peer.OwnerID, r.Peer.Hostname = target.OwnerPrincipalID().String(), "provider.example"
	r.Peer.MachineKey, r.Peer.NodeKey = hex.EncodeToString(machineKey[:]), hex.EncodeToString(nodeKey[:])
	r.Peer.SessionGeneration, r.Peer.CreatedAt, r.Peer.KeyExpiry = 1, self.CreatedAt(), self.KeyExpiry()
	r.Peer.Addresses = []string{"100.64.2.3/32"}
	return r, self
}

func encodeDirectRecord(t *testing.T, record directEdgeRecord) string {
	t.Helper()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestDirectRecordProviderReceivesOnlyConsumerInitiation(t *testing.T) {
	record, consumer := directRecordFixture(t)
	scope, err := scopeFromText(record.ProviderWorkspaceID, record.ProviderNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{Scope: scope, Revision: 1, Rules: []policy.Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := hex.DecodeString(record.Peer.MachineKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(record.Peer.NodeKey)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := (snapshotRecord{
		numericNodeID: record.Peer.NumericNodeID, numericOwnerID: record.Peer.NumericOwnerID,
		networkName: "Provider Network", nodeID: record.Peer.ID, hostname: record.Peer.Hostname,
		machineKey: machine, nodeKey: key, sessionGeneration: record.Peer.SessionGeneration,
		createdAt: record.Peer.CreatedAt, keyExpiry: record.Peer.KeyExpiry,
		networkRevision: record.ProviderNetworkRevision, policyRevision: 1, addresses: record.Peer.Addresses,
	}).snapshot(record.ProviderWorkspaceID, record.ProviderNetworkID, record.RecoveryEpoch,
		nil, packetPolicy, consumer.RelayDirectory())
	if err != nil {
		t.Fatal(err)
	}
	record.Peer.NumericNodeID, record.Peer.NumericOwnerID = consumer.NumericNodeID(), consumer.NumericOwnerID()
	record.Peer.ID, record.Peer.OwnerID, record.Peer.Hostname = consumer.NodeID().String(), record.Target.OwnerID, consumer.Hostname().String()
	machineKey, nodeKey := consumer.MachineKey().Bytes(), consumer.NodeKey().Bytes()
	record.Peer.MachineKey, record.Peer.NodeKey = hex.EncodeToString(machineKey[:]), hex.EncodeToString(nodeKey[:])
	record.Peer.SessionGeneration, record.Peer.CreatedAt, record.Peer.KeyExpiry = consumer.SessionGeneration(), consumer.CreatedAt(), consumer.KeyExpiry()
	record.Peer.Addresses = []string{"100.64.0.1/32", "fd7a:115c:a1e0::1/128"}
	projection, err := decodeDirectEdge([]byte(encodeDirectRecord(t, record)), provider)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := provider.WithDirectDeviceProjections([]appmapsession.DirectDeviceProjection{projection})
	if err != nil {
		t.Fatal(err)
	}
	rules := mapped.InboundPacketRules()
	if len(rules) != 1 || rules[0].SourceNodeID() != consumer.NodeID() || rules[0].DestinationNodeID() != provider.NodeID() ||
		rules[0].Protocol() != policy.ProtocolTCP || len(rules[0].DestinationPortRanges()) != 1 || rules[0].DestinationPortRanges()[0].First() != 443 {
		t.Fatal("provider projection failed to preserve the one-way grant")
	}
}

func TestDirectReaderRejectsOutputOverflow(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	record, _ := directRecordFixture(t)
	values := make([]string, appmapsession.MaximumDirectDeviceProjections+1)
	for index := range values {
		values[index] = encodeDirectRecord(t, record)
	}
	transaction.directRows = &directEdgeRows{values: values}
	if _, err := store.Load(t.Context(), identity); !errors.Is(err, ErrSnapshotEvidence) {
		t.Fatalf("overflow accepted: %v", err)
	}
	if transaction.committed || transaction.rollbackCalls != 1 || !transaction.directRows.closed {
		t.Fatal("overflow retained a partial map")
	}
}
