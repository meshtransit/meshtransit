package mapsession

import (
	"errors"
	"testing"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
)

// gatewayRows answers loadKubernetesGatewaysSQL (schema 231).
type gatewayRows struct {
	nodes    []int64
	clusters []string
	index    int
}

func (rows *gatewayRows) Next() bool {
	if rows.index >= len(rows.nodes) {
		return false
	}
	rows.index++
	return true
}

func (rows *gatewayRows) Scan(destinations ...any) error {
	if rows.index == 0 || rows.index > len(rows.nodes) {
		return errors.New("scan without current row")
	}
	*destinations[0].(*int64) = rows.nodes[rows.index-1]
	*destinations[1].(*string) = rows.clusters[rows.index-1]
	return nil
}

func (rows *gatewayRows) Err() error { return nil }

func (rows *gatewayRows) Close() {}

func clusterOf(t *testing.T, candidate appmapsession.PeerCandidate) string {
	t.Helper()
	cluster, ok := candidate.KubernetesCluster()
	if !ok {
		return ""
	}
	return cluster.String()
}

func deviceCluster(t *testing.T, cached cachedInventory, marker byte) string {
	t.Helper()
	device, found := cached.inventory.Device(must(node.ParseID(validPeerCandidateRecord(marker).nodeID)))
	if !found {
		t.Fatalf("Device %d is not listed", marker)
	}
	return clusterOf(t, device)
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

// TestStoreLoadsTheClusterOfReplicaCandidates: the per-Device read marks a
// gateway replica with its cluster once schema 231 is granted, and reads as
// before without it (K1a2b §8).
func TestStoreLoadsTheClusterOfReplicaCandidates(t *testing.T) {
	t.Parallel()
	store, _, transaction, _, identity := validStoreFixture(t)
	transaction.kubernetesGateways = map[int64]string{702: "kinda-k1"}
	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if got := clusterOf(t, snapshot.PeerCandidates()[0]); got != "kinda-k1" {
		t.Fatalf("peer cluster = %q", got)
	}
	store, _, transaction, _, identity = validStoreFixture(t)
	snapshot, err = store.Load(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if got := clusterOf(t, snapshot.PeerCandidates()[0]); got != "" ||
		countQueries(transaction.queries, loadKubernetesGatewaysSQL) != 0 {
		t.Fatalf("without schema 231: cluster %q, queries %v", got, transaction.queries)
	}
}

// TestInventoryCarriesTheClusterOfReplicas: the whole read and the change
// read both mark replicas with their cluster.
func TestInventoryCarriesTheClusterOfReplicas(t *testing.T) {
	t.Parallel()
	store, transaction, scope := changeTrackingStore(t)
	transaction.kubernetesGateways = map[int64]string{703: "kinda-k1"}
	queueInventoryRead(transaction, 7, 10, true)
	transaction.inventoryRows = []*peerCandidateRows{{records: []peerCandidateRecord{
		validPeerCandidateRecord(2), validPeerCandidateRecord(3)}}}
	first, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, cachedInventory{})
	if err != nil {
		t.Fatal(err)
	}
	if deviceCluster(t, first, 2) != "" || deviceCluster(t, first, 3) != "kinda-k1" {
		t.Fatal("the whole read lost a cluster")
	}
	transaction.kubernetesGateways = map[int64]string{703: "kinda-k1", 704: "kinda-k1"}
	queueInventoryRead(transaction, 8, 11, true)
	transaction.changeRows = []*inventoryChangeRows{{changes: []inventoryChange{
		{seq: 11, record: validPeerCandidateRecord(4)}}}}
	second, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, first)
	if err != nil {
		t.Fatal(err)
	}
	if countQueries(transaction.queries, loadNetworkDeviceChangesSQL) != 1 ||
		deviceCluster(t, second, 4) != "kinda-k1" || deviceCluster(t, second, 3) != "kinda-k1" {
		t.Fatalf("the change read lost a cluster (queries %v)", transaction.queries)
	}
}

// TestStoreRefusesInvalidGatewayEvidence: a cluster name or row count the
// schema cannot produce fails the read rather than naming a replica.
func TestStoreRefusesInvalidGatewayEvidence(t *testing.T) {
	t.Parallel()
	tooMany := make(map[int64]string, maximumMapKubernetesGateways+1)
	for index := range maximumMapKubernetesGateways + 1 {
		tooMany[int64(10_000+index)] = "c"
	}
	for name, gateways := range map[string]map[int64]string{
		"invalid name": {702: "Not_A_Label"},
		"too many":     tooMany,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, _, transaction, _, identity := validStoreFixture(t)
			transaction.kubernetesGateways = gateways
			if _, err := store.Load(t.Context(), identity); !errors.Is(err, ErrSnapshotEvidence) {
				t.Fatalf("Load() error = %v, want ErrSnapshotEvidence", err)
			}
		})
	}
}

// TestInventoryIsReadWholeOnceGatewaysAreRead: changes never apply to an
// inventory read before schema 231, whose replicas carry no cluster.
func TestInventoryIsReadWholeOnceGatewaysAreRead(t *testing.T) {
	t.Parallel()
	store, transaction, scope := changeTrackingStore(t)
	queueInventoryRead(transaction, 7, 10, true)
	transaction.inventoryRows = []*peerCandidateRows{{records: []peerCandidateRecord{validPeerCandidateRecord(3)}}}
	first, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, cachedInventory{})
	if err != nil {
		t.Fatal(err)
	}
	transaction.kubernetesGateways = map[int64]string{703: "kinda-k1"}
	queueInventoryRead(transaction, 8, 10, true)
	transaction.inventoryRows = []*peerCandidateRows{{records: []peerCandidateRecord{validPeerCandidateRecord(3)}}}
	second, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, first)
	if err != nil {
		t.Fatal(err)
	}
	if countQueries(transaction.queries, loadNetworkDevicesSQL) != 2 || deviceCluster(t, second, 3) != "kinda-k1" {
		t.Fatalf("the inventory kept a replica without its cluster (queries %v)", transaction.queries)
	}
}

// TestInventoryReadsTheKubernetesSourcesOfAClusterNetwork: once schema 237
// is granted, a Network with a cluster gateway reads its rules' Kubernetes
// groups and its Devices' owners into the policy (K1a3 §16 b1).
func TestInventoryReadsTheKubernetesSourcesOfAClusterNetwork(t *testing.T) {
	t.Parallel()
	until := inventoryReadAt.Add(2 * time.Hour)
	changed := inventoryReadAt.Add(-time.Hour)
	store, transaction, scope := changeTrackingStore(t)
	transaction.kubernetesGateways = map[int64]string{702: "kinda-k1"}
	transaction.clusterRule = true
	transaction.policyExpiry = inventoryReadAt.Add(24 * time.Hour)
	transaction.kubernetesRuleGroups = [][]any{{testRuleID, []string{"edit", "view"}}}
	transaction.kubernetesSources = [][]any{
		{int64(701), "member", "01890f00-0000-7000-8000-000000000011", true, true, until, changed, false},
		{int64(702), "workspace", "", false, false, nil, nil, false},
	}
	queueInventoryRead(transaction, 7, 10, true)
	transaction.inventoryRows = []*peerCandidateRows{{records: []peerCandidateRecord{validPeerCandidateRecord(2)}}}
	cached, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, cachedInventory{})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := node.ParseID(testPeerNodeID)
	if err != nil {
		t.Fatal(err)
	}
	client, err := node.ParseID(testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	access := cached.policy.KubernetesAccessFor(gateway, inventoryReadAt)[client]
	if len(access.Grants) != 2 || access.Grants[0].Group != "edit" || access.Grants[1].Group != "view" ||
		!access.Grants[0].ValidUntil.Equal(until) || !access.OwnerChangedAt.Equal(changed) ||
		access.OwnerKind != appmapsession.KubernetesOwnerMember {
		t.Fatalf("access = %+v", access)
	}
}

// TestStoreRefusesInvalidKubernetesSources: groups for a rule the release
// does not hold, or an owner the schema cannot produce, fail the read.
func TestStoreRefusesInvalidKubernetesSources(t *testing.T) {
	t.Parallel()
	member := []any{int64(701), "member", "01890f00-0000-7000-8000-000000000011", true, true,
		nil, nil, false}
	for name, test := range map[string]struct {
		groups  [][]any
		sources [][]any
	}{
		"unknown rule":     {groups: [][]any{{"01890f00-0000-7000-8000-000000000899", []string{"view"}}}, sources: [][]any{member}},
		"no groups":        {groups: [][]any{{testRuleID, []string{}}}, sources: [][]any{member}},
		"unknown owner":    {sources: [][]any{{int64(701), "robot", "", false, false, nil, nil, false}}},
		"workspace active": {sources: [][]any{{int64(701), "workspace", "", false, true, nil, nil, false}}},
		"tags without ref": {sources: [][]any{{int64(701), "tags", "x", false, false, nil, nil, false}}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, transaction, scope := changeTrackingStore(t)
			transaction.kubernetesGateways = map[int64]string{702: "kinda-k1"}
			transaction.clusterRule = true
			transaction.kubernetesRuleGroups, transaction.kubernetesSources = test.groups, test.sources
			queueInventoryRead(transaction, 7, 10, true)
			transaction.inventoryRows = []*peerCandidateRows{{records: []peerCandidateRecord{validPeerCandidateRecord(2)}}}
			if _, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID,
				cachedInventory{}); !errors.Is(err, ErrSnapshotEvidence) {
				t.Fatalf("readInventory() error = %v, want ErrSnapshotEvidence", err)
			}
		})
	}
}

// TestInventoryReadsNoKubernetesSourcesUnlessNeeded: a Network without a
// gateway never probes for schema 237, and a database without it reads
// none of its data (a rolling deploy onto schema 236).
func TestInventoryReadsNoKubernetesSourcesUnlessNeeded(t *testing.T) {
	t.Parallel()
	for name, gateways := range map[string]map[int64]string{"no gateway": nil, "schema 236": {702: "kinda-k1"}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, transaction, scope := changeTrackingStore(t)
			transaction.kubernetesGateways = gateways
			queueInventoryRead(transaction, 7, 10, true)
			transaction.inventoryRows = []*peerCandidateRows{{records: []peerCandidateRecord{validPeerCandidateRecord(2)}}}
			if _, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID,
				cachedInventory{}); err != nil {
				t.Fatal(err)
			}
			probes := countQueries(transaction.queries, kubernetesSourcesGrantedSQL)
			if gateways == nil && probes != 0 || gateways != nil && probes != 1 ||
				countQueries(transaction.queries, loadKubernetesSourcesSQL) != 0 ||
				countQueries(transaction.queries, loadKubernetesRuleGroupsSQL) != 0 {
				t.Fatalf("queries %v", transaction.queries)
			}
		})
	}
}
