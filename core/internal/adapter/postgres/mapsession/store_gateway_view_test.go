package mapsession

import (
	"strings"
	"testing"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/kubeprofile"
)

// gatewayStoreFixture is liveStoreFixture with the Device a replica of
// cluster kinda-k1 that one rule from Device 702 reaches with group view;
// the Device's own policy read is that rule, expanded.
func gatewayStoreFixture(t *testing.T) (*Store, *fakeTransaction, snapshotRecord) {
	t.Helper()
	store, transaction, record := liveStoreFixture(t)
	transaction.kubernetesGateways = map[int64]string{record.numericNodeID: "kinda-k1"}
	transaction.clusterSelf = true
	transaction.kubernetesRuleGroups = [][]any{{testRuleID, []string{"view"}}}
	transaction.kubernetesSources = [][]any{
		{int64(702), "workspace", "", false, false, nil, nil, false},
	}
	inbound := validPolicyRuleRecord()
	source, destination := testPeerNodeID, testNodeID
	inbound.sourceNodeID, inbound.destinationNodeID = &source, &destination
	transaction.policyRows = &policyRuleRows{records: []policyRuleRecord{inbound}}
	return store, transaction, record
}

// TestGatewayMapCarriesItsPeersKubernetesAccess: a gateway's map from the
// shared view, loaded or derived, carries each peer's groups until their
// deadline; while that holds the map is unchanged, and once it differs the
// map is rebuilt (K1a3 §12.2, §13.2).
func TestGatewayMapCarriesItsPeersKubernetesAccess(t *testing.T) {
	store, transaction, _ := gatewayStoreFixture(t)
	peer, err := node.ParseID(testPeerNodeID)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(t.Context(), validIdentity(t))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	access, found := loaded.Kubernetes().For(peer)
	if store.InventoryStats().Shared != 1 || !found || len(access.Grants) != 1 || access.Grants[0].Group != "view" ||
		!access.Grants[0].ValidUntil.Equal(transaction.policyExpiry) ||
		access.OwnerKind != appmapsession.KubernetesOwnerWorkspace {
		t.Fatalf("loaded access = %+v (found %v), stats %+v", access, found, store.InventoryStats())
	}
	derived, found, err := store.Derive(t.Context(), loaded, loaded.NetworkRevision())
	if err != nil || !found || !derived.Kubernetes().Equal(loaded.Kubernetes()) {
		t.Fatalf("Derive() = %v, %v; access %+v", found, err, derived.Kubernetes())
	}
	if unchanged, err := store.Unchanged(t.Context(), derived, 0); err != nil || !unchanged {
		t.Fatalf("Unchanged() = %v, %v", unchanged, err)
	}
	other, err := appmapsession.NewKubernetesView(map[node.ID]appmapsession.KubernetesAccess{peer: {
		Grants:    []appmapsession.KubernetesGrant{{Group: "edit", ValidUntil: transaction.policyExpiry}},
		OwnerKind: appmapsession.KubernetesOwnerWorkspace,
	}}, appmapsession.KubernetesScopeTable{})
	if err != nil {
		t.Fatal(err)
	}
	if unchanged, _ := store.Unchanged(t.Context(), derived.WithKubernetes(other), 0); unchanged {
		t.Fatal("a map whose access differs counted as unchanged")
	}
	// A map whose refresh time the view's clock reached is rebuilt even
	// when its access still reads the same.
	lapsed, err := appmapsession.NewKubernetesView(map[node.ID]appmapsession.KubernetesAccess{peer: {
		Grants:    []appmapsession.KubernetesGrant{{Group: "view", ValidUntil: time.Now().Add(-time.Minute)}},
		OwnerKind: appmapsession.KubernetesOwnerWorkspace,
	}}, appmapsession.KubernetesScopeTable{})
	if err != nil {
		t.Fatal(err)
	}
	if unchanged, _ := store.Unchanged(t.Context(), derived.WithKubernetes(lapsed), 0); unchanged {
		t.Fatal("a map past its refresh time counted as unchanged")
	}
}

// TestDeviceMapsCarryNoKubernetesAccess: the same Network's other Devices,
// and a gateway whose Network lacks schema 237, get none.
func TestDeviceMapsCarryNoKubernetesAccess(t *testing.T) {
	store, transaction, _ := gatewayStoreFixture(t)
	transaction.kubernetesGateways = map[int64]string{999: "kinda-k1"}
	loaded, err := store.Load(t.Context(), validIdentity(t))
	if err != nil || loaded.Kubernetes().Computed() {
		t.Fatalf("a plain Device's map: %v, %+v", err, loaded.Kubernetes())
	}
	store, transaction, record := gatewayStoreFixture(t)
	transaction.kubernetesSources = nil // schema 236: the readers are not granted
	loaded, err = store.Load(t.Context(), validIdentity(t))
	if err != nil || loaded.Kubernetes().Computed() || store.InventoryStats().KubernetesWithheldUnread != 1 {
		t.Fatalf("a gateway without schema 237: %v, %+v, stats %+v (Device %d)", err, loaded.Kubernetes(),
			store.InventoryStats(), record.numericNodeID)
	}
}

// TestGatewayReadOnItsOwnWithholdsAccess: a gateway whose own policy read
// disagrees with the view of the same revision is read on its own, without
// a second try, and its map carries no access, counted (K1a3 §13.10).
func TestGatewayReadOnItsOwnWithholdsAccess(t *testing.T) {
	store, transaction, record := gatewayStoreFixture(t)
	transaction.policyRows = &policyRuleRows{records: []policyRuleRecord{validPolicyRuleRecord()}}
	queueDeviceRead(transaction, record)
	loaded, err := store.Load(t.Context(), validIdentity(t))
	stats := store.InventoryStats()
	if err != nil || loaded.Kubernetes().Computed() || stats.Direct != 1 || stats.KubernetesWithheldDirect != 1 {
		t.Fatalf("Load() = %v, access %+v, stats %+v", err, loaded.Kubernetes(), stats)
	}
	if reads := countQueries(transaction.queries, loadPacketPolicySQL); reads != 2 {
		t.Fatalf("the Device's policy was read %d times, want the shared try and its own read", reads)
	}
}

// TestWithheldEvidenceLeavesThePlainPolicy: inconsistent evidence leaves
// the policy exactly as a read without it, its rules naming no groups.
func TestWithheldEvidenceLeavesThePlainPolicy(t *testing.T) {
	t.Parallel()
	read := func(groups, sources [][]any) cachedInventory {
		store, transaction, scope := changeTrackingStore(t)
		transaction.kubernetesGateways = map[int64]string{702: "kinda-k1"}
		transaction.clusterRule = true
		transaction.kubernetesRuleGroups, transaction.kubernetesSources = groups, sources
		queueInventoryRead(transaction, 7, 10, true)
		transaction.inventoryRows = []*peerCandidateRows{{records: []peerCandidateRecord{validPeerCandidateRecord(2)}}}
		cached, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, cachedInventory{})
		if err != nil {
			t.Fatal(err)
		}
		return cached
	}
	withheld := read([][]any{{testRuleID, []string{"view"}}},
		[][]any{{int64(701), "robot", "", false, false, nil, nil, false}})
	plain := read(nil, nil)
	if withheld.kubernetes != kubernetesWithheld || plain.kubernetes != kubernetesNotRead ||
		!withheld.policy.Equal(plain.policy) {
		t.Fatalf("withheld %v, plain %v, equal %v", withheld.kubernetes, plain.kubernetes,
			withheld.policy.Equal(plain.policy))
	}
}

// TestGatewayMapNamesItsClusterCAs: a gateway's map from the shared view
// names its cluster's root and signing CA when schema 242 is granted; none
// while a restore is suspected or the reader is missing; both empty for a
// cluster without CAs (mtcp-v1 §7.10).
func TestGatewayMapNamesItsClusterCAs(t *testing.T) {
	root, signing := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	for name, test := range map[string]struct {
		cas     *string
		known   bool
		root    bool
		signing bool
	}{
		"named": {cas: pointer(`{"withheld":false,"clusters":[{"name":"kinda-k1","root":"` + root +
			`","signing":"` + signing + `"}]}`), known: true, root: true, signing: true},
		"no intermediate": {cas: pointer(`{"withheld":false,"clusters":[{"name":"kinda-k1","root":"` + root +
			`","signing":null}]}`), known: true, root: true},
		"no CA yet": {cas: pointer(`{"withheld":false,"clusters":[{"name":"kinda-k1","root":null,` +
			`"signing":null}]}`), known: true},
		// Every active cluster is listed; one missing was left out.
		"not listed":        {cas: pointer(`{"withheld":false,"clusters":[]}`)},
		"restore suspected": {cas: pointer(`{"withheld":true,"clusters":[]}`)},
		"reader missing":    {},
		"malformed":         {cas: pointer(`{"withheld":false,"clusters":[{"name":"kinda-k1","root":"ab"}]}`)},
	} {
		t.Run(name, func(t *testing.T) {
			store, transaction, _ := gatewayStoreFixture(t)
			transaction.kubernetesCAs = test.cas
			loaded, err := store.Load(t.Context(), validIdentity(t))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			ca, known := loaded.Kubernetes().CA()
			if known != test.known || (len(ca.Root) == 32) != test.root || (len(ca.Signing) == 32) != test.signing {
				t.Fatalf("CA() = %+v, %v", ca, known)
			}
		})
	}
}

func pointer(value string) *string { return &value }

// A gateway.kube.v1 session without gateway.cert1 carries no CAs; its map
// is still found unchanged when nothing changed (review a3b2 H1), and one
// with the CAs is too. Withheld and rejected CAs are counted.
func TestUnchangedGatewayMapWithClusterCAs(t *testing.T) {
	store, transaction, _ := gatewayStoreFixture(t)
	transaction.kubernetesCAs = pointer(`{"withheld":false,"clusters":[{"name":"kinda-k1","root":"` +
		strings.Repeat("ab", 32) + `","signing":"` + strings.Repeat("cd", 32) + `"}]}`)
	loaded, err := store.Load(t.Context(), validIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	withoutCA := loaded.WithKubernetes(loaded.Kubernetes().WithoutCA())
	for name, current := range map[string]appmapsession.Snapshot{"with CAs": loaded, "without CAs": withoutCA} {
		if unchanged, err := store.Unchanged(t.Context(), current, 0); err != nil || !unchanged {
			t.Fatalf("%s: Unchanged() = %v, %v", name, unchanged, err)
		}
	}
	for _, test := range []struct {
		cas                string
		withheld, rejected uint64
	}{
		{`{"withheld":true,"clusters":[]}`, 1, 0},
		{`{"withheld":false,"clusters":[{"name":"kinda-k1","signing":"` + strings.Repeat("cd", 32) + `"}]}`, 0, 1},
	} {
		store, transaction, _ := gatewayStoreFixture(t)
		transaction.kubernetesCAs = pointer(test.cas)
		if _, err := store.Load(t.Context(), validIdentity(t)); err != nil {
			t.Fatal(err)
		}
		if stats := store.InventoryStats(); stats.KubernetesCAsWithheld != test.withheld ||
			stats.KubernetesCAsRejected != test.rejected {
			t.Fatalf("%s: stats %+v", test.cas, stats)
		}
	}
}

// A gateway session without gateway.kube.v2 stays unchanged while its
// cluster's rules apply a profile: it compares what it was sent, without
// profiles, not the whole view (review d3 H1).
func TestUnchangedGatewayMapWithoutProfiles(t *testing.T) {
	store, transaction, _ := gatewayStoreFixture(t)
	profile := kubeprofile.Profile{Name: "developer", Namespaced: []kubeprofile.Rule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}}
	hash := must(kubeprofile.ContentHash(profile))
	transaction.kubernetesProfilesGranted = true
	transaction.kubernetesRuleAccess = [][]any{{testRuleID, []string{"view"}, "01890f00-0000-7000-8000-00000000cc01",
		hash[:], []string{"team-a"}, false, "enforce", nil}}
	transaction.kubernetesProfiles = [][]any{{"01890f00-0000-7000-8000-00000000cc01", hash[:], "developer",
		`{"namespaced": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]}`}}
	loaded, err := store.Load(t.Context(), validIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Kubernetes().Scopes().IsEmpty() {
		t.Fatal("the gateway's view has no table")
	}
	v1 := loaded.WithKubernetes(loaded.Kubernetes().WithoutProfiles())
	if unchanged, err := store.Unchanged(t.Context(), v1, 0); err != nil || !unchanged {
		t.Fatalf("Unchanged() = %v, %v", unchanged, err)
	}
}
