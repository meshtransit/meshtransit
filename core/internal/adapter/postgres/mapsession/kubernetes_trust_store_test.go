package mapsession

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
)

const testClusterID = "01890f00-0000-7000-8000-000000000901"

var (
	testRootDER   = []byte("the root of kinda-k1")
	testRootPrint = sha256.Sum256(testRootDER)
	testSigning   = strings.Repeat("cd", 32)
)

// trustAnswer is schema 244's v2 answer for kinda-k1 with one trusted root
// that the signing intermediate chains to.
func trustAnswer(signingRoot string) string {
	root := hex.EncodeToString(testRootPrint[:])
	return `{"withheld":false,"clusters":[{"id":"` + testClusterID + `","name":"kinda-k1","signing":"` +
		testSigning + `","signing_root":"` + signingRoot + `","tls_name":"kinda-k1.kube.example","trusted":["` +
		root + `"]}]}`
}

// readTrustInventory reads a cluster Network's inventory once with store
// and transaction, after previous.
func readTrustInventory(t *testing.T, store *Store, transaction *fakeTransaction,
	previous cachedInventory,
) cachedInventory {
	t.Helper()
	cached, err := readTrustInventoryErr(t, store, transaction, previous)
	if err != nil {
		t.Fatal(err)
	}
	return cached
}

func readTrustInventoryErr(t *testing.T, store *Store, transaction *fakeTransaction,
	previous cachedInventory,
) (cachedInventory, error) {
	t.Helper()
	transaction.kubernetesGateways = map[int64]string{702: "kinda-k1"}
	queueInventoryRead(transaction, 7, 10, true)
	transaction.inventoryRows = []*peerCandidateRows{{records: []peerCandidateRecord{validPeerCandidateRecord(2)}}}
	return store.readInventory(t.Context(), trustScope(t), testWorkspaceID, testNetworkID, previous)
}

func trustStore(t *testing.T) (*Store, *fakeTransaction) {
	t.Helper()
	store, transaction, _ := changeTrackingStore(t)
	transaction.kubernetesTrust = pointer(trustAnswer(hex.EncodeToString(testRootPrint[:])))
	transaction.kubernetesRoots = map[[32]byte][]byte{testRootPrint: testRootDER}
	return store, transaction
}

func ran(transaction *fakeTransaction, query string) int {
	count := 0
	for _, ran := range transaction.queries {
		if ran == query {
			count++
		}
	}
	return count
}

// The inventory reads what a client trusts its clusters by, and the
// gateway's CAs, from schema 244 behind a savepoint; v1 is not read
// (K1a4d design §3.1).
func TestInventoryReadsTheClientTrust(t *testing.T) {
	t.Parallel()
	store, transaction := trustStore(t)
	transaction.kubernetesCAs = pointer(`{"withheld":false,"clusters":[]}`)
	cached := readTrustInventory(t, store, transaction, cachedInventory{})
	trust := cached.kubernetesTrust
	cluster, found := trust.Cluster("kinda-k1")
	if trust.Availability() != appmapsession.KubernetesTrustAvailable || !found ||
		cluster.ID.String() != testClusterID || cluster.TLSName != "kinda-k1.kube.example" ||
		!slices.Equal(cluster.Roots, [][32]byte{testRootPrint}) {
		t.Fatalf("trust %v, cluster %+v", trust.Availability(), cluster)
	}
	if der, held := trust.Root(testRootPrint); !held || string(der) != string(testRootDER) {
		t.Fatal("the root's DER was not read")
	}
	ca := cached.kubernetesCAs["kinda-k1"]
	if !cached.kubernetesCAsRead || [32]byte(ca.Root) != testRootPrint || hex.EncodeToString(ca.Signing) != testSigning {
		t.Fatalf("the gateway's CAs: %+v, read %v", ca, cached.kubernetesCAsRead)
	}
	if ran(transaction, loadKubernetesCAsSQL) != 0 || ran(transaction, kubernetesCAsSavepoint) != 1 ||
		ran(transaction, kubernetesCAsRelease) != 1 || ran(transaction, kubernetesRootsRelease) != 1 {
		t.Fatalf("queries: %q", transaction.queries)
	}
	// The next read of the same store takes the root from its cache.
	_ = readTrustInventory(t, store, transaction, cachedInventory{})
	if transaction.rootReads != 1 {
		t.Fatalf("roots read %d times", transaction.rootReads)
	}
	// Another store takes it from the Network's previous inventory.
	other, otherTransaction := trustStore(t)
	again := readTrustInventory(t, other, otherTransaction, cached)
	if _, held := again.kubernetesTrust.Root(testRootPrint); !held || otherTransaction.rootReads != 0 {
		t.Fatalf("not carried forward: read %d", otherTransaction.rootReads)
	}
}

// A failed or untrusted v2 read rolls back to its savepoint: gateways get
// v1's CAs, clients' trust is unread and counted (design §3.2).
func TestInventoryFallsBackWhenTheTrustFails(t *testing.T) {
	t.Parallel()
	for name, broken := range map[string]func(*fakeTransaction){
		"query fails": func(transaction *fakeTransaction) {
			transaction.kubernetesTrustErr = errors.New("permission denied")
		},
		"withheld with clusters": func(transaction *fakeTransaction) {
			transaction.kubernetesTrust = pointer(strings.Replace(trustAnswer(""), `"withheld":false`,
				`"withheld":true`, 1))
		},
		"unknown field": func(transaction *fakeTransaction) {
			transaction.kubernetesTrust = pointer(strings.Replace(trustAnswer(hex.EncodeToString(testRootPrint[:])),
				`"name"`, `"extra":1,"name"`, 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, transaction := trustStore(t)
			transaction.kubernetesCAs = pointer(`{"withheld":false,"clusters":[{"name":"kinda-k1","root":"` +
				strings.Repeat("ab", 32) + `","signing":null}]}`)
			broken(transaction)
			cached := readTrustInventory(t, store, transaction, cachedInventory{})
			if cached.kubernetesTrust.Availability() != appmapsession.KubernetesTrustUnread ||
				!cached.kubernetesCAsRead || len(cached.kubernetesCAs["kinda-k1"].Root) != 32 ||
				store.InventoryStats().KubernetesTrustUnread != 1 {
				t.Fatalf("trust %v, gateway %+v", cached.kubernetesTrust.Availability(), cached.kubernetesCAs)
			}
			if name == "query fails" && ran(transaction, kubernetesCAsRollback) != 1 {
				t.Fatalf("no rollback to the savepoint: %q", transaction.queries)
			}
		})
	}
}

// While a restore is suspected the trust says so and gateways name no CAs.
func TestInventoryTrustWhileARestoreIsSuspected(t *testing.T) {
	t.Parallel()
	store, transaction := trustStore(t)
	transaction.kubernetesTrust = pointer(`{"withheld":true,"clusters":[]}`)
	cached := readTrustInventory(t, store, transaction, cachedInventory{})
	if cached.kubernetesTrust.Availability() != appmapsession.KubernetesTrustRestore || cached.kubernetesCAsRead ||
		store.InventoryStats().KubernetesCAsWithheld != 1 || transaction.rootReads != 0 {
		t.Fatalf("trust %v, gateway read %v", cached.kubernetesTrust.Availability(), cached.kubernetesCAsRead)
	}
}

// A root the database does not give, or gives under another fingerprint,
// is left out and counted; the cluster still names it (design §3.3).
func TestInventoryTrustWithoutARoot(t *testing.T) {
	t.Parallel()
	for name, broken := range map[string]func(*fakeTransaction){
		"read fails":  func(transaction *fakeTransaction) { transaction.kubernetesRootsErr = errors.New("boom") },
		"not found":   func(transaction *fakeTransaction) { transaction.kubernetesRoots = nil },
		"another DER": func(transaction *fakeTransaction) { transaction.kubernetesRoots[testRootPrint] = []byte("x") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, transaction := trustStore(t)
			broken(transaction)
			cached := readTrustInventory(t, store, transaction, cachedInventory{})
			cluster, _ := cached.kubernetesTrust.Cluster("kinda-k1")
			if _, held := cached.kubernetesTrust.Root(testRootPrint); held || len(cluster.Roots) != 1 ||
				cached.kubernetesTrust.Availability() != appmapsession.KubernetesTrustAvailable ||
				store.InventoryStats().KubernetesRootsMissing != 1 {
				t.Fatalf("trust %v, cluster %+v", cached.kubernetesTrust.Availability(), cluster)
			}
			if name == "read fails" && ran(transaction, kubernetesRootsRollback) != 1 {
				t.Fatalf("no rollback to the savepoint: %q", transaction.queries)
			}
		})
	}
}

// A savepoint that cannot be set, or rolled back to, fails the inventory:
// its transaction is unusable (review d1 H2).
func TestInventoryFailsWhenTheSavepointFails(t *testing.T) {
	t.Parallel()
	for name, broken := range map[string]func(*fakeTransaction){
		"savepoint": func(transaction *fakeTransaction) {
			transaction.execErrs = map[string]error{kubernetesCAsSavepoint: errors.New("aborted")}
		},
		"rollback": func(transaction *fakeTransaction) {
			transaction.kubernetesTrustErr = errors.New("statement timeout")
			transaction.execErrs = map[string]error{kubernetesCAsRollback: errors.New("aborted")}
		},
		"roots rollback": func(transaction *fakeTransaction) {
			transaction.kubernetesRootsErr = errors.New("statement timeout")
			transaction.execErrs = map[string]error{kubernetesRootsRollback: errors.New("aborted")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, transaction := trustStore(t)
			broken(transaction)
			if _, err := readTrustInventoryErr(t, store, transaction, cachedInventory{}); !errors.Is(err,
				ErrKubernetesSavepoint) || !errors.Is(err, ErrLoadSnapshot) {
				t.Fatalf("readInventory() = %v", err)
			}
		})
	}
}

// A cluster whose gateway root its clients do not trust keeps their trust
// and is left out of the gateways' CAs only, counted; the Network's other
// clusters stay (review d1 L8).
func TestInventoryOmitsAnUntrustedGatewayRoot(t *testing.T) {
	t.Parallel()
	store, transaction := trustStore(t)
	root := hex.EncodeToString(testRootPrint[:])
	good := `{"id":"` + testClusterID + `","name":"kinda-k1","signing":"` + testSigning + `","signing_root":"` +
		root + `","tls_name":"kinda-k1.kube.example","trusted":["` + root + `"]}`
	bad := `{"id":"01890f00-0000-7000-8000-000000000902","name":"other","signing":"` + testSigning +
		`","signing_root":"` + strings.Repeat("ab", 32) + `","tls_name":"other.kube.example","trusted":["` +
		root + `"]}`
	transaction.kubernetesTrust = pointer(`{"withheld":false,"clusters":[` + good + `,` + bad + `]}`)
	cached := readTrustInventory(t, store, transaction, cachedInventory{})
	_, other := cached.kubernetesCAs["other"]
	if _, found := cached.kubernetesTrust.Cluster("other"); !found || other ||
		cached.kubernetesTrust.Len() != 2 || len(cached.kubernetesCAs) != 1 ||
		store.InventoryStats().KubernetesGatewayCAsOmitted != 1 || store.InventoryStats().KubernetesCAsRejected != 0 {
		t.Fatalf("trust %d clusters, gateways %+v, stats %+v", cached.kubernetesTrust.Len(), cached.kubernetesCAs,
			store.InventoryStats())
	}
}

// More roots than one read takes are read in batches.
func TestInventoryReadsRootsInBatches(t *testing.T) {
	t.Parallel()
	store, transaction := trustStore(t)
	transaction.kubernetesRoots = map[[32]byte][]byte{}
	var clusters []string
	for index := range kubernetesRootsPerRead + 10 {
		der := fmt.Appendf(nil, "root %d", index)
		fingerprint := sha256.Sum256(der)
		transaction.kubernetesRoots[fingerprint] = der
		clusters = append(clusters, fmt.Sprintf(`{"id":"01890f00-0000-7000-8000-%012x","name":"c%d",`+
			`"signing":null,"signing_root":null,"tls_name":"c%d.kube.example","trusted":["%s"]}`,
			index+1, index, index, hex.EncodeToString(fingerprint[:])))
	}
	transaction.kubernetesTrust = pointer(`{"withheld":false,"clusters":[` + strings.Join(clusters, ",") + `]}`)
	cached := readTrustInventory(t, store, transaction, cachedInventory{})
	if transaction.rootReads != 2 || cached.kubernetesTrust.Len() != kubernetesRootsPerRead+10 ||
		store.InventoryStats().KubernetesRootsMissing != 0 {
		t.Fatalf("reads %d, clusters %d, stats %+v", transaction.rootReads, cached.kubernetesTrust.Len(),
			store.InventoryStats())
	}
	for fingerprint := range transaction.kubernetesRoots {
		if _, held := cached.kubernetesTrust.Root(fingerprint); !held {
			t.Fatal("a root of the second batch is missing")
		}
	}
}

// A root the previous inventory held needs no read, even when reads fail.
func TestInventoryCarriesRootsWhenReadsFail(t *testing.T) {
	t.Parallel()
	store, transaction := trustStore(t)
	previous := readTrustInventory(t, store, transaction, cachedInventory{})
	other, otherTransaction := trustStore(t)
	otherTransaction.kubernetesRootsErr = errors.New("statement timeout")
	cached := readTrustInventory(t, other, otherTransaction, previous)
	if _, held := cached.kubernetesTrust.Root(testRootPrint); !held || otherTransaction.rootReads != 0 ||
		other.InventoryStats().KubernetesRootsMissing != 0 {
		t.Fatalf("reads %d, stats %+v", otherTransaction.rootReads, other.InventoryStats())
	}
}

// A Network without a cluster gateway names no cluster: available, empty.
func TestInventoryWithoutGatewaysTrustsNoCluster(t *testing.T) {
	t.Parallel()
	store, transaction := trustStore(t)
	queueInventoryRead(transaction, 7, 10, true)
	transaction.inventoryRows = []*peerCandidateRows{{records: []peerCandidateRecord{validPeerCandidateRecord(2)}}}
	cached, err := store.readInventory(t.Context(), trustScope(t), testWorkspaceID, testNetworkID, cachedInventory{})
	if err != nil {
		t.Fatal(err)
	}
	if cached.kubernetesTrust.Availability() != appmapsession.KubernetesTrustAvailable ||
		cached.kubernetesTrust.Len() != 0 || ran(transaction, loadKubernetesCAsV2SQL) != 0 {
		t.Fatalf("trust %v, %d clusters", cached.kubernetesTrust.Availability(), cached.kubernetesTrust.Len())
	}
}

// The cache keeps DER of its fingerprint only, within its bytes, least
// recently used first out.
func TestKubernetesRootCache(t *testing.T) {
	t.Parallel()
	cache := newKubernetesRootCache(10)
	first, second, third := []byte("aaaa"), []byte("bbbb"), []byte("cccc")
	printOf := func(der []byte) [32]byte { return sha256.Sum256(der) }
	if cache.put(printOf(first), second) || cache.put(printOf([]byte("too long here")), []byte("too long here")) {
		t.Fatal("kept DER of another fingerprint or over the bound")
	}
	cache.put(printOf(first), first)
	cache.put(printOf(second), second)
	cache.get(printOf(first))
	cache.put(printOf(third), third)
	if _, ok := cache.get(printOf(second)); ok {
		t.Fatal("the least recently used root was kept")
	}
	if _, ok := cache.get(printOf(first)); !ok || cache.size != 8 {
		t.Fatalf("size %d", cache.size)
	}
}

func trustScope(t *testing.T) network.Scope {
	t.Helper()
	scope, err := scopeFromText(testWorkspaceID, testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
