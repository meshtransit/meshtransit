package lifecycle

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// sealingCustody is a custody that wraps a data key by appending a tag,
// enough to tell the worker used it.
type sealingCustody struct{ dataKey kubeca.DataKey }

func (custody sealingCustody) NewDataKey(context.Context, string) (kubeca.DataKey, kubeca.WrappedKey, error) {
	return custody.dataKey, kubeca.WrappedKey{Custody: "file", KeyID: "k1", Ciphertext: []byte("wrapped")}, nil
}

func (custody sealingCustody) WrapDataKey(context.Context, string, kubeca.DataKey) (kubeca.WrappedKey, error) {
	return kubeca.WrappedKey{Custody: "file", KeyID: "k1", Ciphertext: []byte("wrapped")}, nil
}

func (custody sealingCustody) OpenDataKey(_ context.Context, _ string, wrapped kubeca.WrappedKey) (kubeca.DataKey,
	error,
) {
	if string(wrapped.Ciphertext) != "wrapped" {
		return kubeca.DataKey{}, kubeca.ErrInvalid
	}
	return custody.dataKey, nil
}

// fakeStore holds one Network and records what the worker did to it.
type fakeStore struct {
	read      kubeca.Network
	scope     network.Scope
	matched   bool
	changes   []kubeca.Changes
	added     []publicid.ID
	postponed int
	beats     []bool
	planErr   error
	readErr   error
	busy      bool
	guard     kubeca.Guard
	marked    []kubeca.Operator
	listed    int
	stamped   []int64
	guardErr  error
}

func (store *fakeStore) ReadGuard(context.Context, deployment.ID) (kubeca.Guard, error) {
	if store.guardErr != nil {
		return kubeca.Guard{}, store.guardErr
	}
	guard := store.guard
	if guard.Generation == 0 {
		guard.Generation, guard.ReadStarted, guard.ReadFinished = 1, time.Now(), time.Now()
	}
	return guard, nil
}

func (store *fakeStore) StampGuard(_ context.Context, _ deployment.ID, generation int64) error {
	store.stamped = append(store.stamped, generation)
	return nil
}

func (store *fakeStore) MarkRestored(_ context.Context, _ deployment.ID, operator kubeca.Operator) error {
	store.marked = append(store.marked, operator)
	store.guard.Suspected = true
	return nil
}

func (store *fakeStore) ListDue(context.Context, deployment.ID, int) ([]network.Scope, error) {
	store.listed++
	return []network.Scope{store.scope}, nil
}

func (store *fakeStore) ClaimDNSSuffix(context.Context, deployment.ID, string) (string, bool, error) {
	return "mesh.test", store.matched, nil
}

func (store *fakeStore) Read(context.Context, deployment.ID, network.Scope) (kubeca.Network, error) {
	return store.read, store.readErr
}

func (store *fakeStore) Change(_ context.Context, _ deployment.ID, _ network.Scope,
	plan func(kubeca.Network) (kubeca.Changes, error),
) (bool, error) {
	if store.busy {
		return true, nil
	}
	changes, err := plan(store.read)
	if err != nil {
		store.planErr = err
		return false, err
	}
	store.changes = append(store.changes, changes)
	return false, nil
}

func (store *fakeStore) AddDataKey(_ context.Context, _ deployment.ID, _ network.Scope, id publicid.ID,
	wrapped kubeca.WrappedKey, _ kubeca.Operator,
) (bool, error) {
	store.added = append(store.added, id)
	store.read.DataKeys = append(store.read.DataKeys, kubeca.StoredDataKey{
		ID: id, Version: 1, Wrapped: wrapped,
		Active: true,
	})
	return true, nil
}

func (store *fakeStore) Postpone(context.Context, deployment.ID, network.Scope, time.Time) (bool, error) {
	store.postponed++
	return false, nil
}

func (store *fakeStore) Beat(_ context.Context, _ deployment.ID, _ publicid.ID, ready bool, _, _ string,
	capabilities []string,
) (time.Time, error) {
	if len(capabilities) != 1 || capabilities[0] != Capability {
		return time.Time{}, errors.New("capabilities")
	}
	store.beats = append(store.beats, ready)
	return time.Now(), nil
}

func testScope(t *testing.T) network.Scope {
	t.Helper()
	scope, err := network.NewScope(workspace.ID(testID(t)), network.ID(testID(t)))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func testWorker(t *testing.T, store *fakeStore, source CustodySource) *Worker {
	t.Helper()
	installation, err := deployment.ParseID(testID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := dnsname.ParseSuffix("mesh.internal")
	if err != nil {
		t.Fatal(err)
	}
	worker, err := New(Options{
		DeploymentID: installation, Suffix: suffix, BatchSize: 4, PollInterval: time.Second,
		OperationTimeout: time.Second, Version: "test", Policy: DefaultPolicy(),
	}, store, source,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func newNetwork(t *testing.T, dataKeys ...kubeca.StoredDataKey) (kubeca.Network, publicid.ID) {
	t.Helper()
	cluster, now := testID(t), time.Now()
	return kubeca.Network{
		Now: now, WorkspaceCode: "123456789012", NetworkCode: "210987654321",
		DataKeys: dataKeys, Clusters: []kubeca.Cluster{{
			ID: cluster, Name: "prod", Active: true,
			NextActionAt: now,
		}},
	}, cluster
}

// A new cluster gets a root and an intermediate the root signed, sealed
// under the Network's data key, created first in a new Network without a
// data key; the worker beats but is not ready to sign.
func TestWorkerGivesANewClusterItsCAs(t *testing.T) {
	t.Parallel()
	dataKey := kubeca.DataKey{1, 2, 3}
	read, cluster := newNetwork(t)
	store := &fakeStore{read: read, scope: testScope(t), matched: true}
	worker := testWorker(t, store, func(context.Context) (kubeca.Custody, string, error) {
		return sealingCustody{dataKey: dataKey}, "file", nil
	})
	worker.Pass(t.Context())
	if len(store.added) != 1 || len(store.changes) != 1 || len(store.beats) != 1 || store.beats[0] {
		t.Fatalf("added %d, changes %d, beats %v", len(store.added), len(store.changes), store.beats)
	}
	steps := store.changes[0].Steps
	if len(steps) != 2 || steps[0].Create == nil || steps[1].Create == nil ||
		steps[0].Create.Kind != kubeca.KindRoot || steps[1].Create.Kind != kubeca.KindIntermediate ||
		steps[1].Create.IssuerID != steps[0].Create.ID || steps[0].Create.DataKeyID != store.added[0] ||
		len(store.changes[0].Schedules) != 1 || !store.changes[0].Operator.IsWorker() {
		t.Fatalf("changes = %+v", store.changes[0])
	}
	name := "prod.kube.123456789012.210987654321.mesh.internal"
	root, err := kubeca.OpenRoot(dataKey, steps[0].Create.Certificate, steps[0].Create.SealedKey,
		worker.options.DeploymentID.String(), cluster.String(), steps[0].Create.ID.String())
	if err != nil || root.ClusterDNSName() != name {
		t.Fatalf("the root does not open: %v", err)
	}
	intermediate, err := kubeca.OpenIntermediate(dataKey, steps[1].Create.Certificate, steps[1].Create.SealedKey,
		worker.options.DeploymentID.String(), cluster.String(), steps[1].Create.ID.String(), root.Certificate())
	if err != nil {
		t.Fatalf("the intermediate does not open under its root: %v", err)
	}
	life := time.Until(intermediate.Certificate().NotAfter)
	if life < 26*24*time.Hour || life > 34*24*time.Hour {
		t.Fatalf("intermediate life %v", life)
	}
	if subject := intermediate.Certificate().Subject.CommonName; subject == root.Certificate().Subject.CommonName {
		t.Fatalf("both tiers are named %q", subject)
	}
	if snapshot := worker.Snapshot(); snapshot.Created != 2 || snapshot.Changed != 1 || !snapshot.CustodyReady {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

// A worker whose suffix is not the recorded one does nothing but beat.
func TestWorkerStopsOnAnotherSuffix(t *testing.T) {
	t.Parallel()
	read, _ := newNetwork(t)
	store := &fakeStore{read: read, scope: testScope(t)}
	worker := testWorker(t, store, func(context.Context) (kubeca.Custody, string, error) {
		return sealingCustody{}, "file", nil
	})
	worker.Pass(t.Context())
	if len(store.changes) != 0 || len(store.added) != 0 || len(store.beats) != 1 || !worker.Snapshot().SuffixMismatch {
		t.Fatalf("a mismatched worker acted: %+v", store)
	}
}

// Without its custody the worker still beats (custody none), counts a
// failure and schedules the cluster that needed it again; moves alone need
// no custody.
func TestWorkerWithoutCustodyPostpones(t *testing.T) {
	t.Parallel()
	read, _ := newNetwork(t)
	store := &fakeStore{read: read, scope: testScope(t), matched: true}
	worker := testWorker(t, store, func(context.Context) (kubeca.Custody, string, error) {
		return nil, "", errors.New("no key file")
	})
	worker.Pass(t.Context())
	if len(store.changes) != 1 || len(store.changes[0].Steps) != 0 || len(store.changes[0].Schedules) != 1 ||
		!store.changes[0].Schedules[0].Failed || store.postponed != 0 || len(store.beats) != 1 ||
		worker.Snapshot().Failures != 1 || worker.Snapshot().CustodyReady {
		t.Fatalf("store %+v, snapshot %+v", store, worker.Snapshot())
	}
	store.changes = nil
	// A deleted cluster's CAs retire without the custody.
	read.Clusters[0].Active = false
	read.Clusters[0].CAs = []kubeca.StoredCA{root(t, kubeca.StateActive, testName, -day, 9*365*day)}
	store.read = read
	worker.backoff = map[network.Scope]retryState{}
	worker.Pass(t.Context())
	if len(store.changes) != 1 || len(store.changes[0].Steps) != 1 || !store.changes[0].Schedules[0].Done {
		t.Fatalf("a deleted cluster: %+v", store.changes)
	}
	// A Network whose read fails as a whole is postponed.
	store.readErr = errors.New("read failed")
	worker.backoff = map[network.Scope]retryState{}
	worker.Pass(t.Context())
	if store.postponed != 1 {
		t.Fatalf("a failed read was not postponed: %d", store.postponed)
	}
}

// What was prepared applies only while the locked read needs exactly that.
func TestRecheckRefusesAChangedNetwork(t *testing.T) {
	t.Parallel()
	read, cluster := newNetwork(t)
	names := map[publicid.ID]string{cluster: testName}
	prepared := Decide(read, names, DefaultPolicy())
	decide := func(locked kubeca.Network) Decision { return Decide(locked, names, DefaultPolicy()) }
	if _, err := Recheck(prepared, nil, read, decide); err != nil {
		t.Fatalf("an unchanged Network: %v", err)
	}
	locked := read
	locked.Clusters = []kubeca.Cluster{read.Clusters[0]}
	locked.Clusters[0].CAs = []kubeca.StoredCA{root(t, kubeca.StateActive, testName, -day, 9*365*day)}
	if _, err := Recheck(prepared, nil, locked, decide); !errors.Is(err, ErrPlanChanged) {
		t.Fatalf("a changed Network: %v", err)
	}
}

// Clusters are named under their Network's codes and the suffix; deleted
// ones and Networks without codes are not.
func TestNames(t *testing.T) {
	t.Parallel()
	suffix, err := dnsname.ParseSuffix("mesh.internal")
	if err != nil {
		t.Fatal(err)
	}
	read, cluster := newNetwork(t)
	gone := kubeca.Cluster{ID: testID(t), Name: "gone"}
	read.Clusters = append(read.Clusters, gone)
	names := Names(read, suffix)
	if len(names) != 1 || names[cluster] != "prod.kube.123456789012.210987654321.mesh.internal" {
		t.Fatalf("Names() = %v", names)
	}
	read.WorkspaceCode = "nope"
	if names := Names(read, suffix); len(names) != 0 {
		t.Fatalf("Names() without codes = %v", names)
	}
}

// An intermediate under a stored root opens the root under the data key
// that sealed it, even one since retired.
func TestPrepareOpensAStoredRoot(t *testing.T) {
	t.Parallel()
	installation := "dep-1"
	oldKey, newKey := kubeca.DataKey{9}, kubeca.DataKey{8}
	read, cluster := newNetwork(t)
	rootCA, err := kubeca.NewRoot(kubeca.RootParams{
		ClusterDNSName: testName, Subject: "r", NotBefore: time.Now(),
		Lifetime: kubeca.DefaultRootLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored := root(t, kubeca.StateActive, testName, -day, 9*365*day)
	stored.Certificate, stored.DataKeyID = rootCA.Certificate().Raw, testID(t)
	if stored.SealedKey, err = kubeca.SealCA(oldKey, rootCA, installation, cluster.String(),
		stored.ID.String()); err != nil {
		t.Fatal(err)
	}
	read.Clusters[0].CAs = []kubeca.StoredCA{stored}
	decision := Decide(read, map[publicid.ID]string{cluster: testName}, DefaultPolicy())
	opened := 0
	sealer := Sealer{
		Installation: installation, DataKeyID: testID(t), DataKey: newKey,
		OpenDataKey: func(id publicid.ID) (kubeca.DataKey, error) {
			opened++
			if id != stored.DataKeyID {
				return kubeca.DataKey{}, kubeca.ErrInvalid
			}
			return oldKey, nil
		},
	}
	steps, err := Prepare(read, decision, sealer, DefaultPolicy(), func(time.Duration) time.Duration { return 0 })
	if err != nil || len(steps) != 1 || steps[0].Create == nil || steps[0].Create.IssuerID != stored.ID || opened != 1 {
		t.Fatalf("Prepare() = %+v, %v, opened %d", steps, err, opened)
	}
	intermediate, err := x509.ParseCertificate(steps[0].Create.Certificate)
	if err != nil || intermediate.CheckSignatureFrom(rootCA.Certificate()) != nil {
		t.Fatalf("the intermediate is not signed by the stored root: %v", err)
	}
	if _, err := kubeca.OpenIntermediate(newKey, steps[0].Create.Certificate, steps[0].Create.SealedKey,
		installation, cluster.String(), steps[0].Create.ID.String(), rootCA.Certificate()); err != nil {
		t.Fatalf("the intermediate is not sealed under the active data key: %v", err)
	}
}

// A promoted successor root signs the new intermediate in the same plan:
// in the read Prepare works from it is still next (review a2 H-A).
func TestPreparePromotesTheNextRoot(t *testing.T) {
	t.Parallel()
	installation := "dep-1"
	dataKey, dataKeyID := kubeca.DataKey{5}, testID(t)
	read, cluster := newNetwork(t)
	sealed := func(ca kubeca.CA, stored kubeca.StoredCA) kubeca.StoredCA {
		stored.Certificate, stored.DataKeyID = ca.Certificate().Raw, dataKeyID
		var err error
		if stored.SealedKey, err = kubeca.SealCA(dataKey, ca, installation, cluster.String(),
			stored.ID.String()); err != nil {
			t.Fatal(err)
		}
		return stored
	}
	newRoot := func() kubeca.CA {
		ca, err := kubeca.NewRoot(kubeca.RootParams{
			ClusterDNSName: testName, Subject: "r", NotBefore: time.Now(),
			Lifetime: kubeca.DefaultRootLifetime,
		})
		if err != nil {
			t.Fatal(err)
		}
		return ca
	}
	endingCA, nextCA := newRoot(), newRoot()
	ending := sealed(endingCA, root(t, kubeca.StateActive, testName, -9*365*day, 300*day))
	next := sealed(nextCA, root(t, kubeca.StateNext, testName, -91*day, 10*365*day))
	inter := intermediate(t, kubeca.StateActive, ending, -5*day, 25*day)
	read.Clusters[0].CAs = []kubeca.StoredCA{ending, inter, next}
	decision := Decide(read, map[publicid.ID]string{cluster: testName}, DefaultPolicy())
	steps, err := Prepare(read, decision, Sealer{Installation: installation, DataKeyID: dataKeyID, DataKey: dataKey},
		DefaultPolicy(), func(time.Duration) time.Duration { return 0 })
	if err != nil || len(steps) != 4 || steps[3].Create == nil || steps[3].Create.IssuerID != next.ID {
		t.Fatalf("Prepare() = %+v, %v", steps, err)
	}
	certificate, err := x509.ParseCertificate(steps[3].Create.Certificate)
	if err != nil || certificate.CheckSignatureFrom(nextCA.Certificate()) != nil {
		t.Fatalf("the intermediate is not signed by the promoted root: %v", err)
	}
}

// A Network another worker holds is neither a change nor a failure, and
// counts nothing created (review a2 H-B).
func TestWorkerCountsABusyNetwork(t *testing.T) {
	t.Parallel()
	read, _ := newNetwork(t, kubeca.StoredDataKey{
		ID: testID(t), Version: 1, Active: true,
		Wrapped: kubeca.WrappedKey{Custody: "file", KeyID: "k1", Ciphertext: []byte("wrapped")},
	})
	store := &fakeStore{read: read, scope: testScope(t), matched: true, busy: true}
	worker := testWorker(t, store, func(context.Context) (kubeca.Custody, string, error) {
		return sealingCustody{dataKey: kubeca.DataKey{1}}, "file", nil
	})
	worker.Pass(t.Context())
	if snapshot := worker.Snapshot(); snapshot.Busy != 1 || snapshot.Changed != 0 || snapshot.Created != 0 ||
		snapshot.Failures != 0 || store.postponed != 0 {
		t.Fatalf("snapshot %+v, postponed %d", snapshot, store.postponed)
	}
}

// One cluster that cannot be kept does not hold back the others: the good
// one gets its CAs, the bad one is scheduled again alone (§17.3).
func TestWorkerKeepsClustersOneByOneAfterAFailure(t *testing.T) {
	t.Parallel()
	dataKey := kubeca.DataKey{1}
	read, good := newNetwork(t, kubeca.StoredDataKey{
		ID: testID(t), Version: 1, Active: true,
		Wrapped: kubeca.WrappedKey{Custody: "file", KeyID: "k1", Ciphertext: []byte("wrapped")},
	})
	// The bad cluster's root does not open: its intermediate cannot be made.
	broken := root(t, kubeca.StateActive, "bad.kube.123456789012.210987654321.mesh.internal", -day, 9*365*day)
	broken.Certificate, broken.DataKeyID = []byte("not a certificate"), read.DataKeys[0].ID
	bad := kubeca.Cluster{
		ID: testID(t), Name: "bad", Active: true, NextActionAt: read.Now,
		CAs: []kubeca.StoredCA{broken},
	}
	read.Clusters = append(read.Clusters, bad)
	store := &fakeStore{read: read, scope: testScope(t), matched: true}
	worker := testWorker(t, store, func(context.Context) (kubeca.Custody, string, error) {
		return sealingCustody{dataKey: dataKey}, "file", nil
	})
	worker.Pass(t.Context())
	if len(store.changes) != 2 {
		t.Fatalf("changes = %+v", store.changes)
	}
	kept, failed := store.changes[0], store.changes[1]
	if len(kept.Steps) != 2 || kept.Steps[0].Create.Cluster != good || len(kept.Schedules) != 1 ||
		kept.Schedules[0].Cluster != good {
		t.Fatalf("the good cluster = %+v", kept)
	}
	if len(failed.Steps) != 0 || len(failed.Schedules) != 1 || failed.Schedules[0].Cluster != bad.ID ||
		!failed.Schedules[0].Failed {
		t.Fatalf("the bad cluster = %+v", failed)
	}
	if snapshot := worker.Snapshot(); snapshot.Failures != 1 || store.postponed != 0 {
		t.Fatalf("snapshot %+v, postponed %d", snapshot, store.postponed)
	}
}

// regressingMarks reports the database below its marks.
type regressingMarks struct {
	regressed bool
	err       error
	compared  []kubeca.Guard
}

func (marks *regressingMarks) Compare(_ context.Context, _ deployment.ID, guard kubeca.Guard) (bool, error) {
	marks.compared = append(marks.compared, guard)
	return marks.regressed, marks.err
}

func TestWorkerStopsAfterARestore(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		suspected bool
		marks     *regressingMarks
		marked    int
		suspect   bool
		// stamped: signing may go on (a3 §14 R-M9).
		stamped bool
	}{
		"an operator marked the restore":        {suspected: true, suspect: true},
		"the marks show the database went back": {marks: &regressingMarks{regressed: true}, marked: 1, suspect: true},
		"the marks cannot be read":              {marks: &regressingMarks{err: errors.New("redis")}},
		"no restore":                            {marks: &regressingMarks{}, stamped: true},
		"no marks configured":                   {stamped: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := &fakeStore{scope: testScope(t), matched: true}
			store.guard = kubeca.Guard{Suspected: test.suspected, Generation: 1, ReadStarted: time.Now(), ReadFinished: time.Now()}
			worker := testWorker(t, store, func(context.Context) (kubeca.Custody, string, error) {
				return sealingCustody{}, "file", nil
			})
			if test.marks != nil {
				worker.options.Marks = test.marks
			}
			worker.Pass(t.Context())
			if snapshot := worker.Snapshot(); snapshot.RestoreSuspected != test.suspect ||
				len(store.marked) != test.marked || (store.listed == 0) != test.suspect {
				t.Fatalf("snapshot %+v, marked %v, listed %d", snapshot, store.marked, store.listed)
			}
			if (len(store.stamped) == 1 && store.stamped[0] == 1) != test.stamped {
				t.Fatalf("stamped %v", store.stamped)
			}
			if test.marked == 1 && (store.marked[0].IsWorker() || !store.marked[0].Valid()) {
				t.Fatalf("marked by %+v", store.marked[0])
			}
		})
	}
}
