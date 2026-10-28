package signing

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/publicid"
)

// fakeStore hands out one batch and records what the worker did with it.
type fakeStore struct {
	mu         sync.Mutex
	batch      Batch
	claimErr   error
	issueAs    Outcome
	issued     []Issue
	refused    []Reason
	released   []publicid.ID
	beats      []bool
	pruned     int
	claimCalls int
	recorded   []VerifiedToken
	recordAs   Outcome
	recordErr  error
}

func (store *fakeStore) RecordToken(_ context.Context, _ deployment.ID, _ publicid.ID, _ ClaimToken,
	verified VerifiedToken,
) (Outcome, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.recorded = append(store.recorded, verified)
	if store.recordErr != nil {
		return "", store.recordErr
	}
	if store.recordAs == "" {
		return OutcomeRecorded, nil
	}
	return store.recordAs, nil
}

func (store *fakeStore) Claim(context.Context, deployment.ID, int, time.Duration) (Batch, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.claimCalls++
	batch := store.batch
	store.batch = Batch{Now: batch.Now, Suffix: batch.Suffix}
	return batch, store.claimErr
}

func (store *fakeStore) Issue(_ context.Context, _ deployment.ID, issue Issue) (Outcome, Reason, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.issued = append(store.issued, issue)
	if store.issueAs == "" {
		return OutcomeIssued, "", nil
	}
	return store.issueAs, "", nil
}

func (store *fakeStore) Refuse(_ context.Context, _ deployment.ID, _ publicid.ID, _ ClaimToken, reason Reason) (Outcome, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.refused = append(store.refused, reason)
	return OutcomeRefused, nil
}

func (store *fakeStore) Release(_ context.Context, _ deployment.ID, request publicid.ID, _ ClaimToken) (Outcome, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.released = append(store.released, request)
	return OutcomeReleased, nil
}

func (store *fakeStore) Prune(context.Context, deployment.ID, int) (int, int, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.pruned++
	return 0, 0, nil
}

func (store *fakeStore) Beat(_ context.Context, _ deployment.ID, _ publicid.ID, ready bool, _, _ string,
	capabilities []string,
) (time.Time, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(capabilities) != 1 || capabilities[0] != Capability {
		return time.Time{}, errors.New("capabilities")
	}
	store.beats = append(store.beats, ready)
	return time.Now().Add(90 * time.Second), nil
}

func testSigningWorker(t *testing.T, fixture signFixture, store *fakeStore, custody kubeca.Custody) *Worker {
	t.Helper()
	suffix, err := dnsname.ParseSuffix(testSuffix)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := New(Options{
		DeploymentID: fixture.installation, Suffix: suffix, Version: "test", BatchSize: 8,
		OperationTimeout: 5 * time.Second, MaximumPerSecond: 100,
	}, store, func(context.Context) (kubeca.Custody, string, error) {
		if custody == nil {
			return nil, "", kubeca.ErrUnavailable
		}
		return custody, "file", nil
	}, fixture.signer(t, true).verifyToken, fixture.signer(t, true).verifyRenewal,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func TestWorkerIssuesAndRefuses(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	refused := fixture.claim
	refused.ID, refused.Token = mustID(t), "forged"
	store := &fakeStore{batch: Batch{
		Now: fixture.now, Suffix: testSuffix, Pending: 3,
		Claims: []Claim{fixture.claim, refused},
	}}
	worker := testSigningWorker(t, fixture, store, fixture.custody)
	if handled := worker.Pass(t.Context()); handled != 2 {
		t.Fatalf("Pass() handled %d", handled)
	}
	snapshot := worker.Snapshot()
	if len(store.issued) != 1 || store.issued[0].Request != fixture.claim.ID || len(store.refused) != 1 ||
		store.refused[0] != ReasonToken || snapshot.Issued != 1 || snapshot.Refused[ReasonToken] != 1 ||
		snapshot.Pending != 3 || !snapshot.CustodyReady || len(store.beats) != 1 || !store.beats[0] ||
		store.pruned != 1 {
		t.Fatalf("store %+v, snapshot %+v", store, snapshot)
	}
}

func TestWorkerStopsWhileARestoreIsSuspected(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	store := &fakeStore{batch: Batch{Now: fixture.now, Suspected: true}}
	worker := testSigningWorker(t, fixture, store, fixture.custody)
	worker.Pass(t.Context())
	if !worker.Snapshot().Suspected || len(store.issued) != 0 {
		t.Fatalf("snapshot %+v", worker.Snapshot())
	}
	// The next heartbeat says it cannot sign.
	worker.lastBeat = time.Time{}
	worker.Pass(t.Context())
	if len(store.beats) != 2 || store.beats[1] {
		t.Fatalf("beats = %v", store.beats)
	}
}

func TestWorkerGivesBackWhatItCannotSign(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	// Another installation's suffix: nothing is signed.
	store := &fakeStore{batch: Batch{Now: fixture.now, Suffix: "other.internal", Claims: []Claim{fixture.claim}}}
	worker := testSigningWorker(t, fixture, store, fixture.custody)
	worker.Pass(t.Context())
	if len(store.released) != 1 || len(store.issued) != 0 || !worker.Snapshot().SuffixMismatch {
		t.Fatalf("store %+v", store)
	}
	// Custody trouble: the claim goes back.
	fixture = newSignFixture(t)
	failing := fixture.custody
	failing.fail = kubeca.ErrUnavailable
	store = &fakeStore{batch: Batch{Now: fixture.now, Suffix: testSuffix, Claims: []Claim{fixture.claim}}}
	worker = testSigningWorker(t, fixture, store, failing)
	worker.Pass(t.Context())
	if len(store.released) != 1 || worker.Snapshot().Failures != 1 {
		t.Fatalf("store %+v, snapshot %+v", store, worker.Snapshot())
	}
	// No custody: nothing is claimed.
	store = &fakeStore{batch: Batch{Now: fixture.now, Suffix: testSuffix, Claims: []Claim{fixture.claim}}}
	worker = testSigningWorker(t, fixture, store, nil)
	worker.Pass(t.Context())
	if store.claimCalls != 0 || len(store.beats) != 1 || store.beats[0] {
		t.Fatalf("store %+v", store)
	}
}

func TestWorkerForgetsACAThatChanged(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	store := &fakeStore{
		issueAs: OutcomeRequeued,
		batch:   Batch{Now: fixture.now, Suffix: testSuffix, Claims: []Claim{fixture.claim}},
	}
	worker := testSigningWorker(t, fixture, store, fixture.custody)
	worker.Pass(t.Context())
	if len(worker.signer.cache) != 0 || worker.Snapshot().Requeued != 1 {
		t.Fatalf("cache %d, snapshot %+v", len(worker.signer.cache), worker.Snapshot())
	}
}

func TestWorkerLifecycle(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	store := &fakeStore{batch: Batch{Now: fixture.now, Suffix: testSuffix}}
	worker := testSigningWorker(t, fixture, store, fixture.custody)
	if err := worker.Shutdown(t.Context()); !errors.Is(err, ErrWorkerNotStarted) {
		t.Fatalf("Shutdown() before Start = %v", err)
	}
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(t.Context()); !errors.Is(err, ErrWorkerStarted) {
		t.Fatalf("Start() twice = %v", err)
	}
	if err := worker.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-worker.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the worker did not stop")
	}
	if _, err := New(Options{}, store, nil, nil, nil, nil); !errors.Is(err, ErrInvalidWorker) {
		t.Fatalf("New(invalid) = %v", err)
	}
}

// A CA that does not open refuses its requests and is not opened again for
// a minute; custody trouble or another suffix makes the worker wait instead
// of claiming the same requests again at once (review a3a H1).
func TestWorkerDoesNotSpinOnWhatItCannotSign(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	broken := fixture.claim
	intermediate := *broken.Intermediate
	intermediate.SealedKey = append([]byte(nil), intermediate.SealedKey...)
	intermediate.SealedKey[len(intermediate.SealedKey)-1] ^= 1
	broken.Intermediate = &intermediate
	second := broken
	second.ID = mustID(t)
	store := &fakeStore{batch: Batch{Now: fixture.now, Suffix: testSuffix, Claims: []Claim{broken, second}}}
	worker := testSigningWorker(t, fixture, store, fixture.custody)
	if settled := worker.Pass(t.Context()); settled != 2 || len(store.refused) != 2 ||
		store.refused[0] != ReasonNoCA || store.refused[1] != ReasonNoCA || *fixture.opened != 1 {
		t.Fatalf("settled %d, refused %v, opened %d", settled, store.refused, *fixture.opened)
	}

	failing := fixture.custody
	failing.fail = kubeca.ErrUnavailable
	store = &fakeStore{batch: Batch{Now: fixture.now, Suffix: testSuffix, Claims: []Claim{fixture.claim, second}}}
	worker = testSigningWorker(t, fixture, store, failing)
	if settled := worker.Pass(t.Context()); settled != 0 || len(store.released) != 2 {
		t.Fatalf("settled %d, released %v", settled, store.released)
	}
	store.batch = Batch{Now: fixture.now, Suffix: testSuffix, Claims: []Claim{fixture.claim}}
	worker.Pass(t.Context())
	if store.claimCalls != 1 {
		t.Fatalf("claimed %d times while backing off", store.claimCalls)
	}
	// Not ready while it backs off, told at once.
	if len(store.beats) != 1 || store.beats[0] {
		t.Fatalf("beats = %v", store.beats)
	}

	store = &fakeStore{batch: Batch{Now: fixture.now, Suffix: "other.internal", Claims: []Claim{fixture.claim}}}
	worker = testSigningWorker(t, fixture, store, fixture.custody)
	if settled := worker.Pass(t.Context()); settled != 0 {
		t.Fatalf("settled %d under another suffix", settled)
	}
	worker.Pass(t.Context())
	if store.claimCalls != 1 {
		t.Fatalf("claimed %d times under another suffix", store.claimCalls)
	}
}

// Refusals the claim itself made after three leases are counted.
func TestWorkerCountsRefusedAttempts(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	store := &fakeStore{batch: Batch{Now: fixture.now, Suffix: testSuffix, RefusedAttempts: 2}}
	worker := testSigningWorker(t, fixture, store, fixture.custody)
	worker.Pass(t.Context())
	if refused := worker.Snapshot().Refused[ReasonAttempts]; refused != 2 {
		t.Fatalf("refused attempts = %d", refused)
	}
}

func TestWorkerRecordsTheTokenBeforeSigning(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	store := &fakeStore{batch: Batch{Now: fixture.now, Suffix: testSuffix, Claims: []Claim{fixture.claim}}}
	worker := testSigningWorker(t, fixture, store, fixture.custody)
	worker.Pass(t.Context())
	// The token is checked once and its claims replace it; the issue
	// carries those claims (§14 R-M1).
	if len(store.recorded) != 1 || store.recorded[0].Use.JTI != "jti-1" || store.recorded[0].TrustVersion != 1 ||
		len(store.issued) != 1 || store.issued[0].Token == nil || *store.issued[0].Token != store.recorded[0].Use {
		t.Fatalf("recorded %+v, issued %+v", store.recorded, store.issued)
	}
	// A claim whose token a worker checked before is not checked again.
	claim := fixture.claim
	claim.Verified, claim.Token = &store.recorded[0], ""
	store.batch = Batch{Now: fixture.now, Suffix: testSuffix, Claims: []Claim{claim}}
	worker.Pass(t.Context())
	if len(store.recorded) != 1 || len(store.issued) != 2 {
		t.Fatalf("recorded %d, issued %d", len(store.recorded), len(store.issued))
	}
	// A claim lost before its token was recorded is not signed.
	store.recordAs = OutcomeLost
	store.batch = Batch{Now: fixture.now, Suffix: testSuffix, Claims: []Claim{fixture.claim}}
	worker.Pass(t.Context())
	if len(store.issued) != 2 || worker.Snapshot().Lost != 1 {
		t.Fatalf("issued %d, snapshot %+v", len(store.issued), worker.Snapshot())
	}
}

func TestWorkerRefusesAClaimThatPanics(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	other := fixture.claim
	other.ID = mustID(t)
	store := &fakeStore{batch: Batch{Now: fixture.now, Suffix: testSuffix, Claims: []Claim{fixture.claim, other}}}
	worker := testSigningWorker(t, fixture, store, fixture.custody)
	calls := 0
	worker.signer.verifyToken = func(string, Trust, time.Time) (TokenUse, error) {
		calls++
		if calls == 1 {
			panic("malformed")
		}
		return TokenUse{JTI: "jti-2", ExpiresAt: fixture.now.Add(10 * time.Minute), PodName: "gateway-0"}, nil
	}
	// Only the claim that panicked is refused; the next one is signed
	// (§14 R-L4).
	if handled := worker.Pass(t.Context()); handled != 2 {
		t.Fatalf("Pass() handled %d", handled)
	}
	if len(store.refused) != 1 || store.refused[0] != ReasonInternal || len(store.issued) != 1 ||
		store.issued[0].Request != other.ID {
		t.Fatalf("refused %v, issued %+v", store.refused, store.issued)
	}
}

func TestWorkerWaitsForTheTripwire(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	store := &fakeStore{batch: Batch{Now: fixture.now, Unchecked: true}}
	worker := testSigningWorker(t, fixture, store, fixture.custody)
	worker.Pass(t.Context())
	// Nothing is signed and the worker says it cannot sign (§14 R-M9).
	if !worker.Snapshot().Unchecked || len(store.issued) != 0 || len(store.beats) != 1 || store.beats[0] {
		t.Fatalf("snapshot %+v, beats %v", worker.Snapshot(), store.beats)
	}
}

// A record that failed gives the claim back and counts no progress
// (review a3b Go M6).
func TestWorkerReleasesAClaimWhoseTokenWasNotRecorded(t *testing.T) {
	t.Parallel()
	fixture := newSignFixture(t)
	store := &fakeStore{
		batch:     Batch{Now: fixture.now, Suffix: testSuffix, Claims: []Claim{fixture.claim}},
		recordErr: errors.New("database"),
	}
	worker := testSigningWorker(t, fixture, store, fixture.custody)
	if handled := worker.Pass(t.Context()); handled != 0 {
		t.Fatalf("Pass() handled %d", handled)
	}
	if len(store.released) != 1 || len(store.issued) != 0 || len(store.refused) != 0 {
		t.Fatalf("released %d, issued %d, refused %v", len(store.released), len(store.issued), store.refused)
	}
}

// A token whose jti or pod name the ledger cannot keep is refused at once.
func TestCheckTokenRefusesWhatTheLedgerCannotKeep(t *testing.T) {
	t.Parallel()
	for name, use := range map[string]TokenUse{
		"a jti with a space": {JTI: "a b", PodName: "gateway-0"},
		"a long jti":         {JTI: strings.Repeat("j", 129), PodName: "gateway-0"},
		"an upper-case pod":  {JTI: "jti", PodName: "Gateway-0"},
	} {
		fixture := newSignFixture(t)
		signer := fixture.signer(t, true)
		signer.verifyToken = func(string, Trust, time.Time) (TokenUse, error) {
			use.ExpiresAt = fixture.now.Add(time.Minute)
			return use, nil
		}
		claim := fixture.claim
		trust := *claim.Trust
		trust.PodName = use.PodName
		claim.Trust = &trust
		if _, reason := signer.checkToken(claim, fixture.now); reason != ReasonToken {
			t.Errorf("%s: %q", name, reason)
		}
	}
}
