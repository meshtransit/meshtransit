package renewal_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/deployment/entitlement"
	"meshtransit.net/core/internal/domain/deployment/entitlement/renewal"
)

const (
	deploymentText = "01890f00-0000-7000-8000-000000000001"
	otherText      = "01890f00-0000-7000-8000-000000000002"
	renewalKeyID   = "meshtransit-cloud-renew-test"
)

var start = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

type fixture struct {
	seed         [ed25519.SeedSize]byte
	installation *entitlement.Installation
	deploymentID deployment.ID
	verifier     *entitlement.Verifier
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	var seed, installSeed [ed25519.SeedSize]byte
	seed[0], seed[31], installSeed[0] = 1, 2, 3
	installation, err := entitlement.NewInstallation(installSeed)
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, err := deployment.ParseID(deploymentText)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	verifier, err := entitlement.NewScopedVerifier(map[string]entitlement.TrustedKey{
		renewalKeyID: {Public: public, Deployment: deploymentID, Profile: deployment.ProfileCloud},
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{seed, installation, deploymentID, verifier}
}

func (f fixture) signer(t *testing.T) *renewal.Signer {
	t.Helper()
	signer, err := renewal.NewSigner(renewalKeyID, f.seed, f.installation, f.deploymentID, f.verifier)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func current() renewal.Current {
	return renewal.Current{
		Generation: 4, Profile: deployment.ProfileCloud,
		Limits:       entitlement.Limits{MaxActiveWorkspaces: 50, MaxOwnedWorkspacesPerAccount: 5},
		Capabilities: []entitlement.Capability{entitlement.CapabilityCloudBilling},
		NotBefore:    start, ExpiresAt: start.Add(300 * 24 * time.Hour),
	}
}

func TestDueAfterTwoThirdsOfTheLife(t *testing.T) {
	t.Parallel()
	generation := current() // 300 days: due from day 200
	for name, test := range map[string]struct {
		at  time.Time
		due bool
	}{
		"fresh":                {start, false},
		"just before 2/3":      {start.Add(200*24*time.Hour - time.Second), false},
		"at 2/3":               {start.Add(200 * 24 * time.Hour), true},
		"in grace":             {start.Add(301 * 24 * time.Hour), true},
		"lapsed (old restore)": {start.Add(5 * 365 * 24 * time.Hour), true},
	} {
		if got := renewal.Due(generation, test.at); got != test.due {
			t.Errorf("%s: Due() = %v, want %v", name, got, test.due)
		}
	}
}

func TestNextSignsTheSameClaimsAsTheNextGeneration(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	now := start.Add(250*24*time.Hour + 500*time.Millisecond)
	next, err := f.signer(t).Next(current(), now)
	if err != nil {
		t.Fatal(err)
	}
	truncated := now.Truncate(time.Second)
	if next.Generation != 5 || next.DeploymentID != f.deploymentID || next.Profile != deployment.ProfileCloud ||
		next.Limits != current().Limits || !slices.Equal(next.Capabilities, current().Capabilities) ||
		!next.NotBefore.Equal(truncated.Add(-time.Minute)) || !next.ExpiresAt.Equal(truncated.Add(renewal.Lifetime)) ||
		next.Grace != renewal.Grace || next.KeyID != renewalKeyID || next.StateAt(now) != entitlement.StateActive {
		t.Fatalf("next = %+v", next)
	}
	again, err := f.signer(t).Next(current(), now)
	if err != nil || again.ID == next.ID {
		t.Fatalf("each renewal has its own entitlement ID: %v", err)
	}
	selfHosted := current()
	selfHosted.Profile = deployment.ProfileSelfHosted
	if _, err := f.signer(t).Next(selfHosted, now); !errors.Is(err, renewal.ErrNotRenewable) {
		t.Fatalf("Next(self_hosted) = %v", err)
	}
	// A clock behind the current generation's start signs nothing.
	if _, err := f.signer(t).Next(current(), start.Add(-time.Hour)); !errors.Is(err, renewal.ErrNotRenewable) {
		t.Fatalf("Next() before the current start = %v", err)
	}
}

func TestNewSignerAcceptsOnlyThisDeploymentsRenewalKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	other, err := deployment.ParseID(otherText)
	if err != nil {
		t.Fatal(err)
	}
	var wrongSeed [ed25519.SeedSize]byte
	wrongSeed[5] = 9
	offline, err := entitlement.NewVerifier(map[string]ed25519.PublicKey{
		renewalKeyID: ed25519.NewKeyFromSeed(f.seed[:]).Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, build := range map[string]func() error{
		"another Deployment": func() error {
			_, err := renewal.NewSigner(renewalKeyID, f.seed, f.installation, other, f.verifier)
			return err
		},
		"another key": func() error {
			_, err := renewal.NewSigner(renewalKeyID, wrongSeed, f.installation, f.deploymentID, f.verifier)
			return err
		},
		"an offline key": func() error {
			_, err := renewal.NewSigner(renewalKeyID, f.seed, f.installation, f.deploymentID, offline)
			return err
		},
	} {
		if err := build(); !errors.Is(err, renewal.ErrInvalidSigner) {
			t.Errorf("%s: NewSigner() = %v", name, err)
		}
	}
}

// fakeStore plays one transaction: it hands next the current generation
// with the database's clock and records what it returns.
type fakeStore struct {
	current  renewal.Current
	now      *time.Time
	busy     bool
	err      error
	recorded []entitlement.Entitlement
}

func (store *fakeStore) RenewDeploymentEntitlement(_ context.Context, _ deployment.ID,
	next renewal.NextFunc) (renewal.Outcome, error) {
	if store.err != nil {
		return "", store.err
	}
	if store.busy {
		return renewal.OutcomeBusy, nil
	}
	current := store.current
	if store.now != nil {
		current.DatabaseNow = *store.now
	}
	renewed, due, err := next(current)
	if err != nil {
		return "", err
	}
	if !due {
		return renewal.OutcomeNotDue, nil
	}
	store.recorded = append(store.recorded, renewed)
	store.current = renewal.Current{Generation: renewed.Generation, Profile: renewed.Profile, Limits: renewed.Limits,
		Capabilities: renewed.Capabilities, NotBefore: renewed.NotBefore, ExpiresAt: renewed.ExpiresAt}
	return renewal.OutcomeRenewed, nil
}

func newRenewer(t *testing.T, store renewal.Store) *renewal.Renewer {
	t.Helper()
	f := newFixture(t)
	renewer, err := renewal.New(renewal.DefaultOptions(f.deploymentID), store, f.signer(t),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return renewer
}

func TestAttemptRenewsOnceWhenDue(t *testing.T) {
	t.Parallel()
	now := start.Add(100 * 24 * time.Hour)
	store := &fakeStore{current: current(), now: &now}
	renewer := newRenewer(t, store)
	if outcome := renewer.Attempt(t.Context()); outcome != renewal.OutcomeNotDue || len(store.recorded) != 0 {
		t.Fatalf("not due: %s, %d recorded", outcome, len(store.recorded))
	}
	now = start.Add(250 * 24 * time.Hour)
	if outcome := renewer.Attempt(t.Context()); outcome != renewal.OutcomeRenewed || len(store.recorded) != 1 {
		t.Fatalf("due: %s, %d recorded", outcome, len(store.recorded))
	}
	// The renewed generation is fresh: the next hour renews nothing.
	now = now.Add(time.Hour)
	if outcome := renewer.Attempt(t.Context()); outcome != renewal.OutcomeNotDue || store.current.Generation != 5 {
		t.Fatalf("after renewal: %s, generation %d", outcome, store.current.Generation)
	}
	if measured := renewer.Snapshot(); measured.Attempts != 3 || measured.Renewed != 1 || measured.Failed != 0 {
		t.Fatalf("measurements = %+v", measured)
	}
}

func TestAttemptCountsFailuresAndLeavesBusyAlone(t *testing.T) {
	t.Parallel()
	now := start.Add(250 * 24 * time.Hour)
	failing := newRenewer(t, &fakeStore{err: errors.New("database down")})
	if outcome := failing.Attempt(t.Context()); outcome != "" || failing.Snapshot().Failed != 1 {
		t.Fatalf("failure: %q, %+v", outcome, failing.Snapshot())
	}
	busy := newRenewer(t, &fakeStore{busy: true, current: current(), now: &now})
	if outcome := busy.Attempt(t.Context()); outcome != renewal.OutcomeBusy || busy.Snapshot().Failed != 0 {
		t.Fatalf("busy: %q, %+v", outcome, busy.Snapshot())
	}
	// Without the database's clock nothing is signed.
	clockless := newRenewer(t, &fakeStore{current: current()})
	if outcome := clockless.Attempt(t.Context()); outcome != "" || clockless.Snapshot().Failed != 1 {
		t.Fatalf("no database clock: %q, %+v", outcome, clockless.Snapshot())
	}
}

func TestRenewerStartsAndStops(t *testing.T) {
	t.Parallel()
	now := start
	renewer := newRenewer(t, &fakeStore{current: current(), now: &now})
	if err := renewer.Shutdown(t.Context()); !errors.Is(err, renewal.ErrRenewerNotStarted) {
		t.Fatalf("Shutdown() before Start = %v", err)
	}
	if err := renewer.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := renewer.Start(t.Context()); !errors.Is(err, renewal.ErrRenewerStarted) {
		t.Fatalf("second Start() = %v", err)
	}
	if err := renewer.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-renewer.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("renewer did not stop")
	}
}
