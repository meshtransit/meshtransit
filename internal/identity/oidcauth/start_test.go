package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestStartServiceCommitsBeforeReturningRedirect(t *testing.T) {
	t.Parallel()
	fixture := newStartFixture(t)
	service := fixture.service(t)
	result, err := service.Start(t.Context(), fixture.params.Route)
	if err != nil || !result.IsValid() {
		t.Fatalf("Start() error = %v, want committed redirect", err)
	}
	if !slices.Equal(fixture.calls, []string{"opened", "metadata", "ids", "secrets", "begin", "create", "commit", "closed"}) {
		t.Fatalf("Start() effects = %v, want preparation then one commit", fixture.calls)
	}
	if result.Created().TransactionID() != fixture.params.TransactionID ||
		!result.AuthorizationRequest().IsValid() || fixture.outcome != StartOutcomeCommitted {
		t.Fatal("Start() lost exact committed creation evidence")
	}
	assertStartCookieBinding(t, fixture, result)
}

func TestNewStartServiceRejectsUnsafeConstruction(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*StartOptions, *StartDependencies)
	}{
		{name: "no request budget", mutate: func(o *StartOptions, _ *StartDependencies) { o.RequestTimeout = 0 }},
		{name: "excessive request budget", mutate: func(o *StartOptions, _ *StartDependencies) { o.RequestTimeout = 31 * time.Second }},
		{name: "short pending lifetime", mutate: func(o *StartOptions, _ *StartDependencies) { o.PendingLifetime = time.Second }},
		{name: "excessive pending lifetime", mutate: func(o *StartOptions, _ *StartDependencies) { o.PendingLifetime = 11 * time.Minute }},
		{name: "unbounded rollback", mutate: func(o *StartOptions, _ *StartDependencies) { o.RollbackTimeout = 0 }},
		{name: "excessive resolution", mutate: func(o *StartOptions, _ *StartDependencies) { o.ResolveTimeout = 6 * time.Second }},
		{name: "missing metadata", mutate: func(_ *StartOptions, d *StartDependencies) { d.Metadata = nil }},
		{name: "missing transactions", mutate: func(_ *StartOptions, d *StartDependencies) { d.Transactions = nil }},
		{name: "missing replay", mutate: func(_ *StartOptions, d *StartDependencies) { d.Committed = nil }},
		{name: "missing ids", mutate: func(_ *StartOptions, d *StartDependencies) { d.IDs = nil }},
		{name: "missing secrets", mutate: func(_ *StartOptions, d *StartDependencies) { d.Secrets = nil }},
		{name: "missing clock", mutate: func(_ *StartOptions, d *StartDependencies) { d.Clock = nil }},
		{name: "missing observer", mutate: func(_ *StartOptions, d *StartDependencies) { d.Observer = nil }},
		{name: "missing digest key", mutate: func(_ *StartOptions, d *StartDependencies) { d.DigestKey = DigestKey{} }},
		{name: "missing verifier cipher", mutate: func(_ *StartOptions, d *StartDependencies) { d.VerifierCipher = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newStartFixture(t)
			service := fixture.service(t)
			options, dependencies := service.options, service.dependencies
			test.mutate(&options, &dependencies)
			if _, err := NewStartService(options, dependencies); !errors.Is(err, ErrInvalidStartService) {
				t.Fatalf("NewStartService() error = %v, want invalid construction", err)
			}
			if len(fixture.calls) != 0 {
				t.Fatal("invalid construction performed effects")
			}
		})
	}
}

func TestStartServiceRejectsZeroServiceAndRoute(t *testing.T) {
	t.Parallel()
	for _, service := range []*StartService{nil, {}} {
		if _, err := service.Start(t.Context(), Route{}); !errors.Is(err, ErrInvalidStartService) {
			t.Fatal("zero service did not reject")
		}
	}
	fixture := newStartFixture(t)
	service := fixture.service(t)
	// The zero context interface deliberately exercises invalid caller input;
	// this rejection performs no I/O or context operation.
	var absentContext context.Context
	if _, err := service.Start(absentContext, fixture.params.Route); !errors.Is(err, ErrInvalidStartService) {
		t.Fatal("nil context did not reject")
	}
	if _, err := service.Start(t.Context(), Route{}); !errors.Is(err, ErrInvalidRoute) {
		t.Fatal("zero route did not reject")
	}
	if !slices.Equal(fixture.calls, []string{"opened", "closed"}) {
		t.Fatal("invalid route performed effects")
	}
}

type startFixture struct {
	params         PendingParams
	calls          []string
	outcome        StartOutcome
	metadataErr    error
	idsErr         error
	secretsErr     error
	beginErr       error
	createErr      error
	commitErr      error
	rollbackErr    error
	resolveErr     error
	replayFound    bool
	wrongCreated   string
	wrongReplay    string
	nilTransaction bool
	now            time.Time
	pending        Pending
	hook           func(context.Context, string)
}

func newStartFixture(t *testing.T) *startFixture {
	t.Helper()
	params := pendingParamsFixture(t)
	return &startFixture{params: params, calls: []string{}, now: params.CreatedAt}
}

func (fixture *startFixture) service(t *testing.T) *StartService {
	t.Helper()
	service, err := NewStartService(StartOptions{
		RequestTimeout: 10 * time.Second, PendingLifetime: 5 * time.Minute,
		RollbackTimeout: time.Second, ResolveTimeout: time.Second,
	}, StartDependencies{
		Metadata: fixture, Transactions: fixture, Committed: fixture,
		IDs: fixture, Secrets: fixture, Clock: fixture, Observer: fixture,
		DigestKey: fixture.params.DigestKey, VerifierCipher: fixture.params.VerifierCipher,
	})
	if err != nil {
		t.Fatalf("NewStartService() error = %v", err)
	}
	return service
}

func (fixture *startFixture) Resolve(ctx context.Context, _ Route) (Metadata, error) {
	fixture.calls = append(fixture.calls, "metadata")
	fixture.callHook(ctx, "metadata")
	return fixture.params.Metadata, fixture.metadataErr
}

func (fixture *startFixture) NewStartIDs() (TransactionID, MutationIDs, error) {
	fixture.calls = append(fixture.calls, "ids")
	return fixture.params.TransactionID, fixture.params.MutationIDs, fixture.idsErr
}

func (fixture *startFixture) NewSecrets() (Secrets, error) {
	fixture.calls = append(fixture.calls, "secrets")
	return fixture.params.Secrets, fixture.secretsErr
}

func (fixture *startFixture) Now() time.Time { return fixture.now }

func (fixture *startFixture) Begin(ctx context.Context, _ Route) (Transaction, error) {
	fixture.calls = append(fixture.calls, "begin")
	fixture.callHook(ctx, "begin")
	if fixture.nilTransaction {
		return nil, fixture.beginErr
	}
	return fixture, fixture.beginErr
}

func (fixture *startFixture) Create(ctx context.Context, pending Pending) (Created, error) {
	fixture.calls = append(fixture.calls, "create")
	fixture.pending = pending
	fixture.callHook(ctx, "create")
	if fixture.createErr != nil {
		return Created{}, fixture.createErr
	}
	return fixture.created(pending, fixture.wrongCreated)
}

func (fixture *startFixture) Commit(ctx context.Context) error {
	fixture.calls = append(fixture.calls, "commit")
	fixture.callHook(ctx, "commit")
	return fixture.commitErr
}

func (fixture *startFixture) Rollback(ctx context.Context) error {
	fixture.calls = append(fixture.calls, "rollback")
	fixture.callHook(ctx, "rollback")
	return fixture.rollbackErr
}

func (fixture *startFixture) ResolveCommitted(ctx context.Context, pending Pending) (Created, bool, error) {
	fixture.calls = append(fixture.calls, "resolve")
	fixture.callHook(ctx, "resolve")
	if pending.SemanticHash() != fixture.pending.SemanticHash() ||
		pending.MutationIDs() != fixture.pending.MutationIDs() ||
		pending.TransactionID() != fixture.pending.TransactionID() {
		return Created{}, false, errors.New("replay changed original pending evidence")
	}
	created, err := fixture.created(pending, fixture.wrongReplay)
	return created, fixture.replayFound, errors.Join(err, fixture.resolveErr)
}

func (fixture *startFixture) StartOpened() { fixture.calls = append(fixture.calls, "opened") }

func (fixture *startFixture) StartClosed(outcome StartOutcome, _ time.Duration) {
	fixture.calls = append(fixture.calls, "closed")
	fixture.outcome = outcome
}

func (fixture *startFixture) callHook(ctx context.Context, stage string) {
	if fixture.hook != nil {
		fixture.hook(ctx, stage)
	}
}

func (fixture *startFixture) created(pending Pending, substitution string) (Created, error) {
	transactionID := pending.TransactionID()
	createdAt, expiresAt := pending.CreatedAt(), pending.ExpiresAt()
	switch substitution {
	case "id":
		transactionID = TransactionID(fixture.params.MutationIDs.ChangeID())
	case "creation time":
		createdAt = createdAt.Add(time.Second)
	case "expiry":
		expiresAt = expiresAt.Add(time.Second)
	case "zero":
		return Created{}, nil
	}
	return NewCreated(transactionID, 1, createdAt, expiresAt)
}

func TestStartServiceRejectsPreparationAndCreationFailures(t *testing.T) {
	t.Parallel()
	failure := errors.New("synthetic dependency failure")
	for _, test := range []struct {
		name        string
		mutate      func(*startFixture)
		wantErr     error
		wantEffects []string
	}{
		{name: "discovery unavailable", mutate: func(f *startFixture) { f.metadataErr = failure }, wantErr: failure, wantEffects: []string{"metadata"}},
		{name: "wrong discovery issuer", mutate: func(f *startFixture) { f.params.Metadata.issuer = "https://other.example.test" }, wantErr: ErrProviderMismatch, wantEffects: []string{"metadata", "ids", "secrets"}},
		{name: "id generation unavailable", mutate: func(f *startFixture) { f.idsErr = failure }, wantErr: failure, wantEffects: []string{"metadata", "ids"}},
		{name: "secret generation unavailable", mutate: func(f *startFixture) { f.secretsErr = failure }, wantErr: failure, wantEffects: []string{"metadata", "ids", "secrets"}},
		{name: "invalid generated ids", mutate: func(f *startFixture) { f.params.TransactionID = TransactionID{} }, wantErr: ErrInvalidPending, wantEffects: []string{"metadata", "ids", "secrets"}},
		{name: "invalid generated secrets", mutate: func(f *startFixture) { f.params.Secrets = Secrets{} }, wantErr: ErrInvalidPending, wantEffects: []string{"metadata", "ids", "secrets"}},
		{name: "missing independent cookie", mutate: func(f *startFixture) { f.params.Secrets.preAuthCookie = PreAuthCookie{} }, wantErr: ErrInvalidPending, wantEffects: []string{"metadata", "ids", "secrets"}},
		{name: "cookie reused state", mutate: func(f *startFixture) { f.params.Secrets.preAuthCookie.value = f.params.Secrets.state.value }, wantErr: ErrInvalidPending, wantEffects: []string{"metadata", "ids", "secrets"}},
		{name: "zero preparation clock", mutate: func(f *startFixture) { f.now = time.Time{} }, wantErr: ErrInvalidPending, wantEffects: []string{"metadata", "ids", "secrets"}},
		{name: "begin unavailable", mutate: func(f *startFixture) { f.beginErr = failure; f.nilTransaction = true }, wantErr: failure, wantEffects: []string{"metadata", "ids", "secrets", "begin"}},
		{name: "partially opened begin fails", mutate: func(f *startFixture) { f.beginErr = failure }, wantErr: failure, wantEffects: []string{"metadata", "ids", "secrets", "begin", "rollback"}},
		{name: "nil transaction", mutate: func(f *startFixture) { f.nilTransaction = true }, wantErr: ErrInvalidStartService, wantEffects: []string{"metadata", "ids", "secrets", "begin"}},
		{name: "creation failure", mutate: func(f *startFixture) { f.createErr = failure }, wantErr: failure, wantEffects: []string{"metadata", "ids", "secrets", "begin", "create", "rollback"}},
		{name: "known commit failure", mutate: func(f *startFixture) { f.commitErr = failure }, wantErr: failure, wantEffects: []string{"metadata", "ids", "secrets", "begin", "create", "commit", "rollback"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newStartFixture(t)
			test.mutate(fixture)
			result, err := fixture.service(t).Start(t.Context(), fixture.params.Route)
			if !errors.Is(err, ErrStartFailed) || !errors.Is(err, test.wantErr) || result.IsValid() ||
				result.AuthorizationRequest().Location() != "" || result.PreAuthCookie().IsValid() {
				t.Fatalf("Start() error = %v, want failure without redirect", err)
			}
			want := append([]string{"opened"}, test.wantEffects...)
			want = append(want, "closed")
			if !slices.Equal(fixture.calls, want) {
				t.Fatalf("effects = %v, want %v", fixture.calls, want)
			}
		})
	}
}

func TestStartServiceRejectsSubstitutedDurableEvidence(t *testing.T) {
	t.Parallel()
	for _, substitution := range []string{"id", "creation time", "expiry", "zero"} {
		t.Run(substitution, func(t *testing.T) {
			t.Parallel()
			fixture := newStartFixture(t)
			fixture.wrongCreated = substitution
			result, err := fixture.service(t).Start(t.Context(), fixture.params.Route)
			if !errors.Is(err, ErrInvalidCreated) || result.IsValid() || slices.Contains(fixture.calls, "commit") ||
				!slices.Contains(fixture.calls, "rollback") || fixture.outcome != StartOutcomeRejected {
				t.Fatalf("Start() error = %v, want rollback before commit", err)
			}
		})
	}
}

func TestStartServiceSettlesUnknownCommitOnceWithoutAnotherCreation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		found       bool
		resolveErr  error
		wrongReplay string
		rollbackErr error
		wantSuccess bool
		wantOutcome StartOutcome
	}{
		{name: "exact durable result", found: true, wantSuccess: true, wantOutcome: StartOutcomeCommitted},
		{name: "absent result", wantOutcome: StartOutcomeUncertain},
		{name: "lookup fails after scan", found: true, resolveErr: errors.New("synthetic replay failure"), wantOutcome: StartOutcomeUncertain},
		{name: "wrong result id", found: true, wrongReplay: "id", wantOutcome: StartOutcomeUncertain},
		{name: "wrong result expiry", found: true, wrongReplay: "expiry", wantOutcome: StartOutcomeUncertain},
		{name: "cleanup fails", found: true, rollbackErr: errors.New("synthetic cleanup failure"), wantOutcome: StartOutcomeCleanupFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newStartFixture(t)
			fixture.commitErr = ErrCommitOutcomeUnknown
			fixture.replayFound, fixture.resolveErr = test.found, test.resolveErr
			fixture.wrongReplay, fixture.rollbackErr = test.wrongReplay, test.rollbackErr
			result, err := fixture.service(t).Start(t.Context(), fixture.params.Route)
			if test.wantSuccess {
				if err != nil || !result.IsValid() {
					t.Fatalf("Start() error = %v, want confirmed result", err)
				}
				assertStartCookieBinding(t, fixture, result)
			} else if !errors.Is(err, ErrCommitOutcomeUnknown) || result.IsValid() || result.PreAuthCookie().IsValid() {
				t.Fatalf("Start() error = %v, want unknown without redirect", err)
			}
			want := []string{"opened", "metadata", "ids", "secrets", "begin", "create", "commit", "rollback", "resolve", "closed"}
			if !slices.Equal(fixture.calls, want) || fixture.outcome != test.wantOutcome {
				t.Fatalf("Start() effects = %v outcome=%s", fixture.calls, fixture.outcome)
			}
		})
	}
}

func assertStartCookieBinding(t *testing.T, fixture *startFixture, result StartResult) {
	t.Helper()
	binding, err := fixture.pending.Route().Binding(fixture.pending.TransactionID())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := fixture.params.VerifierCipher.OpenBrowser(binding, fixture.pending.VerifierCiphertext())
	if err != nil || !fixture.params.DigestKey.VerifyPreAuthCookie(binding, result.PreAuthCookie(), proof.CookieDigest()) ||
		result.PreAuthCookie().Encoded() != fixture.params.Secrets.PreAuthCookie().Encoded() {
		t.Fatal("start did not release the exact durably prepared cookie binding")
	}
	if strings.Contains(result.AuthorizationRequest().Location(), result.PreAuthCookie().Encoded()) {
		t.Fatal("authorization URL disclosed independent cookie")
	}
}

func TestStartServiceCleanupPreservesOriginalFailureAfterCancellation(t *testing.T) {
	t.Parallel()
	fixture := newStartFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fixture.createErr = errors.New("synthetic creation failure")
	fixture.rollbackErr = errors.New("synthetic cleanup failure")
	fixture.hook = func(cleanupCtx context.Context, stage string) {
		if stage == "create" {
			cancel()
		}
		if stage == "rollback" {
			if cleanupCtx.Err() != nil {
				t.Fatal("cleanup inherited canceled request")
			}
			if _, ok := cleanupCtx.Deadline(); !ok {
				t.Fatal("cleanup lacks deadline")
			}
		}
	}
	result, err := fixture.service(t).Start(ctx, fixture.params.Route)
	if !errors.Is(err, fixture.createErr) || !errors.Is(err, fixture.rollbackErr) ||
		!errors.Is(err, ErrStartRollbackFailed) || result.IsValid() {
		t.Fatalf("Start() error = %v, want original and cleanup failures", err)
	}
}

func TestStartServiceCancellationNeverReleasesRedirect(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"before", "metadata", "begin", "create", "commit", "unknown commit"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			fixture := newStartFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if stage == "before" {
				cancel()
			}
			if stage == "unknown commit" {
				fixture.commitErr = ErrCommitOutcomeUnknown
				fixture.replayFound = true
			}
			fixture.hook = func(effectCtx context.Context, effect string) {
				if effect == stage || (effect == "commit" && stage == "unknown commit") {
					cancel()
				}
				if effect == "resolve" && effectCtx.Err() != nil {
					t.Fatal("commit settlement inherited cancellation")
				}
			}
			result, err := fixture.service(t).Start(ctx, fixture.params.Route)
			if !errors.Is(err, context.Canceled) || result.IsValid() || result.AuthorizationRequest().Location() != "" {
				t.Fatalf("Start() error = %v, want cancellation without redirect", err)
			}
			if stage == "before" && !slices.Equal(fixture.calls, []string{"opened", "closed"}) {
				t.Fatal("canceled call performed effects")
			}
			if stage == "create" && slices.Contains(fixture.calls, "commit") {
				t.Fatal("canceled creation proceeded to commit")
			}
		})
	}
}

func TestStartServiceRequestBudgetCancelsDiscoveryBeforeBegin(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		fixture := newStartFixture(t)
		fixture.hook = func(ctx context.Context, stage string) {
			if stage == "metadata" {
				<-ctx.Done()
			}
		}
		result, err := fixture.service(t).Start(t.Context(), fixture.params.Route)
		if !errors.Is(err, context.DeadlineExceeded) || result.IsValid() || slices.Contains(fixture.calls, "begin") {
			t.Fatalf("Start() error = %v, want bounded discovery without database unit", err)
		}
	})
}

func TestStartServiceRejectsExpiredAndBackwardReleaseTime(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"expiry", "backward", "zero"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			fixture := newStartFixture(t)
			fixture.hook = func(_ context.Context, effect string) {
				if effect != "commit" {
					return
				}
				switch stage {
				case "expiry":
					fixture.now = fixture.params.ExpiresAt
				case "backward":
					fixture.now = fixture.params.CreatedAt.Add(-time.Second)
				case "zero":
					fixture.now = time.Time{}
				}
			}
			result, err := fixture.service(t).Start(t.Context(), fixture.params.Route)
			if !errors.Is(err, ErrStartExpired) || result.IsValid() {
				t.Fatalf("Start() error = %v, want no stale redirect", err)
			}
		})
	}
}

func TestStartResultRedactsFormatting(t *testing.T) {
	t.Parallel()
	fixture := newStartFixture(t)
	result, err := fixture.service(t).Start(t.Context(), fixture.params.Route)
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{fmt.Sprint(result), fmt.Sprintf("%#v", result), result.LogValue().String()} {
		if !strings.Contains(formatted, "REDACTED") || strings.Contains(formatted, "https://") ||
			strings.Contains(formatted, fixture.params.Secrets.State().Encoded()) {
			t.Fatal("start result leaked browser authorization")
		}
	}
}

func TestStartServiceCleanupAndResolutionBudgetsRejectLateDependencySuccess(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"rollback", "resolve"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				fixture := newStartFixture(t)
				if stage == "rollback" {
					fixture.createErr = errors.New("synthetic creation failure")
				} else {
					fixture.commitErr = ErrCommitOutcomeUnknown
					fixture.replayFound = true
				}
				fixture.hook = func(ctx context.Context, effect string) {
					if effect == stage {
						<-ctx.Done()
					}
				}
				result, err := fixture.service(t).Start(t.Context(), fixture.params.Route)
				if !errors.Is(err, context.DeadlineExceeded) || result.IsValid() {
					t.Fatalf("Start() error = %v, want expired budget without redirect", err)
				}
				if stage == "rollback" && !errors.Is(err, ErrStartRollbackFailed) {
					t.Fatal("cleanup deadline not classified")
				}
				if stage == "resolve" && !errors.Is(err, ErrCommitOutcomeUnknown) {
					t.Fatal("late lookup lost unknown outcome")
				}
			})
		})
	}
}
