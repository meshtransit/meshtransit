package oidcauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/goleak"
)

func TestCallbackCommandRejectsAmbiguousOrAbsentInput(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"zero", "unknown kind", "code with provider error", "absent code", "oversized code"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pending := pendingParamsFixture(t)
			code, err := ParseCode("synthetic-callback-code")
			if err != nil {
				t.Fatal(err)
			}
			params := CallbackCommandParams{
				Route: pending.Route, State: pending.Secrets.State(),
				PreAuthCookie: pending.Secrets.PreAuthCookie(), Code: code, Kind: CallbackCodeReceived,
			}
			switch name {
			case "zero":
				params = CallbackCommandParams{}
			case "unknown kind":
				params.Kind = CallbackKindUnknown
			case "code with provider error":
				params.Kind = CallbackProviderErrorReceived
			case "absent code":
				params.Code = Code{}
			case "oversized code":
				params.Code = Code{value: strings.Repeat("x", 2049)}
			}
			command, err := NewCallbackCommand(params)
			if !errors.Is(err, ErrInvalidCallback) || command.IsValid() {
				t.Fatal("ambiguous callback syntax accepted")
			}
		})
	}
}

func TestCallbackWorkAndCleanupDeadlinesAreFinite(t *testing.T) {
	// Process-wide leak inventory runs serially on the real clock. Each bubble
	// still owns and joins all callback work before this outer check runs.
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, name := range []string{"application deadline", "failure deadline", "rollback deadline"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fixture := newCallbackFixture(t)
				fixture.options.RequestTimeout = time.Second
				fixture.options.FailureTimeout = time.Second
				fixture.options.RollbackTimeout = time.Second
				if name == "application deadline" {
					fixture.deps.Provider = exchangeTestProvider{authenticate: func(
						ctx context.Context,
						_ ExchangeRequest,
					) (TokenEvidence, error) {
						<-ctx.Done()
						return TokenEvidence{}, ctx.Err()
					}}
				} else {
					fixture.command.params.Kind, fixture.command.params.Code = CallbackProviderErrorReceived, Code{}
					if name == "failure deadline" {
						fixture.failure.beforeBegin = func(ctx context.Context) { <-ctx.Done() }
					} else {
						fixture.failure.unit.applyErr = errors.New("private apply failure")
						fixture.failure.wrapped = callbackDeadlineRollback{FailureTransaction: fixture.failure.unit}
					}
				}
				service, err := NewCallbackService(fixture.options, fixture.deps)
				if err != nil {
					t.Fatal(err)
				}
				started := time.Now()
				result, resultErr := service.CompleteBrowser(t.Context(), fixture.command)
				if resultErr == nil || !reflect.DeepEqual(result, CallbackResult{}) || time.Since(started) != time.Second ||
					len(service.active) != 0 || fixture.observer.closed != 1 {
					t.Fatal("application/cleanup escaped its finite owned deadline")
				}
				if name == "application deadline" {
					if !errors.Is(resultErr, context.DeadlineExceeded) || fixture.failure.unit.commits != 1 {
						t.Fatal("global application timeout did not join confirmed-claim cleanup")
					}
				} else if !errors.Is(resultErr, ErrCallbackCleanupFailed) || fixture.failure.unit.commits != 0 ||
					fixture.failure.unit.rollbacks != 1 {
					t.Fatal("cleanup deadline did not return zero and join exactly one rollback")
				}
			})
		})
	}
}

type callbackDeadlineRollback struct{ FailureTransaction }

func (unit callbackDeadlineRollback) Rollback(ctx context.Context) error {
	if err := unit.FailureTransaction.Rollback(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestCallbackRejectsCancellationAbsentContextAndZeroCommandBeforeEffects(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"canceled", "absent context", "zero command"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newCallbackFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if name == "canceled" {
				cancel()
			}
			if name == "absent context" {
				ctx = nil
			}
			if name == "zero command" {
				fixture.command = CallbackCommand{}
			}
			result, err := fixture.service.CompleteBrowser(ctx, fixture.command)
			if err == nil || !reflect.DeepEqual(result, CallbackResult{}) || len(fixture.effects) != 0 ||
				len(fixture.service.active) != 0 {
				t.Fatal("invalid/canceled request reached application effects")
			}
		})
	}
}

func FuzzCallbackCommand(f *testing.F) {
	f.Add("synthetic-code", uint8(CallbackCodeReceived))
	f.Add("", uint8(CallbackProviderErrorReceived))
	f.Add("synthetic-code", uint8(CallbackKindUnknown))
	f.Fuzz(func(t *testing.T, raw string, variant uint8) {
		pending := pendingParamsFixture(t)
		code := Code{value: raw}
		params := CallbackCommandParams{
			Route: pending.Route, State: pending.Secrets.State(), PreAuthCookie: pending.Secrets.PreAuthCookie(),
			Code: code, Kind: CallbackKind(variant),
		}
		command, err := NewCallbackCommand(params)
		if err != nil {
			if command.IsValid() {
				t.Fatal("rejected callback retained positive syntax")
			}
			return
		}
		if !command.IsValid() || (params.Kind == CallbackCodeReceived && (raw != code.Encoded() || len(raw) > 2048)) ||
			(params.Kind == CallbackProviderErrorReceived && code != (Code{})) {
			t.Fatal("callback accepted ambiguous or widened code syntax")
		}
	})
}

func TestCallbackSequencesFreshProofAndConfirmedOnlyEffects(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"issued", "provider error", "wrong state", "wrong cookie", "route substitution", "missing pending",
		"unknown claim commit", "claim cleanup failure", "canceled after claim commit",
		"provider failure", "wrong nonce", "subject rejected", "subject unavailable", "subject substitution",
		"missing auth time", "issue failure", "unknown issue commit", "canceled after issue commit",
		"expired after issue commit", "issue cleanup failure", "unknown failure commit", "failure cleanup failure",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newCallbackFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			params := fixture.command.params
			if name == "provider error" || name == "unknown failure commit" || name == "failure cleanup failure" {
				params.Kind, params.Code = CallbackProviderErrorReceived, Code{}
			}
			switch name {
			case "wrong state":
				params.State = State{value: [32]byte{1}}
			case "wrong cookie":
				params.PreAuthCookie = PreAuthCookie{value: [32]byte{1}}
			case "route substitution":
				params.Route.recoveryEpoch++
			case "missing pending":
				fixture.loaderMissing = true
			case "unknown claim commit":
				fixture.claim.unit.commitErr = ErrCommitOutcomeUnknown
			case "claim cleanup failure":
				fixture.claim.unit.claimErr = errors.New("private apply detail")
				fixture.claim.unit.rollbackErr = errors.New("private cleanup detail")
			case "canceled after claim commit":
				fixture.claim.unit.afterCommit = cancel
			case "unknown failure commit":
				fixture.failure.unit.commitErr = ErrCommitOutcomeUnknown
			case "failure cleanup failure":
				fixture.failure.unit.applyErr = errors.New("private apply detail")
				fixture.failure.unit.rollbackErr = errors.New("private cleanup detail")
			case "issue failure", "issue cleanup failure":
				fixture.issue.issue = func(IssueCommand) (Issued, error) {
					return Issued{}, errors.New("private issue detail")
				}
				if name == "issue cleanup failure" {
					fixture.issue.rollbackErr = errors.New("private cleanup detail")
				}
			case "unknown issue commit":
				fixture.issue.commitErr = ErrCommitOutcomeUnknown
			case "canceled after issue commit":
				fixture.issue.onCommit = cancel
			case "expired after issue commit":
				fixture.issue.onCommit = func() { fixture.now = fixture.snapshot.ExpiresAt() }
			}
			fixture.providerFault, fixture.subjectFault = name, name
			fixture.command = CallbackCommand{params: params}
			result, err := fixture.service.CompleteBrowser(ctx, fixture.command)
			if name == "issued" {
				if err != nil || !result.IsValid() || !result.Issued().IsValid() || result.Failure().IsValid() {
					t.Fatalf("confirmed callback did not issue: %v", err)
				}
				want := []string{"verify", "claim", "exchange", "resolve", "issue"}
				if !reflect.DeepEqual(fixture.effects, want) || fixture.issue.commits != 1 || fixture.failure.begins != 0 {
					t.Fatal("callback reordered effects or terminalized issued state")
				}
			} else if name == "provider error" {
				if err != nil || !result.IsValid() || !result.Failure().IsValid() || result.Issued().IsValid() ||
					!reflect.DeepEqual(fixture.effects, []string{"verify", "claim", "fail"}) {
					t.Fatal("provider error exchanged or lacked confirmed no-grant erasure")
				}
			} else if err == nil || !reflect.DeepEqual(result, CallbackResult{}) || result.Issued().Token().Encoded() != "" ||
				strings.Contains(err.Error(), "private") {
				t.Fatal("failed callback released evidence or private dependency text")
			}
			preClaim := name == "wrong state" || name == "wrong cookie" ||
				name == "route substitution" || name == "missing pending"
			claimError := name == "unknown claim commit" || name == "claim cleanup failure" ||
				name == "canceled after claim commit"
			if preClaim && fixture.claim.begins != 0 {
				t.Fatal("invalid browser proof reached claim")
			}
			noDownstreamEffects := fixture.providerCalls == 0 && fixture.failure.begins == 0 && fixture.issue.begins == 0
			if (preClaim || claimError) && !noDownstreamEffects {
				t.Fatal("unconfirmed claim reached downstream work")
			}
			beforeIssueFailure := name == "provider failure" || name == "wrong nonce" || name == "subject rejected" ||
				name == "subject unavailable" || name == "subject substitution"
			cleanupConfirmed := fixture.failure.begins == 1 && fixture.failure.unit.commits == 1 && fixture.issue.begins == 0
			if beforeIssueFailure && !cleanupConfirmed {
				t.Fatal("pre-issuance failure lacked one confirmed cleanup")
			}
			afterIssue := name == "missing auth time" || strings.Contains(name, "issue")
			if afterIssue && fixture.failure.begins != 0 {
				t.Fatal("issuance error incorrectly inferred non-commit and requested failure")
			}
			if strings.Contains(name, "unknown") && !errors.Is(err, ErrCommitOutcomeUnknown) {
				t.Fatal("unknown acknowledgement classification lost")
			}
			if strings.Contains(name, "cleanup failure") && !errors.Is(err, ErrCallbackCleanupFailed) {
				t.Fatal("joined cleanup failure lost")
			}
			if strings.Contains(name, "canceled") && !errors.Is(err, context.Canceled) {
				t.Fatal("request cancellation lost")
			}
			if fixture.observer.opened != 1 || fixture.observer.closed != 1 ||
				fixture.observer.outcome != callbackOutcome(result, err) || fixture.observer.elapsed < 0 {
				t.Fatal("final observation excluded cleanup or final result")
			}
			if fixture.claim.unit.commits > 0 {
				providerCalls, issueBegins, failureBegins := fixture.providerCalls, fixture.issue.begins, fixture.failure.begins
				replay, replayErr := fixture.service.CompleteBrowser(t.Context(), fixture.command)
				if replayErr == nil || replay.IsValid() || fixture.providerCalls != providerCalls ||
					fixture.issue.begins != issueBegins || fixture.failure.begins != failureBegins {
					t.Fatal("durably consumed callback reconstructed capability or retried")
				}
			}
		})
	}
}

func TestCallbackCommandAndResultNeverSerializeCredentials(t *testing.T) {
	t.Parallel()
	fixture := newCallbackFixture(t)
	result, err := fixture.service.CompleteBrowser(t.Context(), fixture.command)
	if err != nil || !result.Issued().IsValid() {
		t.Fatal("redaction fixture failed")
	}
	for _, value := range []any{fixture.command.params, fixture.command, result, CallbackCommandParams{}} {
		if fmt.Sprint(value) != "[REDACTED]" || strings.Contains(fmt.Sprintf("%#v", value), "synthetic-callback-code") ||
			strings.Contains(fmt.Sprintf("%#v", value), result.Issued().Token().Encoded()) {
			t.Fatal("callback input/result formatted credentials")
		}
		encoded, err := json.Marshal(value)
		if err == nil || len(encoded) != 0 {
			t.Fatal("callback input/result serialized credentials")
		}
	}
	if result.LogValue().String() != "[REDACTED]" || fixture.command.LogValue().String() != "[REDACTED]" ||
		fixture.command.params.LogValue().String() != "[REDACTED]" {
		t.Fatal("structured callback logging disclosed credentials")
	}
}

func TestCallbackConstructionRejectsIncompleteAndTypedNilDependencies(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"request zero", "request too long", "failure zero", "failure too long", "rollback zero", "rollback too long",
		"capacity zero", "capacity too large", "idle fractional", "absolute too long", "pending typed nil", "claim typed nil",
		"failure typed nil", "issue typed nil", "IDs absent", "material absent", "provider absent", "subjects absent",
		"clock typed nil", "observer typed nil", "subject observer typed nil", "issue observer typed nil",
		"digest zero", "cipher zero", "subjects zero", "sessions zero", "SID zero", "SID reused subject material",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newCallbackFixture(t)
			options, deps := fixture.options, fixture.deps
			switch name {
			case "request zero":
				options.RequestTimeout = 0
			case "request too long":
				options.RequestTimeout = 31 * time.Second
			case "failure zero":
				options.FailureTimeout = 0
			case "failure too long":
				options.FailureTimeout = 6 * time.Second
			case "rollback zero":
				options.RollbackTimeout = 0
			case "rollback too long":
				options.RollbackTimeout = 6 * time.Second
			case "capacity zero":
				options.MaxConcurrent = 0
			case "capacity too large":
				options.MaxConcurrent = 129
			case "idle fractional":
				options.IdleLifetime = time.Second + time.Nanosecond
			case "absolute too long":
				options.AbsoluteLifetime = 25 * time.Hour
			case "pending typed nil":
				deps.Pending = (*callbackTestPending)(nil)
			case "claim typed nil":
				deps.Claims = (*callbackTestClaim)(nil)
			case "failure typed nil":
				deps.Failures = (*callbackTestFailure)(nil)
			case "issue typed nil":
				deps.Issues = (*issueTestUnit)(nil)
			case "IDs absent":
				deps.IDs = nil
			case "material absent":
				deps.Material = nil
			case "provider absent":
				deps.Provider = nil
			case "subjects absent":
				deps.Subjects = nil
			case "clock typed nil":
				deps.Clock = (*browserVerificationClock)(nil)
			case "observer typed nil":
				deps.Observer = (*callbackTestObserver)(nil)
			case "subject observer typed nil":
				deps.SubjectObserver = (*subjectTestObserver)(nil)
			case "issue observer typed nil":
				deps.IssueObserver = (*issueTestObserver)(nil)
			case "digest zero":
				deps.DigestKey = DigestKey{}
			case "cipher zero":
				deps.VerifierCipher = &VerifierCipher{}
			case "subjects zero":
				deps.SubjectKeys = &SubjectKeyring{}
			case "sessions zero":
				deps.SessionKeys = nil
			case "SID zero":
				deps.ProviderSessions = ProviderSessionKey{}
			case "SID reused subject material":
				deps.ProviderSessions.key.material = deps.SubjectKeys.active.key.material
			}
			service, err := NewCallbackService(options, deps)
			if !errors.Is(err, ErrInvalidCallback) || service != nil || len(fixture.effects) != 0 {
				t.Fatal("invalid callback constructor accepted or performed effects")
			}
		})
	}
	var service *CallbackService
	result, err := service.CompleteBrowser(t.Context(), CallbackCommand{})
	if !errors.Is(err, ErrInvalidCallback) || result.IsValid() {
		t.Fatal("nil callback service accepted")
	}
	service = &CallbackService{}
	result, err = service.CompleteBrowser(t.Context(), CallbackCommand{})
	if !errors.Is(err, ErrInvalidCallback) || result.IsValid() {
		t.Fatal("zero callback service accepted")
	}
}

func TestCallbackBoundsWholeDeadlineCapacityAndCanceledCleanup(t *testing.T) {
	// Keep the process-global leak check outside the fake-clock bubble and away
	// from unrelated parallel tests; the bubble joins the callback owner first.
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	synctest.Test(t, func(t *testing.T) {
		fixture := newCallbackFixture(t)
		fixture.options.RequestTimeout = 3 * time.Second
		fixture.options.FailureTimeout = 2 * time.Second
		fixture.options.RollbackTimeout = time.Second
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		deadline, _ := ctx.Deadline()
		fixture.expectedDeadline = deadline
		providerEntered := make(chan struct{})
		failureEntered := make(chan struct{})
		releaseFailure := make(chan struct{})
		originalProvider := fixture.deps.Provider
		fixture.deps.Provider = exchangeTestProvider{authenticate: func(
			ctx context.Context,
			request ExchangeRequest,
		) (TokenEvidence, error) {
			if got, ok := ctx.Deadline(); !ok || !got.Equal(deadline) {
				t.Error("provider work extended whole caller deadline")
			}
			close(providerEntered)
			<-ctx.Done()
			return originalProvider.Authenticate(ctx, request)
		}}
		fixture.failure.beforeBegin = func(ctx context.Context) {
			if ctx.Err() != nil {
				t.Error("terminal cleanup inherited canceled request")
			}
			got, ok := ctx.Deadline()
			if !ok || time.Until(got) != 2*time.Second {
				t.Error("terminal cleanup lacks independent finite window")
			}
			close(failureEntered)
			select {
			case <-releaseFailure:
			case <-ctx.Done():
			}
		}
		service, err := NewCallbackService(fixture.options, fixture.deps)
		if err != nil {
			t.Fatal(err)
		}
		var owner sync.WaitGroup
		var result CallbackResult
		var resultErr error
		owner.Go(func() { result, resultErr = service.CompleteBrowser(ctx, fixture.command) })
		<-providerEntered
		limited, limitedErr := service.CompleteBrowser(t.Context(), fixture.command)
		if !errors.Is(limitedErr, ErrCallbackLimited) || limited.IsValid() {
			t.Error("application capacity queued a callback")
		}
		<-failureEntered
		if len(service.active) != 1 || fixture.observer.closed != 1 {
			t.Error("caller returned or capacity released before cleanup joined")
		}
		limited, limitedErr = service.CompleteBrowser(t.Context(), fixture.command)
		if !errors.Is(limitedErr, ErrCallbackLimited) || limited.IsValid() {
			t.Error("cleanup did not retain application capacity")
		}
		close(releaseFailure)
		owner.Wait()
		if !reflect.DeepEqual(result, CallbackResult{}) || !errors.Is(resultErr, context.DeadlineExceeded) ||
			fixture.failure.begins != 1 || fixture.failure.unit.commits != 1 || len(service.active) != 0 {
			t.Fatal("canceled callback released evidence or failed to join one cleanup")
		}
		if fixture.observer.opened != 3 || fixture.observer.closed != 3 || fixture.observer.elapsed != time.Second {
			t.Fatal("whole lifetime observation missed deadline or cleanup")
		}
	})
}

type callbackFixture struct {
	service                     *CallbackService
	command                     CallbackCommand
	options                     CallbackOptions
	deps                        CallbackDependencies
	snapshot                    PendingSnapshot
	now, expectedDeadline       time.Time
	effects                     []string
	claim                       *callbackTestClaim
	failure                     *callbackTestFailure
	issue                       *issueTestUnit
	observer                    *callbackTestObserver
	loaderMissing               bool
	providerFault, subjectFault string
	// providerEmail is the address the provider marks verified.
	providerEmail string
	providerCalls int
}

func newCallbackFixture(t *testing.T) *callbackFixture {
	t.Helper()
	params := pendingParamsFixture(t)
	snapshot, err := NewPendingSnapshot(snapshotParamsFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	fixture := &callbackFixture{snapshot: snapshot, now: snapshot.CreatedAt().Add(time.Second), effects: []string{}}
	fixture.claim = &callbackTestClaim{fixture: fixture, unit: &claimTestUnit{now: fixture.now}}
	fixture.failure = &callbackTestFailure{fixture: fixture, unit: &failureTestUnit{at: fixture.now}}
	fixture.observer = &callbackTestObserver{}
	issue, _, unit := issueFixture(t, issueExchangeFixture(t))
	fixture.issue = unit
	originalIssue := unit.issue
	unit.issue = func(command IssueCommand) (Issued, error) {
		fixture.effects = append(fixture.effects, "issue")
		return originalIssue(command)
	}
	fixture.options = CallbackOptions{
		RequestTimeout: time.Second, FailureTimeout: time.Second, RollbackTimeout: time.Second,
		IdleLifetime: time.Minute, AbsoluteLifetime: time.Hour, MaxConcurrent: 1,
	}
	fixture.deps = CallbackDependencies{
		Pending: &callbackTestPending{fixture: fixture}, Claims: fixture.claim, Failures: fixture.failure,
		Issues: fixture.issue, IDs: SystemClaimIDs{}, Material: SystemIssueMaterial{},
		DigestKey: params.DigestKey, VerifierCipher: params.VerifierCipher,
		SubjectKeys: issue.dependencies.Subjects, SessionKeys: issue.dependencies.Sessions,
		ProviderSessions: issue.dependencies.ProviderSessions,
		Clock:            browserVerificationClock{now: func() time.Time { return fixture.now }},
		Observer:         fixture.observer, SubjectObserver: &subjectTestObserver{}, IssueObserver: &issueTestObserver{},
		Provider: exchangeTestProvider{authenticate: func(
			ctx context.Context,
			request ExchangeRequest,
		) (TokenEvidence, error) {
			fixture.effects = append(fixture.effects, "exchange")
			fixture.providerCalls++
			if fixture.claim.unit.commits != 1 || fixture.claim.unit.rollbacks != 0 ||
				request.Verifier().Encoded() != params.Secrets.Verifier().Encoded() || !request.IsValid() {
				t.Error("provider used unconfirmed claim or replaced PKCE")
			}
			if fixture.providerFault == "provider failure" || ctx.Err() != nil {
				return TokenEvidence{}, errors.New("private provider detail")
			}
			nonce := params.Secrets.Nonce()
			if fixture.providerFault == "wrong nonce" {
				nonce = Nonce{value: [32]byte{1}}
			}
			authTime := fixture.now.Add(-time.Minute)
			if fixture.providerFault == "missing auth time" {
				authTime = time.Time{}
			}
			return NewTokenEvidence(TokenEvidenceParams{
				Issuer: params.Route.Issuer(), Subject: " Case-é ", Nonce: nonce, IssuedAt: fixture.now,
				ExpiresAt: fixture.now.Add(time.Minute), AuthTime: authTime, VerifiedEmail: fixture.providerEmail,
			})
		}},
		Subjects: subjectTestResolver{resolve: func(_ context.Context, lookup SubjectLookup) (LoginSubjectSnapshot, error) {
			fixture.effects = append(fixture.effects, "resolve")
			if fixture.subjectFault == "subject rejected" {
				return LoginSubjectSnapshot{}, ErrSubjectResolutionRejected
			}
			if fixture.subjectFault == "subject unavailable" {
				return LoginSubjectSnapshot{}, errors.New("private subject detail")
			}
			if fixture.subjectFault == "subject substitution" {
				return LoginSubjectSnapshot{}, nil
			}
			return NewLoginSubjectSnapshot(subjectSnapshotParamsFixture(t, lookup, fixture.now))
		}},
	}
	fixture.service, err = NewCallbackService(fixture.options, fixture.deps)
	if err != nil {
		t.Fatal(err)
	}
	code, err := ParseCode("synthetic-callback-code")
	if err != nil {
		t.Fatal(err)
	}
	fixture.command, err = NewCallbackCommand(CallbackCommandParams{
		Route: params.Route, State: params.Secrets.State(), PreAuthCookie: params.Secrets.PreAuthCookie(),
		Kind: CallbackCodeReceived, Code: code,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

type callbackTestPending struct{ fixture *callbackFixture }

func (loader *callbackTestPending) LoadPending(
	ctx context.Context,
	route Route,
	digest Digest,
) (PendingSnapshot, bool, error) {
	fixture := loader.fixture
	fixture.effects = append(fixture.effects, "verify")
	if !fixture.expectedDeadline.IsZero() {
		if got, ok := ctx.Deadline(); !ok || !got.Equal(fixture.expectedDeadline) {
			return PendingSnapshot{}, false, errors.New("incorrect whole deadline")
		}
	}
	if fixture.loaderMissing || fixture.claim.unit.commits > 0 || !fixture.snapshot.MatchesRoute(route) ||
		digest.Bytes() != fixture.snapshot.StateDigest().Bytes() {
		return PendingSnapshot{}, false, nil
	}
	return fixture.snapshot, true, nil
}

type callbackTestClaim struct {
	fixture *callbackFixture
	unit    *claimTestUnit
	begins  int
}

func (store *callbackTestClaim) BeginClaim(context.Context, Route) (ClaimTransaction, error) {
	store.fixture.effects = append(store.fixture.effects, "claim")
	store.begins++
	return store.unit, nil
}

type callbackTestFailure struct {
	fixture     *callbackFixture
	unit        *failureTestUnit
	begins      int
	beforeBegin func(context.Context)
	wrapped     FailureTransaction
}

func (store *callbackTestFailure) BeginFailure(ctx context.Context, _ Route) (FailureTransaction, error) {
	store.fixture.effects = append(store.fixture.effects, "fail")
	store.begins++
	if store.beforeBegin != nil {
		store.beforeBegin(ctx)
	}
	if store.wrapped != nil {
		return store.wrapped, nil
	}
	return store.unit, nil
}

type callbackTestObserver struct {
	mu             sync.Mutex
	opened, closed int
	outcome        CallbackOutcome
	elapsed        time.Duration
}

func (observer *callbackTestObserver) CallbackOpened() {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.opened++
}

func (observer *callbackTestObserver) CallbackClosed(outcome CallbackOutcome, elapsed time.Duration) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.closed++
	observer.outcome, observer.elapsed = outcome, elapsed
}
