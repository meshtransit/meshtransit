package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
)

func TestIssueRequiresSignedAuthenticationTimeBeforeEffects(t *testing.T) {
	t.Parallel()
	exchange := subjectExchangeFixture(t)
	service, subject, unit := issueFixture(t, exchange)
	result, err := service.IssueBrowser(t.Context(), exchange, subject)
	if !errors.Is(err, ErrIssueRejected) || result.IsValid() || unit.begins != 0 {
		t.Fatal("absent auth_time issued or began a write")
	}
}

func TestIssueReturnsOnlyConfirmedLiveBoundSession(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"confirmed", "unknown commit", "commit failure", "begin owned failure", "nil unit", "apply failure", "wrong command", "wrong session", "claim expired after apply", "expired after commit", "canceled after apply", "canceled after commit", "cleanup failure"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			exchange := issueExchangeFixture(t)
			service, subject, unit := issueFixture(t, exchange)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			now := exchange.Claimed().ConsumedAt()
			service.dependencies.Clock = browserVerificationClock{now: func() time.Time { return now }}
			original := unit.issue
			unit.issue = func(command IssueCommand) (Issued, error) {
				issued, err := original(command)
				switch name {
				case "apply failure", "cleanup failure":
					return Issued{}, errors.New("private dependency detail")
				case "wrong command":
					issued.command.acr = "substituted"
				case "wrong session":
					issued.session = accountsession.Session{}
				case "claim expired after apply":
					now = exchange.claimed.snapshot.ExpiresAt()
				case "canceled after apply":
					cancel()
				}
				return issued, err
			}
			switch name {
			case "unknown commit":
				unit.commitErr = ErrCommitOutcomeUnknown
			case "commit failure":
				unit.commitErr = errors.New("private commit detail")
			case "begin owned failure":
				unit.beginErr = errors.New("private begin detail")
			case "nil unit":
				unit.nilUnit = true
			case "cleanup failure":
				unit.rollbackErr = errors.New("private cleanup detail")
			}
			unit.onCommit = func() {
				if name == "expired after commit" {
					now = exchange.claimed.snapshot.ExpiresAt()
				}
				if name == "canceled after commit" {
					cancel()
				}
			}
			unit.onRollback = func(cleanup context.Context) {
				if cleanup.Err() != nil {
					t.Error("cleanup inherited request cancellation")
				}
				if _, ok := cleanup.Deadline(); !ok {
					t.Error("cleanup has no finite deadline")
				}
			}
			result, err := service.IssueBrowser(ctx, exchange, subject)
			if name == "confirmed" {
				if err != nil || !result.IsValid() || result.Token().Encoded() == "" || unit.commits != 1 || unit.rollbacks != 0 {
					t.Fatal("confirmed result not released exactly once")
				}
				if fmt.Sprint(result) != "[REDACTED]" || strings.Contains(fmt.Sprintf("%#v", result), result.Token().Encoded()) {
					t.Fatal("result formatted raw bearer")
				}
			} else if err == nil || result.IsValid() || result.Token().Encoded() != "" || strings.Contains(err.Error(), "private") {
				t.Fatal("failure released bearer or dependency detail")
			}
			if name == "unknown commit" && !errors.Is(err, ErrCommitOutcomeUnknown) {
				t.Fatal("unknown Commit category lost")
			}
			if name == "cleanup failure" && !errors.Is(err, ErrIssueCleanupFailed) {
				t.Fatal("joined cleanup failure lost")
			}
			observer := service.dependencies.Observer.(*issueTestObserver)
			if observer.opened != 1 || observer.closed != 1 || observer.outcome != issueOutcome(err) {
				t.Fatal("owned observation did not include final cleanup outcome")
			}
			if (name == "canceled after apply" || name == "claim expired after apply" || name == "wrong command" || name == "wrong session") && unit.commits != 0 {
				t.Fatal("invalid pre-Commit evidence committed")
			}
			if name != "nil unit" && name != "confirmed" && name != "expired after commit" && name != "canceled after commit" && unit.rollbacks != 1 {
				t.Fatal("failed owned unit not joined exactly once")
			}
			if replay, replayErr := service.IssueBrowser(t.Context(), exchange, subject); replayErr == nil || replay.IsValid() || unit.begins != 1 {
				t.Fatal("burned exchange issuance was retried")
			}
		})
	}
}

func TestIssueRejectsExpiredMembershipBeforeEntropyOrBegin(t *testing.T) {
	t.Parallel()
	exchange := issueExchangeFixture(t)
	service, subject, unit := issueFixture(t, exchange)
	params := subjectSnapshotParamsFixture(t, subject.params.Lookup, exchange.Claimed().ConsumedAt())
	params.MembershipExpiresAt = params.EvaluatedAt.Add(time.Second)
	bounded, err := NewLoginSubjectSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	service.dependencies.Clock = browserVerificationClock{now: func() time.Time { return params.MembershipExpiresAt }}
	materialCalls := 0
	service.dependencies.Material = issueTestMaterial(func(ctx context.Context, dep deployment.ID, epoch int64) (IssueIDs, accountsession.Token, error) {
		materialCalls++
		return (SystemIssueMaterial{}).NewIssueMaterial(ctx, dep, epoch)
	})
	result, err := service.IssueBrowser(t.Context(), exchange, bounded)
	if err == nil || result.IsValid() || unit.begins != 0 || materialCalls != 0 {
		t.Fatal("exclusive expired membership entered write unit")
	}
}

func TestIssueRejectsPreparationFailureBeforeBeginAndBurnsAttempt(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"entropy failure", "wrong token scope", "duplicate IDs", "canceled preparation"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			exchange := issueExchangeFixture(t)
			service, subject, unit := issueFixture(t, exchange)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			service.dependencies.Material = issueTestMaterial(func(ctx context.Context, dep deployment.ID, epoch int64) (IssueIDs, accountsession.Token, error) {
				calls++
				if name == "entropy failure" {
					return IssueIDs{}, accountsession.Token{}, errors.New("private entropy detail")
				}
				ids, token, err := (SystemIssueMaterial{}).NewIssueMaterial(ctx, dep, epoch)
				if err != nil {
					return ids, token, err
				}
				switch name {
				case "wrong token scope":
					token, err = accountsession.GenerateToken(dep, epoch+1)
				case "duplicate IDs":
					ids.params.SuccessOutboxID = ids.params.SessionOutboxID
				case "canceled preparation":
					cancel()
				}
				return ids, token, err
			})
			result, err := service.IssueBrowser(ctx, exchange, subject)
			if err == nil || result.IsValid() || result.Token().Encoded() != "" || unit.begins != 0 ||
				calls != 1 || strings.Contains(err.Error(), "private") {
				t.Fatal("invalid preparation entered DB or released private evidence")
			}
			if _, err := service.IssueBrowser(t.Context(), exchange, subject); err == nil || calls != 1 {
				t.Fatal("failed preparation replayed")
			}
		})
	}
}

func TestIssuedRejectsWrongDurableMetadataAndCapsMembership(t *testing.T) {
	t.Parallel()
	exchange := issueExchangeFixture(t)
	service, subject, unit := issueFixture(t, exchange)
	params := subject.params
	params.MembershipExpiresAt = params.EvaluatedAt.Add(30 * time.Second)
	bounded, err := NewLoginSubjectSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	var command IssueCommand
	original := unit.issue
	unit.issue = func(value IssueCommand) (Issued, error) { command = value; return original(value) }
	result, err := service.IssueBrowser(t.Context(), exchange, bounded)
	if err != nil || !result.Session().IdleExpiresAt().Equal(params.MembershipExpiresAt) ||
		!result.Session().AbsoluteExpiresAt().Equal(params.MembershipExpiresAt) {
		t.Fatal("membership did not intersect both deadlines")
	}
	for _, name := range []string{"wrong ID", "wrong version", "early time", "expired time", "extended idle", "extended absolute"} {
		t.Run(name, func(t *testing.T) {
			metadata := IssuedParams{Command: command, SessionID: command.IDs().SessionID(), Version: 1,
				IssuedAt: params.EvaluatedAt, IdleExpiresAt: params.MembershipExpiresAt,
				AbsoluteExpiresAt: params.MembershipExpiresAt}
			switch name {
			case "wrong ID":
				metadata.SessionID[15] ^= 1
			case "wrong version":
				metadata.Version++
			case "early time":
				metadata.IssuedAt = params.EvaluatedAt.Add(-time.Microsecond)
			case "expired time":
				metadata.IssuedAt = params.MembershipExpiresAt
			case "extended idle":
				metadata.IdleExpiresAt = params.MembershipExpiresAt.Add(time.Microsecond)
			case "extended absolute":
				metadata.AbsoluteExpiresAt = params.MembershipExpiresAt.Add(time.Microsecond)
			}
			if issued, err := NewIssued(metadata); err == nil || issued.IsValid() {
				t.Fatal("substituted durable metadata accepted")
			}
		})
	}
}

type issueTestMaterial func(context.Context, deployment.ID, int64) (IssueIDs, accountsession.Token, error)

func (material issueTestMaterial) NewIssueMaterial(ctx context.Context, dep deployment.ID, epoch int64) (IssueIDs, accountsession.Token, error) {
	return material(ctx, dep, epoch)
}

func TestIssueCopiesShareAttemptAndOverloadDoesNotQueue(t *testing.T) {
	t.Parallel()
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	exchange := issueExchangeFixture(t)
	service, subject, unit := issueFixture(t, exchange)
	entered, release := make(chan struct{}), make(chan struct{})
	original := unit.issue
	unit.issue = func(command IssueCommand) (Issued, error) {
		close(entered)
		<-release
		return original(command)
	}
	var owner sync.WaitGroup
	var result IssueResult
	var err error
	owner.Go(func() { result, err = service.IssueBrowser(t.Context(), exchange, subject) })
	<-entered
	copyResult, copyErr := service.IssueBrowser(t.Context(), exchange, subject)
	if copyErr == nil || copyResult.IsValid() {
		t.Error("exchange copy entered a second issuance")
	}
	other := issueExchangeFixture(t)
	_, otherSubject, _ := issueFixture(t, other)
	limited, limitedErr := service.IssueBrowser(t.Context(), other, otherSubject)
	if !errors.Is(limitedErr, ErrIssueLimited) || limited.IsValid() {
		t.Error("overload queued or released")
	}
	close(release)
	owner.Wait()
	if err != nil || !result.IsValid() || unit.begins != 1 {
		t.Fatal("owned issuance failed")
	}
	if retry, retryErr := service.IssueBrowser(t.Context(), other, otherSubject); retryErr == nil || retry.IsValid() || unit.begins != 1 {
		t.Fatal("limited attempt was not burned")
	}
}

func issueExchangeFixture(t *testing.T) ExchangeResult {
	t.Helper()
	exchange := subjectExchangeFixture(t)
	exchange.identity.authTime = exchange.identity.IssuedAt().Add(-time.Minute)
	return exchange
}

type issueTestUnit struct {
	begins, applies, commits, rollbacks int
	commitErr                           error
	beginErr, rollbackErr               error
	nilUnit                             bool
	onCommit                            func()
	onRollback                          func(context.Context)
	issue                               func(IssueCommand) (Issued, error)
}

func (unit *issueTestUnit) BeginIssue(context.Context, Route) (IssueTransaction, error) {
	unit.begins++
	if unit.nilUnit {
		return nil, unit.beginErr
	}
	return unit, unit.beginErr
}
func (unit *issueTestUnit) Issue(_ context.Context, command IssueCommand) (Issued, error) {
	unit.applies++
	return unit.issue(command)
}
func (unit *issueTestUnit) Commit(context.Context) error {
	unit.commits++
	if unit.onCommit != nil {
		unit.onCommit()
	}
	return unit.commitErr
}
func (unit *issueTestUnit) Rollback(ctx context.Context) error {
	unit.rollbacks++
	if unit.onRollback != nil {
		unit.onRollback(ctx)
	}
	return unit.rollbackErr
}

func issueFixture(t *testing.T, exchange ExchangeResult) (*IssueService, LoginSubjectSnapshot, *issueTestUnit) {
	t.Helper()
	ring, err := NewSubjectKeyring(subjectKeyFixture(t, "subject-v1", 7))
	if err != nil {
		t.Fatal(err)
	}
	digests, err := ring.Digests(exchange.claimed.snapshot.Route(), exchange.identity)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := NewSubjectLookup(exchange.claimed, digests)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := NewLoginSubjectSnapshot(subjectSnapshotParamsFixture(t, lookup, exchange.claimed.ConsumedAt()))
	if err != nil {
		t.Fatal(err)
	}
	id, err := accountsession.NewDigestKeyID("session-v1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := accountsession.NewDigestKey(id, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	sessionKeys, err := accountsession.NewKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	sidID, err := NewDigestKeyID("sid-v1")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := NewProviderSessionKey(sidID, []byte("abcdef0123456789abcdef0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	unit := &issueTestUnit{}
	unit.issue = func(command IssueCommand) (Issued, error) {
		at := exchange.claimed.ConsumedAt()
		idle, absolute := issueDeadlines(command, at)
		return NewIssued(IssuedParams{
			Command: command, SessionID: command.IDs().SessionID(), Version: 1,
			IssuedAt: at, IdleExpiresAt: idle, AbsoluteExpiresAt: absolute,
		})
	}
	service, err := NewIssueService(IssueOptions{RequestTimeout: time.Second, RollbackTimeout: time.Second, IdleLifetime: time.Minute, AbsoluteLifetime: time.Hour, MaxConcurrent: 1}, IssueDependencies{
		Transactions: unit, Material: SystemIssueMaterial{}, Subjects: ring, Sessions: sessionKeys, ProviderSessions: sid, Clock: browserVerificationClock{now: func() time.Time { return exchange.claimed.ConsumedAt() }}, Observer: &issueTestObserver{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, subject, unit
}

type issueTestObserver struct {
	mu             sync.Mutex
	opened, closed int
	outcome        IssueOutcome
}

func (observer *issueTestObserver) IssueOpened() {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.opened++
}
func (observer *issueTestObserver) IssueClosed(outcome IssueOutcome, _ time.Duration) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.closed++
	observer.outcome = outcome
}
