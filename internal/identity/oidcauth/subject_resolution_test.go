package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"go.uber.org/goleak"
)

func TestSubjectResolutionReturnsOnlyClosedExactSnapshot(t *testing.T) {
	t.Parallel()
	exchange := subjectExchangeFixture(t)
	now := exchange.claimed.ConsumedAt()
	ring, err := NewSubjectKeyring(subjectKeyFixture(t, "subject-v1", 7))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	observer := &subjectTestObserver{}
	service, err := NewSubjectResolutionService(SubjectResolutionOptions{RequestTimeout: time.Second, MaxConcurrent: 1}, SubjectResolutionDependencies{
		Keys: ring, Clock: browserVerificationClock{now: func() time.Time { return now }}, Observer: observer,
		Subjects: subjectTestResolver{resolve: func(ctx context.Context, query SubjectLookup) (LoginSubjectSnapshot, error) {
			calls++
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Second {
				t.Fatal("missing request budget")
			}
			return NewLoginSubjectSnapshot(subjectSnapshotParamsFixture(t, query, now))
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ResolveBrowser(t.Context(), exchange)
	if err != nil || !result.IsValid() || calls != 1 || result.PrincipalID().String() != "01890f00-0000-7000-8000-000000000011" {
		t.Fatal("closed exact resolution failed")
	}
	if !exchange.Identity().AuthTime().IsZero() {
		t.Fatal("optional auth_time manufactured")
	}
	if observer.opened != 1 || observer.outcome != SubjectResolutionResolved {
		t.Fatal("resolution observation lost")
	}
	if fmt.Sprint(result) != "[REDACTED]" || fmt.Sprintf("%#v", result) != "oidcauth.LoginSubjectSnapshot([REDACTED])" || result.LogValue().String() != "[REDACTED]" {
		t.Fatal("snapshot disclosed identity")
	}
}

func TestSubjectResolutionAcceptsBoundedAuthorityClockSkew(t *testing.T) {
	t.Parallel()
	exchange := subjectExchangeFixture(t)
	now := exchange.claimed.ConsumedAt()
	evaluatedAt := now.Add(time.Second)
	ring, err := NewSubjectKeyring(subjectKeyFixture(t, "subject-v1", 7))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewSubjectResolutionService(
		SubjectResolutionOptions{RequestTimeout: time.Second, MaxConcurrent: 1},
		SubjectResolutionDependencies{
			Keys: ring,
			Clock: browserVerificationClock{now: func() time.Time {
				return now
			}},
			Observer: &subjectTestObserver{},
			Subjects: subjectTestResolver{resolve: func(_ context.Context, query SubjectLookup) (LoginSubjectSnapshot, error) {
				return NewLoginSubjectSnapshot(subjectSnapshotParamsFixture(t, query, evaluatedAt))
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result, resolveErr := service.ResolveBrowser(t.Context(), exchange); resolveErr != nil || !result.IsValid() {
		t.Fatalf("bounded database clock skew rejected: %v", resolveErr)
	}
}

func TestSubjectResolutionRejectsStaleMalformedAndFailedReads(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"zero exchange", "canceled before", "expired before", "dependency", "no access", "cleanup after rejection", "wrong digest", "wrong key", "bad principal", "zero generation", "wrong claim", "noncanonical time", "future DB time", "canceled after", "claim expired after", "token expired after", "member expired after"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			exchange := subjectExchangeFixture(t)
			now := exchange.claimed.ConsumedAt()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if name == "canceled before" {
				cancel()
			}
			if name == "zero exchange" {
				exchange = ExchangeResult{}
			}
			if name == "expired before" {
				now = exchange.claimed.snapshot.ExpiresAt()
			}
			ring, err := NewSubjectKeyring(subjectKeyFixture(t, "subject-v1", 7))
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			service, err := NewSubjectResolutionService(SubjectResolutionOptions{RequestTimeout: time.Second, MaxConcurrent: 1}, SubjectResolutionDependencies{
				Keys: ring, Clock: browserVerificationClock{now: func() time.Time { return now }}, Observer: &subjectTestObserver{},
				Subjects: subjectTestResolver{resolve: func(_ context.Context, query SubjectLookup) (LoginSubjectSnapshot, error) {
					calls++
					if name == "dependency" {
						return LoginSubjectSnapshot{}, errors.New("private database identity")
					}
					if name == "no access" {
						return LoginSubjectSnapshot{}, ErrSubjectResolutionRejected
					}
					if name == "cleanup after rejection" {
						return LoginSubjectSnapshot{}, errors.Join(ErrSubjectResolutionRejected, ErrSubjectResolutionUnavailable)
					}
					params := subjectSnapshotParamsFixture(t, query, now)
					switch name {
					case "wrong digest":
						value := params.Digest.Bytes()
						value[0] ^= 1
						params.Digest, err = NewSubjectDigest(params.Digest.KeyID(), value)
					case "wrong key":
						id, keyErr := NewDigestKeyID("unknown-v1")
						if keyErr != nil {
							t.Fatal(keyErr)
						}
						params.Digest, err = NewSubjectDigest(id, params.Digest.Bytes())
					case "bad principal":
						params.PrincipalID = identity.PrincipalID{}
					case "zero generation":
						params.AccountSessionGeneration = 0
					case "wrong claim":
						params.Lookup.claimed.consumedAt = now.Add(time.Microsecond)
						params.EvaluatedAt = now.Add(time.Microsecond)
					case "noncanonical time":
						params.EvaluatedAt = now.Add(time.Nanosecond)
					case "future DB time":
						params.EvaluatedAt = now.Add(authorityClockSkewAllowance + time.Microsecond)
					case "canceled after":
						cancel()
					case "claim expired after":
						now = exchange.claimed.snapshot.ExpiresAt()
					case "token expired after":
						now = exchange.identity.ExpiresAt()
					case "member expired after":
						params.MembershipExpiresAt = now.Add(time.Second)
						now = params.MembershipExpiresAt
					}
					if err != nil {
						t.Fatal(err)
					}
					return NewLoginSubjectSnapshot(params)
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.ResolveBrowser(ctx, exchange)
			if err == nil || result.IsValid() || strings.Contains(err.Error(), "private") {
				t.Fatal("rejection released evidence or private error")
			}
			if calls > 1 {
				t.Fatal("read retried")
			}
			if name == "cleanup after rejection" && !errors.Is(err, ErrSubjectResolutionUnavailable) {
				t.Fatal("cleanup failure hidden as no-access")
			}
			if (name == "zero exchange" || name == "canceled before" || name == "expired before") && calls != 0 {
				t.Fatal("invalid exchange touched database")
			}
		})
	}
}

func TestSubjectResolutionBoundsConcurrencyWithoutStickyAuthority(t *testing.T) {
	t.Parallel()
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	exchange := subjectExchangeFixture(t)
	ring, err := NewSubjectKeyring(subjectKeyFixture(t, "subject-v1", 7))
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	observer := &subjectTestObserver{}
	service, err := NewSubjectResolutionService(SubjectResolutionOptions{RequestTimeout: time.Second, MaxConcurrent: 1}, SubjectResolutionDependencies{
		Keys: ring, Clock: browserVerificationClock{now: func() time.Time { return exchange.claimed.ConsumedAt() }}, Observer: observer,
		Subjects: subjectTestResolver{resolve: func(ctx context.Context, query SubjectLookup) (LoginSubjectSnapshot, error) {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return LoginSubjectSnapshot{}, ctx.Err()
			}
			return NewLoginSubjectSnapshot(subjectSnapshotParamsFixture(t, query, exchange.claimed.ConsumedAt()))
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var owner sync.WaitGroup
	var ownerResult LoginSubjectSnapshot
	var ownerErr error
	owner.Go(func() { ownerResult, ownerErr = service.ResolveBrowser(t.Context(), exchange) })
	<-entered
	if result, err := service.ResolveBrowser(t.Context(), exchange); !errors.Is(err, ErrSubjectResolutionLimited) || result.IsValid() {
		t.Error("overload queued or released")
	}
	close(release)
	owner.Wait()
	if ownerErr != nil || !ownerResult.IsValid() {
		t.Fatal("owned read failed")
	}
	// Equivalent replicas can read the same original claim; neither consumes it.
	second, err := NewSubjectResolutionService(SubjectResolutionOptions{RequestTimeout: time.Second, MaxConcurrent: 1}, SubjectResolutionDependencies{
		Keys: ring, Clock: browserVerificationClock{now: func() time.Time { return exchange.claimed.ConsumedAt() }}, Observer: &subjectTestObserver{},
		Subjects: subjectTestResolver{resolve: func(_ context.Context, query SubjectLookup) (LoginSubjectSnapshot, error) {
			return NewLoginSubjectSnapshot(subjectSnapshotParamsFixture(t, query, exchange.claimed.ConsumedAt()))
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := second.ResolveBrowser(t.Context(), exchange); err != nil || !result.IsValid() {
		t.Fatal("read depended on sticky state")
	}
}

func TestSubjectResolutionConstructorRejectsUnsafeBounds(t *testing.T) {
	t.Parallel()
	ring, err := NewSubjectKeyring(subjectKeyFixture(t, "subject-v1", 7))
	if err != nil {
		t.Fatal(err)
	}
	dependencies := SubjectResolutionDependencies{Keys: ring, Clock: SystemStartClock{}, Observer: &subjectTestObserver{}, Subjects: subjectTestResolver{}}
	for _, options := range []SubjectResolutionOptions{{}, {RequestTimeout: 31 * time.Second, MaxConcurrent: 1}, {RequestTimeout: time.Second, MaxConcurrent: 257}} {
		if _, err := NewSubjectResolutionService(options, dependencies); err == nil {
			t.Fatal("unsafe bounds admitted")
		}
	}
	for _, name := range []string{"keys", "clock", "subjects", "observer"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := dependencies
			switch name {
			case "keys":
				candidate.Keys = nil
			case "clock":
				candidate.Clock = nil
			case "subjects":
				candidate.Subjects = nil
			case "observer":
				candidate.Observer = nil
			}
			if _, err := NewSubjectResolutionService(SubjectResolutionOptions{RequestTimeout: time.Second, MaxConcurrent: 1}, candidate); err == nil {
				t.Fatal("missing security dependency accepted")
			}
		})
	}
}

func subjectExchangeFixture(t *testing.T) ExchangeResult {
	t.Helper()
	verified := claimVerifiedFixture(t)
	claimed, err := NewClaimed(verified.Snapshot(), 2, verified.Snapshot().CreatedAt().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return ExchangeResult{claimed: claimed, identity: subjectIdentityFixture(t, claimed.snapshot.Route().Issuer(), " Case-é "), issuanceAttempt: &atomic.Bool{}}
}

func subjectSnapshotParamsFixture(t *testing.T, query SubjectLookup, at time.Time) LoginSubjectParams {
	t.Helper()
	principal, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000711")
	if err != nil {
		t.Fatal(err)
	}
	member, err := ParseLoginMembershipID("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatal(err)
	}
	return LoginSubjectParams{Lookup: query, Digest: query.Digests()[0], PrincipalID: principal, IdentitySubjectID: subject, MembershipID: member,
		SubjectVersion: 1, AccountVersion: 1, MembershipVersion: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1, MembershipAuthorityGeneration: 1, EvaluatedAt: at}
}

type subjectTestResolver struct {
	resolve func(context.Context, SubjectLookup) (LoginSubjectSnapshot, error)
}

func (resolver subjectTestResolver) ResolveLoginSubject(ctx context.Context, query SubjectLookup) (LoginSubjectSnapshot, error) {
	return resolver.resolve(ctx, query)
}

type subjectTestObserver struct {
	mu      sync.Mutex
	opened  int
	outcome SubjectResolutionOutcome
}

func (observer *subjectTestObserver) SubjectResolutionOpened() {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.opened++
}
func (observer *subjectTestObserver) SubjectResolutionClosed(outcome SubjectResolutionOutcome, _ time.Duration) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.outcome = outcome
}
