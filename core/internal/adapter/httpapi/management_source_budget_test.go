package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/node/revocation"
	"meshtransit.net/core/internal/platform/ratelimit"
)

// budgetRecorder is a limiter that records each spend and each refund.
type budgetRecorder struct {
	mu        sync.Mutex
	calls     []string
	exhausted map[ratelimit.SubjectKind]bool
	// refundLive records whether each refund ran on a live context.
	refundLive []bool
}

func (recorder *budgetRecorder) decide(op string, subject ratelimit.Subject, policy ratelimit.Policy) (ratelimit.Decision, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.calls = append(recorder.calls, op+":"+string(subject.Kind()))
	if recorder.exhausted[subject.Kind()] {
		return ratelimit.NewDecision(false, policy.Capacity(), 0, 1500*time.Millisecond)
	}
	return ratelimit.NewDecision(true, policy.Capacity(), policy.Capacity()-1, 0)
}

func (recorder *budgetRecorder) Allow(_ context.Context, subject ratelimit.Subject, policy ratelimit.Policy) (ratelimit.Decision, error) {
	return recorder.decide("charge", subject, policy)
}

func (recorder *budgetRecorder) Refund(ctx context.Context, subject ratelimit.Subject, _ ratelimit.Policy) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.calls = append(recorder.calls, "refund:"+string(subject.Kind()))
	recorder.refundLive = append(recorder.refundLive, ctx.Err() == nil)
	return nil
}

// TD-CORE-138: every request spends a source token before authenticating,
// as before; a valid session gets it back and spends its own budget, so a
// failed (or abandoned) authentication is what the source budget counts.
func TestManagementHandlerRefundsTheSourceToAValidSession(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		exhausted ratelimit.SubjectKind
		authErr   error
		status    int
		want      []string
	}{
		{
			name: "valid session", status: http.StatusOK,
			want: []string{"charge:" + string(ratelimit.SubjectSource), "refund:" + string(ratelimit.SubjectSource),
				"charge:" + string(ratelimit.SubjectAccountSession)},
		},
		{
			name: "failed authentication", authErr: accountsession.ErrUnauthenticated, status: http.StatusUnauthorized,
			want: []string{"charge:" + string(ratelimit.SubjectSource)},
		},
		{
			name: "source exhausted by failures", exhausted: ratelimit.SubjectSource, status: http.StatusTooManyRequests,
			want: []string{"charge:" + string(ratelimit.SubjectSource)},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			recorder := &budgetRecorder{exhausted: map[ratelimit.SubjectKind]bool{test.exhausted: true}}
			options := validManagementHandlerOptions(t)
			options.RateLimiter = recorder
			options.Sessions = managementSessionAuthenticatorFunc(func(context.Context, accountsession.Token) (accountsession.Session, error) {
				if test.authErr != nil {
					return accountsession.Session{}, test.authErr
				}
				return managementSessionFixture(t), nil
			})
			options.Revocations = managementDeviceRevokerFunc(func(_ context.Context, command revocation.Command) (revocation.Result, error) {
				return managementResultFixture(t, command), nil
			})
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, newManagementRequest(t, http.MethodPost, validManagementPath(),
				`{"reason":"compromised device"}`))
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.status, response.Body.String())
			}
			if !slices.Equal(recorder.calls, test.want) {
				t.Fatalf("limiter calls = %v, want %v", recorder.calls, test.want)
			}
		})
	}
}

// The same holds for the Console's cookie path (browser management).
func TestBrowserManagementRefundsTheSourceToAValidSession(t *testing.T) {
	t.Parallel()
	for _, revoked := range []bool{false, true} {
		options, fixture := browserManagementTestOptions(t)
		recorder := &budgetRecorder{}
		options.Management.rateLimiter = recorder
		fixture.sessionRevoked = revoked
		browser, err := NewBrowserManagement(options)
		if err != nil {
			t.Fatal(err)
		}
		response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		if err := browser.Handle(response, browserManagementReadRequest(t, AccountSessionManagementScopesPath)); err != nil {
			t.Fatal(err)
		}
		want := []string{"charge:" + string(ratelimit.SubjectSource), "refund:" + string(ratelimit.SubjectSource),
			"charge:" + string(ratelimit.SubjectAccountSession)}
		if revoked {
			want = []string{"charge:" + string(ratelimit.SubjectSource)}
		}
		if !slices.Equal(recorder.calls, want) {
			t.Fatalf("revoked=%t: limiter calls = %v, want %v (status %d)", revoked, recorder.calls, want, response.Code)
		}
	}
}

// A client that goes away once authenticated still gets its source token
// back: the refund does not run on the request's (cancelled) context.
func TestRefundOutlivesTheRequest(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	recorder := &budgetRecorder{}
	options.RateLimiter = recorder
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	handler.refundAuthenticated(ctx, continuationBudget{
		kind: ratelimit.SubjectSource, raw: "192.0.2.10", policy: options.SourceRateLimit,
	})
	if len(recorder.refundLive) != 1 || !recorder.refundLive[0] {
		t.Fatalf("refunds on a live context = %v, want [true]", recorder.refundLive)
	}
}
