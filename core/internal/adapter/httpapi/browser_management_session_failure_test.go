package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identity/sessioncontext"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/platform/ratelimit"
)

type sessionScopeListFunc func(context.Context, accountsession.Session, int, network.ID) (sessioncontext.Page, error)

func (function sessionScopeListFunc) List(ctx context.Context, session accountsession.Session, limit int,
	after network.ID) (sessioncontext.Page, error) {
	return function(ctx, session, limit, after)
}

type sessionCapabilityReadFunc func(context.Context, accountsession.Session) (sessioncontext.DeploymentCapabilities, error)

func (function sessionCapabilityReadFunc) Read(ctx context.Context,
	session accountsession.Session) (sessioncontext.DeploymentCapabilities, error) {
	return function(ctx, session)
}

func serveSessionRead(t *testing.T, options BrowserManagementOptions) *continuationStatusRecorder {
	t.Helper()
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, browserManagementReadRequest(t, AccountSessionPath)); err != nil {
		t.Fatal(err)
	}
	return response
}

// The start read asks for exactly one scope page: the first, of 50.
func TestSessionReadAsksForTheFirstScopePageOnce(t *testing.T) {
	t.Parallel()
	options, _ := browserManagementTestOptions(t)
	scopes := options.Scopes
	calls := 0
	options.Scopes = sessionScopeListFunc(func(ctx context.Context, session accountsession.Session, limit int,
		after network.ID) (sessioncontext.Page, error) {
		calls++
		if limit != defaultManagementScopePageSize || after != (network.ID{}) {
			t.Errorf("scope page asked with limit %d after %v", limit, after)
		}
		return scopes.List(ctx, session, limit, after)
	})
	if response := serveSessionRead(t, options); response.Code != http.StatusOK || calls != 1 {
		t.Fatalf("status %d after %d scope reads", response.Code, calls)
	}
}

func TestSessionReadRefusesAnEndedSessionBeforeAnyRead(t *testing.T) {
	t.Parallel()
	options, fixture := browserManagementTestOptions(t)
	fixture.sessionRevoked = true
	response := serveSessionRead(t, options)
	// Only the source budget was spent: no refund, no Session budget, no read.
	if response.Code != http.StatusUnauthorized || fixture.budgets != 1 || fixture.capabilityReads != 0 ||
		response.Header().Get("Server-Timing") != "" {
		t.Fatalf("ended session = %d, budgets %d, capability reads %d", response.Code, fixture.budgets,
			fixture.capabilityReads)
	}
}

func TestSessionReadStopsAtAnExhaustedBudget(t *testing.T) {
	t.Parallel()
	options, fixture := browserManagementTestOptions(t)
	limiter := managementRateLimiterFunc(func(_ context.Context, _ ratelimit.Subject,
		policy ratelimit.Policy) (ratelimit.Decision, error) {
		return ratelimit.NewDecision(false, policy.Capacity(), 0, policy.RefillInterval())
	})
	options.Management.rateLimiter = limiter
	response := serveSessionRead(t, options)
	if response.Code != http.StatusTooManyRequests || fixture.auth != 0 || fixture.capabilityReads != 0 {
		t.Fatalf("exhausted budget = %d, auth %d, reads %d", response.Code, fixture.auth, fixture.capabilityReads)
	}
}

func TestSessionReadNamesTheHalfThatFailed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name                      string
		capabilitiesErr, scopeErr error
		capabilitiesPanic         bool
		wantStatus                int
		wantCode                  string
	}{
		{"capabilities unavailable", sessioncontext.ErrCapabilitiesUnavailable, nil, false,
			http.StatusServiceUnavailable, "deployment_capabilities_unavailable"},
		{"scopes unavailable", nil, sessioncontext.ErrUnavailable, false,
			http.StatusServiceUnavailable, "management_scopes_unavailable"},
		{"both unavailable", sessioncontext.ErrCapabilitiesUnavailable, sessioncontext.ErrUnavailable, false,
			http.StatusServiceUnavailable, "deployment_capabilities_unavailable"},
		// The Session ended between authentication and the reads: sign in again.
		{"scopes see the Session ended", sessioncontext.ErrCapabilitiesUnavailable, sessioncontext.ErrUnauthenticated,
			false, http.StatusUnauthorized, "unauthenticated"},
		{"capabilities see the Session ended", sessioncontext.ErrCapabilitiesUnauthenticated, sessioncontext.ErrUnavailable,
			false, http.StatusUnauthorized, "unauthenticated"},
		{"capability read panics", nil, nil, true, http.StatusInternalServerError, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options, _ := browserManagementTestOptions(t)
			realScopes, realCapabilities := options.Scopes, options.Capabilities
			options.Scopes = sessionScopeListFunc(func(ctx context.Context, session accountsession.Session, limit int,
				after network.ID) (sessioncontext.Page, error) {
				if test.scopeErr != nil {
					return sessioncontext.Page{}, test.scopeErr
				}
				return realScopes.List(ctx, session, limit, after)
			})
			options.Capabilities = sessionCapabilityReadFunc(func(ctx context.Context,
				session accountsession.Session) (sessioncontext.DeploymentCapabilities, error) {
				if test.capabilitiesPanic {
					panic("capability read")
				}
				if test.capabilitiesErr != nil {
					return sessioncontext.DeploymentCapabilities{}, test.capabilitiesErr
				}
				return realCapabilities.Read(ctx, session)
			})
			response := serveSessionRead(t, options)
			if response.Code != test.wantStatus ||
				test.wantCode != "" && !strings.Contains(response.Body.String(), `"code":"`+test.wantCode+`"`) {
				t.Fatalf("status %d body %s, want %d %s", response.Code, response.Body.String(), test.wantStatus,
					test.wantCode)
			}
		})
	}
}

func TestSessionReadFailureRanksAnEndedSessionFirst(t *testing.T) {
	t.Parallel()
	if _, failed := sessionReadFailure(nil, nil); failed {
		t.Fatal("two successful reads failed")
	}
	unavailable := errors.Join(sessioncontext.ErrCapabilitiesUnavailable, context.DeadlineExceeded)
	if failure, _ := sessionReadFailure(unavailable, sessioncontext.ErrUnauthenticated); failure.Status != http.StatusUnauthorized {
		t.Fatalf("ended Session lost to an outage: %d", failure.Status)
	}
}
