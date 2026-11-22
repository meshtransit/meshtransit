//go:build dexbroker

package dexbroker

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const guardIssuer = "https://sso.example.test:8443/realms/corp"

func guardEndpoints() OIDCProviderEndpoints {
	endpoints := genericTestEndpoints(guardIssuer)
	endpoints.UserInfoURL = guardIssuer + "/protocol/openid-connect/userinfo"
	return endpoints
}

func fakeIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

// guardedTripper routes requests to a fake provider through the bounded
// round tripper with the claim guard on.
func guardedTripper(tokenAuth TokenAuth, provider func(*http.Request, []byte) (int, string)) (
	*boundedOutboundRoundTripper, *atomic.Int32,
) {
	endpoints := guardEndpoints()
	var calls atomic.Int32
	base := outboundRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		var body []byte
		if request.Body != nil {
			body, _ = io.ReadAll(request.Body)
		}
		status, text := provider(request, body)
		header := http.Header{"Content-Type": {"application/json; charset=utf-8"}}
		if request.Header.Get("X-Test-Content-Type") != "" {
			header.Set("Content-Type", request.Header.Get("X-Test-Content-Type"))
		}
		if request.Header.Get("X-Test-Status") == "201" && status == http.StatusOK {
			status = http.StatusCreated
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(text)), Header: header}, nil
	})
	return &boundedOutboundRoundTripper{
		base: base,
		rules: map[string]outboundEndpointRule{
			outboundRuleKey(http.MethodPost, endpoints.TokenURL):   {maxRequestBytes: 4096, maxResponseBytes: 65536},
			outboundRuleKey(http.MethodGet, endpoints.UserInfoURL): {maxResponseBytes: 65536},
		},
		guard: newOutboundClaimGuard(endpoints, tokenAuth),
	}, &calls
}

func tokenRequest(t *testing.T, basic bool, form url.Values) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, guardEndpoints().TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		request.SetBasicAuth("meshtransit", "secret")
	}
	return request
}

func userInfoRequest(t *testing.T, accessToken string) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, guardEndpoints().UserInfoURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	return request
}

func TestClaimGuardPinsTokenAuthentication(t *testing.T) {
	ok := func(*http.Request, []byte) (int, string) { return http.StatusBadRequest, `{"error":"invalid_grant"}` }
	code := url.Values{"grant_type": {"authorization_code"}, "code": {"abc"}}
	withSecret := url.Values{"grant_type": {"authorization_code"}, "code": {"abc"}, "client_secret": {"secret"}}

	tripper, calls := guardedTripper(TokenAuthBasic, ok)
	if response, err := tripper.RoundTrip(tokenRequest(t, true, code)); err != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("basic request = %v", err)
	}
	// oauth2's fallback: the code again, with the secret in the form.
	if _, err := tripper.RoundTrip(tokenRequest(t, false, withSecret)); !errors.Is(err, errOutboundHTTPPolicy) {
		t.Fatalf("form fallback error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("provider saw %d token requests, want 1", calls.Load())
	}

	tripper, calls = guardedTripper(TokenAuthPost, ok)
	if _, err := tripper.RoundTrip(tokenRequest(t, false, withSecret)); err != nil {
		t.Fatalf("post request error = %v", err)
	}
	if _, err := tripper.RoundTrip(tokenRequest(t, true, code)); !errors.Is(err, errOutboundHTTPPolicy) {
		t.Fatalf("header under post error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("provider saw %d token requests, want 1", calls.Load())
	}
}

func TestClaimGuardRequiresUserInfoSubjectOfTheIDToken(t *testing.T) {
	userInfo := `{"sub":"alice","email":"alice@example.test","email_verified":true}`
	provider := func(request *http.Request, _ []byte) (int, string) {
		if request.Method == http.MethodPost {
			return http.StatusOK, `{"access_token":"at-1","token_type":"Bearer","id_token":"` +
				fakeIDToken(t, map[string]any{"sub": "alice"}) + `"}`
		}
		return http.StatusOK, userInfo
	}
	tripper, _ := guardedTripper(TokenAuthBasic, provider)
	code := url.Values{"grant_type": {"authorization_code"}, "code": {"abc"}}
	if _, err := tripper.RoundTrip(tokenRequest(t, true, code)); err != nil {
		t.Fatalf("token error = %v", err)
	}
	if _, err := tripper.RoundTrip(userInfoRequest(t, "at-1")); err != nil {
		t.Fatalf("matching userinfo error = %v", err)
	}
	// The subject is used once; an unknown access token is refused.
	if _, err := tripper.RoundTrip(userInfoRequest(t, "at-1")); !errors.Is(err, errOutboundHTTPPolicy) {
		t.Fatalf("replayed userinfo error = %v", err)
	}
	userInfo = `{"sub":"mallory","email":"alice@example.test","email_verified":true}`
	if _, err := tripper.RoundTrip(tokenRequest(t, true, code)); err != nil {
		t.Fatalf("token error = %v", err)
	}
	if _, err := tripper.RoundTrip(userInfoRequest(t, "at-1")); !errors.Is(err, errOutboundHTTPPolicy) {
		t.Fatalf("other subject error = %v", err)
	}
}

func TestClaimGuardRefusesEmailVerifiedThatIsNotBoolean(t *testing.T) {
	cases := map[string]struct {
		idToken  map[string]any
		userInfo string
	}{
		"id token string": {idToken: map[string]any{"sub": "alice", "email_verified": "false"}},
		"userinfo string": {
			idToken:  map[string]any{"sub": "alice"},
			userInfo: `{"sub":"alice","email_verified":"false"}`,
		},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			provider := func(request *http.Request, _ []byte) (int, string) {
				if request.Method == http.MethodPost {
					return http.StatusOK, `{"access_token":"at-1","id_token":"` + fakeIDToken(t, test.idToken) + `"}`
				}
				return http.StatusOK, test.userInfo
			}
			tripper, _ := guardedTripper(TokenAuthBasic, provider)
			code := url.Values{"grant_type": {"authorization_code"}, "code": {"abc"}}
			_, tokenErr := tripper.RoundTrip(tokenRequest(t, true, code))
			if test.userInfo == "" {
				if !errors.Is(tokenErr, errOutboundHTTPPolicy) {
					t.Fatalf("token error = %v", tokenErr)
				}
				return
			}
			if tokenErr != nil {
				t.Fatalf("token error = %v", tokenErr)
			}
			if _, err := tripper.RoundTrip(userInfoRequest(t, "at-1")); !errors.Is(err, errOutboundHTTPPolicy) {
				t.Fatalf("userinfo error = %v", err)
			}
		})
	}
}

func TestClaimGuardChecksEveryTokenSuccessAndOnlyJSON(t *testing.T) {
	stringVerified := func(request *http.Request, _ []byte) (int, string) {
		return http.StatusOK, `{"access_token":"at-1","id_token":"` +
			fakeIDToken(t, map[string]any{"sub": "alice", "email_verified": "false"}) + `"}`
	}
	code := url.Values{"grant_type": {"authorization_code"}, "code": {"abc"}}
	tripper, _ := guardedTripper(TokenAuthBasic, stringVerified)
	created := tokenRequest(t, true, code)
	created.Header.Set("X-Test-Status", "201")
	if _, err := tripper.RoundTrip(created); !errors.Is(err, errOutboundHTTPPolicy) {
		t.Fatalf("201 token response error = %v", err)
	}
	valid := func(*http.Request, []byte) (int, string) {
		return http.StatusOK, `{"access_token":"at-1","id_token":"` + fakeIDToken(t, map[string]any{"sub": "alice"}) + `"}`
	}
	tripper, _ = guardedTripper(TokenAuthBasic, valid)
	form := tokenRequest(t, true, code)
	form.Header.Set("X-Test-Content-Type", "text/plain")
	if _, err := tripper.RoundTrip(form); !errors.Is(err, errOutboundHTTPPolicy) {
		t.Fatalf("text/plain token response error = %v", err)
	}
	// Keys are exact: ID_TOKEN is not the id_token oauth2 reads.
	upper := func(*http.Request, []byte) (int, string) {
		return http.StatusOK, `{"access_token":"at-1","id_token":"` + fakeIDToken(t, map[string]any{"sub": "alice", "email_verified": "no"}) +
			`","ID_TOKEN":"` + fakeIDToken(t, map[string]any{"sub": "alice"}) + `"}`
	}
	tripper, _ = guardedTripper(TokenAuthBasic, upper)
	if _, err := tripper.RoundTrip(tokenRequest(t, true, code)); !errors.Is(err, errOutboundHTTPPolicy) {
		t.Fatalf("case-folded key error = %v", err)
	}
	if _, ok := idTokenClaims(`{"payload":"e30","signatures":[]}`); ok {
		t.Fatal("a JSON-serialised JWS was decoded")
	}
}

func TestClaimGuardEvictsTheOldestSubject(t *testing.T) {
	guard := newOutboundClaimGuard(guardEndpoints(), TokenAuthBasic)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	guard.now = func() time.Time { return now }
	for index := range claimGuardMaximumSubjects {
		now = now.Add(time.Millisecond)
		guard.remember("token-"+strconv.Itoa(index), "user")
	}
	guard.remember("newest", "user")
	if _, ok := guard.take("newest"); !ok {
		t.Fatal("a full map refused the newest login")
	}
	if _, ok := guard.take("token-0"); ok {
		t.Fatal("the oldest subject was kept")
	}
}

func TestClaimGuardForgetsExpiredSubjects(t *testing.T) {
	guard := newOutboundClaimGuard(guardEndpoints(), TokenAuthBasic)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	guard.now = func() time.Time { return now }
	guard.remember("at-1", "alice")
	now = now.Add(claimGuardSubjectLifetime)
	if _, ok := guard.take("at-1"); ok {
		t.Fatal("an expired subject was used")
	}
}

func TestSharedAddressSpaceNeedsASubRange(t *testing.T) {
	if validPrivateNetwork(sharedAddressSpace) {
		t.Fatal("all of 100.64/10 was allowed")
	}
	if !validPrivateNetwork(netip.MustParsePrefix("100.80.0.0/16")) {
		t.Fatal("a range inside 100.64/10 was refused")
	}
	if validPrivateNetwork(netip.MustParsePrefix("100.64.0.0/11")) {
		t.Fatal("half of 100.64/10 was allowed")
	}
	for _, address := range []string{"100.100.100.100", "168.63.129.16", "::ffff:0:a14:105", "fec0::1"} {
		if validOutboundIP(netip.MustParseAddr(address), []netip.Prefix{sharedAddressSpace, netip.MustParsePrefix("10.0.0.0/8")}) {
			t.Fatalf("%s was reachable", address)
		}
	}
}
