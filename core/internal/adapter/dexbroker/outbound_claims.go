//go:build dexbroker

package dexbroker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The claim guard holds the provider to what V1-22 pins, in the broker's own
// HTTP client, without changing Dex (v1-22-generic-oidc-design.md §2.1, §3a):
//
//   - token_auth basic or post: the client secret goes only the pinned way.
//     oauth2 otherwise retries a failed header request with the secret in
//     the form, sending the authorization code twice.
//   - userinfo: its "sub" must be the ID token's (OIDC Core §5.3.2). Dex
//     merges userinfo claims over the ID token's and go-oidc does not
//     compare the two, so a differing userinfo would choose the subject.
//   - email_verified, when present, must be a JSON boolean: Dex treats any
//     other type as absent, which "email: assume" turns into verified.
//
// It only ever refuses; whatever it lets through, Dex still verifies. It
// relies on the broker allowing only the authorization_code grant
// (component.go): a refresh or token exchange would reach userinfo without a
// token response, which the guard refuses.

const (
	// The token response and the userinfo call follow each other at once.
	claimGuardSubjectLifetime = time.Minute
	claimGuardMaximumSubjects = 4096
	claimGuardMaximumSubject  = 255
)

type outboundClaimGuard struct {
	tokenAuth   TokenAuth
	tokenURL    string
	userInfoURL string

	mu       sync.Mutex
	subjects map[[sha256.Size]byte]guardedSubject
	now      func() time.Time
}

type guardedSubject struct {
	subject string
	expires time.Time
}

func newOutboundClaimGuard(endpoints OIDCProviderEndpoints, tokenAuth TokenAuth) *outboundClaimGuard {
	return &outboundClaimGuard{
		tokenAuth: tokenAuth, tokenURL: endpoints.TokenURL, userInfoURL: endpoints.UserInfoURL,
		subjects: map[[sha256.Size]byte]guardedSubject{}, now: time.Now,
	}
}

// checkRequest enforces token_auth on a token request and returns the body
// to forward.
func (guard *outboundClaimGuard) checkRequest(request *http.Request, body []byte) bool {
	if guard == nil || request.Method != http.MethodPost || request.URL.String() != guard.tokenURL ||
		guard.tokenAuth == TokenAuthProbe {
		return true
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return false
	}
	_, basic := strings.CutPrefix(request.Header.Get("Authorization"), "Basic ")
	inForm := form.Has("client_secret")
	switch guard.tokenAuth {
	case TokenAuthBasic:
		return basic && !inForm
	case TokenAuthPost:
		return !basic && inForm && request.Header.Get("Authorization") == ""
	default:
		return false
	}
}

// checkResponse inspects a successful token or userinfo response: oauth2
// takes any 2xx token response, go-oidc only a 200 userinfo one.
func (guard *outboundClaimGuard) checkResponse(request *http.Request, response *http.Response, body []byte) bool {
	if guard == nil {
		return true
	}
	switch endpoint := request.URL.String(); {
	case request.Method == http.MethodPost && endpoint == guard.tokenURL:
		if response.StatusCode < 200 || response.StatusCode > 299 {
			return true
		}
		return jsonMediaType(response.Header.Get("Content-Type")) && guard.checkTokenResponse(body)
	case request.Method == http.MethodGet && guard.userInfoURL != "" && endpoint == guard.userInfoURL:
		return response.StatusCode != http.StatusOK || guard.checkUserInfo(request, body)
	default:
		return true
	}
}

// jsonMediaType is application/json with parameters at most: oauth2 parses
// any other type as a form, which the guard would read differently.
func jsonMediaType(value string) bool {
	mediaType, _, _ := strings.Cut(value, ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/json")
}

func (guard *outboundClaimGuard) checkTokenResponse(body []byte) bool {
	// Exact keys, as oauth2's token.Extra reads them.
	var response map[string]any
	if json.Unmarshal(body, &response) != nil {
		return false
	}
	idToken, _ := response["id_token"].(string)
	accessToken, _ := response["access_token"].(string)
	if idToken == "" {
		// Dex refuses a code response without an ID token.
		return true
	}
	claims, ok := idTokenClaims(idToken)
	if !ok || !emailVerifiedIsBoolean(claims) {
		return false
	}
	if guard.userInfoURL == "" {
		return true
	}
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" || len(subject) > claimGuardMaximumSubject || accessToken == "" {
		return false
	}
	guard.remember(accessToken, subject)
	return true
}

func (guard *outboundClaimGuard) checkUserInfo(request *http.Request, body []byte) bool {
	token, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return false
	}
	expected, known := guard.take(token)
	var claims map[string]any
	if !known || json.Unmarshal(body, &claims) != nil {
		return false
	}
	subject, ok := claims["sub"].(string)
	return ok && subject == expected && emailVerifiedIsBoolean(claims)
}

func (guard *outboundClaimGuard) remember(accessToken, subject string) {
	key := sha256.Sum256([]byte(accessToken))
	now := guard.now()
	guard.mu.Lock()
	defer guard.mu.Unlock()
	var oldest [sha256.Size]byte
	var oldestExpiry time.Time
	for stored, value := range guard.subjects {
		if !now.Before(value.expires) {
			delete(guard.subjects, stored)
			continue
		}
		if oldestExpiry.IsZero() || value.expires.Before(oldestExpiry) {
			oldest, oldestExpiry = stored, value.expires
		}
	}
	if len(guard.subjects) >= claimGuardMaximumSubjects {
		// Abandoned callbacks must not lock out new logins: the oldest
		// entry goes, and its login fails closed at userinfo.
		delete(guard.subjects, oldest)
	}
	guard.subjects[key] = guardedSubject{subject: subject, expires: now.Add(claimGuardSubjectLifetime)}
}

// take returns and forgets the subject the token response named.
func (guard *outboundClaimGuard) take(accessToken string) (string, bool) {
	key := sha256.Sum256([]byte(accessToken))
	guard.mu.Lock()
	defer guard.mu.Unlock()
	value, ok := guard.subjects[key]
	delete(guard.subjects, key)
	if !ok || !guard.now().Before(value.expires) {
		return "", false
	}
	return value.subject, true
}

// idTokenClaims decodes, without verifying, the payload of a compact JWS.
// Dex verifies the token afterwards; the guard only uses it to refuse.
func idTokenClaims(token string) (map[string]any, bool) {
	// Compact serialisation only: go-jose also takes the JSON form and
	// strips whitespace, which the guard would split differently.
	if strings.HasPrefix(token, "{") || strings.ContainsAny(token, " \t\r\n") {
		return nil, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if decoder.Decode(&claims) != nil {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return claims, true
}

func emailVerifiedIsBoolean(claims map[string]any) bool {
	value, present := claims["email_verified"]
	if !present {
		return true
	}
	_, ok := value.(bool)
	return ok
}
