package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/meshtransit/meshtransit/api/openapi"
	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/identity/sessioncontext"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node/revocation"
	"github.com/meshtransit/meshtransit/internal/policy"
	policyapproval "github.com/meshtransit/meshtransit/internal/policy/approval"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
	policypublication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestComposePrivateIdentityRejectsAbsentInput(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		context context.Context
	}{
		{name: "absent context"},
		{name: "absent resident keys", context: t.Context()},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root, err := composePrivateIdentity(test.context, nil, privateIdentityOptions{}, privateIdentityPorts{})
			if root != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) {
				t.Fatal("incomplete private root released authority")
			}
		})
	}
}

func TestComposePrivateIdentityIsEffectFreeAndOwnsCompleteGraph(t *testing.T) {
	t.Parallel()
	fixture := newPrivateIdentityFixture(t)
	root := fixture.compose(t)
	if root.start == nil || root.callback == nil || root.sessions == nil || root.logout == nil || root.login == nil ||
		root.management == nil || root.metrics == nil || len(fixture.effects) != 0 || fixture.clockReads != 0 {
		t.Fatal("construction performed effects or released a partial graph")
	}
	// Two roots with identical metric descriptors must remain independent, never
	// collide through a global registry or inherit one another's observations.
	other := fixture.compose(t)
	if root.metrics == other.metrics {
		t.Fatal("roots share a registry")
	}
	if _, err := root.metrics.Gather(); err != nil {
		t.Fatal("root metric registration is not pedantic", err)
	}
	if fixture.clockReads != 0 || len(fixture.effects) != 0 {
		t.Fatal("gather touched authority or clock")
	}
}

func TestComposePrivateIdentityRejectsTypedNilEffectsBeforeWork(t *testing.T) {
	t.Parallel()
	var missing *privateIdentityFixture
	var missingMetadata *privateIdentityMetadata
	var missingAuthority *privateIdentityAuthority
	var missingScopes *privateIdentityManagementScopes
	var missingCapabilities *privateIdentityManagementCapabilities
	for _, test := range []struct {
		name   string
		change func(*privateIdentityPorts)
	}{
		{name: "admission", change: func(p *privateIdentityPorts) { p.Admission = missing }},
		{name: "metadata", change: func(p *privateIdentityPorts) { p.Metadata = missingMetadata }},
		{name: "creation clock", change: func(p *privateIdentityPorts) { p.CreationClock = missing }},
		{name: "creation", change: func(p *privateIdentityPorts) { p.Creations = missing }},
		{name: "committed lookup", change: func(p *privateIdentityPorts) { p.Committed = missing }},
		{name: "pending", change: func(p *privateIdentityPorts) { p.Pending = missing }},
		{name: "claim", change: func(p *privateIdentityPorts) { p.Claims = missing }},
		{name: "failure", change: func(p *privateIdentityPorts) { p.Failures = missing }},
		{name: "issue", change: func(p *privateIdentityPorts) { p.Issues = missing }},
		{name: "provider", change: func(p *privateIdentityPorts) { p.Provider = missing }},
		{name: "subjects", change: func(p *privateIdentityPorts) { p.Subjects = missing }},
		{name: "session authority", change: func(p *privateIdentityPorts) { p.SessionAuthority = missingAuthority }},
		{name: "session revocations", change: func(p *privateIdentityPorts) { p.SessionRevocations = missingAuthority }},
		{name: "session scopes", change: func(p *privateIdentityPorts) { p.SessionScopes = missingScopes }},
		{name: "session capabilities", change: func(p *privateIdentityPorts) { p.SessionCapabilities = missingCapabilities }},
		{name: "start ids", change: func(p *privateIdentityPorts) { p.StartIDs = missing }},
		{name: "secrets", change: func(p *privateIdentityPorts) { p.Secrets = missing }},
		{name: "claim ids", change: func(p *privateIdentityPorts) { p.ClaimIDs = missing }},
		{name: "issue material", change: func(p *privateIdentityPorts) { p.IssueMaterial = missing }},
		{name: "revocations", change: func(p *privateIdentityPorts) { p.Revocations = missing }},
		{name: "policy publications", change: func(p *privateIdentityPorts) { p.PolicyPublications = missing }},
		{name: "limiter", change: func(p *privateIdentityPorts) { p.RateLimiter = missing }},
		{name: "correlation ids", change: func(p *privateIdentityPorts) { p.CorrelationIDs = missing }},
		{name: "clock", change: func(p *privateIdentityPorts) { p.Clock = missing }},
		{name: "resource creations", change: func(p *privateIdentityPorts) {
			var missing *privateIdentityResourcePorts
			p.ResourceCreations = missing
		}},
		{name: "resource catalog", change: func(p *privateIdentityPorts) { var missing *privateIdentityResourcePorts; p.ResourceCatalog = missing }},
		{name: "resource sharing", change: func(p *privateIdentityPorts) { var missing *privateIdentityResourcePorts; p.ResourceSharing = missing }},
		{name: "logger", change: func(p *privateIdentityPorts) { p.Logger = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newPrivateIdentityFixture(t)
			test.change(&fixture.ports)
			root, err := composePrivateIdentity(t.Context(), fixture.keys, fixture.options, fixture.ports)
			if root != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) ||
				len(fixture.effects) != 0 || fixture.clockReads != 0 {
				t.Fatal("typed nil effect accepted or constructor did work")
			}
		})
	}
}

func TestComposePrivateIdentityRejectsUnsafeProfilesAndResidentDrift(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*privateIdentityFixture)
	}{
		{name: "zero route", change: func(f *privateIdentityFixture) { f.options.Route = oidcauth.Route{} }},
		{name: "foreign origin", change: func(f *privateIdentityFixture) {
			f.options.Origin = "https://foreign.example.test"
		}},
		{name: "return navigation", change: func(f *privateIdentityFixture) {
			f.options.ReturnPath = "//foreign.example.test"
		}},
		{name: "start window above http", change: func(f *privateIdentityFixture) {
			f.options.Start.RequestTimeout = 6 * time.Second
		}},
		{name: "callback window above http", change: func(f *privateIdentityFixture) {
			f.options.Callback.RequestTimeout = 26 * time.Second
		}},
		{name: "zero start window", change: func(f *privateIdentityFixture) { f.options.Start.RequestTimeout = 0 }},
		{name: "zero callback capacity", change: func(f *privateIdentityFixture) { f.options.Callback.MaxConcurrent = 0 }},
		{name: "long rollback", change: func(f *privateIdentityFixture) {
			f.options.Callback.RollbackTimeout = 6 * time.Second
		}},
		{name: "fractional session ttl", change: func(f *privateIdentityFixture) {
			f.options.Callback.IdleLifetime += time.Nanosecond
		}},
		{name: "browser capacity", change: func(f *privateIdentityFixture) { f.options.Browser.MaxConcurrent = 129 }},
		{name: "cookie capacity", change: func(f *privateIdentityFixture) { f.options.Management.MaxConcurrent = 129 }},
		{name: "cookie proof ttl", change: func(f *privateIdentityFixture) {
			f.options.Management.ProofLifetime = 29 * time.Second
		}},
		{name: "cookie timeout", change: func(f *privateIdentityFixture) {
			f.options.Management.RequestTimeout = 31 * time.Second
		}},
		{name: "missing source policy", change: func(f *privateIdentityFixture) {
			f.options.Browser.SourceRateLimit = ratelimit.Policy{}
		}},
		{name: "missing session policy", change: func(f *privateIdentityFixture) {
			f.options.Management.SessionRateLimit = ratelimit.Policy{}
		}},
		{name: "proxy all", change: func(f *privateIdentityFixture) {
			f.options.Browser.TrustedProxyPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		}},
		{name: "transaction key zero", change: func(f *privateIdentityFixture) { f.keys.transaction = oidcauth.DigestKey{} }},
		{name: "verifier absent", change: func(f *privateIdentityFixture) { f.keys.verifier = nil }},
		{name: "subject ring absent", change: func(f *privateIdentityFixture) { f.keys.subjects = nil }},
		{name: "session ring zero", change: func(f *privateIdentityFixture) { f.keys.sessions = &accountsession.Keyring{} }},
		{name: "provider session zero", change: func(f *privateIdentityFixture) {
			f.keys.providerSessions = oidcauth.ProviderSessionKey{}
		}},
		{name: "rate key absent", change: func(f *privateIdentityFixture) { f.keys.rateLimit = nil }},
		{name: "idempotency key absent", change: func(f *privateIdentityFixture) { f.keys.idempotency = nil }},
		{name: "csrf aliases capture", change: func(f *privateIdentityFixture) {
			f.keys.csrf.Material = f.keys.capture.Material
		}},
		{name: "csrf id aliases initiation", change: func(f *privateIdentityFixture) {
			f.keys.csrf.ID = f.keys.initiation.ID
		}},
		{name: "csrf zero", change: func(f *privateIdentityFixture) { clear(f.keys.csrf.Material) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newPrivateIdentityFixture(t)
			test.change(fixture)
			root, err := composePrivateIdentity(t.Context(), fixture.keys, fixture.options, fixture.ports)
			if root != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) ||
				len(fixture.effects) != 0 || fixture.clockReads != 0 {
				t.Fatal("unsafe private profile released a partial root or performed effects")
			}
		})
	}
}

func TestComposePrivateIdentityWithholdsCanceledConstruction(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"before construction", "during construction"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newPrivateIdentityFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var caller = ctx
			if name == "before construction" {
				cancel()
			} else {
				caller = privateIdentityCancelOnDone{Context: ctx, cancel: cancel}
			}
			root, err := composePrivateIdentity(caller, fixture.keys, fixture.options, fixture.ports)
			if root != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) ||
				len(fixture.effects) != 0 || fixture.clockReads != 0 || ctx.Err() == nil {
				t.Fatal("canceled construction released a graph or performed effects")
			}
		})
	}
}

type privateIdentityCancelOnDone struct {
	context.Context
	cancel context.CancelFunc
}

func (caller privateIdentityCancelOnDone) Done() <-chan struct{} {
	caller.cancel()
	return caller.Context.Done()
}

func TestPrivateIdentitySharesCreationCallbackAndSessionKeys(t *testing.T) {
	t.Parallel()
	fixture := newPrivateIdentityFixture(t)
	root := fixture.compose(t)
	result := fixture.issue(t, root)
	token := result.Issued().Token()
	expected, err := fixture.keys.sessions.ActiveDigest(token)
	if err != nil || expected != fixture.tokenDigest {
		t.Fatal("issuance did not use the prepared Session owner", err)
	}
	if fixture.subjectDigest.KeyID().String() != "subject-v1" ||
		fixture.providerSessionDigest.KeyID().String() != "provider-session-v1" {
		t.Fatal("subject/provider Session purposes substituted")
	}
	session, err := root.sessions.Authenticate(t.Context(), token)
	if err != nil || session.ID() != result.Issued().Session().ID() || fixture.authorityReads != 1 {
		t.Fatal("newly issued Session cannot authenticate through the same resident ring", err)
	}
	if fixture.pending.StateDigest().KeyID().String() != "transaction-v1" ||
		fixture.pending.VerifierCiphertext().KeyID().String() != "verifier-v1" {
		t.Fatal("creation used an independent crypto profile")
	}
	if got := fixture.effects; !slices.Equal(got, []string{
		"metadata", "start_ids", "secrets", "begin_create", "create", "commit_create",
		"pending", "claim_ids", "begin_claim", "claim", "commit_claim",
		"provider", "subject", "issue_material", "begin_issue", "issue", "commit_issue", "session",
	}) {
		t.Fatal("private root changed application ordering or effects", got)
	}
	// Authority is reloaded, not cached from issuance or the previous authentication.
	fixture.authorityFound = false
	if _, err := root.sessions.Authenticate(t.Context(), token); !errors.Is(err, accountsession.ErrUnauthenticated) ||
		fixture.authorityReads != 3 { // Active and explicit previous candidate both miss.
		t.Fatal("revoked authority was cached or previous-key bound changed")
	}
}

func TestPrivateIdentityBrowserUsesCopiedKeysAndNoGrantCapture(t *testing.T) {
	t.Parallel()
	fixture := newPrivateIdentityFixture(t)
	root := fixture.compose(t)
	// All four adapters must have copied resident caller-owned browser buffers.
	clear(fixture.keys.initiation.Material)
	clear(fixture.keys.capture.Material)
	clear(fixture.keys.continuation.Material)
	clear(fixture.keys.csrf.Material)
	request := fixture.loginRequest(t, httpapi.LoginPreparePath)
	response := newPrivateIdentityResponse()
	root.login.Initiation().ServeHTTP(response, request)
	var prepared struct {
		Proof string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &prepared); err != nil || prepared.Proof == "" ||
		response.Code != http.StatusOK || !slices.Equal(fixture.effects, []string{"budget", "admit"}) {
		t.Fatal("browser preparation granted authority or failed after caller key erasure", err)
	}
	request = fixture.loginRequest(t, httpapi.LoginStartPath)
	request.Header.Set(oidc.LoginCSRFHeader, prepared.Proof)
	for _, cookie := range response.Result().Cookies() {
		request.AddCookie(cookie)
	}
	response = newPrivateIdentityResponse()
	root.login.Initiation().ServeHTTP(response, request)
	var started struct {
		URL string `json:"authorization_url"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &started); err != nil || response.Code != http.StatusOK {
		t.Fatal("browser did not use the real configured Start service", err)
	}
	location, err := url.Parse(started.URL)
	if err != nil || location.Query().Get("state") != fixture.secrets.State().Encoded() {
		t.Fatal("browser creation lost exact state", err)
	}
	callback, err := url.Parse(fixture.options.Route.RedirectURI())
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{
		"state": []string{fixture.secrets.State().Encoded()}, "iss": []string{fixture.options.Route.Issuer()},
		"code": []string{"synthetic-private-code"},
	}.Encode()
	request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, callback.Path+"?"+query, nil)
	request.Host, request.RemoteAddr = callback.Host, "192.0.2.9:12345"
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.AddCookie(&http.Cookie{
		Name: oidc.PreAuthCookieName, Value: fixture.secrets.PreAuthCookie().Encoded(),
		Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	before := len(fixture.effects)
	response = newPrivateIdentityResponse()
	if err := root.login.Capture(response, request); err != nil || response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != httpapi.LoginCallbackContinuePath || response.Body.Len() != 0 ||
		!slices.Equal(fixture.effects[before:], []string{"budget", "budget"}) {
		t.Fatal("GET capture invoked application authority or lost copied capture key", err)
	}
	if slices.Contains(fixture.effects, "pending") || slices.Contains(fixture.effects, "provider") ||
		slices.Contains(fixture.effects, "issue") || strings.Contains(response.Header().Get("Location"), query) {
		t.Fatal("capture verified/exchanged/issued authority or reflected the transient query")
	}
}

func TestPrivateIdentityCallbackRetainsNoGrantAndUncertaintyRules(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"provider error", "unknown claim commit", "unknown issue commit", "exclusive pending expiry",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newPrivateIdentityFixture(t)
			root := fixture.compose(t)
			command := fixture.startCommand(t, root)
			if name == "provider error" {
				var err error
				command, err = oidcauth.NewCallbackCommand(oidcauth.CallbackCommandParams{
					Route: fixture.options.Route, State: fixture.secrets.State(), PreAuthCookie: fixture.secrets.PreAuthCookie(),
					Kind: oidcauth.CallbackProviderErrorReceived,
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if name == "unknown claim commit" {
				fixture.unknownCommit = "claim"
			}
			if name == "unknown issue commit" {
				fixture.unknownCommit = "issue"
			}
			if name == "exclusive pending expiry" {
				fixture.now = fixture.pending.ExpiresAt()
			}
			before := len(fixture.effects)
			result, err := root.callback.CompleteBrowser(t.Context(), command)
			effects := fixture.effects[before:]
			if name == "provider error" {
				invalidResult := err != nil || !result.Failure().IsValid() || result.Issued().IsValid()
				unexpectedEffects := slices.Contains(effects, "provider") || slices.Contains(effects, "issue") ||
					!slices.Contains(effects, "commit_failure")
				if invalidResult || unexpectedEffects {
					t.Fatal("provider error exchanged or issued authority", err)
				}
			} else if err == nil || !reflect.DeepEqual(result, oidcauth.CallbackResult{}) {
				t.Fatal("uncertainty or exclusive expiry released authority")
			}
			if name == "unknown claim commit" &&
				(slices.Contains(effects, "provider") || slices.Contains(effects, "begin_failure")) {
				t.Fatal("uncertain claim produced another privileged effect")
			}
			if name == "unknown issue commit" &&
				(slices.Contains(effects, "begin_failure") || slices.Contains(effects, "begin_create")) {
				t.Fatal("uncertain issuance retried or terminalized possible committed authority")
			}
			if name == "exclusive pending expiry" && slices.Contains(effects, "begin_claim") {
				t.Fatal("expired pending evidence reached claim")
			}
		})
	}
}

func TestPrivateIdentityCookieManagementUsesFreshSessionAndResidentBudgets(t *testing.T) {
	t.Parallel()
	fixture := newPrivateIdentityFixture(t)
	root := fixture.compose(t)
	issued := fixture.issue(t, root).Issued()
	request := fixture.managementRequest(t, issued.Token(), httpapi.AccountSessionCSRFPreparePath, "{}")
	response := newPrivateIdentityResponse()
	if err := root.management.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	var prepared struct {
		Proof     string `json:"csrf_token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &prepared); err != nil || prepared.Proof == "" ||
		prepared.ExpiresAt == "" || response.Code != http.StatusOK || fixture.authorityReads != 1 {
		t.Fatal("cookie management did not freshly authenticate the issued Session", err)
	}
	if !strings.HasPrefix(prepared.Proof, "mtscsrf1.csrf-v1.") || response.Header().Get("Set-Cookie") != "" ||
		strings.Contains(response.Body.String(), issued.Token().Encoded()) {
		t.Fatal("cookie prepare used the wrong purpose or disclosed/renewed a credential")
	}
	if len(fixture.budgets) != 2 {
		t.Fatal("cookie prepare skipped shared budgets")
	}
	expected, err := fixture.keys.rateLimit.Subject(ratelimit.SubjectSource,
		"browser-session-prepare-source/v1\x00"+fixture.options.Route.DeploymentID().String()+"\x00192.0.2.9")
	if err != nil || fixture.budgets[0] != expected {
		t.Fatal("source counter profile substituted", err)
	}
	sessionCounter := "browser-session-prepare-session/v1\x00" + fixture.options.Route.DeploymentID().String() +
		"\x00" + issued.Session().ID().String()
	expected, err = fixture.keys.rateLimit.Subject(ratelimit.SubjectAccountSession, sessionCounter)
	if err != nil || fixture.budgets[1] != expected {
		t.Fatal("Session counter profile substituted", err)
	}
	request = fixture.managementRequest(
		t, issued.Token(), privateIdentityRevokePath(fixture.options.Route), `{"reason":"compromised peer"}`,
	)
	request.Header.Set("X-MeshTransit-CSRF", prepared.Proof)
	response = newPrivateIdentityResponse()
	if err := root.management.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	expectedProof, err := fixture.keys.idempotency.Proof("private-root-intent")
	if err != nil || fixture.revokeCommand.IdempotencyEvidence() != expectedProof ||
		fixture.revokeCommand.AccountSession().ID() != issued.Session().ID() || fixture.authorityReads != 2 {
		t.Fatal("resource mutation did not receive resident replay evidence and freshly authenticated Session", err)
	}
	if response.Code < 500 || strings.Contains(response.Body.String(), "private controlled") ||
		strings.Contains(response.Body.String(), issued.Token().Encoded()) {
		t.Fatal("controlled effect failure leaked private diagnostics or credentials")
	}
	// The proof is intent transport, never a revocation lease or cached identity.
	fixture.authorityFound = false
	before := len(fixture.effects)
	request = fixture.managementRequest(
		t, issued.Token(), privateIdentityRevokePath(fixture.options.Route), `{"reason":"compromised peer"}`,
	)
	request.Header.Set("X-MeshTransit-CSRF", prepared.Proof)
	response = newPrivateIdentityResponse()
	if err := root.management.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusUnauthorized || fixture.authorityReads != 4 ||
		slices.Contains(fixture.effects[before:], "revoke") || response.Header().Get("Www-Authenticate") != "" {
		t.Fatal("prepared proof bypassed current Session revocation or fell back to Bearer")
	}
}

func TestPrivateIdentityCookieManagementMatchesCompiledProfile(t *testing.T) {
	t.Parallel()
	document, err := openapi.ManagementDocument(openapi.ManagementProfileConsoleCookiePrivateV1)
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(document, &contract); err != nil {
		t.Fatal(err)
	}
	fixture := newPrivateIdentityFixture(t)
	root := fixture.compose(t)
	issued := fixture.issue(t, root).Issued()
	request := fixture.managementRequest(t, issued.Token(), httpapi.AccountSessionCSRFPreparePath, "{}")
	response := newPrivateIdentityResponse()
	if err := root.management.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	var actual map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &actual); err != nil {
		t.Fatal(err)
	}
	properties := contract.Components.Schemas["ConsoleCSRFPrepared"].Properties
	if len(actual) != 2 || len(properties) != len(actual) {
		t.Fatal("actual no-grant preparation and compiled response shape differ")
	}
	for name := range actual {
		if _, present := properties[name]; !present {
			t.Fatal("private response exposes data outside the compiled contract")
		}
	}
	validPreparation := response.Code == http.StatusOK && response.Header().Get("Cache-Control") == "no-store"
	if !validPreparation || response.Header().Get("Set-Cookie") != "" {
		t.Fatal("compiled no-store/no-renewal response does not match the actual adapter")
	}
	// Even empty Authorization custody cannot negotiate this source profile.
	before := len(fixture.effects)
	request = fixture.managementRequest(t, issued.Token(), httpapi.AccountSessionCSRFPreparePath, "{}")
	request.Header["Authorization"] = []string{""}
	response = newPrivateIdentityResponse()
	err = root.management.Handle(response, request)
	closedTransport := errors.Is(err, httpapi.ErrInvalidBrowserManagement) && len(fixture.effects) == before
	untouchedResponse := len(response.Header()) == 0 && response.Body.Len() == 0
	if !closedTransport || !untouchedResponse {
		t.Fatal("source profile negotiated Bearer or reflected rejected credential transport")
	}
}

func TestPrivateIdentityPrivateMetricsAndDiagnosticsStayIsolated(t *testing.T) {
	t.Parallel()
	fixture := newPrivateIdentityFixture(t)
	root, other := fixture.compose(t), fixture.compose(t)
	fixture.issue(t, root)
	collected, err := root.metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var seenCallback bool
	for _, family := range collected {
		if family.GetName() == "meshtransit_oidc_browser_callbacks_total" {
			seenCallback = true
			if len(family.Metric) != 1 || family.Metric[0].GetCounter().GetValue() != 1 ||
				family.Metric[0].Label[0].GetName() != "result" || family.Metric[0].Label[0].GetValue() != "issued" {
				t.Fatal("closed application outcome not registered at private root")
			}
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() != "result" && label.GetName() != "operation" {
					t.Fatal("unbounded root metric label")
				}
			}
		}
	}
	if !seenCallback {
		t.Fatal("root omitted callback observer registration")
	}
	untouched, err := other.metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range untouched {
		if family.GetName() == "meshtransit_oidc_browser_callbacks_total" {
			t.Fatal("observation escaped root registry")
		}
	}
	// Export to a test-owned operator registry, never the global default.
	operator := prometheus.NewPedanticRegistry()
	if err := operator.Register(root.metrics); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.Gather(); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{root, *root, fixture.options, &fixture.options, fixture.ports, &fixture.ports} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, value) != "[REDACTED]" {
				t.Fatal("private diagnostic disclosed custody")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private root serialized")
		}
		var logs bytes.Buffer
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("private root", "profile", value)
		if strings.Contains(logs.String(), fixture.options.Origin) || strings.Contains(logs.String(), "private subject") {
			t.Fatal("root profile entered structured logs")
		}
	}
}

// Controlled in-memory effects qualify wiring, not PostgreSQL, OIDC signatures,
// browser receipt, deployment HA or any production membership/authority grant.
type privateIdentityFixture struct {
	t                          *testing.T
	keys                       *privateIdentityKeys
	options                    privateIdentityOptions
	ports                      privateIdentityPorts
	now                        time.Time
	clockReads, authorityReads int
	effects                    []string
	budgets                    []ratelimit.Subject
	secrets                    oidcauth.Secrets
	pending                    oidcauth.PendingSnapshot
	session                    accountsession.Session
	tokenDigest                accountsession.Digest
	subjectDigest              oidcauth.SubjectDigest
	providerSessionDigest      oidcauth.ProviderSessionDigest
	revokeCommand              revocation.Command
	authorityFound, claimed    bool
	unknownCommit              string
}

func newPrivateIdentityFixture(t *testing.T) *privateIdentityFixture {
	t.Helper()
	files, _, _ := privateIdentityCompositionFixture(t, true)
	keys, err := composePrivateIdentityKeys(t.Context(), files)
	if err != nil {
		t.Fatal(err)
	}
	dep := deployment.ID(privateIdentityID(t, 1))
	// All synthetic provider endpoints share this reserved origin and realm.
	providerBase, err := url.Parse("https://identity.example.test/realm")
	if err != nil {
		t.Fatal(err)
	}
	route, err := oidcauth.NewRoute(oidcauth.RouteParams{
		DeploymentID: dep,
		ProviderID:   oidcauth.ProviderID(privateIdentityID(t, 3)), ClientID: oidcauth.ClientID(privateIdentityID(t, 4)),
		ProviderGeneration: 2, RecoveryEpoch: 7,
		Issuer: providerBase.String(), DiscoveryURI: providerBase.JoinPath("discovery").String(),
		AuthorizationEndpoint: providerBase.JoinPath("authorize").String(),
		TokenEndpoint:         providerBase.JoinPath("token").String(), JWKSURI: providerBase.JoinPath("jwks").String(),
		OIDCClientID: "private-browser-client", ClientKind: "confidential",
		ClientAuthMethod: "client_secret_basic", Scopes: []string{"openid"}, AllowedAlgorithms: []string{"RS256"},
		RedirectID: "browser-callback", RedirectURI: "https://console.example.test/auth/v1/callback",
		ReturnRouteID: "console",
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ratelimit.NewPolicy(20, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &privateIdentityFixture{t: t, keys: keys, now: time.Date(2026, 9, 17, 1, 0, 0, 0, time.UTC),
		effects: []string{}, budgets: []ratelimit.Subject{}}
	fixture.options = privateIdentityOptions{
		Route: route, Origin: "https://console.example.test", ReturnPath: "/console",
		Start: oidcauth.StartOptions{
			RequestTimeout: 5 * time.Second, PendingLifetime: 2 * time.Minute,
			RollbackTimeout: time.Second, ResolveTimeout: time.Second,
		},
		Callback: oidcauth.CallbackOptions{
			RequestTimeout: 25 * time.Second, FailureTimeout: time.Second, RollbackTimeout: time.Second,
			IdleLifetime: time.Hour, AbsoluteLifetime: 2 * time.Hour, MaxConcurrent: 2},
		Browser: privateIdentityBrowserOptions{
			IntentLifetime: time.Minute, CaptureLifetime: time.Minute, ContinuationLifetime: time.Minute,
			RequestTimeout: 5 * time.Second, CompletionTimeout: 25 * time.Second,
			MaxConcurrent: 2, SourceRateLimit: policy, StateRateLimit: policy,
		},
		Management: privateIdentityManagementOptions{
			RequestTimeout: 2 * time.Second, ProofLifetime: time.Minute, MaxConcurrent: 2,
			SourceRateLimit: policy, SessionRateLimit: policy},
	}
	authority := &privateIdentityAuthority{fixture: fixture}
	approvals := privateIdentityPolicyApprovals{}
	fixture.ports = privateIdentityPorts{
		Admission: fixture, Metadata: &privateIdentityMetadata{fixture: fixture}, Creations: fixture, Committed: fixture,
		CreationClock: fixture, Pending: fixture, Claims: fixture, Failures: fixture, Issues: fixture, Provider: fixture, Subjects: fixture,
		SessionAuthority: authority, SessionRevocations: authority,
		SessionScopes:       &privateIdentityManagementScopes{},
		SessionCapabilities: &privateIdentityManagementCapabilities{},
		StartIDs:            fixture, Secrets: fixture, ClaimIDs: fixture,
		IssueMaterial: fixture, Revocations: fixture, PolicyPublications: fixture,
		PolicyCompilations: fixture,
		PolicyExplanations: fixture,
		PolicySimulations:  fixture,
		PolicyApprovals:    approvals, PolicyApprovalCatalog: approvals,
		ResourceCreations: privateIdentityResourcePorts{}, ResourceCatalog: privateIdentityResourcePorts{},
		ResourceSharing: privateIdentityResourcePorts{},
		RateLimiter:     fixture, CorrelationIDs: fixture,
		Clock: fixture, Logger: discardCompositionLogger(),
	}
	return fixture
}

type privateIdentityPolicyApprovals struct{}

type privateIdentityManagementScopes struct{}

type privateIdentityManagementCapabilities struct{}

func (*privateIdentityManagementScopes) List(
	context.Context,
	accountsession.Session,
	int,
	network.ID,
) (sessioncontext.Page, error) {
	return sessioncontext.Page{}, sessioncontext.ErrUnavailable
}

func (*privateIdentityManagementCapabilities) Read(
	context.Context,
	accountsession.Session,
) (sessioncontext.DeploymentCapabilities, error) {
	return sessioncontext.DeploymentCapabilities{}, sessioncontext.ErrCapabilitiesUnavailable
}

func (privateIdentityPolicyApprovals) Request(
	context.Context,
	policyapproval.RequestIntent,
) (policyapproval.RequestResult, error) {
	return policyapproval.RequestResult{}, policyapproval.ErrOperationFailed
}

func (privateIdentityPolicyApprovals) Approve(
	context.Context,
	policyapproval.Command,
) (policyapproval.Result, error) {
	return policyapproval.Result{}, policyapproval.ErrOperationFailed
}

func (privateIdentityPolicyApprovals) Get(
	context.Context,
	accountsession.Session,
	network.Scope,
	policyapproval.RequestID,
) (policyapproval.Snapshot, error) {
	return policyapproval.Snapshot{}, policyapproval.ErrCatalogUnavailable
}

func (privateIdentityPolicyApprovals) List(
	context.Context,
	accountsession.Session,
	network.Scope,
	policyapproval.State,
	int,
	policyapproval.RequestID,
) (policyapproval.CatalogPage, error) {
	return policyapproval.CatalogPage{}, policyapproval.ErrCatalogUnavailable
}

func privateIdentityID(t *testing.T, suffix byte) publicid.ID {
	t.Helper()
	id, err := publicid.FromBytes([16]byte{0x01, 0x89, 0x0f, 0x00, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, suffix})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (fixture *privateIdentityFixture) compose(t *testing.T) *privateIdentity {
	t.Helper()
	root, err := composePrivateIdentity(t.Context(), fixture.keys, fixture.options, fixture.ports)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func (fixture *privateIdentityFixture) startCommand(t *testing.T, root *privateIdentity) oidcauth.CallbackCommand {
	t.Helper()
	started, err := root.start.Start(t.Context(), fixture.options.Route)
	if err != nil || !started.IsValid() {
		t.Fatal("creation through root", err)
	}
	location, err := url.Parse(started.AuthorizationRequest().Location())
	if err != nil {
		t.Fatal(err)
	}
	state, err := oidcauth.ParseState(location.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	if state != fixture.secrets.State() || started.PreAuthCookie() != fixture.secrets.PreAuthCookie() {
		t.Fatal("creation changed transient binding")
	}
	code, err := oidcauth.ParseCode("synthetic-private-code")
	if err != nil {
		t.Fatal(err)
	}
	command, err := oidcauth.NewCallbackCommand(oidcauth.CallbackCommandParams{
		Route: fixture.options.Route, State: state, PreAuthCookie: started.PreAuthCookie(),
		Code: code, Kind: oidcauth.CallbackCodeReceived,
	})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func (fixture *privateIdentityFixture) issue(t *testing.T, root *privateIdentity) oidcauth.CallbackResult {
	t.Helper()
	command := fixture.startCommand(t, root)
	result, err := root.callback.CompleteBrowser(t.Context(), command)
	if err != nil || !result.Issued().IsValid() {
		t.Fatal("callback through private root", err)
	}
	return result
}

func (fixture *privateIdentityFixture) record(ctx context.Context, effect string) {
	fixture.effects = append(fixture.effects, effect)
	if ctx.Err() != nil {
		fixture.t.Error("effect received canceled context")
	}
	if _, ok := ctx.Deadline(); !ok && effect != "session" {
		fixture.t.Error("effect lacks finite context")
	}
}

func (fixture *privateIdentityFixture) CreationTime(ctx context.Context) (time.Time, error) {
	return fixture.now, ctx.Err()
}

func (fixture *privateIdentityFixture) Now() time.Time { fixture.clockReads++; return fixture.now }
func (fixture *privateIdentityFixture) Admit(ctx context.Context, route oidcauth.Route) error {
	fixture.record(ctx, "admit")
	if !route.IsValid() || route.DeploymentID() != fixture.options.Route.DeploymentID() {
		return oidcauth.ErrInvalidRoute
	}
	return nil
}

type privateIdentityMetadata struct{ fixture *privateIdentityFixture }

func (port *privateIdentityMetadata) Resolve(ctx context.Context, route oidcauth.Route) (oidcauth.Metadata, error) {
	port.fixture.record(ctx, "metadata")
	return oidcauth.NewMetadata(oidcauth.MetadataParams{
		Issuer: route.Issuer(), AuthorizationEndpoint: route.AuthorizationEndpoint(),
		TokenEndpoint: route.TokenEndpoint(), JWKSURI: route.JWKSURI(),
		ResponseTypes: []string{"code"}, CodeChallengeMethods: []string{"S256"},
		IDTokenSigningAlgorithms: []string{"RS256"}, TokenAuthMethods: []string{"client_secret_basic"},
	})
}

func (fixture *privateIdentityFixture) NewStartIDs() (oidcauth.TransactionID, oidcauth.MutationIDs, error) {
	fixture.effects = append(fixture.effects, "start_ids")
	return (oidcauth.SystemStartIDs{}).NewStartIDs()
}
func (fixture *privateIdentityFixture) NewSecrets() (oidcauth.Secrets, error) {
	fixture.effects = append(fixture.effects, "secrets")
	secrets, err := oidcauth.GenerateSecrets()
	fixture.secrets = secrets
	return secrets, err
}
func (fixture *privateIdentityFixture) NewClaimIDs() (oidcauth.MutationIDs, error) {
	fixture.effects = append(fixture.effects, "claim_ids")
	return (oidcauth.SystemClaimIDs{}).NewClaimIDs()
}
func (fixture *privateIdentityFixture) NewIssueMaterial(
	ctx context.Context,
	dep deployment.ID,
	epoch int64,
) (oidcauth.IssueIDs, accountsession.Token, error) {
	fixture.record(ctx, "issue_material")
	return (oidcauth.SystemIssueMaterial{}).NewIssueMaterial(ctx, dep, epoch)
}
func (fixture *privateIdentityFixture) NewID() (publicid.ID, error) {
	fixture.effects = append(fixture.effects, "correlation_id")
	return publicid.New()
}

type privateIdentityTestUnit struct {
	fixture *privateIdentityFixture
	stage   string
}

func (unit privateIdentityTestUnit) Commit(ctx context.Context) error {
	unit.fixture.record(ctx, "commit_"+unit.stage)
	if unit.stage == "claim" {
		unit.fixture.claimed = true
	}
	if unit.stage == "issue" {
		unit.fixture.authorityFound = true
	}
	if unit.fixture.unknownCommit == unit.stage {
		return oidcauth.ErrCommitOutcomeUnknown
	}
	return nil
}
func (unit privateIdentityTestUnit) Rollback(ctx context.Context) error {
	unit.fixture.record(ctx, "rollback_"+unit.stage)
	return nil
}

type privateIdentityCreation struct{ privateIdentityTestUnit }

func (fixture *privateIdentityFixture) Begin(ctx context.Context, _ oidcauth.Route) (oidcauth.Transaction, error) {
	fixture.record(ctx, "begin_create")
	return privateIdentityCreation{privateIdentityTestUnit{fixture: fixture, stage: "create"}}, nil
}
func (unit privateIdentityCreation) Create(ctx context.Context, pending oidcauth.Pending) (oidcauth.Created, error) {
	f := unit.fixture
	f.record(ctx, "create")
	snapshot, err := oidcauth.NewPendingSnapshot(oidcauth.PendingSnapshotParams{
		TransactionID: pending.TransactionID(), Route: pending.Route(), Version: 1, State: "pending",
		FlowKind: "browser_authorization_code", OperationKind: "login",
		StateDigest: pending.StateDigest(), NonceDigest: pending.NonceDigest(),
		VerifierCiphertext: pending.VerifierCiphertext(), SemanticHash: pending.SemanticHash(),
		CreatedAt: pending.CreatedAt(), ExpiresAt: pending.ExpiresAt(),
	})
	if err != nil {
		return oidcauth.Created{}, err
	}
	f.pending = snapshot
	return oidcauth.NewCreated(pending.TransactionID(), 1, pending.CreatedAt(), pending.ExpiresAt())
}
func (fixture *privateIdentityFixture) ResolveCommitted(
	ctx context.Context, _ oidcauth.Pending,
) (oidcauth.Created, bool, error) {
	fixture.record(ctx, "committed_lookup")
	return oidcauth.Created{}, false, nil
}
func (fixture *privateIdentityFixture) LoadPending(
	ctx context.Context, route oidcauth.Route, digest oidcauth.Digest,
) (oidcauth.PendingSnapshot, bool, error) {
	fixture.record(ctx, "pending")
	if fixture.claimed || !fixture.pending.MatchesRoute(route) || digest != fixture.pending.StateDigest() {
		return oidcauth.PendingSnapshot{}, false, nil
	}
	return fixture.pending, true, nil
}

type privateIdentityClaim struct{ privateIdentityTestUnit }

func (fixture *privateIdentityFixture) BeginClaim(
	ctx context.Context, _ oidcauth.Route,
) (oidcauth.ClaimTransaction, error) {
	fixture.record(ctx, "begin_claim")
	return privateIdentityClaim{privateIdentityTestUnit{fixture: fixture, stage: "claim"}}, nil
}
func (unit privateIdentityClaim) Claim(ctx context.Context, command oidcauth.ClaimCommand) (oidcauth.Claimed, error) {
	unit.fixture.record(ctx, "claim")
	return oidcauth.NewClaimed(command.Snapshot(), 2, unit.fixture.now)
}

type privateIdentityFailure struct{ privateIdentityTestUnit }

func (fixture *privateIdentityFixture) BeginFailure(
	ctx context.Context, _ oidcauth.Route,
) (oidcauth.FailureTransaction, error) {
	fixture.record(ctx, "begin_failure")
	return privateIdentityFailure{privateIdentityTestUnit{fixture: fixture, stage: "failure"}}, nil
}
func (unit privateIdentityFailure) Fail(
	ctx context.Context, command oidcauth.FailureCommand,
) (oidcauth.Terminated, error) {
	unit.fixture.record(ctx, "failure")
	return oidcauth.NewTerminated(command.Claimed(), 3, "failed", "authentication_failed", unit.fixture.now)
}
func (fixture *privateIdentityFixture) Authenticate(
	ctx context.Context, request oidcauth.ExchangeRequest,
) (oidcauth.TokenEvidence, error) {
	fixture.record(ctx, "provider")
	if request.Verifier() != fixture.secrets.Verifier() || request.Code().Encoded() != "synthetic-private-code" {
		return oidcauth.TokenEvidence{}, oidcauth.ErrExchangeRejected
	}
	return oidcauth.NewTokenEvidence(oidcauth.TokenEvidenceParams{
		Issuer: request.Route().Issuer(), Subject: "private subject", SessionID: "synthetic-provider-session",
		Nonce:    fixture.secrets.Nonce(),
		IssuedAt: fixture.now, ExpiresAt: fixture.now.Add(5 * time.Minute), AuthTime: fixture.now.Add(-time.Minute),
	})
}
func (fixture *privateIdentityFixture) ResolveLoginSubject(
	ctx context.Context, lookup oidcauth.SubjectLookup,
) (oidcauth.LoginSubjectSnapshot, error) {
	fixture.record(ctx, "subject")
	fixture.subjectDigest = lookup.Digests()[0]
	return oidcauth.NewLoginSubjectSnapshot(oidcauth.LoginSubjectParams{
		Lookup: lookup, Digest: lookup.Digests()[0], PrincipalID: identity.PrincipalID(privateIdentityID(fixture.t, 5)),
		IdentitySubjectID: accountsession.IdentitySubjectID(privateIdentityID(fixture.t, 6)),
		MembershipID:      oidcauth.LoginMembershipID(privateIdentityID(fixture.t, 7)),
		WorkspaceID:       workspace.ID(privateIdentityID(fixture.t, 2)),
		SubjectVersion:    1, AccountVersion: 1, MembershipVersion: 1,
		PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		MembershipAuthorityGeneration: 1, EvaluatedAt: fixture.now,
	})
}

type privateIdentityIssue struct{ privateIdentityTestUnit }

func (fixture *privateIdentityFixture) BeginIssue(
	ctx context.Context, _ oidcauth.Route,
) (oidcauth.IssueTransaction, error) {
	fixture.record(ctx, "begin_issue")
	return privateIdentityIssue{privateIdentityTestUnit{fixture: fixture, stage: "issue"}}, nil
}
func (unit privateIdentityIssue) Issue(ctx context.Context, command oidcauth.IssueCommand) (oidcauth.Issued, error) {
	f := unit.fixture
	f.record(ctx, "issue")
	f.tokenDigest, f.providerSessionDigest = command.TokenDigest(), command.ProviderSessionDigest()
	issued, err := oidcauth.NewIssued(oidcauth.IssuedParams{
		Command: command, SessionID: command.IDs().SessionID(), Version: 1, IssuedAt: f.now,
		IdleExpiresAt: f.now.Add(command.IdleLifetime()), AbsoluteExpiresAt: f.now.Add(command.AbsoluteLifetime()),
	})
	if err != nil {
		return oidcauth.Issued{}, err
	}
	f.session = issued.Session()
	return issued, nil
}

type privateIdentityAuthority struct{ fixture *privateIdentityFixture }

func (port *privateIdentityAuthority) Resolve(
	ctx context.Context,
	dep deployment.ID,
	epoch int64,
	digest accountsession.Digest,
) (accountsession.Session, bool, error) {
	f := port.fixture
	f.record(ctx, "session")
	f.authorityReads++
	validScope := dep == f.session.DeploymentID() && epoch == f.session.DeploymentRecoveryEpoch()
	if !f.authorityFound || !validScope || digest != f.tokenDigest {
		return accountsession.Session{}, false, nil
	}
	return f.session, true, nil
}

func (port *privateIdentityAuthority) Revoke(
	ctx context.Context,
	dep deployment.ID,
	epoch int64,
	digest accountsession.Digest,
) (accountsession.ID, int64, bool, error) {
	f := port.fixture
	f.record(ctx, "session_logout")
	validScope := dep == f.session.DeploymentID() && epoch == f.session.DeploymentRecoveryEpoch()
	if !f.authorityFound || !validScope || digest != f.tokenDigest {
		return accountsession.ID{}, 0, false, nil
	}
	f.authorityFound = false
	return f.session.ID(), f.session.Version() + 1, true, nil
}
func (fixture *privateIdentityFixture) Allow(
	ctx context.Context, subject ratelimit.Subject, policy ratelimit.Policy,
) (ratelimit.Decision, error) {
	fixture.record(ctx, "budget")
	fixture.budgets = append(fixture.budgets, subject)
	return ratelimit.NewDecision(true, policy.Capacity(), policy.Capacity()-1, 0)
}
func (fixture *privateIdentityFixture) Revoke(
	ctx context.Context, command revocation.Command,
) (revocation.Result, error) {
	fixture.record(ctx, "revoke")
	fixture.revokeCommand = command
	return revocation.Result{}, errors.New("private controlled revocation failure")
}
func (fixture *privateIdentityFixture) Publish(
	ctx context.Context, _ policypublication.Command,
) (policypublication.Result, error) {
	fixture.record(ctx, "publish")
	return policypublication.Result{}, errors.New("private controlled publication failure")
}

func (fixture *privateIdentityFixture) Compile(
	ctx context.Context,
	_ accountsession.Session,
	request compilation.Request,
) (policypublication.Candidate, error) {
	fixture.record(ctx, "compile")
	rules := make([]policy.Rule, len(request.Rules()))
	for index, intent := range request.Rules() {
		if intent.DestinationResourceID().IsValid() {
			return policypublication.Candidate{}, compilation.ErrResourceConflict
		}
		rule, err := policy.NewRule(policy.RuleParams{
			ID: intent.ID(), Scope: intent.Scope(), SourceNodeID: intent.SourceNodeID(),
			DestinationNodeID: intent.DestinationNodeID(), Protocol: intent.Protocol(),
			DestinationPortRanges: intent.DestinationPortRanges(),
		})
		if err != nil {
			return policypublication.Candidate{}, err
		}
		rules[index] = rule
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: request.Scope(), Revision: request.Revision(), Rules: rules,
	})
	if err != nil {
		return policypublication.Candidate{}, err
	}
	return policypublication.NewCandidate(snapshot, 1)
}

func (fixture *privateIdentityFixture) Explain(
	ctx context.Context,
	_ accountsession.Session,
	_ accessgraph.Query,
) (accessgraph.Result, error) {
	fixture.record(ctx, "explain")
	return accessgraph.Result{}, errors.New("private controlled explanation failure")
}

func (fixture *privateIdentityFixture) Simulate(
	ctx context.Context,
	_ accountsession.Session,
	_ compilation.Request,
) (simulation.Result, error) {
	fixture.record(ctx, "simulate")
	return simulation.Result{}, errors.New("private controlled simulation failure")
}

type privateIdentityResponse struct{ *httptest.ResponseRecorder }

func newPrivateIdentityResponse() *privateIdentityResponse {
	return &privateIdentityResponse{ResponseRecorder: httptest.NewRecorder()}
}
func (*privateIdentityResponse) SetReadDeadline(time.Time) error  { return nil }
func (*privateIdentityResponse) SetWriteDeadline(time.Time) error { return nil }
func (fixture *privateIdentityFixture) managementRequest(
	t *testing.T, token accountsession.Token, path, body string,
) *http.Request {
	t.Helper()
	request := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, fixture.options.Origin+path, strings.NewReader(body),
	)
	request.URL.Scheme, request.URL.Host = "", ""
	request.RequestURI = path
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.RemoteAddr = "192.0.2.9:12345"
	request.Header.Set("Origin", fixture.options.Origin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-MeshTransit-Session", "v1")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Idempotency-Key", "private-root-intent")
	request.AddCookie(&http.Cookie{
		Name: "__Host-mt_session", Value: token.Encoded(),
		Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	return request
}
func privateIdentityRevokePath(_ oidcauth.Route) string {
	return "/api/v1/workspaces/01890f00-0000-7000-8000-000000000002" +
		"/networks/01890f00-0000-7000-8000-000000000008/devices/" +
		"01890f00-0000-7000-8000-000000000009/actions/revoke"
}

func (fixture *privateIdentityFixture) loginRequest(t *testing.T, path string) *http.Request {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader("{}"))
	request.Host, request.RemoteAddr = "console.example.test", "192.0.2.9:12345"
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.Header.Set("Origin", fixture.options.Origin)
	request.Header.Set("X-MeshTransit-Login", "v1")
	request.Header.Set("Content-Type", "application/json")
	return request
}
