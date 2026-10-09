package bootstrap_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/platform/bootstrap"
)

func route(t *testing.T) oidcauth.Route {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	providerID, _ := oidcauth.ParseProviderID("01890f00-0000-7000-8000-000000000601")
	clientID, _ := oidcauth.ParseClientID("01890f00-0000-7000-8000-000000000621")
	issuer := "https://idp.example.test/realms/main"
	// #nosec G101 -- synthetic OIDC metadata, no credentials.
	value, err := oidcauth.NewRoute(oidcauth.RouteParams{
		DeploymentID: deploymentID, ProviderID: providerID, ClientID: clientID,
		ProviderGeneration: 1, RecoveryEpoch: 1, Issuer: issuer,
		DiscoveryURI: issuer + "/.well-known/openid-configuration", AuthorizationEndpoint: issuer + "/auth",
		TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/certs", OIDCClientID: "meshtransit-console",
		ClientKind: "confidential", ClientAuthMethod: "client_secret_basic", Scopes: []string{"openid"},
		AllowedAlgorithms: []string{"RS256"}, RedirectID: "console-callback",
		RedirectURI: "https://console.example.test/auth/v1/callback", ReturnRouteID: "workspace-home",
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func subjectKey(t *testing.T, first byte) oidcauth.SubjectKey {
	t.Helper()
	id, err := oidcauth.NewDigestKeyID("subject-v1")
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 32)
	material[0], material[31] = first, 1
	key, err := oidcauth.NewSubjectKey(id, material)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

const valid = `{"format":"meshtransit-bootstrap/v1","profile":"cloud","minimum_assurance":null,
"accounts":[{"subject":"abc-123","display_name":"Owner","workspace_name":"Default"},
{"subject":"def-456","display_name":"Second","workspace_name":"Team"}]}`

func TestNewPlanDerivesLoginDigests(t *testing.T) {
	t.Parallel()
	plan, err := bootstrap.NewPlan([]byte(valid), route(t), subjectKey(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Profile != deployment.ProfileCloud || len(plan.Accounts) != 2 || plan.MinimumAssurance != "" ||
		plan.Accounts[0].SubjectDigest.KeyID().String() != "subject-v1" ||
		plan.Accounts[0].SubjectDigest == plan.Accounts[1].SubjectDigest {
		t.Fatalf("plan = %+v", plan)
	}
	expected, err := oidcauth.NewSubjectMigrationDigest(route(t).DeploymentID(), route(t).ProviderID(),
		subjectKey(t, 1), route(t).Issuer(), "abc-123")
	if err != nil || expected.Bytes() != plan.Accounts[0].SubjectDigest.Bytes() {
		t.Fatal("plan digest differs from the login digest")
	}
	other, err := bootstrap.NewPlan([]byte(valid), route(t), subjectKey(t, 2))
	if err != nil || other.Accounts[0].SubjectDigest.Bytes() == plan.Accounts[0].SubjectDigest.Bytes() {
		t.Fatal("digest does not depend on the subject key")
	}
}

func TestNewPlanRejectsInvalidFiles(t *testing.T) {
	t.Parallel()
	for name, contents := range map[string]string{
		"empty":                        ``,
		"wrong format":                 strings.Replace(valid, "bootstrap/v1", "bootstrap/v2", 1),
		"unknown profile":              strings.Replace(valid, `"cloud"`, `"enterprise"`, 1),
		"unknown field":                strings.Replace(valid, `"profile"`, `"role":"x","profile"`, 1),
		"self-hosted without accounts": `{"format":"meshtransit-bootstrap/v1","profile":"self_hosted","minimum_assurance":null,"accounts":[]}`,
		"duplicate":                    strings.Replace(valid, "def-456", "abc-123", 1),
		"padded name":                  strings.Replace(valid, `"Owner"`, `" Owner"`, 1),
		"empty subject":                strings.Replace(valid, "abc-123", "", 1),
		"bad workspace":                strings.Replace(valid, `"Team"`, `"Team\n"`, 1),
		"trailing content":             valid + `{}`,
	} {
		if _, err := bootstrap.NewPlan([]byte(contents), route(t), subjectKey(t, 1)); !errors.Is(err, bootstrap.ErrInvalidPlan) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewPlanAcceptsStoredSubjectDigests(t *testing.T) {
	t.Parallel()
	expected, err := oidcauth.NewSubjectMigrationDigest(route(t).DeploymentID(), route(t).ProviderID(),
		subjectKey(t, 1), route(t).Issuer(), "abc-123")
	if err != nil {
		t.Fatal(err)
	}
	raw := expected.Bytes()
	encoded := hex.EncodeToString(raw[:])
	plan, err := bootstrap.NewPlan([]byte(`{"format":"meshtransit-bootstrap/v1","profile":"cloud","accounts":[
 {"subject_digest":"`+encoded+`","display_name":"Rebuilt","workspace_name":"Rebuilt"}]}`), route(t), subjectKey(t, 1))
	if err != nil || plan.Accounts[0].SubjectDigest.Bytes() != expected.Bytes() ||
		plan.Accounts[0].SubjectDigest.KeyID() != expected.KeyID() {
		t.Fatalf("digest account = %+v, %v", plan, err)
	}
	for name, line := range map[string]string{
		"both":      `{"subject":"abc-123","subject_digest":"` + encoded + `","display_name":"A","workspace_name":"A"}`,
		"neither":   `{"display_name":"A","workspace_name":"A"}`,
		"uppercase": `{"subject_digest":"` + strings.ToUpper(encoded) + `","display_name":"A","workspace_name":"A"}`,
		"short":     `{"subject_digest":"abcd","display_name":"A","workspace_name":"A"}`,
		"duplicate": `{"subject_digest":"` + encoded + `","display_name":"A","workspace_name":"A"},
 {"subject":"abc-123","display_name":"B","workspace_name":"B"}`,
	} {
		contents := `{"format":"meshtransit-bootstrap/v1","profile":"cloud","accounts":[` + line + `]}`
		if _, err := bootstrap.NewPlan([]byte(contents), route(t), subjectKey(t, 1)); !errors.Is(err, bootstrap.ErrInvalidPlan) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestNewPlanAllowsCloudWithoutAccounts(t *testing.T) {
	t.Parallel()
	plan, err := bootstrap.NewPlan([]byte(`{"format":"meshtransit-bootstrap/v1","profile":"cloud","accounts":[]}`),
		route(t), subjectKey(t, 1))
	if err != nil || len(plan.Accounts) != 0 {
		t.Fatalf("cloud plan without accounts = %+v, %v", plan, err)
	}
}
