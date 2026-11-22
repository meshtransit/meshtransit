package selfhost

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const oidcLogin = `login:
  provider: oidc
  display_name: Corp SSO
  issuer: https://sso.example.test:8443/realms/corp
  client_id: meshtransit
  client_secret_file: /etc/meshtransit/oidc-client-secret
  authorization_url: https://sso.example.test:8443/realms/corp/protocol/openid-connect/auth
  token_url: https://sso.example.test:8443/realms/corp/protocol/openid-connect/token
  jwks_url: https://sso.example.test:8443/realms/corp/protocol/openid-connect/certs
  name_claim: preferred_username
  ca_file: /etc/meshtransit/oidc-ca.pem
  private_network_cidrs: [10.20.0.0/16]
`

var googleLogin = `login:
  provider: google
  client_id: 1234.apps.googleusercontent.com
  client_secret_file: /etc/meshtransit/google-client-secret
`

func oidcConfigText(extra string) string {
	return strings.Replace(validConfig, googleLogin, oidcLogin+extra, 1)
}

func TestDexSubjectMatchesDexVectors(t *testing.T) {
	t.Parallel()
	// Produced by Dex v2.45.1 server.genSubject. When Dex is upgraded,
	// regenerate them there: a different encoding orphans every Account.
	vectors := []struct{ upstream, connector, subject string }{
		{"100000000000000000000", "google-v1", "ChUxMDAwMDAwMDAwMDAwMDAwMDAwMDASCWdvb2dsZS12MQ"},
		{"f:1a2b3c4d-0000-4000-8000-000000000001:alice", "oidc-0123456789abcdef",
			"CixmOjFhMmIzYzRkLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMTphbGljZRIVb2lkYy0wMTIzNDU2Nzg5YWJjZGVm"},
	}
	for _, vector := range vectors {
		if got := dexSubject(vector.upstream, vector.connector); got != vector.subject {
			t.Fatalf("dexSubject(%q, %q) = %q, want %q", vector.upstream, vector.connector, got, vector.subject)
		}
		if !isDexSubject(vector.subject, vector.connector) || isDexSubject(vector.subject, "other") ||
			isDexSubject(vector.upstream, vector.connector) {
			t.Fatalf("isDexSubject mismatch for %q", vector.subject)
		}
	}
}

func TestParseConfigReadsOIDCLogin(t *testing.T) {
	t.Parallel()
	config, err := ParseConfig([]byte(oidcConfigText("")))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	login := config.Login
	if login.issuer() != "https://sso.example.test:8443/realms/corp" || login.displayName() != "Corp SSO" ||
		!strings.HasPrefix(login.connectorID(), "oidc-") || len(login.connectorID()) != len("oidc-")+16 {
		t.Fatalf("login = %+v, connector %q", login, login.connectorID())
	}
	// Spellings of one issuer share a connector ID; another issuer does not.
	for _, issuer := range []string{"https://SSO.example.test:8443/realms/corp", "https://sso.example.test:8443/realms/corp/"} {
		if (Login{Provider: providerOIDC, Issuer: issuer}).connectorID() != login.connectorID() {
			t.Fatalf("connector ID differs for %q", issuer)
		}
	}
	if (Login{Provider: providerOIDC, Issuer: "https://sso.example.test:8443/realms/other"}).connectorID() == login.connectorID() {
		t.Fatal("two issuers share a connector ID")
	}
	if (Login{Provider: providerOIDC, Issuer: googleIssuer}).connectorID() != googleConnectorID {
		t.Fatal("Google named through provider oidc lost google-v1")
	}
	settings := login.connectorSettings()
	if settings["MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_PROMPT"] != "login" ||
		settings["MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_TOKEN_AUTH"] != "basic" ||
		settings["MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_EMAIL"] != "required" ||
		settings["MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_PRIVATE_NETWORK_CIDRS"] != "10.20.0.0/16" ||
		settings["MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CA_FILE"] != "/etc/meshtransit/oidc-ca.pem" {
		t.Fatalf("connector settings = %v", settings)
	}
	if _, set := settings["MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_USERINFO_URL"]; set {
		t.Fatal("an empty userinfo URL was rendered")
	}
	files, err := composeFiles(config, testLayout, serviceMounts{}, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(files["console.env"]), "MESH_CONSOLE_SIGN_IN_PROVIDER=Corp SSO\n") {
		t.Fatalf("console.env does not name the provider:\n%s", files["console.env"])
	}
	google, err := composeFiles(testConfig(t), testLayout, serviceMounts{}, 64)
	if err != nil || strings.Contains(string(google["console.env"]), "SIGN_IN_PROVIDER") {
		t.Fatalf("Google console.env names a provider: %v", err)
	}
}

func TestParseConfigRefusesBadLogin(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"google with issuer": strings.Replace(validConfig, "  provider: google\n",
			"  provider: google\n  issuer: https://sso.example.test\n", 1),
		"google with cidrs": strings.Replace(validConfig, "  provider: google\n",
			"  provider: google\n  private_network_cidrs: [10.0.0.0/8]\n", 1),
		"oidc http issuer":   strings.Replace(oidcConfigText(""), "issuer: https://", "issuer: http://", 1),
		"oidc no token url":  strings.Replace(oidcConfigText(""), "  token_url: https://sso.example.test:8443/realms/corp/protocol/openid-connect/token\n", "", 1),
		"oidc bad email":     oidcConfigText("  email: untrusted\n"),
		"oidc bad prompt":    oidcConfigText("  prompt: consent\n"),
		"oidc bad auth":      oidcConfigText("  token_auth: private_key_jwt\n"),
		"oidc ca outside":    strings.Replace(oidcConfigText(""), "ca_file: /etc/meshtransit/oidc-ca.pem", "ca_file: /tmp/ca.pem", 1),
		"oidc cidr unmasked": strings.Replace(oidcConfigText(""), "[10.20.0.0/16]", "[10.20.1.1/16]", 1),
		"oidc no display":    strings.Replace(oidcConfigText(""), "  display_name: Corp SSO\n", "", 1),
		"oidc query url":     strings.Replace(oidcConfigText(""), "openid-connect/certs", "openid-connect/certs?x=1", 1),
	}
	for name, text := range cases {
		if _, err := ParseConfig([]byte(text)); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: ParseConfig() error = %v", name, err)
		}
	}
}

func TestFirstAdminSubjectIsEncodedForTheBroker(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	plan, err := bootstrapPlanJSON(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Accounts []struct {
			Subject string `json:"subject"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(plan, &decoded); err != nil || len(decoded.Accounts) != 1 ||
		decoded.Accounts[0].Subject != dexSubject("110169484474386276334", googleConnectorID) {
		t.Fatalf("bootstrap plan = %s, %v", plan, err)
	}
	// An already encoded subject and one too long once encoded are refused.
	encoded := strings.Replace(validConfig, "110169484474386276334", dexSubject("110169484474386276334", googleConnectorID), 1)
	if _, err := ParseConfig([]byte(encoded)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("encoded subject error = %v", err)
	}
	long := strings.Replace(validConfig, "110169484474386276334", strings.Repeat("a", 200), 1)
	if _, err := ParseConfig([]byte(long)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("long subject error = %v", err)
	}
}

func TestApproveIdentityRefusesAnotherProvider(t *testing.T) {
	t.Parallel()
	dir := secretsDir(t)
	layout := Layout{SecretsDir: dir, RunDir: "/var/lib/meshtransit/run"}
	config := testConfig(t)
	if _, err := GenerateSecrets(config, dir, GenerateOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	first, err := ApproveIdentity(config, layout, fakeFingerprint, nil)
	if err != nil || first.Format != stateFormat || first.Provider != providerOf(config) {
		t.Fatalf("first approval = %+v, %v", first, err)
	}
	for name, text := range map[string]string{
		"client":   strings.Replace(validConfig, "1234.apps", "5678.apps", 1),
		"provider": oidcConfigText(""),
	} {
		other, err := ParseConfig([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckIdentity(other, first, layout, fakeFingerprint); !errors.Is(err, ErrProviderChanged) {
			t.Fatalf("%s: CheckIdentity() error = %v", name, err)
		}
		if _, err := ApproveIdentity(other, layout, fakeFingerprint, nil); !errors.Is(err, ErrProviderChanged) {
			t.Fatalf("%s: ApproveIdentity() error = %v", name, err)
		}
	}
	if loaded, err := LoadState(dir); err != nil || loaded != first {
		t.Fatalf("a refused change wrote state: %+v, %v", loaded, err)
	}
}

func TestApproveIdentityUpgradesAnApprovedV1State(t *testing.T) {
	t.Parallel()
	dir := secretsDir(t)
	layout := Layout{SecretsDir: dir, RunDir: "/var/lib/meshtransit/run"}
	config := testConfig(t)
	if _, err := GenerateSecrets(config, dir, GenerateOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	approved, err := ApproveIdentity(config, layout, fakeFingerprint, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy := approved
	legacy.Format, legacy.Provider = stateFormatV1, ApprovedProvider{}
	writeTestState(t, dir, legacy)
	// A v1 state with a changed configuration cannot tell its provider.
	changed, err := ParseConfig([]byte(strings.Replace(validConfig, "1234.apps", "5678.apps", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveIdentity(changed, layout, fakeFingerprint, nil); !errors.Is(err, ErrStateV1Changed) {
		t.Fatalf("v1 changed approval error = %v", err)
	}
	// apply upgrades it while the configuration is the approved one.
	if wrote, err := UpgradeApprovedState(changed, layout, fakeFingerprint, nil); err == nil || wrote {
		t.Fatalf("upgrade with a changed configuration = %v, %v", wrote, err)
	}
	if wrote, err := UpgradeApprovedState(config, layout, fakeFingerprint, nil); err != nil || !wrote {
		t.Fatalf("upgrade = %v, %v", wrote, err)
	}
	if wrote, err := UpgradeApprovedState(config, layout, fakeFingerprint, nil); err != nil || wrote {
		t.Fatalf("second upgrade = %v, %v", wrote, err)
	}
	upgraded, err := ApproveIdentity(config, layout, fakeFingerprint, nil)
	if err != nil || upgraded.Format != stateFormat || upgraded.Provider != providerOf(config) ||
		upgraded.IdentityFingerprint != approved.IdentityFingerprint || upgraded.ConnectorGeneration != 1 {
		t.Fatalf("upgraded = %+v, %v", upgraded, err)
	}
	// A v2 state that names no provider after an approval is refused.
	broken := upgraded
	broken.Provider = ApprovedProvider{}
	writeTestState(t, dir, broken)
	if _, err := LoadState(dir); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("v2 without provider error = %v", err)
	}
}

func writeTestState(t *testing.T, dir string, state State) {
	t.Helper()
	contents, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFile), contents, 0o600); err != nil {
		t.Fatal(err)
	}
}
