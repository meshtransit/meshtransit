package selfhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// #nosec G101 -- directory paths, no credentials.
var testLayout = Layout{SecretsDir: "/var/lib/meshtransit/secrets", RunDir: "/var/lib/meshtransit/run"}

func approvedState() State {
	return State{
		Format: stateFormat, DeploymentID: "01890f00-0000-7000-8000-000000000001", RecoveryEpoch: 1,
		ProviderID: "01890f00-0000-7000-8000-000000000002", ClientID: "01890f00-0000-7000-8000-000000000003",
		ProviderGeneration: 1, ConnectorGeneration: 1, CoreClientGeneration: 1,
		IdentityFingerprint: "sha256-v2:" + strings.Repeat("ab", 32),
		MTCPKeyNotAfter:     time.Date(2027, 11, 4, 0, 0, 0, 0, time.UTC),
	}
}

func parseEnv(t *testing.T, contents []byte) map[string]string {
	t.Helper()
	settings := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || name == "" || strings.ContainsAny(value, "\n\r") {
			t.Fatalf("bad env line %q", line)
		}
		if _, duplicate := settings[name]; duplicate {
			t.Fatalf("duplicate %s", name)
		}
		settings[name] = value
	}
	return settings
}

func TestRenderNeedsAnApprovedIdentity(t *testing.T) {
	t.Parallel()
	state := approvedState()
	state.IdentityFingerprint = ""
	if _, err := Render(testConfig(t), state, testLayout); !errors.Is(err, ErrIdentityNotApproved) {
		t.Fatalf("Render() error = %v", err)
	}
}

func TestRenderIsDeterministicAndOwnsEverySettingItWrites(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	first, err := Render(config, approvedState(), testLayout)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(config, approvedState(), testLayout)
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range first.Files {
		if !bytes.Equal(contents, second.Files[name]) {
			t.Errorf("%s differs between two renders", name)
		}
	}
	for _, file := range []string{"core.env", "migrate.env", "bootstrap.env"} {
		for name := range parseEnv(t, first.Files[file]) {
			// advanced: may never override what render derives.
			if tunableSetting(name) {
				t.Errorf("%s writes %s, which advanced: could override", file, name)
			}
		}
	}
}

func TestRenderTrustsOnlyTheProxyAndKeepsTheSuperuserOut(t *testing.T) {
	t.Parallel()
	rendered, err := Render(testConfig(t), approvedState(), testLayout)
	if err != nil {
		t.Fatal(err)
	}
	core := parseEnv(t, rendered.Files["core.env"])
	for _, name := range []string{"MESHTRANSIT_API_TRUSTED_PROXY_CIDRS", "MESHTRANSIT_CONTROL_MTCP_TRUSTED_PROXY_CIDRS"} {
		if core[name] != "172.30.0.10/32" {
			t.Errorf("%s = %q, want only the proxy", name, core[name])
		}
	}
	var profile struct {
		Prefixes []string `json:"trusted_proxy_prefixes"`
	}
	if err := json.Unmarshal(rendered.Files["private-login.json"], &profile); err != nil ||
		len(profile.Prefixes) != 1 || profile.Prefixes[0] != "172.30.0.10/32" {
		t.Fatalf("login profile proxies = %v, %v", profile.Prefixes, err)
	}
	for name := range parseEnv(t, rendered.Files["bootstrap.env"]) {
		if strings.HasPrefix(name, "MESHTRANSIT_OPERATOR_") {
			t.Errorf("bootstrap.env holds %s", name)
		}
	}
	if parseEnv(t, rendered.Files["migrate.env"])["MESHTRANSIT_OPERATOR_POSTGRES_USER"] != "postgres" {
		t.Error("migrate.env lacks the operator")
	}
}

func TestRenderRefusesNewPublicNamesAfterInstallation(t *testing.T) {
	t.Parallel()
	state := approvedState()
	state.ApprovedIssuer, state.ApprovedOrigin = "https://id.mesh.example.com/oauth2", "https://mesh.example.com"
	if _, err := Render(testConfig(t), state, testLayout); err != nil {
		t.Fatalf("same names: %v", err)
	}
	moved, err := ParseConfig([]byte(strings.Replace(validConfig, "mesh.example.com", "vpn.example.com", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Render(moved, state, testLayout); !errors.Is(err, ErrPublicNamesChanged) {
		t.Fatalf("new domain: %v", err)
	}
}

func TestRenderPinsTheApprovedFingerprintAndMatchesAcrossFiles(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	state := approvedState()
	rendered, err := Render(config, state, testLayout)
	if err != nil {
		t.Fatal(err)
	}
	core := parseEnv(t, rendered.Files["core.env"])
	if core["MESHTRANSIT_ROLE"] != "all" || core["MESHTRANSIT_IDENTITY_CONFIGURATION_FINGERPRINT"] != state.IdentityFingerprint {
		t.Fatalf("core role/fingerprint = %q %q", core["MESHTRANSIT_ROLE"], core["MESHTRANSIT_IDENTITY_CONFIGURATION_FINGERPRINT"])
	}
	if _, ok := core["MESHTRANSIT_OPERATOR_POSTGRES_PASSWORD_FILE"]; ok {
		t.Fatal("the serving process gets the superuser's password")
	}
	digest := sha256.Sum256(rendered.Files["relay-directory.json"])
	if core["MESHTRANSIT_RELAY_DIRECTORY_SHA256"] != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("relay directory digest does not match the rendered file")
	}
	var profile map[string]json.RawMessage
	if err := json.Unmarshal(rendered.Files["private-login.json"], &profile); err != nil || len(profile) != 23 {
		t.Fatalf("login profile has %d fields, %v", len(profile), err)
	}
	var issuer, origin, deploymentID string
	_ = json.Unmarshal(profile["issuer"], &issuer)
	_ = json.Unmarshal(profile["origin"], &origin)
	_ = json.Unmarshal(profile["deployment_id"], &deploymentID)
	if issuer != core["MESHTRANSIT_IDENTITY_ISSUER"] || origin != core["MESHTRANSIT_BROWSER_REGISTRATION_ORIGIN"] ||
		deploymentID != core["MESHTRANSIT_BROWSER_REGISTRATION_DEPLOYMENT_ID"] ||
		core["MESHTRANSIT_IDENTITY_CORE_CLIENT_REDIRECT_URI"] != origin+"/auth/v1/callback" {
		t.Fatalf("issuer %q origin %q deployment %q disagree with core.env", issuer, origin, deploymentID)
	}
	bootstrap := parseEnv(t, rendered.Files["bootstrap.env"])
	if bootstrap["MESHTRANSIT_ROLE"] != "api" || bootstrap["MESHTRANSIT_MIGRATION_POSTGRES_USER"] != "mesh_migrator" {
		t.Fatalf("bootstrap env = %q %q", bootstrap["MESHTRANSIT_ROLE"], bootstrap["MESHTRANSIT_MIGRATION_POSTGRES_USER"])
	}
}

func TestRenderAppliesAdvancedTunables(t *testing.T) {
	t.Parallel()
	config, err := ParseConfig([]byte(validConfig + "advanced:\n  MESHTRANSIT_LOG_LEVEL: debug\n"))
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := Render(config, approvedState(), testLayout)
	if err != nil {
		t.Fatal(err)
	}
	if parseEnv(t, rendered.Files["core.env"])["MESHTRANSIT_LOG_LEVEL"] != "debug" {
		t.Fatal("advanced tunable not rendered")
	}
}

func TestIdentitySettingsLeaveOutTheFingerprint(t *testing.T) {
	t.Parallel()
	settings := IdentitySettings(testConfig(t), approvedState(), testLayout)
	if _, ok := settings["MESHTRANSIT_IDENTITY_CONFIGURATION_FINGERPRINT"]; ok || settings["MESHTRANSIT_ROLE"] != "identity" {
		t.Fatalf("identity settings = %v", settings)
	}
}
