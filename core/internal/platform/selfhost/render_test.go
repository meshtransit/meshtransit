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

var testKeys = PublicKeys{
	Relay:   "mtrelay:" + strings.Repeat("1", 64),
	Signing: "mtsign:" + strings.Repeat("2", 64),
}

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
	if _, err := Render(testConfig(t), state, testKeys, testLayout); !errors.Is(err, ErrIdentityNotApproved) {
		t.Fatalf("Render() error = %v", err)
	}
}

func TestRenderIsDeterministicAndOwnsEverySettingItWrites(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	first, err := Render(config, approvedState(), testKeys, testLayout)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(config, approvedState(), testKeys, testLayout)
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
			// advanced: may never override what render derives; the pool
			// budget is a default it is meant to raise.
			if _, budget := onePostgresBudget[name]; tunableSetting(name) && !budget {
				t.Errorf("%s writes %s, which advanced: could override", file, name)
			}
		}
	}
}

// Auto-renewal design §2.2: the control key rolls a year from every answer,
// also for a state written before, which named a fixed expiry; rendering
// again moves an install to the rolling key.
func TestRenderRollsTheControlKey(t *testing.T) {
	t.Parallel()
	for _, state := range []State{approvedState(), withoutKeyExpiry(approvedState())} {
		rendered, err := Render(testConfig(t), state, testKeys, testLayout)
		if err != nil {
			t.Fatal(err)
		}
		core := parseEnv(t, rendered.Files["core.env"])
		if core["MESHTRANSIT_CONTROL_MTCP_KEY_LIFETIME"] != "8760h" {
			t.Errorf("lifetime = %q", core["MESHTRANSIT_CONTROL_MTCP_KEY_LIFETIME"])
		}
		if value, present := core["MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER"]; present {
			t.Errorf("fixed expiry still rendered: %q", value)
		}
	}
}

func withoutKeyExpiry(state State) State {
	state.MTCPKeyNotAfter = time.Time{}
	return state
}

func TestRenderTrustsOnlyTheProxyAndKeepsTheSuperuserOut(t *testing.T) {
	t.Parallel()
	rendered, err := Render(testConfig(t), approvedState(), testKeys, testLayout)
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
	// The proxy (browser registration) and the Console reach the login
	// listener, nothing else.
	if err := json.Unmarshal(rendered.Files["private-login.json"], &profile); err != nil ||
		len(profile.Prefixes) != 2 || profile.Prefixes[0] != "172.30.0.10/32" || profile.Prefixes[1] != "172.30.0.11/32" {
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
	if _, err := Render(testConfig(t), state, testKeys, testLayout); err != nil {
		t.Fatalf("same names: %v", err)
	}
	moved, err := ParseConfig([]byte(strings.Replace(validConfig, "mesh.example.com", "vpn.example.com", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Render(moved, state, testKeys, testLayout); !errors.Is(err, ErrPublicNamesChanged) {
		t.Fatalf("new domain: %v", err)
	}
}

func TestRenderPinsTheApprovedFingerprintAndMatchesAcrossFiles(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	state := approvedState()
	rendered, err := Render(config, state, testKeys, testLayout)
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
	digest := sha256.Sum256(rendered.Files["relay-map.json"])
	if core["MESHTRANSIT_RELAY_MAP_SHA256"] != "sha256:"+hex.EncodeToString(digest[:]) ||
		core["MESHTRANSIT_RELAY_AUTHORITY_ENABLED"] != "true" ||
		core["MESHTRANSIT_RELAY_DEPLOYMENT_PUBLIC_ID"] != state.DeploymentID {
		t.Fatal("relay authority settings do not match the rendered map")
	}
	if !strings.Contains(string(rendered.Files["relay-map.json"]), testKeys.Relay) {
		t.Fatal("relay map lacks the relay's key")
	}
	relay := parseEnv(t, rendered.Files["relay.env"])
	if relay["MESHRELAY_TRUSTED_SIGNING_KEYS"] != testKeys.Signing || relay["MESHRELAY_CORE_URL"] != "https://mesh.example.com" {
		t.Fatalf("relay.env = %v", relay)
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
	rendered, err := Render(config, approvedState(), testKeys, testLayout)
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

func TestRenderSizesThePoolsForOneServerAndAdvancedRaisesThem(t *testing.T) {
	t.Parallel()
	rendered, err := Render(testConfig(t), approvedState(), testKeys, testLayout)
	if err != nil {
		t.Fatal(err)
	}
	core := parseEnv(t, rendered.Files["core.env"])
	for name, want := range map[string]string{
		"MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS":       "4",
		"MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS":        "2",
		"MESHTRANSIT_IDENTITY_POSTGRES_MAX_OPEN_CONNECTIONS": "4",
		"MESHTRANSIT_IDENTITY_POSTGRES_MAX_IDLE_CONNECTIONS": "2",
	} {
		if core[name] != want {
			t.Errorf("core.env %s = %q, want %q", name, core[name], want)
		}
	}
	config, err := ParseConfig([]byte(validConfig + "advanced:\n  MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS: \"8\"\n" +
		"  MESHTRANSIT_IDENTITY_POSTGRES_MAX_OPEN_CONNECTIONS: \"6\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	larger, err := Render(config, approvedState(), testKeys, testLayout)
	if err != nil {
		t.Fatal(err)
	}
	raised := parseEnv(t, larger.Files["core.env"])
	if raised["MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS"] != "8" ||
		raised["MESHTRANSIT_IDENTITY_POSTGRES_MAX_OPEN_CONNECTIONS"] != "6" {
		t.Fatalf("advanced: did not raise the pools: runtime %q, identity %q",
			raised["MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS"], raised["MESHTRANSIT_IDENTITY_POSTGRES_MAX_OPEN_CONNECTIONS"])
	}
}

func TestPostgresConnectionsRefusesPoolsOutsideCoresBounds(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS":       "4",
		"MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS":        "2",
		"MESHTRANSIT_IDENTITY_POSTGRES_MAX_OPEN_CONNECTIONS": "4",
	}
	if got, err := postgresConnections(base); err != nil || got != 20 {
		t.Fatalf("postgresConnections = %d, %v; want 20", got, err)
	}
	for _, bad := range []string{"0", "51", "", "x"} {
		settings := map[string]string{}
		for name, value := range base {
			settings[name] = value
		}
		settings["MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS"] = bad
		if _, err := postgresConnections(settings); err == nil {
			t.Errorf("worker pool %q was accepted", bad)
		}
	}
}
