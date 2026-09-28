package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/app"
)

func privateLoginTestDocument(t testing.TB) (Config, map[string]any) {
	t.Helper()
	process, err := Load(mapLookup(validProcessValues(map[string]string{envRole: "api"})))
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]any{}
	issuer := "https://identity.example.test/realm"
	for _, purpose := range []string{"initiation", "capture", "continuation", "management_csrf",
		"transaction_digest", "verifier_encryption", "subject_active", "provider_session"} {
		keys[purpose] = map[string]string{"id": purpose + "-v1", "file": "/run/private/" + purpose}
	}
	document := map[string]any{
		"version": 2, "address": "127.0.0.1:9443",
		"origin": "https://app.example.test", "trusted_proxy_prefixes": []string{"127.0.0.1/32"},
		"deployment_id":       "01890f00-0000-7000-8000-000000000001",
		"workspace_id":        "01890f00-0000-7000-8000-000000000002",
		"provider_id":         "01890f00-0000-7000-8000-000000000003",
		"client_id":           "01890f00-0000-7000-8000-000000000004",
		"provider_generation": 1, "recovery_epoch": 1,
		"issuer": issuer, "discovery_uri": issuer + "/discovery",
		"authorization_endpoint": issuer + "/authorize",
		"token_endpoint":         issuer + "/token",
		"jwks_uri":               issuer + "/jwks", "oidc_client_id": "private-browser",
		"redirect_id": "browser-callback", "return_route_id": "console", "keys": keys,
		"tls_certificate_file": filepath.Join("/run/private", "server.crt"),
		"tls_private_key_file": filepath.Join("/run/private", "server.key"),
	}
	document["client_secret_file"] = filepath.Join("/run/private", "client-secret")
	return process, document
}

func privateLoginTestJSON(t testing.TB, document map[string]any) []byte {
	t.Helper()
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func TestPrivateLoginConfigOwnsVersionedEdgeProfile(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, address, origin string
		version               int
		proxies               []string
	}{
		{name: "legacy ipv4 loopback", version: 1, address: "127.0.0.1:9443", origin: "https://127.0.0.1:9443"},
		{name: "legacy ipv6 loopback", version: 1, address: "[::1]:9443", origin: "https://[::1]:9443"},
		{name: "edge loopback", version: 2, address: "127.0.0.1:9443", origin: "https://app.example.test", proxies: []string{"127.0.0.1/32"}},
		{name: "edge private", version: 2, address: "10.20.30.40:9443", origin: "https://app.example.test", proxies: []string{"10.20.0.0/16", "fd20:30::/48"}},
		{name: "edge ipv4 wildcard", version: 2, address: "0.0.0.0:9443", origin: "https://app.example.test", proxies: []string{"10.20.0.0/16"}},
		{name: "edge ipv6 wildcard", version: 2, address: "[::]:9443", origin: "https://app.example.test", proxies: []string{"fd20:30::/48"}},
		{name: "broker edge wildcard", version: 3, address: "0.0.0.0:9443", origin: "https://app.example.test", proxies: []string{"10.20.0.0/16"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			process, document := privateLoginTestDocument(t)
			document["version"] = test.version
			document["address"] = test.address
			if test.version == 1 {
				delete(document, "origin")
				delete(document, "trusted_proxy_prefixes")
			} else {
				document["origin"] = test.origin
				document["trusted_proxy_prefixes"] = test.proxies
			}
			if test.version == 3 {
				document["connector_id"] = "google-v1"
				document["scopes"] = []string{"openid", "federated:id"}
			}
			profile, err := parsePrivateLoginConfig(privateLoginTestJSON(t, document), process)
			if err != nil {
				t.Fatal(err)
			}
			if profile.Address() != test.address || profile.Origin() != test.origin ||
				profile.Route().RedirectURI() != test.origin+"/auth/v1/callback" ||
				profile.Route().ClientAuthMethod() != "client_secret_basic" {
				t.Fatal("profile binding changed")
			}
			if test.version == 3 && (profile.Route().ConnectorID() != "google-v1" ||
				!slices.Equal(profile.Route().Scopes(), []string{"openid", "federated:id"})) {
				t.Fatal("broker route binding changed")
			}
			prefixes := make([]netip.Prefix, 0, len(test.proxies))
			for _, value := range test.proxies {
				prefixes = append(prefixes, netip.MustParsePrefix(value))
			}
			if !slices.Equal(profile.TrustedProxyPrefixes(), prefixes) {
				t.Fatal("trusted proxy binding changed")
			}
			if returned := profile.TrustedProxyPrefixes(); len(returned) > 0 {
				returned[0] = netip.MustParsePrefix("10.255.0.0/16")
				if slices.Equal(profile.TrustedProxyPrefixes(), returned) {
					t.Fatal("trusted proxy accessor released mutable ownership")
				}
			}
			if profile.keys.keys[8].File != process.API.AccountSessionDigest.Active.MaterialFile ||
				profile.keys.keys[9].File != process.API.IdempotencyDigest.MaterialFile ||
				profile.keys.keys[10].File != process.API.RateLimitDigest.MaterialFile {
				t.Fatal("API purpose owner forked")
			}
			for _, value := range []any{profile, &PrivateLoginFile{}, &PrivateLoginMaterial{ClientSecret: []byte("private")}} {
				if fmt.Sprint(value) != redactedValue || fmt.Sprintf("%#v", value) != redactedValue {
					t.Fatal("profile formatting disclosed")
				}
				if body, err := json.Marshal(value); err == nil || body != nil {
					t.Fatal("profile serialized")
				}
			}
		})
	}
}

func TestPrivateLoginConfigBindsSplitBrokerRoute(t *testing.T) {
	t.Parallel()
	process, document := privateLoginTestDocument(t)
	document["version"] = 3
	document["connector_id"] = "google-v1"
	document["scopes"] = []string{"openid", "federated:id"}
	profile, err := parsePrivateLoginConfig(privateLoginTestJSON(t, document), process)
	if err != nil || profile == nil || profile.Route().ConnectorID() != "google-v1" ||
		!slices.Equal(profile.Route().Scopes(), []string{"openid", "federated:id"}) {
		t.Fatalf("valid split broker route rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{name: "missing connector", change: func(document map[string]any) { delete(document, "connector_id") }},
		{name: "empty connector", change: func(document map[string]any) { document["connector_id"] = "" }},
		{name: "missing scopes", change: func(document map[string]any) { delete(document, "scopes") }},
		{name: "direct scopes", change: func(document map[string]any) { document["scopes"] = []string{"openid"} }},
		{name: "duplicate scopes", change: func(document map[string]any) {
			document["scopes"] = []string{"openid", "federated:id", "openid"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, candidate := privateLoginTestDocument(t)
			candidate["version"] = 3
			candidate["connector_id"] = "google-v1"
			candidate["scopes"] = []string{"openid", "federated:id"}
			test.change(candidate)
			if profile, err := parsePrivateLoginConfig(privateLoginTestJSON(t, candidate), process); profile != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe split broker route released")
			}
		})
	}
}

func TestPrivateLoginConfigRejectsUnsafeOperatorInput(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(Config, map[string]any)
	}{
		{name: "public bind", change: func(_ Config, d map[string]any) { d["address"] = "192.0.2.1:9443" }},
		{name: "legacy wildcard bind", change: func(_ Config, d map[string]any) {
			d["version"] = 1
			d["address"] = "0.0.0.0:9443"
			delete(d, "origin")
			delete(d, "trusted_proxy_prefixes")
		}},
		{name: "zero port", change: func(_ Config, d map[string]any) { d["address"] = "127.0.0.1:0" }},
		{name: "mapped address", change: func(_ Config, d map[string]any) { d["address"] = "[::ffff:127.0.0.1]:9443" }},
		{name: "health conflict", change: func(p Config, d map[string]any) { d["address"] = p.HealthAddress }},
		{name: "API conflict", change: func(_ Config, d map[string]any) { d["address"] = "127.0.0.1:8444" }},
		{name: "origin with path", change: func(_ Config, d map[string]any) { d["origin"] = "https://app.example.test/login" }},
		{name: "origin with port", change: func(_ Config, d map[string]any) { d["origin"] = "https://app.example.test:443" }},
		{name: "origin ip", change: func(_ Config, d map[string]any) { d["origin"] = "https://192.0.2.10" }},
		{name: "origin uppercase", change: func(_ Config, d map[string]any) { d["origin"] = "https://App.example.test" }},
		{name: "origin aliases issuer", change: func(_ Config, d map[string]any) { d["origin"] = "https://identity.example.test" }},
		{name: "empty proxies", change: func(_ Config, d map[string]any) { d["trusted_proxy_prefixes"] = []string{} }},
		{name: "wildcard proxy", change: func(_ Config, d map[string]any) { d["trusted_proxy_prefixes"] = []string{"0.0.0.0/0"} }},
		{name: "public proxy", change: func(_ Config, d map[string]any) { d["trusted_proxy_prefixes"] = []string{"192.0.2.0/24"} }},
		{name: "noncanonical proxy", change: func(_ Config, d map[string]any) { d["trusted_proxy_prefixes"] = []string{"10.0.1.1/24"} }},
		{name: "duplicate proxy", change: func(_ Config, d map[string]any) { d["trusted_proxy_prefixes"] = []string{"10.0.0.0/8", "10.0.0.0/8"} }},
		{name: "unknown field", change: func(_ Config, d map[string]any) { d["enabled"] = true }},
		{name: "case alias", change: func(_ Config, d map[string]any) { d["Version"] = 1 }},
		{name: "missing field", change: func(_ Config, d map[string]any) { delete(d, "recovery_epoch") }},
		{name: "null", change: func(_ Config, d map[string]any) { d["provider_generation"] = nil }},
		{name: "zero generation", change: func(_ Config, d map[string]any) { d["provider_generation"] = 0 }},
		{name: "unsafe issuer", change: func(_ Config, d map[string]any) {
			d["issuer"] = "http://identity.example.test/realm"
		}},
		{name: "credential alias", change: func(_ Config, d map[string]any) {
			d["client_secret_file"] = d["tls_private_key_file"]
		}},
		{name: "external alias", change: func(p Config, d map[string]any) {
			d["client_secret_file"] = p.Storage.Redis.PasswordFile.path
		}},
		{name: "missing key", change: func(_ Config, d map[string]any) {
			keys, ok := d["keys"].(map[string]any)
			if !ok {
				return
			}
			delete(keys, "capture")
		}},
		{name: "unknown key", change: func(_ Config, d map[string]any) {
			keys, ok := d["keys"].(map[string]any)
			if !ok {
				return
			}
			keys["session_active"] = keys["capture"]
		}},
		{name: "key alias", change: func(_ Config, d map[string]any) {
			keys, ok := d["keys"].(map[string]any)
			if !ok {
				return
			}
			keys["capture"] = keys["initiation"]
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			process, document := privateLoginTestDocument(t)
			test.change(process, document)
			profile, err := parsePrivateLoginConfig(privateLoginTestJSON(t, document), process)
			if profile != nil || !errors.Is(err, ErrInvalid) || err.Error() != ErrInvalid.Error() {
				t.Fatal("unsafe profile released")
			}
		})
	}
	process, document := privateLoginTestDocument(t)
	valid := string(privateLoginTestJSON(t, document))
	for _, contents := range []string{
		valid + `{}`, strings.Replace(valid, `"version":2`, `"version":2,"version":2`, 1),
		strings.Replace(valid, `"id":"capture-v1"`, `"id":"capture-v1","id":"capture-v1"`, 1),
		strings.Repeat(" ", 16*1024+1), `[]`, `null`, `{"version":1`,
	} {
		if profile, err := parsePrivateLoginConfig([]byte(contents), process); profile != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("malformed/duplicate/trailing candidate released")
		}
	}
}

func TestPrivateLoginConfigBindsEmbeddedIdentityWithoutSharingCustody(t *testing.T) {
	t.Parallel()

	validDocument := func(t *testing.T, process Config) map[string]any {
		t.Helper()
		_, document := privateLoginTestDocument(t)
		issuer := process.Identity.Issuer
		document["address"] = "127.0.0.1:9444"
		document["issuer"] = issuer
		document["discovery_uri"] = issuer + "/.well-known/openid-configuration"
		document["authorization_endpoint"] = issuer + "/auth"
		document["token_endpoint"] = issuer + "/token"
		document["jwks_uri"] = issuer + "/keys"
		document["oidc_client_id"] = process.Identity.Clients[0].ID
		document["version"] = 3
		document["connector_id"] = process.Identity.OIDCConnectors[0].ID
		document["scopes"] = []string{"openid", "federated:id"}
		return document
	}

	process, err := Load(mapLookup(validProcessValues(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if profile, err := parsePrivateLoginConfig(
		privateLoginTestJSON(t, validDocument(t, process)),
		process,
	); err != nil || profile == nil ||
		profile.Route().ConnectorID() != process.Identity.OIDCConnectors[0].ID ||
		!slices.Equal(profile.Route().Scopes(), []string{"openid", "federated:id"}) {
		t.Fatalf("valid embedded identity binding rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{name: "listener conflict", change: func(document map[string]any) {
			document["address"] = process.Identity.Listener.Address
		}},
		{name: "issuer mismatch", change: func(document map[string]any) {
			document["issuer"] = "https://other.example.test/oauth2"
		}},
		{name: "client mismatch", change: func(document map[string]any) {
			document["oidc_client_id"] = "other-client"
		}},
		{name: "connector mismatch", change: func(document map[string]any) {
			document["connector_id"] = "other-connector"
		}},
		{name: "identity secret alias", change: func(document map[string]any) {
			document["client_secret_file"] = process.Identity.Clients[0].SecretFile.path
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			document := validDocument(t, process)
			test.change(document)
			if profile, err := parsePrivateLoginConfig(
				privateLoginTestJSON(t, document),
				process,
			); profile != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe embedded identity binding released")
			}
		})
	}
}

func TestPrivateLoginFileDefaultRolesAndProtectedCustody(t *testing.T) {
	t.Parallel()
	for _, role := range []app.Role{app.RoleAPI, app.RoleAll, app.RoleControl, app.RoleWorker, app.RoleRelay} {
		reference, err := loadPrivateLoginFile(mapLookup(map[string]string{}), role)
		if reference != nil || err != nil {
			t.Fatal("default enabled")
		}
		_, err = loadPrivateLoginFile(mapLookup(map[string]string{envPrivateLoginConfigFile: "/run/private/login.json"}), role)
		valid := role == app.RoleAPI || role == app.RoleAll
		if (err == nil) != valid {
			t.Fatal("role mismatch")
		}
	}
	process, document := privateLoginTestDocument(t)
	path := filepath.Join(t.TempDir(), "login.json")
	if err := os.WriteFile(path, privateLoginTestJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	reference, err := loadPrivateLoginFile(mapLookup(map[string]string{envPrivateLoginConfigFile: path}), app.RoleAPI)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		mode  os.FileMode
		valid bool
	}{{mode: 0o600, valid: true}, {mode: 0o440, valid: true}, {mode: 0o640, valid: true}, {mode: 0o644}} {
		if err := os.Chmod(path, test.mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != test.mode {
			t.Fatal("fixture permissions not established")
		}
		profile, err := reference.Load(t.Context(), process)
		if test.valid {
			if profile == nil || err != nil {
				t.Fatal("protected candidate denied")
			}
		} else if profile != nil || !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), path) {
			t.Fatal("public file read or diagnostic disclosed")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if profile, err := reference.Load(ctx, process); profile != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("canceled read released")
	}
}

func FuzzPrivateLoginConfig(f *testing.F) {
	process, document := privateLoginTestDocument(f)
	f.Add(privateLoginTestJSON(f, document))
	f.Add([]byte(`{"version":2,"version":2}`))
	f.Fuzz(func(t *testing.T, contents []byte) {
		profile, err := parsePrivateLoginConfig(contents, process)
		if err != nil {
			if profile != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("partial candidate")
			}
			return
		}
		if !profile.Route().IsValid() || profile.Route().RedirectURI() != profile.Origin()+"/auth/v1/callback" {
			t.Fatal("invalid accepted route")
		}
	})
}
