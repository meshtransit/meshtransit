package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		"version": 1, "address": "127.0.0.1:9443",
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

func TestPrivateLoginConfigOwnsExactLoopbackProfile(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"127.0.0.1:9443", "[::1]:9443"} {
		t.Run(address, func(t *testing.T) {
			process, document := privateLoginTestDocument(t)
			document["address"] = address
			profile, err := parsePrivateLoginConfig(privateLoginTestJSON(t, document), process)
			if err != nil {
				t.Fatal(err)
			}
			if profile.Address() != address || profile.Route().RedirectURI() != "https://"+address+"/auth/v1/callback" ||
				profile.Route().ClientAuthMethod() != "client_secret_basic" {
				t.Fatal("profile binding changed")
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

func TestPrivateLoginConfigRejectsUnsafeOperatorInput(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(Config, map[string]any)
	}{
		{name: "public bind", change: func(_ Config, d map[string]any) { d["address"] = "192.0.2.1:9443" }},
		{name: "wildcard bind", change: func(_ Config, d map[string]any) { d["address"] = "0.0.0.0:9443" }},
		{name: "zero port", change: func(_ Config, d map[string]any) { d["address"] = "127.0.0.1:0" }},
		{name: "mapped address", change: func(_ Config, d map[string]any) { d["address"] = "[::ffff:127.0.0.1]:9443" }},
		{name: "health conflict", change: func(p Config, d map[string]any) { d["address"] = p.HealthAddress }},
		{name: "API conflict", change: func(_ Config, d map[string]any) { d["address"] = "127.0.0.1:8444" }},
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
		valid + `{}`, strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(valid, `"id":"capture-v1"`, `"id":"capture-v1","id":"capture-v1"`, 1),
		strings.Repeat(" ", 16*1024+1), `[]`, `null`, `{"version":1`,
	} {
		if profile, err := parsePrivateLoginConfig([]byte(contents), process); profile != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("malformed/duplicate/trailing candidate released")
		}
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
	}{{mode: 0o600, valid: true}, {mode: 0o644}} {
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
	f.Add([]byte(`{"version":1,"version":1}`))
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
