package config

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func entitlementValues(t *testing.T, role string) map[string]string {
	t.Helper()
	directory := t.TempDir()
	envelope := filepath.Join(directory, "entitlement.json")
	key := filepath.Join(directory, "installation.key")
	if err := os.WriteFile(envelope, []byte(`{"format":"x"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	seed[0] = 1
	if err := os.WriteFile(key, []byte(base64.RawURLEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return validProcessValues(map[string]string{
		envRole:                       role,
		envEntitlementDeploymentID:    "01958000-0000-7000-8000-000000000001",
		envEntitlementFile:            envelope,
		envEntitlementInstallationKey: key,
	})
}

func TestLoadDeploymentEntitlementIsOptionalAndAPIScoped(t *testing.T) {
	t.Parallel()
	loaded, err := Load(mapLookup(validProcessValues(map[string]string{envRole: "api"})))
	if err != nil || loaded.DeploymentEntitlement != nil {
		t.Fatal("entitlement configured without settings", err)
	}
	for _, role := range []string{"all", "api", "control", "worker", "relay"} {
		loaded, err := Load(mapLookup(entitlementValues(t, role)))
		if role != "all" && role != "api" {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s accepted entitlement settings", role)
			}
			continue
		}
		if err != nil || loaded.DeploymentEntitlement == nil {
			t.Fatalf("%s rejected entitlement settings: %v", role, err)
		}
		envelope, seed, err := loaded.DeploymentEntitlement.Load(t.Context())
		if err != nil || string(envelope) != `{"format":"x"}` || seed[0] != 1 {
			t.Fatalf("%s did not read entitlement material: %v", role, err)
		}
		if strings.Contains(loaded.DeploymentEntitlement.String(), "entitlement.json") {
			t.Fatal("entitlement path formatted")
		}
	}
}

func TestLoadDeploymentEntitlementIsAllOrNothing(t *testing.T) {
	t.Parallel()
	for _, missing := range []string{envEntitlementDeploymentID, envEntitlementFile, envEntitlementInstallationKey} {
		values := entitlementValues(t, "api")
		delete(values, missing)
		if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), missing) {
			t.Fatalf("missing %s accepted: %v", missing, err)
		}
	}
	values := entitlementValues(t, "api")
	values[envEntitlementDeploymentID] = "not-a-deployment"
	if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid Deployment ID accepted")
	}
	values = entitlementValues(t, "api")
	values[envEntitlementFile] = "relative/entitlement.json"
	if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) {
		t.Fatal("relative entitlement path accepted")
	}
}

func TestLoadDeploymentEntitlementRenewalKey(t *testing.T) {
	t.Parallel()
	values := entitlementValues(t, "api")
	renewal := filepath.Join(t.TempDir(), "renewal.key")
	seed := make([]byte, 32)
	seed[0] = 7
	if err := os.WriteFile(renewal, []byte(base64.RawURLEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	with := func(changes map[string]string) map[string]string {
		copied := make(map[string]string, len(values)+len(changes))
		for key, value := range values {
			copied[key] = value
		}
		for key, value := range changes {
			if value == "-" {
				delete(copied, key)
				continue
			}
			copied[key] = value
		}
		return copied
	}

	loaded, err := Load(mapLookup(values))
	if err != nil || loaded.DeploymentEntitlement.RenewalKeyID() != "" {
		t.Fatalf("no renewal key: %v", err)
	}
	loaded, err = Load(mapLookup(with(map[string]string{
		envEntitlementRenewalKeyID: "meshtransit-cloud-renew-2026", envEntitlementRenewalKey: renewal,
	})))
	if err != nil || loaded.DeploymentEntitlement.RenewalKeyID() != "meshtransit-cloud-renew-2026" {
		t.Fatalf("renewal key: %v", err)
	}
	if read, err := loaded.DeploymentEntitlement.LoadRenewalKey(t.Context()); err != nil || read[0] != 7 {
		t.Fatalf("LoadRenewalKey() = %v", err)
	}
	for name, changes := range map[string]map[string]string{
		"ID without key": {envEntitlementRenewalKeyID: "meshtransit-cloud-renew-2026"},
		"key without ID": {envEntitlementRenewalKey: renewal},
		"bad ID":         {envEntitlementRenewalKeyID: "Bad ID", envEntitlementRenewalKey: renewal},
		"without an entitlement": {
			envEntitlementRenewalKeyID: "meshtransit-cloud-renew-2026", envEntitlementRenewalKey: renewal,
			envEntitlementDeploymentID: "-", envEntitlementFile: "-", envEntitlementInstallationKey: "-",
		},
	} {
		if _, err := Load(mapLookup(with(changes))); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Load() = %v", name, err)
		}
	}
}
