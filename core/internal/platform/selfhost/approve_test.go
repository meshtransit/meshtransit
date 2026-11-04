package selfhost

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeFingerprint stands in for the broker's: a digest of the settings.
func fakeFingerprint(settings map[string]string) (string, error) {
	names := make([]string, 0, len(settings))
	for name := range settings {
		names = append(names, name)
	}
	slices.Sort(names)
	digest := sha256.New()
	for _, name := range names {
		digest.Write([]byte(name + "=" + settings[name] + "\n"))
	}
	return "sha256-v2:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func TestApproveIdentityPinsThenAsksAgainOnChange(t *testing.T) {
	t.Parallel()
	dir := secretsDir(t)
	layout := Layout{SecretsDir: dir, RunDir: "/var/lib/meshtransit/run"}
	config := testConfig(t)
	if _, err := GenerateSecrets(config, dir, GenerateOptions{Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	state, _ := LoadState(dir)
	if status, err := CheckIdentity(config, state, layout, fakeFingerprint); err != nil || status != IdentityUnapproved {
		t.Fatalf("new installation status = %v, %v", status, err)
	}
	first, err := ApproveIdentity(config, layout, fakeFingerprint, nil)
	if err != nil || first.IdentityFingerprint == "" || first.ConnectorGeneration != 1 {
		t.Fatalf("first approval = %+v, %v", first, err)
	}
	if status, _ := CheckIdentity(config, first, layout, fakeFingerprint); status != IdentityApproved {
		t.Fatalf("after approval status = %v", status)
	}
	// Approving again without a change changes nothing.
	again, err := ApproveIdentity(config, layout, fakeFingerprint, nil)
	if err != nil || again != first {
		t.Fatalf("second approval = %+v, %v", again, err)
	}
	// A new upstream client is a change: render keeps the old pin until it
	// is approved, and approval moves the generations on.
	changed, err := ParseConfig([]byte(strings.Replace(validConfig, "1234.apps", "5678.apps", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := CheckIdentity(changed, first, layout, fakeFingerprint); status != IdentityChanged {
		t.Fatalf("changed client status = %v", status)
	}
	rendered, err := Render(changed, first, layout)
	if err != nil || parseEnv(t, rendered.Files["core.env"])["MESHTRANSIT_IDENTITY_CONFIGURATION_FINGERPRINT"] !=
		first.IdentityFingerprint {
		t.Fatalf("render before approval does not keep the old pin: %v", err)
	}
	approved, err := ApproveIdentity(changed, layout, fakeFingerprint, nil)
	if err != nil || approved.ConnectorGeneration != 2 || approved.CoreClientGeneration != 2 ||
		approved.IdentityFingerprint == first.IdentityFingerprint {
		t.Fatalf("approved change = %+v, %v", approved, err)
	}
	if status, _ := CheckIdentity(changed, approved, layout, fakeFingerprint); status != IdentityApproved {
		t.Fatalf("after approving the change status = %v", status)
	}
	if loaded, err := LoadState(dir); err != nil || loaded != approved {
		t.Fatalf("state on disk = %+v, %v", loaded, err)
	}
}
