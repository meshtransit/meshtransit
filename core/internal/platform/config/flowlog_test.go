package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"meshtransit.net/core/internal/platform/app"
)

func TestLoadFlowLogConfig(t *testing.T) {
	t.Parallel()
	private, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := hex.EncodeToString(private.PublicKey().Bytes())
	lookup := func(values map[string]string) LookupFunc {
		return func(name string) (string, bool) {
			value, ok := values[name]
			return value, ok
		}
	}
	none, err := loadFlowLogConfig(lookup(nil), app.RoleAPI)
	if err != nil || none != nil {
		t.Fatalf("none: %v %v", none, err)
	}
	loaded, err := loadFlowLogConfig(lookup(map[string]string{
		envFlowLogCredentialKey: key, envFlowLogCredentialKeyID: "meshflow-1",
	}), app.RoleAPI)
	if err != nil || loaded.CredentialKeyID != "meshflow-1" || !loaded.CredentialKey.Equal(private.PublicKey()) {
		t.Fatalf("loaded: %v %v", loaded, err)
	}
	for name, values := range map[string]map[string]string{
		"key only":   {envFlowLogCredentialKey: key},
		"id only":    {envFlowLogCredentialKeyID: "k"},
		"short key":  {envFlowLogCredentialKey: key[:62], envFlowLogCredentialKeyID: "k"},
		"bad id":     {envFlowLogCredentialKey: key, envFlowLogCredentialKeyID: "k k"},
		"not hex":    {envFlowLogCredentialKey: "zz" + key[2:], envFlowLogCredentialKeyID: "k"},
		"zero point": {envFlowLogCredentialKey: hex.EncodeToString(make([]byte, 32)), envFlowLogCredentialKeyID: "k"},
	} {
		if _, err := loadFlowLogConfig(lookup(values), app.RoleAPI); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := loadFlowLogConfig(lookup(map[string]string{
		envFlowLogCredentialKey: key, envFlowLogCredentialKeyID: "k",
	}), app.RoleWorker); err == nil {
		t.Error("loaded for a worker")
	}
}

func TestLoadFlowTicketConfig(t *testing.T) {
	t.Parallel()
	receiver, _ := ecdh.X25519().GenerateKey(rand.Reader)
	receiverKey := hex.EncodeToString(receiver.PublicKey().Bytes())
	current, next := writeSigningSeed(t, 0x51), writeSigningSeed(t, 0x52)
	const deploymentID = "01890f00-0000-7000-8000-000000000123"
	full := map[string]string{
		envFlowTicketSigningKeyFile: current, envFlowTicketNextSigningKey: next,
		envFlowTicketDeploymentID: deploymentID, envFlowTicketReceiverKey: receiverKey,
	}
	if none, err := loadFlowTicketConfig(mapLookup(nil), app.RoleControl); err != nil || none != nil {
		t.Fatalf("none: %v %v", none, err)
	}
	loaded, err := loadFlowTicketConfig(mapLookup(full), app.RoleControl)
	if err != nil || loaded.Deployment.String() != deploymentID || !loaded.ReceiverKey.Equal(receiver.PublicKey()) ||
		loaded.NextSigningKeyFile == nil {
		t.Fatalf("loaded: %v %v", loaded, err)
	}
	signing, upcoming, err := loaded.SigningKeys(t.Context())
	if err != nil || upcoming == nil || signing.Public() == upcoming.Public() {
		t.Fatalf("SigningKeys() = %v", err)
	}
	if printed := fmt.Sprintf("%v %+v %#v", *loaded, *loaded, *loaded); strings.Contains(printed, current) {
		t.Errorf("printed %q", printed)
	}
	without := func(name string, value ...string) map[string]string {
		values := make(map[string]string, len(full))
		for key, setting := range full {
			if key != name {
				values[key] = setting
			}
		}
		if len(value) == 1 {
			values[name] = value[0]
		}
		return values
	}
	for name, values := range map[string]map[string]string{
		"no key":          without(envFlowTicketSigningKeyFile),
		"no deployment":   without(envFlowTicketDeploymentID),
		"no receiver":     without(envFlowTicketReceiverKey),
		"bad deployment":  without(envFlowTicketDeploymentID, "not-an-id"),
		"zero receiver":   without(envFlowTicketReceiverKey, hex.EncodeToString(make([]byte, 32))),
		"short receiver":  without(envFlowTicketReceiverKey, receiverKey[:62]),
		"next is current": without(envFlowTicketNextSigningKey, current),
		"next only":       {envFlowTicketNextSigningKey: next},
	} {
		if _, err := loadFlowTicketConfig(mapLookup(values), app.RoleControl); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := loadFlowTicketConfig(mapLookup(full), app.RoleAPI); err == nil {
		t.Error("loaded for the API role")
	}
	if cfg, err := loadFlowTicketConfig(mapLookup(without(envFlowTicketNextSigningKey)), app.RoleAll); err != nil ||
		cfg.NextSigningKeyFile != nil {
		t.Errorf("without a next key: %v %v", cfg, err)
	}
}
