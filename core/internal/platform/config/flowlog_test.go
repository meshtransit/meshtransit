package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
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
