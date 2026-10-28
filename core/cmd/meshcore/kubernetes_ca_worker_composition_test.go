package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/platform/config"
)

func TestKubernetesCAWorkerCompositionRejectsMissingDependencies(t *testing.T) {
	t.Parallel()
	suffix := dnsname.Default()
	for _, pool := range []*postgresadapter.Pool{nil, {}} {
		worker, metrics, err := composeKubernetesCAWorker(config.KubernetesCAWorkerConfig{}, suffix, pool,
			discardCompositionLogger())
		if worker != nil || metrics != nil || !errors.Is(err, errInvalidKubernetesCAWorkerComposition) {
			t.Fatal("invalid worker pool accepted", err)
		}
	}
	if worker, _, err := composeKubernetesCAWorker(config.KubernetesCAWorkerConfig{}, dnsname.Suffix{},
		&postgresadapter.Pool{}, discardCompositionLogger()); worker != nil || err == nil {
		t.Fatal("a missing suffix accepted", err)
	}
}

// The wrap key file holds 32 bytes as base64url; anything else, or the
// all-zero key, is refused.
func TestReadWrapKey(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	write := func(name, content string) config.SecretFile {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := config.NewSecretFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	key := make([]byte, 32)
	key[0] = 7
	for name, content := range map[string]string{
		"unpadded": base64.RawURLEncoding.EncodeToString(key) + "\n",
		"padded":   base64.URLEncoding.EncodeToString(key),
		"standard": base64.StdEncoding.EncodeToString(append([]byte{7, 0xfb, 0xff}, key[3:]...)),
	} {
		got, err := readWrapKey(write(name, content))
		if err != nil || got[0] != 7 {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, content := range map[string]string{
		"short":   base64.RawURLEncoding.EncodeToString(key[:16]),
		"zero":    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"not b64": "not a key!",
	} {
		if _, err := readWrapKey(write(name, content)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
