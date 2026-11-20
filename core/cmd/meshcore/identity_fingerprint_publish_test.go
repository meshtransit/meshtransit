package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"meshtransit.net/core/internal/adapter/kubeapi"
	"meshtransit.net/core/internal/platform/config"
)

func TestPublishIdentityFingerprint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFakeSecretStore()
	changed, err := publishIdentityFingerprint(ctx, store, "mt-identity", "fp-a", "1111")
	if err != nil || !changed {
		t.Fatalf("first: %v %v", changed, err)
	}
	if changed, err = publishIdentityFingerprint(ctx, store, "mt-identity", "fp-a", "1111"); err != nil || changed {
		t.Fatalf("same again: %v %v", changed, err)
	}
	// Seven renders: the newest five stay, newest first.
	for index := range 6 {
		store.conflicts = index % 2
		key := fmt.Sprintf("fp-%c", 'b'+index)
		if _, err := publishIdentityFingerprint(ctx, store, "mt-identity", key, strings.Repeat("2", index+1)); err != nil {
			t.Fatal(err)
		}
	}
	configMap := store.configMaps["mt-identity"]
	if got := configMap.Metadata.Annotations[fingerprintKeysAnnotation]; got != "fp-g,fp-f,fp-e,fp-d,fp-c" {
		t.Fatalf("order = %s", got)
	}
	if len(configMap.Data) != keptFingerprints || configMap.Data["fp-g"] != "222222" || configMap.Data["fp-a"] != "" {
		t.Fatalf("data = %v", configMap.Data)
	}
	// A render key's fingerprint changes when its value does.
	if changed, err = publishIdentityFingerprint(ctx, store, "mt-identity", "fp-e", "9999"); err != nil || !changed ||
		store.configMaps["mt-identity"].Data["fp-e"] != "9999" {
		t.Fatalf("changed value: %v %v", changed, err)
	}
	// fp-c, the oldest kept, comes back: it moves first and survives the
	// next new render.
	if changed, err = publishIdentityFingerprint(ctx, store, "mt-identity", "fp-c", "222"); err != nil || !changed {
		t.Fatalf("returning render: %v %v", changed, err)
	}
	if _, err = publishIdentityFingerprint(ctx, store, "mt-identity", "fp-h", "8"); err != nil {
		t.Fatal(err)
	}
	if got := store.configMaps["mt-identity"].Metadata.Annotations[fingerprintKeysAnnotation]; got != "fp-h,fp-c,fp-e,fp-g,fp-f" {
		t.Fatalf("order after a returning render = %s", got)
	}
	// Two conflicts in a row fail; nothing is half-written.
	store.conflicts = 2
	if _, err = publishIdentityFingerprint(ctx, store, "mt-identity", "fp-i", "9"); !errors.Is(err, kubeapi.ErrConflict) {
		t.Fatalf("two conflicts: %v", err)
	}
	store.configMaps["foreign"] = kubeapi.ConfigMap{Metadata: kubeapi.Metadata{Name: "foreign"}}
	if _, err := publishIdentityFingerprint(ctx, store, "foreign", "fp-a", "1"); !errors.Is(err, errFingerprintNotOurs) {
		t.Fatalf("foreign: %v", err)
	}
}

func TestRunIdentityFingerprintPublish(t *testing.T) {
	t.Parallel()
	store := newFakeSecretStore()
	environment := map[string]string{envIdentityFingerprintConfigMap: "mt-identity", envIdentityFingerprintKey: "fp-abc"}
	lookup := func(name string) (string, bool) {
		value, ok := environment[name]
		return value, ok
	}
	calculate := func(config.LookupFunc) (string, error) { return "abcd", nil }
	stores := func() (identityFingerprintStore, error) { return store, nil }
	var output, errorOutput bytes.Buffer
	if code := runIdentityFingerprintPublish(context.Background(), lookup, &output, &errorOutput, calculate, stores); code != 0 ||
		!strings.Contains(output.String(), `"changed":true`) || strings.Contains(output.String(), `"fingerprint":`) || store.configMaps["mt-identity"].Data["fp-abc"] != "abcd" {
		t.Fatalf("publish: %d %s %s", code, output.String(), errorOutput.String())
	}
	environment[envIdentityFingerprintKey] = "FP_bad"
	errorOutput.Reset()
	if code := runIdentityFingerprintPublish(context.Background(), lookup, &output, &errorOutput, calculate, stores); code != 1 ||
		!strings.Contains(errorOutput.String(), "invalid_configuration") {
		t.Fatalf("bad key: %d %s", code, errorOutput.String())
	}
	environment[envIdentityFingerprintKey] = "fp-abc"
	failing := func(config.LookupFunc) (string, error) { return "", errors.New("no identity settings") }
	errorOutput.Reset()
	if code := runIdentityFingerprintPublish(context.Background(), lookup, &output, &errorOutput, failing, stores); code != 1 ||
		!strings.Contains(errorOutput.String(), "invalid_identity_configuration") {
		t.Fatalf("calculate fails: %d %s", code, errorOutput.String())
	}
}

func TestRunIdentityMigrateRefusesBadSettings(t *testing.T) {
	t.Parallel()
	var output, errorOutput bytes.Buffer
	lookup := func(string) (string, bool) { return "", false }
	if code := runIdentityMigrate(context.Background(), lookup, &output, &errorOutput); code != 1 ||
		!strings.Contains(errorOutput.String(), "invalid_migration_configuration") {
		t.Fatalf("migrate: %d %s", code, errorOutput.String())
	}
}

// A ConfigMap another run created between the read and the create is used.
func TestPublishIdentityFingerprintCreateRace(t *testing.T) {
	t.Parallel()
	store := &racingConfigMapStore{fakeSecretStore: newFakeSecretStore()}
	changed, err := publishIdentityFingerprint(context.Background(), store, "mt-identity", "fp-a", "1")
	if err != nil || !changed || store.configMaps["mt-identity"].Data["fp-a"] != "1" {
		t.Fatalf("race: %v %v %v", changed, err, store.configMaps["mt-identity"].Data)
	}
}

// racingConfigMapStore loses the first create to another run that wrote
// an older key.
type racingConfigMapStore struct {
	*fakeSecretStore
	raced bool
}

func (store *racingConfigMapStore) CreateConfigMapIfAbsent(ctx context.Context, configMap kubeapi.ConfigMap) (bool, error) {
	if !store.raced {
		store.raced = true
		other := configMap
		other.Data = map[string]string{"fp-old": "0"}
		other.Metadata.Annotations = map[string]string{fingerprintKeysAnnotation: "fp-old"}
		store.configMaps[configMap.Metadata.Name] = other
		return false, nil
	}
	return store.fakeSecretStore.CreateConfigMapIfAbsent(ctx, configMap)
}
