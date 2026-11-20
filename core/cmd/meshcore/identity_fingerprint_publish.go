package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"meshtransit.net/core/internal/adapter/kubeapi"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
)

const (
	envIdentityFingerprintConfigMap = "MESHTRANSIT_IDENTITY_FINGERPRINT_CONFIGMAP"
	envIdentityFingerprintKey       = "MESHTRANSIT_IDENTITY_FINGERPRINT_KEY"
	// fingerprintKeysAnnotation lists the ConfigMap's keys, newest first.
	fingerprintKeysAnnotation = "meshtransit.net/fingerprint-keys"
	// keptFingerprints is how many renders' fingerprints the ConfigMap
	// keeps, so a rollback finds its own.
	keptFingerprints = 5
)

var (
	fingerprintKey        = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	fingerprintConfigMap  = regexp.MustCompile(`^[a-z0-9]([-.a-z0-9]{0,251}[a-z0-9])?$`)
	errFingerprintNotOurs = errors.New("identity fingerprint: the ConfigMap was not made by the install")
)

// identityFingerprintStore is the part of the Kubernetes API the publisher
// uses.
type identityFingerprintStore interface {
	GetConfigMap(ctx context.Context, name string) (kubeapi.ConfigMap, bool, error)
	CreateConfigMapIfAbsent(ctx context.Context, configMap kubeapi.ConfigMap) (bool, error)
	UpdateConfigMap(ctx context.Context, configMap kubeapi.ConfigMap) error
}

// runIdentityFingerprintPublish is "meshcore identity fingerprint publish"
// (the chart's identity fingerprint Job, V1-11 Q-Z5): fingerprint the
// identity configuration as the identity pods will see it and write it to
// a ConfigMap under the key the chart computed for this render, which the
// identity pods read. Installs approve their identity configuration this way,
// without a hand step.
func runIdentityFingerprintPublish(ctx context.Context, lookup config.LookupFunc, output, errorOutput io.Writer,
	calculate func(config.LookupFunc) (string, error), store func() (identityFingerprintStore, error),
) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	fail := func(code string, err error) int {
		logger.ErrorContext(ctx, "identity fingerprint publish failed", "error_code", code, "error", err)
		return 1
	}
	name, _ := lookup(envIdentityFingerprintConfigMap)
	key, _ := lookup(envIdentityFingerprintKey)
	if !fingerprintConfigMap.MatchString(name) || !fingerprintKey.MatchString(key) {
		return fail("invalid_configuration", errors.New("identity fingerprint: ConfigMap name or key"))
	}
	fingerprint, err := calculate(lookup)
	if err != nil {
		return fail("invalid_identity_configuration", err)
	}
	kube, err := store()
	if err != nil {
		return fail("install_kubernetes_unavailable", err)
	}
	changed, err := publishIdentityFingerprint(ctx, kube, name, key, fingerprint)
	if errors.Is(err, errFingerprintNotOurs) {
		return fail("identity_fingerprint_not_ours", err)
	}
	if err != nil {
		return fail("identity_fingerprint_publish_failure", err)
	}
	// A prefix only: the full digest covers client secrets, and logs travel
	// further than the ConfigMap.
	prefix := fingerprintPrefix(fingerprint)
	logger.InfoContext(ctx, "identity fingerprint published", "key", key, "fingerprint_prefix", prefix, "changed", changed)
	return writeInstallReport(output, map[string]any{
		"operation": "identity fingerprint publish", "key": key, "fingerprint_prefix": prefix, "changed": changed,
	})
}

func fingerprintPrefix(fingerprint string) string {
	if len(fingerprint) > 20 {
		return fingerprint[:20]
	}
	return fingerprint
}

// publishIdentityFingerprint sets key to fingerprint in the ConfigMap name,
// first in the order, and keeps the newest keptFingerprints keys. It
// reports whether it wrote.
func publishIdentityFingerprint(ctx context.Context, store identityFingerprintStore, name, key, fingerprint string,
) (bool, error) {
	existing, found, err := store.GetConfigMap(ctx, name)
	if err != nil {
		return false, fmt.Errorf("get ConfigMap %s: %w", name, err)
	}
	if !found {
		created, err := store.CreateConfigMapIfAbsent(ctx, kubeapi.ConfigMap{
			Metadata: kubeapi.Metadata{Name: name, Labels: map[string]string{
				installManagedByLabel: installManagedBy, "app.kubernetes.io/part-of": "meshtransit",
			}, Annotations: map[string]string{fingerprintKeysAnnotation: key}},
			Data: map[string]string{key: fingerprint},
		})
		if err != nil {
			return false, fmt.Errorf("create ConfigMap %s: %w", name, err)
		}
		if created {
			return true, nil
		}
		// Another run created it first: compare with what it wrote.
		if existing, err = rereadFingerprints(ctx, store, name); err != nil {
			return false, err
		}
	}
	for attempt := 0; ; attempt++ {
		if existing.Metadata.Labels[installManagedByLabel] != installManagedBy {
			return false, errFingerprintNotOurs
		}
		// Kept as it is only when it is the newest: a render that comes
		// back (a re-deployed image) moves to the front, so the next new
		// render does not drop it.
		order := strings.Split(existing.Metadata.Annotations[fingerprintKeysAnnotation], ",")
		if existing.Data[key] == fingerprint && order[0] == key {
			return false, nil
		}
		err := store.UpdateConfigMap(ctx, withFingerprint(existing, key, fingerprint))
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, kubeapi.ErrConflict) || attempt > 0 {
			return false, fmt.Errorf("update ConfigMap %s: %w", name, err)
		}
		if existing, err = rereadFingerprints(ctx, store, name); err != nil {
			return false, err
		}
	}
}

func rereadFingerprints(ctx context.Context, store identityFingerprintStore, name string) (kubeapi.ConfigMap, error) {
	existing, found, err := store.GetConfigMap(ctx, name)
	if err != nil {
		return kubeapi.ConfigMap{}, fmt.Errorf("get ConfigMap %s: %w", name, err)
	}
	if !found {
		return kubeapi.ConfigMap{}, fmt.Errorf("ConfigMap %s disappeared: %w", name, errFingerprintNotOurs)
	}
	return existing, nil
}

// withFingerprint returns a copy of configMap with key set first in the
// order and only the newest keptFingerprints keys kept.
func withFingerprint(configMap kubeapi.ConfigMap, key, fingerprint string) kubeapi.ConfigMap {
	order := []string{key}
	for _, older := range strings.Split(configMap.Metadata.Annotations[fingerprintKeysAnnotation], ",") {
		if older != "" && older != key && !slices.Contains(order, older) {
			order = append(order, older)
		}
	}
	if len(order) > keptFingerprints {
		order = order[:keptFingerprints]
	}
	data := map[string]string{}
	for _, kept := range order {
		if kept == key {
			data[kept] = fingerprint
		} else if value, ok := configMap.Data[kept]; ok {
			data[kept] = value
		}
	}
	annotations := map[string]string{}
	for name, value := range configMap.Metadata.Annotations {
		annotations[name] = value
	}
	annotations[fingerprintKeysAnnotation] = strings.Join(order, ",")
	updated := configMap
	updated.Metadata.Annotations = annotations
	updated.Data = data
	return updated
}
