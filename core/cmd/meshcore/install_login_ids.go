package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"

	"meshtransit.net/core/internal/adapter/kubeapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/installsecrets"
)

const (
	loginProviderIDKey = "provider-id"
	loginClientIDKey   = "client-id"
	loginGenerationKey = "provider-generation"
	loginEpochKey      = "recovery-epoch"
)

// errInstallLoginIDs: the recorded login IDs differ from the database's.
var errInstallLoginIDs = errors.New("install: the recorded login provider or client differs from the database's")

// installLoginReport says what the login step wrote.
type installLoginReport struct {
	IDsRecorded bool   `json:"login_ids_recorded,omitempty"`
	State       string `json:"login_state,omitempty"`
}

// loginIdentityInput is what ensureLoginIdentity decides from: the plan,
// the database's login route (inDatabase when a deployment exists) and the
// ID generator.
type loginIdentityInput struct {
	plan       installsecrets.Plan
	database   postgresadapter.LoginIdentityRecord
	inDatabase bool
	newID      func() (string, error)
}

// ensureLoginIdentity keeps the login route's IDs for a version 5 login
// profile (V1-11 S2h): the database's when a deployment exists (the
// recorded ones must equal them), else the recorded ones, else new ones,
// in the immutable <fullname>-login-ids; the provider's generation and the
// recovery epoch, which follow the database, in <fullname>-login-state.
func ensureLoginIdentity(ctx context.Context, store installSecretStore, input loginIdentityInput,
) (installLoginReport, error) {
	plan, database, inDatabase, newID := input.plan, input.database, input.inDatabase, input.newID
	if plan.Login == nil {
		return installLoginReport{}, nil
	}
	report := installLoginReport{}
	idsName := installsecrets.LoginIDsConfigMap(plan.Fullname)
	recorded, found, err := readOwnConfigMap(ctx, store, idsName)
	if err != nil {
		return report, err
	}
	ids := map[string]string{}
	switch {
	case inDatabase:
		ids = map[string]string{loginProviderIDKey: database.ProviderID, loginClientIDKey: database.ClientID}
		if found && !maps.Equal(recorded, ids) {
			return report, errInstallLoginIDs
		}
	case found:
		ids = recorded
	default:
		for _, key := range []string{loginProviderIDKey, loginClientIDKey} {
			if ids[key], err = newID(); err != nil {
				return report, fmt.Errorf("generate a login ID: %w", err)
			}
		}
	}
	for _, key := range []string{loginProviderIDKey, loginClientIDKey} {
		if _, err := publicid.Parse(ids[key]); err != nil {
			return report, errInstallNotOurs
		}
	}
	if !found {
		if err := createImmutableConfigMap(ctx, store, idsName, ids); err != nil {
			return report, err
		}
		report.IDsRecorded = true
	}
	state := map[string]string{loginGenerationKey: "1", loginEpochKey: "1"}
	if inDatabase {
		state = map[string]string{
			loginGenerationKey: strconv.FormatInt(database.ProviderGeneration, 10),
			loginEpochKey:      strconv.FormatInt(database.RecoveryEpoch, 10),
		}
	}
	report.State, err = keepConfigMap(ctx, store, installsecrets.LoginStateConfigMap(plan.Fullname), state)
	return report, err
}

// readOwnConfigMap reads a ConfigMap the bootstrap made; one it did not
// make is refused.
func readOwnConfigMap(ctx context.Context, store installSecretStore, name string) (map[string]string, bool, error) {
	existing, found, err := store.GetConfigMap(ctx, name)
	if err != nil {
		return nil, false, fmt.Errorf("get ConfigMap %s: %w", name, err)
	}
	if !found {
		return nil, false, nil
	}
	if existing.Metadata.Labels[installManagedByLabel] != installManagedBy {
		return nil, false, errInstallNotOurs
	}
	return existing.Data, true, nil
}

func installConfigMapMetadata(name string) kubeapi.Metadata {
	return kubeapi.Metadata{Name: name, Labels: map[string]string{
		installManagedByLabel: installManagedBy, "app.kubernetes.io/part-of": "meshtransit",
	}, Annotations: map[string]string{
		"argocd.argoproj.io/compare-options": "IgnoreExtraneous", "argocd.argoproj.io/sync-options": "Prune=false",
	}}
}

// createImmutableConfigMap creates name with data, immutable; when another
// run created it first, its data must be the same.
func createImmutableConfigMap(ctx context.Context, store installSecretStore, name string, data map[string]string) error {
	immutable := true
	metadata := installConfigMapMetadata(name)
	metadata.Annotations["meshtransit.net/backup"] = "required"
	created, err := store.CreateConfigMapIfAbsent(ctx, kubeapi.ConfigMap{Immutable: &immutable, Metadata: metadata, Data: data})
	if err != nil {
		return fmt.Errorf("create ConfigMap %s: %w", name, err)
	}
	if created {
		return nil
	}
	recorded, found, err := readOwnConfigMap(ctx, store, name)
	if err != nil {
		return err
	}
	if !found || !maps.Equal(recorded, data) {
		return errInstallLoginIDs
	}
	return nil
}

// keepConfigMap makes name hold data: created, updated when it differs
// (one retry after a conflict), or left alone. It reports "created",
// "updated" or "".
func keepConfigMap(ctx context.Context, store installSecretStore, name string, data map[string]string) (string, error) {
	existing, found, err := store.GetConfigMap(ctx, name)
	if err != nil {
		return "", fmt.Errorf("get ConfigMap %s: %w", name, err)
	}
	if !found {
		created, err := store.CreateConfigMapIfAbsent(ctx, kubeapi.ConfigMap{Metadata: installConfigMapMetadata(name), Data: data})
		if err != nil {
			return "", fmt.Errorf("create ConfigMap %s: %w", name, err)
		}
		if created {
			return "created", nil
		}
		if existing, found, err = store.GetConfigMap(ctx, name); err != nil || !found {
			return "", errors.Join(errInstallNotOurs, err)
		}
	}
	for attempt := 0; ; attempt++ {
		if existing.Metadata.Labels[installManagedByLabel] != installManagedBy {
			return "", errInstallNotOurs
		}
		if maps.Equal(existing.Data, data) {
			return "", nil
		}
		existing.Data = data
		err := store.UpdateConfigMap(ctx, existing)
		if err == nil {
			return "updated", nil
		}
		if !errors.Is(err, kubeapi.ErrConflict) || attempt > 0 {
			return "", fmt.Errorf("update ConfigMap %s: %w", name, err)
		}
		if existing, found, err = store.GetConfigMap(ctx, name); err != nil || !found {
			return "", errors.Join(errInstallNotOurs, err)
		}
	}
}
