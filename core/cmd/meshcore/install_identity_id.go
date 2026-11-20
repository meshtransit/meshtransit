package main

import (
	"context"
	"errors"
	"fmt"

	"meshtransit.net/core/internal/adapter/kubeapi"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/installsecrets"
)

const installDeploymentIDKey = "deployment-public-id"

var (
	// errInstallDeploymentID: the database, the values and the recorded ID
	// do not agree on the installation's Deployment ID.
	errInstallDeploymentID = errors.New("install: the Deployment ID differs between the database, the values and the install ConfigMap")
	// errInstallDeploymentIDRequired: nothing names the ID yet. The
	// installer sets it (it is also the login profile's deployment_id, which
	// creates the deployment), rather than the Job inventing one nothing
	// else uses.
	errInstallDeploymentIDRequired = errors.New("install: set the installation's Deployment ID (bootstrap.deploymentPublicID)")
	errInstallNotOurs              = errors.New("install: the install ConfigMap was not made by the bootstrap, or holds no valid ID")
)

// ensureInstallationID decides the installation's Deployment ID and records
// it in the immutable install ConfigMap: the database's, the values' and the
// recorded one must agree; at least one must exist. It reports the ID and
// whether it recorded it now.
func ensureInstallationID(ctx context.Context, store installSecretStore, plan installsecrets.Plan, database []string,
) (string, bool, error) {
	if len(database) > 1 {
		return "", false, fmt.Errorf("%w: the database holds %d deployments", errInstallDeploymentID, len(database))
	}
	name := installsecrets.InstallConfigMap(plan.Fullname)
	recorded, found, err := recordedInstallationID(ctx, store, name)
	if err != nil {
		return "", false, err
	}
	candidates := []string{}
	if len(database) == 1 {
		candidates = append(candidates, database[0])
	}
	if plan.DeploymentPublicID != "" {
		candidates = append(candidates, plan.DeploymentPublicID)
	}
	if found {
		candidates = append(candidates, recorded)
	}
	if len(candidates) == 0 {
		return "", false, errInstallDeploymentIDRequired
	}
	for _, candidate := range candidates {
		if candidate != candidates[0] {
			return "", false, errInstallDeploymentID
		}
	}
	if found {
		return recorded, false, nil
	}
	return recordInstallationID(ctx, store, name, candidates[0])
}

// recordedInstallationID reads the install ConfigMap's ID; one that is not
// the bootstrap's or holds no valid ID is refused.
func recordedInstallationID(ctx context.Context, store installSecretStore, name string) (string, bool, error) {
	existing, found, err := store.GetConfigMap(ctx, name)
	if err != nil {
		return "", false, fmt.Errorf("get ConfigMap %s: %w", name, err)
	}
	if !found {
		return "", false, nil
	}
	recorded := existing.Data[installDeploymentIDKey]
	if existing.Metadata.Labels[installManagedByLabel] != installManagedBy {
		return "", false, errInstallNotOurs
	}
	if _, err := deployment.ParseID(recorded); err != nil {
		return "", false, errInstallNotOurs
	}
	return recorded, true, nil
}

// recordInstallationID creates the immutable install ConfigMap with id; when
// another run created it first, its ID must be id.
func recordInstallationID(ctx context.Context, store installSecretStore, name, id string) (string, bool, error) {
	immutable := true
	created, err := store.CreateConfigMapIfAbsent(ctx, kubeapi.ConfigMap{
		Immutable: &immutable,
		Metadata: kubeapi.Metadata{Name: name, Labels: map[string]string{
			installManagedByLabel: installManagedBy, "app.kubernetes.io/part-of": "meshtransit",
		}, Annotations: map[string]string{
			"argocd.argoproj.io/compare-options": "IgnoreExtraneous", "argocd.argoproj.io/sync-options": "Prune=false",
			"meshtransit.net/backup": "required",
		}},
		Data: map[string]string{installDeploymentIDKey: id},
	})
	if err != nil {
		return "", false, fmt.Errorf("create ConfigMap %s: %w", name, err)
	}
	if created {
		return id, true, nil
	}
	recorded, found, err := recordedInstallationID(ctx, store, name)
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", false, errInstallNotOurs
	}
	if recorded != id {
		return "", false, errInstallDeploymentID
	}
	return id, false, nil
}
