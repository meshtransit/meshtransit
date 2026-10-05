package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/deployment/entitlement"
)

const entitlementRecordTimeout = 10 * time.Second

// errEntitlementStartup is the only error reported; details stay in the
// structured error code so no path, key or envelope content is logged.
var errEntitlementStartup = errors.New("deployment entitlement startup failure")

// recordDeploymentEntitlement verifies the mounted entitlement against the
// embedded issuer keys and this installation's key, then records it. A newer
// generation already recorded by another replica is not an error. Any other
// failure stops startup so a misconfigured installation is visible at once;
// an expired entitlement still verifies and keeps tenants working.
func recordDeploymentEntitlement(ctx context.Context, settings *config.DeploymentEntitlementConfig,
	runtime *postgresadapter.Pool, logger *slog.Logger, now time.Time) (string, error) {
	if settings == nil {
		return "", nil
	}
	if runtime == nil {
		return "entitlement_storage_unavailable", errEntitlementStartup
	}
	envelope, seed, err := settings.Load(ctx)
	if err != nil {
		return "entitlement_material_unavailable", errEntitlementStartup
	}
	installation, err := entitlement.NewInstallation(seed)
	clear(seed[:])
	if err != nil {
		return "entitlement_installation_key_invalid", errEntitlementStartup
	}
	verifier, err := entitlement.TrustedVerifier()
	if err != nil {
		return "entitlement_trust_invalid", errEntitlementStartup
	}
	verified, err := verifier.Verify(envelope, settings.DeploymentID, installation, now)
	switch {
	case errors.Is(err, entitlement.ErrForeign):
		return "entitlement_foreign", errEntitlementStartup
	case errors.Is(err, entitlement.ErrUntrusted):
		return "entitlement_untrusted", errEntitlementStartup
	case errors.Is(err, entitlement.ErrNotYetValid):
		return "entitlement_not_yet_valid", errEntitlementStartup
	case err != nil:
		return "entitlement_invalid", errEntitlementStartup
	}
	store, err := postgresadapter.NewDeploymentEntitlementStore(runtime,
		postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: entitlementRecordTimeout})
	if err != nil {
		return "entitlement_storage_unavailable", errEntitlementStartup
	}
	recordCtx, cancel := context.WithTimeout(ctx, entitlementRecordTimeout)
	defer cancel()
	outcome, err := store.Record(recordCtx, verified)
	if errors.Is(err, postgresadapter.ErrEntitlementRejected) {
		return "entitlement_rejected", errEntitlementStartup
	}
	if err != nil {
		return "entitlement_record_unavailable", errEntitlementStartup
	}
	logger.InfoContext(ctx, "deployment entitlement verified",
		"entitlement_id", verified.ID.String(), "profile", string(verified.Profile),
		"generation", verified.Generation, "state", string(verified.StateAt(now)),
		"capabilities_sha256", verified.CapabilitiesSHA256(), "signer_key_id", verified.KeyID,
		"outcome", string(outcome))
	return "", nil
}
