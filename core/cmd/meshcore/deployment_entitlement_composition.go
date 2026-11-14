package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment/entitlement"
	"meshtransit.net/core/internal/domain/deployment/entitlement/renewal"
	"meshtransit.net/core/internal/platform/config"
)

const entitlementRecordTimeout = 10 * time.Second

// errEntitlementStartup is the only error reported; details stay in the
// structured error code so no path, key or envelope content is logged.
var errEntitlementStartup = errors.New("deployment entitlement startup failure")

// recordDeploymentEntitlement verifies the mounted entitlement against the
// embedded issuer keys and this installation's key, then records it. A newer
// generation already recorded (another replica, or a self-renewal) is not an
// error. Another entitlement recorded under the mounted generation is not an
// error either when a self-renewal overtook the mount (mountSuperseded):
// Core runs with the recorded one and warns entitlement_mount_superseded (the
// operator issues the change again, after the recorded generation). Any
// other failure, an offline issuance reusing a generation included, stops
// startup so a misconfigured installation is visible at once; an expired
// entitlement still verifies and keeps tenants working.
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
	if errors.Is(err, postgresadapter.ErrEntitlementGenerationConflict) {
		current, found, readErr := store.CurrentDeploymentEntitlement(recordCtx, settings.DeploymentID)
		if readErr != nil {
			return "entitlement_record_unavailable", errEntitlementStartup
		}
		if !mountSuperseded(verified, current, found, verifier) {
			return "entitlement_rejected", errEntitlementStartup
		}
		logger.WarnContext(ctx, "deployment entitlement mount superseded",
			"error_code", "entitlement_mount_superseded", "entitlement_id", verified.ID.String(),
			"generation", verified.Generation, "signer_key_id", verified.KeyID,
			"recorded_generation", current.Generation, "recorded_signer_key_id", current.SignerKeyID)
		return "", nil
	}
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

// mountSuperseded reports a mounted generation that lost its number to a
// self-renewal: the recorded current generation is newer, or it is the same
// number and a self-renewal key (scoped in the allowlist) signed it. An
// offline issuance that reused a recorded generation is not superseded.
func mountSuperseded(mounted entitlement.Entitlement, current renewal.Current, found bool,
	verifier *entitlement.Verifier) bool {
	return found && (current.Generation > mounted.Generation ||
		(current.Generation == mounted.Generation && verifier.IsScoped(current.SignerKeyID)))
}

// composeEntitlementRenewer builds the self-renewal service when a renewal
// key is mounted (api role only, config enforces it). The key must be the
// allowlisted self-renewal key of this Deployment, or startup stops: a key
// that would sign entitlements Core refuses is a configuration error.
func composeEntitlementRenewer(ctx context.Context, settings *config.DeploymentEntitlementConfig,
	runtime *postgresadapter.Pool, logger *slog.Logger) (*renewal.Renewer, []prometheus.Collector, string, error) {
	renewer, code, err := buildEntitlementRenewer(ctx, settings, runtime, logger)
	if renewer == nil || err != nil {
		return nil, nil, code, err
	}
	return renewer, entitlementRenewalMetrics(renewer), "", nil
}

// entitlementRenewalMetrics exports the renewer's counters: renewal is due
// four months before expiry, so failures that keep coming show here long
// before anything lapses.
func entitlementRenewalMetrics(renewer *renewal.Renewer) []prometheus.Collector {
	counter := func(name, help string, read func(renewal.Measurements) uint64) prometheus.Collector {
		return prometheus.NewCounterFunc(prometheus.CounterOpts{
			Namespace: "meshtransit", Subsystem: "deployment_entitlement", Name: name, Help: help,
		}, func() float64 { return float64(read(renewer.Snapshot())) })
	}
	return []prometheus.Collector{
		counter("renewal_attempts_total", "Self-renewal attempts.",
			func(measured renewal.Measurements) uint64 { return measured.Attempts }),
		counter("renewals_total", "Generations this process renewed.",
			func(measured renewal.Measurements) uint64 { return measured.Renewed }),
		counter("renewal_failures_total", "Self-renewal attempts that failed.",
			func(measured renewal.Measurements) uint64 { return measured.Failed }),
	}
}

func buildEntitlementRenewer(ctx context.Context, settings *config.DeploymentEntitlementConfig,
	runtime *postgresadapter.Pool, logger *slog.Logger) (*renewal.Renewer, string, error) {
	if settings == nil || settings.RenewalKeyID() == "" {
		return nil, "", nil
	}
	if runtime == nil {
		return nil, "entitlement_storage_unavailable", errEntitlementStartup
	}
	_, installationSeed, err := settings.Load(ctx)
	if err != nil {
		return nil, "entitlement_material_unavailable", errEntitlementStartup
	}
	installation, err := entitlement.NewInstallation(installationSeed)
	clear(installationSeed[:])
	if err != nil {
		return nil, "entitlement_installation_key_invalid", errEntitlementStartup
	}
	renewalSeed, err := settings.LoadRenewalKey(ctx)
	if err != nil {
		return nil, "entitlement_renewal_key_unavailable", errEntitlementStartup
	}
	verifier, err := entitlement.TrustedVerifier()
	if err != nil {
		clear(renewalSeed[:])
		return nil, "entitlement_trust_invalid", errEntitlementStartup
	}
	signer, err := renewal.NewSigner(settings.RenewalKeyID(), renewalSeed, installation, settings.DeploymentID, verifier)
	clear(renewalSeed[:])
	if err != nil {
		return nil, "entitlement_renewal_key_not_allowlisted", errEntitlementStartup
	}
	store, err := postgresadapter.NewDeploymentEntitlementStore(runtime,
		postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: entitlementRecordTimeout})
	if err != nil {
		return nil, "entitlement_storage_unavailable", errEntitlementStartup
	}
	renewer, err := renewal.New(renewal.DefaultOptions(settings.DeploymentID), store, signer, logger)
	if err != nil {
		return nil, "entitlement_renewal_composition_failure", errEntitlementStartup
	}
	return renewer, "", nil
}

var _ renewal.Store = (*postgresadapter.DeploymentEntitlementStore)(nil)
