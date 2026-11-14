//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/deployment/entitlement"
	"meshtransit.net/core/internal/domain/deployment/entitlement/issuer"
	"meshtransit.net/core/internal/domain/deployment/entitlement/renewal"
)

const integrationDeploymentPublicID = "01890f00-0000-7000-8000-000000000001"

type entitlementFixture struct {
	signing      ed25519.PrivateKey
	verifier     *entitlement.Verifier
	installation *entitlement.Installation
	installPub   ed25519.PublicKey
	deploymentID deployment.ID
}

func newEntitlementFixture(t *testing.T) entitlementFixture {
	t.Helper()
	signingPub, signing, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := entitlement.NewVerifier(map[string]ed25519.PublicKey{"integration": signingPub})
	if err != nil {
		t.Fatal(err)
	}
	var seed [ed25519.SeedSize]byte
	seed[0], seed[31] = 3, 5
	installation, err := entitlement.NewInstallation(seed)
	if err != nil {
		t.Fatal(err)
	}
	installPub, _ := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	deploymentID, err := deployment.ParseID(integrationDeploymentPublicID)
	if err != nil {
		t.Fatal(err)
	}
	return entitlementFixture{signing, verifier, installation, installPub, deploymentID}
}

func (f entitlementFixture) verified(t *testing.T, id string, generation, maxActive int64, profile string) entitlement.Entitlement {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	return f.verifiedWindow(t, id, generation, maxActive, min(maxActive, 5), profile,
		now.Add(-time.Minute), now.Add(30*24*time.Hour), 7*24*time.Hour)
}

func (f entitlementFixture) verifiedWindow(t *testing.T, id string, generation, maxActive, maxOwned int64,
	profile string, notBefore, expires time.Time, grace time.Duration) entitlement.Entitlement {
	t.Helper()
	raw, err := issuer.Sign(issuer.Claims{
		EntitlementID: id, DeploymentID: integrationDeploymentPublicID, InstallationPublicKey: f.installPub,
		Profile: profile, MaxActiveWorkspaces: maxActive, MaxOwnedWorkspacesPerAccount: maxOwned,
		Capabilities: []entitlement.Capability{}, Generation: generation,
		IssuedAt: notBefore, NotBefore: notBefore, ExpiresAt: expires, Grace: grace,
	}, "integration", f.signing)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.verifier.Verify(raw, f.deploymentID, f.installation, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// assertPostgreSQLDeploymentEntitlement drives schema 97 through the production
// store: record, replay, conflict, upgrade, stale generation, profile
// mismatch, immutability, audit evidence and capabilities v2.
func assertPostgreSQLDeploymentEntitlement(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewDeploymentEntitlementStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f := newEntitlementFixture(t)
	auditBefore := countAuditTarget(ctx, t, admin, "deployment_entitlement")

	first := f.verified(t, "01890f00-0000-7000-8000-0000000e0001", 1, 50, "cloud")
	if outcome, err := store.Record(ctx, first); err != nil || outcome != postgresadapter.EntitlementRecorded {
		t.Fatalf("first generation = %q, %v", outcome, err)
	}
	if outcome, err := store.Record(ctx, first); err != nil || outcome != postgresadapter.EntitlementReplayed {
		t.Fatalf("replay = %q, %v", outcome, err)
	}
	conflict := f.verified(t, "01890f00-0000-7000-8000-0000000e0001", 1, 60, "cloud")
	if _, err := store.Record(ctx, conflict); !errors.Is(err, postgresadapter.ErrEntitlementRejected) {
		t.Fatalf("conflicting generation content: %v", err)
	}
	second := f.verified(t, "01890f00-0000-7000-8000-0000000e0002", 2, 80, "cloud")
	if outcome, err := store.Record(ctx, second); err != nil || outcome != postgresadapter.EntitlementRecorded {
		t.Fatalf("upgrade = %q, %v", outcome, err)
	}
	if outcome, err := store.Record(ctx, first); err != nil || outcome != postgresadapter.EntitlementSuperseded {
		t.Fatalf("downgrade = %q, %v", outcome, err)
	}
	mismatch := f.verified(t, "01890f00-0000-7000-8000-0000000e0003", 3, 1, "self_hosted")
	if _, err := store.Record(ctx, mismatch); !errors.Is(err, postgresadapter.ErrEntitlementRejected) {
		t.Fatalf("profile mismatch: %v", err)
	}
	if countAuditTarget(ctx, t, admin, "deployment_entitlement") != auditBefore+2 {
		t.Fatal("each recorded generation must produce exactly one audit event")
	}
	if _, err := admin.Exec(ctx, `UPDATE mesh.deployment_entitlement SET max_active_workspaces = 1000`); err == nil {
		t.Fatal("entitlement rows are mutable")
	}

	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	var raw []byte
	if err := admin.QueryRow(ctx, `SELECT mesh_ops.read_console_deployment_capabilities_v2(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,
 pg_catalog.clock_timestamp())::TEXT`,
		owner.ID().String(), owner.DeploymentID().String(), owner.PrincipalID().String(),
		owner.IdentitySubjectID().String(), owner.Version(), owner.PrincipalAuthorityGeneration(),
		owner.AccountSessionGeneration(), owner.ProviderGeneration(), owner.DeploymentRecoveryEpoch(),
		workspaceID.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var capabilities struct {
		Profile     string `json:"profile"`
		Entitlement struct {
			Generation          int64    `json:"generation"`
			MaxActiveWorkspaces int64    `json:"max_active_workspaces"`
			Capabilities        []string `json:"capabilities"`
			State               string   `json:"state"`
		} `json:"entitlement"`
	}
	if err := json.Unmarshal(raw, &capabilities); err != nil || capabilities.Profile != "cloud" ||
		capabilities.Entitlement.Generation != 2 || capabilities.Entitlement.MaxActiveWorkspaces != 80 ||
		capabilities.Entitlement.State != "active" || capabilities.Entitlement.Capabilities == nil {
		t.Fatalf("capabilities v2 = %s, %v", raw, err)
	}
}

func countAuditTarget(ctx context.Context, t *testing.T, admin *pgx.Conn, kind string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event WHERE target_kind = $1`, kind).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// assertPostgreSQLDeploymentEntitlementRenewal drives schema 292 through the
// production store on whatever generation N is current: a renewal that is
// not due, a renewal that records N+1 with the same limits and audit
// evidence, a replica that finds the renewal lock held, a mounted N+1 that
// loses to it, and a startup Record of N+2 racing a renewal.
func assertPostgreSQLDeploymentEntitlementRenewal(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewDeploymentEntitlementStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f := newEntitlementFixture(t)
	renewalPublic, renewalPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := entitlement.NewScopedVerifier(map[string]entitlement.TrustedKey{
		"integration-renew": {Public: renewalPublic, Deployment: f.deploymentID, Profile: deployment.ProfileCloud},
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := renewal.NewSigner("integration-renew", [ed25519.SeedSize]byte(renewalPrivate.Seed()), f.installation,
		f.deploymentID, scoped)
	if err != nil {
		t.Fatal(err)
	}
	auditBefore := countAuditTarget(ctx, t, admin, "deployment_entitlement")

	var seen renewal.Current
	outcome, err := store.RenewDeploymentEntitlement(ctx, f.deploymentID,
		func(current renewal.Current) (entitlement.Entitlement, bool, error) {
			seen = current
			return entitlement.Entitlement{}, false, nil
		})
	if err != nil || outcome != renewal.OutcomeNotDue || seen.Generation < 1 ||
		seen.Profile != deployment.ProfileCloud || seen.SignerKeyID != "integration" || seen.DatabaseNow.IsZero() ||
		time.Until(seen.DatabaseNow).Abs() > time.Minute {
		t.Fatalf("not due = %q, %v, current %+v", outcome, err, seen)
	}
	// Only the api role reads it.
	for role, want := range map[string]bool{"mesh_runtime": true, "mesh_worker": false, "mesh_observer": false} {
		var allowed bool
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege($1,
 'mesh_ops.read_current_deployment_entitlement_v1(uuid)', 'EXECUTE')`, role).Scan(&allowed); err != nil {
			t.Fatal(err)
		}
		if allowed != want {
			t.Fatalf("%s EXECUTE = %v, want %v", role, allowed, want)
		}
	}

	var renewed entitlement.Entitlement
	outcome, err = store.RenewDeploymentEntitlement(ctx, f.deploymentID,
		func(current renewal.Current) (entitlement.Entitlement, bool, error) {
			next, err := signer.Next(current, current.DatabaseNow)
			renewed = next
			return next, err == nil, err
		})
	base := seen.Generation
	if err != nil || outcome != renewal.OutcomeRenewed || renewed.Generation != base+1 ||
		renewed.Limits != seen.Limits {
		t.Fatalf("renewal = %q, %v, %+v", outcome, err, renewed)
	}
	// Workspace creation compares not_before with the database's clock.
	var valid bool
	if err := admin.QueryRow(ctx, `SELECT not_before <= pg_catalog.clock_timestamp()
FROM mesh.deployment_entitlement ORDER BY generation DESC LIMIT 1`).Scan(&valid); err != nil || !valid {
		t.Fatalf("the renewed generation is not valid yet by the database's clock: %v", err)
	}
	var generation, maxActive int64
	var signer3 string
	if err := admin.QueryRow(ctx, `SELECT generation, max_active_workspaces, signer_key_id
FROM mesh.deployment_entitlement ORDER BY generation DESC LIMIT 1`).Scan(&generation, &maxActive, &signer3); err != nil {
		t.Fatal(err)
	}
	if generation != base+1 || maxActive != seen.Limits.MaxActiveWorkspaces || signer3 != "integration-renew" {
		t.Fatalf("recorded generation %d, max %d, signer %s", generation, maxActive, signer3)
	}
	if countAuditTarget(ctx, t, admin, "deployment_entitlement") != auditBefore+1 {
		t.Fatal("a renewal must produce exactly one audit event")
	}

	// Another replica holds the renewal lock: this one skips its turn.
	if _, err := admin.Exec(ctx, `SELECT pg_catalog.pg_advisory_lock($1::BIGINT)`, int64(0x4d54454e54524e57)); err != nil {
		t.Fatal(err)
	}
	outcome, err = store.RenewDeploymentEntitlement(ctx, f.deploymentID,
		func(renewal.Current) (entitlement.Entitlement, bool, error) {
			t.Error("a busy renewal read the current generation")
			return entitlement.Entitlement{}, false, nil
		})
	if _, unlockErr := admin.Exec(ctx, `SELECT pg_catalog.pg_advisory_unlock($1::BIGINT)`,
		int64(0x4d54454e54524e57)); unlockErr != nil {
		t.Fatal(unlockErr)
	}
	if err != nil || outcome != renewal.OutcomeBusy {
		t.Fatalf("busy = %q, %v", outcome, err)
	}

	// An offline N+1 mounted after the renewal took the number.
	mounted := f.verified(t, "01890f00-0000-7000-8000-0000000e0013", base+1, 90, "cloud")
	if _, err := store.Record(ctx, mounted); !errors.Is(err, postgresadapter.ErrEntitlementGenerationConflict) ||
		!errors.Is(err, postgresadapter.ErrEntitlementRejected) {
		t.Fatalf("mounted generation N+1 after the renewal: %v", err)
	}

	assertEntitlementRenewalRace(ctx, t, admin, store, f, signer, base+2)
}

// assertEntitlementRenewalRace races a renewal and a startup Record of the
// same generation: the renewal holds the Deployment row, Record waits for it
// (seen in pg_stat_activity, not by sleeping) and then loses with a
// generation conflict.
func assertEntitlementRenewalRace(ctx context.Context, t *testing.T, admin *pgx.Conn,
	store *postgresadapter.DeploymentEntitlementStore, f entitlementFixture, signer *renewal.Signer, generation int64) {
	t.Helper()
	mounted := f.verified(t, "01890f00-0000-7000-8000-0000000e0014", generation, 70, "cloud")
	recorded := make(chan error, 1)
	outcome, err := store.RenewDeploymentEntitlement(ctx, f.deploymentID,
		func(current renewal.Current) (entitlement.Entitlement, bool, error) {
			go func() {
				_, err := store.Record(ctx, mounted)
				recorded <- err
			}()
			deadline := time.Now().Add(10 * time.Second)
			for {
				var waiting int
				if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_stat_activity
WHERE wait_event_type = 'Lock' AND query LIKE '%record_deployment_entitlement_v1%'`).Scan(&waiting); err != nil {
					return entitlement.Entitlement{}, false, err
				}
				if waiting > 0 {
					break
				}
				if time.Now().After(deadline) {
					return entitlement.Entitlement{}, false, errors.New("Record never waited for the renewal")
				}
				time.Sleep(20 * time.Millisecond)
			}
			next, err := signer.Next(current, current.DatabaseNow)
			return next, err == nil, err
		})
	if err != nil || outcome != renewal.OutcomeRenewed {
		t.Fatalf("racing renewal = %q, %v", outcome, err)
	}
	if err := <-recorded; !errors.Is(err, postgresadapter.ErrEntitlementGenerationConflict) {
		t.Fatalf("the mounted generation that waited: %v", err)
	}
}
