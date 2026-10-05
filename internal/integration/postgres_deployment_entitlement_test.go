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
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/deployment/entitlement"
	"github.com/meshtransit/meshtransit/internal/deployment/entitlement/issuer"
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
	owned := min(maxActive, 5)
	raw, err := issuer.Sign(issuer.Claims{
		EntitlementID: id, DeploymentID: integrationDeploymentPublicID, InstallationPublicKey: f.installPub,
		Profile: profile, MaxActiveWorkspaces: maxActive, MaxOwnedWorkspacesPerAccount: owned,
		Capabilities: []entitlement.Capability{}, Generation: generation,
		IssuedAt: now.Add(-time.Minute), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(30 * 24 * time.Hour),
		Grace: 7 * 24 * time.Hour,
	}, "integration", f.signing)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.verifier.Verify(raw, f.deploymentID, f.installation, now)
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
