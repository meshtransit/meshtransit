//go:build integration

package integration

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/sessioncontext"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace/settings"
)

func assertPostgreSQLWorkspaceRename(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewWorkspaceRenameStore(runtimePool, postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := settings.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	session := managementRBACAccountSessionFixture(t)
	workspaceID, _ := session.LoginWorkspaceID()
	correlationID, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	var name, code string
	var version, ownerGeneration, audits, outbox, networkRevision int64
	if err := admin.QueryRow(ctx, `SELECT workspace.display_name,workspace.version,workspace.authority_generation,
 identity.display_code,(SELECT count(*) FROM mesh_audit.audit_event),(SELECT count(*) FROM mesh_ops.outbox_event),
 (SELECT network_revision FROM mesh_ops.network_revision WHERE workspace_id=103 AND network_id=203)
 FROM mesh.workspace AS workspace JOIN mesh_ops.tenant_display_identity AS identity ON identity.workspace_public_id=workspace.public_id
 WHERE workspace.id=103`).Scan(&name, &version, &ownerGeneration, &code, &audits, &outbox, &networkRevision); err != nil {
		t.Fatal(err)
	}
	command := settings.Command{Session: session, WorkspaceID: workspaceID, DisplayName: "Renamed integration Workspace", ExpectedVersion: version, CorrelationID: correlationID}
	memberCommand := command
	memberCommand.Session = authorityConfirmerAccountSessionFixture(t)
	if _, err := service.Rename(ctx, memberCommand); !errors.Is(err, settings.ErrForbidden) {
		t.Fatal("member inherited owner rename authority", err)
	}
	result, err := service.Rename(ctx, command)
	if err != nil || result.DisplayCode.String() != code || result.Version != version+1 {
		t.Fatal("owner rename failed or display identity changed", err)
	}
	if _, err := service.Rename(ctx, command); !errors.Is(err, settings.ErrConflict) {
		t.Fatal("stale rename did not conflict", err)
	}
	var nextName, nextCode string
	var nextVersion, nextOwner, nextAudit, nextOutbox, nextRevision int64
	if err := admin.QueryRow(ctx, `SELECT workspace.display_name,workspace.version,workspace.authority_generation,
 identity.display_code,(SELECT count(*) FROM mesh_audit.audit_event),(SELECT count(*) FROM mesh_ops.outbox_event),
 (SELECT network_revision FROM mesh_ops.network_revision WHERE workspace_id=103 AND network_id=203)
 FROM mesh.workspace AS workspace JOIN mesh_ops.tenant_display_identity AS identity ON identity.workspace_public_id=workspace.public_id
 WHERE workspace.id=103`).Scan(&nextName, &nextVersion, &nextOwner, &nextCode, &nextAudit, &nextOutbox, &nextRevision); err != nil {
		t.Fatal(err)
	}
	if nextName != command.DisplayName || nextCode != code || nextVersion != version+1 || nextOwner != ownerGeneration ||
		nextAudit != audits+1 || nextOutbox != outbox+1 || nextRevision != networkRevision {
		t.Fatal("rename changed authority or failed atomic audit/outbox")
	}
	scopes, err := sessioncontext.NewService(newIntegrationAccountSessionStore(t, runtimePool), accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	page, err := scopes.List(ctx, session, 100, network.ID{})
	if err != nil || page.WorkspaceDisplayName() != nextName || !page.WorkspaceCanRename() || page.WorkspaceVersion() != nextVersion {
		t.Fatal("fresh projection lost owner name metadata", err)
	}
	if !slices.Contains(page.WorkspacePermissions(), "network.create") ||
		!slices.Contains(page.WorkspacePermissions(), "member.read") {
		t.Fatalf("owner projection lacks Workspace permissions: %v", page.WorkspacePermissions())
	}
	member, err := scopes.List(ctx, memberCommand.Session, 100, network.ID{})
	if err != nil || member.WorkspaceCanRename() {
		t.Fatal("member projection acquired owner hint", err)
	}
	if slices.Contains(member.WorkspacePermissions(), "role_binding.manage") {
		t.Fatalf("member projection acquired role management: %v", member.WorkspacePermissions())
	}
	command.ExpectedVersion = nextVersion
	assertWorkspaceRenameAuthorityDenials(ctx, t, admin, command)
	// Restore the label through the same public application path, leaving immutable evidence.
	command.DisplayName = name
	command.ExpectedVersion = nextVersion
	if _, err := service.Rename(ctx, command); err != nil {
		t.Fatal("restore integration Workspace name", err)
	}
}

func setWorkspaceRenameFixtureOwner(ctx context.Context, t *testing.T, admin *pgx.Conn, principal int64) {
	t.Helper()
	var version int64
	if err := admin.QueryRow(ctx, `SELECT version FROM mesh.workspace WHERE id=103`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	change, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	event, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: change.String(), eventPublicID: event.String(), outboxPublicID: outbox.String(),
		streamID: 1, aggregateKind: "workspace", aggregatePublicID: "01890f00-0000-7000-8000-000000000103",
		aggregateVersion: version + 1, action: "workspace.rename_fixture.owner_changed", permission: "system.bootstrap", outboxEventClass: "workspace.rename_fixture.owner_changed",
	}, func(tx pgx.Tx) {
		setIntegrationScope(ctx, t, tx, 103, 203)
		if _, err := tx.Exec(ctx, `UPDATE mesh.workspace SET owner_principal_id=$1,
 authority_generation=authority_generation+1,version=version+1,updated_at=pg_catalog.transaction_timestamp() WHERE id=103`, principal); err != nil {
			t.Fatal(err)
		}
	})
}

func assertWorkspaceRenameAuthorityDenials(ctx context.Context, t *testing.T, admin *pgx.Conn, command settings.Command) {
	t.Helper()
	for _, test := range []struct{ name, query string }{
		{"ownership transferred", `UPDATE mesh.workspace SET owner_principal_id=14,authority_generation=authority_generation+1,version=version+1,updated_at=pg_catalog.transaction_timestamp() WHERE id=103`},
		{"membership suspended", `UPDATE mesh.workspace_membership SET state='suspended',authority_generation=authority_generation+1,version=version+1,updated_at=pg_catalog.transaction_timestamp() WHERE workspace_id=103 AND principal_id=11`},
		{"membership expired", `UPDATE mesh.workspace_membership SET expires_at=pg_catalog.transaction_timestamp()-INTERVAL '1 second',authority_generation=authority_generation+1,version=version+1,updated_at=pg_catalog.transaction_timestamp() WHERE workspace_id=103 AND principal_id=11`},
		{"Session revoked", `UPDATE mesh.account_session SET state='revoked',ended_at=pg_catalog.transaction_timestamp(),end_reason='local_logout',version=version+1,updated_at=pg_catalog.transaction_timestamp() WHERE public_id='01890f00-0000-7000-8000-000000000812'`},
		{"provider quarantined", `UPDATE mesh.identity_provider SET recovery_state='quarantined',version=version+1,updated_at=pg_catalog.transaction_timestamp() WHERE id=601`},
		{"Principal soft deleted", `UPDATE mesh.principal SET deleted_at=pg_catalog.transaction_timestamp(),version=version+1,updated_at=pg_catalog.transaction_timestamp() WHERE id=11`},
		{"Workspace soft deleted", `UPDATE mesh.workspace SET deleted_at=pg_catalog.transaction_timestamp(),version=version+1,updated_at=pg_catalog.transaction_timestamp() WHERE id=103`},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			change, err := publicid.New()
			if err != nil {
				t.Fatal(err)
			}
			setIntegrationChange(ctx, t, tx, change.String())
			setIntegrationScope(ctx, t, tx, 103, 203)
			if _, err := tx.Exec(ctx, test.query); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
				t.Fatal(err)
			}
			session := command.Session
			var count int64
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM mesh_ops.rename_owned_workspace_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,
 $10::UUID,$11::BIGINT,$12::TEXT,$13::UUID)`, session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(), session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(), session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(), command.WorkspaceID.String(), command.ExpectedVersion, "Denied rename", change.String()).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatal("rename bypassed current durable authority")
			}
		})
	}
}
