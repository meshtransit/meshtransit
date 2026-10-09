//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/domain/workspace/selection"
)

const switchSessionPublicID = "01890f00-0000-7000-8000-00000000a701"

// assertPostgreSQLSessionWorkspace drives schema 103 through the production
// store on a copy of the owner's Session, so later fixtures keep their exact
// Session version: list the Workspaces created in schema 99, switch into one,
// replay, reject a stale version and an unavailable Workspace, and refuse a
// direct login_workspace_id update.
func assertPostgreSQLSessionWorkspace(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewSessionWorkspaceStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := selection.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	owner := managementRBACAccountSessionFixture(t)
	copySessionForSwitch(ctx, t, admin, owner)
	login, _ := owner.LoginWorkspaceID()
	first := sessionWithWorkspace(t, owner, 1, login)

	candidates, err := service.List(ctx, first)
	if err != nil {
		t.Fatalf("list = %v", err)
	}
	var engineering workspace.ID
	current := 0
	for _, candidate := range candidates {
		if candidate.Current {
			current++
			if candidate.WorkspaceID != login {
				t.Fatalf("current candidate %s, want %s", candidate.WorkspaceID, login)
			}
		}
		if candidate.DisplayName == "Engineering" && candidate.Owner {
			engineering = candidate.WorkspaceID
		}
	}
	if current != 1 || !engineering.IsValid() {
		t.Fatalf("candidates = %+v", candidates)
	}
	auditBefore := countAuditTarget(ctx, t, admin, "account_session")

	switched, err := service.Switch(ctx, newSwitchCommand(t, first, engineering))
	if err != nil || switched.Replayed || switched.SessionVersion != 2 {
		t.Fatalf("switch = %+v, %v", switched, err)
	}
	second := sessionWithWorkspace(t, owner, 2, engineering)
	if replay, err := service.Switch(ctx, newSwitchCommand(t, second, engineering)); err != nil || !replay.Replayed ||
		replay.SessionVersion != 2 {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	if _, err := service.Switch(ctx, newSwitchCommand(t, first, login)); !errors.Is(err, selection.ErrForbidden) {
		t.Fatalf("stale Session version: %v", err)
	}
	if _, err := service.Switch(ctx, newSwitchCommand(t, second, workspace.ID(newPublicID(t)))); !errors.Is(err, selection.ErrNotAvailable) {
		t.Fatalf("unavailable Workspace: %v", err)
	}
	if countAuditTarget(ctx, t, admin, "account_session") != auditBefore+1 {
		t.Fatal("only the committed switch is audited")
	}
	after, err := service.List(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range after {
		if candidate.Current != (candidate.WorkspaceID == engineering) {
			t.Fatalf("after switch, candidate %s current=%v", candidate.WorkspaceID, candidate.Current)
		}
	}
	var bound string
	if err := admin.QueryRow(ctx, `SELECT w.public_id::TEXT FROM mesh.account_session s
JOIN mesh.workspace w ON w.id = s.login_workspace_id WHERE s.public_id = $1::UUID`, switchSessionPublicID).Scan(&bound); err != nil || bound != engineering.String() {
		t.Fatalf("bound Workspace = %s, %v", bound, err)
	}
	_, err = admin.Exec(ctx, `UPDATE mesh.account_session SET login_workspace_id = (
 SELECT id FROM mesh.workspace WHERE public_id = $2::UUID), version = version + 1
WHERE public_id = $1::UUID`, switchSessionPublicID, login.String())
	assertPostgreSQLCode(t, err, "23514")
}

// copySessionForSwitch inserts an active copy of the fixture Session with its
// own ID and token digest at version 1.
func copySessionForSwitch(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture accountsession.Session) {
	t.Helper()
	var columns []string
	rows, err := admin.Query(ctx, `SELECT column_name FROM information_schema.columns
WHERE table_schema = 'mesh' AND table_name = 'account_session'
  AND column_name NOT IN ('id', 'public_id', 'token_digest', 'version')
  AND is_generated = 'NEVER' ORDER BY ordinal_position`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, column)
	}
	rows.Close()
	if rows.Err() != nil || len(columns) == 0 {
		t.Fatalf("read account_session columns: %v", rows.Err())
	}
	list := strings.Join(columns, ", ")
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-00000000a701", eventPublicID: "01890f02-0000-7000-8000-00000000a701",
		outboxPublicID: "01890f03-0000-7000-8000-00000000a701", streamID: 1, aggregateKind: "account_session",
		aggregatePublicID: switchSessionPublicID, aggregateVersion: 1,
		action: "account_session.issued", permission: "identity.session", outboxEventClass: "identity.account_session.issued",
	}, func(transaction pgx.Tx) {
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.account_session (public_id, token_digest, version, `+list+`)
SELECT $1::UUID, pg_catalog.sha256(pg_catalog.convert_to($1::TEXT, 'UTF8')), 1, `+list+`
FROM mesh.account_session WHERE public_id = $2::UUID`, switchSessionPublicID, fixture.ID().String()); err != nil {
			t.Fatalf("copy Account Session: %v", err)
		}
	})
}

func sessionWithWorkspace(t *testing.T, fixture accountsession.Session, version int64, login workspace.ID) accountsession.Session {
	t.Helper()
	id, err := accountsession.ParseID(switchSessionPublicID)
	if err != nil {
		t.Fatal(err)
	}
	session, err := accountsession.NewSession(accountsession.Params{
		ID: id, DeploymentID: fixture.DeploymentID(), PrincipalID: fixture.PrincipalID(),
		IdentitySubjectID: fixture.IdentitySubjectID(), LoginWorkspaceID: login, HasLoginWorkspace: true,
		AuthenticationTime: fixture.AuthenticationTime(), ACR: fixture.ACR(), AMR: fixture.AMR(), Version: version,
		PrincipalAuthorityGeneration: fixture.PrincipalAuthorityGeneration(),
		AccountSessionGeneration:     fixture.AccountSessionGeneration(),
		ProviderGeneration:           fixture.ProviderGeneration(), DeploymentRecoveryEpoch: fixture.DeploymentRecoveryEpoch(),
		IdleExpiresAt: fixture.IdleExpiresAt(), AbsoluteExpiresAt: fixture.AbsoluteExpiresAt(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func newSwitchCommand(t *testing.T, session accountsession.Session, target workspace.ID) selection.SwitchCommand {
	t.Helper()
	return selection.SwitchCommand{Session: session, WorkspaceID: target, CorrelationID: newPublicID(t)}
}

func newPublicID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
