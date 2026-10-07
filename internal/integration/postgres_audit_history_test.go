//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/audit/history"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"

	"github.com/jackc/pgx/v5"
)

// assertAuditHistory qualifies schema 117 after the sharing flow: the
// Session reads the share evidence of its own Networks newest first, pages
// continue without overlap, filters narrow the page, every sealed record
// verifies, and a Workspace the Session is not bound to stays hidden.
func assertAuditHistory(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	session accountsession.Session, providerScope, consumerScope, foreignScope network.Scope) {
	t.Helper()
	store, err := postgresadapter.NewAuditHistoryStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := history.NewService(store, integrationClock{})
	if err != nil {
		t.Fatal(err)
	}
	list := func(query history.Query) (history.Page, error) {
		listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return service.List(listCtx, session, query)
	}

	provider := history.Query{WorkspaceID: providerScope.WorkspaceID(), NetworkID: providerScope.NetworkID()}
	if _, err := list(provider); !errors.Is(err, history.ErrForbidden) {
		t.Fatalf("history before audit.read error = %v, want ErrForbidden", err)
	}
	grantAuditRead(ctx, t, admin)
	page, err := list(provider)
	if err != nil {
		t.Fatalf("list provider Network history: %v", err)
	}
	if len(page.Records) == 0 {
		t.Fatal("provider Network history is empty after the sharing flow")
	}
	actions := map[string]bool{}
	for index, record := range page.Records {
		if record.NetworkID != providerScope.NetworkID().String() || record.WorkspaceID != providerScope.WorkspaceID().String() {
			t.Fatalf("record %s belongs to %s/%s, want the provider Network", record.EventID, record.WorkspaceID, record.NetworkID)
		}
		if record.Integrity.Status != audit.IntegritySealed {
			t.Fatalf("record %s integrity = %s, want sealed", record.EventID, record.Integrity.Status)
		}
		if index > 0 && page.Records[index-1].EventTime < record.EventTime {
			t.Fatalf("records are not newest first at %d", index)
		}
		if record.ActorKind == audit.ActorPrincipal && page.Actors[record.ActorPrincipalID] == "" {
			t.Fatalf("record %s actor %s has no display name", record.EventID, record.ActorPrincipalID)
		}
		actions[record.Action] = true
	}
	if !actions["share_offer.created"] {
		t.Fatalf("provider history actions = %v, want share_offer.created", actions)
	}

	paged := provider
	paged.PageSize = 1
	seen := map[string]bool{}
	for step := 0; step < 3 && step < len(page.Records); step++ {
		one, err := list(paged)
		if err != nil || len(one.Records) != 1 {
			t.Fatalf("page %d = %d records, %v", step, len(one.Records), err)
		}
		if one.Records[0].EventID != page.Records[step].EventID || seen[one.Records[0].EventID] {
			t.Fatalf("page %d returned %s, want %s", step, one.Records[0].EventID, page.Records[step].EventID)
		}
		seen[one.Records[0].EventID] = true
		if one.Next == nil {
			break
		}
		paged.Cursor = one.Next
	}

	filtered := provider
	filtered.TargetKinds, filtered.ActorKind = []string{"share_offer"}, audit.ActorPrincipal
	narrow, err := list(filtered)
	if err != nil || len(narrow.Records) == 0 {
		t.Fatalf("filtered history = %d records, %v", len(narrow.Records), err)
	}
	for _, record := range narrow.Records {
		if record.TargetKind != "share_offer" || record.ActorKind != audit.ActorPrincipal {
			t.Fatalf("filter returned %s by %s", record.TargetKind, record.ActorKind)
		}
	}
	empty := provider
	empty.Until = time.Now().UTC().Add(-365 * 24 * time.Hour)
	if old, err := list(empty); err != nil || len(old.Records) != 0 || old.Next != nil {
		t.Fatalf("history a year ago = %d records, %v; want none", len(old.Records), err)
	}

	consumer := history.Query{WorkspaceID: consumerScope.WorkspaceID(), NetworkID: consumerScope.NetworkID()}
	if received, err := list(consumer); err != nil || len(received.Records) == 0 {
		t.Fatalf("consumer Network history = %d records, %v", len(received.Records), err)
	}

	foreign := history.Query{WorkspaceID: foreignScope.WorkspaceID(), NetworkID: foreignScope.NetworkID()}
	if _, err := list(foreign); !errors.Is(err, history.ErrForbidden) {
		t.Fatalf("foreign Network history error = %v, want ErrForbidden", err)
	}
	if _, err := list(history.Query{WorkspaceID: foreignScope.WorkspaceID()}); !errors.Is(err, history.ErrForbidden) {
		t.Fatalf("foreign Workspace history error = %v, want ErrForbidden", err)
	}
	// The fixture role is bound per Network, so Workspace-wide reading needs
	// a Workspace role such as owner, admin or auditor.
	if _, err := list(history.Query{WorkspaceID: providerScope.WorkspaceID()}); !errors.Is(err, history.ErrForbidden) {
		t.Fatalf("Workspace-wide history with a Network role error = %v, want ErrForbidden", err)
	}
}

// grantAuditRead gives the shared fixture role audit.read.
func grantAuditRead(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var networkRevision int64
	if err := admin.QueryRow(ctx, `SELECT network_revision FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&networkRevision); err != nil {
		t.Fatal(err)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000890",
		eventPublicID:          "01890f02-0000-7000-8000-000000000890",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000890",
		streamID:               203,
		aggregateKind:          "role_permission",
		aggregatePublicID:      "01890f00-0000-7000-8000-000000000890",
		aggregateVersion:       1,
		networkRevision:        networkRevision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "management_rbac.seeded",
		permission:             "system.bootstrap",
		outboxEventClass:       "management_rbac.seeded",
	}, func(transaction pgx.Tx) {
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 890, '01890f00-0000-7000-8000-000000000890'::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission WHERE permission.permission_key = 'audit.read'`); err != nil {
			t.Fatalf("grant audit.read: %v", err)
		}
	})
}
