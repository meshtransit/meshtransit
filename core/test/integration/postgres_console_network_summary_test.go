//go:build integration

package integration

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identity/sessioncontext"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/networksummary"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// Schema 278: the Console reads of the summaries list exactly the Networks
// the management-scope projection gives the Session, with exactly its
// permissions, and each figure only with the permission it needs; the
// one-Network read uses the same projection for that Network alone, so it
// agrees with the list (TD-CON-48 C4).
func assertPostgreSQLConsoleNetworkSummaries(ctx context.Context, t *testing.T, admin *pgx.Conn,
	workerPool, runtimePool *postgresadapter.Pool) {
	t.Helper()
	summarizeEveryNetwork(ctx, t, admin, workerPool)
	reader, err := postgresadapter.NewConsoleNetworkSummaryStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := sessioncontext.NewService(newIntegrationAccountSessionStore(t, runtimePool), accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	for name, session := range map[string]accountsession.Session{
		"authority confirmer": authorityConfirmerAccountSessionFixture(t),
		"sharing manager":     managementRBACAccountSessionFixture(t),
	} {
		workspaceID, _ := session.LoginWorkspaceID()
		scopePage, err := scopes.List(ctx, session, 100, network.ID{})
		if err != nil {
			t.Fatal(name, "scopes", err)
		}
		page, err := reader.ReadPage(ctx, session, workspaceID, networksummary.PageRequest{Limit: 50})
		if err != nil {
			t.Fatal(name, "page", err)
		}
		if len(page.Items) != len(scopePage.Items()) || page.Next.IsValid() {
			t.Fatalf("%s: %d summaries for %d scopes", name, len(page.Items), len(scopePage.Items()))
		}
		for index, scope := range scopePage.Items() {
			item := page.Items[index]
			want := make([]string, 0, len(scope.Permissions()))
			for _, permission := range scope.Permissions() {
				want = append(want, string(permission))
			}
			if item.NetworkID != scope.NetworkID() || !slices.Equal(item.Permissions, want) {
				t.Fatalf("%s: item %d = %s %v, scope %s %v", name, index, item.NetworkID, item.Permissions,
					scope.NetworkID(), want)
			}
			if item.ComputedAt == nil {
				var queued, marked, state string
				_ = admin.QueryRow(ctx, `SELECT COALESCE((SELECT format('%s/%s', dirty_generation, computed_generation)
 FROM mesh_ops.network_summary_queue AS queue WHERE queue.network_id = network.id), 'none'),
 (SELECT count(*)::TEXT FROM mesh_ops.network_summary_mark AS mark WHERE mark.network_id = network.id), network.state
 FROM mesh.network AS network WHERE network.public_id = $1::UUID`, item.NetworkID.String()).Scan(&queued, &marked, &state)
				t.Fatalf("%s: Network %s has no summary (queue %s, marks %s, state %s)", name, item.NetworkID, queued, marked, state)
			}
			assertFiguresGated(t, name, item, item.Permissions, false)
		}
		overview, err := reader.ReadOverview(ctx, session, workspaceID)
		if err != nil || overview.Networks != int64(len(page.Items)) {
			t.Fatalf("%s: overview %+v %v", name, overview, err)
		}
		if len(page.Items) == 0 {
			continue
		}
		// One Network: the same projection for that Network alone agrees
		// with the list.
		first := page.Items[0]
		scope, _ := network.NewScope(workspaceID, first.NetworkID)
		figures, err := reader.ReadNetwork(ctx, session, scope)
		if err != nil {
			t.Fatal(name, "one Network", err)
		}
		for _, permission := range []string{"device.read", "network.read", "policy.approve", "policy.read", "share.read"} {
			if slices.Contains(figures.Permissions, permission) != slices.Contains(first.Permissions, permission) {
				t.Fatalf("%s: %s resolved %v, projected %v", name, permission, figures.Permissions, first.Permissions)
			}
		}
		assertFiguresGated(t, name, figures, figures.Permissions, true)
		// Search finds a Network by its display code, with spaces or dashes.
		if first.DisplayCode != "" {
			code := first.DisplayCode[:4] + " " + first.DisplayCode[4:8] + "-" + first.DisplayCode[8:]
			found, err := reader.ReadPage(ctx, session, workspaceID, networksummary.PageRequest{Limit: 10, Query: code})
			if err != nil || len(found.Items) != 1 || found.Items[0].NetworkID != first.NetworkID {
				t.Fatalf("%s: search by code %q = %+v %v", name, code, found, err)
			}
		}
		// An unknown Network answers as one the Session may not read.
		unknown, _ := network.ParseID("01890f00-0000-7000-8000-0000000002ff")
		unknownScope, _ := network.NewScope(workspaceID, unknown)
		if _, err := reader.ReadNetwork(ctx, session, unknownScope); !errors.Is(err, networksummary.ErrReadForbidden) {
			t.Fatalf("%s: unknown Network = %v", name, err)
		}
		// A search that matches nothing answers an empty, finished page.
		empty, err := reader.ReadPage(ctx, session, workspaceID,
			networksummary.PageRequest{Limit: 10, Query: "no-network-is-called-this"})
		if err != nil || len(empty.Items) != 0 || empty.Next.IsValid() || !empty.SearchedAll {
			t.Fatalf("%s: empty search = %+v %v", name, empty, err)
		}
	}
	// The functions put the projection's RLS settings back.
	assertSummaryReadRestoresSettings(ctx, t, admin, authorityConfirmerAccountSessionFixture(t))
	// A Session cannot read another Workspace's summaries.
	session := authorityConfirmerAccountSessionFixture(t)
	foreignWorkspace, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000199")
	if _, err := reader.ReadOverview(ctx, session, foreignWorkspace); err == nil {
		t.Fatal("a Session read another Workspace's overview")
	}
}

// Every figure is present exactly when the Session holds its permission
// (and, for the list, a summary exists; every fixture Network has one).
func assertFiguresGated(t *testing.T, name string, figures networksummary.Figures, permissions []string, single bool) {
	t.Helper()
	held := func(permission string) bool { return slices.Contains(permissions, permission) }
	checks := []struct {
		label   string
		present bool
		want    bool
	}{
		{"ipv4/addresses", figures.AddressesInUse != nil, held("network.read")},
		{"clusters", figures.KubernetesClusters != nil, held("network.read")},
		{"active Devices", figures.ActiveDevices != nil, held("device.read")},
		{"rules", figures.RuleCount != nil, held("policy.read")},
		{"approvals", figures.PendingApprovals != nil, held("policy.approve")},
		{"shares", figures.SharesOutActive != nil && figures.OffersWaiting != nil, held("share.read")},
	}
	if !single {
		checks = append(checks, struct {
			label   string
			present bool
			want    bool
		}{"Sites in a list", figures.Sites != nil, false})
	}
	for _, check := range checks {
		if check.present != check.want {
			t.Fatalf("%s: %s present %v, permission %v (%v)", name, check.label, check.present, check.want, permissions)
		}
	}
}

// summarizeEveryNetwork runs the worker's steps until no Network waits.
func summarizeEveryNetwork(ctx context.Context, t *testing.T, admin *pgx.Conn, workerPool *postgresadapter.Pool) {
	t.Helper()
	var installationText string
	if err := admin.QueryRow(ctx, `SELECT installation_public_id::TEXT FROM mesh.deployment WHERE id = 1`).
		Scan(&installationText); err != nil {
		t.Fatal(err)
	}
	installation, _ := deployment.ParseID(installationText)
	store, err := postgresadapter.NewNetworkSummaryStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	worker, _ := publicid.New()
	for range 10 {
		if _, err := store.Fold(ctx, 5000); err != nil {
			t.Fatal("fold", err)
		}
		claimed, err := store.Claim(ctx, installation, worker, 64, time.Minute)
		if err != nil {
			t.Fatal("claim", err)
		}
		if len(claimed) == 0 {
			return
		}
		for _, scope := range claimed {
			summary, found, err := store.Compute(ctx, installation, scope)
			if err != nil {
				t.Fatal("compute", err)
			}
			if !found {
				continue
			}
			if _, err := store.Save(ctx, installation, worker, summary, time.Millisecond, 0); err != nil {
				t.Fatal("save", err)
			}
		}
	}
}

func assertSummaryReadRestoresSettings(ctx context.Context, t *testing.T, admin *pgx.Conn,
	session accountsession.Session) {
	t.Helper()
	workspaceID, _ := session.LoginWorkspaceID()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config('mesh.requested_workspace_public_id', 'prior', TRUE),
pg_catalog.set_config('mesh.console_management_scope_workspace_public_id', 'prior', TRUE)`); err != nil {
		t.Fatal(err)
	}
	var overview *string
	if err := transaction.QueryRow(ctx, `SELECT mesh_ops.read_console_workspace_overview_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,
 pg_catalog.transaction_timestamp())::TEXT`, session.ID().String(), session.DeploymentID().String(),
		session.PrincipalID().String(), session.IdentitySubjectID().String(), session.Version(),
		session.PrincipalAuthorityGeneration(), session.AccountSessionGeneration(), session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(), workspaceID.String()).Scan(&overview); err != nil || overview == nil {
		t.Fatal("direct overview", err)
	}
	var requested, projection string
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.current_setting('mesh.requested_workspace_public_id', TRUE),
pg_catalog.current_setting('mesh.console_management_scope_workspace_public_id', TRUE)`).Scan(&requested, &projection); err != nil ||
		requested != "prior" || projection != "prior" {
		t.Fatalf("settings after the overview: %q %q (%v)", requested, projection, err)
	}
}
