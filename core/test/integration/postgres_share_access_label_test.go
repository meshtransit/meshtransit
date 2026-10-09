//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
)

// assertShareAccessLabelRules qualifies schema 94 on a fresh labeled offer:
// canonical storage, the frozen column, the provider-Network binding, the
// derived-name decision, and the exact-scope runtime reader.
func assertShareAccessLabelRules(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	service *sharing.Service,
	session accountsession.Session,
	providerScope, consumerScope, foreignScope network.Scope,
	resourceID resource.ID,
	maximumTraffic sharing.TrafficSet,
	reason sharing.AuditReason,
) {
	t.Helper()
	created, err := service.CreateOffer(ctx, mustCreateSharingOffer(
		t, providerScope, consumerScope, resourceID, maximumTraffic, session, reason, 170, "Labeled-DB",
	))
	if err != nil {
		t.Fatalf("create labeled Share Offer: %v", err)
	}
	offer, hasOffer := created.Offer()
	token, hasToken := created.Token()
	if !hasOffer || !hasToken || offer.AccessLabel().String() != "labeled-db" {
		t.Fatalf("labeled Share Offer = %+v", created)
	}
	assertDerivedAccessName(t, offer)

	_, err = admin.Exec(ctx, `UPDATE mesh.share_offer SET access_label = 'renamed' WHERE public_id = $1::UUID`,
		offer.Offer().ID().String())
	assertPostgreSQLCode(t, err, "23514")

	var providerWorkspace, providerNetwork, resourceInternal int64
	if err := admin.QueryRow(ctx, `SELECT offer.provider_workspace_id, offer.provider_network_id, export.resource_id
FROM mesh.share_offer AS offer
JOIN mesh.resource_export AS export ON export.id = offer.resource_export_id
WHERE offer.public_id = $1::UUID`, offer.Offer().ID().String()).Scan(
		&providerWorkspace, &providerNetwork, &resourceInternal,
	); err != nil {
		t.Fatalf("read labeled offer scope: %v", err)
	}
	for _, testCase := range []struct {
		name       string
		resourceID int64
		want       bool
	}{
		{name: "same Resource may reuse its label", resourceID: resourceInternal},
		{name: "another Resource cannot take a live label", resourceID: resourceInternal + 100000, want: true},
	} {
		var conflicts bool
		if err := admin.QueryRow(ctx, `SELECT mesh_ops.share_access_label_conflicts_v1(
    $1::BIGINT, $2::BIGINT, 'labeled-db', $3::BIGINT, pg_catalog.clock_timestamp())`,
			providerWorkspace, providerNetwork, testCase.resourceID,
		).Scan(&conflicts); err != nil || conflicts != testCase.want {
			t.Fatalf("%s: conflicts = %t, error = %v", testCase.name, conflicts, err)
		}
	}

	importedName, err := resource.ParseDisplayName("labeled-db")
	if err != nil {
		t.Fatal(err)
	}
	wrongName, err := sharing.ParseAccessName("labeled-db.shared.consumer.example")
	if err != nil {
		t.Fatal(err)
	}
	decision, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		OfferID: offer.Offer().ID(), ExpectedOfferVersion: offer.Offer().Version(),
		Token: token, Action: sharing.DecisionActionAccept,
		ImportedDisplayName: importedName, AccessName: wrongName, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 171),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DecideOffer(ctx, decision); !errors.Is(err, sharing.ErrInvalidManagementRequest) {
		t.Fatalf("accept with a name other than the derived one: error = %v, want invalid", err)
	}

	for _, testCase := range []struct {
		name  string
		scope network.Scope
		want  string
	}{
		{name: "consumer locator", scope: consumerScope, want: offer.AccessName().String()},
		{name: "unrelated Network", scope: foreignScope},
	} {
		got := readShareOfferAccessNameAsRuntime(ctx, t, admin, testCase.scope, offer.Offer().ID())
		if got != testCase.want {
			t.Fatalf("%s: runtime access name = %q, want %q", testCase.name, got, testCase.want)
		}
	}
}

func readShareOfferAccessNameAsRuntime(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	scope network.Scope,
	offerID sharing.OfferID,
) string {
	t.Helper()
	var workspaceInternal, networkInternal int64
	if err := admin.QueryRow(ctx, `SELECT network.workspace_id, network.id
FROM mesh.network AS network WHERE network.public_id = $1::UUID`, scope.NetworkID().String()).Scan(
		&workspaceInternal, &networkInternal,
	); err != nil {
		t.Fatalf("resolve runtime scope: %v", err)
	}
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setIntegrationScope(ctx, t, transaction, workspaceInternal, networkInternal)
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	var name *string
	if err := transaction.QueryRow(ctx, `SELECT mesh_ops.read_share_offer_access_name_v1($1::UUID)`,
		offerID.String()).Scan(&name); err != nil {
		t.Fatalf("runtime access-name read: %v", err)
	}
	if name == nil {
		return ""
	}
	return *name
}
