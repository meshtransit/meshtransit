//go:build integration

package integration

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	postgresmapsession "meshtransit.net/core/internal/adapter/postgres/mapsession"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// assertPostgreSQLExitMaps qualifies schema 205 through the shared map
// store: a consumer whose group a rule grants an Exit Pool gets the pool
// with its offering exit node as primary and peer; the exit node serves the
// pool and admits the consumer, both as Derive rebuilds them; an exit node
// that withdraws its offer leaves the pool unserved; a store without exit
// nodes carries none.
func assertPostgreSQLExitMaps(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	pools := newIntegrationExitPoolService(t, runtimePool)
	groups := newIntegrationDeviceGroupService(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	devices := activeFixtureDevices(ctx, t, admin, 2)
	exitNode, consumer := devices[0], devices[1]
	exitIdentity, consumerIdentity := fixtureDeviceIdentity(ctx, t, admin, exitNode),
		fixtureDeviceIdentity(ctx, t, admin, consumer)
	if row := readIntegrationDevice(ctx, t, admin, exitNode); row.ownership != "workspace" {
		if _, err := newIntegrationDeviceLifecycle(t, runtimePool).Change(ctx, owner, devicelifecycle.Request{
			Scope: scope, DeviceID: exitNode, Action: devicelifecycle.ActionTransferWorkspace, Reason: "Exit node",
			ExpectedVersion: row.version, CorrelationID: newCorrelationID(t)}); err != nil {
			t.Fatalf("transfer the exit node to the Workspace: %v", err)
		}
	}
	offers, err := postgresadapter.NewExitOfferStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := offers.ReportExitOffer(ctx, exitIdentity, true); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixtureRouteOffer(ctx, admin, `DELETE FROM mesh.device_exit_offer`); err != nil {
			t.Error(err)
		}
	}()
	created, err := pools.Create(ctx, owner, scope, exitpool.Definition{Name: "Map exit",
		ConntrackPerConsumer: exitpool.DefaultConntrackPerConsumer}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	poolID := created.Pool.ID
	if _, err := pools.PutNode(ctx, owner, scope, poolID, created.Pool.Version, exitpool.NodeAssignment{
		DeviceID: exitNode, Priority: 1, State: exitpool.NodeActive}, newCorrelationID(t)); err != nil {
		t.Fatalf("assign the exit node: %v", err)
	}
	clients, err := groups.Create(ctx, owner, scope, devicegroup.Definition{Name: "Exit map clients"},
		newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groups.ChangeMembers(ctx, owner, scope, clients.Group.ID, 1, []node.ID{consumer}, nil,
		newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
	base := fixturePolicyRevision(ctx, t, admin)
	compiler := newIntegrationExitPolicyCompiler(t, runtimePool)
	candidate, err := compileSiteRules(ctx, t, compiler, owner, scope, base+1,
		exitRuleIntent(t, scope, clients.Group.ID, poolID))
	if err != nil {
		t.Fatal(err)
	}
	reason, err := publication.NewAuditReason("integration exit maps")
	if err != nil {
		t.Fatal(err)
	}
	publish := func(candidate publication.Candidate, base int64) {
		command, err := publication.NewManagementCommand(publication.ManagementCommandParams{
			Candidate: candidate, BasePolicyRevision: base, AccountSession: owner, AuditReason: reason,
		})
		if err != nil {
			t.Fatal(err)
		}
		publishPolicyOverBrowserManagement(ctx, t, runtimePool, newIntegrationManagementPolicyPublicationService(t, runtimePool),
			command)
	}
	publish(candidate, base)

	store := func(exits bool) *postgresmapsession.Store {
		shared, err := postgresadapter.NewMapSessionStore(runtimePool, postgresadapter.MapSessionOptions{
			StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
			PeerCandidateLimit: mapsession.MaximumPeerCandidates, PolicyRuleLimit: mapsession.MaximumPacketPolicyRules,
			RelayDirectory: integrationRelayDirectory(t), SharedInventory: true,
			InventoryStatementTimeout: 30 * time.Second, InventoryMaxAge: 30 * time.Second,
			ExitNodes: exits, RoutePeerLimit: mapsession.DefaultPeerLimit,
		})
		if err != nil {
			t.Fatal(err)
		}
		return shared
	}
	exits := store(true)
	consumerMap, err := exits.Load(ctx, consumerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	granted := consumerMap.Routes().Exits()
	if len(granted) != 1 || granted[0].Ref != poolID.String() || granted[0].Name != "Map exit" ||
		granted[0].Primary != exitNode || granted[0].Status != mapsession.RouteServed ||
		!slices.Equal(granted[0].Candidates, []node.ID{exitNode}) || len(consumerMap.Routes().Sites()) != 0 {
		t.Fatalf("consumer exits = %+v", granted)
	}
	if !slices.ContainsFunc(consumerMap.AuthorizedPeers(), func(peer mapsession.PeerCandidate) bool {
		return peer.NodeID() == exitNode
	}) {
		t.Fatal("the consumer's map lacks its exit node")
	}
	exitMap, err := exits.Load(ctx, exitIdentity)
	if err != nil {
		t.Fatal(err)
	}
	served, inbound := exitMap.Routes().ServedExits(), exitMap.Routes().ExitInbound()
	if len(served) != 1 || served[0].Ref != poolID.String() ||
		served[0].ConntrackPerConsumer != exitpool.DefaultConntrackPerConsumer || len(inbound) != 1 ||
		!slices.Equal(inbound[0].Sources, []node.ID{consumer}) || len(exitMap.Routes().Exits()) != 0 {
		t.Fatalf("exit node served %+v, inbound %+v", served, inbound)
	}
	if derived, found, err := exits.Derive(ctx, consumerMap, 0); err != nil || !found ||
		!derived.Routes().Equal(consumerMap.Routes()) {
		t.Fatalf("derived consumer exits = %+v, found %t, error %v", derived.Routes().Exits(), found, err)
	}
	if plain, err := store(false).Load(ctx, consumerIdentity); err != nil || !plain.Routes().IsEmpty() {
		t.Fatalf("exits without exit nodes on = %+v, error %v", plain.Routes().Exits(), err)
	}
	// Withdrawing the offer advances the Network: the pool stays granted,
	// with its exit node still the primary before any election, unserved.
	if _, err := offers.ReportExitOffer(ctx, exitIdentity, false); err != nil {
		t.Fatal(err)
	}
	if withdrawn, err := exits.Load(ctx, consumerIdentity); err != nil || len(withdrawn.Routes().Exits()) != 1 ||
		withdrawn.Routes().Exits()[0].Status != mapsession.RouteUnserved {
		t.Fatalf("exits after the offer was withdrawn = %+v, error %v", withdrawn.Routes().Exits(), err)
	}
	if exitMap, err := exits.Load(ctx, exitIdentity); err != nil || len(exitMap.Routes().ServedExits()) != 0 {
		t.Fatalf("an exit node without offer serves %+v, error %v", exitMap.Routes().ServedExits(), err)
	}

	// Clean up: a deny-all release frees the pool and the group.
	empty, err := compilation.NewRequest(compilation.RequestParams{Scope: scope, Revision: base + 2,
		Rules: []compilation.RuleIntent{}})
	if err != nil {
		t.Fatal(err)
	}
	denyAll, err := compiler.Compile(ctx, owner, empty)
	if err != nil {
		t.Fatal(err)
	}
	publish(denyAll, base+1)
	reading, err := pools.Read(ctx, owner, scope, poolID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pools.Delete(ctx, owner, scope, poolID, reading.Pool.Version, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the pool: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, scope, clients.Group.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the group: %v", err)
	}
}
