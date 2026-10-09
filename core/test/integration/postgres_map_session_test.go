//go:build integration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/control"
	"github.com/meshtransit/meshtransit/core/internal/control/mapsession"
	registrationapp "github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/relay"
)

func assertPostgreSQLMapSessionSnapshot(
	ctx context.Context,
	t *testing.T,
	pool *postgresadapter.Pool,
	command registrationapp.Command,
) {
	t.Helper()
	store, err := postgresadapter.NewMapSessionStore(pool, postgresadapter.MapSessionOptions{
		StatementTimeout:   3 * time.Second,
		IdleTimeout:        5 * time.Second,
		PeerCandidateLimit: mapsession.MaximumPeerCandidates,
		PolicyRuleLimit:    mapsession.MaximumPacketPolicyRules,
		RelayDirectory:     integrationRelayDirectory(t),
	})
	if err != nil {
		t.Fatalf("postgres.NewMapSessionStore() error = %v", err)
	}
	service, err := mapsession.NewService(
		store,
		unusedEndpointObserver{},
		unusedConnectivityStore{},
		mapsession.ServiceOptions{EndpointTTL: 30 * time.Second, EndpointTimeout: time.Second},
	)
	if err != nil {
		t.Fatalf("mapsession.NewService() error = %v", err)
	}
	machine, err := control.NewAuthenticatedMachine(command.Identity.MachineKey())
	if err != nil {
		t.Fatalf("control.NewAuthenticatedMachine() error = %v", err)
	}
	request, err := mapsession.NewRequest(command.Identity.NodeKey(), 142)
	if err != nil {
		t.Fatalf("mapsession.NewRequest() error = %v", err)
	}

	snapshot, err := service.Open(ctx, machine, request)
	if err != nil {
		t.Fatalf("map session Open() error = %v", err)
	}
	if snapshot.NumericNodeID() != 603 || snapshot.NumericOwnerID() != 11 ||
		snapshot.NodeID().String() != "01890f10-0000-7000-8000-000000000603" ||
		snapshot.Hostname().String() != "node-one.example" ||
		snapshot.NetworkName().String() != "Network one updated" ||
		snapshot.Scope() != command.Scope || snapshot.RecoveryEpoch() != 1 ||
		snapshot.SessionGeneration() != 1 || snapshot.NetworkRevision() <= 0 ||
		snapshot.PacketPolicy().Revision() <= 0 ||
		snapshot.MachineKey() != command.Identity.MachineKey() ||
		snapshot.NodeKey() != command.Identity.NodeKey() {
		t.Fatalf("map session snapshot = %+v, want seeded authoritative Node", snapshot)
	}
	wantAddress := netip.MustParsePrefix("100.64.1.1/32")
	if addresses := snapshot.Addresses(); len(addresses) != 1 || addresses[0] != wantAddress {
		t.Fatalf("map session addresses = %v, want [%v]", addresses, wantAddress)
	}
	if candidates := snapshot.PeerCandidates(); len(candidates) != 0 {
		t.Fatalf("initial map session candidates = %+v, want none", candidates)
	}
	if peers := snapshot.AuthorizedPeers(); len(peers) != 0 {
		t.Fatalf("initial authorized peers = %+v, want default deny", peers)
	}

	unknownMachineKey, err := node.NewMachineKey(filledIntegrationKey(0x71))
	if err != nil {
		t.Fatalf("construct unknown machine key: %v", err)
	}
	unknownMachine, err := control.NewAuthenticatedMachine(unknownMachineKey)
	if err != nil {
		t.Fatalf("construct unknown authenticated machine: %v", err)
	}
	if _, err := service.Open(ctx, unknownMachine, request); !errors.Is(err, mapsession.ErrUnauthorized) {
		t.Fatalf("unknown machine Open() error = %v, want mapsession.ErrUnauthorized", err)
	}

	unknownNodeKey, err := node.NewKey(filledIntegrationKey(0x72))
	if err != nil {
		t.Fatalf("construct unknown Node key: %v", err)
	}
	unknownNodeRequest, err := mapsession.NewRequest(unknownNodeKey, 142)
	if err != nil {
		t.Fatalf("construct unknown Node request: %v", err)
	}
	if _, err := service.Open(ctx, machine, unknownNodeRequest); !errors.Is(err, mapsession.ErrUnauthorized) {
		t.Fatalf("unknown Node key Open() error = %v, want mapsession.ErrUnauthorized", err)
	}
}

func integrationRelayDirectory(t *testing.T) relay.Directory {
	t.Helper()
	relayNode, err := relay.NewNode(relay.NodeParams{
		Name:      "1a",
		HostName:  "relay-sin.example.com",
		IPv4:      "192.0.2.10",
		IPv6:      "2001:db8::10",
		STUNPort:  3478,
		RelayPort: 443,
	})
	if err != nil {
		t.Fatalf("relay.NewNode() error = %v", err)
	}
	region, err := relay.NewRegion(relay.RegionParams{
		ID: 1, Code: "sin", Name: "Singapore", Nodes: []relay.Node{relayNode},
	})
	if err != nil {
		t.Fatalf("relay.NewRegion() error = %v", err)
	}
	directory, err := relay.NewDirectory(relay.DirectoryParams{
		Revision: 1,
		Regions:  []relay.Region{region},
	})
	if err != nil {
		t.Fatalf("relay.NewDirectory() error = %v", err)
	}
	return directory
}

func assertWorkerCannotLoadMapPeerCandidates(
	ctx context.Context,
	t *testing.T,
	workerConnection *pgx.Conn,
) {
	t.Helper()
	var canLoad bool
	if err := workerConnection.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege(
    CURRENT_USER,
	'mesh_ops.load_map_peer_candidates_v2(bytea,bytea,integer)',
    'EXECUTE'
)`).Scan(&canLoad); err != nil {
		t.Fatalf("query worker map peer candidate privilege: %v", err)
	}
	if canLoad {
		t.Fatal("worker can load map peer candidates, want false")
	}
	err := workerConnection.QueryRow(ctx, `SELECT node_public_id
FROM mesh_ops.load_map_peer_candidates_v2(
    pg_catalog.decode(pg_catalog.repeat('11', 32), 'hex'),
    pg_catalog.decode(pg_catalog.repeat('22', 32), 'hex'),
    1
)`).Scan(new(string))
	assertPostgreSQLCode(t, err, "42501")
}

type unusedEndpointObserver struct{}

func (unusedEndpointObserver) ObserveEndpoints(
	context.Context,
	network.Scope,
	node.EndpointObservation,
) (bool, error) {
	return false, errors.New("unused endpoint observer called")
}

type unusedConnectivityStore struct{}

func (unusedConnectivityStore) LoadConnectivity(
	_ context.Context,
	keys []mapsession.ConnectivityKey,
) ([]mapsession.Connectivity, error) {
	values := make([]mapsession.Connectivity, len(keys))
	for index, key := range keys {
		var err error
		values[index], err = mapsession.NewConnectivity(mapsession.ConnectivityParams{Key: key})
		if err != nil {
			return nil, err
		}
	}
	return values, nil
}

func assertWorkerCannotResolveMapSessionScope(
	ctx context.Context,
	t *testing.T,
	workerConnection *pgx.Conn,
) {
	t.Helper()
	var canResolve bool
	if err := workerConnection.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege(
    CURRENT_USER,
    'mesh_ops.resolve_map_session_scope(bytea,bytea)',
    'EXECUTE'
)`).Scan(&canResolve); err != nil {
		t.Fatalf("query worker map-session scope privilege: %v", err)
	}
	if canResolve {
		t.Fatal("worker can resolve map-session scope, want false")
	}
	err := workerConnection.QueryRow(ctx, `SELECT workspace_public_id
FROM mesh_ops.resolve_map_session_scope(
    pg_catalog.decode(pg_catalog.repeat('11', 32), 'hex'),
    pg_catalog.decode(pg_catalog.repeat('22', 32), 'hex')
)`).Scan(new(string))
	assertPostgreSQLCode(t, err, "42501")
}
