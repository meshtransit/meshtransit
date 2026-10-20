package accessgraph_test

import (
	"net/netip"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/site"
)

func TestServiceExplainsInternetAddressThroughExitPool(t *testing.T) {
	t.Parallel()

	query := siteQueryFixture(t, "8.8.8.8", policy.ProtocolTCP, 22)
	allowed := explainFixture(t, query, exitSnapshotFixture(t, query, true, []accessgraph.Path{
		exitPathFixture(t, 1, policy.ProtocolTCP),
	}))
	if allowed.Decision() != accessgraph.DecisionAllow || len(allowed.Paths()) != 1 ||
		allowed.Snapshot().TargetExitPoolID() != exitPoolIDFixture(t) {
		t.Fatalf("allowed Internet address: decision %s, %d paths", allowed.Decision(), len(allowed.Paths()))
	}
	path := allowed.Paths()[0]
	if path.SelectorKind() != accessgraph.SelectorKindExitPool || path.DestinationExitPoolID() != exitPoolIDFixture(t) ||
		path.DestinationNodeID().IsValid() || path.DestinationSiteID().IsValid() || len(path.DestinationPrefixes()) != 0 {
		t.Fatalf("exit path = %+v", path)
	}
	// Without a pool whose rules grant it, no rule lets the Device reach
	// the Internet.
	denied := explainFixture(t, query, exitSnapshotFixture(t, query, false, nil))
	if reason, denied := denied.DenyReason(); !denied || reason != accessgraph.DenyReasonNoMatchingActiveRule {
		t.Fatalf("no pool: deny reason %s", reason)
	}
}

func TestSnapshotRejectsExitPoolForAddressesOffTheInternet(t *testing.T) {
	t.Parallel()

	// A private address is never reached through an Exit Pool.
	query := siteQueryFixture(t, "10.35.0.4", policy.ProtocolTCP, 22)
	service, err := accessgraph.NewService(accessgraph.Dependencies{Reader: &accessGraphReaderFixture{
		snapshot: exitSnapshotFixture(t, query, false, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Explain(t.Context(), accessGraphSessionFixture(t), query); err == nil {
		t.Fatal("an Exit Pool answered for a private address")
	}
	// A Device query never gets an Exit Pool target.
	internet := siteQueryFixture(t, "8.8.8.8", policy.ProtocolTCP, 22)
	params := exitSnapshotParams(t, internet, true, []accessgraph.Path{exitPathFixture(t, 1, policy.ProtocolTCP)})
	params.TargetSiteID = siteIDFixture(t)
	if _, err := accessgraph.NewSnapshot(params); err == nil {
		t.Fatal("an Exit Pool target with a Site was accepted")
	}
	params = exitSnapshotParams(t, internet, false, []accessgraph.Path{exitPathFixture(t, 1, policy.ProtocolTCP)})
	if _, err := accessgraph.NewSnapshot(params); err == nil {
		t.Fatal("an exit path without a pool target was accepted")
	}
}

func TestNewPathValidatesExitPaths(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		change func(*accessgraph.PathParams)
		valid  bool
	}{
		"plain":   {change: func(*accessgraph.PathParams) {}, valid: true},
		"no pool": {change: func(params *accessgraph.PathParams) { params.DestinationExitPoolID = exitpool.ID{} }},
		"prefixes": {change: func(params *accessgraph.PathParams) {
			params.DestinationPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		}},
		"a Site": {change: func(params *accessgraph.PathParams) { params.DestinationSiteID = siteIDFixture(t) }},
		"destination Device": {change: func(params *accessgraph.PathParams) {
			params.DestinationNodeID = accessGraphNodeID(t, 302)
		}},
		"Site kind": {change: func(params *accessgraph.PathParams) { params.SelectorKind = accessgraph.SelectorKindSite }},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			params := exitPathParams(t, 1, policy.ProtocolTCP)
			test.change(&params)
			if _, err := accessgraph.NewPath(params); test.valid != (err == nil) {
				t.Fatalf("NewPath() error = %v, want valid %t", err, test.valid)
			}
		})
	}
}

func exitSnapshotFixture(t *testing.T, query accessgraph.Query, granted bool, paths []accessgraph.Path,
) accessgraph.Snapshot {
	t.Helper()
	snapshot, err := accessgraph.NewSnapshot(exitSnapshotParams(t, query, granted, paths))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func exitSnapshotParams(t *testing.T, query accessgraph.Query, granted bool, paths []accessgraph.Path,
) accessgraph.SnapshotParams {
	t.Helper()
	params := accessGraphSnapshotParams(t, query, paths)
	params.TargetKind, params.TargetNodeID, params.TargetSiteID = accessgraph.TargetKindExitPool, node.ID{}, site.ID{}
	if granted {
		params.TargetExitPoolID = exitPoolIDFixture(t)
		params.Target = accessGraphParticipant(t, accessgraph.ParticipantStateActive, "egress")
	} else {
		params.Target = accessGraphParticipant(t, accessgraph.ParticipantStateMissing, "")
	}
	return params
}

func exitPoolIDFixture(t *testing.T) exitpool.ID {
	t.Helper()
	id, err := exitpool.ParseID("01890f00-0000-7000-8000-000000000981")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func exitPathFixture(t *testing.T, sequence int, protocol policy.Protocol) accessgraph.Path {
	t.Helper()
	path, err := accessgraph.NewPath(exitPathParams(t, sequence, protocol))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func exitPathParams(t *testing.T, sequence int, protocol policy.Protocol) accessgraph.PathParams {
	t.Helper()
	params := sitePathParams(t, sequence, protocol, "10.35.0.0/24")
	params.SelectorKind, params.DestinationSiteID, params.DestinationPrefixes =
		accessgraph.SelectorKindExitPool, site.ID{}, nil
	params.DestinationExitPoolID = exitPoolIDFixture(t)
	return params
}

func TestGraphNodeNamesExitPools(t *testing.T) {
	t.Parallel()

	participant := accessGraphParticipant(t, accessgraph.ParticipantStateActive, "egress")
	pool, err := accessgraph.NewGraphNode(accessgraph.GraphNodeParams{Kind: accessgraph.GraphNodeKindExitPool,
		ExitPoolID: exitPoolIDFixture(t), Participant: participant})
	if err != nil || pool.ExitPoolID() != exitPoolIDFixture(t) || pool.Kind().String() != "exit_pool" {
		t.Fatalf("Exit Pool node = %+v, %v", pool, err)
	}
	for name, params := range map[string]accessgraph.GraphNodeParams{
		"no pool":         {Kind: accessgraph.GraphNodeKindExitPool, Participant: participant},
		"a Site as pool":  {Kind: accessgraph.GraphNodeKindExitPool, SiteID: siteIDFixture(t), Participant: participant},
		"a pool on Site":  {Kind: accessgraph.GraphNodeKindSite, SiteID: siteIDFixture(t), ExitPoolID: exitPoolIDFixture(t), Participant: participant},
		"a pool and node": {Kind: accessgraph.GraphNodeKindExitPool, ExitPoolID: exitPoolIDFixture(t), DeviceID: accessGraphNodeID(t, 302), Participant: participant},
	} {
		if _, err := accessgraph.NewGraphNode(params); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
