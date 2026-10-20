package accessgraph_test

import (
	"fmt"
	"net/netip"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/site"
)

func TestQueryAcceptsOneSiteAddress(t *testing.T) {
	t.Parallel()

	base := accessgraph.QueryParams{
		Scope: accessGraphScopeFixture(t), SourceNodeID: accessGraphNodeID(t, 301),
		Protocol: policy.ProtocolTCP, DestinationPort: 22,
	}
	for name, test := range map[string]struct {
		address netip.Addr
		device  bool
		valid   bool
	}{
		"IPv4":                 {address: netip.MustParseAddr("10.35.0.4"), valid: true},
		"IPv6":                 {address: netip.MustParseAddr("fd12:3456:789a::4"), valid: true},
		"mapped IPv4":          {address: netip.MustParseAddr("::ffff:10.35.0.4")},
		"zoned":                {address: netip.MustParseAddr("fe80::1%eth0")},
		"unspecified":          {address: netip.IPv4Unspecified()},
		"multicast":            {address: netip.MustParseAddr("224.0.0.1")},
		"address and a Device": {address: netip.MustParseAddr("10.35.0.4"), device: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			params := base
			params.DestinationAddress = test.address
			if test.device {
				params.DestinationNodeID = accessGraphNodeID(t, 302)
			}
			query, err := accessgraph.NewQuery(params)
			if test.valid != (err == nil) {
				t.Fatalf("NewQuery(%s) error = %v, want valid %t", test.address, err, test.valid)
			}
			if test.valid && query.DestinationAddress() != test.address {
				t.Fatalf("DestinationAddress() = %s", query.DestinationAddress())
			}
		})
	}
}

func TestServiceExplainsSiteAddress(t *testing.T) {
	t.Parallel()

	query := siteQueryFixture(t, "10.35.0.4", policy.ProtocolTCP, 22)
	allowed := siteSnapshotFixture(t, query, true, []accessgraph.Path{
		sitePathFixture(t, 1, policy.ProtocolTCP, "10.35.0.0/24"),
	})
	result := explainFixture(t, query, allowed)
	if result.Decision() != accessgraph.DecisionAllow || len(result.Paths()) != 1 {
		t.Fatalf("allowed Site address: decision %s, %d paths", result.Decision(), len(result.Paths()))
	}
	path := result.Paths()[0]
	if path.SelectorKind() != accessgraph.SelectorKindSite || path.DestinationSiteID() != siteIDFixture(t) ||
		path.DestinationNodeID().IsValid() || len(path.DestinationPrefixes()) != 1 {
		t.Fatalf("Site path = %+v", path)
	}

	denied := explainFixture(t, query, siteSnapshotFixture(t, query, true, nil))
	if reason, denied := denied.DenyReason(); !denied || reason != accessgraph.DenyReasonNoMatchingActiveRule {
		t.Fatalf("no rule: deny reason %s", reason)
	}

	outside := explainFixture(t, query, siteSnapshotFixture(t, query, false, nil))
	if reason, denied := outside.DenyReason(); !denied || reason != accessgraph.DenyReasonTargetInactive {
		t.Fatalf("no Site: deny reason %s", reason)
	}
}

func TestSnapshotRejectsSitePathThatMissesTheAddress(t *testing.T) {
	t.Parallel()

	query := siteQueryFixture(t, "10.35.1.4", policy.ProtocolTCP, 22)
	snapshot := siteSnapshotFixture(t, query, true, []accessgraph.Path{
		sitePathFixture(t, 1, policy.ProtocolTCP, "10.35.0.0/24"),
	})
	service, err := accessgraph.NewService(accessgraph.Dependencies{Reader: &accessGraphReaderFixture{snapshot: snapshot}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Explain(t.Context(), accessGraphSessionFixture(t), query); err == nil {
		t.Fatal("a path whose prefixes miss the address was accepted")
	}
}

func TestSnapshotRejectsSitePathWithoutSiteTarget(t *testing.T) {
	t.Parallel()

	query := siteQueryFixture(t, "10.35.0.4", policy.ProtocolTCP, 22)
	params := siteSnapshotParams(t, query, false, []accessgraph.Path{
		sitePathFixture(t, 1, policy.ProtocolTCP, "10.35.0.0/24"),
	})
	if _, err := accessgraph.NewSnapshot(params); err == nil {
		t.Fatal("a Site path without a Site was accepted")
	}
	params = siteSnapshotParams(t, query, true, []accessgraph.Path{
		accessGraphPathFixture(t, 1, policy.ProtocolTCP, 22, 22),
	})
	if _, err := accessgraph.NewSnapshot(params); err == nil {
		t.Fatal("a Resource path to a Site was accepted")
	}
}

func TestNewPathValidatesSitePaths(t *testing.T) {
	t.Parallel()

	valid := sitePathParams(t, 1, policy.ProtocolTCP, "10.35.0.0/24")
	groupID, err := devicegroup.ParseID("01890f00-0000-7000-8000-000000000961")
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		change func(*accessgraph.PathParams)
		valid  bool
	}{
		"plain":             {change: func(*accessgraph.PathParams) {}, valid: true},
		"source group":      {change: func(params *accessgraph.PathParams) { params.SourceDeviceGroupID = groupID }, valid: true},
		"destination group": {change: func(params *accessgraph.PathParams) { params.DestinationDeviceGroupID = groupID }},
		"no Site":           {change: func(params *accessgraph.PathParams) { params.DestinationSiteID = site.ID{} }},
		"no prefixes":       {change: func(params *accessgraph.PathParams) { params.DestinationPrefixes = nil }},
		"unmasked prefix": {change: func(params *accessgraph.PathParams) {
			params.DestinationPrefixes = []netip.Prefix{netip.MustParsePrefix("10.35.0.4/24")}
		}},
		"destination Device": {change: func(params *accessgraph.PathParams) {
			params.DestinationNodeID = accessGraphNodeID(t, 302)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			params := valid
			params.DestinationPrefixes = append([]netip.Prefix(nil), valid.DestinationPrefixes...)
			test.change(&params)
			if _, err := accessgraph.NewPath(params); test.valid != (err == nil) {
				t.Fatalf("NewPath() error = %v, want valid %t", err, test.valid)
			}
		})
	}
	params := sitePathParams(t, 1, policy.ProtocolTCP, "10.35.0.0/24")
	params.SelectorKind = accessgraph.SelectorKindDevice
	params.DestinationNodeID = accessGraphNodeID(t, 302)
	if _, err := accessgraph.NewPath(params); err == nil {
		t.Fatal("a Device path naming a Site was accepted")
	}
}

func explainFixture(t *testing.T, query accessgraph.Query, snapshot accessgraph.Snapshot) accessgraph.Result {
	t.Helper()
	service, err := accessgraph.NewService(accessgraph.Dependencies{Reader: &accessGraphReaderFixture{snapshot: snapshot}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Explain(t.Context(), accessGraphSessionFixture(t), query)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	return result
}

func siteQueryFixture(t *testing.T, address string, protocol policy.Protocol, port uint16) accessgraph.Query {
	t.Helper()
	query, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: accessGraphScopeFixture(t), SourceNodeID: accessGraphNodeID(t, 301),
		DestinationAddress: netip.MustParseAddr(address), Protocol: protocol, DestinationPort: port,
	})
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func siteSnapshotFixture(t *testing.T, query accessgraph.Query, inSite bool, paths []accessgraph.Path,
) accessgraph.Snapshot {
	t.Helper()
	snapshot, err := accessgraph.NewSnapshot(siteSnapshotParams(t, query, inSite, paths))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func siteSnapshotParams(t *testing.T, query accessgraph.Query, inSite bool, paths []accessgraph.Path,
) accessgraph.SnapshotParams {
	t.Helper()
	params := accessGraphSnapshotParams(t, query, paths)
	params.TargetKind, params.TargetNodeID = accessgraph.TargetKindSite, node.ID{}
	if inSite {
		params.TargetSiteID = siteIDFixture(t)
		params.Target = accessGraphParticipant(t, accessgraph.ParticipantStateActive, "prod")
	} else {
		params.Target = accessGraphParticipant(t, accessgraph.ParticipantStateMissing, "")
	}
	return params
}

func siteIDFixture(t *testing.T) site.ID {
	t.Helper()
	id, err := site.ParseID("01890f00-0000-7000-8000-000000000971")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func sitePathFixture(t *testing.T, sequence int, protocol policy.Protocol, prefix string) accessgraph.Path {
	t.Helper()
	path, err := accessgraph.NewPath(sitePathParams(t, sequence, protocol, prefix))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func sitePathParams(t *testing.T, sequence int, protocol policy.Protocol, prefix string) accessgraph.PathParams {
	t.Helper()
	projectionID, err := publication.ParseProjectionID(fmt.Sprintf("01890f00-0000-7000-8000-%012d", 3_000+sequence))
	if err != nil {
		t.Fatal(err)
	}
	ruleID, err := policy.ParseRuleID(fmt.Sprintf("01890f00-0000-7000-8000-%012d", 4_000+sequence))
	if err != nil {
		t.Fatal(err)
	}
	ranges := []policy.PortRange{}
	if protocol != policy.ProtocolICMP {
		portRange, err := policy.NewPortRange(22, 22)
		if err != nil {
			t.Fatal(err)
		}
		ranges = []policy.PortRange{portRange}
	}
	return accessgraph.PathParams{
		ProjectionID: projectionID, RuleID: ruleID, SourceNodeID: accessGraphNodeID(t, 301),
		Protocol: protocol, DestinationPortRanges: ranges, SelectorKind: accessgraph.SelectorKindSite,
		DestinationSiteID: siteIDFixture(t), DestinationPrefixes: []netip.Prefix{netip.MustParsePrefix(prefix)},
	}
}
