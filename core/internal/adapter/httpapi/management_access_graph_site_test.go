package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/site"
)

func TestManagementHandlerExplainsSiteAddress(t *testing.T) {
	t.Parallel()

	const siteID = "01890f00-0000-7000-8000-000000000971"
	reader := managementAccessGraphReaderFunc(func(
		_ context.Context,
		_ accountsession.Session,
		query accessgraph.Query,
	) (accessgraph.Snapshot, error) {
		if query.DestinationAddress() != netip.MustParseAddr("10.35.0.4") {
			t.Errorf("DestinationAddress() = %s", query.DestinationAddress())
		}
		return managementSiteAccessGraphSnapshot(t, query, siteID), nil
	})
	service, err := accessgraph.NewService(accessgraph.Dependencies{Reader: reader})
	if err != nil {
		t.Fatal(err)
	}
	options := validManagementHandlerOptions(t)
	options.PolicyExplanations = service
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, http.MethodPost, validAccessGraphExplainPath(),
		`{"source_device_id":"01890f00-0000-7000-8000-000000000301",`+
			`"destination_address":"10.35.0.4","protocol":"tcp","destination_port":22}`)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
	var body explainPolicyResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Decision != "allow" || body.Data.Target.Address != "10.35.0.4" || body.Data.Target.SiteID != siteID ||
		body.Data.Context.Target.Kind != "site" || body.Data.Context.Target.Name == nil ||
		*body.Data.Context.Target.Name != "prod" || len(body.Data.Paths) != 1 ||
		body.Data.Paths[0].SelectorKind != "site" || body.Data.Paths[0].DestinationSiteID != siteID ||
		len(body.Data.Paths[0].DestinationPrefixes) != 1 || body.Data.Paths[0].DestinationPrefixes[0] != "10.35.0.0/17" ||
		body.Data.Paths[0].DestinationDeviceID != "" {
		t.Fatalf("response = %+v", body)
	}
}

func TestManagementHandlerRejectsInvalidSiteAddress(t *testing.T) {
	t.Parallel()

	options := validManagementHandlerOptions(t)
	service, err := accessgraph.NewService(accessgraph.Dependencies{Reader: managementAccessGraphReaderFunc(
		func(context.Context, accountsession.Session, accessgraph.Query) (accessgraph.Snapshot, error) {
			t.Error("an invalid question reached the reader")
			return accessgraph.Snapshot{}, accessgraph.ErrUnavailable
		})})
	if err != nil {
		t.Fatal(err)
	}
	options.PolicyExplanations = service
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"source_device_id":"01890f00-0000-7000-8000-000000000301","destination_address":"10.35.0.0/24",` +
			`"protocol":"tcp","destination_port":22}`,
		`{"source_device_id":"01890f00-0000-7000-8000-000000000301","destination_address":"224.0.0.1",` +
			`"protocol":"icmp"}`,
		`{"source_device_id":"01890f00-0000-7000-8000-000000000301","destination_address":"10.35.0.4",` +
			`"destination_device_id":"01890f00-0000-7000-8000-000000000302","protocol":"icmp"}`,
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, newManagementRequest(t, http.MethodPost, validAccessGraphExplainPath(), body))
		if response.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d", body, response.Code)
		}
	}
}

func managementSiteAccessGraphSnapshot(t *testing.T, query accessgraph.Query, siteText string) accessgraph.Snapshot {
	t.Helper()
	siteID, err := site.ParseID(siteText)
	if err != nil {
		t.Fatal(err)
	}
	projectionID, err := publication.ParseProjectionID("01890f00-0000-7000-8000-000000000711")
	if err != nil {
		t.Fatal(err)
	}
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000511")
	if err != nil {
		t.Fatal(err)
	}
	portRange, err := policy.NewPortRange(22, 22)
	if err != nil {
		t.Fatal(err)
	}
	path, err := accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: projectionID, RuleID: ruleID, SourceNodeID: query.SourceNodeID(),
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{portRange},
		SelectorKind: accessgraph.SelectorKindSite, DestinationSiteID: siteID,
		DestinationPrefixes: []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")},
	})
	if err != nil {
		t.Fatal(err)
	}
	releaseID, err := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000903")
	if err != nil {
		t.Fatal(err)
	}
	semanticHash, err := publication.NewSemanticHash(sha256.Sum256([]byte("Site access graph fixture")))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := accessgraph.NewSnapshot(accessgraph.SnapshotParams{
		Scope: query.Scope(), NetworkRevision: 12, InventoryRevision: 8,
		GroupRevision: 9, PolicyRevision: 6, DNSRevision: 2, RouteRevision: 2,
		SharingRevision: 2, IsolationGeneration: 1, HasActiveRelease: true,
		ReleaseID: releaseID, CompilerFormatVersion: 3, SemanticHash: semanticHash,
		TargetSiteID: siteID, Paths: []accessgraph.Path{path},
		Source:     managementAccessGraphParticipant(t, "poc-02"),
		TargetKind: accessgraph.TargetKindSite,
		Target:     managementAccessGraphParticipant(t, "prod"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
