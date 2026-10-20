package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
)

func TestManagementHandlerExplainsInternetAddressThroughExitPool(t *testing.T) {
	t.Parallel()

	const poolID = "01890f00-0000-7000-8000-000000000981"
	reader := managementAccessGraphReaderFunc(func(
		_ context.Context,
		_ accountsession.Session,
		query accessgraph.Query,
	) (accessgraph.Snapshot, error) {
		return managementExitAccessGraphSnapshot(t, query, poolID), nil
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
			`"destination_address":"8.8.8.8","protocol":"tcp","destination_port":443}`)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
	var body explainPolicyResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Decision != "allow" || body.Data.Target.Address != "8.8.8.8" || body.Data.Target.ExitPoolID != poolID ||
		body.Data.Target.SiteID != "" || body.Data.Context.Target.Kind != "exit_pool" || len(body.Data.Paths) != 1 ||
		body.Data.Paths[0].SelectorKind != "exit_pool" || body.Data.Paths[0].DestinationExitPoolID != poolID ||
		len(body.Data.Paths[0].DestinationPrefixes) != 0 || body.Data.Paths[0].DestinationDeviceID != "" {
		t.Fatalf("response = %+v", body)
	}
}

func managementExitAccessGraphSnapshot(t *testing.T, query accessgraph.Query, poolText string) accessgraph.Snapshot {
	t.Helper()
	poolID, err := exitpool.ParseID(poolText)
	if err != nil {
		t.Fatal(err)
	}
	projectionID, err := publication.ParseProjectionID("01890f00-0000-7000-8000-000000000712")
	if err != nil {
		t.Fatal(err)
	}
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000512")
	if err != nil {
		t.Fatal(err)
	}
	portRange, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	path, err := accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: projectionID, RuleID: ruleID, SourceNodeID: query.SourceNodeID(),
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{portRange},
		SelectorKind: accessgraph.SelectorKindExitPool, DestinationExitPoolID: poolID,
	})
	if err != nil {
		t.Fatal(err)
	}
	releaseID, err := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000904")
	if err != nil {
		t.Fatal(err)
	}
	semanticHash, err := publication.NewSemanticHash(sha256.Sum256([]byte("Exit access graph fixture")))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := accessgraph.NewSnapshot(accessgraph.SnapshotParams{
		Scope: query.Scope(), NetworkRevision: 12, InventoryRevision: 8,
		GroupRevision: 9, PolicyRevision: 6, DNSRevision: 2, RouteRevision: 2,
		SharingRevision: 2, IsolationGeneration: 1, HasActiveRelease: true,
		ReleaseID: releaseID, CompilerFormatVersion: 3, SemanticHash: semanticHash,
		TargetExitPoolID: poolID, Paths: []accessgraph.Path{path},
		Source:     managementAccessGraphParticipant(t, "poc-02"),
		TargetKind: accessgraph.TargetKindExitPool,
		Target:     managementAccessGraphParticipant(t, "egress"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
