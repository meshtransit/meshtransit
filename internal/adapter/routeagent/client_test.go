package routeagent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/sharing/endpointpublication"
	"github.com/meshtransit/meshtransit/internal/workspace"
	"net/netip"
)

func TestClientSendsBoundedIdempotentRouteCommand(t *testing.T) {
	t.Parallel()
	route := routeFixture(t)
	hash, err := route.Hash()
	if err != nil {
		t.Fatalf("route.Hash() error = %v", err)
	}
	origin, _ := url.Parse("https://route-agent.example.test:8443")
	transport := &routeAgentDoer{respond: func(request *http.Request) *http.Response {
		if request.Method != http.MethodPut || request.URL.Path != "/v1/private-endpoint-routes/"+route.EndpointID ||
			request.Header.Get("Content-Type") != "application/json" ||
			request.Header.Get("X-MeshTransit-Operation") != "apply" ||
			request.Header.Get("Idempotency-Key") == "" {
			t.Fatalf("unexpected request: %s %s headers=%v", request.Method, request.URL.Path, request.Header)
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil || len(body) == 0 || len(body) > maximumCommandBytes {
			t.Fatalf("command body length=%d error=%v", len(body), readErr)
		}
		return acknowledgedResponse(request)
	}}
	client := &Client{origin: origin, client: transport, timeout: time.Second}
	if err := client.Apply(t.Context(), route, hash); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if transport.calls != 1 {
		t.Fatalf("calls = %d, want 1", transport.calls)
	}
}

func TestClientRejectsMismatchedProofBeforeIO(t *testing.T) {
	t.Parallel()
	route := routeFixture(t)
	origin, _ := url.Parse("https://route-agent.example.test")
	transport := &routeAgentDoer{respond: acknowledgedResponse}
	client := &Client{origin: origin, client: transport, timeout: time.Second}
	if err := client.Apply(t.Context(), route, sha256.Sum256([]byte("wrong"))); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("Apply() error = %v, want ErrInvalidClient", err)
	}
	if transport.calls != 0 {
		t.Fatal("mismatched command proof reached network I/O")
	}
}

func TestClientBindsWithdrawalAcknowledgementToOperation(t *testing.T) {
	t.Parallel()
	route := routeFixture(t)
	routeHash, err := route.Hash()
	if err != nil {
		t.Fatal(err)
	}
	command := endpointpublication.Withdrawal{
		DeploymentID: route.DeploymentID, EndpointID: route.EndpointID,
		EndpointGeneration: route.EndpointGeneration, ResourceAlias: route.ResourceAlias,
		RouteSnapshotHash: hex.EncodeToString(routeHash[:]), RoutePresent: true,
		Reason: "invalidated",
	}
	commandHash, err := command.Hash()
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse("https://route-agent.example.test")
	transport := &routeAgentDoer{respond: func(request *http.Request) *http.Response {
		if request.Method != http.MethodDelete || request.Header.Get("X-MeshTransit-Operation") != "withdraw" {
			t.Fatalf("withdrawal request = %s operation=%q", request.Method, request.Header.Get("X-MeshTransit-Operation"))
		}
		return acknowledgedResponse(request)
	}}
	client := &Client{origin: origin, client: transport, timeout: time.Second}
	if err := client.Withdraw(t.Context(), command, commandHash); err != nil {
		t.Fatalf("Withdraw() error = %v", err)
	}
}

func TestClientRejectsAmbiguousAcknowledgement(t *testing.T) {
	t.Parallel()
	route := routeFixture(t)
	hash, _ := route.Hash()
	origin, _ := url.Parse("https://route-agent.example.test")
	transport := &routeAgentDoer{respond: func(request *http.Request) *http.Response {
		response := acknowledgedResponse(request)
		response.Header.Set("X-MeshTransit-Route-SHA256", strings.Repeat("0", 64))
		return response
	}}
	client := &Client{origin: origin, client: transport, timeout: time.Second}
	if err := client.Apply(t.Context(), route, hash); !errors.Is(err, ErrRejected) {
		t.Fatalf("Apply() error = %v, want ErrRejected", err)
	}
}

func TestParseOriginRequiresExactHTTPSOrigin(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"http://route-agent.example.test", "https://user@route-agent.example.test",
		"https://route-agent.example.test/path", "https://route-agent.example.test?query=1",
		"https://route-agent.example.test:", "https://route-agent.example.test:0",
	} {
		if _, err := parseOrigin(value); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("parseOrigin(%q) error = %v, want ErrInvalidClient", value, err)
		}
	}
}

type routeAgentDoer struct {
	calls   int
	respond func(*http.Request) *http.Response
}

func (doer *routeAgentDoer) Do(request *http.Request) (*http.Response, error) {
	doer.calls++
	return doer.respond(request), nil
}

func acknowledgedResponse(request *http.Request) *http.Response {
	header := make(http.Header)
	header.Set("X-MeshTransit-Route-SHA256", request.Header.Get("X-MeshTransit-Route-SHA256"))
	header.Set("X-MeshTransit-Endpoint-Generation", request.Header.Get("X-MeshTransit-Endpoint-Generation"))
	header.Set("X-MeshTransit-Operation", request.Header.Get("X-MeshTransit-Operation"))
	return &http.Response{
		StatusCode: http.StatusNoContent, Header: header,
		Body: io.NopCloser(strings.NewReader("")), Request: request,
	}
}

func routeFixture(t *testing.T) endpointpublication.Route {
	t.Helper()
	newID := func() publicid.ID {
		id, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	deploymentID, _ := deployment.NewID(newID().Bytes())
	endpointID, _ := sharing.ParsePrivateEndpointID(newID().String())
	providerWorkspace, _ := workspace.NewID(newID().Bytes())
	providerNetwork, _ := network.NewID(newID().Bytes())
	consumerWorkspace, _ := workspace.NewID(newID().Bytes())
	consumerNetwork, _ := network.NewID(newID().Bytes())
	accessName, _ := sharing.ParseAccessName("database.shared.example")
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	snapshot := endpointpublication.Snapshot{
		DeploymentID: deploymentID, EndpointID: endpointID, EndpointVersion: 1, EndpointGeneration: 1,
		AliasLeaseVersion: 1, ContractVersion: 2, ImportedResourceVersion: 2,
		ProviderScope:  endpointpublication.Scope{WorkspaceID: providerWorkspace, NetworkID: providerNetwork},
		ConsumerScope:  endpointpublication.Scope{WorkspaceID: consumerWorkspace, NetworkID: consumerNetwork},
		TargetDeviceID: newID(), TargetGeneration: 1,
		TargetAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.10")},
		ResourceAlias:   netip.MustParseAddr("100.100.0.1"), AccessName: accessName,
		Traffic:        []endpointpublication.TrafficConstraint{{Protocol: "tcp", DestinationPortRanges: []endpointpublication.PortRange{{First: 443, Last: 443}}}},
		ConstraintHash: sha256.Sum256([]byte("constraint")), ExpiresAt: now.Add(time.Hour), SnapshotAt: now,
		ProviderNetworkRevision: 1, ProviderDNSRevision: 1, ProviderRouteRevision: 1, ProviderSharingRevision: 1,
		ConsumerNetworkRevision: 1, ConsumerDNSRevision: 1, ConsumerRouteRevision: 1, ConsumerSharingRevision: 1,
		ProviderStreamID: 1, ProviderStreamSequence: 1, ProviderStreamHash: sha256.Sum256([]byte("provider")),
		ConsumerStreamID: 2, ConsumerStreamSequence: 1, ConsumerStreamHash: sha256.Sum256([]byte("consumer")),
	}
	route, err := snapshot.Route()
	if err != nil {
		t.Fatalf("Snapshot.Route() error = %v", err)
	}
	return route
}

var _ doer = (*routeAgentDoer)(nil)
