package sharing

import (
	"net/netip"
	"testing"
	"time"
)

func TestPrivateEndpointRequiresFederationAliasAcrossWorkspaces(t *testing.T) {
	t.Parallel()

	contract := mustContract(t)
	params := privateEndpointParams(t, contract)
	params.Mode = EndpointModeDirect
	if _, err := NewPrivateEndpoint(params); err == nil {
		t.Fatal("NewPrivateEndpoint() accepted direct cross-Workspace routing")
	}

	endpoint, err := NewPrivateEndpoint(privateEndpointParams(t, contract))
	if err != nil {
		t.Fatalf("NewPrivateEndpoint() error = %v", err)
	}
	if endpoint.ScopeRelation() != ScopeRelationCrossWorkspace ||
		endpoint.Mode() != EndpointModeFederationAlias ||
		endpoint.ResourceAlias() != netip.MustParseAddr("fd00:feed::10") {
		t.Fatalf("Private Endpoint = %#v, want cross-Workspace federation alias", endpoint)
	}
}

func TestPrivateEndpointAllowsExplicitDirectModeOnlyWithinWorkspace(t *testing.T) {
	t.Parallel()

	crossWorkspace := mustContract(t)
	contractParams := crossWorkspace.params
	contractParams.ConsumerScope = mustScope(t, 1, 4)
	withinWorkspace, err := NewContract(contractParams)
	if err != nil {
		t.Fatalf("NewContract() error = %v", err)
	}
	params := privateEndpointParams(t, withinWorkspace)
	params.Mode = EndpointModeDirect
	params.ResourceAlias = netip.MustParseAddr("10.40.0.10")
	endpoint, err := NewPrivateEndpoint(params)
	if err != nil {
		t.Fatalf("NewPrivateEndpoint() error = %v", err)
	}
	if endpoint.ScopeRelation() != ScopeRelationWithinWorkspace ||
		endpoint.Mode() != EndpointModeDirect {
		t.Fatalf("Private Endpoint = %#v, want explicit within-Workspace direct mode", endpoint)
	}
}

func TestPrivateEndpointUsabilityBindsEveryPublicationVersion(t *testing.T) {
	t.Parallel()

	contract := mustContract(t)
	endpoint, err := NewPrivateEndpoint(privateEndpointParams(t, contract))
	if err != nil {
		t.Fatalf("NewPrivateEndpoint() error = %v", err)
	}
	evaluatedAt := endpoint.ExpiresAt().Add(-time.Minute)
	if !endpoint.IsUsableAt(contract, endpoint.ImportedResourceVersion(), evaluatedAt) {
		t.Fatal("Private Endpoint denied exact current authority")
	}

	tests := []struct {
		name            string
		endpoint        PrivateEndpoint
		contract        Contract
		importedVersion int64
		evaluatedAt     time.Time
	}{
		{
			name: "provisioning is not ready", endpoint: func() PrivateEndpoint {
				value := endpoint
				value.state = EndpointStateProvisioning
				return value
			}(), contract: contract, importedVersion: endpoint.ImportedResourceVersion(), evaluatedAt: evaluatedAt,
		},
		{
			name: "stale contract version", endpoint: func() PrivateEndpoint {
				value := endpoint
				value.contractVersion++
				return value
			}(), contract: contract, importedVersion: endpoint.ImportedResourceVersion(), evaluatedAt: evaluatedAt,
		},
		{
			name: "stale Imported Resource version", endpoint: endpoint, contract: contract,
			importedVersion: endpoint.ImportedResourceVersion() + 1, evaluatedAt: evaluatedAt,
		},
		{
			name: "stale recovery epoch", endpoint: func() PrivateEndpoint {
				value := endpoint
				value.recoveryEpoch++
				return value
			}(), contract: contract, importedVersion: endpoint.ImportedResourceVersion(), evaluatedAt: evaluatedAt,
		},
		{
			name: "exclusive endpoint expiry", endpoint: endpoint, contract: contract,
			importedVersion: endpoint.ImportedResourceVersion(), evaluatedAt: endpoint.ExpiresAt(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.endpoint.IsUsableAt(test.contract, test.importedVersion, test.evaluatedAt) {
				t.Fatal("Private Endpoint accepted stale or unavailable authority")
			}
		})
	}
}

func TestPrivateEndpointRejectsUnsafeAliasAndDNSFallback(t *testing.T) {
	t.Parallel()

	contract := mustContract(t)
	tests := []struct {
		name   string
		mutate func(*PrivateEndpointParams)
	}{
		{name: "IP literal access name", mutate: func(params *PrivateEndpointParams) {
			params.AccessName = AccessName{value: "10.20.30.40"}
		}},
		{name: "loopback alias", mutate: func(params *PrivateEndpointParams) {
			params.ResourceAlias = netip.MustParseAddr("127.0.0.1")
		}},
		{name: "multicast alias", mutate: func(params *PrivateEndpointParams) {
			params.ResourceAlias = netip.MustParseAddr("ff02::1")
		}},
		{name: "ready against activating contract", mutate: func(params *PrivateEndpointParams) {
			contractParams := contract.params
			contractParams.State = ContractStateActivating
			activating, err := NewContract(contractParams)
			if err != nil {
				t.Fatal(err)
			}
			params.Contract = activating
		}},
		{name: "endpoint outlives contract", mutate: func(params *PrivateEndpointParams) {
			params.ExpiresAt = contract.ExpiresAt().Add(time.Nanosecond)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := privateEndpointParams(t, contract)
			test.mutate(&params)
			if _, err := NewPrivateEndpoint(params); err == nil {
				t.Fatal("NewPrivateEndpoint() accepted unsafe authority")
			}
		})
	}
}

func privateEndpointParams(t *testing.T, contract Contract) PrivateEndpointParams {
	t.Helper()
	id, err := ParsePrivateEndpointID(uuidWithSuffix(10))
	if err != nil {
		t.Fatal(err)
	}
	accessName, err := ParseAccessName("database.shared.consumer.example")
	if err != nil {
		t.Fatal(err)
	}
	return PrivateEndpointParams{
		ID: id, Contract: contract, AccessName: accessName,
		Mode: EndpointModeFederationAlias, ResourceAlias: netip.MustParseAddr("fd00:feed::10"),
		Generation: 1, ImportedResourceVersion: 2, Grant: contract.MaximumTraffic(),
		ExpiresAt: contract.ExpiresAt(), State: EndpointStateReady,
	}
}

func mustPrivateEndpoint(t *testing.T, contract Contract) PrivateEndpoint {
	t.Helper()
	endpoint, err := NewPrivateEndpoint(privateEndpointParams(t, contract))
	if err != nil {
		t.Fatalf("NewPrivateEndpoint() error = %v", err)
	}
	return endpoint
}
