package compilation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestServiceCompilesResourceDestinationWithPinnedAuthority(t *testing.T) {
	t.Parallel()

	value := compilationResourceFixture(t, resource.StateActive)
	resolver := &compilationResourceResolverFixture{values: []catalog.Resource{value}}
	service, err := compilation.NewService(resolver)
	if err != nil {
		t.Fatal(err)
	}
	request := compilationRequestFixture(t, value.ID(), node.ID{})

	candidate, err := service.Compile(t.Context(), compilationSessionFixture(t), request)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	rules := candidate.Snapshot().Rules()
	destinations := candidate.ResourceDestinations()
	if resolver.calls != 1 || candidate.CompilerFormatVersion() != 2 || len(rules) != 1 ||
		len(destinations) != 1 || rules[0].DestinationNodeID() != value.DeviceID() ||
		destinations[0].Reference().ResourceID() != value.ID() ||
		destinations[0].Reference().ResourceVersion() != value.Version() ||
		destinations[0].Reference().TargetGeneration() != value.TargetGeneration() ||
		destinations[0].InventoryRevision() != value.InventoryRevision() ||
		destinations[0].ResourceSemanticHash() != value.SemanticHash() {
		t.Fatalf("candidate=%+v rules=%+v destinations=%+v resolver=%+v", candidate, rules, destinations, resolver)
	}
}

func TestServiceCompilesDirectDeviceWithoutResourceRead(t *testing.T) {
	t.Parallel()

	resolver := &compilationResourceResolverFixture{err: errors.New("unexpected Resource resolution")}
	service, err := compilation.NewService(resolver)
	if err != nil {
		t.Fatal(err)
	}
	destinationID := compilationNodeID(t, "000000000702")
	request := compilationRequestFixture(t, resource.ID{}, destinationID)

	candidate, err := service.Compile(t.Context(), compilationSessionFixture(t), request)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if resolver.calls != 0 || candidate.CompilerFormatVersion() != 1 ||
		len(candidate.ResourceDestinations()) != 0 ||
		candidate.Snapshot().Rules()[0].DestinationNodeID() != destinationID {
		t.Fatalf("candidate=%+v resolver=%+v", candidate, resolver)
	}
}

func TestServiceRejectsInactiveResource(t *testing.T) {
	t.Parallel()

	value := compilationResourceFixture(t, resource.StateSuspended)
	resolver := &compilationResourceResolverFixture{values: []catalog.Resource{value}}
	service, err := compilation.NewService(resolver)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Compile(
		t.Context(),
		compilationSessionFixture(t),
		compilationRequestFixture(t, value.ID(), node.ID{}),
	)
	if !errors.Is(err, compilation.ErrResourceConflict) {
		t.Fatalf("Compile() error = %v, want ErrResourceConflict", err)
	}
}

type compilationResourceResolverFixture struct {
	values []catalog.Resource
	err    error
	calls  int
}

func (resolver *compilationResourceResolverFixture) ResolvePolicyResources(
	context.Context,
	accountsession.Session,
	network.Scope,
	[]resource.ID,
) ([]catalog.Resource, error) {
	resolver.calls++
	return resolver.values, resolver.err
}

func compilationRequestFixture(
	t *testing.T,
	resourceID resource.ID,
	destinationID node.ID,
) compilation.Request {
	t.Helper()
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	if err != nil {
		t.Fatal(err)
	}
	port, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: ruleID, Scope: compilationScopeFixture(t),
		SourceNodeID:      compilationNodeID(t, "000000000701"),
		DestinationNodeID: destinationID, DestinationResourceID: resourceID,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{port},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: compilationScopeFixture(t), Revision: 2, Rules: []compilation.RuleIntent{intent},
	})
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func compilationResourceFixture(t *testing.T, state resource.State) catalog.Resource {
	t.Helper()
	scope := compilationScopeFixture(t)
	name, err := resource.ParseDisplayName("payments-api")
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	if err != nil {
		t.Fatal(err)
	}
	deviceID := compilationNodeID(t, "000000000702")
	definition, err := resource.NewDeviceDefinition(resource.DeviceDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: ownerID,
		CustodianPrincipalID: ownerID, DeviceID: deviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceID, err := resource.ParseID("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 29, 3, 0, 0, 0, time.UTC)
	value, err := catalog.NewResource(catalog.ResourceParams{
		ID: resourceID, Scope: scope, DisplayName: name,
		OwnerPrincipalID: ownerID, CustodianPrincipalID: ownerID,
		DeviceID: deviceID, State: state, Provenance: resource.ProvenanceManual,
		Version: 1, TargetGeneration: 1, SemanticHash: definition.SemanticHash(),
		ActivatedNetworkRevision: 7, InventoryRevision: 7,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func compilationScopeFixture(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func compilationNodeID(t *testing.T, suffix string) node.ID {
	t.Helper()
	id, err := node.ParseID("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func compilationSessionFixture(t *testing.T) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	now := time.Date(2026, time.September, 29, 3, 0, 0, 0, time.UTC)
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}
