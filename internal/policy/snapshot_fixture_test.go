package policy

import (
	"testing"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func policyScopeFixture(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	return scope
}

func policyNodeFixture(t *testing.T, suffix string) node.ID {
	t.Helper()
	id, err := node.ParseID("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	return id
}

func policyRuleFixture(
	t *testing.T,
	idSuffix string,
	source node.ID,
	destination node.ID,
	protocol Protocol,
	ports []PortRange,
) Rule {
	t.Helper()
	id, err := ParseRuleID("01890f00-0000-7000-8000-" + idSuffix)
	if err != nil {
		t.Fatalf("ParseRuleID() error = %v", err)
	}
	rule, err := NewRule(RuleParams{
		ID:                    id,
		Scope:                 policyScopeFixture(t),
		SourceNodeID:          source,
		DestinationNodeID:     destination,
		Protocol:              protocol,
		DestinationPortRanges: ports,
	})
	if err != nil {
		t.Fatalf("NewRule() error = %v", err)
	}
	return rule
}
