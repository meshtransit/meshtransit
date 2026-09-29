package sharing

import (
	"testing"

	"github.com/meshtransit/meshtransit/internal/network"
)

func TestClassifyScopeRelationDerivesTrustBoundary(t *testing.T) {
	t.Parallel()

	withinProvider := mustScope(t, 1, 2)
	withinConsumer := mustScope(t, 1, 3)
	crossConsumer := mustScope(t, 4, 5)

	tests := []struct {
		name     string
		provider network.Scope
		consumer network.Scope
		want     ScopeRelation
		wire     string
	}{
		{
			name: "within Workspace", provider: withinProvider, consumer: withinConsumer,
			want: ScopeRelationWithinWorkspace, wire: "within_workspace",
		},
		{
			name: "cross Workspace", provider: withinProvider, consumer: crossConsumer,
			want: ScopeRelationCrossWorkspace, wire: "cross_workspace",
		},
		{
			name: "same Network", provider: withinProvider, consumer: withinProvider,
			want: ScopeRelationUnknown,
		},
		{
			name: "invalid provider", provider: network.Scope{}, consumer: withinConsumer,
			want: ScopeRelationUnknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			relation := ClassifyScopeRelation(test.provider, test.consumer)
			if relation != test.want || relation.String() != test.wire ||
				relation.IsValid() != (test.want != ScopeRelationUnknown) ||
				relation.RequiresIndependentWorkspaceConsent() !=
					(test.want == ScopeRelationCrossWorkspace) {
				t.Fatalf("ClassifyScopeRelation() = %v/%q", relation, relation.String())
			}
		})
	}
}
