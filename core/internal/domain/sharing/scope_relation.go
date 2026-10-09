package sharing

import "github.com/meshtransit/meshtransit/core/internal/domain/network"

// ScopeRelation describes how the provider and consumer Networks are related.
// It is always derived from authoritative scope identities, never caller input.
type ScopeRelation uint8

const (
	// ScopeRelationUnknown is the unusable zero value.
	ScopeRelationUnknown ScopeRelation = iota
	// ScopeRelationWithinWorkspace connects two distinct Networks in one Workspace.
	ScopeRelationWithinWorkspace
	// ScopeRelationCrossWorkspace crosses a Workspace trust boundary.
	ScopeRelationCrossWorkspace
)

// ClassifyScopeRelation derives the sharing trust boundary from exact scopes.
func ClassifyScopeRelation(provider, consumer network.Scope) ScopeRelation {
	if !provider.IsValid() || !consumer.IsValid() || provider == consumer {
		return ScopeRelationUnknown
	}
	if provider.WorkspaceID() == consumer.WorkspaceID() {
		return ScopeRelationWithinWorkspace
	}
	return ScopeRelationCrossWorkspace
}

// IsValid reports whether the relation has defined sharing semantics.
func (relation ScopeRelation) IsValid() bool {
	return relation == ScopeRelationWithinWorkspace || relation == ScopeRelationCrossWorkspace
}

// String returns the stable management and evidence representation.
func (relation ScopeRelation) String() string {
	switch relation {
	case ScopeRelationWithinWorkspace:
		return "within_workspace"
	case ScopeRelationCrossWorkspace:
		return "cross_workspace"
	default:
		return ""
	}
}

// RequiresIndependentWorkspaceConsent reports whether acceptance crosses a
// Workspace authority boundary. The provider offer remains the provider-side
// consent; acceptance must be freshly authorized in the consumer Workspace.
func (relation ScopeRelation) RequiresIndependentWorkspaceConsent() bool {
	return relation == ScopeRelationCrossWorkspace
}
