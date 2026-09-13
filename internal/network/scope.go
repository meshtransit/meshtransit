package network

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/workspace"
)

// ErrInvalidScope reports an incomplete Workspace-qualified Network scope.
var ErrInvalidScope = errors.New("network: invalid scope")

// Scope is an immutable Network identity qualified by its owning Workspace.
type Scope struct {
	workspaceID workspace.ID
	networkID   ID
}

// NewScope validates and returns an exact Workspace and Network pair.
func NewScope(workspaceID workspace.ID, networkID ID) (Scope, error) {
	if !workspaceID.IsValid() || !networkID.IsValid() {
		return Scope{}, ErrInvalidScope
	}
	return Scope{workspaceID: workspaceID, networkID: networkID}, nil
}

// WorkspaceID returns the owning Workspace identity.
func (s Scope) WorkspaceID() workspace.ID { return s.workspaceID }

// NetworkID returns the Network identity.
func (s Scope) NetworkID() ID { return s.networkID }

// IsValid reports whether both scope identities are valid.
func (s Scope) IsValid() bool {
	return s.workspaceID.IsValid() && s.networkID.IsValid()
}
