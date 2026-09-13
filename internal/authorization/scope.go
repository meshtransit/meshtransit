// Package authorization owns management permissions and scoped grant evaluation.
package authorization

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

var (
	// ErrInvalidPublicID reports an absent or malformed domain public identifier.
	ErrInvalidPublicID = errors.New("authorization: invalid public id")
	// ErrInvalidScope reports an incomplete or structurally invalid authority scope.
	ErrInvalidScope = errors.New("authorization: invalid scope")
)

// DeploymentID is the canonical Deployment domain identifier.
type DeploymentID = deployment.ID

// WorkspaceID is the canonical Workspace domain identifier.
type WorkspaceID = workspace.ID

// NetworkID is the canonical Network domain identifier.
type NetworkID = network.ID

// PrincipalID is a validated opaque UUIDv7 identifying one management principal.
type PrincipalID publicid.ID

// NewDeploymentID validates and returns an opaque deployment identifier.
func NewDeploymentID(value [16]byte) (DeploymentID, error) {
	id, err := deployment.NewID(value)
	if err != nil {
		return DeploymentID{}, ErrInvalidPublicID
	}
	return id, nil
}

// NewWorkspaceID validates and returns an opaque workspace identifier.
func NewWorkspaceID(value [16]byte) (WorkspaceID, error) {
	id, err := workspace.NewID(value)
	if err != nil {
		return WorkspaceID{}, ErrInvalidPublicID
	}
	return id, nil
}

// NewNetworkID validates and returns an opaque network identifier.
func NewNetworkID(value [16]byte) (NetworkID, error) {
	id, err := network.NewID(value)
	if err != nil {
		return NetworkID{}, ErrInvalidPublicID
	}
	return id, nil
}

// NewPrincipalID validates and returns an opaque principal identifier.
func NewPrincipalID(value [16]byte) (PrincipalID, error) {
	id, err := publicid.FromBytes(value)
	if err != nil {
		return PrincipalID{}, ErrInvalidPublicID
	}
	return PrincipalID(id), nil
}

func (id PrincipalID) isValid() bool { return publicid.ID(id).IsValid() }

// ScopeKind identifies an authorization boundary level.
type ScopeKind uint8

const (
	// ScopeUnknown is the invalid zero-value scope kind.
	ScopeUnknown ScopeKind = iota
	// ScopeDeployment identifies the deployment authority boundary.
	ScopeDeployment
	// ScopeWorkspace identifies one workspace within a deployment.
	ScopeWorkspace
	// ScopeNetwork identifies one network within a workspace.
	ScopeNetwork
)

// Scope is an immutable, fully qualified management-authority boundary.
type Scope struct {
	kind         ScopeKind
	deploymentID DeploymentID
	workspaceID  WorkspaceID
	networkID    NetworkID
}

// NewDeploymentScope constructs an exact deployment scope.
func NewDeploymentScope(deploymentID DeploymentID) (Scope, error) {
	if !deploymentID.IsValid() {
		return Scope{}, ErrInvalidScope
	}
	return Scope{
		kind:         ScopeDeployment,
		deploymentID: deploymentID,
	}, nil
}

// NewWorkspaceScope constructs a workspace scope qualified by its deployment.
func NewWorkspaceScope(deploymentID DeploymentID, workspaceID WorkspaceID) (Scope, error) {
	if !deploymentID.IsValid() || !workspaceID.IsValid() {
		return Scope{}, ErrInvalidScope
	}
	return Scope{
		kind:         ScopeWorkspace,
		deploymentID: deploymentID,
		workspaceID:  workspaceID,
	}, nil
}

// NewNetworkScope constructs a network scope qualified by its workspace and deployment.
func NewNetworkScope(
	deploymentID DeploymentID,
	workspaceID WorkspaceID,
	networkID NetworkID,
) (Scope, error) {
	if !deploymentID.IsValid() || !workspaceID.IsValid() || !networkID.IsValid() {
		return Scope{}, ErrInvalidScope
	}
	return Scope{
		kind:         ScopeNetwork,
		deploymentID: deploymentID,
		workspaceID:  workspaceID,
		networkID:    networkID,
	}, nil
}

// Kind returns the scope hierarchy level.
func (s Scope) Kind() ScopeKind { return s.kind }

// DeploymentID returns the deployment qualifier shared by every scope.
func (s Scope) DeploymentID() DeploymentID { return s.deploymentID }

// WorkspaceID returns the workspace qualifier and whether this scope has one.
func (s Scope) WorkspaceID() (WorkspaceID, bool) {
	return s.workspaceID, s.kind == ScopeWorkspace || s.kind == ScopeNetwork
}

// NetworkID returns the network qualifier and whether this is a network scope.
func (s Scope) NetworkID() (NetworkID, bool) {
	return s.networkID, s.kind == ScopeNetwork
}

func (s Scope) isValid() bool {
	switch s.kind {
	case ScopeDeployment:
		return s.deploymentID.IsValid() && s.workspaceID == (WorkspaceID{}) &&
			s.networkID == (NetworkID{})
	case ScopeWorkspace:
		return s.deploymentID.IsValid() && s.workspaceID.IsValid() &&
			s.networkID == (NetworkID{})
	case ScopeNetwork:
		return s.deploymentID.IsValid() && s.workspaceID.IsValid() && s.networkID.IsValid()
	default:
		return false
	}
}

func (s Scope) contains(target Scope) bool {
	if !s.isValid() || !target.isValid() || s.deploymentID != target.deploymentID {
		return false
	}
	switch s.kind {
	case ScopeDeployment:
		return true
	case ScopeWorkspace:
		return target.kind >= ScopeWorkspace && s.workspaceID == target.workspaceID
	case ScopeNetwork:
		return target.kind == ScopeNetwork && s.workspaceID == target.workspaceID &&
			s.networkID == target.networkID
	default:
		return false
	}
}
