// Package authorization owns management permissions and scoped grant evaluation.
package authorization

import "errors"

var (
	// ErrInvalidPublicID reports an absent or malformed domain public identifier.
	ErrInvalidPublicID = errors.New("authorization: invalid public id")
	// ErrInvalidScope reports an incomplete or structurally invalid authority scope.
	ErrInvalidScope = errors.New("authorization: invalid scope")
)

// DeploymentID is a validated opaque UUIDv7 identifying one deployment.
type DeploymentID [16]byte

// WorkspaceID is a validated opaque UUIDv7 identifying one workspace.
type WorkspaceID [16]byte

// NetworkID is a validated opaque UUIDv7 identifying one network.
type NetworkID [16]byte

// PrincipalID is a validated opaque UUIDv7 identifying one management principal.
type PrincipalID [16]byte

// NewDeploymentID validates and returns an opaque deployment identifier.
func NewDeploymentID(value [16]byte) (DeploymentID, error) {
	if !isUUIDv7(value) {
		return DeploymentID{}, ErrInvalidPublicID
	}
	return DeploymentID(value), nil
}

// NewWorkspaceID validates and returns an opaque workspace identifier.
func NewWorkspaceID(value [16]byte) (WorkspaceID, error) {
	if !isUUIDv7(value) {
		return WorkspaceID{}, ErrInvalidPublicID
	}
	return WorkspaceID(value), nil
}

// NewNetworkID validates and returns an opaque network identifier.
func NewNetworkID(value [16]byte) (NetworkID, error) {
	if !isUUIDv7(value) {
		return NetworkID{}, ErrInvalidPublicID
	}
	return NetworkID(value), nil
}

// NewPrincipalID validates and returns an opaque principal identifier.
func NewPrincipalID(value [16]byte) (PrincipalID, error) {
	if !isUUIDv7(value) {
		return PrincipalID{}, ErrInvalidPublicID
	}
	return PrincipalID(value), nil
}

func isUUIDv7(value [16]byte) bool {
	return value[6]>>4 == 7 && value[8]&0xc0 == 0x80
}

func (id DeploymentID) isValid() bool { return isUUIDv7([16]byte(id)) }

func (id WorkspaceID) isValid() bool { return isUUIDv7([16]byte(id)) }

func (id NetworkID) isValid() bool { return isUUIDv7([16]byte(id)) }

func (id PrincipalID) isValid() bool { return isUUIDv7([16]byte(id)) }

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
	if !deploymentID.isValid() {
		return Scope{}, ErrInvalidScope
	}
	return Scope{
		kind:         ScopeDeployment,
		deploymentID: deploymentID,
	}, nil
}

// NewWorkspaceScope constructs a workspace scope qualified by its deployment.
func NewWorkspaceScope(deploymentID DeploymentID, workspaceID WorkspaceID) (Scope, error) {
	if !deploymentID.isValid() || !workspaceID.isValid() {
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
	if !deploymentID.isValid() || !workspaceID.isValid() || !networkID.isValid() {
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
		return s.deploymentID.isValid() && s.workspaceID == (WorkspaceID{}) &&
			s.networkID == (NetworkID{})
	case ScopeWorkspace:
		return s.deploymentID.isValid() && s.workspaceID.isValid() &&
			s.networkID == (NetworkID{})
	case ScopeNetwork:
		return s.deploymentID.isValid() && s.workspaceID.isValid() && s.networkID.isValid()
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
