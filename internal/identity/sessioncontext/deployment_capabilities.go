package sessioncontext

import (
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

// WorkspaceMode describes only Console navigation shape, never authorization.
type WorkspaceMode string

const (
	// WorkspaceModeSingle means the Deployment admits exactly one active Workspace.
	WorkspaceModeSingle WorkspaceMode = "single"
)

// WorkspaceCreation describes whether tenant users may create Workspaces.
type WorkspaceCreation string

const (
	// WorkspaceCreationBootstrapOnly means ordinary runtime creation is unavailable.
	WorkspaceCreationBootstrapOnly WorkspaceCreation = "bootstrap_only"
)

var (
	// ErrInvalidCapabilityRequest reports malformed input or dependencies.
	ErrInvalidCapabilityRequest = errors.New("session context: invalid deployment capability request")
	// ErrInvalidCapabilityResult reports contradictory or unsupported authority evidence.
	ErrInvalidCapabilityResult = errors.New("session context: invalid deployment capability result")
	// ErrCapabilitiesUnauthenticated conceals stale durable Session authority.
	ErrCapabilitiesUnauthenticated = errors.New("session context: deployment capabilities unauthenticated")
	// ErrCapabilitiesUnavailable reports an unavailable durable projection dependency.
	ErrCapabilitiesUnavailable = errors.New("session context: deployment capabilities unavailable")
)

// CapabilityReadResult is untrusted durable Deployment evidence.
type CapabilityReadResult struct {
	DeploymentID deployment.ID
	Profile      deployment.Profile
	Revision     int64
}

// CapabilityReader loads one fresh capability projection from durable authority.
type CapabilityReader interface {
	ReadDeploymentCapabilities(
		context.Context,
		accountsession.Session,
		time.Time,
	) (CapabilityReadResult, error)
}

// DeploymentCapabilities is a validated non-secret Console projection.
// It is navigation evidence only and grants no product or platform authority.
type DeploymentCapabilities struct {
	profile             deployment.Profile
	workspaceMode       WorkspaceMode
	maxActiveWorkspaces int
	workspaceCreation   WorkspaceCreation
	cloudBilling        bool
	platformOperations  bool
	revision            int64
}

// Profile returns the effective Deployment profile.
func (capabilities DeploymentCapabilities) Profile() deployment.Profile { return capabilities.profile }

// WorkspaceMode returns the server-owned navigation mode.
func (capabilities DeploymentCapabilities) WorkspaceMode() WorkspaceMode {
	return capabilities.workspaceMode
}

// MaxActiveWorkspaces returns the effective active Workspace ceiling.
func (capabilities DeploymentCapabilities) MaxActiveWorkspaces() int {
	return capabilities.maxActiveWorkspaces
}

// WorkspaceCreation returns the effective Workspace creation mode.
func (capabilities DeploymentCapabilities) WorkspaceCreation() WorkspaceCreation {
	return capabilities.workspaceCreation
}

// CloudBilling reports whether tenant cloud billing routes may be rendered.
func (capabilities DeploymentCapabilities) CloudBilling() bool { return capabilities.cloudBilling }

// PlatformOperations reports whether platform operations may be rendered.
func (capabilities DeploymentCapabilities) PlatformOperations() bool {
	return capabilities.platformOperations
}

// Revision returns the monotonic durable capability authority version.
func (capabilities DeploymentCapabilities) Revision() int64 { return capabilities.revision }

// IsValid reports whether this release's closed self-hosted projection is coherent.
func (capabilities DeploymentCapabilities) IsValid() bool {
	return capabilities.profile == deployment.ProfileSelfHosted &&
		capabilities.workspaceMode == WorkspaceModeSingle &&
		capabilities.maxActiveWorkspaces == 1 &&
		capabilities.workspaceCreation == WorkspaceCreationBootstrapOnly &&
		!capabilities.cloudBilling && !capabilities.platformOperations && capabilities.revision > 0
}

// CapabilityService validates server-authoritative Deployment projections.
type CapabilityService struct {
	reader CapabilityReader
	clock  Clock
}

// NewCapabilityService constructs a fail-closed projection service.
func NewCapabilityService(reader CapabilityReader, clock Clock) (*CapabilityService, error) {
	if reader == nil || clock == nil {
		return nil, ErrInvalidCapabilityRequest
	}
	return &CapabilityService{reader: reader, clock: clock}, nil
}

// Read returns the official self-hosted baseline for one fresh exact Session.
// Cloud remains unsupported until signed entitlement authority is implemented.
func (service *CapabilityService) Read(
	ctx context.Context,
	session accountsession.Session,
) (DeploymentCapabilities, error) {
	if ctx == nil || service == nil || service.reader == nil || service.clock == nil || !session.IsValid() {
		return DeploymentCapabilities{}, ErrInvalidCapabilityRequest
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return DeploymentCapabilities{}, ErrCapabilitiesUnauthenticated
	}
	result, err := service.reader.ReadDeploymentCapabilities(ctx, session, now)
	if err != nil {
		return DeploymentCapabilities{}, err
	}
	if result.DeploymentID != session.DeploymentID() ||
		result.Profile != deployment.ProfileSelfHosted || result.Revision <= 0 {
		return DeploymentCapabilities{}, ErrInvalidCapabilityResult
	}
	capabilities := DeploymentCapabilities{
		profile:             deployment.ProfileSelfHosted,
		workspaceMode:       WorkspaceModeSingle,
		maxActiveWorkspaces: 1,
		workspaceCreation:   WorkspaceCreationBootstrapOnly,
		revision:            result.Revision,
	}
	if !capabilities.IsValid() {
		return DeploymentCapabilities{}, ErrInvalidCapabilityResult
	}
	return capabilities, nil
}
