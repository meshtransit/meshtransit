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
	// WorkspaceModeMulti means the Deployment admits several Workspaces.
	WorkspaceModeMulti WorkspaceMode = "multi"
)

// WorkspaceCreation describes whether tenant users may create Workspaces.
type WorkspaceCreation string

const (
	// WorkspaceCreationBootstrapOnly means ordinary runtime creation is unavailable.
	WorkspaceCreationBootstrapOnly WorkspaceCreation = "bootstrap_only"
	// WorkspaceCreationAccount means any authenticated Account may create a
	// Workspace within the entitlement quotas (ADR-050 D3).
	WorkspaceCreationAccount WorkspaceCreation = "account"
	// WorkspaceCreationSuspended means the entitlement is past its grace
	// period; creation fails closed while existing Workspaces keep working.
	WorkspaceCreationSuspended WorkspaceCreation = "suspended"
)

// EntitlementState is the verified entitlement's validity state.
type EntitlementState string

const (
	// EntitlementStateNone means no entitlement; only the legacy self-host
	// baseline is available.
	EntitlementStateNone EntitlementState = "none"
	// EntitlementStateActive is inside the validity window.
	EntitlementStateActive EntitlementState = "active"
	// EntitlementStateGrace is after expiry and inside the grace period.
	EntitlementStateGrace EntitlementState = "grace"
	// EntitlementStateExpired is after the grace period.
	EntitlementStateExpired EntitlementState = "expired"
)

const (
	cloudBillingCapability       = "cloud_billing"
	platformOperationsCapability = "platform_operations"
	maxEntitledWorkspaces        = 1_000_000
	maxEntitledOwnedWorkspaces   = 1_000
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

// EntitlementEvidence is the current recorded entitlement generation.
type EntitlementEvidence struct {
	Generation                   int64
	MaxActiveWorkspaces          int64
	MaxOwnedWorkspacesPerAccount int64
	Capabilities                 []string
	State                        string
}

// CapabilityReadResult is untrusted durable Deployment evidence. A nil
// Entitlement means no verified generation is recorded.
type CapabilityReadResult struct {
	DeploymentID deployment.ID
	Profile      deployment.Profile
	Revision     int64
	Entitlement  *EntitlementEvidence
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
// Profiles share one feature set; only the limits differ.
type DeploymentCapabilities struct {
	profile                      deployment.Profile
	workspaceMode                WorkspaceMode
	maxActiveWorkspaces          int
	maxOwnedWorkspacesPerAccount int
	workspaceCreation            WorkspaceCreation
	entitlementState             EntitlementState
	cloudBilling                 bool
	platformOperations           bool
	revision                     int64
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

// MaxOwnedWorkspacesPerAccount returns the per-Account ownership quota.
func (capabilities DeploymentCapabilities) MaxOwnedWorkspacesPerAccount() int {
	return capabilities.maxOwnedWorkspacesPerAccount
}

// WorkspaceCreation returns the effective Workspace creation mode.
func (capabilities DeploymentCapabilities) WorkspaceCreation() WorkspaceCreation {
	return capabilities.workspaceCreation
}

// EntitlementState returns the verified entitlement state.
func (capabilities DeploymentCapabilities) EntitlementState() EntitlementState {
	return capabilities.entitlementState
}

// CloudBilling reports whether tenant cloud billing routes may be rendered.
func (capabilities DeploymentCapabilities) CloudBilling() bool { return capabilities.cloudBilling }

// PlatformOperations reports whether platform operations may be rendered.
func (capabilities DeploymentCapabilities) PlatformOperations() bool {
	return capabilities.platformOperations
}

// Revision returns the monotonic durable capability authority version.
func (capabilities DeploymentCapabilities) Revision() int64 { return capabilities.revision }

// IsValid reports whether the projection is coherent: the legacy self-host
// baseline without an entitlement, or entitlement-derived limits.
func (capabilities DeploymentCapabilities) IsValid() bool {
	if !capabilities.profile.IsValid() || capabilities.revision <= 0 {
		return false
	}
	if capabilities.entitlementState == EntitlementStateNone {
		return capabilities.profile == deployment.ProfileSelfHosted &&
			capabilities.workspaceMode == WorkspaceModeSingle &&
			capabilities.maxActiveWorkspaces == 1 && capabilities.maxOwnedWorkspacesPerAccount == 1 &&
			capabilities.workspaceCreation == WorkspaceCreationBootstrapOnly &&
			!capabilities.cloudBilling && !capabilities.platformOperations
	}
	expired := capabilities.entitlementState == EntitlementStateExpired
	return (capabilities.entitlementState == EntitlementStateActive ||
		capabilities.entitlementState == EntitlementStateGrace || expired) &&
		capabilities.maxActiveWorkspaces >= 1 && capabilities.maxActiveWorkspaces <= maxEntitledWorkspaces &&
		capabilities.maxOwnedWorkspacesPerAccount >= 1 &&
		capabilities.maxOwnedWorkspacesPerAccount <= min(capabilities.maxActiveWorkspaces, maxEntitledOwnedWorkspaces) &&
		(capabilities.workspaceMode == WorkspaceModeMulti) == (capabilities.maxActiveWorkspaces > 1) &&
		(capabilities.workspaceCreation == WorkspaceCreationSuspended) == expired &&
		(capabilities.workspaceCreation == WorkspaceCreationAccount) == !expired
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

// Read derives capabilities for one fresh exact Session. Without a verified
// entitlement a self-hosted Deployment keeps the legacy single-Workspace
// baseline and a Cloud Deployment fails closed.
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
	if result.DeploymentID != session.DeploymentID() || !result.Profile.IsValid() || result.Revision <= 0 {
		return DeploymentCapabilities{}, ErrInvalidCapabilityResult
	}
	capabilities, err := project(result)
	if err != nil {
		return DeploymentCapabilities{}, err
	}
	if !capabilities.IsValid() {
		return DeploymentCapabilities{}, ErrInvalidCapabilityResult
	}
	return capabilities, nil
}

func project(result CapabilityReadResult) (DeploymentCapabilities, error) {
	evidence := result.Entitlement
	if evidence == nil || evidence.State == "not_yet_valid" {
		if result.Profile != deployment.ProfileSelfHosted {
			return DeploymentCapabilities{}, ErrCapabilitiesUnavailable
		}
		return DeploymentCapabilities{
			profile: deployment.ProfileSelfHosted, workspaceMode: WorkspaceModeSingle,
			maxActiveWorkspaces: 1, maxOwnedWorkspacesPerAccount: 1,
			workspaceCreation: WorkspaceCreationBootstrapOnly, entitlementState: EntitlementStateNone,
			revision: result.Revision,
		}, nil
	}
	state := EntitlementState(evidence.State)
	if evidence.Generation <= 0 || evidence.MaxActiveWorkspaces < 1 ||
		evidence.MaxActiveWorkspaces > maxEntitledWorkspaces || evidence.MaxOwnedWorkspacesPerAccount < 1 ||
		evidence.MaxOwnedWorkspacesPerAccount > maxEntitledOwnedWorkspaces ||
		(state != EntitlementStateActive && state != EntitlementStateGrace && state != EntitlementStateExpired) {
		return DeploymentCapabilities{}, ErrInvalidCapabilityResult
	}
	capabilities := DeploymentCapabilities{
		profile: result.Profile, workspaceMode: WorkspaceModeSingle,
		maxActiveWorkspaces:          int(evidence.MaxActiveWorkspaces),
		maxOwnedWorkspacesPerAccount: int(evidence.MaxOwnedWorkspacesPerAccount),
		workspaceCreation:            WorkspaceCreationAccount, entitlementState: state,
		// Both inputs only increase, so the sum is monotonic.
		revision: result.Revision + evidence.Generation,
	}
	if evidence.MaxActiveWorkspaces > 1 {
		capabilities.workspaceMode = WorkspaceModeMulti
	}
	if state == EntitlementStateExpired {
		capabilities.workspaceCreation = WorkspaceCreationSuspended
	}
	for _, capability := range evidence.Capabilities {
		switch capability {
		case cloudBillingCapability:
			capabilities.cloudBilling = true
		case platformOperationsCapability:
			capabilities.platformOperations = true
		default:
			return DeploymentCapabilities{}, ErrInvalidCapabilityResult
		}
	}
	return capabilities, nil
}
