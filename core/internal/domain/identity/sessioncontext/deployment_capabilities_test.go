package sessioncontext_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identity/sessioncontext"
)

func TestCapabilityServiceProjectsValidatedSelfHostedBaseline(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	session := testSession(t, now)
	reader := &capabilityReader{result: sessioncontext.CapabilityReadResult{
		DeploymentID: session.DeploymentID(),
		Profile:      deployment.ProfileSelfHosted,
		Revision:     7,
	}}
	service, err := sessioncontext.NewCapabilityService(reader, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewCapabilityService() error = %v", err)
	}

	capabilities, err := service.Read(t.Context(), session)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if capabilities.Profile() != deployment.ProfileSelfHosted ||
		capabilities.WorkspaceMode() != sessioncontext.WorkspaceModeSingle ||
		capabilities.MaxActiveWorkspaces() != 1 ||
		capabilities.WorkspaceCreation() != sessioncontext.WorkspaceCreationBootstrapOnly ||
		capabilities.CloudBilling() || capabilities.PlatformOperations() || capabilities.Revision() != 7 {
		t.Fatalf("Read() capabilities = %+v", capabilities)
	}
	if reader.session.ID() != session.ID() {
		t.Fatal("Read() did not bind the exact Session")
	}
}

func TestCapabilityServiceFailsClosedForUnsupportedOrContradictoryEvidence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	session := testSession(t, now)
	otherDeploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		result sessioncontext.CapabilityReadResult
	}{
		{name: "unknown capability", result: sessioncontext.CapabilityReadResult{
			DeploymentID: session.DeploymentID(), Profile: deployment.ProfileCloud, Revision: 1,
			Entitlement: &sessioncontext.EntitlementEvidence{Generation: 1, MaxActiveWorkspaces: 5,
				MaxOwnedWorkspacesPerAccount: 5, Capabilities: []string{"vip"}, State: "active"},
		}},
		{name: "owned above active", result: sessioncontext.CapabilityReadResult{
			DeploymentID: session.DeploymentID(), Profile: deployment.ProfileCloud, Revision: 1,
			Entitlement: &sessioncontext.EntitlementEvidence{Generation: 1, MaxActiveWorkspaces: 2,
				MaxOwnedWorkspacesPerAccount: 5, Capabilities: []string{}, State: "active"},
		}},
		{name: "unknown state", result: sessioncontext.CapabilityReadResult{
			DeploymentID: session.DeploymentID(), Profile: deployment.ProfileCloud, Revision: 1,
			Entitlement: &sessioncontext.EntitlementEvidence{Generation: 1, MaxActiveWorkspaces: 2,
				MaxOwnedWorkspacesPerAccount: 1, Capabilities: []string{}, State: "revoked"},
		}},
		{name: "wrong deployment", result: sessioncontext.CapabilityReadResult{
			DeploymentID: otherDeploymentID, Profile: deployment.ProfileSelfHosted, Revision: 1,
		}},
		{name: "zero revision", result: sessioncontext.CapabilityReadResult{
			DeploymentID: session.DeploymentID(), Profile: deployment.ProfileSelfHosted,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service, err := sessioncontext.NewCapabilityService(
				&capabilityReader{result: test.result},
				fixedClock{now: now},
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Read(t.Context(), session); !errors.Is(err, sessioncontext.ErrInvalidCapabilityResult) {
				t.Fatalf("Read() error = %v, want ErrInvalidCapabilityResult", err)
			}
		})
	}
}

func TestCapabilityServiceDerivesLimitsFromEntitlement(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	session := testSession(t, now)
	for _, test := range []struct {
		name     string
		profile  deployment.Profile
		evidence sessioncontext.EntitlementEvidence
		mode     sessioncontext.WorkspaceMode
		creation sessioncontext.WorkspaceCreation
	}{
		{"cloud active", deployment.ProfileCloud, sessioncontext.EntitlementEvidence{Generation: 2,
			MaxActiveWorkspaces: 50, MaxOwnedWorkspacesPerAccount: 5, Capabilities: []string{"cloud_billing"},
			State: "active"}, sessioncontext.WorkspaceModeMulti, sessioncontext.WorkspaceCreationAccount},
		{"self-host same features lower limit", deployment.ProfileSelfHosted, sessioncontext.EntitlementEvidence{
			Generation: 1, MaxActiveWorkspaces: 3, MaxOwnedWorkspacesPerAccount: 3, Capabilities: []string{},
			State: "grace"}, sessioncontext.WorkspaceModeMulti, sessioncontext.WorkspaceCreationAccount},
		{"expired keeps tenants but stops creation", deployment.ProfileCloud, sessioncontext.EntitlementEvidence{
			Generation: 3, MaxActiveWorkspaces: 50, MaxOwnedWorkspacesPerAccount: 5, Capabilities: []string{},
			State: "expired"}, sessioncontext.WorkspaceModeMulti, sessioncontext.WorkspaceCreationSuspended},
		{"one Workspace entitlement", deployment.ProfileSelfHosted, sessioncontext.EntitlementEvidence{
			Generation: 1, MaxActiveWorkspaces: 1, MaxOwnedWorkspacesPerAccount: 1, Capabilities: []string{},
			State: "active"}, sessioncontext.WorkspaceModeSingle, sessioncontext.WorkspaceCreationAccount},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			evidence := test.evidence
			service, err := sessioncontext.NewCapabilityService(&capabilityReader{result: sessioncontext.CapabilityReadResult{
				DeploymentID: session.DeploymentID(), Profile: test.profile, Revision: 7, Entitlement: &evidence,
			}}, fixedClock{now: now})
			if err != nil {
				t.Fatal(err)
			}
			capabilities, err := service.Read(t.Context(), session)
			if err != nil || capabilities.WorkspaceMode() != test.mode || capabilities.WorkspaceCreation() != test.creation ||
				capabilities.MaxActiveWorkspaces() != int(evidence.MaxActiveWorkspaces) ||
				capabilities.MaxOwnedWorkspacesPerAccount() != int(evidence.MaxOwnedWorkspacesPerAccount) ||
				capabilities.Revision() != 7+evidence.Generation ||
				capabilities.CloudBilling() != (len(evidence.Capabilities) == 1) {
				t.Fatalf("Read() = %+v, %v", capabilities, err)
			}
		})
	}
}

func TestCapabilityServiceCloudWithoutEntitlementIsUnavailable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	session := testSession(t, now)
	service, err := sessioncontext.NewCapabilityService(&capabilityReader{result: sessioncontext.CapabilityReadResult{
		DeploymentID: session.DeploymentID(), Profile: deployment.ProfileCloud, Revision: 1,
	}}, fixedClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Read(t.Context(), session); !errors.Is(err, sessioncontext.ErrCapabilitiesUnavailable) {
		t.Fatalf("Cloud without entitlement: %v", err)
	}
}

type capabilityReader struct {
	result  sessioncontext.CapabilityReadResult
	err     error
	session accountsession.Session
}

func (reader *capabilityReader) ReadDeploymentCapabilities(
	_ context.Context,
	session accountsession.Session,
) (sessioncontext.CapabilityReadResult, error) {
	reader.session = session
	return reader.result, reader.err
}
