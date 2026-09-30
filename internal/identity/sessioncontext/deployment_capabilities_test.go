package sessioncontext_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/sessioncontext"
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
	if !reader.evaluatedAt.Equal(now) || reader.session.ID() != session.ID() {
		t.Fatal("Read() did not bind the exact Session and evaluation time")
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
		{name: "cloud entitlement not implemented", result: sessioncontext.CapabilityReadResult{
			DeploymentID: session.DeploymentID(), Profile: deployment.ProfileCloud, Revision: 1,
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

type capabilityReader struct {
	result      sessioncontext.CapabilityReadResult
	err         error
	session     accountsession.Session
	evaluatedAt time.Time
}

func (reader *capabilityReader) ReadDeploymentCapabilities(
	_ context.Context,
	session accountsession.Session,
	evaluatedAt time.Time,
) (sessioncontext.CapabilityReadResult, error) {
	reader.session, reader.evaluatedAt = session, evaluatedAt
	return reader.result, reader.err
}
