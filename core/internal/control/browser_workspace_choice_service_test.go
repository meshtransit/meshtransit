package control

import (
	"context"
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

type browserWorkspaceChoicesFake struct {
	workspaces     enrollment.BrowserEnrollmentWorkspaceChoices
	networks       enrollment.BrowserEnrollmentChoices
	found          bool
	workspaceCalls int
	networkCalls   int
	selected       workspace.ID
}

func (fake *browserWorkspaceChoicesFake) ReadBrowserEnrollmentWorkspaces(_ context.Context,
	_ deployment.ID, _ int64, _ accountsession.Digest, _ workspace.ID, _ int,
) (enrollment.BrowserEnrollmentWorkspaceChoices, bool, error) {
	fake.workspaceCalls++
	return fake.workspaces, fake.found, nil
}

func (fake *browserWorkspaceChoicesFake) ReadBrowserEnrollmentNetworksInWorkspace(_ context.Context,
	_ deployment.ID, _ int64, _ accountsession.Digest, selected workspace.ID, _ network.ID, _ int,
) (enrollment.BrowserEnrollmentChoices, bool, error) {
	fake.networkCalls++
	fake.selected = selected
	return fake.networks, fake.found, nil
}

func TestBrowserWorkspaceChoiceRequiresExplicitWorkspaceAndRechecksScope(t *testing.T) {
	t.Parallel()
	old, landing, networks, digest := browserChoiceFixture(t)
	first := networks.value.WorkspaceID
	second, err := workspace.ParseID("01890f00-0000-7000-8000-000000000104")
	if err != nil {
		t.Fatal(err)
	}
	reader := &browserWorkspaceChoicesFake{found: true,
		workspaces: enrollment.BrowserEnrollmentWorkspaceChoices{Workspaces: []enrollment.BrowserEnrollmentWorkspaceChoice{
			{WorkspaceID: first, DisplayName: "Owned Workspace"},
			{WorkspaceID: second, DisplayName: "Invited Workspace"},
		}}, networks: networks.value}
	reader.networks.WorkspaceDisplayName = "Owned Workspace"
	service, err := NewBrowserWorkspaceChoiceService(landing, reader, old.deploymentID, old.epoch)
	if err != nil {
		t.Fatal(err)
	}
	page, found, err := service.ReadWorkspaces(t.Context(), digest, browserChoiceTestToken, workspace.ID{}, 1)
	if err != nil || !found || !page.HasMore || len(page.Choices.Workspaces) != 1 || reader.networkCalls != 0 {
		t.Fatalf("first Workspace page = (%+v, %v, %v), Network calls=%d", page, found, err, reader.networkCalls)
	}
	if _, _, err := service.ReadNetworks(t.Context(), digest, browserChoiceTestToken, workspace.ID{}, network.ID{}, 100); !errors.Is(err, ErrInvalidBrowserChoice) || reader.networkCalls != 0 {
		t.Fatal("missing Workspace reached Network inventory")
	}
	chosen, found, err := service.ReadNetworks(t.Context(), digest, browserChoiceTestToken, first, network.ID{}, 100)
	if err != nil || !found || chosen.Choices.WorkspaceID != first || reader.selected != first || reader.networkCalls != 1 {
		t.Fatalf("exact Workspace choices = (%+v, %v, %v)", chosen, found, err)
	}
	if _, _, err := service.ReadNetworks(t.Context(), digest, browserChoiceTestToken, second, network.ID{}, 100); !errors.Is(err, ErrBrowserChoiceUnavailable) {
		t.Fatal("another Workspace's returned inventory accepted")
	}
	reader.networks.WorkspaceID = second
	reader.networks.WorkspaceDisplayName = "Invited Workspace"
	if page, found, err := service.ReadNetworks(t.Context(), digest, browserChoiceTestToken, second, network.ID{}, 100); err != nil || !found || page.Choices.WorkspaceID != second {
		t.Fatalf("invited Workspace choices = (%+v, %v, %v)", page, found, err)
	}
	reader.found = false
	if page, found, err := service.ReadNetworks(t.Context(), digest, browserChoiceTestToken, second, network.ID{}, 100); err != nil || found || page.Choices.WorkspaceID.IsValid() {
		t.Fatal("revoked Workspace retained Network inventory")
	}
	landing.found = false
	before := reader.workspaceCalls
	if _, found, err := service.ReadWorkspaces(t.Context(), digest, browserChoiceTestToken, workspace.ID{}, 100); err != nil || found || reader.workspaceCalls != before {
		t.Fatal("missing intent reached Workspace inventory")
	}
}
