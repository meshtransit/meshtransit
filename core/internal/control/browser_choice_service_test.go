package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

var browserChoiceTestToken = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))

type browserLandingFake struct {
	value  enrollment.BrowserIntentLanding
	found  bool
	calls  int
	digest accountsession.Digest
}

func (fake *browserLandingFake) ReadLanding(
	_ context.Context, _ deployment.ID, _ int64,
	digest accountsession.Digest, _ string,
) (enrollment.BrowserIntentLanding, bool, error) {
	fake.calls++
	fake.digest = digest
	return fake.value, fake.found, nil
}

type browserNetworkChoicesFake struct {
	value  enrollment.BrowserEnrollmentChoices
	found  bool
	calls  int
	digest accountsession.Digest
}

func (fake *browserNetworkChoicesFake) ReadBrowserEnrollmentNetworks(
	_ context.Context, _ deployment.ID, _ int64,
	digest accountsession.Digest, _ network.ID, _ int,
) (enrollment.BrowserEnrollmentChoices, bool, error) {
	fake.calls++
	fake.digest = digest
	return fake.value, fake.found, nil
}

func TestBrowserChoiceServiceKeepsNetworkChoiceExplicit(t *testing.T) {
	t.Parallel()
	service, landing, networks, digest := browserChoiceFixture(t)
	page, found, err := service.Read(t.Context(), digest,
		browserChoiceTestToken, network.ID{}, 100)
	if err != nil || !found || landing.calls != 1 || networks.calls != 1 ||
		landing.digest != digest || networks.digest != digest ||
		page.Landing.Hostname != "node-one.example" ||
		len(page.Choices.Networks) != 1 ||
		page.Choices.Networks[0].DisplayName != "Owned Network" {
		t.Fatalf("read SSO choices = (%+v, %v, %v), calls=%d/%d",
			page, found, err, landing.calls, networks.calls)
	}
	// The service returns the one eligible option but never a selected Network.
	landing.found = false
	page, found, err = service.Read(t.Context(), digest,
		browserChoiceTestToken, network.ID{}, 100)
	if err != nil || found || page.Landing.IsValid() ||
		page.Choices.WorkspaceID.IsValid() || networks.calls != 1 {
		t.Fatal("invalid intent reached Network inventory")
	}
	landing.found = true
	networks.found = false
	page, found, err = service.Read(t.Context(), digest,
		browserChoiceTestToken, network.ID{}, 100)
	if err != nil || found || page.Landing.IsValid() || page.Choices.WorkspaceID.IsValid() {
		t.Fatal("lost SSO Session retained Network inventory")
	}
}

func TestBrowserChoiceServiceRejectsInvalidInputsAndEvidence(t *testing.T) {
	t.Parallel()
	service, landing, networks, digest := browserChoiceFixture(t)
	if _, _, err := service.Read(t.Context(), digest, "short", network.ID{}, 100); !errors.Is(err, ErrInvalidBrowserChoice) || landing.calls != 0 {
		t.Fatalf("invalid token reached storage: %v", err)
	}
	if _, _, err := service.Read(t.Context(), digest, browserChoiceTestToken, network.ID{}, 0); !errors.Is(err, ErrInvalidBrowserChoice) || landing.calls != 0 {
		t.Fatalf("invalid page bound reached storage: %v", err)
	}
	networks.value.Networks = nil
	if _, _, err := service.Read(t.Context(), digest, browserChoiceTestToken, network.ID{}, 100); !errors.Is(err, ErrBrowserChoiceUnavailable) {
		t.Fatalf("malformed choice evidence accepted: %v", err)
	}
}

func browserChoiceFixture(t *testing.T) (
	*BrowserChoiceService, *browserLandingFake, *browserNetworkChoicesFake,
	accountsession.Digest,
) {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	intentID, err := enrollment.ParseBrowserIntentID("01890f00-0000-7000-8000-000000016301")
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	if err != nil {
		t.Fatal(err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000203")
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := accountsession.NewDigestKeyID("session-v1")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := accountsession.NewDigest(keyID, [32]byte{0: 1})
	if err != nil {
		t.Fatal(err)
	}
	landing := &browserLandingFake{
		value: enrollment.BrowserIntentLanding{
			IntentID: intentID, State: "pending", Hostname: "node-one.example",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		found: true,
	}
	networks := &browserNetworkChoicesFake{
		value: enrollment.BrowserEnrollmentChoices{
			WorkspaceID: workspaceID,
			Networks: []enrollment.BrowserEnrollmentNetworkChoice{
				{NetworkID: networkID, DisplayName: "Owned Network"},
			},
		},
		found: true,
	}
	service, err := NewBrowserChoiceService(landing, networks, deploymentID, 1)
	if err != nil {
		t.Fatal(err)
	}
	return service, landing, networks, digest
}
