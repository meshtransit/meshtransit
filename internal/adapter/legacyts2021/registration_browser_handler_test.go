package legacyts2021

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/node"
)

type recordingBrowserRegistrationService struct {
	calls    int
	followup string
}

type recordingBrowserCompletionService struct {
	result registration.Result
	calls  int
}

func (service *recordingBrowserCompletionService) CompleteBrowser(
	_ context.Context, machine control.AuthenticatedMachine,
	nodeKey node.Key, hostname node.Hostname, followup string,
) (registration.Result, bool, error) {
	if machine.IsValid() && nodeKey.IsValid() && hostname.IsValid() &&
		followup == fixtureFollowupURL {
		service.calls++
		return service.result, true, nil
	}
	return registration.Result{}, false, nil
}

func (service *recordingBrowserRegistrationService) RegisterBrowser(
	_ context.Context, machine control.AuthenticatedMachine,
	nodeKey node.Key, hostname node.Hostname, followup string,
) (string, error) {
	if machine.IsValid() && nodeKey.IsValid() && hostname.IsValid() {
		service.calls++
	}
	service.followup = followup
	return fixtureFollowupURL, nil
}

func TestRegistrationHandlerRoutesBrowserInitialAndFollowup(t *testing.T) {
	t.Parallel()
	encoded, err := os.ReadFile("testdata/browser_registration_cap142_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture browserRegistrationFixture
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	credential := newRecordingRegistrationService(t)
	browser := &recordingBrowserRegistrationService{}
	ids := &fixedRegistrationIDGenerator{id: parseRegistrationID(t)}
	handler, err := NewCredentialRegistrationHandler(CredentialRegistrationHandlerOptions{
		Service: credential, Browser: browser, IDs: ids,
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Telemetry: controlTelemetryFixture(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	bound := authenticatedHandler(t, handler)
	for index, body := range []json.RawMessage{fixture.InitialRequest, fixture.FollowupRequest} {
		response := serveRegistration(t, bound, http.MethodPost,
			credentialRegistrationPath, string(body))
		if response.Code != http.StatusOK ||
			response.Body.String() != "{\"MachineAuthorized\":false,\"AuthURL\":\""+fixtureFollowupURL+"\"}\n" {
			t.Fatalf("browser response %d = (%d, %q)", index, response.Code, response.Body.String())
		}
	}
	if browser.calls != 2 || browser.followup != fixtureFollowupURL ||
		credential.calls.Load() != 0 || ids.calls.Load() != 0 {
		t.Fatal("browser request crossed credential route or lost follow-up URL")
	}
	metrics := gatherControlMetrics(t, handler.telemetry)
	if !strings.Contains(metrics,
		`meshtransit_control_registration_requests_total{result="pending"} 2`) {
		t.Fatal("browser pending result was not counted")
	}
}

func TestRegistrationHandlerAuthorizesCommittedBrowserFollowup(t *testing.T) {
	t.Parallel()
	encoded, err := os.ReadFile("testdata/browser_registration_cap142_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture browserRegistrationFixture
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	credential := newRecordingRegistrationService(t)
	browser := &recordingBrowserRegistrationService{}
	completion := &recordingBrowserCompletionService{result: credential.result}
	handler, err := NewCredentialRegistrationHandler(CredentialRegistrationHandlerOptions{
		Service: credential, Browser: browser, Completion: completion,
		IDs:       &fixedRegistrationIDGenerator{id: parseRegistrationID(t)},
		Logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Telemetry: controlTelemetryFixture(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	bound := authenticatedHandler(t, handler)
	initial := serveRegistration(t, bound, http.MethodPost,
		credentialRegistrationPath, string(fixture.InitialRequest))
	if initial.Code != http.StatusOK ||
		!strings.Contains(initial.Body.String(), `"MachineAuthorized":false`) {
		t.Fatalf("initial browser response = (%d, %q)", initial.Code, initial.Body.String())
	}
	followup := serveRegistration(t, bound, http.MethodPost,
		credentialRegistrationPath, string(fixture.FollowupRequest))
	if followup.Code != http.StatusOK ||
		followup.Body.String() != "{\"MachineAuthorized\":true}\n" ||
		completion.calls != 1 || browser.calls != 1 || credential.calls.Load() != 0 {
		t.Fatalf("approved browser response = (%d, %q), completion=%d browser=%d",
			followup.Code, followup.Body.String(), completion.calls, browser.calls)
	}
}
