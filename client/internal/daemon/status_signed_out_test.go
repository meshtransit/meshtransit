package daemon

import (
	"strings"
	"testing"
)

// TD-CLI-102: status says why a machine is offline when it is signed out
// or down, and reports down.
func TestService_StatusExplainsSignedOutAndDown(t *testing.T) {
	t.Parallel()

	service, identities, _, first, _, _ := newRemovalService(t)
	if _, err := service.ActivateProfile(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := identities.SetSignedOut(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	status, err := service.Status(t.Context())
	if err != nil || status.Registration != RegistrationSignedOut || status.Disconnected ||
		!strings.Contains(status.CompatibilityNote, "meshctl login (without a key) signs it back in") {
		t.Fatalf("signed-out Status() = %+v, %v", status, err)
	}
	if _, err := service.profiles.SetDisconnected(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	status, err = service.Status(t.Context())
	if err != nil || !status.Disconnected || !strings.Contains(status.CompatibilityNote, "then meshctl up connects") {
		t.Fatalf("signed-out and down Status() = %+v, %v", status, err)
	}
	if _, err := identities.SetRegistration(t.Context(), first, "", true); err != nil {
		t.Fatal(err)
	}
	status, err = service.Status(t.Context())
	if err != nil || status.Registration != RegistrationRegistered ||
		status.CompatibilityNote != "disconnected (meshctl down): meshctl up connects" {
		t.Fatalf("down Status() = %+v, %v", status, err)
	}
}
