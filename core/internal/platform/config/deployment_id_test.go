package config

import (
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/platform/app"
)

const (
	testDeploymentID  = "01995d00-0000-7000-8000-000000000001"
	otherDeploymentID = "01995d00-0000-7000-8000-000000000002"
)

// The install-wide ID fills a configured feature's own ID, never turns a
// feature on, and must agree with a feature's own ID.
func TestDeploymentIDDefault(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		values  map[string]string
		wantID  string
		wantNil bool
		wantErr string
	}{
		{name: "enabled worker takes the install ID", wantID: testDeploymentID, values: map[string]string{
			envDeploymentPublicID: testDeploymentID, envContractExpiryWorkerEnabled: "true"}},
		{name: "disabled worker stays off", wantNil: true, values: map[string]string{
			envDeploymentPublicID: testDeploymentID}},
		{name: "own ID equal to the install ID", wantID: testDeploymentID, values: map[string]string{
			envDeploymentPublicID: testDeploymentID, envContractExpiryWorkerEnabled: "true",
			envContractExpiryWorkerDeployment: testDeploymentID}},
		{name: "own ID differs", wantErr: envContractExpiryWorkerDeployment, values: map[string]string{
			envDeploymentPublicID: testDeploymentID, envContractExpiryWorkerEnabled: "true",
			envContractExpiryWorkerDeployment: otherDeploymentID}},
		{name: "invalid install ID", wantErr: envDeploymentPublicID, values: map[string]string{
			envDeploymentPublicID: "not-an-id", envContractExpiryWorkerEnabled: "true"}},
		{name: "own ID alone still works", wantID: otherDeploymentID, values: map[string]string{
			envContractExpiryWorkerEnabled: "true", envContractExpiryWorkerDeployment: otherDeploymentID}},
		{name: "disabled worker with its own ID", wantErr: envContractExpiryWorkerDeployment, values: map[string]string{
			envDeploymentPublicID: testDeploymentID, envContractExpiryWorkerDeployment: testDeploymentID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := loadContractExpiryWorkerConfig(mapLookup(test.values), app.RoleWorker)
			switch {
			case test.wantErr != "":
				if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("err = %v", err)
				}
			case err != nil:
				t.Fatal(err)
			case test.wantNil != (got == nil):
				t.Fatalf("config = %+v", got)
			case got != nil && got.DeploymentID.String() != test.wantID:
				t.Fatalf("ID = %s", got.DeploymentID)
			}
		})
	}
}

// The relay's ticket ID is never filled but must agree.
func TestRelayDeploymentIDMustAgree(t *testing.T) {
	t.Parallel()
	if err := requireSameDeploymentID(mapLookup(map[string]string{envDeploymentPublicID: testDeploymentID,
		envRelayDeploymentID: otherDeploymentID}), envRelayDeploymentID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("differs: %v", err)
	}
	for _, values := range []map[string]string{
		{envDeploymentPublicID: testDeploymentID},
		{envDeploymentPublicID: testDeploymentID, envRelayDeploymentID: testDeploymentID},
		{envRelayDeploymentID: otherDeploymentID},
	} {
		if err := requireSameDeploymentID(mapLookup(values), envRelayDeploymentID); err != nil {
			t.Fatalf("%v: %v", values, err)
		}
	}
	if id, err := loadInstallationID(mapLookup(map[string]string{envDeploymentPublicID: "x"})); err == nil || id != nil {
		t.Fatalf("invalid install ID: %v %v", id, err)
	}
}

// All-or-nothing groups and the relay's opt-in ticket ID stay off with the
// install ID alone.
func TestDeploymentIDTurnsNothingOn(t *testing.T) {
	t.Parallel()
	lookup := mapLookup(map[string]string{envDeploymentPublicID: testDeploymentID})
	if browser, err := loadBrowserRegistrationConfig(lookup); err != nil || browser != nil {
		t.Fatalf("browser registration: %+v, %v", browser, err)
	}
	if entitlement, err := loadDeploymentEntitlementConfig(lookup, app.RoleAPI); err != nil || entitlement != nil {
		t.Fatalf("entitlement: %+v, %v", entitlement, err)
	}
	if flow, err := loadFlowTicketConfig(lookup, app.RoleControl); err != nil || flow != nil {
		t.Fatalf("flow tickets: %+v, %v", flow, err)
	}
	// A configured group gets the ID: entitlement with its file set fails
	// on the installation key, not on the ID.
	partial := mapLookup(map[string]string{envDeploymentPublicID: testDeploymentID,
		envEntitlementFile: "/run/meshtransit/entitlement/entitlement.json"})
	_, err := loadDeploymentEntitlementConfig(partial, app.RoleAPI)
	if err == nil || strings.Contains(err.Error(), envEntitlementDeploymentID) ||
		!strings.Contains(err.Error(), envEntitlementInstallationKey) {
		t.Fatalf("the entitlement ID should be filled and the installation key missing: %v", err)
	}
}
