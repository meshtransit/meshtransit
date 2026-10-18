package devicelifetime_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/devicelifetime"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

var now = time.Date(2026, time.October, 18, 1, 0, 0, 0, time.UTC)

func TestCommandValidation(t *testing.T) {
	t.Parallel()
	base := testCommand(t)
	for _, test := range []struct {
		name   string
		mutate func(*devicelifetime.Command)
		valid  bool
	}{
		{"one day", func(*devicelifetime.Command) {}, true},
		{"one hour", func(command *devicelifetime.Command) { command.Lifetime = time.Hour }, true},
		{"180 days", func(command *devicelifetime.Command) { command.Lifetime = 180 * 24 * time.Hour }, true},
		{"never", func(command *devicelifetime.Command) { command.Lifetime, command.NeverExpires = 0, true }, true},
		{"never with a lifetime", func(command *devicelifetime.Command) { command.NeverExpires = true }, false},
		{"below one hour", func(command *devicelifetime.Command) { command.Lifetime = time.Minute }, false},
		{"above 180 days", func(command *devicelifetime.Command) { command.Lifetime = 181 * 24 * time.Hour }, false},
		{"fraction of a second", func(command *devicelifetime.Command) { command.Lifetime += time.Millisecond }, false},
		{"no version", func(command *devicelifetime.Command) { command.ExpectedVersion = 0 }, false},
		{"no correlation", func(command *devicelifetime.Command) { command.CorrelationID = publicid.ID{} }, false},
	} {
		command := base
		test.mutate(&command)
		if got := command.IsValid(); got != test.valid {
			t.Errorf("%s: IsValid() = %v, want %v", test.name, got, test.valid)
		}
	}
}

func TestStateValidation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		state devicelifetime.State
		valid bool
	}{
		{"default", devicelifetime.State{Version: 1, Lifetime: 180 * 24 * time.Hour, Default: true}, true},
		{"chosen", devicelifetime.State{Version: 2, Lifetime: 7 * 24 * time.Hour}, true},
		{"never", devicelifetime.State{Version: 2, NeverExpires: true}, true},
		{"default of an older profile", devicelifetime.State{Version: 1, Lifetime: 30 * time.Minute, Default: true}, true},
		{"chosen below one hour", devicelifetime.State{Version: 2, Lifetime: 30 * time.Minute}, false},
		{"default without a lifetime", devicelifetime.State{Version: 1, Default: true}, false},
		{"never with a lifetime", devicelifetime.State{Version: 2, Lifetime: time.Hour, NeverExpires: true}, false},
		{"no version", devicelifetime.State{Lifetime: time.Hour}, false},
	} {
		if got := test.state.IsValid(); got != test.valid {
			t.Errorf("%s: IsValid() = %v, want %v", test.name, got, test.valid)
		}
	}
}

type fakeStore struct {
	state  devicelifetime.State
	result devicelifetime.Result
	err    error
	calls  int
}

func (store *fakeStore) Read(context.Context, accountsession.Session, network.Scope) (devicelifetime.State, error) {
	store.calls++
	return store.state, store.err
}

func (store *fakeStore) Update(context.Context, devicelifetime.Command) (devicelifetime.Result, error) {
	store.calls++
	return store.result, store.err
}

type fixedClock struct{ at time.Time }

func (clock fixedClock) Now() time.Time { return clock.at }

func TestServiceChecksReceipts(t *testing.T) {
	t.Parallel()
	command := testCommand(t)
	for _, test := range []struct {
		name   string
		result devicelifetime.Result
		want   error
	}{
		{"changed", devicelifetime.Result{State: devicelifetime.State{Version: 3, Lifetime: 24 * time.Hour}, Changed: true}, nil},
		{"unchanged", devicelifetime.Result{State: devicelifetime.State{Version: 2, Lifetime: 24 * time.Hour}}, nil},
		{"other lifetime", devicelifetime.Result{State: devicelifetime.State{Version: 3, Lifetime: time.Hour}, Changed: true},
			devicelifetime.ErrInvalid},
		{"changed without a new version", devicelifetime.Result{State: devicelifetime.State{Version: 2,
			Lifetime: 24 * time.Hour}, Changed: true}, devicelifetime.ErrInvalid},
		{"still the default", devicelifetime.Result{State: devicelifetime.State{Version: 2,
			Lifetime: 180 * 24 * time.Hour, Default: true}}, devicelifetime.ErrInvalid},
	} {
		service, err := devicelifetime.NewService(&fakeStore{result: test.result}, fixedClock{now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Update(context.Background(), command); !errors.Is(err, test.want) {
			t.Errorf("%s: Update() error = %v, want %v", test.name, err, test.want)
		}
	}
}

func TestServiceRefusesAnExpiredSessionBeforeTheStore(t *testing.T) {
	t.Parallel()
	command := testCommand(t)
	store := &fakeStore{}
	service, err := devicelifetime.NewService(store, fixedClock{now.Add(3 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Update(context.Background(), command); !errors.Is(err, devicelifetime.ErrForbidden) {
		t.Fatalf("Update() error = %v, want ErrForbidden", err)
	}
	if _, err := service.Read(context.Background(), command.Session, command.Scope); !errors.Is(err,
		devicelifetime.ErrForbidden) {
		t.Fatalf("Read() error = %v, want ErrForbidden", err)
	}
	if store.calls != 0 {
		t.Fatalf("store called %d times for an expired session", store.calls)
	}
}

func testCommand(t *testing.T) devicelifetime.Command {
	t.Helper()
	ids := make([]publicid.ID, 7)
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		ids[index] = id
	}
	session, err := accountsession.NewSession(accountsession.Params{
		ID: accountsession.ID(ids[0]), DeploymentID: deployment.ID(ids[1]), PrincipalID: identity.PrincipalID(ids[2]),
		IdentitySubjectID: accountsession.IdentitySubjectID(ids[3]), LoginWorkspaceID: workspace.ID(ids[4]),
		HasLoginWorkspace: true, AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test",
		AMR: []string{"mfa"}, Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspace.ID(ids[4]), network.ID(ids[5]))
	if err != nil {
		t.Fatal(err)
	}
	return devicelifetime.Command{Session: session, Scope: scope, ExpectedVersion: 2, Lifetime: 24 * time.Hour,
		CorrelationID: ids[6]}
}
