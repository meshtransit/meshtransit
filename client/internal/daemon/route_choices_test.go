package daemon

import (
	"errors"
	"testing"

	"meshtransit.net/client/internal/routesettings"
)

// routeChoicesService is a Service that writes its route settings in
// memory, as meshd does on Windows.
func routeChoicesService(t *testing.T) (*Service, *routesettings.Settings) {
	t.Helper()
	saved := &routesettings.Settings{}
	service := &Service{
		routeChoicesWritable: true,
		routeSettingsPath:    "routes.json",
		loadRouteSettings:    func(string) (routesettings.Settings, error) { return *saved, nil },
		updateRouteSettings: func(_ string, change func(routesettings.Settings, error) (routesettings.Settings, error),
		) (routesettings.Settings, error) {
			changed, err := change(*saved, nil)
			if err != nil {
				return routesettings.Settings{}, err
			}
			*saved = changed
			return changed, nil
		},
	}
	return service, saved
}

// TD-CLI-120: a pool the Network does not grant (a typo, another
// Network's pool) is refused before it is written, so it never drops the
// host's Internet traffic; a granted one, by reference or name, auto and
// off are taken. Before any map meshd cannot tell, and takes it: the kill
// switch then stays as designed (exit node design §6.4).
func TestChangeRouteChoicesRefusesAPoolNotGranted(t *testing.T) {
	t.Parallel()
	granted := []GrantedExitPool{
		{Ref: "pool-ref-1", Name: "World"}, {Ref: "pool-ref-2", Name: "Office"}, {Ref: "pool-ref-3", Name: "Office"},
	}
	for _, test := range []struct {
		name    string
		use     string
		known   bool
		refused bool
	}{
		{name: "not granted", use: "world-typo", known: true, refused: true},
		{name: "another case", use: "world", known: true, refused: true},
		{name: "by name", use: "World", known: true},
		{name: "by reference", use: "pool-ref-2", known: true},
		{name: "a name two pools share", use: "Office", known: true, refused: true},
		{name: "auto", use: routesettings.ExitUseAuto, known: true},
		{name: "off", use: routesettings.ExitUseOff, known: true},
		{name: "no map yet", use: "world-typo"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service, saved := routeChoicesService(t)
			if test.known {
				service.setExit(nil, exitSticky{}, nil, granted)
			}
			use := test.use
			_, err := service.ChangeRouteChoices(t.Context(), routesettings.ChoiceChange{ExitUse: &use}, true)
			if refused := errors.Is(err, ErrExitPoolNotGranted); refused != test.refused || (!test.refused && err != nil) {
				t.Fatalf("ChangeRouteChoices(%q) error = %v, refused want %v", test.use, err, test.refused)
			}
			if test.refused && saved.ExitUse != "" {
				t.Fatalf("saved exit use = %q after a refusal", saved.ExitUse)
			}
		})
	}
}

// After the session ends meshd no longer knows the grants: it takes the
// choice again rather than refuse it on an old map.
func TestChangeRouteChoicesChecksTheOperatorFirst(t *testing.T) {
	t.Parallel()
	service, saved := routeChoicesService(t)
	*saved = routesettings.WithOperators(*saved, false)
	service.setExit(nil, exitSticky{}, nil, []GrantedExitPool{})
	use := "World"
	if _, err := service.ChangeRouteChoices(t.Context(), routesettings.ChoiceChange{ExitUse: &use}, false); !errors.Is(
		err, ErrOperatorsOff,
	) {
		t.Fatalf("an operator's change while root keeps them = %v, want ErrOperatorsOff", err)
	}
}

func TestChangeRouteChoicesForgetsGrantsWithTheSession(t *testing.T) {
	t.Parallel()
	service, _ := routeChoicesService(t)
	service.setExit(nil, exitSticky{}, nil, []GrantedExitPool{{Ref: "r", Name: "World"}})
	service.clearExit()
	use := "Office"
	if _, err := service.ChangeRouteChoices(t.Context(), routesettings.ChoiceChange{ExitUse: &use}, true); err != nil {
		t.Fatalf("ChangeRouteChoices() error = %v", err)
	}
	if pools, known := service.GrantedExitPools(); known || pools != nil {
		t.Fatalf("GrantedExitPools() = %v, %v after the session", pools, known)
	}
}
