package mobile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/dataplane"
)

func TestEngineSubnetRouteSettings(t *testing.T) {
	t.Parallel()
	engine := &Engine{routeSettings: filepath.Join(t.TempDir(), routeSettingsFile)}
	if accepted, err := engine.AcceptsSubnetRoutes(); err != nil || accepted {
		t.Fatalf("AcceptsSubnetRoutes() before any setting = %t, %v", accepted, err)
	}
	// Public routes need accept: alone they stay off.
	if err := engine.SetSubnetRoutes(false, true); err != nil {
		t.Fatal(err)
	}
	if public, err := engine.AcceptsPublicSubnetRoutes(); err != nil || public {
		t.Fatalf("AcceptsPublicSubnetRoutes() without accept = %t, %v", public, err)
	}
	if err := engine.SetSubnetRoutes(true, true); err != nil {
		t.Fatal(err)
	}
	accepted, err := engine.AcceptsSubnetRoutes()
	public, publicErr := engine.AcceptsPublicSubnetRoutes()
	if err != nil || publicErr != nil || !accepted || !public {
		t.Fatalf("after SetSubnetRoutes(true, true) = %t %t, %v %v", accepted, public, err, publicErr)
	}
	settings, err := loadRouteSettings(engine.routeSettings)
	if err != nil || !settings.AcceptRoutes || !settings.AcceptPublicRoutes {
		t.Fatalf("file = %+v, %v", settings, err)
	}

	if err := os.WriteFile(engine.routeSettings, []byte(`{"accept_routes":"yes"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.AcceptsSubnetRoutes(); err == nil {
		t.Fatal("a malformed file read as valid")
	}
	// A change repairs it.
	if err := engine.SetSubnetRoutes(true, false); err != nil {
		t.Fatal(err)
	}
	if accepted, err := engine.AcceptsSubnetRoutes(); err != nil || !accepted {
		t.Fatalf("after repair = %t, %v", accepted, err)
	}
	var closed *Engine
	if err := closed.SetSubnetRoutes(true, false); !errors.Is(err, errEngineClosed) {
		t.Fatalf("nil engine error = %v", err)
	}
}

func TestStatusShowsSubnetRoutes(t *testing.T) {
	t.Parallel()
	current := daemon.Status{
		SubnetRoutes: dataplane.SubnetRouteStatus{Requested: 2, Installed: 1, RefusedTotal: 1, LocalConflict: true},
		RouteSites: []daemon.RouteSiteView{
			{Ref: "prod", Router: "01a156d6", RouterName: "prod-1", Via: "primary"},
			{Ref: "lab", Via: "none"},
		},
	}
	encoded, err := newStatus(true, current).marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"subnetRoutes":{"requested":2,"installed":1,"refused":1,"localConflict":true}`,
		`"sites":[{"site":"prod","router":"prod-1","via":"primary"},{"site":"lab","via":"none"}]`,
	} {
		if !strings.Contains(encoded, want) {
			t.Errorf("status %s lacks %s", encoded, want)
		}
	}
	if encoded, _ := newStatus(false, daemon.Status{}).marshal(); !strings.Contains(encoded, `"sites":[]`) {
		t.Errorf("empty status %s lacks an empty sites list", encoded)
	}
}
