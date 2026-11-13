package localapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/routesettings"
)

// memoryRouteSettings is a route settings file in memory, read and changed
// under one lock as routesettings.Update does.
type memoryRouteSettings struct {
	mu       sync.Mutex
	settings routesettings.Settings
	loadErr  error
	// beforeChange runs under the lock before the change, as another
	// writer that wrote just before it.
	beforeChange func(*routesettings.Settings)
	// updates counts the locked changes started.
	updates int
}

func (m *memoryRouteSettings) load(string) (routesettings.Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings, m.loadErr
}

func (m *memoryRouteSettings) update(
	_ string, change func(routesettings.Settings, error) (routesettings.Settings, error),
) (routesettings.Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates++
	if m.beforeChange != nil {
		m.beforeChange(&m.settings)
	}
	changed, err := change(m.settings, m.loadErr)
	if err != nil {
		return routesettings.Settings{}, err
	}
	m.settings = changed
	return changed.Canonical(), nil
}

func (m *memoryRouteSettings) updateCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.updates
}

func (m *memoryRouteSettings) current() routesettings.Settings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings
}

func newRouteChoicesServer(t *testing.T, file *memoryRouteSettings, writable bool) *Server {
	t.Helper()
	server, _ := newTestServerWithDaemon(t, Options{AllowedUIDs: []uint32{testUID}}, daemon.Options{
		RouteSettingsPath: "routes.json", LoadRouteSettings: file.load, UpdateRouteSettings: file.update,
		RouteChoicesWritable: writable,
	})
	return server
}

func routeChoicesRequest(t *testing.T, server *Server, method, body string, administrator bool) (
	int, string, routeChoicesResponse,
) {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), method, "/v1/route-choices", bytes.NewBufferString(body))
	request = request.WithContext(contextWithPeer(request.Context(), peerIdentity{
		uid: testUID, isPresent: true, isVerified: true, administrator: administrator,
	}))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	var decoded routeChoicesResponse
	if response.Code == http.StatusOK {
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("decoding %s: %v", response.Body.String(), err)
		}
	}
	return response.Code, response.Body.String(), decoded
}

func TestRouteChoices_ReadShowsChoicesAndWhoMayChange(t *testing.T) {
	t.Parallel()
	file := &memoryRouteSettings{settings: routesettings.Settings{
		AcceptRoutes: true, ExitUse: "World", ExitAllowLAN: true, ExitMode: true, OperatorsOn: true,
	}}
	server := newRouteChoicesServer(t, file, true)
	code, body, choices := routeChoicesRequest(t, server, http.MethodGet, "", false)
	if code != http.StatusOK || !choices.AcceptRoutes || choices.ExitUse != "World" || !choices.ExitAllowLAN ||
		!choices.Operators || !choices.CanChange {
		t.Fatalf("GET = %d %s", code, body)
	}
	if strings.Contains(body, "exit_mode") {
		t.Fatalf("GET shows root's settings: %s", body)
	}
	file.settings.OperatorsOn, file.settings.OperatorsOff = false, true
	if _, body, choices := routeChoicesRequest(t, server, http.MethodGet, "", false); choices.Operators ||
		choices.CanChange {
		t.Fatalf("operator with operators off = %s", body)
	}
	if _, body, choices := routeChoicesRequest(t, server, http.MethodGet, "", true); !choices.CanChange {
		t.Fatalf("administrator with operators off = %s", body)
	}
	readOnly := newRouteChoicesServer(t, &memoryRouteSettings{}, false)
	if _, body, choices := routeChoicesRequest(t, readOnly, http.MethodGet, "", true); choices.CanChange {
		t.Fatalf("read-only host = %s", body)
	}
}

func TestRouteChoices_OperatorChangesOnlyWhileRootLets(t *testing.T) {
	t.Parallel()
	file := &memoryRouteSettings{settings: routesettings.Settings{OperatorsOn: true, ExitMode: true}}
	server := newRouteChoicesServer(t, file, true)
	code, body, choices := routeChoicesRequest(t, server, http.MethodPatch,
		`{"exit_use":"auto","accept_routes":true,"exit_allow_lan":true}`, false)
	if code != http.StatusOK || choices.ExitUse != "auto" || !choices.AcceptRoutes || !choices.ExitAllowLAN {
		t.Fatalf("operator PATCH = %d %s", code, body)
	}
	if saved := file.current(); saved.ExitUse != "auto" || !saved.ExitMode || !saved.OperatorsOn {
		t.Fatalf("saved = %+v", saved)
	}
	if code, _, choices := routeChoicesRequest(t, server, http.MethodPatch, `{"exit_use":"off"}`, false); code !=
		http.StatusOK || choices.ExitUse != "" {
		t.Fatalf("exit_use off = %d %+v", code, choices)
	}
	// Root takes the choices back just before the change: read again
	// under the lock, it is refused.
	file.beforeChange = func(settings *routesettings.Settings) { settings.OperatorsOff = true }
	code, body, _ = routeChoicesRequest(t, server, http.MethodPatch, `{"exit_use":"auto"}`, false)
	if code != http.StatusForbidden || !strings.Contains(body, "operators_off") || file.current().ExitUse != "" {
		t.Fatalf("operator PATCH while root takes them back = %d %s, %+v", code, body, file.current())
	}
	file.beforeChange = nil
	code, body, choices = routeChoicesRequest(t, server, http.MethodPatch, `{"exit_use":"auto"}`, true)
	if code != http.StatusOK || choices.ExitUse != "auto" {
		t.Fatalf("administrator PATCH with operators off = %d %s", code, body)
	}
}

func TestRouteChoices_OperatorsOffByDefaultOnAMissingFile(t *testing.T) {
	t.Parallel()
	file := &memoryRouteSettings{}
	server := newRouteChoicesServer(t, file, true)
	code, body, _ := routeChoicesRequest(t, server, http.MethodPatch, `{"accept_routes":true}`, false)
	if file.current().OperatorsAllowed() {
		if code != http.StatusOK {
			t.Fatalf("operators on by default, PATCH = %d %s", code, body)
		}
		return
	}
	if code != http.StatusForbidden || !strings.Contains(body, "operators_off") || file.current().AcceptRoutes {
		t.Fatalf("operators off by default, PATCH = %d %s", code, body)
	}
}

func TestRouteChoices_Refusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		file     *memoryRouteSettings
		writable bool
		body     string
		code     int
		error    string
	}{
		{
			"read-only host", &memoryRouteSettings{}, false, `{"exit_use":"auto"}`, http.StatusMethodNotAllowed,
			"route_choices_read_only",
		},
		{
			"unsafe file", &memoryRouteSettings{loadErr: routesettings.ErrUnsafeFile}, true, `{"exit_use":"auto"}`,
			http.StatusServiceUnavailable, "route_settings_unavailable",
		},
		{"accept with root's accept-public", &memoryRouteSettings{settings: routesettings.Settings{
			AcceptPublicRoutes: true, OperatorsOn: true,
		}}, true, `{"accept_routes":true}`, http.StatusConflict, "root_setting"},
		{
			"bad pool name", &memoryRouteSettings{settings: routesettings.Settings{OperatorsOn: true}}, true,
			`{"exit_use":" World"}`, http.StatusBadRequest, "invalid_route_choice",
		},
		{"no choice", &memoryRouteSettings{}, true, `{}`, http.StatusBadRequest, "invalid_route_choice"},
		{"unknown field", &memoryRouteSettings{}, true, `{"exit_mode":true}`, http.StatusBadRequest, "invalid_json"},
		{
			"too large", &memoryRouteSettings{}, true, `{"exit_use":"` + strings.Repeat("a", 5000) + `"}`,
			http.StatusBadRequest, "invalid_json",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			before := test.file.current()
			server := newRouteChoicesServer(t, test.file, test.writable)
			code, body, _ := routeChoicesRequest(t, server, http.MethodPatch, test.body, true)
			if code != test.code || !strings.Contains(body, test.error) {
				t.Fatalf("PATCH = %d %s, want %d %s", code, body, test.code, test.error)
			}
			if after := test.file.current(); after.ExitUse != before.ExitUse ||
				after.AcceptRoutes != before.AcceptRoutes {
				t.Fatalf("refused PATCH changed the file: %+v", after)
			}
		})
	}
	server := newRouteChoicesServer(t, &memoryRouteSettings{loadErr: errors.New("broken")}, true)
	if code, body, _ := routeChoicesRequest(t, server, http.MethodGet, "", false); code !=
		http.StatusServiceUnavailable || strings.Contains(body, "broken") {
		t.Fatalf("GET of a broken file = %d %s", code, body)
	}
	if code, _, _ := routeChoicesRequest(t, server, http.MethodPost, `{}`, true); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", code)
	}
}

// With the choices root's, an operator's change neither locks nor writes:
// meshd touches nothing on disk for it (review H2).
func TestRouteChoices_OperatorRefusedTouchesNothing(t *testing.T) {
	t.Parallel()
	file := &memoryRouteSettings{settings: routesettings.Settings{OperatorsOff: true}}
	server := newRouteChoicesServer(t, file, true)
	code, body, _ := routeChoicesRequest(t, server, http.MethodPatch, `{"exit_use":"auto"}`, false)
	if code != http.StatusForbidden || !strings.Contains(body, "operators_off") || file.updateCount() != 0 {
		t.Fatalf("operator PATCH with operators off = %d %s, %d updates", code, body, file.updateCount())
	}
	broken := &memoryRouteSettings{loadErr: routesettings.ErrUnsafeFile}
	server = newRouteChoicesServer(t, broken, true)
	if code, _, _ := routeChoicesRequest(t, server, http.MethodPatch, `{"exit_use":"auto"}`, false); code !=
		http.StatusServiceUnavailable || broken.updateCount() != 0 {
		t.Fatalf("operator PATCH of an unsafe file = %d, %d updates", code, broken.updateCount())
	}
}

func TestRouteChoices_RefusesEmptyAndManagedPools(t *testing.T) {
	t.Parallel()
	file := &memoryRouteSettings{settings: routesettings.Settings{OperatorsOn: true, ExitUse: "World"}}
	server := newRouteChoicesServer(t, file, true)
	for _, body := range []string{`{"exit_use":""}`, `{"exit_use":"managed"}`} {
		if code, answer, _ := routeChoicesRequest(t, server, http.MethodPatch, body, true); code !=
			http.StatusBadRequest || !strings.Contains(answer, "invalid_route_choice") ||
			file.current().ExitUse != "World" {
			t.Fatalf("PATCH %s = %d %s", body, code, answer)
		}
	}
}

func TestRouteChoices_RateLimited(t *testing.T) {
	t.Parallel()
	server := newRouteChoicesServer(t, &memoryRouteSettings{}, true)
	limited := false
	for range routeChoiceBurst + 5 {
		if code, _, _ := routeChoicesRequest(t, server, http.MethodGet, "", false); code == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Fatal("a burst of reads was never limited")
	}
}

func TestRouteChoices_ReadOnlyNamesTheAllowedMethod(t *testing.T) {
	t.Parallel()
	server := newRouteChoicesServer(t, &memoryRouteSettings{}, false)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/v1/route-choices",
		strings.NewReader(`{"exit_use":"auto"}`))
	request = request.WithContext(contextWithPeer(request.Context(), peerIdentity{
		uid: testUID, isPresent: true, isVerified: true, administrator: true,
	}))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("read-only PATCH = %d, Allow %q", response.Code, response.Header().Get("Allow"))
	}
}

// One caller's burst does not limit another (review R4).
func TestCallerLimitsAreSeparate(t *testing.T) {
	t.Parallel()
	limits := newCallerLimits(0, 2)
	first, second := peerIdentity{userSID: "S-1-5-21-1"}, peerIdentity{uid: 1001}
	answers := []bool{limits.allow(first), limits.allow(first), limits.allow(first)}
	if !answers[0] || !answers[1] || answers[2] {
		t.Fatalf("the first caller's burst = %v", answers)
	}
	if !limits.allow(second) {
		t.Fatal("the first caller's burst limited the second")
	}
}
