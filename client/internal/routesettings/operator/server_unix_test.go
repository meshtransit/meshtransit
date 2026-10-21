//go:build linux || darwin

package operator

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/routesettings"
)

const (
	operatorsGID = 403
	meshdUID     = 410
)

// fakeHost is the server's view of the host: who connects, who is in the
// group, and the settings file.
type fakeHost struct {
	mu       sync.Mutex
	uid      uint32
	members  map[uint32]bool
	groupErr error
	settings routesettings.Settings
	loadErr  error
	saves    int
}

func (h *fakeHost) peerUID(*net.UnixConn) (uint32, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.uid, nil
}

func (h *fakeHost) inGroup(uid, gid uint32) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if gid != operatorsGID {
		return false, errors.New("asked about another group")
	}
	return h.members[uid], h.groupErr
}

func (h *fakeHost) load(string) (routesettings.Settings, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.settings, h.loadErr
}

func (h *fakeHost) update(
	_ string,
	change func(routesettings.Settings, error) (routesettings.Settings, error),
) (routesettings.Settings, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	next, err := change(h.settings, h.loadErr)
	if err != nil {
		return routesettings.Settings{}, err
	}
	h.settings = next
	h.saves++
	return next, nil
}

func (h *fakeHost) snapshot() (routesettings.Settings, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.settings, h.saves
}

// serveFake runs a server over host on a fresh socket and returns its path.
func serveFake(t *testing.T, host *fakeHost) string {
	t.Helper()
	// A short directory: Unix socket paths are limited to about 100 bytes,
	// which t.TempDir's names can pass on macOS.
	directory, err := os.MkdirTemp("", "op") //nolint:usetesting // see above
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "s")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerOptions{
		SettingsPath: "/routes.json", GroupID: operatorsGID, DeniedUIDs: []uint32{meshdUID},
	})
	if err != nil {
		t.Fatal(err)
	}
	server.peerUID, server.inGroup, server.load, server.update = host.peerUID, host.inGroup, host.load, host.update
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Serve() = %v, want context.Canceled", err)
		}
	})
	return path
}

func rootSettings() routesettings.Settings {
	return routesettings.Settings{
		RouterMode:      true,
		AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		ExitMode:        true,
		ExitUse:         "World",
	}
}

func refusal(t *testing.T, err error) ErrorCode {
	t.Helper()
	var refused *Error
	if !errors.As(err, &refused) {
		t.Fatalf("error = %v, want a refusal", err)
	}
	return refused.Code
}

func TestAnOperatorChangesOnlyTheirChoices(t *testing.T) {
	t.Parallel()
	host := &fakeHost{uid: 501, members: map[uint32]bool{501: true}, settings: rootSettings()}
	path := serveFake(t, host)

	for _, request := range []Request{
		{Command: CommandExitUse, ExitUse: routesettings.ExitUseAuto},
		{Command: CommandAccept, On: true},
		{Command: CommandExitAllowLAN, On: true},
	} {
		if _, err := Do(t.Context(), path, request); err != nil {
			t.Fatalf("%s: %v", request.Command, err)
		}
	}
	choices, err := Do(t.Context(), path, Request{Command: CommandShow})
	if err != nil {
		t.Fatal(err)
	}
	want := Choices{AcceptRoutes: true, ExitUse: routesettings.ExitUseAuto, ExitAllowLAN: true, Operators: true}
	if choices != want {
		t.Fatalf("choices = %+v, want %+v", choices, want)
	}
	settings, saves := host.snapshot()
	if saves != 3 || !settings.RouterMode || !settings.ExitMode || len(settings.AdvertiseRoutes) != 1 {
		t.Fatalf("root's settings changed: %+v after %d saves", settings, saves)
	}
	if _, err := Do(t.Context(), path, Request{Command: CommandExitUse, ExitUse: "off"}); err != nil {
		t.Fatal(err)
	}
	if settings, _ := host.snapshot(); settings.ExitUse != "" {
		t.Fatalf("exit-use off left %q", settings.ExitUse)
	}
}

func TestOthersThanOperatorsAreRefused(t *testing.T) {
	t.Parallel()
	host := &fakeHost{uid: 502, members: map[uint32]bool{501: true}, settings: rootSettings()}
	path := serveFake(t, host)

	for _, request := range []Request{{Command: CommandShow}, {Command: CommandExitUse, ExitUse: ""}} {
		_, err := Do(t.Context(), path, request)
		if code := refusal(t, err); code != CodeNotPermitted {
			t.Fatalf("%s by a non-member: %s, want %s", request.Command, code, CodeNotPermitted)
		}
	}
	host.mu.Lock()
	host.uid, host.members, host.groupErr = 501, map[uint32]bool{501: true}, errors.New("directory down")
	host.mu.Unlock()
	_, err := Do(t.Context(), path, Request{Command: CommandExitUse, ExitUse: ""})
	if code := refusal(t, err); code != CodeNotPermitted {
		t.Fatalf("with the groups unknown: %s, want %s", code, CodeNotPermitted)
	}
	if settings, saves := host.snapshot(); saves != 0 || settings.ExitUse != "World" {
		t.Fatalf("a refused caller changed the settings: %+v", settings)
	}
}

func TestRootTakesTheChoicesBack(t *testing.T) {
	t.Parallel()
	settings := rootSettings()
	settings.OperatorsOff = true
	host := &fakeHost{uid: 501, members: map[uint32]bool{501: true}, settings: settings}
	path := serveFake(t, host)

	_, err := Do(t.Context(), path, Request{Command: CommandExitUse, ExitUse: ""})
	if code := refusal(t, err); code != CodeOperatorsOff {
		t.Fatalf("change with operators off: %s, want %s", code, CodeOperatorsOff)
	}
	choices, err := Do(t.Context(), path, Request{Command: CommandShow})
	if err != nil || choices.Operators || choices.ExitUse != "World" {
		t.Fatalf("show with operators off = %+v, %v", choices, err)
	}
	host.mu.Lock()
	host.uid = 0
	host.mu.Unlock()
	if choices, err := Do(t.Context(), path, Request{Command: CommandExitUse, ExitUse: ""}); err != nil ||
		choices.ExitUse != "" {
		t.Fatalf("root's change = %+v, %v", choices, err)
	}
}

func TestBadRequestsChangeNothing(t *testing.T) {
	t.Parallel()
	host := &fakeHost{uid: 501, members: map[uint32]bool{501: true}, settings: rootSettings()}
	path := serveFake(t, host)

	_, err := Do(t.Context(), path, Request{Command: CommandExitUse, ExitUse: " padded"})
	if code := refusal(t, err); code != CodeInvalidValue {
		t.Fatalf("bad pool: %s, want %s", code, CodeInvalidValue)
	}
	_, err = Do(t.Context(), path, Request{Command: "exit-mode", On: true})
	if code := refusal(t, err); code != CodeInvalidRequest {
		t.Fatalf("root's command: %s, want %s", code, CodeInvalidRequest)
	}
	for _, raw := range []string{
		`{"version":1,"command":"accept","on":true,"router_mode":true}` + "\n",
		`{"version":2,"command":"show"}` + "\n",
		`{"version":1,"command":"show"}{}` + "\n",
		"not json\n",
		`{"version":1,"command":"exit-use","exit_use":"` + strings.Repeat("x", maxMessageBytes) + `"}` + "\n",
	} {
		if response := rawExchange(t, path, raw); response.OK || response.Error != CodeInvalidRequest {
			t.Errorf("%.40q = %+v, want %s", raw, response, CodeInvalidRequest)
		}
	}
	if settings, saves := host.snapshot(); saves != 0 || !settings.RouterMode {
		t.Fatalf("a bad request changed the settings: %+v", settings)
	}
}

func TestAnUnreadableFileIsRootsToFix(t *testing.T) {
	t.Parallel()
	host := &fakeHost{
		uid: 501, members: map[uint32]bool{501: true},
		loadErr: routesettings.ErrUnsafeFile,
	}
	path := serveFake(t, host)
	_, err := Do(t.Context(), path, Request{Command: CommandAccept, On: true})
	if code := refusal(t, err); code != CodeUnavailable {
		t.Fatalf("unsafe file: %s, want %s", code, CodeUnavailable)
	}
	if _, saves := host.snapshot(); saves != 0 {
		t.Fatal("an operator started an unsafe file over")
	}
}

func TestDoStopsWithItsContext(t *testing.T) {
	t.Parallel()
	directory, err := os.MkdirTemp("", "op") //nolint:usetesting // a short socket path, as in serveFake
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "s")
	// A listener that never answers.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := Do(ctx, path, Request{Command: CommandShow}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Do() = %v, want the context's deadline", err)
	}
}

func TestNewServerNeedsAPathAndAGroup(t *testing.T) {
	t.Parallel()
	if _, err := NewServer(ServerOptions{GroupID: operatorsGID}); err == nil {
		t.Error("a server without a settings path was made")
	}
	if _, err := NewServer(ServerOptions{SettingsPath: "/routes.json"}); err == nil {
		t.Error("a server with group 0 (wheel) was made")
	}
}

// rawExchange writes raw to the socket and reads the response.
func rawExchange(t *testing.T, path, raw string) Response {
	t.Helper()
	connection, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := decode(connection, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestMeshdNeverChangesTheChoicesEvenInTheGroup(t *testing.T) {
	t.Parallel()
	host := &fakeHost{uid: meshdUID, members: map[uint32]bool{meshdUID: true}, settings: rootSettings()}
	path := serveFake(t, host)
	_, err := Do(t.Context(), path, Request{Command: CommandExitUse, ExitUse: ""})
	if code := refusal(t, err); code != CodeNotPermitted {
		t.Fatalf("meshd's change: %s, want %s", code, CodeNotPermitted)
	}
	if settings, saves := host.snapshot(); saves != 0 || settings.ExitUse != "World" {
		t.Fatalf("meshd changed the settings: %+v", settings)
	}
}

func TestAcceptDoesNotTurnOnRootsPublicRoutes(t *testing.T) {
	t.Parallel()
	settings := rootSettings()
	settings.AcceptPublicRoutes = true
	host := &fakeHost{uid: 501, members: map[uint32]bool{501: true}, settings: settings}
	path := serveFake(t, host)
	_, err := Do(t.Context(), path, Request{Command: CommandAccept, On: true})
	if code := refusal(t, err); code != CodeRootSetting {
		t.Fatalf("accept with root's public routes: %s, want %s", code, CodeRootSetting)
	}
	// Turning it off is always the operator's.
	if choices, err := Do(t.Context(), path, Request{Command: CommandAccept}); err != nil || choices.AcceptRoutes {
		t.Fatalf("accept off = %+v, %v", choices, err)
	}
}

func TestUserInGroupAsksTheSystem(t *testing.T) {
	t.Parallel()
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // IDs fit in 32 bits
	if member, err := UserInGroup(uid, gid); err != nil || !member {
		t.Fatalf("UserInGroup(own uid, own primary group) = %v, %v", member, err)
	}
	if member, err := UserInGroup(uid, 0x7ffffff0); err != nil || member {
		t.Fatalf("UserInGroup(own uid, a group nobody has) = %v, %v", member, err)
	}
}

func TestDoReportsANoSocketAsUnreachable(t *testing.T) {
	t.Parallel()
	_, err := Do(t.Context(), filepath.Join(t.TempDir(), "none"), Request{Command: CommandShow})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Do() = %v, want ErrUnreachable", err)
	}
}
