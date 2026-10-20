package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/underlay"
)

type fakeKeys struct {
	key []byte
	err error
}

func (keys fakeKeys) EnvelopeKey() ([]byte, error) {
	return bytes.Clone(keys.key), keys.err
}

func validKey() []byte { return bytes.Repeat([]byte{0x5a}, 32) }

type fakeTUN struct {
	mu        sync.Mutex
	addresses string
	routes    string
	dns       string
	mtu       int
	fd        int
	err       error
	next      func() (int, error) // when set, gives each call's descriptor
}

func (tun *fakeTUN) OpenTUN(addresses, routes, dns string, mtu int) (int, error) {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	tun.addresses, tun.routes, tun.dns, tun.mtu = addresses, routes, dns, mtu
	if tun.next != nil {
		return tun.next()
	}
	return tun.fd, tun.err
}

type recordingLogs struct {
	mu    sync.Mutex
	lines []string
}

func (logs *recordingLogs) Log(line string) {
	logs.mu.Lock()
	defer logs.mu.Unlock()
	logs.lines = append(logs.lines, line)
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, test := range map[string]struct {
		config   *Config
		wantPort int
		wantErr  bool
	}{
		"defaults":           {config: &Config{StateDir: dir, DeviceName: "pixel"}, wantPort: DefaultListenPort},
		"constructor":        {config: NewConfig(dir, " phone "), wantPort: DefaultListenPort},
		"custom port":        {config: &Config{StateDir: dir, DeviceName: "pixel", ListenPort: 50000}, wantPort: 50000},
		"nil":                {wantErr: true},
		"relative dir":       {config: &Config{StateDir: "state", DeviceName: "pixel"}, wantErr: true},
		"no name":            {config: &Config{StateDir: dir, DeviceName: "  "}, wantErr: true},
		"name with newline":  {config: &Config{StateDir: dir, DeviceName: "a\nb"}, wantErr: true},
		"name too long":      {config: &Config{StateDir: dir, DeviceName: strings.Repeat("a", maxDeviceNameBytes+1)}, wantErr: true},
		"privileged port":    {config: &Config{StateDir: dir, DeviceName: "pixel", ListenPort: 80}, wantErr: true},
		"port out of range":  {config: &Config{StateDir: dir, DeviceName: "pixel", ListenPort: 70000}, wantErr: true},
		"invalid name bytes": {config: &Config{StateDir: dir, DeviceName: "\xff"}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := test.config.validated()
			if test.wantErr {
				if !errors.Is(err, errInvalidConfig) {
					t.Fatalf("validated() error = %v, want errInvalidConfig", err)
				}
				return
			}
			if err != nil || got.ListenPort != test.wantPort || strings.TrimSpace(got.DeviceName) != got.DeviceName {
				t.Fatalf("validated() = %+v, %v", got, err)
			}
		})
	}
}

func TestStatusJSONModel(t *testing.T) {
	t.Parallel()
	encoded, err := newStatus(true, daemon.Status{
		State: "online", DataPlane: "encrypted_relay_ready", Registration: "registered",
		ControlSession: "synchronized", NetworkName: "Lab", PeerCount: 3,
		PeerPaths: dataplane.PeerPathSnapshot{DirectCount: 2, RelayCount: 1},
	}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
		t.Fatal(err)
	}
	paths, _ := decoded["paths"].(map[string]any)
	addresses, isList := decoded["selfAddresses"].([]any)
	if decoded["schemaVersion"] != float64(statusSchemaVersion) || decoded["running"] != true ||
		decoded["networkName"] != "Lab" || paths["direct"] != float64(2) || paths["relay"] != float64(1) ||
		!isList || len(addresses) != 0 || decoded["deviceExpiry"] != "unknown" ||
		decoded["deviceExpiresAt"] != nil {
		t.Fatalf("status JSON = %s", encoded)
	}
	expiry := time.Date(2026, time.November, 1, 10, 0, 0, 0, time.UTC)
	soon, err := newStatus(true, daemon.Status{DeviceExpiresAt: expiry, DeviceExpiry: daemon.DeviceExpirySoon}).marshal()
	if err != nil || !strings.Contains(soon, `"deviceExpiresAt":"2026-11-01T10:00:00Z","deviceExpiry":"soon"`) {
		t.Fatalf("expiring status JSON = %s, %v", soon, err)
	}
	never, err := newStatus(true, daemon.Status{
		DeviceExpiresAt: time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC),
		DeviceExpiry:    daemon.DeviceExpiryNever,
	}).marshal()
	if err != nil || strings.Contains(never, "deviceExpiresAt") || !strings.Contains(never, `"deviceExpiry":"never"`) {
		t.Fatalf("never-expiring status JSON = %s, %v", never, err)
	}
}

func newTestEngine(t *testing.T, dir string, keys KeyStore, logs LogSink) *Engine {
	t.Helper()
	engine, err := NewEngine(NewConfig(dir, "test-phone"), &fakeTUN{err: errors.New("no TUN in tests")}, keys, logs)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine
}

func TestNewEngineRejectsAMissingPlatform(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, test := range map[string]struct {
		tun  TunProvider
		keys KeyStore
	}{
		"no TUN provider": {keys: fakeKeys{key: validKey()}},
		"no key store":    {tun: &fakeTUN{}},
		"short key":       {tun: &fakeTUN{}, keys: fakeKeys{key: []byte{1, 2, 3}}},
		"key store error": {tun: &fakeTUN{}, keys: fakeKeys{err: errors.New("keystore locked")}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			engine, err := NewEngine(NewConfig(filepath.Join(dir, name), "phone"), test.tun, test.keys, nil)
			if !errors.Is(err, errPlatform) || engine != nil {
				t.Fatalf("NewEngine() = %v, %v; want errPlatform", engine, err)
			}
		})
	}
}

// TestEngineLifecycle is not parallel: it counts goroutines.
func TestEngineLifecycle(t *testing.T) {
	logs := &recordingLogs{}
	engine := newTestEngine(t, t.TempDir(), fakeKeys{key: validKey()}, logs)
	before := runtime.NumGoroutine()
	if err := engine.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := engine.Start(); !errors.Is(err, errEngineRunning) {
		t.Fatalf("second Start() error = %v, want errEngineRunning", err)
	}
	encoded, err := engine.StatusJSON()
	if err != nil {
		t.Fatalf("StatusJSON() error = %v", err)
	}
	var current status
	if err := json.Unmarshal([]byte(encoded), &current); err != nil || !current.Running ||
		current.SchemaVersion != statusSchemaVersion || current.ProfileCount != 0 {
		t.Fatalf("StatusJSON() = %s, %v", encoded, err)
	}
	for range 10 {
		engine.NetworkChanged() // never blocks
	}
	if err := engine.Stop(); err != nil || engine.Running() {
		t.Fatalf("Stop() error = %v, running = %t", err, engine.Running())
	}
	if err := engine.Stop(); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}
	waitForGoroutines(t, before)
	if err := engine.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err := engine.Start(); !errors.Is(err, errEngineClosed) {
		t.Fatalf("Start() after Close error = %v", err)
	}
	if _, err := engine.StatusJSON(); !errors.Is(err, errEngineClosed) {
		t.Fatalf("StatusJSON() after Close error = %v", err)
	}
	if _, err := engine.CreateProfile("lab", "https://control.example"); !errors.Is(err, errEngineClosed) {
		t.Fatalf("CreateProfile() after Close error = %v", err)
	}
}

func TestEngineKeepsProfilesAcrossRestarts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := newTestEngine(t, dir, fakeKeys{key: validKey()}, nil)
	id, err := first.CreateProfile("lab", "https://control.example")
	if err != nil || id == "" {
		t.Fatalf("CreateProfile() = %q, %v", id, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := newTestEngine(t, dir, fakeKeys{key: validKey()}, nil)
	t.Cleanup(func() { _ = second.Close() })
	encoded, err := second.StatusJSON()
	if err != nil {
		t.Fatal(err)
	}
	var current status
	if err := json.Unmarshal([]byte(encoded), &current); err != nil || current.ProfileCount != 1 ||
		current.ProfileID != id || current.Running {
		t.Fatalf("StatusJSON() after reopening = %s, %v", encoded, err)
	}
	if err := second.ActivateProfile(id); err != nil {
		t.Fatalf("ActivateProfile() error = %v", err)
	}
}

func TestAsyncLogDeliversOneRecordPerCall(t *testing.T) {
	t.Parallel()
	logs := &recordingLogs{}
	queue := newAsyncLog(logs)
	newLogger(queue).Info("started", "component", "test")
	queue.close()
	queue.close()                        // idempotent
	newLogger(queue).Info("after close") // dropped, not a panic
	logs.mu.Lock()
	defer logs.mu.Unlock()
	if len(logs.lines) != 1 || strings.HasSuffix(logs.lines[0], "\n") || !json.Valid([]byte(logs.lines[0])) {
		t.Fatalf("log lines = %q", logs.lines)
	}
}

// blockingLogs holds the first record until released, so the queue fills.
type blockingLogs struct {
	recordingLogs
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (logs *blockingLogs) Log(line string) {
	logs.once.Do(func() {
		close(logs.entered)
		<-logs.release
	})
	logs.recordingLogs.Log(line)
}

func TestAsyncLogDropsAndCountsWhenTheSinkIsSlow(t *testing.T) {
	t.Parallel()
	logs := &blockingLogs{entered: make(chan struct{}), release: make(chan struct{})}
	queue := newAsyncLog(logs)
	logger := newLogger(queue)
	logger.Info("first")
	<-logs.entered
	const extra = 10
	for range logQueueLength + extra {
		logger.Info("queued") // never blocks
	}
	logger.Info("last")
	close(logs.release)
	queue.close()
	logs.mu.Lock()
	defer logs.mu.Unlock()
	// first, the drop report, then the queue that was full.
	if len(logs.lines) != 1+1+logQueueLength {
		t.Fatalf("delivered %d records", len(logs.lines))
	}
	var report struct {
		Msg   string `json:"msg"`
		Count uint64 `json:"count"`
	}
	if err := json.Unmarshal([]byte(logs.lines[1]), &report); err != nil ||
		report.Msg != "log records dropped" || report.Count != extra+1 {
		t.Fatalf("drop report = %q, %v", logs.lines[1], err)
	}
}

func TestAsyncLogReportsDropsWhenItCloses(t *testing.T) {
	t.Parallel()
	logs := &recordingLogs{}
	queue := newAsyncLog(logs)
	queue.dropped.Add(3)
	queue.close()
	logs.mu.Lock()
	defer logs.mu.Unlock()
	if len(logs.lines) != 1 || !strings.Contains(logs.lines[0], `"count":3`) {
		t.Fatalf("log lines = %q", logs.lines)
	}
}

func TestAsyncLogSurvivesAPanickingSink(t *testing.T) {
	t.Parallel()
	queue := newAsyncLog(panickingLogs{})
	newLogger(queue).Info("one")
	newLogger(queue).Info("two")
	queue.close()
}

type panickingLogs struct{}

func (panickingLogs) Log(string) { panic("sink bug") }

func TestEngineRunningEndsWhenTheRuntimeStopsByItself(t *testing.T) {
	t.Parallel()
	for name, serve := range map[string]func(context.Context) error{
		"error": func(context.Context) error { return errors.New("data plane failed") },
		"panic": func(context.Context) error { panic("runtime bug") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			engine := newTestEngine(t, t.TempDir(), fakeKeys{key: validKey()}, nil)
			t.Cleanup(func() { _ = engine.Close() })
			engine.serve = serve
			if err := engine.Start(); err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			waitFor(t, func() bool { return !engine.Running() })
			if err := engine.Start(); err != nil { // a new run may start
				t.Fatalf("Start() after the runtime stopped error = %v", err)
			}
		})
	}
}

func TestEngineStopTimeoutKeepsTheRun(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t, t.TempDir(), fakeKeys{key: validKey()}, nil)
	release := make(chan struct{})
	engine.serve = func(context.Context) error {
		<-release // ignores cancellation, like a stuck platform call
		return nil
	}
	engine.stopWait = 20 * time.Millisecond
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	// Neither Stop nor Close may report success while the run uses the
	// stores and the TUN.
	if err := engine.Stop(); !errors.Is(err, errStopTimeout) || !engine.Running() {
		t.Fatalf("Stop() error = %v, running = %t; want errStopTimeout while running", err, engine.Running())
	}
	if err := engine.Close(); !errors.Is(err, errStopTimeout) {
		t.Fatalf("Close() error = %v, want errStopTimeout", err)
	}
	if _, err := engine.StatusJSON(); err != nil {
		t.Fatalf("StatusJSON() after a failed Close error = %v; the Engine must stay open", err)
	}
	close(release)
	if err := engine.Close(); err != nil {
		t.Fatalf("Close() after the runtime returned error = %v", err)
	}
}

func TestEngineSerializesConcurrentCalls(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t, t.TempDir(), fakeKeys{key: validKey()}, nil)
	engine.serve = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 20 {
				_ = engine.Start()
				_, _ = engine.StatusJSON()
				engine.NetworkChanged()
				_ = engine.Stop()
			}
		})
	}
	group.Wait()
	if err := engine.Close(); err != nil || engine.Running() {
		t.Fatalf("Close() error = %v, running = %t", err, engine.Running())
	}
}

type fakeProtector struct {
	mu    sync.Mutex
	fds   []int
	allow bool
}

func (protector *fakeProtector) Protect(fd int) bool {
	protector.mu.Lock()
	defer protector.mu.Unlock()
	protector.fds = append(protector.fds, fd)
	return protector.allow
}

// TestEngineSocketProtector is not parallel: the protector is process-wide.
func TestEngineSocketProtector(t *testing.T) {
	engine := newTestEngine(t, t.TempDir(), fakeKeys{key: validKey()}, nil)
	t.Cleanup(func() { _ = engine.Close() })
	engine.serve = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	allowing := &fakeProtector{allow: true}
	if err := engine.SetSocketProtector(allowing); err != nil || !underlay.Active() {
		t.Fatalf("SetSocketProtector() error = %v, active = %t", err, underlay.Active())
	}
	if err := underlay.Protect(7); err != nil || len(allowing.fds) != 1 || allowing.fds[0] != 7 {
		t.Fatalf("Protect(7) error = %v, platform saw %v", err, allowing.fds)
	}
	if err := engine.SetSocketProtector(&fakeProtector{}); err != nil {
		t.Fatal(err)
	}
	if err := underlay.Protect(7); !errors.Is(err, underlay.ErrNotProtected) {
		t.Fatalf("Protect() refused error = %v, want ErrNotProtected", err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	if err := engine.SetSocketProtector(allowing); !errors.Is(err, errEngineRunning) {
		t.Fatalf("SetSocketProtector() while running error = %v", err)
	}
	if err := engine.Close(); err != nil || underlay.Active() {
		t.Fatalf("Close() error = %v, protector still active = %t", err, underlay.Active())
	}
	if err := engine.SetSocketProtector(allowing); !errors.Is(err, errEngineClosed) {
		t.Fatalf("SetSocketProtector() after Close error = %v", err)
	}
}

// TestEngineProtectorOwnership is not parallel: the protector is process-wide.
func TestEngineProtectorOwnership(t *testing.T) {
	first := newTestEngine(t, t.TempDir(), fakeKeys{key: validKey()}, nil)
	second := newTestEngine(t, t.TempDir(), fakeKeys{key: validKey()}, nil)
	t.Cleanup(func() { _ = first.Close(); _ = second.Close() })
	if err := first.SetSocketProtector(&fakeProtector{allow: true}); err != nil {
		t.Fatal(err)
	}
	if err := second.SetSocketProtector(&fakeProtector{allow: true}); !errors.Is(err, errProtectorInUse) {
		t.Fatalf("second engine's SetSocketProtector() error = %v, want errProtectorInUse", err)
	}
	if err := second.SetSocketProtector(nil); err != nil || !underlay.Active() {
		t.Fatalf("second engine removed the first's protector: error = %v, active = %t", err, underlay.Active())
	}
	if err := second.Close(); err != nil || !underlay.Active() {
		t.Fatalf("closing the second engine removed the first's protector: error = %v", err)
	}
	if err := first.Close(); err != nil || underlay.Active() {
		t.Fatalf("closing the owner left the protector: error = %v, active = %t", err, underlay.Active())
	}
}

// TestEngineStartNeedsAProtectorWhereRequired is not parallel: it changes
// requireProtector.
func TestEngineStartNeedsAProtectorWhereRequired(t *testing.T) {
	requireProtector = true
	t.Cleanup(func() { requireProtector = false })
	engine := newTestEngine(t, t.TempDir(), fakeKeys{key: validKey()}, nil)
	t.Cleanup(func() { _ = engine.Close() })
	engine.serve = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	if err := engine.Start(); !errors.Is(err, errNoProtector) || engine.Running() {
		t.Fatalf("Start() without a protector error = %v, running = %t", err, engine.Running())
	}
	if err := engine.SetSocketProtector(&fakeProtector{allow: true}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatalf("Start() with a protector error = %v", err)
	}
}

func TestEngineCompleteLoginWithoutAPendingLogin(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t, t.TempDir(), fakeKeys{key: validKey()}, nil)
	t.Cleanup(func() { _ = engine.Close() })
	if registered, err := engine.CompleteLogin(); err == nil || errors.Is(err, errPanic) || registered {
		t.Fatalf("CompleteLogin() = %t, %v; want a plain error", registered, err)
	}
}

func TestEngineProbeControlNeedsAProfile(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t, t.TempDir(), fakeKeys{key: validKey()}, nil)
	t.Cleanup(func() { _ = engine.Close() })
	if fingerprint, err := engine.ProbeControl(); err == nil || errors.Is(err, errPanic) || fingerprint != "" {
		t.Fatalf("ProbeControl() = %q, %v; want a plain error", fingerprint, err)
	}
}

func TestRecoverPanicReturnsAnError(t *testing.T) {
	t.Parallel()
	call := func() (err error) {
		defer recoverPanic(&err)
		panic("boom")
	}
	if err := call(); !errors.Is(err, errPanic) {
		t.Fatalf("error = %v, want errPanic", err)
	}
}

// waitFor waits until done reports true.
func waitFor(t *testing.T, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached in 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitForGoroutines waits for the runtime's goroutines to exit after Stop.
func waitForGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > want {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines = %d after Stop, want at most %d", runtime.NumGoroutine(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestParseHostAddresses(t *testing.T) {
	t.Parallel()
	// Link-local and zoned addresses parse; the data plane drops them.
	addresses, networks, err := parseHostAddresses(" 10.63.186.255/20, 2001:db8::5/64,, 192.168.1.20 ")
	if err != nil || len(addresses) != 3 || addresses[0] != netip.MustParseAddr("10.63.186.255") {
		t.Fatalf("parseHostAddresses() = %v, %v", addresses, err)
	}
	if len(networks) != 2 || networks[0] != netip.MustParsePrefix("10.63.176.0/20") ||
		networks[1] != netip.MustParsePrefix("2001:db8::/64") {
		t.Fatalf("parseHostAddresses() networks = %v", networks)
	}
	if _, _, err := parseHostAddresses("10.0.0.1,not-an-address"); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("invalid entry error = %v", err)
	}
	if addresses, _, err := parseHostAddresses(""); err != nil || len(addresses) != 0 {
		t.Fatalf("parseHostAddresses(\"\") = %v, %v", addresses, err)
	}
	if _, _, err := parseHostAddresses(strings.Repeat("10.0.0.1,", maxHostAddresses+1)); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("too many addresses error = %v", err)
	}
}

func TestEngineSetHostAddressesFeedsTheDataPlane(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t, t.TempDir(), fakeKeys{key: validKey()}, nil)
	t.Cleanup(func() { _ = engine.Close() })
	if err := engine.SetHostAddresses("192.168.1.20/24,2001:db8::5"); err != nil {
		t.Fatal(err)
	}
	if got := engine.hosts.load(); len(got) != 2 || got[0] != netip.MustParseAddr("192.168.1.20") {
		t.Fatalf("host addresses = %v", got)
	}
	if err := engine.SetHostAddresses("not-an-address"); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("SetHostAddresses(invalid) error = %v", err)
	}
	if got := engine.hosts.load(); len(got) != 2 {
		t.Fatalf("an invalid list replaced the addresses: %v", got)
	}
}
