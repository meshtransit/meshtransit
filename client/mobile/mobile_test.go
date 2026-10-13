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
	"meshtransit.net/client/internal/netadmin"
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
	mtu       int
	fd        int
	err       error
}

func (tun *fakeTUN) OpenTUN(addresses, routes string, mtu int) (int, error) {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	tun.addresses, tun.routes, tun.mtu = addresses, routes, mtu
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
		"name too long":      {config: &Config{StateDir: dir, DeviceName: strings.Repeat("a", 64)}, wantErr: true},
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

func TestPlatformTUNFailsClosed(t *testing.T) {
	t.Parallel()
	address := []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for name, test := range map[string]struct {
		ctx    context.Context
		tun    *fakeTUN
		config netadmin.TUNConfig
	}{
		"platform error":    {ctx: t.Context(), tun: &fakeTUN{err: errors.New("no permission")}, config: netadmin.TUNConfig{Addresses: address}},
		"negative fd":       {ctx: t.Context(), tun: &fakeTUN{fd: -1}, config: netadmin.TUNConfig{Addresses: address}},
		"stdin":             {ctx: t.Context(), tun: &fakeTUN{fd: 0}, config: netadmin.TUNConfig{Addresses: address}},
		"stderr":            {ctx: t.Context(), tun: &fakeTUN{fd: 2}, config: netadmin.TUNConfig{Addresses: address}},
		"no addresses":      {ctx: t.Context(), tun: &fakeTUN{}},
		"context cancelled": {ctx: canceled, tun: &fakeTUN{}, config: netadmin.TUNConfig{Addresses: address}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := (platformTUN{provider: test.tun, mtu: DefaultMTU}).OpenTUN(test.ctx, test.config); err == nil {
				t.Fatal("OpenTUN() succeeded")
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
		!isList || len(addresses) != 0 {
		t.Fatalf("status JSON = %s", encoded)
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
