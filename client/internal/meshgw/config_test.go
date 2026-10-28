package meshgw

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testFingerprint = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testEnv(t *testing.T) (map[string]string, string) {
	t.Helper()
	dir := t.TempDir()
	env := map[string]string{
		"POD_NAME":                   "meshgw-2",
		"MESHGW_CONTROL_URL":         "https://control.example.com",
		"MESHGW_CONTROL_FINGERPRINT": testFingerprint,
		"MESHGW_CLUSTER":             "kinda",
		"MESHGW_STATE_DIR":           filepath.Join(dir, "state"),
		"MESHGW_ENVELOPE_DIR":        filepath.Join(dir, "envelope"),
		"MESHGW_ENROLLMENT_DIR":      filepath.Join(dir, "enroll"),
		"KUBERNETES_SERVICE_HOST":    "fd00:10:96::1",
		"KUBERNETES_SERVICE_PORT":    "443",
	}
	return env, dir
}

func loadFrom(env map[string]string) (Config, error) {
	return LoadConfig(func(name string) string { return env[name] })
}

// A pod's configuration comes from its environment: the ordinal from its
// StatefulSet name, and per-ordinal files for its keys and its state Secret.
func TestLoadConfigReadsThePod(t *testing.T) {
	t.Parallel()
	env, dir := testEnv(t)
	cfg, err := loadFrom(env)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	want := Config{ //nolint:gosec // G101: file paths, not credentials
		Ordinal:            2,
		ControlURL:         "https://control.example.com",
		ControlFingerprint: testFingerprint,
		Hostname:           "meshgw-kinda-2",
		StateDir:           filepath.Join(dir, "state"),
		EnvelopeKeyFile:    filepath.Join(dir, "envelope", "key-2"),
		EnrollmentKeyFile:  filepath.Join(dir, "enroll", "key-2"),
		StateSecret:        "meshgw-state-2",
		PodName:            "meshgw-2",
		ProbeAddress:       ":9090",
		ListenPort:         41641,
		KubeAPIPort:        443,
		KubeAPIBackend:     "[fd00:10:96::1]:443",
	}
	if cfg != want {
		t.Fatalf("LoadConfig() = %+v\nwant %+v", cfg, want)
	}
}

func TestLoadConfigRefusesBadValues(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(map[string]string){
		"no ordinal":            func(env map[string]string) { env["POD_NAME"] = "meshgw" },
		"no pod name":           func(env map[string]string) { delete(env, "POD_NAME") },
		"http control":          func(env map[string]string) { env["MESHGW_CONTROL_URL"] = "http://control.example.com" },
		"control with path":     func(env map[string]string) { env["MESHGW_CONTROL_URL"] = "https://control.example.com/x" },
		"control upper case":    func(env map[string]string) { env["MESHGW_CONTROL_URL"] = "https://Control.example.com" },
		"no fingerprint":        func(env map[string]string) { delete(env, "MESHGW_CONTROL_FINGERPRINT") },
		"cluster not a label":   func(env map[string]string) { env["MESHGW_CLUSTER"] = "Kind_A" },
		"relative state dir":    func(env map[string]string) { env["MESHGW_STATE_DIR"] = "state" },
		"listen port too low":   func(env map[string]string) { env["MESHGW_LISTEN_PORT"] = "80" },
		"listen port not a num": func(env map[string]string) { env["MESHGW_LISTEN_PORT"] = "x" },
		"not in a pod":          func(env map[string]string) { delete(env, "KUBERNETES_SERVICE_HOST") },
		"name too long": func(env map[string]string) {
			env["MESHGW_CLUSTER"] = strings.Repeat("a", 40)
			env["POD_NAME"] = "meshgw-1234567890123456"
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env, _ := testEnv(t)
			change(env)
			if _, err := loadFrom(env); err == nil {
				t.Fatal("LoadConfig() error = nil")
			}
		})
	}
}

// The envelope key is exactly the 32 bytes the Secret holds.
func TestReadEnvelopeKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "key-0")
	key := bytes.Repeat([]byte{0x0a}, 32)
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	got, err := ReadEnvelopeKey(path)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("ReadEnvelopeKey() = %x, %v", got, err)
	}
	for _, bad := range [][]byte{key[:31], append(bytes.Clone(key), '\n')} {
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if _, err := ReadEnvelopeKey(path); err == nil || !strings.Contains(err.Error(), "32") {
			t.Fatalf("ReadEnvelopeKey(%d bytes) error = %v", len(bad), err)
		}
	}
	if _, err := ReadEnvelopeKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("ReadEnvelopeKey(missing) error = nil")
	}
}

// MESHGW_JOIN_DIR makes the replica a K1 gateway with its own join key.
func TestLoadConfigJoinMode(t *testing.T) {
	t.Parallel()
	env, dir := testEnv(t)
	env["MESHGW_JOIN_DIR"] = filepath.Join(dir, "join")
	env["POD_NAMESPACE"], env["NODE_NAME"] = "mt-kube", "worker-1"
	cfg, err := loadFrom(env)
	if err != nil || cfg.JoinKeyFile != filepath.Join(dir, "join", "key-2") || cfg.Namespace != "mt-kube" ||
		cfg.NodeName != "worker-1" {
		t.Fatalf("LoadConfig() = %+v, %v", cfg, err)
	}
	env["MESHGW_JOIN_DIR"] = "join"
	if _, err := loadFrom(env); err == nil {
		t.Fatal("a relative join directory was accepted")
	}
}

// A K1 gateway keeps its certificate unless MESHGW_CERTIFICATES is "off";
// an enrolled replica keeps none (K1a4a a4).
func TestLoadConfigCertificates(t *testing.T) {
	t.Parallel()
	env, dir := testEnv(t)
	if cfg, err := loadFrom(env); err != nil || cfg.Certificates {
		t.Fatalf("an enrolled replica: %+v, %v", cfg.Certificates, err)
	}
	env["MESHGW_JOIN_DIR"] = filepath.Join(dir, "join")
	for value, want := range map[string]bool{"": true, "on": true, "off": false} {
		env["MESHGW_CERTIFICATES"] = value
		if cfg, err := loadFrom(env); err != nil || cfg.Certificates != want {
			t.Errorf("%q: %v, %v", value, cfg.Certificates, err)
		}
	}
	env["MESHGW_CERTIFICATES"] = "yes"
	if _, err := loadFrom(env); err == nil {
		t.Fatal("MESHGW_CERTIFICATES=yes was accepted")
	}
}
