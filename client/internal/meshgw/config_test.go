package meshgw

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
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
		Cluster:            "kinda",
		TCP:                DefaultTCPBuffers(),
		Kube:               KubeConfig{Mode: KubeModePassthrough},
	}
	if !reflect.DeepEqual(cfg, want) {
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
		"receive buffer small":  func(env map[string]string) { env["MESHGW_TCP_RECEIVE_BUFFER"] = "16383" },
		"send buffer large":     func(env map[string]string) { env["MESHGW_TCP_SEND_BUFFER"] = "4194305" },
		"buffer with a unit":    func(env map[string]string) { env["MESHGW_TCP_SEND_BUFFER"] = "96Ki" },
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

// A cluster sets its TCP sizes in bytes, within the bounds (K1c Q88).
func TestLoadConfigTCPBuffers(t *testing.T) {
	t.Parallel()
	env, _ := testEnv(t)
	env["MESHGW_TCP_RECEIVE_BUFFER"] = "16384"
	env["MESHGW_TCP_SEND_BUFFER"] = "4194304"
	cfg, err := loadFrom(env)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TCP != (TCPBuffers{Receive: 16 << 10, Send: 4 << 20}) {
		t.Fatalf("TCP = %+v", cfg.TCP)
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
	env["MESHGW_KUBE_MODE"] = KubeModePassthrough
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
	env["MESHGW_KUBE_MODE"] = KubeModePassthrough
	for value, want := range map[string]bool{"": true, "on": true, "off": false} {
		env["MESHGW_CERTIFICATES"] = value
		if cfg, err := loadFrom(env); err != nil || cfg.Certificates != want {
			t.Errorf("%q: %v, %v", value, cfg.Certificates, err)
		}
	}
	env["MESHGW_CERTIFICATES"] = ""
	env["MESHGW_CERTIFICATE_RENEW_AFTER"] = "15m"
	if cfg, err := loadFrom(env); err != nil || cfg.CertificateRenewAfter != 15*time.Minute {
		t.Fatalf("a renewal after 15 minutes: %v, %v", cfg.CertificateRenewAfter, err)
	}
	for _, refused := range []string{"14m", "soon"} {
		env["MESHGW_CERTIFICATE_RENEW_AFTER"] = refused
		if _, err := loadFrom(env); err == nil {
			t.Errorf("MESHGW_CERTIFICATE_RENEW_AFTER=%s was accepted", refused)
		}
	}
	env["MESHGW_CERTIFICATE_RENEW_AFTER"] = ""
	env["MESHGW_CERTIFICATES"] = "yes"
	if _, err := loadFrom(env); err == nil {
		t.Fatal("MESHGW_CERTIFICATES=yes was accepted")
	}
}

// proxyEnv is a K1 gateway's environment in proxy mode.
func proxyEnv(t *testing.T) map[string]string {
	t.Helper()
	env, dir := testEnv(t)
	env["MESHGW_JOIN_DIR"] = filepath.Join(dir, "join")
	env["POD_NAMESPACE"], env["MESHGW_REPLICAS"] = "mt-kube", "3"
	env["MESHGW_KUBE_GROUPS"] = `[{"name":"view","default":true},{"name":"edit","namespaces":["team-a"]},
		{"name":"sre","privileged":true,"allowedPrincipals":["person-1"],"allowImpersonation":true}]`
	return env
}

// A K1 gateway proxies by default, with the groups the chart gives it
// (K1b design §10).
func TestLoadConfigProxyMode(t *testing.T) {
	t.Parallel()
	env := proxyEnv(t)
	env["MESHGW_SECRET_RESOURCES"] = "sealedsecrets.bitnami.com, tokens"
	env["MESHGW_GUARDED_NAMESPACES"] = "ingress"
	cfg, err := loadFrom(env)
	if err != nil {
		t.Fatal(err)
	}
	kube := cfg.Kube
	if kube.Mode != KubeModeProxy || kube.Cluster != "kinda" || len(kube.Groups) != 3 || !kube.Groups[0].Default ||
		!kube.Groups[2].AllowImpersonation || kube.StaleAfter != 5*time.Minute ||
		kube.APIServer != "https://[fd00:10:96::1]:443" || kube.APIServerOverride || kube.StatefulSet != "meshgw" ||
		kube.Replicas != 3 || kube.ServiceAccount != "meshgw" ||
		!reflect.DeepEqual(kube.GuardedNamespaces, []string{"ingress"}) {
		t.Fatalf("%+v", kube)
	}
	if want := []string{
		"meshgw-envelope", "meshgw-join", "meshgw-state-0", "meshgw-state-1", "meshgw-state-2",
		"meshgw-state-3", "meshgw-state-4",
	}; !reflect.DeepEqual(kube.Secrets, want) {
		t.Fatalf("secrets %v", kube.Secrets)
	}
	if len(kube.SecretResources) != 2 || kube.SecretResources[0].Group != "bitnami.com" ||
		kube.SecretResources[0].Resource != "sealedsecrets" || kube.SecretResources[1].Group != "" {
		t.Fatalf("secret resources %+v", kube.SecretResources)
	}
}

func TestLoadConfigRefusesBadProxyModes(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(map[string]string){
		"no groups":       func(env map[string]string) { delete(env, "MESHGW_KUBE_GROUPS") },
		"groups not json": func(env map[string]string) { env["MESHGW_KUBE_GROUPS"] = "view" },
		"unknown field":   func(env map[string]string) { env["MESHGW_KUBE_GROUPS"] = `[{"name":"view","default":true,"x":1}]` },
		"no default":      func(env map[string]string) { env["MESHGW_KUBE_GROUPS"] = `[{"name":"view"}]` },
		"privileged default": func(env map[string]string) {
			env["MESHGW_KUBE_GROUPS"] = `[{"name":"a","default":true,"privileged":true,"allowedPrincipals":["p"]}]`
		},
		"impersonating plain": func(env map[string]string) {
			env["MESHGW_KUBE_GROUPS"] = `[{"name":"a","default":true,"allowImpersonation":true}]`
		},
		"passthrough with groups": func(env map[string]string) { env["MESHGW_KUBE_MODE"] = KubeModePassthrough },
		"unknown mode":            func(env map[string]string) { env["MESHGW_KUBE_MODE"] = "tcp" },
		"no certificates":         func(env map[string]string) { env["MESHGW_CERTIFICATES"] = "off" },
		"no namespace":            func(env map[string]string) { delete(env, "POD_NAMESPACE") },
		"past the replicas":       func(env map[string]string) { env["MESHGW_REPLICAS"] = "2" },
		"trailing json":           func(env map[string]string) { env["MESHGW_KUBE_GROUPS"] = `[{"name":"view","default":true}]]` },
		"backend with query":      func(env map[string]string) { env["MESHGW_KUBE_API_BACKEND"] = "https://api:6443?x=1" },
		"stale too long":          func(env map[string]string) { env["MESHGW_KUBE_STALE_AFTER"] = "1h" },
		"bad secret resource":     func(env map[string]string) { env["MESHGW_SECRET_RESOURCES"] = "Secrets" },
		"http backend":            func(env map[string]string) { env["MESHGW_KUBE_API_BACKEND"] = "http://api:6443" },
		"too many replicas":       func(env map[string]string) { env["MESHGW_REPLICAS"] = "11" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := proxyEnv(t)
			change(env)
			if _, err := loadFrom(env); err == nil {
				t.Fatal("LoadConfig() error = nil")
			}
		})
	}
	// An enrolled replica only passes through, and takes no proxy settings
	// (review b5b M4).
	for name, value := range map[string]string{
		"MESHGW_KUBE_MODE": KubeModeProxy, "MESHGW_KUBE_GROUPS": `[{"name":"view","default":true}]`,
		"MESHGW_SECRET_RESOURCES": "tokens",
	} {
		env, _ := testEnv(t)
		env[name] = value
		if _, err := loadFrom(env); err == nil {
			t.Errorf("an enrolled replica took %s", name)
		}
	}
}

// MESHGW_KUBE_API_BACKEND points the proxy at another API server, for
// tests.
func TestLoadConfigAPIServerOverride(t *testing.T) {
	t.Parallel()
	env := proxyEnv(t)
	env["MESHGW_KUBE_API_BACKEND"] = "https://127.0.0.1:6443"
	cfg, err := loadFrom(env)
	if err != nil || cfg.Kube.APIServer != "https://127.0.0.1:6443" || !cfg.Kube.APIServerOverride {
		t.Fatalf("%+v, %v", cfg.Kube, err)
	}
}

// MESHGW_CERTIFICATE_DIR keeps the certificate across a restart; it must
// be absolute.
func TestLoadConfigCertificateDir(t *testing.T) {
	t.Parallel()
	env := proxyEnv(t)
	env["MESHGW_CERTIFICATE_DIR"] = "/var/run/meshgw/certificate"
	if cfg, err := loadFrom(env); err != nil || cfg.CertificateDir != "/var/run/meshgw/certificate" {
		t.Fatalf("%q, %v", cfg.CertificateDir, err)
	}
	for _, refused := range []string{"certificate", env["MESHGW_STATE_DIR"], env["MESHGW_STATE_DIR"] + "/cert"} {
		env["MESHGW_CERTIFICATE_DIR"] = refused
		if _, err := loadFrom(env); err == nil {
			t.Fatalf("%q was taken", refused)
		}
	}
	enrolled, _ := testEnv(t)
	enrolled["MESHGW_CERTIFICATE_DIR"] = "/var/run/meshgw/certificate"
	if _, err := loadFrom(enrolled); err == nil {
		t.Fatal("taken without MESHGW_JOIN_DIR")
	}
}
