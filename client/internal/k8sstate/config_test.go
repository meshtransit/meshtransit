package k8sstate

import (
	"os"
	"path/filepath"
	"testing"
)

// In a pod the API server comes from the service environment and the
// namespace, CA and token from the service account mount.
func TestInClusterConfigReadsThePod(t *testing.T) {
	t.Parallel()
	mount := t.TempDir()
	if err := os.WriteFile(filepath.Join(mount, "namespace"), []byte("mt-kube-api\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	env := map[string]string{"KUBERNETES_SERVICE_HOST": "fd00::1", "KUBERNETES_SERVICE_PORT": "443"}
	cfg, err := inClusterConfig(func(name string) string { return env[name] }, mount, "meshgw-state-1")
	if err != nil {
		t.Fatalf("inClusterConfig() error = %v", err)
	}
	want := Config{ //nolint:gosec // G101: file paths, not credentials
		Server:     "https://[fd00::1]:443",
		CAFile:     filepath.Join(mount, "ca.crt"),
		TokenFile:  filepath.Join(mount, "token"),
		Namespace:  "mt-kube-api",
		SecretName: "meshgw-state-1",
		Timeout:    DefaultTimeout,
	}
	if cfg != want {
		t.Fatalf("inClusterConfig() = %+v, want %+v", cfg, want)
	}
}

func TestInClusterConfigNeedsThePod(t *testing.T) {
	t.Parallel()
	mount := t.TempDir()
	if _, err := inClusterConfig(func(string) string { return "" }, mount, "meshgw-state-0"); err == nil {
		t.Fatal("inClusterConfig() outside a pod error = nil")
	}
	env := map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1", "KUBERNETES_SERVICE_PORT": "443"}
	if _, err := inClusterConfig(func(name string) string { return env[name] }, mount, "meshgw-state-0"); err == nil {
		t.Fatal("inClusterConfig() without a namespace file error = nil")
	}
	if err := os.WriteFile(filepath.Join(mount, "namespace"), []byte("mt-kube-api"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := inClusterConfig(func(name string) string { return env[name] }, mount, "Not_A_Name"); err == nil {
		t.Fatal("inClusterConfig() with an invalid Secret name error = nil")
	}
}
