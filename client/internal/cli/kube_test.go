package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/cli/localapi"
	"meshtransit.net/client/internal/kubeconfig"
)

// kubeGateway is a cluster's gateway answering whoami over TLS that a
// root of its own signs, as Core's CA does.
func kubeGateway(t *testing.T, groups string) (localapi.KubernetesClusterStatus, string) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"prod.k8s.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/mt/v1/whoami" {
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write([]byte(`{"device":"d","groups":[` + groups + `],"cluster":"prod"}`))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}},
		MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(rootDER)
	return localapi.KubernetesClusterStatus{ID: "01890f90-0000-7000-8000-0000000000a1", Name: "prod",
		DNSName: strings.TrimPrefix(server.URL, "https://"), TLSServerName: "prod.k8s.example", State: "trusted",
		Roots: []string{hex.EncodeToString(sum[:])}, CAFile: caFile, CAFileState: "current"}, caFile
}

func TestKubeLoginWritesAContext(t *testing.T) {
	cluster, caFile := kubeGateway(t, `"view","sre"`)
	client := &fakeClient{status: localapi.Status{ActiveProfileID: "0a0a", NetworkName: "Acme Corp",
		KubernetesClusters: []localapi.KubernetesClusterStatus{cluster}}}
	kubeconfigFile := filepath.Join(t.TempDir(), "config")
	var stdout, stderr bytes.Buffer
	code := Run(t.Context(), []string{"kube", "login", "prod", "--group", "sre", "--use", "--kubeconfig", kubeconfigFile},
		&stdout, &stderr, testOptions(client))
	if code != 0 {
		t.Fatalf("login = %d: %s", code, stderr.String())
	}
	written, err := os.ReadFile(kubeconfigFile) //nolint:gosec // The test's own file.
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mt-acme-corp-prod-sre", "/mt/g/sre", "certificate-authority: " + caFile,
		"tls-server-name: prod.k8s.example", "current-context: mt-acme-corp-prod-sre", "meshtransit.net/managed"} {
		if !strings.Contains(string(written), want) {
			t.Errorf("kubeconfig lacks %q:\n%s", want, written)
		}
	}
	// A group the Device does not hold is refused.
	if code := Run(t.Context(), []string{"kube", "login", "prod", "--group", "admin", "--kubeconfig", kubeconfigFile},
		&stdout, &stderr, testOptions(client)); code != 1 {
		t.Fatalf("a group not held: %d", code)
	}
	stdout.Reset()
	if code := Run(t.Context(), []string{"kube", "logout", "prod", "--kubeconfig", kubeconfigFile}, &stdout, &stderr,
		testOptions(client)); code != 0 || !strings.Contains(stdout.String(), "Removed 1") {
		t.Fatalf("logout = %d: %s %s", code, stdout.String(), stderr.String())
	}
}

// The CA file must hold exactly roots the map names, never a marker.
func TestKubeLoginRefusesABadCAFile(t *testing.T) {
	cluster, caFile := kubeGateway(t, `"view"`)
	client := &fakeClient{status: localapi.Status{ActiveProfileID: "0a0a", NetworkName: "acme",
		KubernetesClusters: []localapi.KubernetesClusterStatus{cluster}}}
	kubeconfigFile := filepath.Join(t.TempDir(), "config")
	for name, content := range map[string]string{
		"a marker":       "# MeshTransit: CA withheld (disconnected)\n",
		"an extra root":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})),
		"something else": "not pem",
	} {
		if err := os.WriteFile(caFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run(t.Context(), []string{"kube", "login", "prod", "--kubeconfig", kubeconfigFile}, &stdout, &stderr,
			testOptions(client)); code != 1 {
			t.Errorf("%s: login = %d", name, code)
		}
	}
	if _, err := os.Stat(kubeconfigFile); !os.IsNotExist(err) {
		t.Fatal("a refused login wrote the kubeconfig")
	}
}

func TestKubeContextName(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ network, cluster, group, want string }{
		{"Acme Corp", "prod", "", "mt-acme-corp-prod"},
		{"acme", "prod_eu", "sre", "mt-acme-prod-eu-sre"},
		{"", "prod", "", "mt-prod"},
		{strings.Repeat("n", 80), "prod", "", "mt-" + strings.Repeat("n", 60)},
	} {
		if got := kubeContextName(test.network, test.cluster, test.group); got != test.want {
			t.Errorf("%q %q %q = %q, want %q", test.network, test.cluster, test.group, got, test.want)
		}
	}
}

// client-go's order on Windows (re-review e2 M3).
func TestWindowsKubeHome(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile")
	drive := filepath.Join(dir, "drive")
	for _, path := range []string{profile, drive} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	env := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	// HOMEDRIVE is the directory above, HOMEPATH the rest, as on a domain PC.
	values := map[string]string{"HOMEDRIVE": dir, "HOMEPATH": string(filepath.Separator) + "drive",
		"USERPROFILE": profile}
	// No .kube\config anywhere: USERPROFILE before HOMEDRIVE+HOMEPATH.
	if got := windowsKubeHome(env(values), os.Stat); got != profile {
		t.Fatalf("no config: %q, want %q", got, profile)
	}
	// One holds .kube\config: it wins, HOMEDRIVE+HOMEPATH first.
	if err := os.MkdirAll(filepath.Join(drive, ".kube"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(drive, ".kube", "config"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := windowsKubeHome(env(values), os.Stat); got != drive {
		t.Fatalf("with config: %q, want %q", got, drive)
	}
	if got := windowsKubeHome(env(map[string]string{"HOME": filepath.Join(dir, "missing")}), os.Stat); got !=
		filepath.Join(dir, "missing") {
		t.Fatalf("only a HOME that does not exist: %q", got)
	}
}

// Two groups of one cluster whose names clean up alike get different
// suffixes (re-review e2 L1).
func TestWithSuffixTellsEntriesApart(t *testing.T) {
	t.Parallel()
	a := withSuffix("mt-acme-prod-a-b", kubeconfig.Marker{ProfileID: "p", ClusterID: "c", Group: "a.b"})
	b := withSuffix("mt-acme-prod-a-b", kubeconfig.Marker{ProfileID: "p", ClusterID: "c", Group: "a_b"})
	if a == b || len(withSuffix(strings.Repeat("x", 70), kubeconfig.Marker{})) > 63 {
		t.Fatalf("suffixes %q %q", a, b)
	}
}
