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
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	// The fake gateway listens on loopback, outside the mesh's overlay.
	previous := kubeMeshPrefixes
	kubeMeshPrefixes = func(localapi.Status) []netip.Prefix {
		return []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	}
	t.Cleanup(func() { kubeMeshPrefixes = previous })
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

// A cluster that left the map (its rule removed) is still logged out of by
// the names login gave its contexts; another cluster's contexts stay
// (TD-CLI-92).
func TestKubeLogoutOfAClusterGoneFromTheMap(t *testing.T) {
	cluster, _ := kubeGateway(t, `"view","sre"`)
	client := &fakeClient{status: localapi.Status{ActiveProfileID: "0a0a", NetworkName: "acme",
		KubernetesClusters: []localapi.KubernetesClusterStatus{cluster}}}
	kubeconfigFile := filepath.Join(t.TempDir(), "config")
	var stdout, stderr bytes.Buffer
	for _, group := range []string{"", "sre"} {
		args := []string{"kube", "login", "prod", "--kubeconfig", kubeconfigFile}
		if group != "" {
			args = append(args, "--group", group)
		}
		if code := Run(t.Context(), args, &stdout, &stderr, testOptions(client)); code != 0 {
			t.Fatalf("login %q = %d: %s", group, code, stderr.String())
		}
	}
	other := cluster
	other.ID, other.Name = "01890f90-0000-7000-8000-0000000000a2", "prod-eu"
	client.status.KubernetesClusters = []localapi.KubernetesClusterStatus{other}
	if code := Run(t.Context(), []string{"kube", "login", "prod-eu", "--kubeconfig", kubeconfigFile}, &stdout, &stderr,
		testOptions(client)); code != 0 {
		t.Fatalf("login prod-eu = %d: %s", code, stderr.String())
	}
	client.status.KubernetesClusters = nil
	stdout.Reset()
	if code := Run(t.Context(), []string{"kube", "logout", "prod", "--kubeconfig", kubeconfigFile}, &stdout, &stderr,
		testOptions(client)); code != 0 || !strings.Contains(stdout.String(), "Removed 2") {
		t.Fatalf("logout of a cluster gone = %d: %s %s", code, stdout.String(), stderr.String())
	}
	written, err := os.ReadFile(kubeconfigFile) //nolint:gosec // The test's own file.
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(written), "name: mt-acme-prod\n") || strings.Contains(string(written), "mt-acme-prod-sre") ||
		!strings.Contains(string(written), "mt-acme-prod-eu") {
		t.Fatalf("kubeconfig after logout:\n%s", written)
	}
	stderr.Reset()
	if code := Run(t.Context(), []string{"kube", "logout", "staging", "--kubeconfig", kubeconfigFile}, &stdout, &stderr,
		testOptions(client)); code != 1 || !strings.Contains(stderr.String(), "no context meshctl wrote") {
		t.Fatalf("logout of an unknown cluster = %d: %s", code, stderr.String())
	}
}

// Logging out of a cluster gone from the map never touches a cluster still
// in it whose context took the same name first, finds the gone one's
// suffixed context and its ID, and keeps another profile's (review TD-CLI-92).
func TestKubeLogoutOfAGoneClusterKeepsOthers(t *testing.T) {
	cluster, _ := kubeGateway(t, `"view"`)
	kept := cluster
	kept.ID, kept.Name = "01890f90-0000-7000-8000-0000000000b1", "prod--eu"
	gone := cluster
	gone.ID, gone.Name = "01890f90-0000-7000-8000-0000000000b2", "prod-eu"
	kubeconfigFile := filepath.Join(t.TempDir(), "config")
	var stdout, stderr bytes.Buffer
	login := func(profile string, status localapi.KubernetesClusterStatus) {
		t.Helper()
		client := &fakeClient{status: localapi.Status{ActiveProfileID: profile, NetworkName: "acme",
			KubernetesClusters: []localapi.KubernetesClusterStatus{status}}}
		if code := Run(t.Context(), []string{"kube", "login", status.Name, "--kubeconfig", kubeconfigFile}, &stdout,
			&stderr, testOptions(client)); code != 0 {
			t.Fatalf("login %s = %d: %s", status.Name, code, stderr.String())
		}
	}
	login("0a0a", kept) // takes mt-acme-prod-eu
	login("0a0a", gone) // collides: a suffixed name
	login("0b0b", gone) // another profile's
	contexts := func() []kubeconfig.Found {
		t.Helper()
		found, err := kubeconfig.Managed([]string{kubeconfigFile})
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	if len(contexts()) != 3 {
		t.Fatalf("contexts = %+v", contexts())
	}
	client := &fakeClient{status: localapi.Status{ActiveProfileID: "0a0a", NetworkName: "acme",
		KubernetesClusters: []localapi.KubernetesClusterStatus{kept}}}
	stdout.Reset()
	if code := Run(t.Context(), []string{"kube", "logout", "prod-eu", "--kubeconfig", kubeconfigFile}, &stdout, &stderr,
		testOptions(client)); code != 0 || !strings.Contains(stdout.String(), "Removed 1") {
		t.Fatalf("logout of the gone cluster = %d: %s %s", code, stdout.String(), stderr.String())
	}
	var ids []string
	for _, context := range contexts() {
		ids = append(ids, context.Marker.ProfileID+"/"+context.Marker.ClusterID)
	}
	if strings.Join(ids, " ") != "0a0a/"+kept.ID+" 0b0b/"+gone.ID {
		t.Fatalf("left %v, want the cluster in the map and the other profile's", ids)
	}
	// Both gone, the name is ambiguous: refused, by ID it is not.
	login("0a0a", gone)
	client.status.KubernetesClusters = nil
	stderr.Reset()
	if code := Run(t.Context(), []string{"kube", "logout", "prod-eu", "--kubeconfig", kubeconfigFile}, &stdout, &stderr,
		testOptions(client)); code != 1 || !strings.Contains(stderr.String(), "log out by cluster ID") {
		t.Fatalf("ambiguous logout = %d: %s", code, stderr.String())
	}
	// By its ID, once its name tells nothing.
	client.status.NetworkName = "renamed"
	stdout.Reset()
	if code := Run(t.Context(), []string{"kube", "logout", gone.ID, "--kubeconfig", kubeconfigFile}, &stdout, &stderr,
		testOptions(client)); code != 0 || !strings.Contains(stdout.String(), "Removed 1") {
		t.Fatalf("logout by ID = %d: %s %s", code, stdout.String(), stderr.String())
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

// doctor walks the steps and names the first that fails, with its fix.
func TestKubeDoctor(t *testing.T) {
	cluster, caFile := kubeGateway(t, `"view"`)
	client := &fakeClient{status: localapi.Status{ActiveProfileID: "0a0a", NetworkName: "acme",
		ControlSession: "synchronized", KubernetesClusters: []localapi.KubernetesClusterStatus{cluster}}}
	kubeconfigFile := filepath.Join(t.TempDir(), "config")
	var stdout, stderr bytes.Buffer
	if code := Run(t.Context(), []string{"kube", "doctor", "prod", "--kubeconfig", kubeconfigFile}, &stdout, &stderr,
		testOptions(client)); code != 1 || !strings.Contains(stdout.String(), "FAIL kubectl context: none yet") ||
		!strings.Contains(stdout.String(), "ok   gateway answers: groups: view") {
		t.Fatalf("before login = %d:\n%s%s", code, stdout.String(), stderr.String())
	}
	if code := Run(t.Context(), []string{"kube", "login", "prod", "--kubeconfig", kubeconfigFile}, &stdout, &stderr,
		testOptions(client)); code != 0 {
		t.Fatalf("login = %d: %s", code, stderr.String())
	}
	stdout.Reset()
	if code := Run(t.Context(), []string{"kube", "doctor", "prod", "--kubeconfig", kubeconfigFile}, &stdout, &stderr,
		testOptions(client)); code != 0 {
		t.Fatalf("after login = %d:\n%s", code, stdout.String())
	}
	// A withheld CA file stops at its step.
	if err := os.WriteFile(caFile, []byte("# MeshTransit: CA withheld (disconnected)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := Run(t.Context(), []string{"kube", "doctor", "prod"}, &stdout, &stderr, testOptions(client)); code != 1 ||
		!strings.Contains(stdout.String(), "FAIL CA file: meshd withheld its CA file") ||
		strings.Contains(stdout.String(), "gateway answers") {
		t.Fatalf("withheld:\n%s", stdout.String())
	}
}

func TestKubeProxyWarning(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy:3128")
	host := "prod.kube.acme.mesh.internal"
	for noProxy, covered := range map[string]bool{
		"":                              false,
		"localhost,.mesh.internal":      true,
		"MESH.INTERNAL":                 true,
		"*.mesh.internal":               true,
		"mesh.internal:443":             true,
		"mesh.internal:6443":            false,
		".prod.kube.acme.mesh.internal": false, // a leading dot is subdomains only
		"10.0.0.0/8":                    false,
		"*":                             true,
	} {
		t.Setenv("NO_PROXY", noProxy)
		if got := kubeProxyWarning(host) == ""; got != covered {
			t.Errorf("NO_PROXY=%q: covered %t, want %t", noProxy, got, covered)
		}
	}
}

// The mesh is the CGNAT overlay and this Workspace's /48, never the alias
// range (a proxy's fake IPs) nor a LAN's ULA (review e3 H1).
func TestMeshPrefixes(t *testing.T) {
	t.Parallel()
	prefixes := meshPrefixes(localapi.Status{SelfAddresses: []string{"100.64.1.2/32", "fd7a:1234:5678:1::5/128"}})
	for address, inside := range map[string]bool{
		"100.64.9.9":          true,
		"fd7a:1234:5678:2::9": true,
		"198.18.0.7":          false,
		"fd00::1":             false,
		"fd7a:1234:5679::1":   false,
		"192.168.1.10":        false,
		"::ffff:100.64.3.4":   true,
	} {
		if got := inPrefixes(netip.MustParseAddr(address), prefixes); got != inside {
			t.Errorf("%s: inside %t, want %t", address, got, inside)
		}
	}
}

func TestKubeListGroups(t *testing.T) {
	cluster, _ := kubeGateway(t, `"view"`)
	pending := localapi.KubernetesClusterStatus{ID: "01890f90-0000-7000-8000-0000000000b2", Name: "dev", State: "pending"}
	client := &fakeClient{status: localapi.Status{ActiveProfileID: "0a0a",
		KubernetesClusters: []localapi.KubernetesClusterStatus{cluster, pending}}}
	var stdout, stderr bytes.Buffer
	if code := Run(t.Context(), []string{"--json", "kube", "list", "--groups"}, &stdout, &stderr,
		testOptions(client)); code != 0 {
		t.Fatalf("list = %d: %s", code, stderr.String())
	}
	var entries []kubeListEntry
	if err := json.Unmarshal(stdout.Bytes(), &entries); err != nil || len(entries) != 2 {
		t.Fatalf("entries %s, %v", stdout.String(), err)
	}
	if len(entries[0].Groups) != 1 || entries[0].Groups[0] != "view" || entries[1].GroupsError == "" {
		t.Fatalf("groups: %+v", entries)
	}
}

func TestKubeDoctorReconnectingWarns(t *testing.T) {
	check, warning := kubeDaemonCheck(localapi.Status{ControlSession: "reconnecting"})
	if !check.OK || warning == "" {
		t.Fatalf("reconnecting: %+v %q", check, warning)
	}
	if check, _ := kubeDaemonCheck(localapi.Status{ControlSession: "down"}); check.OK || check.Fix != "meshctl up" {
		t.Fatalf("down: %+v", check)
	}
}

func TestKubeAuditCheckExitCodes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	records := filepath.Join(dir, "records.json")
	if err := os.WriteFile(records, []byte(`{"format":"meshtransit-kube-operations/v1","gateway_namespace":"mt-kube",`+
		`"from":"2026-10-30T09:00:00Z","to":"2026-10-30T11:00:00Z","records_from":"2026-10-30T08:55:00Z",`+
		`"records_to":"2026-10-30T11:05:00Z","records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	unrecorded := write("bypass.log", `{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"bbbbbbbb-0000-4000-8000-000000000004","stage":"ResponseComplete",`+
		`"verb":"delete","requestURI":"/api/v1/namespaces/a/pods/p","user":{"username":"system:serviceaccount:mt-kube:mt-edit"},`+
		`"objectRef":{"resource":"pods","namespace":"a","name":"p"},"requestReceivedTimestamp":"2026-10-30T10:00:00Z"}`)
	// A read: no record needed.
	clean := write("clean.log", `{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"cccccccc-0000-4000-8000-000000000005",`+
		`"stage":"ResponseComplete","verb":"get","requestURI":"/api/v1/namespaces/a/pods/p",`+
		`"user":{"username":"system:serviceaccount:mt-kube:mt-edit"},`+
		`"objectRef":{"resource":"pods","namespace":"a","name":"p"},"requestReceivedTimestamp":"2026-10-30T10:00:00Z"}`)
	// A log of no audit events is an error, not a clean result.
	empty := write("empty.log", "")
	unseenRecords := filepath.Join(dir, "unseen.json")
	if err := os.WriteFile(unseenRecords, []byte(`{"format":"meshtransit-kube-operations/v1","gateway_namespace":`+
		`"mt-kube","from":"2026-10-30T09:00:00Z","to":"2026-10-30T11:00:00Z","records_from":"2026-10-30T08:55:00Z",`+
		`"records_to":"2026-10-30T11:05:00Z","records":[{"audit_id":"01a1b2c3-0000-7000-8000-000000000001",`+
		`"received_at":"2026-10-30T10:00:00Z","class":"write","groups":["edit"],"verb":"delete","resource":"pods"}]}`),
		0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		args []string
		want int
	}{
		{[]string{"kube", "audit-check", unrecorded, "--records", records}, auditCheckMismatch},
		{[]string{"kube", "audit-check", clean, "--records", records}, auditCheckClean},
		{[]string{"kube", "audit-check", clean}, auditCheckUsage},
		{[]string{"kube", "audit-check", "--records", records, clean}, auditCheckClean},
		{[]string{"kube", "audit-check", clean, "--records", records, clean}, auditCheckUsage},
		{[]string{"kube", "audit-check", clean, "--records", unseenRecords}, auditCheckIncomplete},
		{[]string{"kube", "audit-check", empty, "--records", records}, auditCheckError},
		{[]string{"kube", "audit-check", filepath.Join(dir, "missing.log"), "--records", records}, auditCheckError},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(t.Context(), test.args, &stdout, &stderr, testOptions(&fakeClient{})); code != test.want {
			t.Errorf("%v = %d, want %d: %s%s", test.args[2:], code, test.want, stdout.String(), stderr.String())
		}
	}
}
