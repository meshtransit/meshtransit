package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/kubecafile"
	"meshtransit.net/client/internal/networkmap"
)

func kubeCARoot(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The daemon's CA files follow its maps: written for the profile it
// serves, withheld when it stops, resumed by a map taken since, and
// withheld for a profile it moved away from (K1e design §3.3, Q118).
func TestKubeCAFilesFollowTheProfile(t *testing.T) {
	t.Parallel()
	base := filepath.Join(t.TempDir(), "kube")
	live := true
	files := newKubeCAFiles(base, slog.New(slog.DiscardHandler), time.Now, func(string) bool { return live })
	const (
		profileA = "0a0a0a0a0a0a0a0a"
		profileB = "0b0b0b0b0b0b0b0b"
		cluster  = "01890f90-0000-7000-8000-0000000000a1"
	)
	snapshot := networkmap.Snapshot{KubernetesClustersAuthoritative: true, KubernetesClustersNegotiated: true,
		KubernetesClusters: []networkmap.KubernetesCluster{{ID: cluster, Name: "prod",
			State: networkmap.KubernetesClusterTrusted, Roots: [][]byte{kubeCARoot(t)}}}}
	read := func(profile string) string {
		t.Helper()
		content, err := os.ReadFile(filepath.Join(base, profile, cluster+".pem")) //nolint:gosec // The test's own directory.
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}
	files.observe(profileA, snapshot)
	files.pass()
	if content := read(profileA); !strings.HasPrefix(content, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("roots: %q", content)
	}
	if status, ok := files.status(profileA, cluster); !ok || status.State != kubecafile.StateCurrent {
		t.Fatalf("status %+v", status)
	}
	if info, err := os.Stat(filepath.Join(base, profileA)); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("profile directory %v, %v", info.Mode(), err)
	}

	// stop waits for a pass the run loop makes: here, the test's.
	go func() {
		time.Sleep(20 * time.Millisecond)
		files.pass()
	}()
	files.stop()
	if content := read(profileA); !kubecafile.IsMarker([]byte(content)) {
		t.Fatalf("withheld: %q", content)
	}
	if status, _ := files.status(profileA, cluster); status.State != kubecafile.StateWithheld {
		t.Fatalf("withheld status %+v", status)
	}
	files.observe(profileA, snapshot)
	files.pass()
	if content := read(profileA); kubecafile.IsMarker([]byte(content)) {
		t.Fatal("a map taken since the withhold did not resume the files")
	}

	// A switch to a profile that never syncs (unregistered, Core away)
	// withholds the profile served before (review e1b H1).
	files.serve(profileB)
	files.pass()
	if content := read(profileA); !kubecafile.IsMarker([]byte(content)) {
		t.Fatal("the profile meshd moved away from kept its roots")
	}
	if status, ok := files.status(profileA, cluster); !ok || status.State != kubecafile.StateWithheld {
		t.Fatalf("the profile moved away from: %+v", status)
	}
	if _, err := os.Stat(filepath.Join(base, profileB)); !os.IsNotExist(err) {
		t.Fatal("serving a profile with no map created its directory")
	}
	files.observe(profileB, snapshot)
	files.pass()
	if content := read(profileB); kubecafile.IsMarker([]byte(content)) {
		t.Fatal("the profile meshd serves has no roots")
	}
	if newKubeCAFiles("", nil, nil, nil) != nil {
		t.Fatal("no directory still keeps files")
	}
}
