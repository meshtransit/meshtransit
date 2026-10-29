//nolint:gosec // G304, G306: files in the test's own temporary directory, public CA files are 0644.
package kubecafile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
)

const (
	clusterA = "01890f90-0000-7000-8000-0000000000a1"
	clusterB = "01890f90-0000-7000-8000-0000000000b2"
)

// tempDirectory is a profile directory in a test's temporary directory.
type tempDirectory struct{ path string }

func (dir tempDirectory) Path() string            { return dir.path }
func (dir tempDirectory) Open() (*os.Root, error) { return os.OpenRoot(dir.path) }

type clock struct{ now time.Time }

func (c *clock) read() time.Time { return c.now }

func newManager(t *testing.T) (*Manager, string, *clock) {
	t.Helper()
	dir := t.TempDir()
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	return New(tempDirectory{path: dir}, c.read), dir, c
}

func selfSigned(t *testing.T, key any, public any) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func p256Root(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return selfSigned(t, key, &key.PublicKey)
}

func trusted(id string, roots ...[]byte) networkmap.KubernetesCluster {
	return networkmap.KubernetesCluster{ID: id, Name: "prod", State: networkmap.KubernetesClusterTrusted, Roots: roots}
}

func read(t *testing.T, dir, id string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, id+fileSuffix))
	if err != nil {
		t.Fatal(err)
	}
	if len(content) == 0 {
		t.Fatal("an empty CA file: kubectl would trust the system roots")
	}
	return content
}

func reconcile(t *testing.T, manager *Manager, authoritative bool, clusters ...networkmap.KubernetesCluster,
) map[string]Status {
	t.Helper()
	statuses, err := manager.Reconcile(clusters, Pass{Authoritative: authoritative, Confirmed: authoritative})
	if err != nil {
		t.Fatal(err)
	}
	return statuses
}

func TestReconcileWritesRootsOrMarkers(t *testing.T) {
	t.Parallel()
	manager, dir, _ := newManager(t)
	root := p256Root(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaRoot := selfSigned(t, rsaKey, &rsaKey.PublicKey)
	pending := networkmap.KubernetesCluster{ID: clusterB, Name: "dev", State: networkmap.KubernetesClusterPending}
	statuses := reconcile(t, manager, true, trusted(clusterA, root), pending)
	block, rest := pem.Decode(read(t, dir, clusterA))
	if block == nil || !bytes.Equal(block.Bytes, root) || len(rest) != 0 || statuses[clusterA].State != StateCurrent {
		t.Fatalf("roots file: %+v", statuses[clusterA])
	}
	if info, err := os.Stat(filepath.Join(dir, clusterA+fileSuffix)); err != nil || info.Mode().Perm() != fileMode {
		t.Fatalf("mode %v, %v", info.Mode(), err)
	}
	if content := read(t, dir, clusterB); !IsMarker(content) || statuses[clusterB].Reason != ReasonPending ||
		statuses[clusterB].State != StateWithheld {
		t.Fatalf("pending: %q %+v", content, statuses[clusterB])
	}
	// A root kubectl's checks would take but K1e does not (not P-256).
	statuses = reconcile(t, manager, true, trusted(clusterA, rsaRoot))
	if content := read(t, dir, clusterA); !IsMarker(content) || statuses[clusterA].Reason != ReasonUnsupportedKey {
		t.Fatalf("RSA root: %q %+v", content, statuses[clusterA])
	}
	invalid := trusted(clusterA)
	invalid.State = networkmap.KubernetesClusterInvalid
	if statuses = reconcile(t, manager, true, invalid); statuses[clusterA].Reason != ReasonInvalid {
		t.Fatalf("invalid: %+v", statuses[clusterA])
	}
	// The authoritative list dropped B: its file goes.
	if _, err := os.Stat(filepath.Join(dir, clusterB+fileSuffix)); !os.IsNotExist(err) {
		t.Fatalf("a cluster gone from the list kept its file: %v", err)
	}
}

// After a restart Core has not said: files stay, until their roots go
// unconfirmed past Expiry (K1e §3.3, review v1 H2/H3).
func TestReconcileWithoutAuthority(t *testing.T) {
	t.Parallel()
	manager, dir, c := newManager(t)
	root := p256Root(t)
	reconcile(t, manager, true, trusted(clusterA, root), trusted(clusterB, root))
	before := read(t, dir, clusterA)

	// A restart: an empty, non-authoritative list.
	c.now = c.now.Add(time.Hour)
	statuses := reconcile(t, manager, false)
	if !bytes.Equal(read(t, dir, clusterA), before) || !bytes.Equal(read(t, dir, clusterB), before) {
		t.Fatal("a non-authoritative list changed a file")
	}
	if len(statuses) != 0 {
		t.Fatalf("statuses %v", statuses)
	}
	// A cluster listed with no file yet.
	if statuses, _ = manager.Reconcile([]networkmap.KubernetesCluster{trusted("01890f90-0000-7000-8000-0000000000c3",
		root)}, Pass{}); statuses["01890f90-0000-7000-8000-0000000000c3"].State != StateMissing {
		t.Fatalf("no file: %+v", statuses)
	}
	// Listed but not authoritative: stale.
	if statuses = reconcile(t, manager, false, trusted(clusterA, root)); statuses[clusterA].State != StateStale {
		t.Fatalf("listed without authority: %+v", statuses[clusterA])
	}
	// Past Expiry since Core last confirmed them: markers, never deletion.
	c.now = c.now.Add(Expiry)
	statuses = reconcile(t, manager, false, trusted(clusterA, root))
	if !IsMarker(read(t, dir, clusterA)) || !IsMarker(read(t, dir, clusterB)) ||
		statuses[clusterA].State != StateExpired {
		t.Fatalf("expired: %+v", statuses[clusterA])
	}
}

// While Core holds, the roots stay but their confirmation time freezes;
// past the hold, the file is withheld (re-review H-a).
func TestReconcileDuringAHold(t *testing.T) {
	t.Parallel()
	manager, dir, c := newManager(t)
	root := p256Root(t)
	reconcile(t, manager, true, trusted(clusterA, root))
	// A stable session past 25 hours, Core not holding: still current.
	c.now = c.now.Add(30 * time.Hour)
	if statuses := reconcile(t, manager, true, trusted(clusterA, root)); statuses[clusterA].State != StateCurrent {
		t.Fatalf("a healthy cluster expired: %+v", statuses[clusterA])
	}
	confirmed := c.now
	held := trusted(clusterA, root)
	held.HeldUntil = c.now.Add(25 * time.Hour)
	c.now = c.now.Add(time.Hour)
	// A hold: Core does not confirm.
	if _, err := manager.Reconcile([]networkmap.KubernetesCluster{held}, Pass{Authoritative: true}); err != nil {
		t.Fatal(err)
	}
	if got := manifestOf(t, dir).Files[clusterA].VerifiedAt; !got.Equal(confirmed) {
		t.Fatalf("a hold moved the confirmation to %v, want %v", got, confirmed)
	}
	c.now = held.HeldUntil.Add(time.Second)
	if statuses, _ := manager.Reconcile([]networkmap.KubernetesCluster{held},
		Pass{Authoritative: true}); statuses[clusterA].State != StateExpired ||
		!IsMarker(read(t, dir, clusterA)) {
		t.Fatalf("past the hold: %+v", statuses[clusterA])
	}
}

func TestWithholdAndClean(t *testing.T) {
	t.Parallel()
	manager, dir, _ := newManager(t)
	root := p256Root(t)
	reconcile(t, manager, true, trusted(clusterA, root), trusted(clusterB, root))
	if err := os.WriteFile(filepath.Join(dir, "notes.pem"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := manager.Withhold(ReasonDisconnected); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{clusterA, clusterB} {
		if content := read(t, dir, id); !bytes.Contains(content, []byte("(disconnected)")) {
			t.Fatalf("%s: %q", id, content)
		}
	}
	if content, _ := os.ReadFile(filepath.Join(dir, "notes.pem")); string(content) != "x" {
		t.Fatal("a file not named by a cluster ID was touched")
	}
	leftover := filepath.Join(dir, clusterA+fileSuffix+tempInfix+"00")
	if err := os.WriteFile(leftover, []byte("half"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := manager.Clean(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatal("a temporary file survived Clean")
	}
}

// A file changed out of band is repaired at the next reconcile.
func TestReconcileRepairsTheDisk(t *testing.T) {
	t.Parallel()
	manager, dir, _ := newManager(t)
	root := p256Root(t)
	reconcile(t, manager, true, trusted(clusterA, root))
	want := read(t, dir, clusterA)
	if err := os.WriteFile(filepath.Join(dir, clusterA+fileSuffix), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	reconcile(t, manager, true, trusted(clusterA, root))
	if !bytes.Equal(read(t, dir, clusterA), want) {
		t.Fatal("a tampered file was not repaired")
	}
}

func manifestOf(t *testing.T, dir string) manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	var recorded manifest
	if err := json.Unmarshal(raw, &recorded); err != nil {
		t.Fatal(err)
	}
	return recorded
}

// Offline, or on a session without kube.ca1, Core confirms nothing: the
// confirmation time stays, and the roots expire 25 hours after it (review
// e1a H3).
func TestReconcileUnconfirmedExpires(t *testing.T) {
	t.Parallel()
	manager, dir, c := newManager(t)
	root := p256Root(t)
	reconcile(t, manager, true, trusted(clusterA, root))
	offline := Pass{Authoritative: true}
	c.now = c.now.Add(24 * time.Hour)
	if statuses, err := manager.Reconcile([]networkmap.KubernetesCluster{trusted(clusterA, root)}, offline); err != nil ||
		statuses[clusterA].State != StateCurrent {
		t.Fatalf("within 25 hours: %+v, %v", statuses, err)
	}
	c.now = c.now.Add(2 * time.Hour)
	if statuses, err := manager.Reconcile([]networkmap.KubernetesCluster{trusted(clusterA, root)}, offline); err != nil ||
		statuses[clusterA].State != StateExpired || !IsMarker(read(t, dir, clusterA)) {
		t.Fatalf("past 25 hours unconfirmed: %+v, %v", statuses, err)
	}
	// New roots while unconfirmed and not holding: nothing dates them.
	other := p256Root(t)
	if statuses, _ := manager.Reconcile([]networkmap.KubernetesCluster{trusted(clusterB, other)}, offline); statuses[clusterB].State != StateExpired {
		t.Fatalf("new unconfirmed roots: %+v", statuses[clusterB])
	}
}

// A roots file the manifest does not date — a crash before the manifest,
// a corrupt manifest — expires when Core does not speak (review e1a H1).
func TestReconcileUndatedRootsExpire(t *testing.T) {
	t.Parallel()
	manager, dir, _ := newManager(t)
	root := p256Root(t)
	reconcile(t, manager, true, trusted(clusterA, root), trusted(clusterB, root))
	if err := os.WriteFile(filepath.Join(dir, manifestName), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	statuses := reconcile(t, manager, false, trusted(clusterA, root))
	if statuses[clusterA].State != StateExpired || !IsMarker(read(t, dir, clusterA)) || !IsMarker(read(t, dir, clusterB)) {
		t.Fatalf("undated roots: %+v", statuses)
	}
}

// One file that cannot be written does not stop the others, and the
// manifest is still written (review e1a H2).
func TestReconcileGoesOnPastAFailedFile(t *testing.T) {
	t.Parallel()
	manager, dir, _ := newManager(t)
	root := p256Root(t)
	if err := os.Mkdir(filepath.Join(dir, clusterB+fileSuffix), 0o755); err != nil {
		t.Fatal(err)
	}
	statuses, err := manager.Reconcile([]networkmap.KubernetesCluster{trusted(clusterA, root), trusted(clusterB, root)},
		Pass{Authoritative: true, Confirmed: true})
	if err == nil || statuses[clusterB].State != StateError || statuses[clusterA].State != StateCurrent {
		t.Fatalf("statuses %+v, %v", statuses, err)
	}
	if _, ok := manifestOf(t, dir).Files[clusterA]; !ok {
		t.Fatal("the manifest was not written past a failed file")
	}
}

// After Withhold, a pass writes nothing until Resume (review e1a M2).
func TestWithholdHoldsUntilResume(t *testing.T) {
	t.Parallel()
	manager, dir, _ := newManager(t)
	root := p256Root(t)
	reconcile(t, manager, true, trusted(clusterA, root))
	if err := manager.Withhold(ReasonDisconnected); err != nil {
		t.Fatal(err)
	}
	if statuses := reconcile(t, manager, true, trusted(clusterA, root)); statuses[clusterA].State != StateWithheld ||
		!IsMarker(read(t, dir, clusterA)) {
		t.Fatalf("a pass undid the withhold: %+v", statuses)
	}
	manager.Resume()
	if statuses := reconcile(t, manager, true, trusted(clusterA, root)); statuses[clusterA].State != StateCurrent ||
		IsMarker(read(t, dir, clusterA)) {
		t.Fatalf("after Resume: %+v", statuses)
	}
}

// A file the withhold could not mark is marked by the next pass, which
// writes no roots (re-review e1a M-1).
func TestWithheldPassRetriesMarkers(t *testing.T) {
	t.Parallel()
	manager, dir, _ := newManager(t)
	root := p256Root(t)
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a read-only directory stops neither Windows nor root")
	}
	reconcile(t, manager, true, trusted(clusterA, root))
	// The withhold cannot write A's marker: the directory is read-only.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := manager.Withhold(ReasonDisconnected); err == nil {
		t.Fatal("a withhold that could not write reported no error")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	reconcile(t, manager, true, trusted(clusterA, root))
	if content := read(t, dir, clusterA); !IsMarker(content) {
		t.Fatalf("the withheld pass left roots: %q", content)
	}
}

// A confirmation time ahead of the clock dates nothing (re-review e1a L-2).
func TestFutureConfirmationIsNotTrusted(t *testing.T) {
	t.Parallel()
	manager, dir, c := newManager(t)
	root := p256Root(t)
	c.now = c.now.Add(30 * 24 * time.Hour) // a clock running ahead
	reconcile(t, manager, true, trusted(clusterA, root))
	c.now = c.now.Add(-30 * 24 * time.Hour) // set back
	if statuses := reconcile(t, manager, false, trusted(clusterA, root)); statuses[clusterA].State != StateExpired ||
		!IsMarker(read(t, dir, clusterA)) {
		t.Fatalf("a future confirmation was trusted: %+v", statuses)
	}
}
