package kubecert

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
)

// storedManager is a manager over core whose store is dir.
func storedManager(t *testing.T, core *fakeCore, dir string) *Manager {
	t.Helper()
	manager, err := New(Options{
		Request: core.request, Token: func() (string, error) { return core.token, nil },
		Now: func() time.Time { return *core.now }, Logger: slog.New(slog.DiscardHandler), StoreDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

// issuedIn has a manager over dir take a certificate from core.
func issuedIn(t *testing.T, core *fakeCore, dir string) Certificate {
	t.Helper()
	core.answers = append(core.answers, core.issue)
	manager := storedManager(t, core, dir)
	manager.mapSeen = true
	manager.step(t.Context(), *core.now)
	issued, ok := manager.Current()
	if !ok {
		t.Fatal("no certificate")
	}
	return issued
}

func fileGone(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, storeFile)); !os.IsNotExist(err) {
		t.Fatalf("file kept: %v", err)
	}
}

// A certificate issued is saved, 0600; after a restart it is taken back
// with its key and schedule, asking Core nothing, then renews with its own
// proof (K1b design §3).
func TestStoreSavesAndRestores(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	core := newFakeCore(t)
	issued := issuedIn(t, core, dir)
	info, err := os.Stat(filepath.Join(dir, storeFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file %v, %v", info, err)
	}

	*core.now = core.now.Add(time.Hour)
	restarted := storedManager(t, core, dir)
	restarted.restore(t.Context())
	restored, ok := restarted.Current()
	if !ok || restored.Serial != issued.Serial || !restored.Key.Equal(issued.Key) ||
		!restored.IssuedAt.Equal(issued.IssuedAt) {
		t.Fatalf("restored %v: serial %x", ok, restored.Serial)
	}
	restarted.mapArrived(&networkmap.KubernetesCA{Root: issued.Root[:], Signing: issued.Issuer[:],
		MapRevision: issued.NetworkRevision}, *core.now)
	if _, ok := restarted.Current(); !ok || restarted.restored || len(core.requests) != 1 {
		t.Fatalf("after the map: restored %t, %d requests", restarted.restored, len(core.requests))
	}
	// Its renewal is due when the first one's was, and proves with its key.
	*core.now = issued.RenewAt
	core.answers = append(core.answers, core.issue)
	restarted.step(t.Context(), *core.now)
	renewal := core.requests[len(core.requests)-1]
	if !renewal.Renewal() || renewal.Token != "" || renewal.RenewalSerial != issued.Serial {
		t.Fatalf("renewal %+v", renewal)
	}
	second, _ := restarted.Current()
	again := storedManager(t, core, dir)
	again.restore(t.Context())
	if latest, ok := again.Current(); !ok || latest.Serial != second.Serial {
		t.Fatal("the file was not replaced by the renewal")
	}
	if restarted.Snapshot().Requests[[2]string{"restored", ""}] != 1 {
		t.Fatalf("snapshot %+v", restarted.Snapshot().Requests)
	}
}

// A stored certificate that does not check is removed, not taken; a
// temporary file a write left is removed too.
func TestStoreRefusesWhatDoesNotCheck(t *testing.T) {
	t.Parallel()
	for name, spoil := range map[string]func(t *testing.T, dir string){
		"garbage": func(t *testing.T, dir string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, storeFile), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"another key": func(t *testing.T, dir string) {
			t.Helper()
			other := newFakeCore(t)
			theirs := issuedIn(t, other, t.TempDir())
			rewrite(t, dir, func(held *stored) { held.Certificate = theirs.DER })
		},
		"another issuer named": func(t *testing.T, dir string) {
			t.Helper()
			rewrite(t, dir, func(held *stored) { held.Issuer = make([]byte, 32) })
		},
		"an unknown form": func(t *testing.T, dir string) {
			t.Helper()
			rewrite(t, dir, func(held *stored) { held.Version = 2 })
		},
		"an issue time past its end": func(t *testing.T, dir string) {
			t.Helper()
			rewrite(t, dir, func(held *stored) { held.IssuedAt = held.IssuedAt.Add(48 * time.Hour) })
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			core := newFakeCore(t)
			issuedIn(t, core, dir)
			spoil(t, dir)
			leftover := filepath.Join(dir, ".certificate-123")
			if err := os.WriteFile(leftover, []byte("key"), 0o600); err != nil {
				t.Fatal(err)
			}
			restarted := storedManager(t, core, dir)
			restarted.restore(t.Context())
			if _, ok := restarted.Current(); ok {
				t.Fatal("restored")
			}
			fileGone(t, dir)
			if _, err := os.Stat(leftover); !os.IsNotExist(err) {
				t.Fatal("a leftover was kept")
			}
			if restarted.Snapshot().Requests[[2]string{"restore_refused", ""}] != 1 {
				t.Fatalf("snapshot %+v", restarted.Snapshot().Requests)
			}
		})
	}
}

// rewrite changes the stored file.
func rewrite(t *testing.T, dir string, change func(*stored)) {
	t.Helper()
	path := filepath.Join(dir, storeFile)
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var held stored
	if err := json.Unmarshal(payload, &held); err != nil {
		t.Fatal(err)
	}
	change(&held)
	rewritten, err := json.Marshal(held)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Time is not judged at restore, where the clock may still be the host's:
// an expired certificate is held but not served, and its file goes when
// Core's clock drops it (review b7a M3).
func TestStoreLeavesTimeToCoresClock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	core := newFakeCore(t)
	issued := issuedIn(t, core, dir)
	*core.now = issued.NotAfter.Add(time.Minute)
	restarted := storedManager(t, core, dir)
	restarted.restore(t.Context())
	if _, ok := restarted.Current(); ok {
		t.Fatal("an expired certificate was served")
	}
	if _, err := os.Stat(filepath.Join(dir, storeFile)); err != nil {
		t.Fatalf("removed at restore: %v", err)
	}
	if _, ok := restarted.validCurrent(*core.now); ok {
		t.Fatal("expired kept")
	}
	fileGone(t, dir)
}

// A restored certificate whose CAs a map at or past its revision no longer
// names is kept, as an issued one is (Q68), and renews with its proof within
// recheck; an older map cannot say (review b7a M1).
func TestStoreRenewsSoonWhatTheMapNoLongerNames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	core := newFakeCore(t)
	issued := issuedIn(t, core, dir)
	*core.now = core.now.Add(time.Hour)
	restarted := storedManager(t, core, dir)
	restarted.restore(t.Context())
	restarted.mapArrived(&networkmap.KubernetesCA{Root: make([]byte, 32), Signing: make([]byte, 32),
		MapRevision: issued.NetworkRevision - 1}, *core.now)
	if !restarted.restored {
		t.Fatal("an older map decided")
	}
	other := make([]byte, 32)
	other[0] = 1
	restarted.mapArrived(&networkmap.KubernetesCA{Root: issued.Root[:], Signing: other,
		MapRevision: issued.NetworkRevision}, *core.now)
	if _, ok := restarted.Current(); !ok || restarted.restored {
		t.Fatal("dropped, or still unchecked")
	}
	restarted.step(t.Context(), *core.now)
	// Another map before the renewal does not put it back to the fleet's
	// spread (re-review b7a N1).
	restarted.mapArrived(&networkmap.KubernetesCA{Root: issued.Root[:], Signing: other,
		MapRevision: issued.NetworkRevision + 1}, core.now.Add(time.Second))
	restarted.step(t.Context(), core.now.Add(time.Second))
	if !restarted.nextAt.Before(core.now.Add(recheck + time.Second)) {
		t.Fatalf("renews in %v", restarted.nextAt.Sub(*core.now))
	}
	*core.now = restarted.nextAt
	core.answers = append(core.answers, core.issue)
	restarted.step(t.Context(), *core.now)
	if renewal := core.requests[len(core.requests)-1]; !renewal.Renewal() || renewal.Token != "" {
		t.Fatalf("not a renewal: %+v", renewal)
	}
}

// A save that fails leaves no older certificate behind (review b7a M2): a
// directory in the file's place makes the rename fail, and forget removes
// it.
func TestStoreForgetsWhenASaveFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	core := newFakeCore(t)
	issued := issuedIn(t, core, dir)
	path := filepath.Join(dir, storeFile)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	manager := storedManager(t, core, dir)
	manager.save(context.Background(), issued)
	fileGone(t, dir)
}

// A renewal Core no longer takes removes the file: a restart would bring
// back a certificate that cannot renew (review b7a M2).
func TestStoreForgetsARefusedRenewal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	core := newFakeCore(t)
	core.answers = append(core.answers, core.issue)
	manager := storedManager(t, core, dir)
	manager.mapSeen = true
	manager.step(t.Context(), *core.now)
	issued, _ := manager.Current()
	*core.now = issued.RenewAt
	core.answers = append(core.answers, func(controlplane.KubeCertRequest) (controlplane.KubeCertResult, error) {
		return controlplane.KubeCertResult{Outcome: controlplane.KubeCertRefused, Reason: "renewal_unknown"}, nil
	})
	manager.step(t.Context(), *core.now)
	fileGone(t, dir)
}

// A map after a refused early renewal keeps the refusal's backoff
// (re-review b7a H2).
func TestStoreMapKeepsARefusalBackoff(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{"revoked", "superseded"} {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			core := newFakeCore(t)
			issued := issuedIn(t, core, dir)
			*core.now = core.now.Add(time.Hour)
			manager := storedManager(t, core, dir)
			manager.restore(t.Context())
			other := make([]byte, 32)
			other[0] = 1
			manager.mapArrived(&networkmap.KubernetesCA{Root: issued.Root[:], Signing: other,
				MapRevision: issued.NetworkRevision}, *core.now)
			manager.step(t.Context(), *core.now)
			*core.now = manager.nextAt
			core.answers = append(core.answers, refuse(reason))
			manager.step(t.Context(), *core.now)
			backoff := manager.nextAt
			*core.now = core.now.Add(time.Second)
			manager.mapArrived(&networkmap.KubernetesCA{Root: issued.Root[:], Signing: other,
				MapRevision: issued.NetworkRevision + 1}, *core.now)
			if manager.nextAt.Before(backoff) {
				t.Fatalf("a map brought the request %v before its backoff", backoff.Sub(manager.nextAt))
			}
		})
	}
}
